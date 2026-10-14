using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Etw;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>Запись watchlist системных хранилищ: корневой каталог и его назначение.</summary>
public sealed record SystemCredentialRoot(string Root, string Kind);

/// <summary>
/// Чистое перечисление корней РЕАЛЬНЫХ хранилищ учётных данных Windows (3.0.0.47,
/// System Credential Guard). Никаких побочных эффектов — тестируемо.
///
/// Отслеживаются четыре корня (без Vault — системные службы читают vault-файлы,
/// что даёт шум алертов при низком эффекте):
///   %APPDATA%\Microsoft\Credentials     — хранилище учётных данных (roaming);
///   %LOCALAPPDATA%\Microsoft\Credentials — то же (local);
///   %APPDATA%\Microsoft\Protect         — DPAPI master keys (roaming);
///   %LOCALAPPDATA%\Microsoft\Protect    — DPAPI master keys (local).
///
/// Protect обязателен вместе с Credentials: без DPAPI-ключа стилер не может
/// расшифровать ни Credentials, ни пароли браузеров (Chrome Local State шифруется
/// тем же пользовательским ключом). Читаются они всегда парой.
/// </summary>
public static class SystemCredentialLocator
{
    /// <summary>Корни хранилищ (нормализованные, с границей каталога). Корни можно
    /// передать явно (для юнит-тестов); по умолчанию — из окружения.</summary>
    public static List<SystemCredentialRoot> BuildRoots(string? localAppData = null, string? roamingAppData = null)
    {
        var result = new List<SystemCredentialRoot>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddRoots(string local, string roaming)
        {
            foreach (var (path, kind) in new[]
            {
                (Path.Combine(roaming, "Microsoft", "Credentials"), "Credentials (roaming)"),
                (Path.Combine(local, "Microsoft", "Credentials"), "Credentials (local)"),
                (Path.Combine(roaming, "Microsoft", "Protect"), "DPAPI Protect (roaming)"),
                (Path.Combine(local, "Microsoft", "Protect"), "DPAPI Protect (local)"),
            })
            {
                try
                {
                    var full = Path.GetFullPath(path).TrimEnd('\\');
                    if (seen.Add(full))
                    {
                        result.Add(new SystemCredentialRoot(full, kind));
                    }
                }
                catch { /* некорректный путь */ }
            }
        }

        // Явные корни (юнит-тесты) — ровно одна пара, как раньше.
        if (!string.IsNullOrWhiteSpace(localAppData) || !string.IsNullOrWhiteSpace(roamingAppData))
        {
            var local = string.IsNullOrWhiteSpace(localAppData)
                ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
                : Path.GetFullPath(localAppData);
            var roaming = string.IsNullOrWhiteSpace(roamingAppData)
                ? Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData)
                : Path.GetFullPath(roamingAppData);
            AddRoots(local, roaming);
            return result;
        }

        // 3.0.0.94: от службы от SYSTEM хранилища Credentials/Protect ищутся во ВСЕХ
        // реальных профилях пользователей (раньше Environment.GetFolderPath возвращал
        // системный профиль — System Credential Guard не видел хранилищ пользователей).
        if (CatGuardian.Data.UserContextPaths.IsSystemAccount)
        {
            foreach (var (local, roaming) in CatGuardian.Data.UserContextPaths.GetUserAppDataRoots())
            {
                AddRoots(local, roaming);
            }
            return result;
        }

        // Обычный запуск (панель/dev asInvoker): корни профиля текущего процесса.
        AddRoots(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData));
        return result;
    }

    /// <summary>Принадлежит ли путь одному из корней хранилищ (с ГРАНИЦЕЙ каталога:
    /// «...\CredentialsEvil\» не считается попаданием). Дешёвая операция для ETW-колбэка.</summary>
    public static bool IsSystemCredentialPath(string? path, IReadOnlyCollection<SystemCredentialRoot> roots)
    {
        if (string.IsNullOrWhiteSpace(path) || roots is null || roots.Count == 0)
        {
            return false;
        }

        foreach (var root in roots)
        {
            if (path.Equals(root.Root, StringComparison.OrdinalIgnoreCase)
                || path.StartsWith(root.Root + "\\", StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Детект ЧТЕНИЯ реальных хранилищ учётных данных Windows (3.0.0.47, System Credential
/// Guard) на уровне ядра через ETW (Microsoft-Windows-Kernel-File). Вектор дополняет
/// Anti-Stealer: приманки и Browser Credential Guard ловят стилеров, а этот наблюдатель —
/// тех, кто читает настоящие %*\Microsoft\Credentials и %*\Microsoft\Protect (DPAPI).
///
/// Используется ЕДИНАЯ сессия ядра KernelEtwBridge (вторая не создаётся — без
/// дублирования). В ETW-колбэке только дешёвые операции (нормализация пути + префиксная
/// проверка корней, БЕЗ Process.MainModule — известное ограничение 3.0.0.17). Решение по
/// процессу выносит AntiStealerMonitor через общий канал HoneypotAccessEvent.
///
/// Легитимные читатели (сам вход в систему, Windows Hello, подписанное ПО) отсекаются
/// в AntiStealerCore этапом подписи/White Paths/SecurityCenter2.
/// Требует прав администратора (служба монитора их имеет).
/// </summary>
public sealed class SystemCredentialWatcher : IDisposable
{
    private readonly GuardianService _service;
    private readonly KernelEtwBridge _bridge;
    private readonly object _sync = new();
    private readonly Dictionary<int, DateTime> _lastEventUtc = new();

    private List<SystemCredentialRoot> _roots = new();
    private IDisposable? _subscription;
    private Timer? _refreshTimer;
    private int _cooldownSeconds;

    /// <summary>Срабатывает при детекте чтения хранилища (после записи в БД).</summary>
    public event Action<EventRecord>? AccessDetected;

    public bool IsRunning => _subscription is not null;

    public SystemCredentialWatcher(GuardianService service, int cooldownSeconds = 30,
        KernelEtwBridge? bridge = null)
    {
        _service = service;
        _cooldownSeconds = Math.Max(1, cooldownSeconds);
        _bridge = bridge ?? KernelEtwBridge.Shared;
    }

    public void Start()
    {
        Stop();
        lock (_sync)
        {
            _roots = SystemCredentialLocator.BuildRoots();
            if (_roots.Count == 0)
            {
                GuardianLog.Info("SYSTEM-GUARD: корни системных хранилищ недоступны — наблюдатель не запущен.");
                return;
            }

            try
            {
                _bridge.FileRead += OnFileRead;
                _subscription = _bridge.Subscribe();
                _refreshTimer = new Timer(_ => RefreshRoots(), null,
                    TimeSpan.FromHours(24), TimeSpan.FromHours(24));
                GuardianLog.Info($"SYSTEM-GUARD: ETW-детект чтения хранилищ учётных данных Windows запущен ({_roots.Count} корней)");
            }
            catch (Exception ex)
            {
                _bridge.FileRead -= OnFileRead;
                _subscription = null;
                GuardianLog.Error("SYSTEM-GUARD: не удалось подписаться на ETW-ядро", ex);
            }
        }
    }

    /// <summary>Перечитывает конфиг (cooldown) и пересобирает корни.</summary>
    public void Reload(int cooldownSeconds)
    {
        _cooldownSeconds = Math.Max(1, cooldownSeconds);
        lock (_sync)
        {
            _roots = SystemCredentialLocator.BuildRoots();
        }
        GuardianLog.Info($"SYSTEM-GUARD: корни пересобраны ({_roots.Count})");
    }

    /// <summary>Периодическая пересборка корней (смена профиля пользователя и т.п.).</summary>
    private void RefreshRoots()
    {
        try
        {
            lock (_sync)
            {
                _roots = SystemCredentialLocator.BuildRoots();
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("SYSTEM-GUARD: ошибка пересборки корней", ex);
        }
    }

    private void OnFileRead(FileIOReadWriteTraceData data) =>
        Handle(data.FileName, data.ProcessID, data.ProcessName);

    private void Handle(string? fileName, int processId, string? processName)
    {
        if (string.IsNullOrEmpty(fileName)) return;

        var full = Normalize(fileName);
        bool hit;
        lock (_sync)
        {
            hit = SystemCredentialLocator.IsSystemCredentialPath(full, _roots);
        }
        if (!hit) return;

        // Анти-шторм по PID (по образцу BrowserCredentialWatcher).
        if (processId > 0)
        {
            var now = DateTime.UtcNow;
            lock (_lastEventUtc)
            {
                if (_lastEventUtc.TryGetValue(processId, out var last)
                    && (now - last).TotalSeconds < _cooldownSeconds)
                {
                    return;
                }
                _lastEventUtc[processId] = now;

                // Поддерживаем словарь компактным: чистим записи старше cooldown*4.
                if (_lastEventUtc.Count > 512)
                {
                    var cutoff = now.AddSeconds(-_cooldownSeconds * 4);
                    foreach (var stale in _lastEventUtc.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    {
                        _lastEventUtc.Remove(stale);
                    }
                }
            }
        }

        // Имя процесса берём из события ETW — Process.MainModule в этом потоке запрещён.
        var proc = string.IsNullOrWhiteSpace(processName)
            ? $"PID {processId}"
            : $"{processName} (PID {processId})";

        var record = new EventRecord
        {
            Source = EventSource.Honeypot,
            Type = ChangeType.Access,
            Target = full,
            Detail = $"хранилище учётных данных Windows прочитано | процесс: {proc}",
            OccurredAt = DateTime.UtcNow,
            Status = EventStatus.Pending,
            ProcessId = processId > 0 ? processId : null,
            ProcessName = string.IsNullOrWhiteSpace(processName) ? null : processName,
            // 3.0.0.47: признак «системное хранилище» — Anti-Stealer меняет текст алерта.
            IsSystemCredential = true,
        };
        _service.Events.Add(record);
        GuardianLog.Info($"SYSTEM-GUARD: чтение хранилища учётных данных: {full} | {proc}");
        AccessDetected?.Invoke(record);
    }

    private static string Normalize(string p)
    {
        try { return Path.GetFullPath(p); }
        catch { return p; }
    }

    public void Stop()
    {
        lock (_sync)
        {
            _refreshTimer?.Dispose();
            _refreshTimer = null;
            if (_subscription != null)
            {
                _subscription.Dispose();
                _subscription = null;
            }
            _bridge.FileRead -= OnFileRead;
        }
    }

    public void Dispose() => Stop();
}