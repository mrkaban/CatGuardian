using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using CatGuardian.Integrity.Filters;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Scanning;
using CatGuardian.Integrity.Services;

namespace CatGuardian.Integrity.Monitoring;

/// <summary>
/// Наблюдатель за изменениями в выбранных ветках реестра через
/// RegNotifyChangeKeyValue. По умолчанию отслеживаются высокорисковые ключи
/// автозагрузки и служб; список расширяется правилами watch_config.
/// </summary>
public sealed class RegistryChangeWatcher : IDisposable
{
    // Флаги уведомлений
    private const uint RegNotifyChangeName = 0x00000001;
    private const uint RegNotifyChangeAttributes = 0x00000002;
    private const uint RegNotifyChangeLastSet = 0x00000004;
    private const uint RegNotifyChangeSecurity = 0x00000008;

    private static readonly string[] DefaultHighRiskKeys =
    {
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        @"HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    };

    private readonly GuardianService _service;
    private readonly ExclusionMatcher _matcher;
    // B2 (3.0.0.18): режим «только уведомление» — наблюдатель не сверяет эталон и не пишет
    // события, а лишь сообщает о факте изменения ветки через <see cref="KeyChanged"/>.
    // Используется монитором автозагрузки для МГНОВЕННОЙ реакции на добавление записи.
    private readonly bool _notifyOnly;
    private readonly List<Task> _tasks = new();

    /// <summary>Срабатывает при изменении наблюдаемой ветки (путь ключа). B2 (3.0.0.18).</summary>
    public event Action<string>? KeyChanged;
    // НЕ переиспользуется (без TryReset): Stop отменяет и заменяет CTS, чтобы потоки,
    // всё ещё заблокированные в RegNotifyChangeKeyValue, гарантированно получили ОТМЕНЁННЫЙ
    // токен и завершились после пробуждения, а новые задачи — всегда свежий.
    private CancellationTokenSource _cts = new();

    public bool IsRunning { get; private set; }
    public IReadOnlyList<string> WatchedKeys => _watchedKeys;
    private readonly List<string> _watchedKeys = new();

    /// <summary>
    /// 3.0.0.36: диагностика жизненного цикла задач наблюдения (старт/выход с причиной).
    /// Устанавливается подписчиком (монитор автозагрузки) для отладки молчаливого
    /// завершения RegNotifyChangeKeyValue-циклов.
    /// </summary>
    public Action<string>? DiagLog { get; set; }

    public RegistryChangeWatcher(GuardianService service, ExclusionMatcher matcher, bool notifyOnly = false)
    {
        _service = service;
        _matcher = matcher;
        _notifyOnly = notifyOnly;
    }

    /// <summary>Начинает наблюдение. Если keys пусто — берутся высокорисковые по умолчанию.</summary>
    public void Start(IEnumerable<string>? keys = null)
    {
        Stop();
        // 3.0.0.36: HKEY_CURRENT_USER-шаблоны разворачиваются во все пользовательские
        // профили (HKEY_USERS\<SID>\...) — события автозагрузки ЛЮБОГО пользователя
        // должны вызывать уведомление, а не только токена процесса службы.
        var targetKeys = RegistryUserHives.ExpandAll(keys ?? DefaultHighRiskKeys);

        foreach (var keyPath in targetKeys)
        {
            _watchedKeys.Add(keyPath);
            _tasks.Add(Task.Run(() => MonitorKeyLoop(keyPath, _cts.Token)));
        }
        IsRunning = _tasks.Count > 0;
    }

    public void Stop()
    {
        _cts.Cancel();
        // Задачи, заблокированные в RegNotifyChangeKeyValue, завершатся после пробуждения:
        // они проверяют отменённый токен и выходят. Ожидание с ограничением по времени —
        // чтобы не блокировать вызывающего навсегда, если ветка реестра «молчит».
        try { Task.WaitAll(_tasks.ToArray(), 3000); } catch { /* ignore */ }
        _tasks.Clear();
        _watchedKeys.Clear();
        // ВАЖНО: старый CTS заменяется НОВЫМ (а не TryReset). Потоки из старого поколения
        // получили отменённый токен и завершатся при следующем пробуждении; новые задачи
        // используют свежий токен — дублирование обработки одного ключа исключено.
        _cts.Dispose();
        _cts = new CancellationTokenSource();
        IsRunning = false;
    }

    private void MonitorKeyLoop(string keyPath, CancellationToken ct)
    {
        DiagLog?.Invoke("task start: " + keyPath);
        while (!ct.IsCancellationRequested)
        {
            using var key = OpenKey(keyPath);
            if (key is null)
            {
                DiagLog?.Invoke("task exit (key not open): " + keyPath);
                return; // ветка недоступна/не существует
            }

            try
            {
                // Синхронное ожидание изменения
                var result = RegNotifyChangeKeyValue(
                    key.Handle.DangerousGetHandle(),
                    1, // bWatchSubtree
                    RegNotifyChangeName | RegNotifyChangeLastSet | RegNotifyChangeAttributes,
                    IntPtr.Zero,
                    0);

                if (result != 0)
                {
                    DiagLog?.Invoke($"task exit (result={result}): {keyPath}");
                    return; // ошибка (например, ветка удалена)
                }

                if (ct.IsCancellationRequested)
                {
                    return;
                }

                if (_matcher.IsExcludedRegistryKey(keyPath))
                {
                    continue;
                }

                if (_notifyOnly)
                {
                    // B2: только сигнал об изменении (сверку эталона делает подписчик).
                    KeyChanged?.Invoke(keyPath);
                    continue;
                }

                // Сверяем затронутую ветку с эталоном и фиксируем конкретные изменения.
                // Если эталона ещё нет (не снят) — пишем общее событие об изменении.
                try
                {
                    _service.CheckRegistryKey(keyPath);
                }
                catch (Exception)
                {
                    _service.Events.Add(new EventRecord
                    {
                        Source = EventSource.Registry,
                        Type = ChangeType.RegistryChanged,
                        Target = keyPath,
                        Detail = "значение или подключ изменён",
                        OccurredAt = DateTime.UtcNow,
                        Status = EventStatus.Pending,
                    });
                }
                KeyChanged?.Invoke(keyPath);
            }
            catch
            {
                DiagLog?.Invoke("task exit (exception): " + keyPath);
                return;
            }
        }
    }

    private static RegistryKey? OpenKey(string keyPath)
        // 3.0.0.36: единый открыватель ключей — поддержка HKEY_USERS\<SID> (см. RegistryUserHives).
        => RegistryUserHives.OpenKey(keyPath);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int RegNotifyChangeKeyValue(
        IntPtr hKey,
        int bWatchSubtree,
        uint dwNotifyFilter,
        IntPtr hEvent,
        int fAsynchronous);

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}