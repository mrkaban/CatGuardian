using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace CatGuardian.Service.SelfDefense;

/// <summary>
/// Защита файлов БД и конфигурации от удаления/переименования через файловые хендлы ОС (3.0.0.22).
///
/// Служба открывает защищаемые файлы с флагами:
///   FileMode.Open, FileAccess.Read, FileShare.ReadWrite
/// и держит хендлы открытыми всё время работы. Проверку прав на удаление/переименование
/// выполняет сама Windows на уровне драйвера NTFS: любой процесс (даже Администратор/SYSTEM)
/// при попытке удалить или переименовать такой файл мгновенно получит ERROR_SHARING_VIOLATION.
/// FileShare.ReadWrite разрешает остальным процессам (SQLite панели и службы, JsonConfiguration.Save)
/// читать и писать файл — не мешая штатной работе, но блокируя Delete/Rename (FileShare.Delete не задан).
///
/// Фоновой нагрузки нет: код совершает 0 вычислений, пока файлы не трогают.
/// </summary>
public sealed class FileLockGuard : IDisposable
{
    private readonly object _sync = new();
    private readonly Dictionary<string, FileStream> _handles = new(StringComparer.OrdinalIgnoreCase);
    private bool _running;

    /// <summary>Количество фактически заблокированных файлов.</summary>
    public int LockedCount
    {
        get { lock (_sync) return _handles.Count; }
    }

    /// <summary>Список заблокированных файлов (для статуса/диагностики).</summary>
    public IReadOnlyList<string> LockedFiles
    {
        get
        {
            lock (_sync) return _handles.Keys.ToArray();
        }
    }

    /// <summary>
    /// Открывает хендлы для указанных файлов. Файлы, которых нет на диске или которые
    /// недоступны после всех повторов, пропускаются (служба продолжает работу).
    /// </summary>
    public void Start(IEnumerable<string> paths)
    {
        Stop();

        lock (_sync)
        {
            foreach (var path in (paths ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(path)) continue;
                var stream = TryOpenWithRetries(path);
                if (stream is not null)
                {
                    _handles[path] = stream;
                }
            }
            _running = true;
        }
    }

    /// <summary>Освобождает все хендлы (снимает блокировки).</summary>
    public void Stop()
    {
        List<FileStream> toClose;
        lock (_sync)
        {
            toClose = _handles.Values.ToList();
            _handles.Clear();
            _running = false;
        }
        foreach (var fs in toClose)
        {
            try { fs.Dispose(); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// 3.0.1.1: дооткрывает хендлы для файлов, которых не было на момент
    /// <see cref="Start"/> (например, threat_intelligence.db создаётся при первом
    /// обновлении фидов, settings.db — при первом запуске комплекса). Существующие
    /// хендлы не трогает. Вызывается по таймеру из ServiceHost каждые 15 с.
    /// </summary>
    public void EnsureLocked(IEnumerable<string> paths)
    {
        lock (_sync)
        {
            if (!_running) return;
            foreach (var path in (paths ?? Array.Empty<string>()).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(path) || _handles.ContainsKey(path)) continue;
                var stream = TryOpenWithRetries(path);
                if (stream is not null)
                {
                    _handles[path] = stream;
                }
            }
        }
    }

    /// <summary>Заблокирован ли файл этим модулем.</summary>
    public bool IsLocked(string path)
    {
        lock (_sync)
        {
            return _handles.ContainsKey(path);
        }
    }

    /// <summary>На короткое время снимает блокировку одного файла (например, перед
    /// операцией, требующей переименования); вернуть блокировку — <see cref="Relock"/>.</summary>
    public void Unlock(string path)
    {
        FileStream? fs;
        lock (_sync)
        {
            if (!_handles.TryGetValue(path, out fs)) return;
            _handles.Remove(path);
        }
        try { fs.Dispose(); } catch { /* ignore */ }
    }

    /// <summary>Возвращает блокировку файла, снятую <see cref="Unlock"/>.</summary>
    public void Relock(string path)
    {
        lock (_sync)
        {
            if (_handles.ContainsKey(path) || !_running) return;
            var stream = TryOpenWithRetries(path);
            if (stream is not null)
            {
                _handles[path] = stream;
            }
        }
    }

    private static FileStream? TryOpenWithRetries(string path)
    {
        const int maxAttempts = 5;
        const int pauseMs = 2000;

        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                // FileShare.ReadWrite БЕЗ FileShare.Delete: чтение/запись разрешены,
                // удаление и переименование — нет (ERROR_SHARING_VIOLATION).
                return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            }
            catch (FileNotFoundException)
            {
                return null; // файл ещё не создан — нечего защищать
            }
            catch (DirectoryNotFoundException)
            {
                return null;
            }
            catch (IOException)
            {
                // Файл временно занят с несовместимым share — повторим позже.
                Thread.Sleep(pauseMs);
            }
            catch (UnauthorizedAccessException)
            {
                return null; // прав нет — защита невозможна
            }
        }
        return null;
    }

    public void Dispose() => Stop();
}