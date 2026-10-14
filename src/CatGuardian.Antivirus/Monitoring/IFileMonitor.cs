namespace CatGuardian.Antivirus.Core.Monitoring;

/// <summary>
/// Монитор изменений файловой системы. Аналог ShellNotify-компонента
/// Cat Guardian, но реализован поверх ReadDirectoryChangesW/FileSystemWatcher.
/// </summary>
public interface IFileMonitor : IDisposable
{
    /// <summary>Событие об изменении отслеживаемого файла/каталога.</summary>
    event EventHandler<FileChange>? FileChanged;

    /// <summary>Запустить мониторинг всех настроенных каталогов.</summary>
    void Start();

    /// <summary>Остановить мониторинг.</summary>
    void Stop();
}