namespace CatGuardian.Antivirus.Core.Logging;

/// <summary>Абстракция журналирования CatGuardian.Antivirus.</summary>
public interface ILogger : IDisposable
{
    /// <summary>Записать сообщение указанного уровня и категории.</summary>
    void Log(LogLevel level, LogCategory category, string message);
}