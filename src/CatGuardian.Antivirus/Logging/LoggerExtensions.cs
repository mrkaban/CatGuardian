namespace CatGuardian.Antivirus.Core.Logging;

/// <summary>Удобные методы журналирования поверх <see cref="ILogger.Log"/>.</summary>
public static class LoggerExtensions
{
    public static void Debug(this ILogger logger, string message)
        => logger.Log(LogLevel.Debug, LogCategory.Main, message);

    public static void Info(this ILogger logger, string message)
        => logger.Log(LogLevel.Info, LogCategory.Main, message);

    public static void Warning(this ILogger logger, string message)
        => logger.Log(LogLevel.Warning, LogCategory.Main, message);

    public static void Error(this ILogger logger, string message)
        => logger.Log(LogLevel.Error, LogCategory.Main, message);

    public static void Debug(this ILogger logger, LogCategory category, string message)
        => logger.Log(LogLevel.Debug, category, message);

    public static void Info(this ILogger logger, LogCategory category, string message)
        => logger.Log(LogLevel.Info, category, message);

    public static void Warning(this ILogger logger, LogCategory category, string message)
        => logger.Log(LogLevel.Warning, category, message);

    public static void Error(this ILogger logger, LogCategory category, string message)
        => logger.Log(LogLevel.Error, category, message);
}