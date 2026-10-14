namespace CatGuardian.Antivirus.Core.Logging;

/// <summary>
/// Категория записи журнала. Как и в Cat Guardian, разные виды активности
/// пишутся в отдельные файлы (<c>CatGuardian.Antivirus.realtime.log</c>, <c>quarantine</c> и т.д.)
/// в дополнение к общему <c>CatGuardian.Antivirus.log</c>.
/// </summary>
public enum LogCategory
{
    /// <summary>Служебные и общие сообщения.</summary>
    Main,

    /// <summary>Резидентный мониторинг файловой системы и обнаружение угроз.</summary>
    Realtime,

    /// <summary>Сообщения пользователю и сервисные уведомления.</summary>
    Messages,

    /// <summary>Действия карантина: перемещение, восстановление, удаление.</summary>
    Quarantine,

    /// <summary>Сканирование памяти при старте.</summary>
    Memory,

    /// <summary>Сканирование дисков, съёмных носителей, ручное сканирование.</summary>
    Drive,

    /// <summary>Обновление базы сигнатур (freshclam).</summary>
    Update,
}