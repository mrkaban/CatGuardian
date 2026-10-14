namespace CatGuardian.Integrity.Services;

/// <summary>
/// Логика определения живости резидент-службы для панели (3.0.0.23, D2).
///
/// Раньше при включённой самозащите (selfdef_watchdog=true) статус зависел ТОЛЬКО от
/// нативного watchdog (PeerProcessWatchdog.IsPeerAlive). Если служба запущена НЕ панелью
/// (нет связи service_pid/panel_pid) — хендл не установлен, IsPeerAlive() == false, и
/// панель показывала серый значок + ложный баллон «Резидентный мониторинг отключен»
/// при ЖИВОЙ службе (подтверждено diag.log: WATCHDOG каждые 60 с, ipc-ping OK).
///
/// Правило: если нативный watchdog не установлен — верить проверке существования
/// процесса (fallback); если watchdog установлен — верить ему (событие ядра).
/// </summary>
public static class ServicePeerStatus
{
    /// <summary>
    /// Истина, если служба считается работающей.
    /// </summary>
    /// <param name="watchdogEnabled">Включена ли самозащита (нативный watchdog).</param>
    /// <param name="watchdogWatching">Установлен ли нативный хендл процесса службы.</param>
    /// <param name="watchdogAlive">Жив ли процесс по сигналу нативного хендла.</param>
    /// <param name="processAlive">Существует ли процесс CatGuardian.Service.</param>
    public static bool IsRunning(
        bool watchdogEnabled,
        bool watchdogWatching,
        bool watchdogAlive,
        bool processAlive)
    {
        if (!watchdogEnabled)
        {
            // Самозащита выключена — только проверка существования процесса.
            return processAlive;
        }

        if (watchdogAlive)
        {
            return true;
        }

        // Watchdog установлен и говорит «мёртв» — верим ему. Запасной вариант — процесс
        // ТОЛЬКО когда хендла нет вовсе (служба запущена не панелью).
        return !watchdogWatching && processAlive;
    }
}