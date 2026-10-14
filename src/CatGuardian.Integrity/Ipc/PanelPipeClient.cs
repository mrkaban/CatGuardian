using System;
using System.IO.Pipes;
using System.Threading;
using System.Threading.Tasks;

namespace CatGuardian.Integrity.Ipc;

/// <summary>
/// Клиент обратного канала «служба → панель управления» (п.5б).
/// Служба (монитор) шлёт панели запросы, на которые та отвечает
/// пользовательскими решениями — например, «Сканировать новый диск?».
/// Работает как односторонний fire-and-forget с жёстким таймаутом:
/// панель может быть свёрнута в трей или вовсе не запущена.
/// </summary>
public static class PanelPipeClient
{
    /// <summary>
    /// 3.0.0.58-trayhost: виды интерактивных алертов, для которых служба ведёт
    /// очередь недоставленных сообщений и поднимает панель по требованию. Если панель
    /// не запущена, обычный fire-and-forget TrySend молча теряет алерт — а тайм-чувствительные
    /// решения (замороженный стилер, изоляция песочницы) остаются без UI.
    /// 3.0.0.63: сюда добавлены VirusAlert и ClipboardAlert — раньше при закрытой панели
    /// они терялись молча (окно не появлялось, баллун трея не показывался, панель не
    /// поднималась); теперь оба вида идут через очередь: баллун + спавн панели
    /// --spawned-by-tray + retry-доставка.
    /// 3.0.0.63: закрыты последние дыры реестра — AskScanDrive (вопрос о новом
    /// накопителе) и PrivacyShieldAlert (камера/микрофон) тоже терялись молча при закрытой
    /// панели; теперь они идут через очередь. Для PrivacyShieldAlert спавн панели подавлен
    /// (информационное уведомление — достаточно баллуна трея), см. InteractiveAlertQueue.
    /// </summary>
    private static readonly System.Collections.Generic.HashSet<IpcProtocol.MessageKind> InteractiveAlertKinds =
        new()
        {
            IpcProtocol.MessageKind.AutoStartAlert,
            IpcProtocol.MessageKind.RansomwareAlert,
            IpcProtocol.MessageKind.EtwAlert,
            IpcProtocol.MessageKind.WmiAlert,
            IpcProtocol.MessageKind.FirewallScanAlert,
            IpcProtocol.MessageKind.FirewallRuleAlert,
            IpcProtocol.MessageKind.AntiStealerAlert,
            IpcProtocol.MessageKind.WinlockAlert,
            IpcProtocol.MessageKind.MinerAlert,
            IpcProtocol.MessageKind.AnomalyAlert,
            IpcProtocol.MessageKind.ShortcutAlert,
            IpcProtocol.MessageKind.PortListenerAlert,
            IpcProtocol.MessageKind.LolBinAlert,
            IpcProtocol.MessageKind.ParentChildAlert,
            IpcProtocol.MessageKind.ExtensionAlert,
            IpcProtocol.MessageKind.SandboxAlert,
            IpcProtocol.MessageKind.EntropyAlert,
            IpcProtocol.MessageKind.VirusAlert,
            IpcProtocol.MessageKind.ClipboardAlert,
            IpcProtocol.MessageKind.AskScanDrive,
            IpcProtocol.MessageKind.PrivacyShieldAlert,
            // 3.0.1.5: AMSI-алерт — блокировка скриптового контента; при закрытой панели
            // уходит в очередь InteractiveAlertQueue (баллун + спавн панели при необходимости).
            IpcProtocol.MessageKind.AmsiAlert,
        };

    /// <summary>
    /// 3.0.0.58-trayhost: перехватчик интерактивных алертов, устанавливаемый СЛУЖБОЙ
    /// при старте (InteractiveAlertQueue в ServiceHost). Вызывается ПЕРЕД отправкой алерта
    /// панели; если вернул true — алерт гарантированно взят службой в очередь (доставка
    /// с retry + спавн панели --spawned-by-tray). Отправка при этом продолжается как обычно:
    /// при доступной панели алерт уйдёт напрямую (без дублей — панель дедуплицирует по
    /// ActionKey), при недоступной — останется в очереди службы. null — перехват отключён.
    /// </summary>
    public static Func<IpcProtocol.MessageKind, string?, bool>? InteractiveAlertInterceptor;

    /// <summary>
    /// Отправляет сообщение панели и ждёт короткий ответ-подтверждение.
    /// Возвращает false, если панель недоступна, не ответила за timeout
    /// или канал закрылся. Никогда не бросает исключений.
    /// </summary>
    public static bool TrySend(IpcProtocol.MessageKind kind, string? data, TimeSpan timeout)
    {
        try
        {
            if (InteractiveAlertKinds.Contains(kind) && InteractiveAlertInterceptor is not null)
            {
                try { InteractiveAlertInterceptor(kind, data); }
                catch { /* перехватчик службы не должен ломать отправку */ }
            }

            var task = Task.Run(() =>
            {
                using var client = new NamedPipeClientStream(".", IpcProtocol.PanelPipeName,
                    PipeDirection.InOut, PipeOptions.Asynchronous);
                client.Connect((int)timeout.TotalMilliseconds);
                IpcProtocol.WriteMessage(client, new IpcProtocol.Message { Kind = kind, Data = data });
                // 3.0.1.3-fix: чтение ответа с ЖЁСТКИМ таймаутом. Раньше ReadMessage был
                // блокирующим без таймаута: если панель приняла соединение, но не ответила,
                // поток Task.Run висел вечно, using не закрывал клиент, и экземпляр канала
                // панели оставался занятым — накопление таких «зависших» соединений давало
                // ложное «панель недоступна» (алерт уходил в очередь на 15+ с).
                using var readCts = new CancellationTokenSource(timeout);
                var response = IpcProtocol.ReadMessageAsync(client, readCts.Token)
                    .GetAwaiter().GetResult();
                return response.Kind != IpcProtocol.MessageKind.Ping;
            });
            // Наблюдаем ошибку фоновой задачи, чтобы не уронить процесс финализатором.
            _ = task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted);
            if (task.Wait(timeout) && task.Result)
            {
                return true;
            }

            // 3.0.1.4: диагностика причины «панель недоступна» — чтобы отличать
            // «панель не запущена» от «панель зависла/канал занят» по логам.
            if (task.IsFaulted)
            {
                GuardianLog.Warning(
                    $"PanelPipeClient: панель недоступна ({kind}) — ошибка канала: " +
                    (task.Exception?.GetBaseException()?.Message ?? "неизвестно"));
            }
            else if (!task.IsCompleted)
            {
                GuardianLog.Warning(
                    $"PanelPipeClient: панель недоступна ({kind}) — таймаут {timeout.TotalMilliseconds} мс " +
                    "(панель не ответила или канал занят).");
            }
            else
            {
                GuardianLog.Warning(
                    $"PanelPipeClient: панель недоступна ({kind}) — панель отклонила сообщение " +
                    "(недоверенный клиент или ответ не получен).");
            }
            return false;
        }
        catch (Exception ex)
        {
            GuardianLog.Warning($"PanelPipeClient: панель недоступна ({kind}) — {ex.GetBaseException().Message}");
            return false;
        }
    }

    /// <summary>Отправляет запрос панели без данных.</summary>
    public static bool TrySend(IpcProtocol.MessageKind kind, TimeSpan timeout)
        => TrySend(kind, null, timeout);

    /// <summary>
    /// Отправляет сообщение панели с повторными попытками и экспоненциальной паузой
    /// (по умолчанию 100/200/400 мс). Используется для критичных алертов (например,
    /// о вирусе), которые не должны теряться при позднем старте панели. Синхронный:
    /// вызывает существующий <see cref="TrySend(MessageKind, string?, TimeSpan)"/>.
    /// Сигнатуры TrySend не меняются — другие вызовы модулей не затрагиваются.
    /// </summary>
    public static bool TrySendRetry(
        IpcProtocol.MessageKind kind,
        string? data,
        int attempts = 3,
        int baseDelayMs = 100)
    {
        if (attempts < 1)
        {
            attempts = 1;
        }

        for (var attempt = 0; attempt < attempts; attempt++)
        {
            if (TrySend(kind, data, TimeSpan.FromSeconds(3)))
            {
                return true;
            }

            // Экспоненциальная пауза между попытками: 100, 200, 400 мс…
            if (attempt < attempts - 1)
            {
                Thread.Sleep(baseDelayMs * (1 << attempt));
            }
        }

        return false;
    }
}