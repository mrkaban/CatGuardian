using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using Microsoft.Win32.SafeHandles;

using CatGuardian.Localization;

namespace CatGuardian.Integrity.Resident;

/// <summary>Named pipe сервер монитора: отвечает на запросы панели управления.</summary>
public sealed class MonitorPipeServer : IDisposable
{
    private readonly Func<MonitorStatusDto> _statusProvider;
    private readonly Action? _onReload;
    private readonly Action<bool>? _onHoneypotSuspend;
    private readonly Action? _onRegenerateHoneypot;
    private readonly Action<string>? _onHoneypotDelete;
    private readonly Action? _onShutdown;
    private readonly Action<DriveScanAnswerDto>? _onDriveScanAnswer;
    // 3.0.0.7: команды мониторинга автозагрузки от панели.
    // M6: AutoStartAction возвращает bool — панель показывает фактический результат (UAC и т.п.).
    private readonly Action? _onAutoStartCheck;
    private readonly Func<AutoStartActionDto, bool>? _onAutoStartAction;
    // 3.0.0.30: решение пользователя по алерту подмены ярлыка (удалить/доверять).
    private readonly Func<ShortcutActionDto, bool>? _onShortcutAction;
    // 3.0.0.42: решение пользователя по алерту быстрого анализа энтропии
    // (восстановить .bak / доверять).
    private readonly Func<EntropyActionDto, bool>? _onEntropyAction;
    // 3.0.0.8: команды защиты от шифровальщиков от панели.
    private readonly Func<RansomwareActionDto, bool>? _onRansomwareAction;
    // 3.0.0.20: решение пользователя по алерту Winlock Protection (восстановить и доверять).
    private readonly Func<WinlockActionDto, bool>? _onWinlockAction;
    // 3.0.0.12: команды ETW-детекта поведения от панели («Завершить процесс»).
    private readonly Func<EtwActionDto, bool>? _onEtwAction;
    // 3.0.0.13: команды мониторинга скрытых обработчиков WMI от панели («Удалить объект»/«Проверить сейчас»).
    private readonly Func<WmiActionDto, bool>? _onWmiAction;
    private readonly Action? _onWmiCheckNow;
    // 3.0.0.14: команды сетевой эвристики брандмауэра от панели (завершить сканер / удалить правило).
    private readonly Func<FirewallScanActionDto, bool>? _onFirewallScanAction;
    private readonly Func<FirewallRuleActionDto, bool>? _onFirewallRuleAction;
    // 3.0.0.31: решение пользователя по алерту слушающего порта (завершить/доверять).
    private readonly Func<PortListenerActionDto, bool>? _onPortListenerAction;
    // 3.0.0.16: решение пользователя по алерту Anti-Stealer (убить/доверять).
    private readonly Func<AntiStealerActionDto, bool>? _onAntiStealerAction;
    // 3.0.0.85: решение пользователя по алерту Anti-Spyware (завершить/доверять/заблокировать).
    private readonly Func<SpywareActionDto, bool>? _onSpywareAction;
    // 3.0.0.23: решение пользователя по алерту антимайнера (завершить/разморозить и доверять/доверять).
    private readonly Func<MinerActionDto, bool>? _onMinerAction;
    // 3.0.0.24: решение пользователя по алерту «Контроля скрытой активности и аномалий»
    // (доверять пути / удалить правило брандмауэра).
    private readonly Func<AnomalyActionDto, bool>? _onAnomalyAction;
    // 3.0.0.33+: решение пользователя по LOLBins-алерту (завершить процесс/доверять артефакту).
    private readonly Func<LolBinActionDto, bool>? _onLolBinAction;
    // 3.0.0.37+: решение пользователя по алерту «Аномальные родительские связи» (завершить процесс/доверять родителю).
    private readonly Func<ParentChildActionDto, bool>? _onParentChildAction;
    // 3.0.0.38: решение пользователя по алерту Malicious Extension Watchdog
    // (Доверять / Отключить / Удалить) + фактический результат (OK, сообщение).
    private readonly Func<ExtensionActionDto, (bool Ok, string Message)>? _onExtensionAction;
    // 3.0.0.38: «Проверить сейчас» — немедленная проверка расширений браузера.
    private readonly Action? _onExtensionScan;
    // 3.0.0.39: решение пользователя по алерту песочницы (запустить в песочнице / завершить /
    // доверять / пропустить / снять изоляцию) + фактический результат (OK, sandboxPid, ошибка).
    private readonly Func<SandboxActionDto, (bool Ok, int SandboxPid, string Error)>? _onSandboxAction;
    // 3.0.0.39: запрос списка активных сессий песочницы.
    private readonly Func<List<SandboxSessionDto>>? _onSandboxStatus;
    // 3.0.0.10: сетевые PID'ы из брандмауэра панели (Pre-Scan Heuristics).
    private readonly Action<NetworkActivityDto>? _onNetworkActivity;
    // 3.0.0.19: включение/отключение интеграции в контекстное меню Проводника (Shell Extension).
    private readonly Func<ContextMenuActionDto, bool>? _onContextMenuAction;
    // 3.0.0.19: команды модуля «DNS» от панели (применить безопасные серверы / вернуть DHCP / статус).
    private readonly Func<DnsActionDto, (bool Ok, string Details)>? _onDnsAction;
    private readonly Func<DnsStatusDto>? _onDnsQuery;
    // 3.0.0.59: управление антивирусом Windows Defender (панель → служба, вариант C:
    // регистрация в Security Center + fallback Set-MpPreference; брандмауэр не трогаем).
    private readonly Func<DefenderActionDto, DefenderActionResultDto>? _onDefenderAction;
    private readonly Func<DefenderStatusDto>? _onDefenderStatusQuery;
    // 3.0.0.53: онлайн-обновление списков пулов антимайнера + статус (домены/IP/время).
    private readonly Action? _onMinerListsRefresh;
    private readonly Func<string>? _onMinerListsStatus;
    // 3.0.0.66: решение пользователя по алерту Privacy Shield (доверять приложению / завершить процесс).
    private readonly Func<PrivacyShieldResolveDto, bool>? _onPrivacyShieldAction;
    // 3.0.1.5: решение пользователя по алерту AMSI — доверять контент (добавить хэш в amsi-trust.txt).
    private readonly Func<AmsiTrustActionDto, bool>? _onAmsiTrust;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;

    public MonitorPipeServer(Func<MonitorStatusDto> statusProvider, Action? onReload = null,
        Action<bool>? onHoneypotSuspend = null, Action? onRegenerateHoneypot = null,
        Action<string>? onHoneypotDelete = null, Action? onShutdown = null,
        Action<DriveScanAnswerDto>? onDriveScanAnswer = null,
        Action? onAutoStartCheck = null, Func<AutoStartActionDto, bool>? onAutoStartAction = null,
        Func<ShortcutActionDto, bool>? onShortcutAction = null,
        Func<EntropyActionDto, bool>? onEntropyAction = null,
        Func<RansomwareActionDto, bool>? onRansomwareAction = null,
        Func<WinlockActionDto, bool>? onWinlockAction = null,
        Func<EtwActionDto, bool>? onEtwAction = null,
        Func<WmiActionDto, bool>? onWmiAction = null,
        Action? onWmiCheckNow = null,
        Func<FirewallScanActionDto, bool>? onFirewallScanAction = null,
        Func<FirewallRuleActionDto, bool>? onFirewallRuleAction = null,
        Func<PortListenerActionDto, bool>? onPortListenerAction = null,
        Func<AntiStealerActionDto, bool>? onAntiStealerAction = null,
        Func<SpywareActionDto, bool>? onSpywareAction = null,
        Func<MinerActionDto, bool>? onMinerAction = null,
        Func<AnomalyActionDto, bool>? onAnomalyAction = null,
        Func<LolBinActionDto, bool>? onLolBinAction = null,
        Func<ParentChildActionDto, bool>? onParentChildAction = null,
        Func<ExtensionActionDto, (bool Ok, string Message)>? onExtensionAction = null,
        Action? onExtensionScan = null,
        Func<SandboxActionDto, (bool Ok, int SandboxPid, string Error)>? onSandboxAction = null,
        Func<List<SandboxSessionDto>>? onSandboxStatus = null,
        Action<NetworkActivityDto>? onNetworkActivity = null,
        Func<ContextMenuActionDto, bool>? onContextMenuAction = null,
        Func<DnsActionDto, (bool Ok, string Details)>? onDnsAction = null,
        Func<DnsStatusDto>? onDnsQuery = null,
        Action? onMinerListsRefresh = null,
        Func<string>? onMinerListsStatus = null,
        Func<DefenderActionDto, DefenderActionResultDto>? onDefenderAction = null,
        Func<DefenderStatusDto>? onDefenderStatusQuery = null,
        Func<PrivacyShieldResolveDto, bool>? onPrivacyShieldAction = null,
        Func<AmsiTrustActionDto, bool>? onAmsiTrust = null)
    {
        _statusProvider = statusProvider;
        _onReload = onReload;
        _onHoneypotSuspend = onHoneypotSuspend;
        _onRegenerateHoneypot = onRegenerateHoneypot;
        _onHoneypotDelete = onHoneypotDelete;
        _onShutdown = onShutdown;
        _onDriveScanAnswer = onDriveScanAnswer;
        _onAutoStartCheck = onAutoStartCheck;
        _onAutoStartAction = onAutoStartAction;
        _onShortcutAction = onShortcutAction;
        _onEntropyAction = onEntropyAction;
        _onRansomwareAction = onRansomwareAction;
        _onWinlockAction = onWinlockAction;
        _onEtwAction = onEtwAction;
        _onWmiAction = onWmiAction;
        _onWmiCheckNow = onWmiCheckNow;
        _onFirewallScanAction = onFirewallScanAction;
        _onFirewallRuleAction = onFirewallRuleAction;
        _onPortListenerAction = onPortListenerAction;
        _onAntiStealerAction = onAntiStealerAction;
        _onSpywareAction = onSpywareAction;
        _onMinerAction = onMinerAction;
        _onAnomalyAction = onAnomalyAction;
        _onLolBinAction = onLolBinAction;
        _onParentChildAction = onParentChildAction;
        _onExtensionAction = onExtensionAction;
        _onExtensionScan = onExtensionScan;
        _onSandboxAction = onSandboxAction;
        _onSandboxStatus = onSandboxStatus;
        _onNetworkActivity = onNetworkActivity;
        _onContextMenuAction = onContextMenuAction;
        _onDnsAction = onDnsAction;
        _onDnsQuery = onDnsQuery;
        _onPrivacyShieldAction = onPrivacyShieldAction;
        _onAmsiTrust = onAmsiTrust;
        _onMinerListsRefresh = onMinerListsRefresh;
        _onMinerListsStatus = onMinerListsStatus;
        _onDefenderAction = onDefenderAction;
        _onDefenderStatusQuery = onDefenderStatusQuery;
    }

    public void Start()
    {
        _loopTask = Task.Run(AcceptLoopAsync);
    }

    /// <summary>Таймаут чтения одного сообщения — защита от «молчаливого» клиента (C4).</summary>
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(10);

    /// <summary>Таймаут обработки команды и записи ответа (3.0.0.39-fix). ОТДЕЛЬНЫЙ от
    /// таймаута чтения: синхронная обработка долгой команды (например, StartSandbox с
    /// CheckNetIsolation/созданием профиля) не должна обрывать соединение до записи ответа,
    /// иначе панель получает ложное «служба не отвечает» при фактически выполненном действии.</summary>
    private static readonly TimeSpan HandleTimeout = TimeSpan.FromSeconds(60);

    private async Task AcceptLoopAsync()
    {
        // L1: 3-секундная задержка убрана — она гарантировала ложный «служба не отвечает»
        // при первом опросе панели (в логах VM: канал запущен 09:45:19.5, а панель
        // опросила в 09:45:20.7 — канал ещё не принимал соединения). При перезапуске
        // службы старый pipe-сервер освобождается ретраями ниже (ERROR_PIPE_BUSY →
        // экспоненциальная задержка 0.5s→1s→2s→4s, потолок 5s), поэтому отдельная
        // пауза перед первым CreateServer не нужна.
        var retry = 0;
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateServer();
                retry = 0; // канал создан — сбрасываем счётчик ретраев
                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);

                // Каждое соединение обрабатывается в отдельной фоновой задаче: медленный/
                // злонамеренный клиент больше не блокирует канал для остальных (C4).
                var conn = server;
                server = null;
                _ = HandleConnectionAsync(conn, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // Раньше ошибки молча проглатывались, и канал мог не создаваться вовсе,
                // из-за чего панель видела ложный статус «ВЫКЛЮЧЕН» (#6). Теперь логируем.
                // 3.0.0.63: экспоненциальная задержка между попытками (0.5s→1s→2s→4s, потолок 5s)
                // вместо фиксированных 500 мс — не долбим SCM/WMI во время разрыва.
                retry++;
                var delayMs = Math.Min(500 * Math.Pow(2, retry - 1), 5000);
                GuardianLog.Warning(
                    $"Ошибка IPC-канала (попытка {retry}, повтор через {(int)delayMs} мс): " + ex.Message);
                try { await Task.Delay((int)delayMs, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            finally
            {
                server?.Dispose();
            }
        }
    }

    /// <summary>
    /// Обрабатывает одно соединение: чтение с таймаутом, аутентификация клиента
    /// (только elevated-панель CatGuardian), обработка и ответ. Владеет экземпляром канала.
    /// </summary>
    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            IpcProtocol.Message request;
            using (var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
            {
                readCts.CancelAfter(ReadTimeout);
                request = await IpcProtocol.ReadMessageAsync(server, readCts.Token).ConfigureAwait(false);
            }

            var trusted = IpcClientAuthorizer.IsElevatedPanel(server);
            using var handleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            handleCts.CancelAfter(HandleTimeout);
            var response = Handle(request, trusted);
            await IpcProtocol.WriteMessageAsync(server, response, handleCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Таймаут/остановка — соединение закрывается.
        }
        catch (Exception ex) when (IsBrokenPipe(ex))
        {
            // 3.0.1.5-fix: клиент закрыл канал до ответа (Pipe is broken / pipe has been
            // ended) — штатная ситуация, а не ошибка. Понижаем уровень до WARN, чтобы
            // журнал не забивался десятками ERROR при обычной работе панели/CLI.
            GuardianLog.Warning("IPC-соединение закрыто клиентом: " + ex.Message);
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка обработки IPC-соединения", ex);
        }
        finally
        {
            try { server.Dispose(); } catch { /* ignore */ }
        }
    }

    /// <summary>
    /// 3.0.1.5-fix: разорванный канал (клиент закрыл соединение до ответа) — штатная
    /// ситуация, а не ошибка. Распознаём по типу и тексту исключения.
    /// </summary>
    private static bool IsBrokenPipe(Exception ex)
    {
        if (ex is not System.IO.IOException) return false;
        var msg = ex.Message;
        return msg.Contains("Pipe is broken", System.StringComparison.OrdinalIgnoreCase)
            || msg.Contains("pipe has been ended", System.StringComparison.OrdinalIgnoreCase)
            || msg.Contains("pipe is being closed", System.StringComparison.OrdinalIgnoreCase)
            || msg.Contains("Канал закрыт", System.StringComparison.OrdinalIgnoreCase)
            || msg.Contains("разорван", System.StringComparison.OrdinalIgnoreCase);
    }

    // 3.0.0.16.1: канал создаётся через CreateNamedPipe с явным DACL.
    // .NET не позволяет задать PipeSecurity: конструктора с ним нет (.NET Core), а
    // SetAccessControl требует WRITE_DAC на хендле канала — UnauthorizedAccessException
    // даже у elevated-службы(канал тогда вовсе не появлялся). Без явного ACL
    // не-админ CLI-клиенты того же пользователя получали AccessDenied, т.к. дефолтный
    // DACL канала elevated-процесса не пропускает фильтрованный токен.
    // Правила: Interactive Users (панель/CLI без админа) + Administrators + SYSTEM.
    private const int PipeAccessDuplex = 0x3;
    private const int FileFlagOverlapped = 0x40000000;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode,
        uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut,
        ref SecurityAttributes lpSecurityAttributes);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor, uint stringSdRevision, out IntPtr securityDescriptor,
        IntPtr securityDescriptorSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    private static NamedPipeServerStream CreateServer()
    {
        try
        {
            // IU — интерактивные пользователи, BA — администраторы, SY — SYSTEM.
            const string sddl = "D:(A;;GA;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out var pSec, IntPtr.Zero))
            {
                throw new InvalidOperationException(
                    "ConvertStringSecurityDescriptorToSecurityDescriptor: error " + Marshal.GetLastWin32Error());
            }

            try
            {
                var sa = new SecurityAttributes
                {
                    nLength = Marshal.SizeOf<SecurityAttributes>(),
                    lpSecurityDescriptor = pSec,
                    bInheritHandle = false,
                };
                // 3.0.1.3-fix: 16 экземпляров вместо 4 — панель допускает до 8 одновременных
                // IPC-вызовов (ActiveIpcCalls), а Dashboard опрашивает статус каждые 5 с.
                // При 4 занятых соединениях 5-й вызов получал ERROR_PIPE_BUSY (231) →
                // ложный статус «мониторинг выключен» (моргание) и «служба не отвечает».
                var handle = CreateNamedPipe(@"\\.\pipe\" + IpcProtocol.PipeName,
                    (uint)(PipeAccessDuplex | FileFlagOverlapped), 0, 16, 4096, 4096, 0, ref sa);
                if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                {
                    throw new IOException("CreateNamedPipe: error " + Marshal.GetLastWin32Error());
                }

                var safe = new SafePipeHandle(handle, ownsHandle: true);
                return new NamedPipeServerStream(PipeDirection.InOut, isAsync: true,
                    isConnected: false, safePipeHandle: safe);
            }
            finally
            {
                Marshal.FreeHGlobal(pSec);
            }
        }
        catch (Exception aclEx)
        {
            GuardianLog.Warning("IPC: не удалось создать канал с явным ACL (" + aclEx.Message +
                                ") — использую дефолтный");
            return new NamedPipeServerStream(
                IpcProtocol.PipeName, PipeDirection.InOut, 16,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        }
    }

    /// <summary>
    /// Запускает действие в фоне с перехватом исключений. Используется для «тяжёлых»
    /// команд (перезагрузка конфигурации, операции с приманками), чтобы они не блокировали
    /// единственный экземпляр named-pipe и всегда возвращали ответ панели без таймаута.
    /// </summary>
    private static void RunInBackground(Action action)
    {
        _ = Task.Run(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                GuardianLog.Error("Ошибка обработки IPC-команды в фоне", ex);
            }
        });
    }

    /// <summary>
    /// Команды, требующие доверенного вызывающего (elevated-панель CatGuardian).
    /// Ping/Status доступны любому клиенту (для ipc-ping.ps1 и CLI-статуса).
    /// </summary>
    private static bool RequiresTrustedCaller(IpcProtocol.MessageKind kind) => kind switch
    {
        IpcProtocol.MessageKind.Ping or IpcProtocol.MessageKind.Status => false,
        _ => true,
    };

    private IpcProtocol.Message Handle(IpcProtocol.Message request, bool trusted)
    {
        // 3.0.0.17: привилегированные команды (kill по PID, удаление файлов/правил/WMI,
        // остановка службы) принимаются только от elevated-панели CatGuardian. Любая
        // локальная малварь на Medium integrity получает отказ ещё до обработки.
        if (RequiresTrustedCaller(request.Kind) && !trusted)
        {
            GuardianLog.Warning("IPC: отклонена привилегированная команда " + request.Kind +
                                " от недоверенного клиента.");
            return new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.Status,
                Data = "{\"ok\":false,\"error\":\"unauthorized\"}",
            };
        }

        switch (request.Kind)
        {
            case IpcProtocol.MessageKind.Ping:
            case IpcProtocol.MessageKind.Status:
                var status = _statusProvider();
                return new IpcProtocol.Message
                {
                    Kind = IpcProtocol.MessageKind.Status,
                    Data = System.Text.Json.JsonSerializer.Serialize(status, IpcProtocol.JsonOptions),
                };
            case IpcProtocol.MessageKind.ReloadConfig:
                RunInBackground(() => _onReload?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"reloaded\":true}" };
            case IpcProtocol.MessageKind.HoneypotSuspend:
                RunInBackground(() => _onHoneypotSuspend?.Invoke(true));
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"honeypotSuspended\":true}" };
            case IpcProtocol.MessageKind.HoneypotResume:
                RunInBackground(() => _onHoneypotSuspend?.Invoke(false));
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"honeypotResumed\":true}" };
            case IpcProtocol.MessageKind.RegenerateHoneypot:
                // Перегенерация приманок может занимать несколько секунд (создание файлов,
                // правка hosts, перезапуск ETW). Выполняем в фоне, чтобы не блокировать
                // единственный экземпляр канала и не заставлять панель ждать таймаут.
                RunInBackground(() => _onRegenerateHoneypot?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"honeypotRegenerating\":true}" };
            case IpcProtocol.MessageKind.HoneypotDelete:
                RunInBackground(() => _onHoneypotDelete?.Invoke(request.Data ?? ""));
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"honeypotDeleted\":true}" };
            case IpcProtocol.MessageKind.DriveScanAnswer:
                // П.5б: решение пользователя по новому диску из панели.
                try
                {
                    var answer = System.Text.Json.JsonSerializer.Deserialize<DriveScanAnswerDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (answer is not null)
                    {
                        RunInBackground(() => _onDriveScanAnswer?.Invoke(answer));
                    }
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора DriveScanAnswer: " + ex.Message, ex);
                }
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"driveAnswerReceived\":true}" };
            case IpcProtocol.MessageKind.AutoStartCheckNow:
                // 3.0.0.7: «Проверить сейчас» из проактивной защиты.
                RunInBackground(() => _onAutoStartCheck?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"autoStartCheck\":true}" };
            case IpcProtocol.MessageKind.AutoStartAction:
                // 3.0.0.7: решение пользователя по аномалии автозагрузки («Удалить»/«Доверять»).
                // M6: выполняем СИНХРОННО и возвращаем фактический результат (например,
                // пользователь отклонил запрос UAC) — панель показывает исход операции.
                try
                {
                    var action = System.Text.Json.JsonSerializer.Deserialize<AutoStartActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (action is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"autoStartAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onAutoStartAction?.Invoke(action) ?? false;
                    var data = ok
                        ? "{\"autoStartAction\":true,\"ok\":true}"
                        : "{\"autoStartAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора AutoStartAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"autoStartAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.ShortcutAction:
                // 3.0.0.30: решение пользователя по алерту подмены ярлыка («Удалить ярлык»/
                // «Доверять»). Выполняем СИНХРОННО и возвращаем фактический результат.
                try
                {
                    var shortcutAction = System.Text.Json.JsonSerializer.Deserialize<ShortcutActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (shortcutAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"shortcutAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onShortcutAction?.Invoke(shortcutAction) ?? false;
                    var data = ok
                        ? "{\"shortcutAction\":true,\"ok\":true}"
                        : "{\"shortcutAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора ShortcutAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"shortcutAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.EntropyAction:
                // 3.0.0.42: решение пользователя по алерту быстрого анализа энтропии
                // («Восстановить файл» / «Доверять»). Выполняем синхронно.
                try
                {
                    var entropyAction = System.Text.Json.JsonSerializer.Deserialize<EntropyActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (entropyAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"entropyAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var entropyOk = _onEntropyAction?.Invoke(entropyAction) ?? false;
                    var entropyData = entropyOk
                        ? "{\"entropyAction\":true,\"ok\":true}"
                        : "{\"entropyAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = entropyData };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора EntropyAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"entropyAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.RansomwareAction:
                // 3.0.0.8: решение пользователя по алерту шифровальщика («Завершить процесс»/
                // «Очистить приманку»/«Доверять процессу»). Выполняем СИНХРОННО и возвращаем
                // фактический результат — панель показывает исход операции.
                try
                {
                    var ransomAction = System.Text.Json.JsonSerializer.Deserialize<RansomwareActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (ransomAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"ransomwareAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onRansomwareAction?.Invoke(ransomAction) ?? false;
                    var data = ok
                        ? "{\"ransomwareAction\":true,\"ok\":true}"
                        : "{\"ransomwareAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора RansomwareAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"ransomwareAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.WinlockAction:
                // 3.0.0.20: решение пользователя по алерту Winlock Protection
                // («Восстановить и доверять» / «Оставить изолированным»). Выполняем
                // СИНХРОННО и возвращаем фактический результат — панель показывает исход.
                try
                {
                    var winlockAction = System.Text.Json.JsonSerializer.Deserialize<WinlockActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (winlockAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"winlockAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onWinlockAction?.Invoke(winlockAction) ?? false;
                    var data = ok
                        ? "{\"winlockAction\":true,\"ok\":true}"
                        : "{\"winlockAction\":true,\"ok\":false,\"error\":\"операция не выполнена (монитор автозагрузки недоступен)\"}";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора WinlockAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"winlockAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.AntiStealerAction:
                // 3.0.0.16: решение пользователя по алерту Anti-Stealer («Убить процесс»/
                // «Разрешить (Доверять)»). Выполняем СИНХРОННО и возвращаем фактический
                // результат — панель показывает исход операции.
                try
                {
                    var antiStealerAction = System.Text.Json.JsonSerializer.Deserialize<AntiStealerActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (antiStealerAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"antiStealerAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onAntiStealerAction?.Invoke(antiStealerAction) ?? false;
                    var data = ok
                        ? "{\"antiStealerAction\":true,\"ok\":true}"
                        : "{\"antiStealerAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора AntiStealerAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"antiStealerAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.SpywareAction:
                // 3.0.0.85: решение пользователя по алерту Anti-Spyware
                // («Завершить» / «Доверять» / «Заблокировать»). Синхронно, с фактическим
                // результатом — панель показывает исход операции.
                try
                {
                    var spywareAction = System.Text.Json.JsonSerializer.Deserialize<SpywareActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (spywareAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"spywareAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onSpywareAction?.Invoke(spywareAction) ?? false;
                    var data = ok
                        ? "{\"spywareAction\":true,\"ok\":true}"
                        : "{\"spywareAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора SpywareAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"spywareAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.EtwAction:
                // 3.0.0.12: решение пользователя по ETW-алерту («Завершить процесс»).
                // Выполняем СИНХРОННО и возвращаем фактический результат — как RansomwareAction.
                try
                {
                    var etwAction = System.Text.Json.JsonSerializer.Deserialize<EtwActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (etwAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"etwAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onEtwAction?.Invoke(etwAction) ?? false;
                    var data = ok
                        ? "{\"etwAction\":true,\"ok\":true}"
                        : "{\"etwAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора EtwAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"etwAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.MinerAction:
                // 3.0.0.23: решение пользователя по алерту антимайнера
                // (завершить / разморозить и доверять / доверять). Синхронно + фактический результат.
                try
                {
                    var minerAction = System.Text.Json.JsonSerializer.Deserialize<MinerActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (minerAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"minerAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok2 = _onMinerAction?.Invoke(minerAction) ?? false;
                    var data2 = ok2
                        ? "{\"minerAction\":true,\"ok\":true}"
                        : "{\"minerAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data2 };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора MinerAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"minerAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.SandboxAction:
                // 3.0.0.39: решение пользователя по алерту песочницы (Restricted-Token Execution):
                // запустить в песочнице / завершить / доверять / пропустить / снять изоляцию.
                try
                {
                    var sandboxAction = System.Text.Json.JsonSerializer.Deserialize<SandboxActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (sandboxAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"sandboxAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var (okS, pidS, errS) = _onSandboxAction?.Invoke(sandboxAction) ?? (false, 0, Tr.T("Svc2344"));
                    var safeS = (errS ?? "").Replace("\"", "'");
                    var dataS = okS
                        ? "{\"sandboxAction\":true,\"ok\":true,\"sandboxPid\":" + pidS + "}"
                        : "{\"sandboxAction\":true,\"ok\":false,\"sandboxPid\":0,\"error\":\"" + safeS + "\"}";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataS };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора SandboxAction: " + ex.Message, ex);
                    var safeX = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"sandboxAction\":true,\"ok\":false,\"error\":\"" + safeX + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.SandboxStatusQuery:
                // 3.0.0.39: список активных сессий песочницы для панели.
                try
                {
                    var sessions = _onSandboxStatus?.Invoke() ?? new List<SandboxSessionDto>();
                    var dataQ = System.Text.Json.JsonSerializer.Serialize(sessions, IpcProtocol.JsonOptions);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataQ };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка SandboxStatusQuery: " + ex.Message, ex);
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "[]",
                    };
                }
            case IpcProtocol.MessageKind.AnomalyAction:
                // 3.0.0.24: решение пользователя по алерту «Контроля скрытой активности
                // и аномалий» (доверять пути / удалить правило). Синхронно + фактический результат.
                try
                {
                    var anomalyAction = System.Text.Json.JsonSerializer.Deserialize<AnomalyActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (anomalyAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"anomalyAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okA = _onAnomalyAction?.Invoke(anomalyAction) ?? false;
                    var dataA = okA
                        ? "{\"anomalyAction\":true,\"ok\":true}"
                        : "{\"anomalyAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataA };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора AnomalyAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"anomalyAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.LolBinAction:
                // 3.0.0.33+: решение пользователя по LOLBins-алерту (завершить/доверять
                // артефакту). Синхронно + фактический результат (панель обновляет кнопки).
                try
                {
                    var lolBinAction = System.Text.Json.JsonSerializer.Deserialize<LolBinActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (lolBinAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"lolBinAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okL = _onLolBinAction?.Invoke(lolBinAction) ?? false;
                    var dataL = okL
                        ? "{\"lolBinAction\":true,\"ok\":true}"
                        : "{\"lolBinAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataL };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора LolBinAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"lolBinAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.ExtensionAction:
                // 3.0.0.38: решение пользователя по алерту Malicious Extension Watchdog
                // (Доверять / Отключить / Удалить). Синхронно + фактический результат.
                try
                {
                    var extensionAction = System.Text.Json.JsonSerializer.Deserialize<ExtensionActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (extensionAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"extensionAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var resExt = _onExtensionAction?.Invoke(extensionAction)
                                 ?? (false, "операция не выполнена (модуль выключен)");
                    var safeMsg = (resExt.Message ?? "").Replace("\\", "\\\\").Replace("\"", "'");
                    var dataExt = resExt.Ok
                        ? $"{{\"extensionAction\":true,\"ok\":true,\"message\":\"{safeMsg}\"}}"
                        : $"{{\"extensionAction\":true,\"ok\":false,\"error\":\"{safeMsg}\"}}";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataExt };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора ExtensionAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\\", "\\\\").Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"extensionAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.ExtensionScan:
                // 3.0.0.38: «Проверить сейчас» — немедленная проверка расширений браузера.
                RunInBackground(() => _onExtensionScan?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"extensionScan\":true}" };
            case IpcProtocol.MessageKind.ParentChildAction:
                // 3.0.0.37+: решение пользователя по алерту «Аномальные родительские связи»
                // (завершить процесс/доверять родителю). Синхронно + фактический результат.
                try
                {
                    var parentChildAction = System.Text.Json.JsonSerializer.Deserialize<ParentChildActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (parentChildAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"parentChildAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okPc = _onParentChildAction?.Invoke(parentChildAction) ?? false;
                    var dataPc = okPc
                        ? "{\"parentChildAction\":true,\"ok\":true}"
                        : "{\"parentChildAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataPc };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора ParentChildAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"parentChildAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.WmiAction:
                // 3.0.0.13: решение пользователя по WMI-алерту («Удалить объект»).
                // Выполняем СИНХРОННО (UAC) и возвращаем фактический результат.
                try
                {
                    var wmiAction = System.Text.Json.JsonSerializer.Deserialize<WmiActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (wmiAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"wmiAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var ok = _onWmiAction?.Invoke(wmiAction) ?? false;
                    var data = ok
                        ? "{\"wmiAction\":true,\"ok\":true}"
                        : "{\"wmiAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = data };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора WmiAction: " + ex.Message, ex);
                    var safe = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"wmiAction\":true,\"ok\":false,\"error\":\"" + safe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.WmiCheckNow:
                // 3.0.0.13: «Проверить сейчас» из проактивной защиты.
                RunInBackground(() => _onWmiCheckNow?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"wmiCheckNow\":true}" };
            case IpcProtocol.MessageKind.FirewallScanAction:
                // 3.0.0.14: решение пользователя по алерту сканера («Завершить процесс»/«Доверять»).
                // Выполняем СИНХРОННО и возвращаем фактический результат.
                try
                {
                    var scanAction = System.Text.Json.JsonSerializer.Deserialize<FirewallScanActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (scanAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"firewallScanAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okScan = _onFirewallScanAction?.Invoke(scanAction) ?? false;
                    var dataScan = okScan
                        ? "{\"firewallScanAction\":true,\"ok\":true}"
                        : "{\"firewallScanAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataScan };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора FirewallScanAction: " + ex.Message, ex);
                    var safeScan = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"firewallScanAction\":true,\"ok\":false,\"error\":\"" + safeScan + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.PortListenerAction:
                // 3.0.0.31: решение пользователя по алерту слушающего порта
                // («Завершить процесс»/«Доверять»). Выполняем СИНХРОННО.
                try
                {
                    var plAction = System.Text.Json.JsonSerializer.Deserialize<PortListenerActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (plAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"portListenerAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okPl = _onPortListenerAction?.Invoke(plAction) ?? false;
                    var dataPl = okPl
                        ? "{\"portListenerAction\":true,\"ok\":true}"
                        : "{\"portListenerAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataPl };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора PortListenerAction: " + ex.Message, ex);
                    var safePl = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"portListenerAction\":true,\"ok\":false,\"error\":\"" + safePl + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.FirewallRuleAction:
                // 3.0.0.14: решение пользователя по алерту правила («Удалить правило»/«Доверять»).
                // Выполняем СИНХРОННО (UAC) и возвращаем фактический результат.
                try
                {
                    var ruleAction = System.Text.Json.JsonSerializer.Deserialize<FirewallRuleActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (ruleAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"firewallRuleAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var okRule = _onFirewallRuleAction?.Invoke(ruleAction) ?? false;
                    var dataRule = okRule
                        ? "{\"firewallRuleAction\":true,\"ok\":true}"
                        : "{\"firewallRuleAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dataRule };
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора FirewallRuleAction: " + ex.Message, ex);
                    var safeRule = ex.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"firewallRuleAction\":true,\"ok\":false,\"error\":\"" + safeRule + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.NetworkActivity:
                // 3.0.0.10: PID'ы с исходящей сетевой активностью из брандмауэра панели —
                // взводим сетевые флаги в ProcessRegistry для Pre-Scan скоринга.
                try
                {
                    var net = System.Text.Json.JsonSerializer.Deserialize<NetworkActivityDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (net is not null && net.Pids.Count > 0)
                    {
                        RunInBackground(() => _onNetworkActivity?.Invoke(net));
                    }
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("Ошибка разбора NetworkActivity: " + ex.Message, ex);
                }
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"networkActivity\":true}" };
            case IpcProtocol.MessageKind.ContextMenuAction:
                // 3.0.0.19: включение/отключение пункта контекстного меню Проводника
                // (Shell Extension). Служба выполняет запись/удаление веток HKLM синхронно
                // и возвращает {"ok":bool,"error":...} — панель показывает фактический исход.
                try
                {
                    var ctxDto = System.Text.Json.JsonSerializer.Deserialize<ContextMenuActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (ctxDto is null)
                    {
                        return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"contextMenuAction\":true,\"ok\":false,\"error\":\"" };
                    }

                    bool ctxOk = _onContextMenuAction?.Invoke(ctxDto) == true;
                    string ctxData = ctxOk
                        ? "{\"contextMenuAction\":true,\"ok\":true}"
                        : "{\"contextMenuAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = ctxData };
                }
                catch (Exception cmEx)
                {
                    var safeCtx = System.Net.WebUtility.HtmlEncode(cmEx.Message);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"contextMenuAction\":true,\"ok\":false,\"error\":\"" + safeCtx + "\"}" };
                }
            case IpcProtocol.MessageKind.DefenderAction:
                // 3.0.0.59: включение/отключение антивируса Windows Defender (только AV-часть,
                // брандмауэр mpssvc не трогаем). Служба (SYSTEM) выполняет операцию синхронно
                // и возвращает фактический результат, включая состояние Tamper Protection.
                try
                {
                    var defDto = System.Text.Json.JsonSerializer.Deserialize<DefenderActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (defDto is null)
                    {
                        return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"ok\":false,\"error\":\"" };
                    }

                    var defResult = _onDefenderAction?.Invoke(defDto)
                        ?? new DefenderActionResultDto { Ok = false, Error = Tr.T("Svc2344") };
                    var defJson = System.Text.Json.JsonSerializer.Serialize(defResult, IpcProtocol.JsonOptions);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = defJson };
                }
                catch (Exception defEx)
                {
                    GuardianLog.Error("Ошибка DefenderAction: " + defEx.Message, defEx);
                    var safeDef = defEx.Message.Replace("\"", "'");
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"ok\":false,\"error\":\"" + safeDef + "\"}" };
                }
            case IpcProtocol.MessageKind.DefenderStatusQuery:
                // 3.0.0.59: статус антивируса Windows Defender для индикатора в настройках.
                try
                {
                    var defStatus = _onDefenderStatusQuery?.Invoke()
                        ?? new DefenderStatusDto { Available = false };
                    var statusJson = System.Text.Json.JsonSerializer.Serialize(defStatus, IpcProtocol.JsonOptions);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = statusJson };
                }
                catch (Exception stEx)
                {
                    GuardianLog.Error("Ошибка DefenderStatusQuery: " + stEx.Message, stEx);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"available\":false}" };
                }
            case IpcProtocol.MessageKind.DnsAction:
                // 3.0.0.19: применение безопасных DNS / возврат DHCP на всех активных адаптерах
                // (модуль «DNS»). Служба выполняет операцию через WMI синхронно и возвращает
                // {"ok":bool,"error":...} — панель показывает фактический исход.
                try
                {
                    var dnsDto = System.Text.Json.JsonSerializer.Deserialize<DnsActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (dnsDto is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = System.Text.Json.JsonSerializer.Serialize(new
                            {
                                dnsAction = true,
                                ok = false,
                                error = "не удалось разобрать запрос",
                                details = "",
                            }, IpcProtocol.JsonOptions),
                        };
                    }

                    var (dnsOk, dnsDetails) = _onDnsAction?.Invoke(dnsDto) ?? (false, Tr.T("Svc2344"));
                    // Сериализуем JSON корректно (без HtmlEncode — он давал мусор ').
                    string dnsData = System.Text.Json.JsonSerializer.Serialize(new
                    {
                        dnsAction = true,
                        ok = dnsOk,
                        error = dnsOk ? "" : Tr.T("Svc2345"),
                        details = dnsDetails.Replace("\r", " ").Replace("\n", " · "),
                    }, IpcProtocol.JsonOptions);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = dnsData };
                }
                catch (Exception dnsEx)
                {
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = System.Text.Json.JsonSerializer.Serialize(new
                        {
                            dnsAction = true,
                            ok = false,
                            error = dnsEx.Message,
                            details = "",
                        }, IpcProtocol.JsonOptions),
                    };
                }
            case IpcProtocol.MessageKind.DnsQuery:
                // 3.0.0.19: текущий статус DNS активных адаптеров (модуль «DNS»).
                try
                {
                    var dnsStatus = _onDnsQuery?.Invoke() ?? new DnsStatusDto { Error = Tr.T("Svc2344") };
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = System.Text.Json.JsonSerializer.Serialize(dnsStatus, IpcProtocol.JsonOptions),
                    };
                }
                catch (Exception dnsQEx)
                {
                    GuardianLog.Error("Ошибка запроса статуса DNS: " + dnsQEx.Message, dnsQEx);
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = System.Text.Json.JsonSerializer.Serialize(
                            new DnsStatusDto { Error = dnsQEx.Message }, IpcProtocol.JsonOptions),
                    };
                }
            case IpcProtocol.MessageKind.MinerListsRefresh:
                // 3.0.0.53: «Обновить списки» — онлайн-загрузка списков пулов в фоне.
                RunInBackground(() => _onMinerListsRefresh?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"minerListsRefreshing\":true}" };
            case IpcProtocol.MessageKind.MinerListsStatus:
                // 3.0.0.53: статус списков антимайнера (домены/IP/время обновления/ошибка).
                try
                {
                    var minerListsJson = _onMinerListsStatus?.Invoke() ?? "{}";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = minerListsJson };
                }
                catch (Exception minerListEx)
                {
                    GuardianLog.Error("Ошибка запроса статуса списков антимайнера: " + minerListEx.Message, minerListEx);
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{}" };
                }
            case IpcProtocol.MessageKind.PrivacyShieldAction:
                // 3.0.0.66: решение пользователя по алерту Privacy Shield
                // («Доверять приложению» / «Завершить процесс»). Синхронно + фактический результат.
                try
                {
                    var psAction = System.Text.Json.JsonSerializer.Deserialize<PrivacyShieldResolveDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (psAction is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"privacyShieldAction\":true,\"ok\":false,\"error\":\"",
                        };
                    }

                    var psOk = _onPrivacyShieldAction?.Invoke(psAction) ?? false;
                    var psData = psOk
                        ? "{\"privacyShieldAction\":true,\"ok\":true}"
                        : "{\"privacyShieldAction\":true,\"ok\":false,\"error\":\"";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = psData };
                }
                catch (Exception psEx)
                {
                    GuardianLog.Error("Ошибка разбора PrivacyShieldAction: " + psEx.Message, psEx);
                    var psSafe = psEx.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"privacyShieldAction\":true,\"ok\":false,\"error\":\"" + psSafe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.AmsiTrustAction:
                // 3.0.1.5: «Доверять этот контент» — добавляем хэш в amsi-trust.txt,
                // чтобы AMSI больше не блокировал этот скриптовый контент.
                try
                {
                    var amsiTrust = System.Text.Json.JsonSerializer.Deserialize<AmsiTrustActionDto>(
                        request.Data ?? "", IpcProtocol.JsonOptions);
                    if (amsiTrust is null)
                    {
                        return new IpcProtocol.Message
                        {
                            Kind = IpcProtocol.MessageKind.Status,
                            Data = "{\"amsiTrustAction\":true,\"ok\":false,\"error\":\"пустой запрос\"}",
                        };
                    }
                    var atOk = _onAmsiTrust?.Invoke(amsiTrust) ?? false;
                    var atData = atOk
                        ? "{\"amsiTrustAction\":true,\"ok\":true}"
                        : "{\"amsiTrustAction\":true,\"ok\":false,\"error\":\"не удалось добавить в список доверенных\"}";
                    return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = atData };
                }
                catch (Exception atEx)
                {
                    GuardianLog.Error("Ошибка разбора AmsiTrustAction: " + atEx.Message, atEx);
                    var atSafe = atEx.Message.Replace("\"", "'");
                    return new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = "{\"amsiTrustAction\":true,\"ok\":false,\"error\":\"" + atSafe + "\"}",
                    };
                }
            case IpcProtocol.MessageKind.Shutdown:
                // Полная остановка резидент-службы (MonitorHost + AntivirusRunner),
                // а не только завершение цикла приёма pipe.
                _cts.Cancel();
                RunInBackground(() => _onShutdown?.Invoke());
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"running\":false}" };
            default:
                return new IpcProtocol.Message { Kind = IpcProtocol.MessageKind.Status, Data = "{\"running\":true}" };
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loopTask?.Wait(2000); } catch { /* ignore */ }
        _cts.Dispose();
    }
}