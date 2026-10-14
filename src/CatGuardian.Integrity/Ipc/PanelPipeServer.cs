using System;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace CatGuardian.Integrity.Ipc;

/// <summary>
/// Named pipe сервер панели управления для обратного канала «служба → панель» (п.5б).
/// Служба подключается как клиент и передаёт панели вопросы пользователю
/// (например, «Сканировать новый диск?» или VirusAlert). Обработчик вызывается в фоновом
/// потоке — панель сама перебрасывает показ диалога в UI-поток через Dispatcher.
///
/// ПОЧЕМУ НУЖЕН ЯВНЫЙ SDDL (3.0.0.16.1): этот канал создаёт ПАНЕЛЬ (CatGuardian.UI,
/// манифест requireAdministrator → High integrity), а подключается к нему СЛУЖБА
/// (CatGuardian.Service, asInvoker → Medium integrity). Дефолтный DACL канала
/// high-integrity процесса не содержит правила для medium-токена службы, поэтому UIPI
/// блокирует доступ medium→high: NamedPipeClientStream.Connect возвращает
/// ERROR_FILE_NOT_FOUND, PanelPipeClient.TrySend молча возвращает false, и алерт теряется
/// (диалог VirusAlert не появляется). Явный SDDL "D:(A;;GA;;;IU)(A;;GA;;;BA)(A;;GA;;;SY)"
/// даёт полный доступ Interactive Users (служба под интерактивным пользователем),
/// Administrators и SYSTEM — та же схема, что в MonitorPipeServer.CreateServer(
/// канал без явного ACL не видели клиенты с фильтрованным токеном).
/// </summary>
public sealed class PanelPipeServer : IDisposable
{
    private readonly Action<IpcProtocol.Message> _onMessage;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;

    public PanelPipeServer(Action<IpcProtocol.Message> onMessage)
    {
        _onMessage = onMessage;
    }

    public void Start()
    {
        _loopTask = Task.Run(AcceptLoopAsync);
    }

    /// <summary>Таймаут чтения одного сообщения — защита от «молчаливого» клиента.</summary>
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(10);

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateServer();
                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);

                // Каждое соединение обрабатывается в отдельной фоновой задаче.
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
                // Ошибки приёма не роняют панель: повторяем попытку через 500 мс.
                GuardianLog.Error("PanelPipeServer: ошибка IPC-канала (повтор через 500 мс)", ex);
                try { await Task.Delay(500, _cts.Token).ConfigureAwait(false); }
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
    /// (только CatGuardian.Service), фоновый вызов обработчика и ответ. Владеет каналом.
    /// </summary>
    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ReadTimeout);

            var request = await IpcProtocol.ReadMessageAsync(server, timeout.Token).ConfigureAwait(false);

            // 3.0.0.17: алерты «служба → панель» принимаются ТОЛЬКО от процесса
            // CatGuardian.Service. Раньше любой процесс интерактивного пользователя мог
            // слать панели фейковые VirusAlert/AskScanDrive (UI-спуфинг).
            if (!IpcClientAuthorizer.IsTrustedClient(server, "CatGuardian.Service"))
            {
                GuardianLog.Warning("PanelPipeServer: отклонено сообщение от недоверенного клиента.");
                await IpcProtocol.WriteMessageAsync(server, new IpcProtocol.Message
                {
                    Kind = IpcProtocol.MessageKind.Status,
                    Data = "{\"received\":false}",
                }, timeout.Token).ConfigureAwait(false);
                return;
            }

            // Обработка в фоне: показ диалога не должен блокировать приём канала.
            RunInBackground(() => _onMessage?.Invoke(request));

            // Короткий ответ-подтверждение, чтобы клиент (служба) не ждал таймаут.
            await IpcProtocol.WriteMessageAsync(server, new IpcProtocol.Message
            {
                Kind = IpcProtocol.MessageKind.Status,
                Data = "{\"received\":true}",
            }, timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Таймаут/остановка — соединение закрывается.
        }
        catch (Exception ex)
        {
            GuardianLog.Error("PanelPipeServer handler: " + ex.Message, ex);
        }
        finally
        {
            try { server.Dispose(); } catch { /* ignore */ }
        }
    }

    // 3.0.0.16.1: канал создаётся через CreateNamedPipe с явным DACL — копия логики
    // MonitorPipeServer.CreateServer (механизм проверен на живой системе).
    // .NET не позволяет задать PipeSecurity: конструктора с ним нет (.NET Core), а
    // SetAccessControl требует WRITE_DAC на хендле канала — UnauthorizedAccessException
    // даже у elevated-процесса(канал тогда вовсе не появлялся). Без явного ACL
    // служба (Medium integrity) не может открыть канал панели (High integrity): UIPI
    // блокирует medium→high, Connect → ERROR_FILE_NOT_FOUND, алерт молча теряется.
    // Правила: Interactive Users (служба под интерактивным пользователем) +
    // Administrators (elevated-панель) + SYSTEM.
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
                // 3.0.1.3-fix: 16 экземпляров вместо 4 — служба может слать несколько алертов
                // одновременно (SandboxAlert + AskScanDrive + PrivacyShield), при 4 занятых
                // соединениях служба получала ERROR_PIPE_BUSY → «панель недоступна» и алерт
                // уходил в очередь даже при открытой панели.
                var handle = CreateNamedPipe(@"\\.\pipe\" + IpcProtocol.PanelPipeName,
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
            // Запасной вариант как в MonitorPipeServer: если создать канал с явным ACL не удалось,
            // используем дефолтный — хуже, чем ничего (канал хотя бы появится для панели).
            GuardianLog.Warning("PanelPipeServer: не удалось создать канал с явным ACL (" + aclEx.Message +
                                ") — использую дефолтный");
            return new NamedPipeServerStream(
                IpcProtocol.PanelPipeName, PipeDirection.InOut, 16,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        }
    }

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
                GuardianLog.Error("PanelPipeServer handler: " + ex.Message, ex);
            }
        });
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loopTask?.Wait(2000); } catch { /* ignore */ }
        _cts.Dispose();
    }
}