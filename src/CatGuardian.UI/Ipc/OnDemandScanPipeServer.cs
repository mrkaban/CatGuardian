using System;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using Microsoft.Win32.SafeHandles;

namespace CatGuardian.UI.Ipc;

/// <summary>
/// Named pipe сервер панели для канала «второй экземпляр → работающая панель» (3.0.0.19).
/// Когда Windows запускает CatGuardian.exe "путь" из контекстного меню Проводника, а панель
/// уже работает, второй экземпляр упирается в мьютекс одиночного экземпляра и молча
/// завершался — путь терялся, диалог сканирования не появлялся. Теперь второй экземпляр
/// отправляет путь по этому каналу, а первый показывает окно и запускает проверку.
/// Обработчик вызывается в фоновом потоке — панель сама перебрасывает вызов в UI через Dispatcher.
/// </summary>
public sealed class OnDemandScanPipeServer : IDisposable
{
    private readonly Action<string> _onPath;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loopTask;

    /// <summary>
    /// 3.0.0.98: запрос второго экземпляра панели «показать главное окно» (панель скрыта
    /// в humble-режиме). Вызывается в фоновом потоке канала — подписчик сам перебрасывает
    /// вызов в UI-поток. Повторный запуск CatGuardian.exe из Пуска/ярлыка при свёрнутом
    /// окне должен возвращать окно, как клик по иконке трея.
    /// </summary>
    public event Action? ShowPanelRequested;

    public OnDemandScanPipeServer(Action<string> onPath)
    {
        _onPath = onPath;
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
            catch (Exception)
            {
                // Канал могут временно занять другие экземпляры — повторяем через 500 мс.
                try { await Task.Delay(500, _cts.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }
            finally
            {
                server?.Dispose();
            }
        }
    }

    private async Task HandleConnectionAsync(NamedPipeServerStream server, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(ReadTimeout);

            var request = await IpcProtocol.ReadMessageAsync(server, timeout.Token).ConfigureAwait(false);
            if (request.Kind == IpcProtocol.MessageKind.OnDemandScan && !string.IsNullOrWhiteSpace(request.Data))
            {
                var path = request.Data;
                _ = Task.Run(() =>
                {
                    try { _onPath?.Invoke(path); }
                    catch (Exception ex) { GuardianLog.Error("OnDemandScan handler: " + ex.Message, ex); }
                });
            }
            // 3.0.0.98: второй экземпляр просит показать скрытое окно (см. TryShowPanelToExistingInstance).
            else if (request.Kind == IpcProtocol.MessageKind.PanelShow)
            {
                ShowPanelRequested?.Invoke();
            }

            // Короткий ответ-подтверждение, чтобы клиент (второй экземпляр) не ждал таймаут.
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
            GuardianLog.Error("OnDemandScan handler: " + ex.Message, ex);
        }
        finally
        {
            try { server.Dispose(); } catch { /* ignore */ }
        }
    }

    // ---- Создание канала с явным DACL (копия PanelPipeServer.CreateServer) ----
    // Второй экземпляр — тот же процесс CatGuardian.exe (elevated), но клиентом может быть
    // и обычный процесс пользователя; SDDL даёт доступ Interactive Users + Administrators + SYSTEM.
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
                // 3.0.1.3-fix: 16 экземпляров вместо 4 — несколько CLI-запросов (сканирование
                // по контекстному меню) одновременно с IPC-опросами панели не должны
                // получать ERROR_PIPE_BUSY.
                var handle = CreateNamedPipe(@"\\.\pipe\" + IpcProtocol.OnDemandScanPipeName,
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
            GuardianLog.Warning("OnDemandScan: не удалось создать канал с явным ACL (" + aclEx.Message +
                                ") — использую дефолтный");
            return new NamedPipeServerStream(
                IpcProtocol.OnDemandScanPipeName, PipeDirection.InOut, 16,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loopTask?.Wait(2000); } catch { /* ignore */ }
        _cts.Dispose();
    }
}