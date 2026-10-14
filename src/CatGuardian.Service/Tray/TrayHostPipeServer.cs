using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using Microsoft.Win32.SafeHandles;

namespace CatGuardian.Service.Tray;

/// <summary>
/// Named pipe сервер «хост трея → служба» (3.0.0.58-trayhost).
/// Фиксированное имя канала <see cref="IpcProtocol.TrayHostPipeName"/> (
/// «случайное имя канала» не является секретом — границей безопасности служит
/// авторизация IsTrustedTrayHost: путь = installDir\CatGuardian.TrayHost.exe +
/// ProcessName = CatGuardian.TrayHost). DACL как у PanelPipeServer: IU/BA/SY.
///
/// Allowlist команд:
///  - open_panel(page) — страницы строго из whitelist MainWindow.NavigateTo:
///    dashboard|inspector|firewall|antivirus|update|settings|about (+ пустое = dashboard).
///    Ответ {"ok":false,"error":"need_runas"} — хост запускает панель через UAC.
///  - toggle_monitoring — переключение monitor_enabled + push status_changed.
///  - exit — штатная остановка службы (panel_exit_requested=true, RequestShutdown).
///  - get_status — JSON статуса для иконки цвет/серая.
///
/// Push службы → хост (доставляется в том же соединении между командами):
///  - {"push":"status_changed","status":{...}}
///  - {"push":"events_changed","count":N}
///  - {"push":"alert","title":..,"text":..}
/// Запись ответа и push сериализуется lock'ом на соединение — гонок нет.
/// </summary>
public sealed class TrayHostPipeServer : IDisposable
{
    private const int PipeAccessDuplex = 0x3;
    private const int FileFlagOverlapped = 0x40000000;
    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(30);

    private readonly CancellationTokenSource _cts = new();
    private readonly object _clientsSync = new();
    private readonly List<ClientConnection> _clients = new();

    // Делегаты, настраиваемые ServiceHost.
    /// <summary>open_panel(page): возвращает "" при успехе, "need_runas" — панель требует UAC.</summary>
    public Func<string, string>? OpenPanelHandler;

    /// <summary>toggle_monitoring: переключает monitor_enabled (останавливает/подтверждает службу).</summary>
    public Action? ToggleMonitoringHandler;

    /// <summary>clipboard_alert (3.0.0.63): детект чувствительных данных в буфере из ИНТЕРАКТИВНОЙ
    /// сессии. Наблюдатель (message-only окно + AddClipboardFormatListener) живёт в хосте трея —
    /// SCM-служба в сессии 0 не получает WM_CLIPBOARDUPDATE пользовательской сессии. Служба
    /// принимает результат и выполняет обязанности по алерту (событие/лог/панель).
    /// Возвращает "" при принятии, текст ошибки — при отказе (модуль выключен и т.п.).</summary>
    public Func<string, string, string, string>? ClipboardAlertHandler;

    /// <summary>exit: штатная остановка комплекса.</summary>
    public Action? ExitHandler;

    /// <summary>get_status: JSON статуса {"running":bool,"version":..,"monitoringEnabled":bool}.</summary>
    public Func<string>? StatusHandler;

    private Thread? _loopThread;

    public void Start()
    {
        // O2 (3.0.1.4): выделенный поток вместо Task.Run — на старте службы пул потоков
        // перегружен инициализацией, и AcceptLoopAsync ждал свободный поток (в логах VM
        // TRAYHOST-IPC канал создан 13:19:13, но хост трея подключился только 13:20:39 —
        // accept не стартовал, иконка была серой ~85 с). Выделенный поток не зависит
        // от пула — канал принимает подключения сразу.
        _loopThread = new Thread(() =>
        {
            try { AcceptLoopAsync().GetAwaiter().GetResult(); }
            catch { /* цикл сам обрабатывает ошибки */ }
        })
        {
            IsBackground = true,
            Name = "TrayHostPipeAccept",
        };
        _loopThread.Start();
    }

    // ---------------------------------------------------------------
    // Push (служба → хост)
    // ---------------------------------------------------------------

    public void PushStatusChanged(bool running, string version, bool monitoringEnabled)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["push"] = "status_changed",
            ["status"] = new Dictionary<string, object?>
            {
                ["running"] = running,
                ["version"] = version,
                ["monitoringEnabled"] = monitoringEnabled,
            },
        }, IpcProtocol.JsonOptions);
        Push(payload);
    }

    public void PushEventsChanged(long count)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["push"] = "events_changed",
            ["count"] = count,
        }, IpcProtocol.JsonOptions);
        Push(payload);
    }

    /// <summary>
    /// Push-алерт хосту трея. alertKind — числовой MessageKind (3.0.0.63):
    /// хост по нему решает, показывать ли POPUP (алерт требует решения) или только
    /// баллун (информационные виды, например PrivacyShieldAlert).
    /// </summary>
    public void PushAlert(string title, string text, int? alertKind = null)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["push"] = "alert",
            ["title"] = title,
            ["text"] = text,
            ["alertKind"] = alertKind,
        }, IpcProtocol.JsonOptions);
        Push(payload);
    }

    /// <summary>
    /// 3.0.0.93: push «алерт снят» — хост трея закрывает POPUP этого вида (алерт
    /// стал неактуален, например извлекли флэшку, о которой спрашивали).
    /// </summary>
    public void PushAlertDismiss(int? alertKind = null)
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["push"] = "alert_dismiss",
            ["alertKind"] = alertKind,
        }, IpcProtocol.JsonOptions);
        Push(payload);
    }

    /// <summary>
    /// 3.0.1.5: штатное обновление конфигурации (ReloadConfig) — хост трея показывает
    /// информационный баллун «настройки применены» вместо тревожного «мониторинг выключен».
    /// </summary>
    public void PushConfigReloaded()
    {
        var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["push"] = "config_reloaded",
        }, IpcProtocol.JsonOptions);
        Push(payload);
    }

    private void Push(string payload)
    {
        List<ClientConnection> snapshot;
        lock (_clientsSync)
        {
            snapshot = new List<ClientConnection>(_clients);
        }

        foreach (var client in snapshot)
        {
            client.TryPush(payload);
        }
    }

    // ---------------------------------------------------------------
    // Цикл приёма
    // ---------------------------------------------------------------

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = CreateServer();
                await server.WaitForConnectionAsync(_cts.Token).ConfigureAwait(false);

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
                GuardianLog.Error("TrayHostPipeServer: ошибка IPC-канала (повтор через 500 мс)", ex);
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
        // Авторизация ДО обработки команд: только легитимный хост из каталога установки.
        if (!IpcClientAuthorizer.IsTrustedTrayHost(server, GuardianPaths.ProcessDirectory))
        {
            GuardianLog.Warning("TrayHostPipeServer: отклонено соединение недоверенного клиента.");
            try { server.Dispose(); } catch { /* ignore */ }
            return;
        }

        var connection = new ClientConnection(server);
        lock (_clientsSync)
        {
            _clients.Add(connection);
        }

        try
        {
            GuardianLog.Info("TRAYHOST-IPC: хост трея подключился.");
            while (!ct.IsCancellationRequested)
            {
                IpcProtocol.Message request;
                try
                {
                    using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    readCts.CancelAfter(ReadTimeout);
                    request = await IpcProtocol.ReadMessageAsync(server, readCts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break; // таймаут ожидания команды — соединение закрывается (клиент ушёл)
                }
                catch (EndOfStreamException)
                {
                    break; // хост завершился/перезапустился
                }
                catch (Exception ex)
                {
                    GuardianLog.Error("TrayHostPipeServer: ошибка чтения команды", ex);
                    break;
                }

                var response = HandleCommand(request.Data);
                connection.TryWrite(response);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("TrayHostPipeServer: ошибка обработки соединения хоста", ex);
        }
        finally
        {
            lock (_clientsSync)
            {
                _clients.Remove(connection);
            }
            connection.Dispose();
            GuardianLog.Info("TRAYHOST-IPC: хост трея отключился.");
        }
    }

    /// <summary>Обрабатывает одну команду хоста и формирует ответ {"replyTo":id,...}.</summary>
    private string HandleCommand(string? data)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(data))
            {
                return Reply(null, false, "пустая команда");
            }

            using var doc = JsonDocument.Parse(data);
            var root = doc.RootElement;
            long id = 0;
            if (root.TryGetProperty("id", out var idEl))
            {
                id = idEl.TryGetInt64(out var v) ? v : 0;
            }

            var cmd = root.TryGetProperty("cmd", out var cmdEl) ? cmdEl.GetString() ?? "" : "";
            switch (cmd)
            {
                case "open_panel":
                {
                    var page = root.TryGetProperty("page", out var pageEl) ? pageEl.GetString() ?? "" : "";
                    // Whitelist страниц — строго из MainWindow.NavigateTo (B4.4): неизвестная
                    // страница = отказ (никакого проброса произвольных аргументов в elevated-панель).
                    if (!IsAllowedPage(page))
                    {
                        GuardianLog.Warning($"TRAYHOST-IPC: open_panel с недопустимой страницей '{page}' — отказ.");
                        return Reply(id, false, "invalid_page");
                    }

                    var needRunAs = OpenPanelHandler?.Invoke(page) ?? "need_runas";
                    return string.IsNullOrEmpty(needRunAs)
                        ? Reply(id, true, "")
                        : Reply(id, false, needRunAs);
                }

                case "toggle_monitoring":
                {
                    GuardianLog.Info("TRAYHOST-IPC: toggle_monitoring от хоста трея.");
                    try { ToggleMonitoringHandler?.Invoke(); }
                    catch (Exception ex) { GuardianLog.Error("TRAYHOST-IPC: toggle_monitoring", ex); }
                    return Reply(id, true, "");
                }

                case "exit":
                {
                    GuardianLog.Info("TRAYHOST-IPC: exit от хоста трея — штатная остановка службы.");
                    try { ExitHandler?.Invoke(); }
                    catch (Exception ex) { GuardianLog.Error("TRAYHOST-IPC: exit", ex); }
                    return Reply(id, true, "");
                }

                case "get_status":
                {
                    var status = StatusHandler?.Invoke() ?? "{\"running\":false,\"version\":\"\"}";
                    return Reply(id, true, "", status);
                }

                case "clipboard_alert":
                {
                    var type = root.TryGetProperty("type", out var tEl) ? tEl.GetString() ?? "" : "";
                    var displayName = root.TryGetProperty("displayName", out var dEl) ? dEl.GetString() ?? "" : "";
                    var maskedPreview = root.TryGetProperty("maskedPreview", out var mEl) ? mEl.GetString() ?? "" : "";
                    if (string.IsNullOrEmpty(type) || string.IsNullOrEmpty(displayName))
                    {
                        return Reply(id, false, "invalid_payload");
                    }

                    var err = ClipboardAlertHandler?.Invoke(type, displayName, maskedPreview)
                              ?? "service_unavailable";
                    return Reply(id, string.IsNullOrEmpty(err), err);
                }

                default:
                    GuardianLog.Warning($"TRAYHOST-IPC: неизвестная команда '{cmd}' — отказ.");
                    return Reply(id, false, "unknown_command");
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Warning("TRAYHOST-IPC: не удалось разобрать команду хоста: " + ex.Message);
            return Reply(null, false, "bad_request");
        }
    }

    /// <summary>Whitelist страниц панели (MainWindow.NavigateTo): пустое значение = dashboard.</summary>
    public static bool IsAllowedPage(string page)
    {
        return string.IsNullOrEmpty(page) ||
               page is "dashboard" or "inspector" or "firewall" or "antivirus" or "update" or "settings" or "about";
    }

    private static string Reply(long? id, bool ok, string error, string? statusJson = null)
    {
        var payload = new Dictionary<string, object?>
        {
            ["ok"] = ok,
        };
        if (id.HasValue)
        {
            payload["replyTo"] = id.Value;
        }
        if (!ok && !string.IsNullOrEmpty(error))
        {
            payload["error"] = error;
        }
        if (statusJson is not null)
        {
            try
            {
                payload["status"] = JsonDocument.Parse(statusJson).RootElement.Clone();
            }
            catch
            {
                payload["status"] = new Dictionary<string, object?> { ["running"] = false };
            }
        }
        return JsonSerializer.Serialize(payload, IpcProtocol.JsonOptions);
    }

    // ---------------------------------------------------------------
    // Создание канала с явным DACL (копия логики PanelPipeServer/MonitorPipeServer)
    // ---------------------------------------------------------------

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
            // IU — интерактивные пользователи (хост asInvoker), BA — администраторы, SY — SYSTEM.
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
                // 3.0.1.3-fix: 16 экземпляров вместо 4 — служба шлёт хосту push-уведомления
                // (status_changed/events_changed/alert) и опрашивает его; при 4 занятых
                // соединениях push терялся (ERROR_PIPE_BUSY) и трей не обновлял статус.
                var handle = CreateNamedPipe(@"\\.\pipe\" + IpcProtocol.TrayHostPipeName,
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
            GuardianLog.Warning("TrayHostPipeServer: не удалось создать канал с явным ACL (" + aclEx.Message +
                                ") — использую дефолтный");
            return new NamedPipeServerStream(
                IpcProtocol.TrayHostPipeName, PipeDirection.InOut, 16,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try { _loopThread?.Join(2000); } catch { /* ignore */ }
        _cts.Dispose();
        lock (_clientsSync)
        {
            foreach (var client in _clients)
            {
                client.Dispose();
            }
            _clients.Clear();
        }
    }

    /// <summary>Одно подключение хоста: сериализация записи ответов/push в канал.</summary>
    private sealed class ClientConnection : IDisposable
    {
        private readonly NamedPipeServerStream _server;
        private readonly object _writeLock = new();
        private volatile bool _disposed;

        public ClientConnection(NamedPipeServerStream server)
        {
            _server = server;
        }

        public void TryPush(string payload)
        {
            if (_disposed)
            {
                return;
            }

            lock (_writeLock)
            {
                if (_disposed || !_server.IsConnected)
                {
                    return;
                }
                try
                {
                    IpcProtocol.WriteMessage(_server, new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = payload,
                    });
                }
                catch
                {
                    // Канал оборвался — следующий AcceptLoop заметит; push теряется безвредно.
                }
            }
        }

        public void TryWrite(string payload)
        {
            if (_disposed)
            {
                return;
            }

            lock (_writeLock)
            {
                if (_disposed || !_server.IsConnected)
                {
                    return;
                }
                try
                {
                    IpcProtocol.WriteMessage(_server, new IpcProtocol.Message
                    {
                        Kind = IpcProtocol.MessageKind.Status,
                        Data = payload,
                    });
                }
                catch (Exception ex)
                {
                    GuardianLog.Warning("TrayHostPipeServer: не удалось записать ответ хосту: " + ex.Message);
                }
            }
        }

        public void Dispose()
        {
            _disposed = true;
            try { _server.Dispose(); } catch { /* ignore */ }
        }
    }
}