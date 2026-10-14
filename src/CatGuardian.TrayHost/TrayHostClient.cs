using System;
using System.Collections.Generic;
using System.IO.Pipes;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Ipc;

namespace CatGuardian.TrayHost;

/// <summary>
/// Duplex-клиент хоста трея к службе (3.0.0.58-trayhost).
/// Постоянное соединение с каналом <see cref="IpcProtocol.TrayHostPipeName"/>,
/// автоматическое переподключение с экспоненциальным backoff'ом (служба могла
/// перезапуститься — хост обязан восстановить связь без перезапуска самого себя).
///
/// Протокол (JSON в Data сообщения):
///  - Хост → служба:  {"id":123,"cmd":"open_panel|toggle_monitoring|exit|get_status",...}
///  - Ответ службы:   {"replyTo":123,"ok":true/false,"error":"need_runas|...","status":{...}}
///  - Push службы:    {"push":"status_changed|events_changed|alert","status":{...},"title":..,"text":..}
///
/// Метка "replyTo" однозначно связывает ответ с ожидающей командой: даже если push
/// службы прилетит сразу после запроса, он не будет принят за ответ (гонка невозможна).
/// </summary>
public sealed class TrayHostClient : IDisposable
{
    private readonly object _sync = new();
    private NamedPipeClientStream? _client;
    private long _nextCmdId;
    private readonly Dictionary<long, TaskCompletionSource<string?>> _pending = new();
    private volatile bool _disposed;
    // M7: последний лог неудачного подключения (не чаще раза в 30 с — иначе diag-лог
    // спамится на каждый retry, пока служба поднимается).
    private DateTime _lastConnectFailLogUtc = DateTime.MinValue;

    /// <summary>Состояние связи со службой (true — канал открыт и чтение активно).</summary>
    public event Action<bool>? ConnectedChanged;

    /// <summary>Push-сообщение службы (сырой JSON: {"push":..., ...}).</summary>
    public event Action<string>? PushReceived;

    /// <summary>true — соединение со службой установлено (последнее известное состояние).</summary>
    public bool IsConnected { get; private set; }

    public void Start()
    {
        // M7: выделенный поток вместо Task.Run — при старте службы пул потоков
        // перегружен инициализацией (в логах VM первый хост не подключался ~70 с:
        // ConnectLoopAsync ждал свободный поток пула, иконка была серой). Выделенный
        // поток не зависит от пула — хост подключается к TRAYHOST-IPC сразу, как
        // только канал службы готов.
        var thread = new Thread(ConnectLoop)
        {
            IsBackground = true,
            Name = "TrayHostConnectLoop",
        };
        thread.Start();
    }

    private void ConnectLoop()
    {
        try
        {
            ConnectLoopAsync().GetAwaiter().GetResult();
        }
        catch
        {
            // Цикл сам обрабатывает ошибки; здесь — только страховка от неожиданного.
        }
    }

    private async Task ConnectLoopAsync()
    {
        var delay = TimeSpan.FromSeconds(2);
        while (!_disposed)
        {
            NamedPipeClientStream? client = null;
            try
            {
                client = new NamedPipeClientStream(".", IpcProtocol.TrayHostPipeName,
                    PipeDirection.InOut, PipeOptions.Asynchronous);
                client.Connect(5000); // синхронный Connect с таймаутом (канал в той же сессии)
                if (_disposed)
                {
                    try { client.Dispose(); } catch { /* ignore */ }
                    return;
                }

                lock (_sync)
                {
                    _client = client;
                }
                SetConnected(true);
                delay = TimeSpan.FromSeconds(2);
                await ReadLoopAsync(client);
            }
            catch (Exception ex)
            {
                // Служба ещё не поднята/перезапускается — повторяем с backoff'ом.
                // M7: диагностика — почему хост не подключается (в логах VM первый
                // хост «молча» не подключался ~70 с, иконка была серой). Не чаще
                // раза в 30 с, чтобы не спамить diag-лог на каждый retry.
                if (DateTime.UtcNow - _lastConnectFailLogUtc > TimeSpan.FromSeconds(30))
                {
                    _lastConnectFailLogUtc = DateTime.UtcNow;
                    try { TrayHostDiag.Write("CONNECT: связь со службой не установлена: " + ex.Message); }
                    catch { /* диагностика не должна ронять цикл */ }
                }
            }
            finally
            {
                SetConnected(false);
                lock (_sync)
                {
                    _client = null;
                }
                try { client?.Dispose(); } catch { /* ignore */ }
            }

            try
            {
                await Task.Delay(delay);
            }
            catch
            {
                return;
            }
            // O2 (3.0.1.4): backoff растёт только до 5 с, пока связь не установлена.
            // Раньше рост до 30 с давал «серую иконку» ~85 с: после двух таймаутов
            // (13:19:19, 13:20:09) следующая попытка была только через 30 с, хотя
            // канал службы уже был готов. 5 с — компромисс: частые попытки на старте
            // без спама (Connect сам ждёт до 5 с, если канал ещё не создан).
            if (delay < TimeSpan.FromSeconds(5))
            {
                delay = TimeSpan.FromSeconds(Math.Min(5, delay.TotalSeconds * 2));
            }
        }
    }

    private async Task ReadLoopAsync(NamedPipeClientStream client)
    {
        while (!_disposed)
        {
            var message = await IpcProtocol.ReadMessageAsync(client);
            var data = message.Data;
            if (string.IsNullOrEmpty(data))
            {
                continue;
            }

            if (TryGetReplyTo(data, out var replyId))
            {
                TaskCompletionSource<string?>? tcs = null;
                lock (_sync)
                {
                    if (_pending.TryGetValue(replyId, out tcs))
                    {
                        _pending.Remove(replyId);
                    }
                }
                tcs?.TrySetResult(data);
            }
            else
            {
                PushReceived?.Invoke(data);
            }
        }
    }

    /// <summary>
    /// Отправляет команду службе и ждёт ответ {"replyTo":id,...}. Возвращает сырой JSON ответа
    /// либо null при недоступности службы/таймауте. Потокобезопасен (одна команда за раз).
    /// </summary>
    public async Task<string?> SendCommandAsync(
        Dictionary<string, object?> command, int timeoutMs = 10000)
    {
        if (_disposed)
        {
            return null;
        }

        var id = Interlocked.Increment(ref _nextCmdId);
        command["id"] = id;
        string json;
        try
        {
            json = JsonSerializer.Serialize(command, IpcProtocol.JsonOptions);
        }
        catch
        {
            return null;
        }

        var tcs = new TaskCompletionSource<string?>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_sync)
        {
            var client = _client;
            if (client is null || !client.IsConnected)
            {
                return null;
            }

            _pending[id] = tcs;
            try
            {
                IpcProtocol.WriteMessage(client, new IpcProtocol.Message
                {
                    Kind = IpcProtocol.MessageKind.Ping,
                    Data = json,
                });
            }
            catch
            {
                _pending.Remove(id);
                tcs.TrySetResult(null);
            }
        }

        var completed = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs));
        if (completed != tcs.Task)
        {
            lock (_sync)
            {
                _pending.Remove(id);
            }
            return null;
        }

        return await tcs.Task;
    }

    private static bool TryGetReplyTo(string json, out long replyId)
    {
        replyId = 0;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return doc.RootElement.TryGetProperty("replyTo", out var el) && el.TryGetInt64(out replyId);
        }
        catch
        {
            return false;
        }
    }

    private void SetConnected(bool connected)
    {
        if (IsConnected == connected)
        {
            return;
        }

        IsConnected = connected;
        try
        {
            ConnectedChanged?.Invoke(connected);
        }
        catch
        {
            // Обработчики хоста не должны ронять цикл подключения.
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        lock (_sync)
        {
            foreach (var tcs in _pending.Values)
            {
                tcs.TrySetResult(null);
            }
            _pending.Clear();
            _client = null;
        }
    }
}