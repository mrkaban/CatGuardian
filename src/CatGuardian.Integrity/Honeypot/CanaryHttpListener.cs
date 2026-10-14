using System;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Data;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Honeypot;

/// <summary>
/// Локальный canary-listener. Слушает http://127.0.0.1:{port} и перехватывает
/// обращения к URL вида /canary/{token}, встроенным в файлы-приманки.
/// Когда стилер или человек открывает/копирует такую ссылку, фиксируется
/// событие доступа и поднимается алерт.
/// Работает только на loopback — не открывает порт наружу и не конфликтует
/// с антивирусами.
/// </summary>
public sealed class CanaryHttpListener : IDisposable
{
    private readonly HoneyPotRepository _repo;
    private readonly EventRepository _events;
    private readonly HttpListener _listener = new();
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private bool _started;

    /// <summary>Срабатывает при детекте обращения к приманке (уже после записи в БД).</summary>
    public event Action<EventRecord>? AccessDetected;

    public int Port { get; }
    public bool IsRunning => _started;

    public CanaryHttpListener(HoneyPotRepository repo, EventRepository events, int port)
    {
        _repo = repo;
        _events = events;
        Port = port;
    }

    public void Start()
    {
        Stop();
        try
        {
            _listener.Prefixes.Clear();
            // Принимаем запросы на всех loopback-адресах: ссылка в приманках использует
            // маскированный корпоративный поддомен (hosts → 127.0.0.1) или localhost.
            _listener.Prefixes.Add($"http://127.0.0.1:{Port}/");
            _listener.Prefixes.Add($"http://localhost:{Port}/");
            _listener.Prefixes.Add($"http://[::1]:{Port}/");
            _listener.Start();
            _cts = new CancellationTokenSource();
            _loopTask = Task.Run(() => ListenLoopAsync(_cts.Token));
            _started = true;
            GuardianLog.Info($"Canary-listener запущен на http://127.0.0.1:{Port}/");
        }
        catch (Exception ex)
        {
            _started = false;
            GuardianLog.Error($"Не удалось запустить canary-listener на порту {Port}", ex);
        }
    }

    public void Stop()
    {
        if (!_started && _listener.IsListening == false) return;
        try { _listener.Stop(); } catch { /* ignore */ }
        try { _cts?.Cancel(); } catch { /* ignore */ }
        if (_loopTask != null)
        {
            try { _loopTask.Wait(1000); } catch { /* ignore */ }
            _loopTask = null;
        }
        _cts?.Dispose();
        _cts = null;
        _started = false;
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch (Exception)
            {
                break; // listener остановлен
            }

            _ = Task.Run(() => HandleAsync(context));
        }
    }

    private async Task HandleAsync(HttpListenerContext context)
    {
        try
        {
            var path = context.Request.Url?.AbsolutePath ?? "/";
            if (TryExtractToken(path, out var token) && _repo.ResolveToken(token) is { } filePath)
            {
                // Определяем, какой процесс открыл соединение с нашим локальным портом.
                var pid = ProcessResolver.FindPidForTcpPortWithRetry(Port, context.Request.RemoteEndPoint?.Port ?? 0);
                var proc = ProcessResolver.DescribePid(pid);
                // 3.0.0.16: PID/имя процесса — машиночитаемо для Anti-Stealer.
                string? procName = null;
                if (pid > 0)
                {
                    try
                    {
                        using var p = Process.GetProcessById(pid);
                        procName = p.ProcessName;
                    }
                    catch
                    {
                        // Процесс завершился — имя остаётся неизвестным.
                    }
                }
                var record = new EventRecord
                {
                    Source = EventSource.Honeypot,
                    Type = ChangeType.Access,
                    Target = filePath,
                    Detail = $"переход по canary-ссылке /canary/{token} | процесс: {proc}",
                    OccurredAt = DateTime.UtcNow,
                    Status = EventStatus.Pending,
                    ProcessId = pid > 0 ? pid : null,
                    ProcessName = procName,
                };
                _events.Add(record);
                GuardianLog.Info($"Canary-токен сработал: {filePath} (token={token})");
                AccessDetected?.Invoke(record);

                // Возвращаем нейтральный ответ, не выдавая факта ловушки.
                WriteText(context.Response, "ok", HttpStatusCode.OK);
            }
            else
            {
                WriteText(context.Response, "not found", HttpStatusCode.NotFound);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("Ошибка обработки canary-запроса", ex);
            try { WriteText(context.Response, "error", HttpStatusCode.InternalServerError); }
            catch { /* ignore */ }
        }
    }

    private static bool TryExtractToken(string path, out string token)
    {
        token = "";
        const string marker = "/canary/";
        var idx = path.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return false;
        var start = idx + marker.Length;
        var end = path.IndexOfAny(new[] { '/', '?' }, start);
        var raw = end < 0 ? path[start..] : path[start..end];
        if (raw.Length == 0) return false;
        token = raw.Trim();
        return true;
    }

    private static void WriteText(HttpListenerResponse response, string text, HttpStatusCode status)
    {
        var bytes = Encoding.UTF8.GetBytes(text);
        response.StatusCode = (int)status;
        response.ContentType = "text/plain; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        response.OutputStream.Write(bytes, 0, bytes.Length);
        response.OutputStream.Close();
    }

    public void Dispose() => Stop();
}