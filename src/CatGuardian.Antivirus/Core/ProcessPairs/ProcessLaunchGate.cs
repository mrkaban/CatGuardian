using System;
using System.Collections.Generic;

namespace CatGuardian.Antivirus.Core.ProcessPairs;

/// <summary>
/// Дедупликация событий запуска процесса (3.0.0.40, P1).
///
/// Один и тот же PID может быть доставлен двумя источниками:
///  1) ETW-сессия ядра (<see cref="CatGuardian.Integrity.Etw.KernelEtwBridge.ProcessStarted"/>);
///  2) поллинг <c>ProcessMonitor</c> (снимок PID каждые ~750 мс).
///
/// Чтобы бинарник не сканировался дважды, каждый PID «заявляется» одним потоком:
/// первый вызов <see cref="TryClaim"/> возвращает true и блокирует повторные заявки
/// в течение <see cref="ClaimWindow"/>. Логика вынесена в отдельный класс для
/// юнит-тестирования (чистая, без обращения к системе).
/// </summary>
public sealed class ProcessLaunchGate
{
    /// <summary>Окно жизни заявки: за это время оба источника успевают доставить событие.</summary>
    public static readonly TimeSpan ClaimWindow = TimeSpan.FromSeconds(60);

    private readonly Dictionary<int, DateTime> _claims = new();
    private readonly object _sync = new();

    /// <summary>Число активных заявок (диагностика/тесты).</summary>
    public int Count
    {
        get
        {
            lock (_sync)
            {
                PruneLocked();
                return _claims.Count;
            }
        }
    }

    /// <summary>
    /// Пытается «заявить» PID для обработки. Возвращает true, если PID ещё не был
    /// заявлен в течение окна, и фиксирует заявку; иначе false (дубликат).
    /// </summary>
    public bool TryClaim(int pid)
    {
        if (pid <= 0)
        {
            return false;
        }

        var now = DateTime.UtcNow;
        lock (_sync)
        {
            PruneLocked(now);
            if (_claims.ContainsKey(pid))
            {
                return false;
            }

            _claims[pid] = now;
            return true;
        }
    }

    /// <summary>Полная очистка заявок (например, при выключении мониторинга).</summary>
    public void Clear()
    {
        lock (_sync)
        {
            _claims.Clear();
        }
    }

    private void PruneLocked() => PruneLocked(DateTime.UtcNow);

    private void PruneLocked(DateTime now)
    {
        if (_claims.Count == 0)
        {
            return;
        }

        var cutoff = now - ClaimWindow;
        var stale = new List<int>(_claims.Count);
        foreach (var (pid, at) in _claims)
        {
            if (at < cutoff)
            {
                stale.Add(pid);
            }
        }

        foreach (var pid in stale)
        {
            _claims.Remove(pid);
        }
    }
}