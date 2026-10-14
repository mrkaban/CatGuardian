using System;
using System.Collections.Generic;
using System.Linq;

namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>
/// Выборка файлов массовой волны для проверки энтропии заголовка (3.0.0.44).
/// Вынесена в Antivirus ради тестируемости (паттерн RwxSignatureContext): монитор отдаёт
/// сырой список изменений защищаемых папок, класс возвращает «каждый N-й уникальный путь»
/// — точечная выборка вместо измерения всех файлов волны.
/// </summary>
public static class WaveSampling
{
    /// <summary>
    /// Возвращает каждый N-й уникальный путь из изменений новее <paramref name="cutoffUtc"/>,
    /// но не более <paramref name="max"/> элементов. Пути считаются без учёта регистра;
    /// пустые пропускаются. Шаг <paramref name="step"/> клампится к минимуму 1.
    /// </summary>
    /// <param name="changes">Сырая последовательность (время, путь) событий изменений.</param>
    /// <param name="cutoffUtc">Граница окна (UTC): события раньше не учитываются.</param>
    /// <param name="step">Шаг выборки: каждый N-й уникальный путь (N по чувствительности).</param>
    /// <param name="max">Максимум возвращаемых путей (лимит нагрузки).</param>
    public static List<string> SampleEveryNth(
        IEnumerable<(DateTime Time, string Path)> changes,
        DateTime cutoffUtc,
        int step,
        int max)
    {
        var result = new List<string>();
        if (step < 1) step = 1;
        if (max < 1) return result;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int index = 0;
        foreach (var (time, path) in changes)
        {
            if (time < cutoffUtc) continue;
            if (string.IsNullOrEmpty(path)) continue;
            if (!seen.Add(path)) continue;
            if (index % step == 0)
            {
                result.Add(path);
                if (result.Count >= max) break;
            }
            index++;
        }
        return result;
    }
}