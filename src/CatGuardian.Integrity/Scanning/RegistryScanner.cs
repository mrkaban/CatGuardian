using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.Win32;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Scanning;

/// <summary>
/// Работа с реестром: снятие эталона значений в наблюдаемых ветках и
/// сравнение текущего состояния с эталоном. Поддерживает HKLM/HKCU.
/// </summary>
public sealed class RegistryScanner
{
    /// <summary>
    /// Снимает снимок всех значений реестра под указанными ветками (рекурсивно).
    /// 3.0.0.21: ветки обходятся ПАРАЛЛЕЛЬНО (раньше — последовательно, на больших
    /// ветках вроде Services это добавляло минуты к «Снятию эталона»/«Поиску нового»).
    /// </summary>
    public List<RegistryValueRecord> TakeSnapshot(IEnumerable<string> rootKeys, Action<string, int, int>? progress = null)
    {
        // 3.0.0.36: HKEY_CURRENT_USER-шаблоны разворачиваются во ВСЕ пользовательские
        // профили (HKEY_USERS\<SID>\...) — автозагрузка каждого пользователя должна
        // контролироваться, а не только того токена, под которым работает процесс.
        var roots = RegistryUserHives.ExpandAll(rootKeys);
        if (roots.Count == 0) return new List<RegistryValueRecord>();

        var now = DateTime.UtcNow;
        // 3.0.0.21: не более 4 и на 1 меньше ядер — обход не забирает все ядра (даже на 4-ядерных).
        var parallelism = Math.Max(1, Math.Min(4, Environment.ProcessorCount - 1));

        // Быстрый путь для одной ветки (используется «Снятием эталона» по-веточно):
        // без накладных расходов параллельной инфраструктуры.
        if (roots.Count == 1)
        {
            var single = new List<RegistryValueRecord>();
            CollectKey(roots[0], now,
                new System.Collections.Concurrent.ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase),
                single);
            try { progress?.Invoke(roots[0], 1, 1); } catch { /* прогресс не критичен */ }
            return single;
        }

        // Единый visited на ВСЕ ветки — перекрывающиеся watch-ключи не дают дублей
        // (как и в последовательной версии); TryAdd потокобезопасен.
        var visited = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        // Каждая ветка собирает локальный список, потом сливаем (ConcurrentBag — только
        // для транспорта, у него нет неявного ICollection.Add).
        var perRoot = new System.Collections.Concurrent.ConcurrentBag<List<RegistryValueRecord>>();
        var done = 0;

        System.Threading.Tasks.Parallel.ForEach(roots,
            new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = parallelism },
            root =>
        {
            var local = new List<RegistryValueRecord>();
            CollectKey(root, now, visited, local);
            perRoot.Add(local);
            System.Threading.Interlocked.Increment(ref done);
            try { progress?.Invoke(root, System.Threading.Volatile.Read(ref done), roots.Count); } catch { }
        });

        var result = new List<RegistryValueRecord>();
        foreach (var l in perRoot) result.AddRange(l);
        return result;
    }

    private static void CollectKey(
        string keyPath,
        DateTime now,
        System.Collections.Concurrent.ConcurrentDictionary<string, byte> visited,
        List<RegistryValueRecord> result)
    {
        if (!visited.TryAdd(keyPath, 0)) return;
        using var key = OpenKey(keyPath);
        if (key is null) return;

        try
        {
            foreach (var valueName in key.GetValueNames())
            {
                var valueData = ReadValue(key, valueName, out var kind);
                result.Add(new RegistryValueRecord
                {
                    Key = keyPath,
                    ValueName = valueName ?? "",
                    ValueType = kind,
                    ValueData = valueData,
                    BaselineAt = now,
                });
            }

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                var child = keyPath.EndsWith("\\", StringComparison.Ordinal)
                    ? keyPath + subKeyName
                    : keyPath + "\\" + subKeyName;
                CollectKey(child, now, visited, result);
            }
        }
        catch (Exception)
        {
            // нет прав доступа — пропускаем ветку
        }
    }

    /// <summary>
    /// Сравнивает текущее состояние реестра с эталоном и возвращает изменения.
    /// 3.0.0.21: ветки сравниваются ПАРАЛЛЕЛЬНО (раньше — последовательно; на большой
    /// ветке Services проверка целостности реестра занимала десятки минут).
    /// </summary>
    public List<RegistryCheckResult> Compare(
        IEnumerable<RegistryValueRecord> baseline,
        IEnumerable<string> rootKeys,
        Action<string, int, int>? progress = null)
    {
        // 3.0.0.36: HKCU-шаблоны разворачиваются по всем профилям (как и при снятии эталона),
        // иначе сравнение со старым «HKEY_CURRENT_USER\...» эталоном давало бы ложные Deleted.
        var roots = RegistryUserHives.ExpandAll(rootKeys);
        // 3.0.0.21: не более 4 и на 1 меньше ядер + отчёт о готовых ветках («ветка X из Y»).
        var parallelism = Math.Max(1, Math.Min(4, Environment.ProcessorCount - 1));

        // Эталон: (Key|ValueName) -> record
        var expected = new Dictionary<string, RegistryValueRecord>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var record in baseline)
        {
            expected[MapKey(record.Key, record.ValueName)] = record;
        }

        var seen = new System.Collections.Concurrent.ConcurrentDictionary<string, byte>(StringComparer.OrdinalIgnoreCase);
        var perRoot = new System.Collections.Concurrent.ConcurrentBag<List<RegistryCheckResult>>();
        var done = 0;

        System.Threading.Tasks.Parallel.ForEach(roots,
            new System.Threading.Tasks.ParallelOptions { MaxDegreeOfParallelism = parallelism },
            root =>
        {
            var local = new List<RegistryCheckResult>();
            CompareKey(root, expected, seen, local);
            perRoot.Add(local);
            System.Threading.Interlocked.Increment(ref done);
            try { progress?.Invoke(root, System.Threading.Volatile.Read(ref done), roots.Count); } catch { }
        });

        var results = new List<RegistryCheckResult>();
        foreach (var l in perRoot) results.AddRange(l);

        // Удалённые значения/подключи, которые были в эталоне, но исчезли
        foreach (var pair in expected)
        {
            if (seen.ContainsKey(pair.Key)) continue;
            var rec = pair.Value;
            results.Add(new RegistryCheckResult
            {
                Key = rec.Key,
                Type = ChangeType.Deleted,
                ValueName = rec.ValueName,
                Detail = $"значение \"{rec.ValueName}\" удалено (было: {rec.ValueData})",
            });
        }

        return results;
    }

    private static void CompareKey(
        string keyPath,
        Dictionary<string, RegistryValueRecord> expected,
        System.Collections.Concurrent.ConcurrentDictionary<string, byte> seen,
        List<RegistryCheckResult> results)
    {
        using var key = OpenKey(keyPath);
        if (key is null)
        {
            // Ветка полностью отсутствует/удалена
            foreach (var pair in expected.Where(p =>
                         p.Value.Key.Equals(keyPath, StringComparison.OrdinalIgnoreCase)))
            {
                results.Add(new RegistryCheckResult
                {
                    Key = keyPath,
                    Type = ChangeType.Deleted,
                    ValueName = pair.Value.ValueName,
                    Detail = "ветка реестра отсутствует",
                });
            }
            return;
        }

        try
        {
            foreach (var valueName in key.GetValueNames())
            {
                var mapKey = MapKey(keyPath, valueName ?? "");
                var valueData = ReadValue(key, valueName, out var kind);

                if (expected.TryGetValue(mapKey, out var exp))
                {
                    seen.TryAdd(mapKey, 0);
                    if (!string.Equals(exp.ValueData, valueData, StringComparison.Ordinal) ||
                        !string.Equals(exp.ValueType, kind, StringComparison.OrdinalIgnoreCase))
                    {
                        results.Add(new RegistryCheckResult
                        {
                            Key = keyPath,
                            Type = ChangeType.Modified,
                            ValueName = valueName ?? "",
                            // 3.0.0.21: тип значения сохраняется для точечного утверждения
                            // (без пересъёмки ветки).
                            ValueType = kind,
                            Detail = $"\"{valueName}\": {exp.ValueData} → {valueData}",
                        });
                    }
                }
                else
                {
                    results.Add(new RegistryCheckResult
                    {
                        Key = keyPath,
                        Type = ChangeType.Created,
                        ValueName = valueName ?? "",
                        ValueType = kind,
                        Detail = $"добавлено значение \"{valueName}\": {valueData}",
                    });
                }
            }

            foreach (var subKeyName in key.GetSubKeyNames())
            {
                var child = keyPath.EndsWith("\\", StringComparison.Ordinal)
                    ? keyPath + subKeyName
                    : keyPath + "\\" + subKeyName;
                CompareKey(child, expected, seen, results);
            }
        }
        catch (Exception)
        {
            // нет доступа — пропускаем
        }
    }

    private static string ReadValue(RegistryKey key, string? valueName, out string kind)
    {
        var kindValue = key.GetValueKind(valueName);
        kind = kindValue.ToString();
        var raw = key.GetValue(valueName);
        return FormatValue(raw);
    }

    private static string FormatValue(object? raw)
    {
        switch (raw)
        {
            case null:
                return "";
            case byte[] bytes:
                return Convert.ToHexString(bytes);
            case string[] array:
                return string.Join("|", array);
            case string s:
                return s;
            default:
                return raw.ToString() ?? "";
        }
    }

    private static string MapKey(string k, string n) => k + "\u0000" + n;

    private static RegistryKey? OpenKey(string keyPath)
        // 3.0.0.36: единый открыватель ключей — поддержка HKEY_USERS\<SID> для
        // контроля автозагрузки ВСЕХ пользователей (см. RegistryUserHives).
        => RegistryUserHives.OpenKey(keyPath);
}