using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CatGuardian.Integrity.Models;

namespace CatGuardian.Integrity.Hashing;

/// <summary>
/// Вычисляет контрольные суммы файлов потоково (без загрузки в память),
/// параллельно по нескольким алгоритмам.
/// </summary>
public static class HashCalculator
{
    private const int BufferSize = 128 * 1024;

    /// <summary>
    /// Вычисляет указанные хеши файла. ВНИМАНИЕ: для всех трёх алгоритмов читается
    /// файл один раз. Возвращает пустой словарь при ошибке доступа.
    /// </summary>
    public static async Task<Dictionary<string, string>> ComputeAsync(
        string filePath,
        IEnumerable<string> algos,
        CancellationToken cancellationToken = default)
    {
        var results = new Dictionary<string, string>();
        try
        {
            var algoList = new List<string>(algos);
            if (algoList.Count == 0)
            {
                return results;
            }

            using var stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, BufferSize,
                FileOptions.SequentialScan);

            var hashObjects = CreateHashObjects(algoList, results);
            if (hashObjects.Count == 0)
            {
                return results;
            }

            try
            {
                var buffer = new byte[BufferSize];
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)
                            .ConfigureAwait(false)) > 0)
                {
                    foreach (var h in hashObjects.Values)
                    {
                        h.TransformBlock(buffer, 0, bytesRead, null, 0);
                    }
                }

                foreach (var (algo, h) in hashObjects)
                {
                    h.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                    results[algo] = Convert.ToHexString(h.Hash ?? Array.Empty<byte>()).ToLowerInvariant();
                }
            }
            finally
            {
                foreach (var h in hashObjects.Values)
                {
                    h.Dispose();
                }
            }
        }
        catch (Exception)
        {
            // Файл может быть занят, удалён или недоступен.
            results.Clear();
        }
        return results;
    }

    /// <summary>Синхронная версия для тестов и простых сценариев.</summary>
    public static Dictionary<string, string> Compute(string filePath, IEnumerable<string> algos)
    {
        return ComputeAsync(filePath, algos, CancellationToken.None).GetAwaiter().GetResult();
    }

    private static Dictionary<string, HashAlgorithm> CreateHashObjects(
        IEnumerable<string> algos, Dictionary<string, string> results)
    {
        var map = new Dictionary<string, HashAlgorithm>();
        foreach (var algo in algos)
        {
            switch (algo.ToLowerInvariant())
            {
                case HashAlgo.Sha256:
                    map[HashAlgo.Sha256] = SHA256.Create();
                    break;
                case HashAlgo.Sha1:
                    map[HashAlgo.Sha1] = SHA1.Create();
                    break;
                case HashAlgo.Md5:
                    map[HashAlgo.Md5] = MD5.Create();
                    break;
            }
        }
        return map;
    }
}