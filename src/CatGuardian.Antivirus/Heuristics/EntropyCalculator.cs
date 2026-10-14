namespace CatGuardian.Antivirus.Core.Heuristics;

/// <summary>Расчёт энтропии Шеннона для блока данных.</summary>
public static class EntropyCalculator
{
    /// <summary>Считает энтропию (бит на байт, 0..8) для всех байтов потока.</summary>
    public static double Compute(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<ulong> counts = stackalloc ulong[256];
        foreach (var b in data)
        {
            counts[b]++;
        }

        double total = data.Length;
        double entropy = 0.0;

        foreach (var count in counts)
        {
            if (count == 0)
            {
                continue;
            }

            double p = count / total;
            entropy -= p * Math.Log2(p);
        }

        return entropy;
    }
}