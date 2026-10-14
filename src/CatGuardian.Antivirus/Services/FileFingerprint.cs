using System.Security.Cryptography;

namespace CatGuardian.Antivirus.Core.Services;

/// <summary>
/// Ограниченный «отпечаток» файла для кэша вердиктов запускаемых процессов.
/// Сочетает размер, время изменения и хэш первых/последних байт, чтобы
/// мгновенно (без чтения всего файла) определять, изменился ли бинарник
/// с момента последней проверки. Чтение ограничено константой
/// <see cref="FileFingerprintComputer.EdgeBytes"/>, поэтому стоимость не
/// зависит от размера файла.
/// </summary>
public readonly record struct FileFingerprint(long Length, long LastWriteTicks, string Hash)
{
    public bool Equals(FileFingerprint other)
        => Length == other.Length
           && LastWriteTicks == other.LastWriteTicks
           && string.Equals(Hash, other.Hash, StringComparison.Ordinal);

    public override int GetHashCode()
    {
        unchecked
        {
            var hash = Length.GetHashCode();
            hash = (hash * 397) ^ LastWriteTicks.GetHashCode();
            hash = (hash * 397) ^ (Hash?.GetHashCode() ?? 0);
            return hash;
        }
    }
}

/// <summary>Вычисляет <see cref="FileFingerprint"/> для файла по пути.</summary>
public static class FileFingerprintComputer
{
    /// <summary>Сколько байт читается с начала и с конца файла (всего ≤ 2×).</summary>
    public const int EdgeBytes = 64 * 1024;

    /// <summary>Попытка вычислить отпечаток. Ложь, если файл недоступен/не существует.</summary>
    public static bool TryCompute(string path, out FileFingerprint fingerprint)
    {
        fingerprint = default;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists)
            {
                return false;
            }

            var length = fi.Length;
            var lastWriteTicks = fi.LastWriteTimeUtc.Ticks;
            var hash = ComputeEdgeHash(path, length);
            fingerprint = new FileFingerprint(length, lastWriteTicks, hash);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// Хэш первых и последних <see cref="EdgeBytes"/> байт (с префиксом длины,
    /// чтобы короткие файлы не путались). Мелкий файл хэшируется целиком.
    /// </summary>
    private static string ComputeEdgeHash(string path, long length)
    {
        using var fs = new FileStream(
            path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);

        var firstLen = (int)Math.Min(EdgeBytes, length);
        var first = new byte[firstLen];
        ReadExactly(fs, first);

        byte[] last = Array.Empty<byte>();
        if (length > EdgeBytes)
        {
            var tailLen = (int)Math.Min(EdgeBytes, length - EdgeBytes);
            last = new byte[tailLen];
            fs.Seek(-tailLen, SeekOrigin.End);
            ReadExactly(fs, last);
        }

        // Префикс длины в байтах, чтобы (A)+(B) не совпадало с (AB)+() и т.п.
        var size = 16 + first.Length + last.Length;
        var combined = new byte[size];
        BitConverter.GetBytes(length).CopyTo(combined, 0);
        BitConverter.GetBytes(first.Length).CopyTo(combined, 8);
        Buffer.BlockCopy(first, 0, combined, 16, first.Length);
        if (last.Length > 0)
        {
            Buffer.BlockCopy(last, 0, combined, 16 + first.Length, last.Length);
        }

        using var sha = SHA256.Create();
        return Convert.ToHexString(sha.ComputeHash(combined));
    }

    private static void ReadExactly(Stream stream, byte[] buffer)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = stream.Read(buffer, offset, buffer.Length - offset);
            if (read <= 0)
            {
                break;
            }

            offset += read;
        }
    }
}