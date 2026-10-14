using System;
using System.IO;
using System.Text;

namespace CatGuardian.Antivirus.Core.Utilities;

/// <summary>
/// Разобранное содержимое ярлыка: цель, аргументы, рабочая папка, иконка, описание.
/// Для .url-ярлыков — адрес сайта и файл иконки.
/// </summary>
public sealed class ShortcutInfo
{
    /// <summary>Расширение файла-ярлыка: "lnk" или "url".</summary>
    public required string Extension { get; init; }

    /// <summary>Цель ярлыка (полный путь, переменные среды не раскрыты). Пусто — не извлечена.</summary>
    public string TargetPath { get; set; } = "";

    /// <summary>Аргументы командной строки.</summary>
    public string Arguments { get; set; } = "";

    /// <summary>Рабочая папка.</summary>
    public string WorkingDirectory { get; set; } = "";

    /// <summary>Файл иконки (IconLocation).</summary>
    public string IconLocation { get; set; } = "";

    /// <summary>Описание ярлыка (NameString).</summary>
    public string Description { get; set; } = "";

    /// <summary>URL для .url-ярлыков.</summary>
    public string Url { get; set; } = "";

    /// <summary>true для .url-ярлыков (текстовый INI).</summary>
    public bool IsUrl => string.Equals(Extension, "url", StringComparison.OrdinalIgnoreCase);
}

/// <summary>
/// Парсер ярлыков Windows БЕЗ COM: бинарного Shell Link (.lnk) по спецификации MS-SHLLINK
/// (https://learn.microsoft.com/openspecs/windows_protocols/ms-shllink) и текстового .url.
/// Извлекает только поля, нужные детектору подмены: TargetPath, Arguments, WorkingDirectory,
/// IconLocation, NameString. Не бросает исключений — при повреждении файла возвращает null.
/// </summary>
public static class ShellLinkParser
{
    // LinkFlags (MS-SHLLINK, раздел 2.1.1 «LinkFlags»).
    private const uint HasLinkTargetIDList = 0x00000001;
    private const uint HasLinkInfo = 0x00000002;
    private const uint HasName = 0x00000004;
    private const uint HasRelativePath = 0x00000008;
    private const uint HasWorkingDir = 0x00000010;
    private const uint HasArguments = 0x00000020;
    private const uint HasIconLocation = 0x00000040;

    // CLSID Shell Link: {00021401-0000-0000-C000-000000000046} (little-endian).
    private static readonly byte[] ShellLinkClsid =
    {
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
    };

    /// <summary>
    /// Разбирает ярлык по расширению файла. При ошибке/повреждении возвращает null.
    /// </summary>
    public static ShortcutInfo? TryParse(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) return null;
            var ext = Path.GetExtension(path).TrimStart('.').ToLowerInvariant();
            if (ext == "url") return TryParseUrl(path);
            if (ext != "lnk") return null;
            return TryParseLnk(path);
        }
        catch
        {
            // Любая ошибка чтения/разбора — ярлык считается недоступным для анализа.
            return null;
        }
    }

    /// <summary>
    /// Сигнатура .url-ярлыка: текстовый INI с секцией [InternetShortcut] и ключом URL.
    /// Легитимные ярлыки на сайты НЕ считаются подозрительными сами по себе — парсер
    /// только извлекает URL, решение о подмене принимает монитор.
    /// </summary>
    private static ShortcutInfo? TryParseUrl(string path)
    {
        var info = new ShortcutInfo { Extension = "url" };
        foreach (var rawLine in File.ReadAllLines(path))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("URL=", StringComparison.OrdinalIgnoreCase))
            {
                info.Url = line.Substring(4).Trim();
            }
            else if (line.StartsWith("IconFile=", StringComparison.OrdinalIgnoreCase))
            {
                info.IconLocation = line.Substring(9).Trim();
            }
        }

        if (info.Url.Length == 0) return null;
        info.TargetPath = info.Url;
        return info;
    }

    /// <summary>Разбирает бинарный Shell Link (.lnk).</summary>
    private static ShortcutInfo? TryParseLnk(string path)
    {
        var bytes = File.ReadAllBytes(path);
        var data = new ReadOnlySpan<byte>(bytes);
        if (data.Length < 76) return null;

        // Заголовок Shell Link: HeaderSize (0x4C=76), CLSID, LinkFlags, ...
        // Данные (IDList/LinkInfo) начинаются со смещения HeaderSize: реальные .lnk от
        // WScript.Shell хранят IDListSize на смещении 76 (проверено на живых файлах),
        // поэтому позицию берём ИЗ HeaderSize, а не фиксируем константой.
        var headerSize = ReadUInt32(data, 0);
        if (headerSize != 0x4C) return null;
        if (!data.Slice(4, 16).SequenceEqual(ShellLinkClsid)) return null;

        var linkFlags = ReadUInt32(data, 20);
        int pos = (int)headerSize;

        var info = new ShortcutInfo { Extension = "lnk" };

        // LinkTargetIDList — пропускаем целиком (нам нужен только путь из LinkInfo).
        if ((linkFlags & HasLinkTargetIDList) != 0)
        {
            if (pos + 2 > data.Length) return null;
            var idListSize = ReadUInt16(data, pos);
            pos += 2;
            if (idListSize > data.Length - pos) return null;
            pos += idListSize;
        }

        // LinkInfo — локальный или сетевой (UNC) путь к цели.
        if ((linkFlags & HasLinkInfo) != 0)
        {
            var target = ParseLinkInfo(data, ref pos);
            if (target is not null) info.TargetPath = target;
        }

        // StringData — имя, относительный путь, рабочая папка, аргументы, иконка.
        // Обрезанные/повреждённые строки НЕ нарушают разбор цели: читаем что успели и
        // прекращаем (goto done), чтобы обрыв хвоста .lnk не прятал найденную цель.
        if ((linkFlags & HasName) != 0)
        {
            if (!TryReadString(data, ref pos, out var name)) goto done;
            info.Description = name;
        }
        if ((linkFlags & HasRelativePath) != 0)
        {
            if (!TryReadString(data, ref pos, out var rel)) goto done;
            if (info.TargetPath.Length == 0) info.TargetPath = rel;
        }
        if ((linkFlags & HasWorkingDir) != 0)
        {
            if (!TryReadString(data, ref pos, out var wd)) goto done;
            info.WorkingDirectory = wd;
        }
        if ((linkFlags & HasArguments) != 0)
        {
            if (!TryReadString(data, ref pos, out var args)) goto done;
            info.Arguments = args;
        }
        if ((linkFlags & HasIconLocation) != 0)
        {
            if (!TryReadString(data, ref pos, out var icon)) goto done;
            info.IconLocation = icon;
        }

    done:
        // Ярлык без цели и аргументов (например, ссылка на системную панель через IDList
        // без LinkInfo) анализировать нечем — пропускаем, чтобы не плодить ложные алерты.
        if (info.TargetPath.Length == 0 && info.Arguments.Length == 0) return null;
        return info;
    }

    /// <summary>
    /// Разбирает LinkInfo (MS-SHLLINK, раздел 2.3 «LinkInfo»). Возвращает полный путь цели
    /// (LocalBasePath + CommonPathSuffix или UNC NetName + CommonPathSuffix) либо null.
    /// Позиция pos сдвигается за структуру LinkInfo.
    /// </summary>
    private static string? ParseLinkInfo(ReadOnlySpan<byte> data, ref int pos)
    {
        if (pos + 28 > data.Length) return null;
        var linkInfoSize = ReadUInt32(data, pos);
        if (linkInfoSize < 28 || linkInfoSize > data.Length - pos) return null;

        var headerSize = ReadUInt32(data, pos + 4);
        if (headerSize < 0x1C) return null;

        // Офсеты структур относительно начала LinkInfo (MS-SHLLINK, раздел 2.3).
        var volumeIdOffset = ReadUInt32(data, pos + 12);
        var localBaseOffset = ReadUInt32(data, pos + 16);
        var netOffset = ReadUInt32(data, pos + 20);
        var suffixOffset = ReadUInt32(data, pos + 24);

        var end = pos + (int)linkInfoSize;
        var unicodeHeader = headerSize >= 0x24;

        // Юникодные дубли смещений появляются при LinkInfoHeaderSize >= 0x24:
        // LocalBasePathOffsetUnicode на +0x1C, CommonPathSuffixOffsetUnicode на +0x20.
        var localBaseOffsetUnicode = unicodeHeader && pos + 36 <= end ? ReadUInt32(data, pos + 28) : 0u;
        var suffixOffsetUnicode = unicodeHeader && pos + 40 <= end ? ReadUInt32(data, pos + 32) : 0u;

        var localPathIsUnicode = localBaseOffsetUnicode > 0;
        var localOffset = localPathIsUnicode ? localBaseOffsetUnicode : localBaseOffset;
        var suffixIsUnicode = suffixOffsetUnicode > 0;
        var suffixOff = suffixIsUnicode ? suffixOffsetUnicode : suffixOffset;

        string? path = null;

        // Ветвление ПО СМЕЩЕНИЯМ, а не по LinkInfoFlags: реальные .lnk от WScript.Shell
        // пишут Flags=0x1 (формально «сетевой путь»), но содержат локальный LocalBasePath.
        // Наличие офсета важнее бита флага.
        if (localOffset > 0 && pos + (int)localOffset < end)
        {
            // Локальный путь: LocalBasePath [+ CommonPathSuffix].
            var basePath = ReadNullTerminated(data, pos + (int)localOffset, end, localPathIsUnicode);
            if (basePath.Length > 0)
            {
                path = basePath;
                if (suffixOff > 0 && pos + (int)suffixOff < end)
                {
                    var suffix = ReadNullTerminated(data, pos + (int)suffixOff, end, suffixIsUnicode);
                    if (suffix.Length > 0)
                    {
                        path = CombinePath(path, suffix);
                    }
                }
            }
        }
        else if (netOffset > 0 && pos + (int)netOffset + 24 <= end)
        {
            // Сетевой путь: CommonNetworkRelativeLink (NetName) + CommonPathSuffix.
            var cnrlPos = pos + (int)netOffset;
            var netName = ReadCommonNetworkNetName(data, cnrlPos, end, unicodeHeader);
            if (netName.Length > 0)
            {
                path = @"\\" + netName.TrimStart('\\');
                if (suffixOff > 0 && pos + (int)suffixOff < end)
                {
                    var suffix = ReadNullTerminated(data, pos + (int)suffixOff, end, suffixIsUnicode);
                    if (suffix.Length > 0)
                    {
                        path = CombinePath(path, suffix);
                    }
                }
            }
        }

        // Позиция двигается за всю структуру LinkInfo.
        pos = end;
        return path;
    }

    /// <summary>
    /// Читает NetName из CommonNetworkRelativeLink (MS-SHLLINK, раздел 2.3.5).
    /// Строка лежит по смещению NetNameOffset от начала структуры CNRL.
    /// </summary>
    private static string ReadCommonNetworkNetName(ReadOnlySpan<byte> data, int cnrlStart, int end, bool unicode)
    {
        // CommonNetworkRelativeLinkSize + Flags + NetNameOffset + DeviceNameOffset +
        // NetworkProviderType [+ NetNameOffsetUnicode + DeviceNameOffsetUnicode].
        var size = ReadUInt32(data, cnrlStart);
        if (size < 0x14 || cnrlStart + size > end) return "";

        var netNameOffset = ReadUInt32(data, cnrlStart + 8);
        var netNameOffsetUnicode = unicode ? ReadUInt32(data, cnrlStart + 16) : 0;

        var offset = netNameOffsetUnicode > 0 ? netNameOffsetUnicode : netNameOffset;
        if (offset == 0 || cnrlStart + (int)offset >= end) return "";

        return ReadNullTerminated(data, cnrlStart + (int)offset, cnrlStart + (int)size, unicode);
    }

    /// <summary>
    /// Читает строку из StringData: uint16 CountCharacters + UTF-16LE (не null-terminated).
    /// </summary>
    private static bool TryReadString(ReadOnlySpan<byte> data, ref int pos, out string value)
    {
        value = "";
        if (pos + 2 > data.Length) return false;
        var count = ReadUInt16(data, pos);
        pos += 2;
        var byteCount = count * 2;
        if (byteCount > data.Length - pos) return false;
        value = Encoding.Unicode.GetString(data.Slice(pos, byteCount));
        pos += byteCount;
        return true;
    }

    /// <summary>Читает null-terminated строку (ANSI или UTF-16) в пределах диапазона.</summary>
    private static string ReadNullTerminated(ReadOnlySpan<byte> data, int start, int end, bool unicode)
    {
        if (start < 0 || start >= end || start > data.Length) return "";
        if (unicode)
        {
            var maxChars = (end - start) / 2;
            for (int i = 0; i < maxChars; i++)
            {
                var offset = start + i * 2;
                if (offset + 1 >= data.Length) break;
                if (data[offset] == 0 && data[offset + 1] == 0)
                {
                    return Encoding.Unicode.GetString(data.Slice(start, i * 2));
                }
            }
            return Encoding.Unicode.GetString(data.Slice(start, maxChars * 2)).TrimEnd('\0');
        }

        var ansiEnd = start;
        while (ansiEnd < end && ansiEnd < data.Length && data[ansiEnd] != 0) ansiEnd++;
        if (ansiEnd == start) return "";
        var ansi = data.Slice(start, ansiEnd - start);
        // OEM/ANSI-кодировка системной локали достаточно точна для путей файлов.
        return Encoding.Default.GetString(ansi.ToArray());
    }

    /// <summary>Склеивает базовый путь с суффиксом без задвоения разделителей.</summary>
    private static string CombinePath(string basePath, string suffix)
    {
        if (basePath.EndsWith("\\", StringComparison.Ordinal) && suffix.StartsWith("\\", StringComparison.Ordinal))
            return basePath + suffix.Substring(1);
        if (!basePath.EndsWith("\\", StringComparison.Ordinal) && !suffix.StartsWith("\\", StringComparison.Ordinal) && suffix.Length > 0)
            return basePath + "\\" + suffix;
        return basePath + suffix;
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> data, int offset) =>
        (ushort)(data[offset] | (data[offset + 1] << 8));

    private static uint ReadUInt32(ReadOnlySpan<byte> data, int offset) =>
        (uint)(data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24));
}