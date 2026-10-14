using System.Buffers.Binary;
using System.Text;

namespace CatGuardian.Antivirus.Core.PE;

/// <summary>Результат чтения таблицы импорта PE (Anti-Spyware, 3.0.0.85).</summary>
public sealed record PeImportInfo(
    bool IsPe,
    IReadOnlyList<string> Functions,
    /// <summary>COFF TimeDateStamp — время компиляции/линковки (для репутации). 0 — не прочитан.</summary>
    uint TimeDateStamp);

/// <summary>
/// Лёгкий анализатор таблицы импорта PE (3.0.0.85, Anti-Spyware).
///
/// Читает ТОЛЬКО заголовки и куски данных, необходимые для получения списка
/// импортируемых функций: DOS → PE → COFF → Optional Header → DataDirectory[1]
/// (IMAGE_DIRECTORY_ENTRY_IMPORT) → IMAGE_IMPORT_DESCRIPTOR[] → IMAGE_THUNK_DATA[]
/// → IMAGE_IMPORT_BY_NAME. Построен по образцу <see cref="PeInspector"/> (Span-структуры,
/// BinaryPrimitives, никаких внешних зависимостей).
///
/// Связки импортов {GetAsyncKeyState+SetWindowsHookEx} и {BitBlt+GetDIBits+
/// CreateCompatibleDC+GetSystemMetrics} — характерные следы юзермодных кейлоггеров и
/// GDI-скринкаптеров из готовых стилеров (см. <see cref="Protection.SpywareSignatureDetector"/>).
/// </summary>
public static class PeImportsReader
{
    // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
    private const int DirectoryEntryImport = 1;
    // Позиция первого элемента массива DataDirectory относительно начала Optional Header
    // (PE32: +96, PE32+: +112). Само поле NumberOfRvaAndSizes — на 4 байта раньше.
    private const int ImageDirectoryEntriesOffset = 96;   // PE32
    private const int ImageDirectoryEntriesOffset64 = 112; // PE32+
    private const int ImageDirectoryEntrySize = 8;
    private const ushort Pe32Magic = 0x10B;
    private const ushort Pe32PlusMagic = 0x20B;

    /// <summary>Максимальное число функций на файл — защита от бесконечных таблиц.</summary>
    private const int MaxFunctions = 20000;
    /// <summary>Максимальное число импортируемых DLL — защита от повреждённых таблиц.</summary>
    private const int MaxDlls = 512;

    private static readonly HashSet<string> KnownBadFunctions = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "?", "???", "ordinal",
    };

    /// <summary>
    /// Читает имена импортируемых функций из PE-файла. Никогда не бросает исключений.
    /// Пустой список при: не-PE, повреждённых таблицах, отсутствии прав/файла.
    /// </summary>
    public static PeImportInfo Read(string filePath)
    {
        var empty = new PeImportInfo(false, Array.Empty<string>(), 0);
        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            if (fs.Length < 64)
            {
                return empty;
            }

            // DOS-заголовок: сигнатура MZ + e_lfanew.
            Span<byte> dos = stackalloc byte[64];
            if (ReadExact(fs, dos) < dos.Length || BinaryPrimitives.ReadUInt16LittleEndian(dos) != 0x5A4D)
            {
                return empty;
            }

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(dos[0x3C..]);
            if (peOffset <= 0 || peOffset + 24 > fs.Length)
            {
                return empty;
            }

            // PE-сигнатура + COFF-заголовок (20 байт).
            fs.Position = peOffset;
            Span<byte> sig = stackalloc byte[4];
            if (ReadExact(fs, sig) < sig.Length || !sig.SequenceEqual("PE\0\0"u8))
            {
                return empty;
            }

            Span<byte> coff = stackalloc byte[24];
            if (ReadExact(fs, coff) < coff.Length)
            {
                return empty;
            }

            var sections = BinaryPrimitives.ReadUInt16LittleEndian(coff[2..]);        // NumberOfSections
            var sizeOfOptional = BinaryPrimitives.ReadUInt16LittleEndian(coff[16..]); // SizeOfOptionalHeader
            var timeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(coff[4..]);   // TimeDateStamp
            if (sections == 0 || sections > 96 || sizeOfOptional < 96)
            {
                return new PeImportInfo(true, Array.Empty<string>(), timeDateStamp);
            }

            var optionalOffset = peOffset + 24;
            var magic = ReadUInt16(fs, optionalOffset);
            var isPe32Plus = magic == Pe32PlusMagic;
            if (magic != Pe32Magic && !isPe32Plus)
            {
                return new PeImportInfo(true, Array.Empty<string>(), timeDateStamp);
            }

            var dataDirPos = optionalOffset + (isPe32Plus ? ImageDirectoryEntriesOffset64 : ImageDirectoryEntriesOffset);
            // 3.0.0.85-fix: dataDirPos указывает на ПЕРВЫЙ элемент массива DataDirectory
            // (Export). Число каталогов лежит на 4 байта раньше (PE32: +92, PE32+: +108).
            // Раньше здесь читался Export RVA как «число каталогов», а importDirPos имел
            // лишние +4 — фактически читались Size каталога импорта и RVA каталога ресурсов
            // (у реального user32.dll получались RVA=0x35C/Size=0xBE000 → RvaToOffset=-1 →
            // пустой список функций, тест RealUser32 падал).
            var dataDirCount = ReadUInt32(fs, dataDirPos - 4);
            if (dataDirCount <= DirectoryEntryImport)
            {
                return new PeImportInfo(true, Array.Empty<string>(), timeDateStamp);
            }

            var importDirPos = dataDirPos + (DirectoryEntryImport * ImageDirectoryEntrySize);
            var importRva = ReadUInt32(fs, importDirPos);
            var importSize = ReadUInt32(fs, importDirPos + 4);

            // Таблица секций идёт сразу после Optional Header.
            var sectionTablePos = optionalOffset + sizeOfOptional;
            var sectionsParsed = ParseSections(fs, sectionTablePos, sections);
            if (importRva == 0 || sectionsParsed.Count == 0)
            {
                return new PeImportInfo(true, Array.Empty<string>(), timeDateStamp);
            }

            var functions = ReadImportDescriptors(fs, sectionsParsed, importRva, importSize, isPe32Plus);
            return new PeImportInfo(true, functions, timeDateStamp);
        }
        // 3.0.0.85-fix: EndOfStreamException — подкласс IOException; отдельный catch
        // недостижим (CS0160) и ломал Release-сборку. IOException уже покрывает его.
        catch (IOException)
        {
            return empty;
        }
        catch (UnauthorizedAccessException)
        {
            return empty;
        }
    }

    // ---------------------------------------------------------------
    // Таблицы секций и RVA → файловое смещение
    // ---------------------------------------------------------------

    private readonly record struct SectionMapping(uint VirtualAddress, uint RawOffset, uint RawSize);

    private static List<SectionMapping> ParseSections(Stream fs, long position, ushort count)
    {
        var result = new List<SectionMapping>(count);
        try
        {
            fs.Position = position;
            Span<byte> header = stackalloc byte[40];
            for (var i = 0; i < count; i++)
            {
                if (ReadExact(fs, header) < header.Length)
                {
                    break;
                }
                // IMAGE_SECTION_HEADER: VirtualAddress @12, SizeOfRawData @16, PointerToRawData @20.
                var va = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
                var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
                var rawPtr = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
                if (rawPtr > 0 && va > 0)
                {
                    result.Add(new SectionMapping(va, rawPtr, rawSize));
                }
            }
        }
        catch (IOException)
        {
            // Повреждённые секции — дальше проверка RvaToOffset отсеет лишнее.
        }
        return result;
    }

    /// <summary>RVA → файловое смещение по таблице секций; -1, если RVA вне секций.</summary>
    private static long RvaToOffset(List<SectionMapping> sections, uint rva)
    {
        foreach (var s in sections)
        {
            if (rva >= s.VirtualAddress && rva - s.VirtualAddress < Math.Max(1, s.RawSize))
            {
                return s.RawOffset + (rva - s.VirtualAddress);
            }
        }
        return -1;
    }

    // ---------------------------------------------------------------
    // IMPORT DESCRIPTOR → имена функций
    // ---------------------------------------------------------------

    private static List<string> ReadImportDescriptors(
        Stream fs, List<SectionMapping> sections, uint importRva, uint importSize, bool isPe32Plus)
    {
        var functions = new List<string>();
        var importOffset = RvaToOffset(sections, importRva);
        if (importOffset < 0)
        {
            return functions;
        }

        var thunkSize = isPe32Plus ? 8u : 4u;
        var readLimit = importSize > 0 ? importSize : 1_000_000u;
        Span<byte> desc = stackalloc byte[20];
        var descriptorOffset = importOffset;

        for (var dllIndex = 0; dllIndex < MaxDlls && functions.Count < MaxFunctions; dllIndex++)
        {
            if (descriptorOffset + 20 > fs.Length)
            {
                break;
            }
            fs.Position = descriptorOffset;
            if (ReadExact(fs, desc) < desc.Length)
            {
                break;
            }

            var originalFirstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc[0..]);  // OriginalFirstThunk
            var nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc[12..]);            // Name
            var firstThunk = BinaryPrimitives.ReadUInt32LittleEndian(desc[16..]);         // FirstThunk

            // Дескриптор с нулевым OriginalFirstThunk/FirstThunk/Name — конец таблицы.
            if (originalFirstThunk == 0 && firstThunk == 0 && nameRva == 0)
            {
                break;
            }

            var thunkRva = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
            ReadThunkChain(fs, sections, thunkRva, thunkSize, functions, readLimit);

            descriptorOffset += 20;
        }

        return functions;
    }

    private static void ReadThunkChain(
        Stream fs, List<SectionMapping> sections, uint thunkRva, uint thunkSize,
        List<string> functions, uint budget)
    {
        var pos = RvaToOffset(sections, thunkRva);
        if (pos < 0)
        {
            return;
        }

        var maxEntries = Math.Min(MaxFunctions, (int)(budget / Math.Max(1, thunkSize)) + 1);
        Span<byte> thunk = stackalloc byte[8];
        for (var i = 0; i < maxEntries && functions.Count < MaxFunctions; i++)
        {
            if (pos + thunkSize > fs.Length)
            {
                break;
            }
            fs.Position = pos;
            if (ReadExact(fs, thunk.Slice(0, (int)thunkSize)) < thunkSize)
            {
                break;
            }

            var value = thunkSize == 8
                ? BinaryPrimitives.ReadUInt64LittleEndian(thunk)
                : BinaryPrimitives.ReadUInt32LittleEndian(thunk);

            if (value == 0)
            {
                break; // конец цепочки
            }

            var ordinalFlag = thunkSize == 8 ? 0x8000000000000000UL : 0x80000000u;
            if ((value & ordinalFlag) == 0)
            {
                var byNameRva = (uint)(value & 0x7FFFFFFF);
                var byNameOffset = RvaToOffset(sections, byNameRva);
                if (byNameOffset >= 0 && byNameOffset + 2 <= fs.Length)
                {
                    var name = ReadAnsiStringAt(fs, byNameOffset + 2, 512); // после WORD Hint
                    if (!string.IsNullOrWhiteSpace(name) && !KnownBadFunctions.Contains(name))
                    {
                        functions.Add(name);
                    }
                }
            }
            // ordinal-импорт — имени нет, пропускаем (вариант флага в value).
            pos += (int)thunkSize;
        }
    }

    /// <summary>Читает ANSI-строку с максимальной длиной (имя функции, null-terminated).</summary>
    private static string ReadAnsiStringAt(Stream fs, long offset, int maxLen)
    {
        if (offset < 0 || offset >= fs.Length)
        {
            return "";
        }

        fs.Position = offset;
        Span<byte> buf = stackalloc byte[256];
        var sb = new StringBuilder(64);
        var total = 0;
        while (total < maxLen)
        {
            var toRead = Math.Min(buf.Length, maxLen - total);
            var read = fs.Read(buf[..toRead]);
            if (read <= 0)
            {
                break;
            }
            for (var i = 0; i < read; i++)
            {
                if (buf[i] == 0)
                {
                    return sb.ToString();
                }
                // Печатные ASCII + старшая половина (кириллица в именах встречается редко).
                if (buf[i] >= 0x20 && buf[i] != 0x7F)
                {
                    sb.Append((char)buf[i]);
                }
            }
            total += read;
        }
        return sb.ToString();
    }

    // ---------------------------------------------------------------
    // Низкоуровневое чтение
    // ---------------------------------------------------------------

    private static int ReadExact(Stream fs, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = fs.Read(buffer[total..]);
            if (read <= 0)
            {
                break;
            }
            total += read;
        }
        return total;
    }

    private static ushort ReadUInt16(Stream fs, long offset)
    {
        if (offset < 0 || offset + 2 > fs.Length)
        {
            throw new EndOfStreamException();
        }
        fs.Position = offset;
        Span<byte> buf = stackalloc byte[2];
        if (fs.Read(buf) < buf.Length)
        {
            throw new EndOfStreamException();
        }
        return BinaryPrimitives.ReadUInt16LittleEndian(buf);
    }

    private static uint ReadUInt32(Stream fs, long offset)
    {
        if (offset < 0 || offset + 4 > fs.Length)
        {
            throw new EndOfStreamException();
        }
        fs.Position = offset;
        Span<byte> buf = stackalloc byte[4];
        if (fs.Read(buf) < buf.Length)
        {
            throw new EndOfStreamException();
        }
        return BinaryPrimitives.ReadUInt32LittleEndian(buf);
    }
}