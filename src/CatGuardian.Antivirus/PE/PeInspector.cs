using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace CatGuardian.Antivirus.Core.PE;

/// <summary>
/// Лёгкий анализатор PE-заголовка: проверка сигнатур MZ/PE, числа секций и
/// наличия встроенной цифровой подписи (каталог безопасности). Является
/// упрощённым переносом части логики <c>VerifyPEFormat.pas</c>.
/// </summary>
public static class PeInspector
{
    // IMAGE_DIRECTORY_ENTRY_SECURITY
    private const int DirectoryEntrySecurity = 4;
    private const int ImageDirectoryEntriesOffset = 96;
    private const int ImageDirectoryEntrySize = 8;
    private const int PeSignatureOffsetInOptionalHeader = 16; // Magic (2) + ...
    // M9: по спецификации PE/COFF поле NumberOfSections лежит на смещении 2
    // (после WORD Machine). Ранее 6 — читались старшие байты TimeDateStamp, и
    // валидные PE с ненулевым таймстампом ошибочно считались «повреждёнными».
    private const int NumberOfSectionsOffset = 2;   // в COFF-заголовке
    private const int OptionalHeaderOffset = 24;    // COFF-заголовок целиком

    public static PeInspectionResult Inspect(string filePath)
    {
        try
        {
            using var fs = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            var size = fs.Length;
            if (size < 64)
            {
                return NonPe(size);
            }

            Span<byte> mz = stackalloc byte[64];
            if (fs.Read(mz) < mz.Length)
            {
                return NonPe(size);
            }

            if (!IsMzHeader(mz))
            {
                return NonPe(size);
            }

            var peOffset = BinaryPrimitives.ReadInt32LittleEndian(mz[0x3C..]);
            if (peOffset <= 0 || peOffset + 24 > fs.Length)
            {
                return new PeInspectionResult(true, false, 0, false, size);
            }

            fs.Position = peOffset;
            Span<byte> peSig = stackalloc byte[4];
            fs.Read(peSig);
            if (!peSig.SequenceEqual("PE\0\0"u8))
            {
                return new PeInspectionResult(true, false, 0, false, size);
            }

            Span<byte> coff = stackalloc byte[20];
            if (fs.Read(coff) < coff.Length)
            {
                return new PeInspectionResult(true, false, 0, false, size);
            }

            var sections = BinaryPrimitives.ReadUInt16LittleEndian(coff[NumberOfSectionsOffset..]);
            var hasEmbeddedSignature = HasEmbeddedSignature(fs, peOffset, sections);

            return new PeInspectionResult(
                IsPe: true,
                HeaderOk: sections is > 0 and <= 96,
                NumberOfSections: sections,
                HasEmbeddedSignature: hasEmbeddedSignature,
                Size: size);
        }
        catch (IOException)
        {
            return NonPe(0);
        }
        catch (UnauthorizedAccessException)
        {
            return NonPe(0);
        }
    }

    private static PeInspectionResult NonPe(long size)
        => new(false, false, 0, false, size);

    private static bool IsMzHeader(ReadOnlySpan<byte> header)
    {
        const ushort MzSignature = 0x5A4D; // "MZ"
        return BinaryPrimitives.ReadUInt16LittleEndian(header) == MzSignature;
    }

    private static bool HasEmbeddedSignature(Stream fs, int peOffset, ushort numberOfSections)
    {
        // Расположение каталога безопасности вычисляется из COFF + Optional Header.
        // Для простоты читаем поля размера/смещения каталога безопасности.
        try
        {
            // Заголовок Optional header начинается сразу после COFF (24 байта).
            var optionalOffset = peOffset + 24;
            var optMagic = ReadUInt16(fs, optionalOffset);
            var isPe32Plus = optMagic == 0x20B; // PE32+
            var dataDirCountPos = optionalOffset + (isPe32Plus ? 108 : 92);
            var dataDirCount = ReadUInt32(fs, dataDirCountPos);
            if (dataDirCount <= DirectoryEntrySecurity)
            {
                return false;
            }

            // Каталог безопасности (IMAGE_DIRECTORY_ENTRY_SECURITY):
            //   VirtualAddress — ФАЙЛОВОЕ смещение таблицы сертификатов (не RVA!),
            //   Size — размер таблицы.
            // M9: ранее условие `certRva == 0` было неверным (файл не может начинаться
            // с таблицы сертификатов), поэтому подписанные PE почти всегда считались
            // неподписанными и получали лишнее «плохое очко» в эвристике инспектора.
            var entryPos = dataDirCountPos + 4 + (DirectoryEntrySecurity * ImageDirectoryEntrySize);
            var certOffset = ReadUInt32(fs, entryPos);
            var certSize = ReadUInt32(fs, entryPos + 4);
            return certSize > 0
                   && certOffset > 0
                   && certOffset + certSize <= fs.Length;
        }
        catch (EndOfStreamException)
        {
            return false;
        }
    }

    private static ushort ReadUInt16(Stream fs, long offset)
    {
        // M9: выход за пределы файла должен приводить к EndOfStreamException,
        // а не к ArgumentOutOfRangeException от FileStream.Position (усечённый PE).
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