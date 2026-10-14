using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CatGuardian.Amsi.ComNet8;

/// <summary>
/// Читает текстовый контент из AMSI-потока устойчивыми стратегиями (по убыванию предпочтения):
/// <list type="number">
/// <item><b>ContentSize → Content</b> (официальная схема amsi.h): размер через
/// <c>AMSI_ATTRIBUTE_CONTENT_SIZE</c>, затем байты через <c>AMSI_ATTRIBUTE_CONTENT</c>;</item>
/// <item><b>Content с нулевым буфером</b>: часть хостов не отдаёт CONTENT_SIZE корректно —
/// вызов <c>AMSI_ATTRIBUTE_CONTENT</c> с dataSize=0 возвращает требуемый размер в retData,
/// после чего контент копируется вторым вызовом;</item>
/// <item><b>ContentName (двухфазная схема)</b>: PowerShell 5.1 не поддерживает CONTENT* вообще
/// (E_INVALIDARG), а Read — E_NOTIMPL: его поток <c>PSNativeAmsiStream</c> отдаёт контент
/// ЧЕРЕЗ атрибут <c>AMSI_ATTRIBUTE_CONTENT_NAME</c>. Для <c>-Command</c> это сам текст команды;
/// для <c>-File</c> — путь к файлу (тогда читаем файл сами). Схема: запрос размера вызовом
/// GetAttribute(dataSize=0) → хост отвечает ERROR_INSUFFICIENT_BUFFER (0x8007007A) и кладёт
/// требуемый размер в retData; второй вызов с выделенным буфером копирует строку;</item>
/// <item><b>Read(position, size)</b> по чанкам 64 КБ: потоковый интерфейс <c>IAmsiStream::Read</c>
/// как последний рубеж для хостов, не поддерживающих атрибуты.</item>
/// </list>
/// Каждая стратегия изолирована try-catch: сбой одной не мешает следующей.
/// Все вызовы идут через <see cref="IntPtr"/> + <c>Marshal.AllocHGlobal/Marshal.Copy</c> —
/// точное соответствие нативному контракту (массив с SizeParamIndex ломает RCW-маршалинг).
/// Кодировка определяется по BOM, иначе — эвристика UTF-16 (PowerShell/Office передают UTF-16LE
/// без BOM), затем строгий UTF-8, фолбэк Windows-1251. Верхний лимит 64 МБ защищает от OOM.
/// </summary>
internal static class AmsiStreamReader
{
    /// <summary>Верхний предел размера контента (64 МБ) — защита от аномально больших буферов.</summary>
    private const uint MaxContentBytes = 64 * 1024 * 1024;

    /// <summary>Размер чанка для потокового чтения через IAmsiStream::Read.</summary>
    private const uint ReadChunkBytes = 64 * 1024;

    /// <summary>
    /// Системная ANSI-кодовая страница (Windows-1251 на ru) — фолбэк декодера.
    /// НЕ <see cref="Encoding.Default"/>: в .NET Core он равен UTF-8, а реальные AMSI-хосты
    /// (PS 5.1/Office) для ANSI-контента используют системную кодовую страницу.
    /// </summary>
    private static readonly Encoding AnsiEncoding = ResolveAnsiEncoding();

    private static Encoding ResolveAnsiEncoding()
    {
        try
        {
            return Encoding.GetEncoding(System.Globalization.CultureInfo.CurrentCulture.TextInfo.ANSICodePage);
        }
        catch
        {
            return Encoding.UTF8;
        }
    }

    public static string? ReadAll(IAmsiStream? stream) => ReadAll(stream, null);

    /// <summary>
    /// Вариант с явным путём к config.json: тесты изолируются от реального конфига машины
    /// (config с DebugLog=false гарантирует отсутствие записи в %APPDATA% при прогоне).
    /// Боевой код вызывает ReadAll(stream) — поведение не меняется.
    /// </summary>
    internal static string? ReadAll(IAmsiStream? stream, string? configFilePath)
    {
        if (stream is null) return null;

        // Стратегия 1: официальная схема Microsoft (CONTENT_SIZE + CONTENT).
        var result = TryReadViaContentSize(stream, configFilePath);
        Log($"ReadAll: strategy1(ContentSize) -> {(result is null ? "FAILED" : "OK len=" + result.Length)}", configFilePath);
        if (result is not null) return result;

        // Стратегия 1b: CONTENT сразу с ненулевым буфером (часть хостов не поддерживает
        // запрос размера — E_INVALIDARG на dataSize=0, но копирует напрямую).
        result = TryReadViaContentDirect(stream, configFilePath);
        Log($"ReadAll: strategy1b(ContentDirect) -> {(result is null ? "FAILED" : "OK len=" + result.Length)}", configFilePath);
        if (result is not null) return result;

        // Стратегия 2: CONTENT с нулевым буфером — хост сам сообщает размер в retData.
        result = TryReadViaContentZero(stream, configFilePath);
        Log($"ReadAll: strategy2(ContentZero) -> {(result is null ? "FAILED" : "OK len=" + result.Length)}", configFilePath);
        if (result is not null) return result;

        // Стратегия 3 (POWERSHELL 5.1): ContentName двухфазной схемой.
        // PS 5.1 отдаёт контент через AMSI_ATTRIBUTE_CONTENT_NAME: для -Command это текст
        // команды, для -File — путь (читаем файл сами). Ставится ДО Read, т.к. поток PS
        // возвращает E_NOTIMPL на Read, а ContentName — единственный источник контента.
        result = TryReadViaContentName(stream, configFilePath);
        Log($"ReadAll: strategy3(ContentName) -> {(result is null ? "FAILED" : "OK len=" + result.Length)}", configFilePath);
        if (result is not null) return result;

        // Стратегия 4: потоковый Read(position, size) по чанкам.
        result = TryReadViaRead(stream, configFilePath);
        Log($"ReadAll: strategy4(Read) -> {(result is null ? "FAILED" : "OK len=" + result.Length)}", configFilePath);
        if (result is not null) return result;

        return null;
    }

    private static string? TryReadViaContentSize(IAmsiStream stream, string? configFilePath)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            // Вариант A: запрос размера нулевым буфером (штатный amsi.h).
            uint size = 0;
            int hr1 = stream.GetAttribute(AmsiAttribute.ContentSize, 0, IntPtr.Zero, out size);

            // Вариант B: некоторые реализации (CAmAmsiStream в amsi.dll) требуют
            // dataSize >= sizeof(ULONG) и ненулевой буфер даже для запроса размера.
            if (hr1 != 0)
            {
                Log($"ContentSize: hr=0x{hr1:X8} (dataSize=0) -> retry with dataSize=4", configFilePath);
                IntPtr probe = Marshal.AllocHGlobal(4);
                try
                {
                    uint dummy = 0;
                    int hr1b = stream.GetAttribute(AmsiAttribute.ContentSize, 4, probe, out dummy);
                    if (hr1b == 0) size = (uint)Marshal.ReadInt32(probe);
                    Log($"ContentSize: retry(4) -> hr=0x{hr1b:X8} size={size}", configFilePath);
                }
                finally
                {
                    Marshal.FreeHGlobal(probe);
                }
            }
            else
            {
                Log($"ContentSize: hr=0x{hr1:X8} size={size}", configFilePath);
            }

            if (size == 0 || size > MaxContentBytes) return null;

            buf = Marshal.AllocHGlobal((int)size);
            uint written = 0;
            int hr2 = stream.GetAttribute(AmsiAttribute.Content, size, buf, out written);
            Log($"Content: hr=0x{hr2:X8} written={written}", configFilePath);
            if (hr2 != 0) return null;
            if (written == 0 || written > size) return null;

            var bytes = new byte[written];
            Marshal.Copy(buf, bytes, 0, (int)written);
            return Decode(bytes, (int)written);
        }
        catch (Exception ex)
        {
            Log($"ContentSize: EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>Размер пробного буфера для прямого чтения CONTENT без предварительного запроса размера.</summary>
    private const uint DirectProbeBytes = 1024 * 1024;

    private static string? TryReadViaContentDirect(IAmsiStream stream, string? configFilePath)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            buf = Marshal.AllocHGlobal((int)DirectProbeBytes);
            uint written = 0;
            int hr = stream.GetAttribute(AmsiAttribute.Content, DirectProbeBytes, buf, out written);
            Log($"ContentDirect: hr=0x{hr:X8} written={written}", configFilePath);
            if (hr != 0 || written == 0) return null;
            if (written > MaxContentBytes) return null;

            var bytes = new byte[written];
            Marshal.Copy(buf, bytes, 0, (int)written);
            return Decode(bytes, (int)written);
        }
        catch (Exception ex)
        {
            Log($"ContentDirect: EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static string? TryReadViaContentZero(IAmsiStream stream, string? configFilePath)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            uint needed = 0;
            int hr1 = stream.GetAttribute(AmsiAttribute.Content, 0, IntPtr.Zero, out needed);
            Log($"ContentZero probe: hr=0x{hr1:X8} needed={needed}", configFilePath);
            if (hr1 != 0) return null;
            if (needed == 0 || needed > MaxContentBytes) return null;

            buf = Marshal.AllocHGlobal((int)needed);
            uint written = 0;
            int hr2 = stream.GetAttribute(AmsiAttribute.Content, needed, buf, out written);
            Log($"ContentZero read: hr=0x{hr2:X8} written={written}", configFilePath);
            if (hr2 != 0) return null;
            if (written == 0 || written > needed) return null;

            var bytes = new byte[written];
            Marshal.Copy(buf, bytes, 0, (int)written);
            return Decode(bytes, (int)written);
        }
        catch (Exception ex)
        {
            Log($"ContentZero: EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>
    /// Стратегия PowerShell 5.1: контент отдаётся через атрибут AMSI_ATTRIBUTE_CONTENT_NAME.
    /// <para>- <c>-Command</c>: значением является сам текст команды (декодируем как контент);</para>
    /// <para>- <c>-File</c>: значением является путь к .ps1-файлу — читаем файл сами
    /// ; если файла нет — используем значение как контент.</para>
    /// </summary>
    private static string? TryReadViaContentName(IAmsiStream stream, string? configFilePath)
    {
        var name = TryReadStringAttributeTwoPhase(stream, AmsiAttribute.ContentName, "ContentName", configFilePath);
        if (string.IsNullOrEmpty(name)) return null;
        Log($"ContentName: value=\"{Truncate(name, 300)}\"", configFilePath);

        // Гипотеза (a): для -File PS отдаёт путь к файлу — читаем содержимое сами.
        try
        {
            if (File.Exists(name))
            {
                var fi = new FileInfo(name);
                if (fi.Length <= MaxContentBytes)
                {
                    var bytes = File.ReadAllBytes(name);
                    Log($"ContentName: file exists ({fi.Length} bytes), reading file content", configFilePath);
                    return Decode(bytes, bytes.Length);
                }

                Log($"ContentName: file too large ({fi.Length} bytes), skipping", configFilePath);
            }
        }
        catch (Exception ex)
        {
            Log($"ContentName: file read EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
        }

        // Для -Command ContentName == текст команды: уже декодирован выше.
        Log("ContentName: used as content directly (not a file path)", configFilePath);
        return name;
    }

    /// <summary>
    /// Двухфазное чтение строкового атрибута (AppName/ContentName) — схема, которую реально
    /// реализует PowerShell 5.1 (PSNativeAmsiStream):
    /// <list type="number">
    /// <item>GetAttribute(attr, dataSize=0, data=NULL) → хост отвечает
    /// ERROR_INSUFFICIENT_BUFFER (0x8007007A) и кладёт ТРЕБУЕМЫЙ размер в retData
    /// (некоторые хосты отвечают S_OK — обрабатываем оба варианта);</item>
    /// <item>GetAttribute(attr, dataSize=needed, data=buffer) → копирует строку, S_OK.</item>
    /// </list>
    /// Возвращает декодированную строку (UTF-16 без BOM → эвристика) или null при сбое.
    /// </summary>
    private static string? TryReadStringAttributeTwoPhase(IAmsiStream stream, AmsiAttribute attribute, string name, string? configFilePath)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            uint needed = 0;
            int hr1 = stream.GetAttribute(attribute, 0, IntPtr.Zero, out needed);
            if (needed == 0 || needed > MaxContentBytes)
            {
                Log($"{name} two-phase: size query -> hr=0x{hr1:X8} needed={needed} (no size)", configFilePath);
                return null;
            }
            if (hr1 != 0)
            {
                Log($"{name} two-phase: size query -> hr=0x{hr1:X8} needed={needed} (ERROR_INSUFFICIENT_BUFFER, continue)", configFilePath);
            }
            else
            {
                Log($"{name} two-phase: size query -> hr=0x{hr1:X8} (S_OK) needed={needed}", configFilePath);
            }

            buf = Marshal.AllocHGlobal((int)needed);
            uint written = 0;
            int hr2 = stream.GetAttribute(attribute, needed, buf, out written);
            Log($"{name} two-phase: fill -> hr=0x{hr2:X8} written={written} (asked={needed})", configFilePath);
            if (hr2 != 0) return null;
            if (written == 0 || written > needed) return null;

            var bytes = new byte[written];
            Marshal.Copy(buf, bytes, 0, (int)written);
            var text = Decode(bytes, (int)written);
            // PowerShell может включать завершающий NUL в размер строки — срезаем.
            return text?.TrimEnd('\0');
        }
        catch (Exception ex)
        {
            Log($"{name} two-phase: EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    private static string? TryReadViaRead(IAmsiStream stream, string? configFilePath)
    {
        IntPtr buf = IntPtr.Zero;
        try
        {
            using (var ms = new MemoryStream())
            {
                buf = Marshal.AllocHGlobal((int)ReadChunkBytes);
                ulong position = 0;
                while (true)
                {
                    uint got = 0;
                    int hr = stream.Read(position, ReadChunkBytes, buf, out got);
                    Log($"Read: pos={position} hr=0x{hr:X8} got={got}", configFilePath);
                    if (hr != 0 || got == 0) break;

                    var chunk = new byte[got];
                    Marshal.Copy(buf, chunk, 0, (int)got);
                    ms.Write(chunk, 0, (int)got);
                    position += got;
                    if (got < ReadChunkBytes) break;     // достигнут конец потока
                    if (ms.Length > MaxContentBytes) return null; // превышен лимит
                }

                if (ms.Length == 0) return null;
                return Decode(ms.ToArray(), (int)ms.Length);
            }
        }
        catch (Exception ex)
        {
            Log($"Read: EXCEPTION {ex.GetType().Name}: {ex.Message}", configFilePath);
            return null;
        }
        finally
        {
            if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
        }
    }

    internal static string Decode(byte[] bytes, int count)
    {
        // BOM-детект.
        if (count >= 3 && bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF)
            return Encoding.UTF8.GetString(bytes, 3, count - 3);
        if (count >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE)
            return Encoding.Unicode.GetString(bytes, 2, count - 2);
        if (count >= 2 && bytes[0] == 0xFE && bytes[1] == 0xFF)
            return Encoding.BigEndianUnicode.GetString(bytes, 2, count - 2);

        // Эвристика UTF-16 без BOM: реальные AMSI-хосты (PowerShell 5.1, Office) передают
        // контент как UTF-16LE без BOM. Признак: чётная длина и плотное распределение
        // нулевых байтов (0x00 в каждой второй позиции для ASCII/Latin-1 диапазона).
        if (LooksLikeUtf16Le(bytes, count))
            return Encoding.Unicode.GetString(bytes, 0, count);
        if (LooksLikeUtf16Be(bytes, count))
            return Encoding.BigEndianUnicode.GetString(bytes, 0, count);

        // Строгий UTF-8: если байты валидны — UTF-8, иначе системная ANSI (Windows-1251 на ru).
        try
        {
            var utf8Strict = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);
            return utf8Strict.GetString(bytes, 0, count);
        }
        catch (DecoderFallbackException)
        {
            return AnsiEncoding.GetString(bytes, 0, count);
        }
    }

    /// <summary>
    /// Детект UTF-16LE без BOM: чётная длина, минимум 2 символа; «текстовая пара» —
    /// ASCII (старший байт 0x00) или кириллица (U+0410–U+045F, старший байт 0x04,
    /// включая Ё/ё U+0401/U+0451). Расширение по сравнению с исходной версией:
    /// кириллический скрипт целиком не распознавался (все старшие байты 0x04),
    /// из-за чего ASCII-маркеры внутри него терялись и давали ложный NOT_DETECTED.
    /// Консервативно: не менее 50% пар должны быть текстовыми.
    /// </summary>
    private static bool LooksLikeUtf16Le(byte[] bytes, int count)
    {
        if (count < 4 || (count & 1) != 0) return false;
        int pairs = count / 2;
        int textPairs = 0;
        for (int i = 0; i < pairs; i++)
        {
            if (IsPlausibleUtf16Pair(bytes[i * 2], bytes[i * 2 + 1])) textPairs++;
        }
        return textPairs >= pairs * 0.5 && textPairs >= 2;
    }

    /// <summary>Детект UTF-16BE без BOM (зеркальный вариант, редкость, но дёшево проверить).</summary>
    private static bool LooksLikeUtf16Be(byte[] bytes, int count)
    {
        if (count < 4 || (count & 1) != 0) return false;
        int pairs = count / 2;
        int textPairs = 0;
        for (int i = 0; i < pairs; i++)
        {
            if (IsPlausibleUtf16Pair(bytes[i * 2 + 1], bytes[i * 2])) textPairs++;
        }
        return textPairs >= pairs * 0.5 && textPairs >= 2;
    }

    /// <summary>
    /// Правдоподобная UTF-16-пара (lo, hi) для скриптового текста:
    /// ASCII 0x20–0x7E со старшим байтом 0x00; кириллица U+0401–U+045F (байт 0x04).
    /// </summary>
    private static bool IsPlausibleUtf16Pair(byte lo, byte hi)
    {
        if (hi == 0x00 && lo >= 0x20 && lo <= 0x7E) return true;
        if (hi == 0x04 && lo >= 0x01 && lo <= 0x5F) return true; // U+0401..U+045F
        return false;
    }

    /// <summary>Обрезает длинную строку для диагностического лога (без ущерба для вердикта).</summary>
    private static string Truncate(string? value, int maxChars)
    {
        if (string.IsNullOrEmpty(value)) return "<empty>";
        var normalized = value.Replace("\r", "\\r").Replace("\n", "\\n");
        return normalized.Length <= maxChars
            ? normalized
            : normalized.Substring(0, maxChars) + $"...(+{normalized.Length - maxChars} chars)";
    }

    /// <summary>Диагностическая запись (только при AmsiDebugLog=true) в amsi-provider-debug.log.</summary>
    private static void Log(string message, string? configFilePath = null)
    {
        try
        {
            var settings = CatGuardian.Amsi.Core.AmsiRuntimeSettings.Get(configFilePath);
            if (!settings.DebugLogEnabled) return;
            var cfg = settings.ConfigFilePath;
            var dir = string.IsNullOrEmpty(cfg) ? Path.GetTempPath() : Path.GetDirectoryName(cfg);
            if (string.IsNullOrEmpty(dir)) dir = Path.GetTempPath();

            var logPath = Path.Combine(dir, "amsi-provider-debug.log");
            TrimLog(logPath);
            File.AppendAllText(
                logPath,
                $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{Environment.ProcessId}] [Reader] {message}{Environment.NewLine}");
        }
        catch
        {
            // Логирование не должно ломать чтение потока.
        }
    }

    /// <summary>Ограничение amsi-provider-debug.log 1 МБ (перезапись при превышении).</summary>
    private static void TrimLog(string logPath)
    {
        try
        {
            var fi = new FileInfo(logPath);
            if (fi.Exists && fi.Length > 1024 * 1024) File.Delete(logPath);
        }
        catch
        {
            // Файл заблокирован — просто дописываем (не критично).
        }
    }
}