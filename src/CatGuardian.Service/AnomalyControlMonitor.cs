using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using CatGuardian.Antivirus.Core.Configuration;
using CatGuardian.Antivirus.Core.Logging;
using CatGuardian.Antivirus.Core.Signing;
using CatGuardian.Firewall.Core;
using CatGuardian.Firewall.Services;
using CatGuardian.Integrity;
using CatGuardian.Integrity.Ipc;
using CatGuardian.Integrity.Models;
using CatGuardian.Integrity.Services;
using Microsoft.Win32;

namespace CatGuardian.Service;

// ===========================================================================
// «Контроль скрытой активности и аномалий» (3.0.0.24, HIPS-lite)
//
// Лёгкий user-mode модуль аудита аномалий без драйвера ядра. Три подсистемы:
//  1) DeepPersistenceAuditor — дифференциальный аудит «тяжёлых» точек закрепления:
//     COM Hijacking (HKCU\<SID>\Software\Classes\CLSID), Shell Extensions
//     (ContextMenuHandlers, ShellServiceObjectDelayLoad, Print Monitors,
//     Credential Providers), Session Manager\BootExecute, per-SID перечисление
//     активных интерактивных сессий через WTSEnumerateSessions;
//  2) BeaconTracker — детектор устойчивых C&C-маяков/эксфильтрации: неподписанный
//     процесс из недоверенного каталога, держащий исходящую сеть N циклов поллинга
//     подряд → постфактум Block-правило брандмауэра по ПУТИ файла (не по хэшу —
//     INetFwPolicy2 его не поддерживает) + сверка SHA-256 каждые N секунд с
//     предфильтром «размер+mtime» (нулевая стоимость для неизменённых файлов);
//  3) MemoryAuditScanner — точечный YARA-скан приватных регионов памяти
//     (MEM_PRIVATE c PAGE_EXECUTE_READ/RWX) рискованных процессов с жёстким
//     таймаутом и ThreadPriority.Lowest. Правила — встроенный YARA-подобный
//     рулсет (строковые/hex-сигнатуры шеллкодов и распаковщиков кейлоггеров),
//     обновляемый подписанным пакетом (хук ReloadRules).
//
// ОГРАНИЧЕНИЯ User-Mode (честно отражены в UI): модуль не перехватывает ввод
// с клавиатуры в реальном времени, не блокирует первый пакет сетевой утечки
// (особенно UDP/DNS) и не обнаруживает руткиты ядра. Это дополнительный
// эшелон контроля конфигурации, а не замена Windows Defender.
//
// Модуль создаётся ТОЛЬКО при включённой настройке AnomalyControlEnabled —
// при выключенной не создаёт ни одного таймера (нулевая нагрузка).
// ===========================================================================

/// <summary>Результат глубокого аудита одной точки закрепления.</summary>
public sealed record DeepPersistenceFinding(
    AnomalyThreatKindDto Kind,
    string Location,
    string TargetPath,
    string Details);

/// <summary>
/// Трекер «маяка»: сколько циклов поллинга подряд процесс (PID+путь) держит
/// исходящую сеть. Чистая логика — полностью юнит-тестируема.
/// </summary>
public sealed class BeaconTracker
{
    private readonly int _requiredCycles;
    private readonly Dictionary<string, int> _cycles = new(StringComparer.OrdinalIgnoreCase);

    public BeaconTracker(int requiredCycles)
    {
        _requiredCycles = Math.Max(2, requiredCycles);
    }

    /// <summary>
    /// Регистрирует цикл поллинга. Возвращает true, когда процесс набрал
    /// <see cref="_requiredCycles"/> последовательных циклов исходящей сети.
    /// </summary>
    public bool Track(int pid, string path, bool hasOutbound)
    {
        var key = pid + "|" + path;
        if (!hasOutbound)
        {
            _cycles.Remove(key);
            return false;
        }
        _cycles.TryGetValue(key, out var c);
        c++;
        if (c >= _requiredCycles)
        {
            // Вердикт вынесен — сбрасываем, чтобы не спамить алерты до кулдауна.
            _cycles.Remove(key);
            return true;
        }
        _cycles[key] = c;
        return false;
    }

    /// <summary>Полное очищение (остановка модуля / перезагрузка конфига).</summary>
    public void Clear() => _cycles.Clear();
}

/// <summary>
/// Кэш сверки SHA-256 заблокированных бинарников (3.0.0.24).
/// Производительность: перед хэшированием — предфильтр «размер + LastWriteTimeUtc»;
/// хэш файла считается только если эти метаданные изменились. SHA-256 небольшого
/// exe (1–10 МБ) занимает единицы миллисекунд, поэтому таймер 5 с на крошечном
/// множестве заблокированных путей не создаёт заметной нагрузки.
/// </summary>
public sealed class BlockedBinaryWatch
{
    private sealed record Entry(string Hash, long Size, long LastWriteTicks);

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);

    public void Add(string path, string hash)
    {
        if (!File.Exists(path)) return;
        var fi = new FileInfo(path);
        _entries[path] = new Entry(hash, fi.Length, fi.LastWriteTimeUtc.Ticks);
    }

    public void Remove(string path) => _entries.Remove(path);

    public bool IsWatched(string path) => _entries.ContainsKey(path);

    /// <summary>
    /// Проверяет текущий файл: если размер/mtime не изменились — вернуть null (без
    /// хэширования). Если изменились — вычислить SHA-256 и вернуть (старый, новый).
    /// </summary>
    public (string OldHash, string NewHash)? Recheck(string path)
    {
        if (!_entries.TryGetValue(path, out var entry) || !File.Exists(path))
        {
            _entries.Remove(path);
            return null;
        }
        var fi = new FileInfo(path);
        if (fi.Length == entry.Size && fi.LastWriteTimeUtc.Ticks == entry.LastWriteTicks)
        {
            return null; // файл не менялся — SHA-256 не считаем
        }
        var newHash = ComputeSha256(path);
        if (string.Equals(entry.Hash, newHash, StringComparison.OrdinalIgnoreCase))
        {
            _entries[path] = entry with { Size = fi.Length, LastWriteTicks = fi.LastWriteTimeUtc.Ticks };
            return null;
        }
        _entries[path] = new Entry(newHash, fi.Length, fi.LastWriteTimeUtc.Ticks);
        return (entry.Hash, newHash);
    }

    private static string ComputeSha256(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }
}

/// <summary>Встроенное YARA-правило (подмножество синтаксиса YARA).</summary>
public sealed class MemoryRule
{
    public string Name { get; init; } = "";
    /// <summary>Строки правила: идентификатор, байты, маска (true = байт должен совпадать,
    /// false = wildcard '??'), флаг nocase (только для текстовых строк).</summary>
    public List<(string Id, byte[] Bytes, bool[] Mask, bool NoCase)> Strings { get; } = new();
    public string Condition { get; set; } = "any of them";
}

/// <summary>
/// Лёгкий локальный инспекционный движок YARA-подмножества (3.0.0.24).
/// Поддерживает блоки strings («строка» c модификатором nocase и {hex с ?? }) и
/// условие: all of them / any of them / N of them / выражения через and/or/(...).
/// Сканирование выполняется в процессе службы (без IPC), таймаут на вызывающей
/// стороне. Правила обновляются подписанным пакетом через <see cref="ReloadText"/>.
/// </summary>
public sealed class MemoryRuleEngine
{
    private List<MemoryRule> _rules = new();

    public IReadOnlyList<MemoryRule> Rules => _rules;

    /// <summary>Компилирует текст YARA-подобного рулсета. Некорректные правила пропускаются.</summary>
    public void ReloadText(string text)
    {
        var parsed = new List<MemoryRule>();
        foreach (var block in SplitRules(text))
        {
            var rule = ParseRule(block);
            if (rule is not null) parsed.Add(rule);
        }
        if (parsed.Count > 0) _rules = parsed;
    }

    /// <summary>Ищет совпадения в байтах (обычно — приватный регион памяти).</summary>
    public List<string> Match(byte[] data)
    {
        var hits = new List<string>();
        foreach (var rule in _rules)
        {
            if (Evaluate(rule, data)) hits.Add(rule.Name);
        }
        return hits;
    }

    private static IEnumerable<string> SplitRules(string text)
    {
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var sb = new StringBuilder();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0) continue;
            if (line.StartsWith("rule ", StringComparison.Ordinal))
            {
                if (sb.Length > 0) { yield return sb.ToString(); sb.Clear(); }
            }
            sb.AppendLine(raw);
        }
        if (sb.Length > 0) yield return sb.ToString();
    }

    private static MemoryRule? ParseRule(string block)
    {
        try
        {
            var nameStart = block.IndexOf("rule ", StringComparison.Ordinal) + 5;
            var nameEnd = block.IndexOf('{', nameStart);
            if (nameEnd < 0) return null;
            var name = block[nameStart..nameEnd].Trim();
            if (name.Length == 0) return null;

            var rule = new MemoryRule { Name = name };

            // Блок strings: $id = "text" [nocase] | $id = { AA BB ?? CC }
            var stringsStart = block.IndexOf("strings:", StringComparison.Ordinal);
            var conditionStart = block.IndexOf("condition:", StringComparison.Ordinal);
            if (conditionStart < 0) return null;
            if (stringsStart >= 0)
            {
                var stringsBody = block[(stringsStart + "strings:".Length)..conditionStart];
                foreach (var rawLine in stringsBody.Split('\n'))
                {
                    var line = rawLine.Trim();
                    if (!line.StartsWith('$')) continue;
                    var eq = line.IndexOf('=');
                    if (eq < 0) continue;
                    var id = line[..eq].Trim();
                    var rhs = line[(eq + 1)..].Trim();
                    var noCase = rhs.EndsWith("nocase", StringComparison.OrdinalIgnoreCase);
                    if (noCase) rhs = rhs[..^"nocase".Length].TrimEnd();
                    if (rhs.StartsWith('"'))
                    {
                        var close = rhs.IndexOf('"', 1);
                        if (close < 0) continue;
                        var lit = rhs[1..close];
                        var bytes = Encoding.UTF8.GetBytes(lit);
                        if (noCase) bytes = ToLower(bytes);
                        var mask = Enumerable.Repeat(true, bytes.Length).ToArray();
                        rule.Strings.Add((id, bytes, mask, noCase));
                    }
                    else if (rhs.StartsWith('{'))
                    {
                        var close = rhs.IndexOf('}');
                        if (close < 0) continue;
                        var hex = rhs[1..close].Replace(" ", "").Replace("\t", "").Replace("\r", "").Replace("\n", "");
                        if (hex.Length % 2 != 0) continue;
                        var bytes = new List<byte>();
                        var mask = new List<bool>();
                        for (var i = 0; i < hex.Length; i += 2)
                        {
                            var chunk = hex.Substring(i, 2);
                            if (chunk.Contains('?'))
                            {
                                bytes.Add(0);
                                mask.Add(false); // wildcard
                            }
                            else
                            {
                                bytes.Add(Convert.ToByte(chunk, 16));
                                mask.Add(true);
                            }
                        }
                        rule.Strings.Add((id, bytes.ToArray(), mask.ToArray(), false));
                    }
                }
            }

            var condRaw = block[(conditionStart + "condition:".Length)..];
            var closeBrace = condRaw.LastIndexOf('}');
            if (closeBrace >= 0) condRaw = condRaw[..closeBrace];
            var cond = NormalizeCondition(condRaw.Trim());
            if (cond.Length > 0) rule.Condition = cond;
            return rule;
        }
        catch
        {
            return null;
        }
    }

    private static string NormalizeCondition(string raw)
    {
        var s = raw.Replace("\r", " ").Replace("\n", " ").Trim();
        s = System.Text.RegularExpressions.Regex.Replace(s, @"\s+", " ").Trim();
        return s;
    }

    private static byte[] ToLower(byte[] b)
    {
        var r = new byte[b.Length];
        for (var i = 0; i < b.Length; i++) r[i] = (byte)char.ToLowerInvariant((char)b[i]);
        return r;
    }

    private static bool Evaluate(MemoryRule rule, byte[] data)
    {
        // Компилируем условие на лету: заменяем "$x" на "true/false".
        var cond = rule.Condition;
        var present = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, bytes, mask, noCase) in rule.Strings)
        {
            if (Contains(data, bytes, mask, noCase)) present.Add(id);
        }
        if (present.Count == 0) return false;

        if (cond.Contains("all of them"))
        {
            return present.Count == rule.Strings.Count;
        }
        if (cond.Contains("any of them"))
        {
            return present.Count > 0;
        }
        // N of them
        var ofMatch = System.Text.RegularExpressions.Regex.Match(cond, @"(\d+)\s+of\s+them");
        if (ofMatch.Success && int.TryParse(ofMatch.Groups[1].Value, out var n))
        {
            return present.Count >= n;
        }
        // $a and $b / ($a or $b)
        var expr = System.Text.RegularExpressions.Regex.Replace(cond, @"\$[\w]+",
            m => present.Contains(m.Value) ? "true" : "false");
        expr = expr.Replace("and", "&&").Replace("or", "||");
        try
        {
            return EvalBoolean(expr);
        }
        catch
        {
            return false;
        }
    }

    private static bool EvalBoolean(string expr)
    {
        expr = expr.Replace("(", " ( ").Replace(")", " ) ");
        var tokens = expr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var pos = 0;
        return ParseOr(tokens, ref pos);
    }

    private static bool ParseOr(string[] t, ref int p)
    {
        var v = ParseAnd(t, ref p);
        while (p < t.Length && t[p] == "||") { p++; var r = ParseAnd(t, ref p); v = v || r; }
        return v;
    }

    private static bool ParseAnd(string[] t, ref int p)
    {
        var v = ParseUnary(t, ref p);
        while (p < t.Length && t[p] == "&&") { p++; var r = ParseUnary(t, ref p); v = v && r; }
        return v;
    }

    private static bool ParseUnary(string[] t, ref int p)
    {
        if (p >= t.Length) throw new InvalidOperationException();
        if (t[p] == "!")
        {
            p++;
            return !ParseUnary(t, ref p);
        }
        if (t[p] == "(")
        {
            p++;
            var v = ParseOr(t, ref p);
            if (p >= t.Length || t[p] != ")") throw new InvalidOperationException();
            p++;
            return v;
        }
        if (t[p] == "true") { p++; return true; }
        if (t[p] == "false") { p++; return false; }
        throw new InvalidOperationException("Unexpected token: " + t[p]);
    }

    private static bool Contains(byte[] haystack, byte[] needle, bool[] mask, bool noCase)
    {
        if (needle.Length == 0 || needle.Length > haystack.Length) return false;
        if (noCase)
        {
            var lowered = ToLower(haystack);
            return IndexOfMasked(lowered, needle, mask) >= 0;
        }
        return IndexOfMasked(haystack, needle, mask) >= 0;
    }

    private static int IndexOfMasked(byte[] haystack, byte[] needle, bool[] mask)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                // wildcard '??' (mask=false) совпадает с любым байтом
                if (!mask[j]) continue;
                if (haystack[i + j] != needle[j]) { ok = false; break; }
            }
            if (ok) return i;
        }
        return -1;
    }
}

/// <summary>
/// Точечный сканер приватных регионов памяти (3.0.0.24). Через VirtualQueryEx
/// перечисляет MEM_PRIVATE-регионы c исполняемыми правами (RX/RWX/WCX), игнорируя
/// спроецированные PE-образы (MEM_IMAGE). PPL/недоступные процессы пропускаются
/// молча (ACCESS_DENIED), чтение ограничено жёстким таймаутом.
/// </summary>
public sealed class MemoryAuditScanner
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint ProcessVmRead = 0x0010;
    private const uint MemCommit = 0x1000;
    private const uint MemImage = 0x1000000;
    private const uint MemPrivate = 0x20000;
    private const uint PageExecuteRead = 0x20;
    private const uint PageExecuteReadWrite = 0x40;
    private const uint PageExecuteWriteCopy = 0x80;

    private const int MaxRegions = 128;
    private const int MaxTotalBytes = 24 * 1024 * 1024;
    private const int RegionReadChunk = 1 * 1024 * 1024;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryBasicInformation
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress,
        out MemoryBasicInformation lpBuffer, IntPtr dwLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
        byte[] lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytesRead);

    private static bool IsExecutableProtect(uint protect)
    {
        var p = protect & 0xFF;
        return p == PageExecuteRead || p == PageExecuteReadWrite || p == PageExecuteWriteCopy;
    }

    /// <summary>
    /// Собирает образцы приватных исполняемых регионов процесса. Возвращает пустой
    /// список при недоступности процесса (PPL/привилегии) — без ложных тревог.
    /// </summary>
    public List<byte[]> CollectExecutableRegions(int pid, TimeSpan timeout)
    {
        var result = new List<byte[]>();
        var h = OpenProcess(ProcessQueryLimitedInformation | ProcessVmRead, false, pid);
        if (h == IntPtr.Zero) return result;
        try
        {
            var sw = Stopwatch.StartNew();
            IntPtr address = IntPtr.Zero;
            var total = 0;
            while (result.Count < MaxRegions && total < MaxTotalBytes)
            {
                if (sw.Elapsed > timeout) break;
                var mbi = new MemoryBasicInformation();
                var got = VirtualQueryEx(h, address, out mbi, (IntPtr)Marshal.SizeOf<MemoryBasicInformation>());
                if (got == IntPtr.Zero) break;
                if (mbi.State == MemCommit && mbi.Type == MemPrivate && IsExecutableProtect(mbi.Protect))
                {
                    var size = mbi.RegionSize.ToInt64();
                    if (size > 0)
                    {
                        var chunk = ReadRegion(h, mbi.BaseAddress, size, ref total);
                        if (chunk is not null) result.Add(chunk);
                    }
                }
                var next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= address.ToInt64()) break;
                address = new IntPtr(next);
            }
            return result;
        }
        finally
        {
            CloseHandle(h);
        }
    }

    private static byte[]? ReadRegion(IntPtr h, IntPtr baseAddr, long size, ref int total)
    {
        var take = (int)Math.Min(size, Math.Min(RegionReadChunk, MaxTotalBytes - total));
        if (take <= 0) return null;
        var buf = new byte[take];
        if (!ReadProcessMemory(h, baseAddr, buf, (IntPtr)take, out var read)) return null;
        if (read.ToInt64() <= 0) return null;
        total += (int)read.ToInt64();
        if (read.ToInt64() == take) return buf;
        var trimmed = new byte[read.ToInt64()];
        Array.Copy(buf, trimmed, read.ToInt64());
        return trimmed;
    }
}

/// <summary>
/// Дифференциальный аудит «тяжёлых» веток персистентности (3.0.0.24):
/// BootExecute, COM Hijacking и Shell Extensions для каждого активного
/// интерактивного пользователя (HKEY_USERS\<SID>) и глобальных веток HKLM.
/// Offline-кусты NTUSER.DAT не монтируются (риск порчи данных) — работаем только
/// с уже смонтированными ветками. Хендлы не удерживаются: перечисление выполняется
/// точечно, лимит на чтение — через WTS-перечисление активных сессий.
/// </summary>
public sealed class DeepPersistenceAuditor
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WtsSessionInfo
    {
        public int SessionId;
        public IntPtr WinStationName;
        public int State;
    }

    private const int WtsCurrentServerHandle = 0;
    private const int WtsUserName = 5;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSEnumerateSessionsW(IntPtr hServer, int reserved, int version,
        out IntPtr ppSessionInfo, out int pCount);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQuerySessionInformationW(IntPtr hServer, int sessionId, int infoClass,
        out IntPtr ppBuffer, out int pBytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool LookupAccountName(string? systemName, string accountName,
        byte[] sid, ref uint sidLen, StringBuilder domain, ref uint domainLen, out int use);

    /// <summary>Возвращает SID активных интерактивных сессий (с запасом на ошибки).</summary>
    public static List<string> EnumerateActiveUserSids()
    {
        var sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            if (WTSEnumerateSessionsW(new IntPtr(WtsCurrentServerHandle), 0, 1, out var info, out var count)
                && count > 0)
            {
                var ptr = info;
                for (var i = 0; i < count; i++)
                {
                    var session = Marshal.PtrToStructure<WtsSessionInfo>(ptr);
                    ptr = IntPtr.Add(ptr, Marshal.SizeOf<WtsSessionInfo>());
                    // Интерактивные сессии: WTSActive=0, WTSConnected=1, WTSConsoleConnect=2, WTSShadow=9...
                    // Берём любую, кроме служб (state>=6 обычно неинтерактивны), и проверяем наличие SID.
                    if (session.SessionId <= 0) continue;
                    var user = QuerySessionUserName(session.SessionId);
                    if (string.IsNullOrWhiteSpace(user)) continue;
                    var sid = UserNameToSid(user);
                    if (sid is not null) sids.Add(sid);
                }
                WTSFreeMemory(info);
            }
        }
        catch (Exception ex)
        {
            GuardianLog.Error("DeepAudit: WTS-перечисление сессий не удалось", ex);
        }

        // Резервный источник: смонтированные профили (ветки HKEY_USERS уже существуют).
        if (sids.Count == 0)
        {
            try
            {
                using var users = Registry.Users;
                foreach (var name in users.GetSubKeyNames())
                {
                    if (name.StartsWith("S-1-5-21", StringComparison.OrdinalIgnoreCase)) sids.Add(name);
                }
            }
            catch { /* реестр недоступен — возвращаем то, что есть */ }
        }
        return sids.ToList();
    }

    private static string? QuerySessionUserName(int sessionId)
    {
        if (!WTSQuerySessionInformationW(new IntPtr(WtsCurrentServerHandle), sessionId, WtsUserName,
                out var buffer, out var len) || buffer == IntPtr.Zero)
        {
            return null;
        }
        try
        {
            return len > 0 ? Marshal.PtrToStringUni(buffer, len / 2) : null;
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private static string? UserNameToSid(string accountName)
    {
        var sid = new byte[256];
        uint sidLen = (uint)sid.Length;
        var domain = new StringBuilder(256);
        uint domainLen = (uint)domain.Capacity;
        if (!LookupAccountName(null, accountName, sid, ref sidLen, domain, ref domainLen, out _)) return null;
        try
        {
            return new System.Security.Principal.SecurityIdentifier(sid, 0).ToString();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Полный проход: BootExecute + COM Hijacking + Shell Extensions для HKLM и
    /// каждого активного пользователя. Возвращает подозрительные объекты.
    /// </summary>
    public List<DeepPersistenceFinding> Scan(Func<string, bool> isTargetSuspicious)
    {
        var findings = new List<DeepPersistenceFinding>();
        try
        {
            ScanBootExecute(findings, isTargetSuspicious);
        }
        catch (Exception ex) { GuardianLog.Error("DeepAudit: BootExecute", ex); }

        try
        {
            ScanComAndShell(findings, isTargetSuspicious);
        }
        catch (Exception ex) { GuardianLog.Error("DeepAudit: COM/ShellExt (HKLM)", ex); }

        foreach (var sid in EnumerateActiveUserSids())
        {
            try
            {
                ScanPerUser(findings, sid, isTargetSuspicious);
            }
            catch (Exception ex) { GuardianLog.Error($"DeepAudit: COM/ShellExt ({sid})", ex); }
        }
        return findings;
    }

    private void ScanBootExecute(List<DeepPersistenceFinding> findings, Func<string, bool> suspicious)
    {
        using var sm = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager");
        var boot = sm?.GetValue("BootExecute") as string[];
        if (boot is null || boot.Length == 0) return;
        foreach (var entry in boot)
        {
            var cmd = (entry ?? "").Trim();
            if (cmd.Length == 0) continue;
            // Штатная запись Windows: autocheck autochk *
            if (cmd.StartsWith("autocheck", StringComparison.OrdinalIgnoreCase)) continue;
            var target = ResolveCommandTarget(cmd);
            if (target is null) continue;
            if (suspicious(target))
            {
                findings.Add(new DeepPersistenceFinding(
                    AnomalyThreatKindDto.BootExecute,
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
                    target,
                    "Посторонняя команда автозагрузки при старте системы: " + cmd));
            }
        }
    }

    private void ScanComAndShell(List<DeepPersistenceFinding> findings, Func<string, bool> suspicious)
    {
        using var root = Registry.LocalMachine;
        // COM (HKLM): программные компоненты, загружаемые всеми пользователями.
        using (var clsid = root.OpenSubKey(@"Software\Classes\CLSID"))
        {
            if (clsid is not null)
            {
                foreach (var guid in clsid.GetSubKeyNames())
                {
                    if (!LooksLikeGuid(guid)) continue;
                    var target = ResolveClsidTarget(clsid, guid);
                    if (target is null || !suspicious(target)) continue;
                    findings.Add(new DeepPersistenceFinding(
                        AnomalyThreatKindDto.ComHijack,
                        $@"HKLM\Software\Classes\CLSID\{guid}",
                        target,
                        $"Подозрительный сервер COM-объекта {guid}"));
                }
            }
        }

        // Shell Extensions (HKLM).
        ScanShellExtensionRoot(findings, root.OpenSubKey(@"Software\Classes\Directory\shellex\ContextMenuHandlers"),
            @"HKLM\Software\Classes\Directory\shellex\ContextMenuHandlers", suspicious);
        ScanNamedValues(findings, root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"),
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            AnomalyThreatKindDto.ShellExtension, suspicious);
        ScanNamedValues(findings, root.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Print\Monitors"),
            @"HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors",
            AnomalyThreatKindDto.ShellExtension, suspicious);
        ScanNamedValues(findings, root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers"),
            @"HKLM\Software\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers",
            AnomalyThreatKindDto.ShellExtension, suspicious);
    }

    private void ScanPerUser(List<DeepPersistenceFinding> findings, string sid, Func<string, bool> suspicious)
    {
        using var usersRoot = Registry.Users;
        // COM Hijacking (HKCU\<SID>): приоритетный вектор закрепления.
        using (var clsid = usersRoot.OpenSubKey(sid + @"\Software\Classes\CLSID"))
        {
            if (clsid is not null)
            {
                foreach (var guid in clsid.GetSubKeyNames())
                {
                    if (!LooksLikeGuid(guid)) continue;
                    var target = ResolveClsidTarget(clsid, guid);
                    if (target is null || !suspicious(target)) continue;
                    findings.Add(new DeepPersistenceFinding(
                        AnomalyThreatKindDto.ComHijack,
                        $@"HKEY_USERS\{sid}\Software\Classes\CLSID\{guid}",
                        target,
                        $"Перехват COM-объекта {guid} в профиле пользователя"));
                }
            }
        }

        // Shell Extensions (контекстное меню + загрузка при старте оболочки).
        ScanShellExtensionRoot(findings, usersRoot.OpenSubKey(sid + @"\Software\Classes\*\shellex\ContextMenuHandlers"),
            $@"HKEY_USERS\{sid}\Software\Classes\*\shellex\ContextMenuHandlers", suspicious);
        ScanShellExtensionRoot(findings, usersRoot.OpenSubKey(sid + @"\Software\Classes\Directory\Background\shellex\ContextMenuHandlers"),
            $@"HKEY_USERS\{sid}\Software\Classes\Directory\Background\shellex\ContextMenuHandlers", suspicious);
        ScanNamedValues(findings, usersRoot.OpenSubKey(sid + @"\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"),
            $@"HKEY_USERS\{sid}\Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
            AnomalyThreatKindDto.ShellExtension, suspicious);
    }

    private static void ScanShellExtensionRoot(List<DeepPersistenceFinding> findings, RegistryKey? key,
        string location, Func<string, bool> suspicious)
    {
        if (key is null) return;
        foreach (var name in key.GetSubKeyNames())
        {
            using var sub = key.OpenSubKey(name);
            if (sub is null) continue;
            var value = (sub.GetValue("") ?? sub.GetValue(null)) as string;
            if (string.IsNullOrWhiteSpace(value)) continue;
            var target = ResolveTarget(value);
            if (target is null || !suspicious(target)) continue;
            findings.Add(new DeepPersistenceFinding(
                AnomalyThreatKindDto.ShellExtension,
                location + @"\" + name,
                target,
                $"Подозрительный обработчик контекстного меню/оболочки «{name}»"));
        }
    }

    private static void ScanNamedValues(List<DeepPersistenceFinding> findings, RegistryKey? key,
        string location, AnomalyThreatKindDto kind, Func<string, bool> suspicious)
    {
        if (key is null) return;
        foreach (var name in key.GetValueNames())
        {
            var value = (key.GetValue(name) as string) ?? "";
            if (string.IsNullOrWhiteSpace(value)) continue;
            var target = ResolveTarget(value);
            if (target is null || !suspicious(target)) continue;
            findings.Add(new DeepPersistenceFinding(
                kind,
                location + @"\" + name,
                target,
                $"Подозрительное значение загрузки «{name}»"));
        }
    }

    private static string? ResolveClsidTarget(RegistryKey clsidRoot, string guid)
    {
        using var key = clsidRoot.OpenSubKey(guid);
        if (key is null) return null;
        var inproc = (key.OpenSubKey("InprocServer32")?.GetValue("")) as string;
        if (!string.IsNullOrWhiteSpace(inproc)) return ResolveTarget(inproc);
        var local = (key.OpenSubKey("LocalServer32")?.GetValue("")) as string;
        if (!string.IsNullOrWhiteSpace(local)) return ResolveTarget(local);
        var treatAs = (key.GetValue("TreatAs")) as string;
        if (!string.IsNullOrWhiteSpace(treatAs))
        {
            if (LooksLikeGuid(treatAs))
            {
                var nested = ResolveClsidTarget(clsidRoot, treatAs);
                if (nested is not null) return nested;
            }
            return ResolveTarget(treatAs);
        }
        return null;
    }

    /// <summary>Преобразует строку значения в путь исполняемого файла (или null).</summary>
    internal static string? ResolveTarget(string value)
    {
        var v = value.Trim().Trim('"');
        if (v.Length == 0) return null;
        v = Environment.ExpandEnvironmentVariables(v);
        // «rundll32.exe C:\path\file.dll,Export» и т.п.
        if (v.StartsWith("rundll32", StringComparison.OrdinalIgnoreCase) ||
            v.StartsWith("rundll32.exe", StringComparison.OrdinalIgnoreCase))
        {
            var parts = v.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                var dll = parts[1].Trim().Trim(',');
                if (dll.Length > 0) v = dll;
            }
        }
        if (v.StartsWith("{")) return null; // ссылка на другой CLSID — проверяется отдельно
        if (v.Contains(' '))
        {
            // аргументы после пути — отбрасываем
            var sp = v.IndexOf(' ');
            v = v[..sp];
        }
        if (!Path.IsPathRooted(v))
        {
            var sys32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), v);
            var win = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), v);
            return File.Exists(sys32) ? sys32 : File.Exists(win) ? win : null;
        }
        return File.Exists(v) ? v : null;
    }

    internal static string? ResolveCommandTarget(string cmd)
    {
        var parts = cmd.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return null;
        var head = parts[0].Trim('"');
        if (head.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return ResolveTarget(head);
        // Например «C:\path\script.cmd»
        return ResolveTarget(head);
    }

    private static bool LooksLikeGuid(string s)
        => s.Length == 38 && s[0] == '{' && s[37] == '}' &&
           Guid.TryParse(s, out _);
}

/// <summary>
/// Оркестратор модуля «Контроль скрытой активности и аномалий» (3.0.0.24, HIPS-lite).
/// Управляет тремя таймерами: дифференциальный аудит персистентности (по умолчанию
/// 5 мин), поллинг сетевых таблиц (1 с) и сверка хэшей заблокированных бинарников
/// (5 с). Все таймеры создаются только при включённом мастере; фоновые потоки —
/// низкоприоритетные.
/// </summary>
public sealed class AnomalyControlMonitor : IDisposable
{
    private static readonly HashSet<int> SystemPids = new() { 0, 4, 8 };

    /// <summary>Пауза между повторными алертами одного объекта (анти-шторм).</summary>
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(15);

    /// <summary>TTL кэша проверки подписей (Authenticode дорога).</summary>
    private static readonly TimeSpan SignatureCacheTtl = TimeSpan.FromMinutes(1);

    /// <summary>Каталоги недоверенных исполняемых файлов (маяки).</summary>
    private static readonly string[] UntrustedPathMarkers =
    {
        @"\temp\", @"\appdata\local\temp\", @"\appdata\roaming\", @"\appdata\", @"\programdata\", @"\users\public\", @"\downloads\",
    };

    /// <summary>Стартовый рулсет YARA-подобных правил памяти загружается из
    /// data\memory_rules.yar рядом со сборкой (3.0.0.68): встроенные строки-сигнатуры
    /// кейлоггера/стилера провоцировали ложные HEUR-детекты антивирусов (E1c).
    /// При отсутствии файла модуль работает с пустым набором правил (остальная
    /// поведенческая часть — глубокий аудит/маяки/хэши — не зависит от рулсета).</summary>
    private static string LoadEmbeddedMemoryRules()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "data", "memory_rules.yar");
            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }
            _ = path;
        }
        catch
        {
            // Файл повреждён/недоступен — безопасный пустой режим.
        }
        return "";
    }

    private readonly JsonConfiguration _config;
    private readonly FileLogger _logger;
    private readonly GuardianService _service;
    private readonly TrafficMonitor _traffic = new();
    private readonly WindowsFirewallEngine _firewall = new();
    private readonly DeepPersistenceAuditor _deepAudit = new();
    private readonly BeaconTracker _beaconTracker;
    private readonly BlockedBinaryWatch _blockedWatch = new();
    private readonly MemoryRuleEngine _ruleEngine = new();
    private readonly MemoryAuditScanner _memoryScanner = new();

    private readonly object _sync = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _trustedPaths = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (SignerInfo Info, DateTime At)> _signatureCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _pathToRule = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _ruleToPath = new(StringComparer.OrdinalIgnoreCase);

    private System.Threading.Timer? _deepTimer;
    private System.Threading.Timer? _beaconTimer;
    private System.Threading.Timer? _hashTimer;
    private bool _running;
    private bool _started;
    private long _totalDetections;

    /// <summary>Срабатывает при сформированном алерте аномалий (HIPS-lite).</summary>
    public event Action<AnomalyAlertDto>? AlertRaised;

    public AnomalyControlMonitor(JsonConfiguration config, FileLogger logger)
    {
        _config = config;
        _logger = logger;
        _service = new GuardianService();
        _beaconTracker = new BeaconTracker(config.AnomalyBeaconMinCycles);
        LoadTrustedPaths(config);
        _ruleEngine.ReloadText(LoadEmbeddedMemoryRules());
    }

    public bool IsRunning => _running;

    /// <summary>Число детектов за сессию (панель/журнал).</summary>
    public long TotalDetections => Interlocked.Read(ref _totalDetections);

    /// <summary>Перечитать правила памяти (хук обновления подписанным пакетом).</summary>
    public void ReloadRules(string yaraText)
    {
        _ruleEngine.ReloadText(yaraText);
        _logger.Info(LogCategory.Realtime,
            $"Аномалии: правила памяти перечитаны ({_ruleEngine.Rules.Count}).");
    }

    // ---------------------------------------------------------------
    // Жизненный цикл
    // ---------------------------------------------------------------

    public void Start()
    {
        if (_started) return;
        _started = true;
        _running = true;
        // Первый глубокий аудит — через 90 с после старта, далее по интервалу.
        _deepTimer = new System.Threading.Timer(_ => DeepAuditTick(), null,
            TimeSpan.FromSeconds(90), TimeSpan.FromMinutes(_config.AnomalyDeepAuditIntervalMinutes));
        _beaconTimer = new System.Threading.Timer(_ => BeaconTick(), null,
            TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(Math.Max(500, _config.AnomalyBeaconPollMs)));
        _hashTimer = new System.Threading.Timer(_ => HashRecheckTick(), null,
            TimeSpan.FromSeconds(35), TimeSpan.FromSeconds(Math.Max(5, _config.AnomalyHashRecheckSeconds)));
        _logger.Info(LogCategory.Realtime,
            "Контроль скрытой активности и аномалий включён (HIPS-lite): глубокий аудит каждые " +
            $"{_config.AnomalyDeepAuditIntervalMinutes} мин, поллинг маяков {_config.AnomalyBeaconPollMs} мс.");
    }

    /// <summary>Перечитывает настройки без перезапуска службы (ReloadConfig).</summary>
    public void Reload()
    {
        LoadTrustedPaths(_config);
        _beaconTracker.Clear();
        _deepTimer?.Change(TimeSpan.FromSeconds(60), TimeSpan.FromMinutes(Math.Max(5, _config.AnomalyDeepAuditIntervalMinutes)));
        _beaconTimer?.Change(TimeSpan.FromSeconds(30), TimeSpan.FromMilliseconds(Math.Max(500, _config.AnomalyBeaconPollMs)));
        _hashTimer?.Change(TimeSpan.FromSeconds(35), TimeSpan.FromSeconds(Math.Max(5, _config.AnomalyHashRecheckSeconds)));
    }

    public void Dispose()
    {
        if (!_started) return;
        _started = false;
        _running = false;
        _deepTimer?.Dispose();
        _deepTimer = null;
        _beaconTimer?.Dispose();
        _beaconTimer = null;
        _hashTimer?.Dispose();
        _hashTimer = null;
        _beaconTracker.Clear();
    }

    // ---------------------------------------------------------------
    // Глубокий аудит персистентности
    // ---------------------------------------------------------------

    private void DeepAuditTick()
    {
        if (!_running) return;
        try
        {
            var findings = _deepAudit.Scan(IsTargetSuspicious);
            foreach (var f in findings)
            {
                Raise(f.Kind, pid: 0, processName: "", processPath: f.TargetPath,
                    location: f.Location, ruleName: "", ruleAdded: false, ruleId: "",
                    details: f.Details);
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: сбой цикла глубокого аудита: " + ex.Message);
        }
    }

    private bool IsTargetSuspicious(string targetPath)
    {
        lock (_sync)
        {
            if (_trustedPaths.Contains(targetPath)) return false;
        }
        var info = GetSignature(targetPath);
        if (info.IsValid) return false; // подпись Microsoft/доверенного издателя — легитимно
        return true;
    }

    // ---------------------------------------------------------------
    // Детектор C&C-маяков / эксфильтрации
    // ---------------------------------------------------------------

    private void BeaconTick()
    {
        if (!_running) return;
        try
        {
            var connections = _traffic.GetAllConnections();
            var byPid = connections
                .Where(c => c.Pid > 0 && !SystemPids.Contains(c.Pid) && !string.IsNullOrEmpty(c.RemoteAddr))
                .GroupBy(c => c.Pid)
                .ToDictionary(g => g.Key, g => g.Select(c => c.RemoteAddr).Distinct(StringComparer.OrdinalIgnoreCase).ToList());

            foreach (var (pid, remotes) in byPid)
            {
                var path = GetProcessPath(pid);
                if (string.IsNullOrEmpty(path)) continue; // PID закрылся — «временная системная», игнорируем
                if (!IsUntrustedPath(path)) continue;
                lock (_sync)
                {
                    if (_trustedPaths.Contains(path)) continue;
                    if (_blockedWatch.IsWatched(path)) continue; // уже заблокирован
                }
                var info = GetSignature(path);
                if (info.IsValid) continue; // подписанные — пропускаем

                if (_beaconTracker.Track(pid, path, hasOutbound: true))
                {
                    var ruleName = BlockPathRuleName(path);
                    var added = AddPathBlockRule(path, ruleName, remotes.FirstOrDefault() ?? "");
                    lock (_sync) _pathToRule[path] = ruleName;

                    Raise(AnomalyThreatKindDto.NetworkBeacon, pid, GetProcessName(pid), path,
                        location: string.Join(", ", remotes.Take(3)),
                        ruleName: added ? ruleName : "", ruleAdded: added, ruleId: "",
                        details: $"Неподписанный процесс из недоверенного каталога устойчиво шлёт данные " +
                                 $"(маяк C&C): {path}. " + (added ? "Исходящий доступ заблокирован правилом брандмауэра по пути." : "Правило не создано."));

                    // Второй эшелон — точечный аудит памяти этого процесса.
                    if (_config.AnomalyMemoryAuditEnabled) MemoryAudit(pid, path);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: сбой поллинга маяков: " + ex.Message);
        }
    }

    private bool AddPathBlockRule(string path, string ruleName, string sampleIp)
    {
        try
        {
            var rule = new FirewallRule
            {
                Name = ruleName,
                Description = "Контроль скрытой активности (HIPS-lite): блокировка исходящих соединений подозрительного бинарника (аномалия C&C-маяка).",
                Enabled = true,
                Action = RuleAction.Block,
                Direction = RuleDirection.Outbound,
                Protocol = Protocol.Any,
                ApplicationPath = path,
            };
            var ok = _firewall.AddRule(rule);
            if (ok)
            {
                var hash = ComputeSha256(path);
                _blockedWatch.Add(path, hash);
                lock (_sync) _ruleToPath[ruleName] = path;
            }
            return ok;
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: не удалось добавить правило брандмауэра: " + ex.Message);
            return false;
        }
    }

    private void RemovePathBlockRule(string path)
    {
        string? ruleName = null;
        lock (_sync)
        {
            if (_pathToRule.TryGetValue(path, out var r)) ruleName = r;
            _pathToRule.Remove(path);
            if (ruleName is not null) _ruleToPath.Remove(ruleName);
            _blockedWatch.Remove(path);
        }
        if (ruleName is null) return;
        try { _firewall.DeleteRule(ruleName, ruleName); }
        catch (Exception ex) { _logger.Error(LogCategory.Realtime, "Аномалии: не удалось удалить правило: " + ex.Message); }
    }

    // ---------------------------------------------------------------
    // Сверка SHA-256 заблокированных бинарников (5 с, предфильтр размер+mtime)
    // ---------------------------------------------------------------

    private void HashRecheckTick()
    {
        if (!_running) return;
        string[] paths;
        lock (_sync) paths = _pathToRule.Keys.ToArray();
        if (paths.Length == 0) return;

        foreach (var path in paths)
        {
            try
            {
                var changed = _blockedWatch.Recheck(path);
                if (changed is null) continue; // файл не менялся — SHA-256 не считали
                // Файл по заблокированному пути подменён: перепроверяем вердикт.
                var info = GetSignature(path);
                if (info.IsValid)
                {
                    // Теперь это легитимный бинарник — снимаем блокировку.
                    _logger.Warning(LogCategory.Realtime,
                        $"Аномалии: бинарник по заблокированному пути стал подписанным — блокировка снята: {path}");
                    RemovePathBlockRule(path);
                }
                else
                {
                    // Подмена вредоносным файлом — правило остаётся (блок по пути),
                    // обновляем учётную запись хэша.
                    _logger.Warning(LogCategory.Realtime,
                        $"Аномалии: бинарник по заблокированному пути подменён (хэш {changed.Value.OldHash[..8]}… → " +
                        $"{changed.Value.NewHash[..8]}…), правило действует: {path}");
                }
            }
            catch (Exception ex)
            {
                _logger.Error(LogCategory.Realtime, "Аномалии: сбой сверки хэша: " + ex.Message);
            }
        }
    }

    // ---------------------------------------------------------------
    // Точечный YARA-скан приватных регионов памяти
    // ---------------------------------------------------------------

    private void MemoryAudit(int pid, string path)
    {
        try
        {
            var regions = _memoryScanner.CollectExecutableRegions(pid,
                TimeSpan.FromSeconds(Math.Max(1, _config.AnomalyMemoryTimeoutSeconds)));
            if (regions.Count == 0) return;
            foreach (var region in regions)
            {
                var hits = _ruleEngine.Match(region);
                if (hits.Count == 0) continue;
                Raise(AnomalyThreatKindDto.MemoryYara, pid, GetProcessName(pid), path,
                    location: $"PID {pid} (приватные исполняемые регионы)",
                    ruleName: "", ruleAdded: false, ruleId: hits[0],
                    details: $"YARA-совпадение в приватном регионе памяти: {hits[0]}. " +
                             "Вероятный шеллкод/распаковщик кейлоггера.");
                return; // один алерт на процесс за цикл
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: сбой аудита памяти: " + ex.Message);
        }
    }

    // ---------------------------------------------------------------
    // Алерты и действия панели
    // ---------------------------------------------------------------

    private void Raise(AnomalyThreatKindDto kind, int pid, string processName, string processPath,
        string location, string ruleName, bool ruleAdded, string ruleId, string details)
    {
        var key = kind + "|" + location + "|" + ruleName;
        lock (_sync)
        {
            if (_lastAlertUtc.TryGetValue(key, out var last) && DateTime.UtcNow - last < AlertCooldown) return;
            _lastAlertUtc[key] = DateTime.UtcNow;
        }
        Interlocked.Increment(ref _totalDetections);

        var sigText = processPath.Length > 0 ? DescribeSignature(processPath) : "—";
        var alert = new AnomalyAlertDto
        {
            ActionKey = key,
            ThreatKind = kind,
            Pid = pid,
            ProcessName = string.IsNullOrEmpty(processName) ? "—" : processName,
            ProcessPath = processPath,
            Location = location,
            RuleName = ruleName,
            FirewallRuleAdded = ruleAdded,
            RuleId = ruleId,
            SignatureText = sigText,
            Details = details,
            OccurredAt = DateTime.UtcNow,
        };
        try
        {
            AlertRaised?.Invoke(alert);
            var json = System.Text.Json.JsonSerializer.Serialize(alert, IpcProtocol.JsonOptions);
            PanelPipeClient.TrySend(IpcProtocol.MessageKind.AnomalyAlert, json, TimeSpan.FromSeconds(3));
            _service.Events.Add(new EventRecord
            {
                Source = EventSource.Anomaly,
                Type = ChangeType.Malicious,
                Target = string.IsNullOrEmpty(processPath) ? location : processPath,
                Detail = $"[Контроль скрытой активности] {details}",
                OccurredAt = alert.OccurredAt,
                Status = EventStatus.Pending,
            });
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: не удалось записать событие: " + ex.Message);
        }
    }

    /// <summary>Обрабатывает решение пользователя по алерту аномалий (3.0.0.24).</summary>
    public bool HandleAction(AnomalyActionDto dto)
    {
        try
        {
            switch (dto.Action)
            {
                case AnomalyActionKindDto.TrustPath when !string.IsNullOrEmpty(dto.ProcessPath):
                    AddTrustedPath(dto.ProcessPath);
                    RemovePathBlockRule(dto.ProcessPath);
                    _logger.Info(LogCategory.Realtime, $"Аномалии: путь доверен: {dto.ProcessPath}");
                    return true;

                case AnomalyActionKindDto.RemoveRule when !string.IsNullOrEmpty(dto.RuleName):
                    try { _firewall.DeleteRule(dto.RuleName, dto.RuleName); }
                    catch (Exception ex) { _logger.Error(LogCategory.Realtime, "Аномалии: не удалось удалить правило: " + ex.Message); }
                    lock (_sync)
                    {
                        if (_ruleToPath.Remove(dto.RuleName, out var path))
                        {
                            _pathToRule.Remove(path);
                            _blockedWatch.Remove(path);
                        }
                    }
                    _logger.Info(LogCategory.Realtime, $"Аномалии: правило удалено: {dto.RuleName}");
                    return true;

                default:
                    return true; // Ignore
            }
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: ошибка обработки действия: " + ex.Message);
            return false;
        }
    }

    private void AddTrustedPath(string path)
    {
        lock (_sync) _trustedPaths.Add(path);
        try
        {
            // 3.0.0.32: перечитываем конфиг перед сохранением — иначе этот Save()
            // запишет устаревшую копию и затрёт свежие настройки панели.
            _config.Load();
            var list = (_config.AnomalyTrustedPaths ?? "")
                .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToList();
            if (!list.Contains(path, StringComparer.OrdinalIgnoreCase)) list.Add(path);
            _config.AnomalyTrustedPaths = string.Join(";", list);
            _config.Save();
        }
        catch (Exception ex)
        {
            _logger.Error(LogCategory.Realtime, "Аномалии: не удалось сохранить доверенный путь: " + ex.Message);
        }
    }

    private void LoadTrustedPaths(JsonConfiguration config)
    {
        _trustedPaths.Clear();
        foreach (var p in (config.AnomalyTrustedPaths ?? "")
                     .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            _trustedPaths.Add(p);
        }
    }

    // ---------------------------------------------------------------
    // Вспомогательные утилиты
    // ---------------------------------------------------------------

    private bool IsUntrustedPath(string path)
    {
        var p = path.Replace('/', '\\');
        foreach (var marker in UntrustedPathMarkers)
        {
            if (p.Contains(marker, StringComparison.OrdinalIgnoreCase)) return true;
        }
        return false;
    }

    private string GetProcessPath(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.MainModule?.FileName ?? "";
        }
        catch
        {
            return ""; // процесс закрылся или PPL — игнорируем
        }
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch
        {
            return "";
        }
    }

    private SignerInfo GetSignature(string path)
    {
        lock (_signatureCache)
        {
            if (_signatureCache.TryGetValue(path, out var cached) && DateTime.UtcNow - cached.At < SignatureCacheTtl)
            {
                return cached.Info;
            }
        }
        var info = DigitalSignatureVerifier.Check(path);
        lock (_signatureCache)
        {
            _signatureCache[path] = (info, DateTime.UtcNow);
            if (_signatureCache.Count > 512)
            {
                foreach (var k in _signatureCache.Where(kv => DateTime.UtcNow - kv.Value.At > SignatureCacheTtl)
                             .Select(kv => kv.Key).ToList())
                {
                    _signatureCache.Remove(k);
                }
            }
        }
        return info;
    }

    private static string DescribeSignature(string path)
    {
        var info = DigitalSignatureVerifier.Check(path);
        return info.Result switch
        {
            VerifyResult.SignOk => "Валидная подпись",
            VerifyResult.SignUntrustedRoot => "Недействительный корень",
            VerifyResult.SignInvalid => "Недействительная подпись",
            VerifyResult.SignExpired => "Истёкший сертификат",
            VerifyResult.Error => "Ошибка проверки подписи",
            _ => "Подпись отсутствует",
        };
    }

    private static string BlockPathRuleName(string path)
    {
        var hash = ComputeSha256(path) ?? path;
        var shortHash = hash.Length >= 8 ? hash[..8] : hash;
        return "CatGuardian_Block_Path_" + shortHash;
    }

    private static string ComputeSha256(string path)
    {
        try
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
        catch
        {
            return "";
        }
    }
}