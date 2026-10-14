using System.Runtime.InteropServices;
using System.Security.Cryptography;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Antivirus.Core.Quarantine;

/// <summary>
/// Шифрование файлов карантина (AES-256). Ключ генерируется один раз на установку
/// и хранится в <c>%APPDATA%\CatGuardian.Antivirus\quarantine.key</c>. Зашифрованные файлы имеют
/// расширение <c>.cgq</c> — это снижает риск того, что другие антивирусы воспримут
/// копии заражённых файлов как реальные угрозы.
/// </summary>
/// <remarks>
/// Начиная с исправления M3 сам ключ шифруется через DPAPI (CurrentUser, scope
/// <c>CRYPTPROTECT_UI_FORBIDDEN</c>) и сохраняется с префиксом «DPAPI:». Это защищает
/// ключ от чтения другими локальными учётными записями и при анализе образа диска.
/// Существующие ключи, сохранённые в открытом виде (без префикса), при первом чтении
/// автоматически мигрируются в DPAPI — уже созданные файлы <c>.cgq</c> остаются
/// расшифровываемыми.
///
/// 3.0.0.56 (SCM): карантин находится в %ProgramData%\CatGuardian\Antivirus (общий),
/// а резидентная служба выполняется от SYSTEM. DPAPI CurrentUser НЕ совместим между
/// пользовательским профилем (ключ создан панелью под пользователем) и профилем SYSTEM:
/// расшифровка ключа службой падала («Ошибка шифрования DPAPI (код 3)»), из-за чего
/// «Выход»/реалтайм НЕ помещали файлы в карантин. Поэтому ключ шифруется через
/// <c>CRYPTPROTECT_LOCAL_MACHINE</c>: расшифровать его может любой процесс на машине
/// (SYSTEM-служба и elevated-панель). Если существующий ключ создан CurrentUser-профилем
/// другого пользователя и не читается — служба от SYSTEM автоматически пересоздаёт ключ
/// (LocalMachine); старые записи карантина остаются расшифровываемыми панелью того же
/// пользователя, чьим профилем они были созданы.
/// </remarks>
internal static class QuarantineCrypto
{
    /// <summary>Префикс, отмечающий, что тело файла — это ключ, зашифрованный через DPAPI.</summary>
    private const string DpapiPrefix = "DPAPI:";

    private const uint CryptProtectUiForbidden = 0x1;
    /// <summary>CRYPTPROTECT_LOCAL_MACHINE — ключ доступен всем процессам машины (SYSTEM-служба + панель).</summary>
    private const uint CryptProtectLocalMachine = 0x4;

    private static readonly object Sync = new();
    private static byte[]? _key;

    /// <summary>Шифрует данные: заголовок (IV) + шифротекст.</summary>
    public static byte[] Encrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = GetOrCreateKey();
        aes.GenerateIV();

        using var output = new MemoryStream();
        output.Write(aes.IV, 0, aes.IV.Length);

        using (var crypto = new CryptoStream(output, aes.CreateEncryptor(), CryptoStreamMode.Write))
        {
            crypto.Write(data, 0, data.Length);
            crypto.FlushFinalBlock();
        }

        return output.ToArray();
    }

    /// <summary>Расшифровывает данные, записанные методом <see cref="Encrypt"/>.</summary>
    public static byte[] Decrypt(byte[] data)
    {
        using var aes = Aes.Create();
        aes.Key = GetOrCreateKey();

        var ivLength = aes.BlockSize / 8;
        if (data.Length <= ivLength)
        {
            throw new CryptographicException("Недопустимый размер зашифрованных данных.");
        }

        var iv = new byte[ivLength];
        Array.Copy(data, iv, ivLength);
        aes.IV = iv;

        using var input = new MemoryStream(data, ivLength, data.Length - ivLength);
        using var crypto = new CryptoStream(input, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var result = new MemoryStream();
        crypto.CopyTo(result);
        return result.ToArray();
    }

    private static byte[] GetOrCreateKey()
    {
        if (_key is not null)
        {
            return _key;
        }

        lock (Sync)
        {
            if (_key is not null)
            {
                return _key;
            }

            var keyFile = Path.Combine(AppPaths.AppDataDirectory, "quarantine.key");
            _key = File.Exists(keyFile) ? ReadOrMigrateKey(keyFile) : CreateAndSaveKey(keyFile);
            return _key;
        }
    }

    /// <summary>Генерирует новый 256-битный ключ и сохраняет его в DPAPI-виде.</summary>
    private static byte[] CreateAndSaveKey(string keyFile)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var protectedBlob = Protect(key);

        Directory.CreateDirectory(Path.GetDirectoryName(keyFile)!);
        File.WriteAllText(keyFile, DpapiPrefix + Convert.ToBase64String(protectedBlob));

        return key;
    }

    /// <summary>
    /// Читает ключ из файла. Если файл содержит legacy-ключ (открытый Base64 без префикса),
    /// выполняет миграцию в DPAPI-формат.
    /// </summary>
    private static byte[] ReadOrMigrateKey(string keyFile)
    {
        var text = File.ReadAllText(keyFile).Trim();

        if (text.StartsWith(DpapiPrefix, StringComparison.Ordinal))
        {
            var protectedBlob = Convert.FromBase64String(text[DpapiPrefix.Length..]);
            try
            {
                return Unprotect(protectedBlob);
            }
            catch (CryptographicException)
            {
                // 3.0.0.56 (SCM): ключ создан под пользовательским профилем (CurrentUser),
                // а читает его SYSTEM-служба (или наоборот) — DPAPI-профили несовместимы.
                // От SYSTEM пересоздаём ключ в LocalMachine-формате (см. также ReadOrMigrateKey
                // вызывается панелью под пользователем — там ключ читается своим профилем).
                if (IsSystemAccount())
                {
                    return RecreateKeyAsLocalMachine(keyFile);
                }

                throw;
            }
        }

        // Legacy-ключ: расшифровываем как раньше и мигрируем в DPAPI.
        var legacyKey = Convert.FromBase64String(text);
        var migratedBlob = Protect(legacyKey);
        File.WriteAllText(keyFile, DpapiPrefix + Convert.ToBase64String(migratedBlob));

        return legacyKey;
    }

    /// <summary>Истина, если текущий процесс выполняется от SYSTEM (SID S-1-5-18).</summary>
    private static bool IsSystemAccount()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return id.User is not null
                   && id.User.IsWellKnown(System.Security.Principal.WellKnownSidType.LocalSystemSid);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Пересоздаёт ключ карантина в LocalMachine-формате (нечитаемый чужой CurrentUser-ключ заменяется).</summary>
    private static byte[] RecreateKeyAsLocalMachine(string keyFile)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var protectedBlob = Protect(key);
        Directory.CreateDirectory(Path.GetDirectoryName(keyFile)!);
        File.WriteAllText(keyFile, DpapiPrefix + Convert.ToBase64String(protectedBlob));
        return key;
    }

    private static byte[] Protect(byte[] data)
    {
        var input = new DataBlob { CbData = data.Length, PbData = Marshal.AllocHGlobal(data.Length) };
        try
        {
            Marshal.Copy(data, 0, input.PbData, data.Length);
            // 3.0.0.56 (SCM): LocalMachine — ключ обязан читаться и SYSTEM-службой, и панелью.
            if (!CryptProtectData(ref input, "CatGuardian.Antivirus quarantine key", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectUiForbidden | CryptProtectLocalMachine, out var output))
            {
                throw new CryptographicException($"Ошибка защиты ключа DPAPI (код {Marshal.GetLastWin32Error()}).");
            }

            try
            {
                return CopyBlob(in output);
            }
            finally
            {
                LocalFree(output.PbData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input.PbData);
        }
    }

    private static byte[] Unprotect(byte[] data)
    {
        var input = new DataBlob { CbData = data.Length, PbData = Marshal.AllocHGlobal(data.Length) };
        try
        {
            Marshal.Copy(data, 0, input.PbData, data.Length);
            // 3.0.0.56 (SCM): LocalMachine — симметрично Protect (см. выше).
            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectUiForbidden | CryptProtectLocalMachine, out var output))
            {
                throw new CryptographicException($"Ошибка расшифровки ключа DPAPI (код {Marshal.GetLastWin32Error()}).");
            }

            try
            {
                return CopyBlob(in output);
            }
            finally
            {
                LocalFree(output.PbData);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(input.PbData);
        }
    }

    private static byte[] CopyBlob(in DataBlob blob)
    {
        if (blob.CbData <= 0 || blob.PbData == IntPtr.Zero)
        {
            return Array.Empty<byte>();
        }

        var result = new byte[blob.CbData];
        Marshal.Copy(blob.PbData, result, 0, blob.CbData);
        return result;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int CbData;
        public IntPtr PbData;
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptProtectData(
        ref DataBlob pDataIn,
        string? szDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DataBlob pDataOut);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptUnprotectData(
        ref DataBlob pDataIn,
        IntPtr ppszDataDescr,
        IntPtr pOptionalEntropy,
        IntPtr pvReserved,
        IntPtr pPromptStruct,
        uint dwFlags,
        out DataBlob pDataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);
}