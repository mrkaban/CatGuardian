using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CatGuardian.Antivirus.Core.Signing;

/// <summary>
/// Проверка КАТАЛОЖНОЙ (Catalog) подписи файла через WinVerifyTrust (3.0.0.12).
///
/// Зачем: часть системных файлов Windows (notepad.exe, usoclient.exe и др.) подписаны
/// НЕ встроенной Authenticode-подписью, а через каталог безопасности (.cat), где
/// хранится хэш файла и подпись издателя. Классический WinVerifyTrust с WTD_CHOICE_FILE
/// такие файлы считает «без подписи» (TRUST_E_NOSIGNATURE) — именно поэтому монитор
/// автозагрузки показывал «не видит подпись» для легитимного usoclient.exe из задачи
/// планировщика «Schedule Wake To Work», хотя файл подписан Microsoft.
///
/// Алгоритм: по хэшу файла ищем его в установленных каталогах Windows
/// (CryptCATAdmin*) и проверяем найденный .cat через WinVerifyTrust с WTD_CHOICE_CATALOG.
/// Издатель (Subject) извлекается из подписи самого .cat-файла.
/// </summary>
internal static class CatalogSignatureCheck
{
    // GUID подсистемы каталогов (DRIVER_ACTION_VERIFY).
    private static readonly Guid CatalogSubsystem = new("F750E6C3-38EE-11D1-85E5-00C04FC295EE");
    private static readonly Guid ActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TrustEOk = 0;
    private const uint WtdChoiceCatalog = 2;     // WTD_CHOICE_CATALOG
    private const uint WtdProvRevocationNone = 0x10; // WTD_REVOCATION_CHECK_NONE

    private const uint GenericRead = 0x80000000;
    private const uint FileShareAll = 7;         // READ|WRITE|DELETE
    private const uint OpenExisting = 3;
    private const uint FileFlagOpenReparsePoint = 0x00200000;

    /// <summary>WINTRUST_CATALOG_INFO — для проверки .cat через WinVerifyTrust.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustCatalogInfo
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
    }

    /// <summary>CATALOG_INFO — для CryptCATCatalogInfoFromContext: путь каталога
    /// записывается во ВСТРОЕННЫЙ буфер wszCatalogFile[260], а не через указатель.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WintrustData
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pCatalog;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminAcquireContext(ref IntPtr phCatAdmin, ref Guid pgSubsystem, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle(
        IntPtr hFile, ref uint pcbHash, byte[]? pbHash, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint dwFlags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo, ref CatalogInfo psCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin, IntPtr hCatInfo, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFile(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    /// <summary>
    /// Ищет файл в каталогах безопасности Windows и проверяет подпись найденного .cat.
    /// Возвращает true и Subject издателя каталога, если подпись действительна.
    /// </summary>
    public static bool TryVerify(string filePath, out string catalogSubject)
    {
        catalogSubject = "";
        IntPtr admin = IntPtr.Zero;
        IntPtr hFile = IntPtr.Zero;
        IntPtr hCat = IntPtr.Zero;
        IntPtr hPrev = IntPtr.Zero;
        try
        {
            var subsystem = CatalogSubsystem; // static readonly нельзя передавать как ref
            if (!CryptCATAdminAcquireContext(ref admin, ref subsystem, 0) || admin == IntPtr.Zero)
            {
                return false;
            }

            hFile = CreateFile(filePath, GenericRead, FileShareAll, IntPtr.Zero,
                OpenExisting, FileFlagOpenReparsePoint, IntPtr.Zero);
            if (hFile == IntPtr.Zero || hFile == new IntPtr(-1))
            {
                return false;
            }

            // Первый вызов возвращает размер хэша.
            uint cbHash = 0;
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, null, 0) || cbHash == 0)
            {
                return false;
            }

            var hash = new byte[cbHash];
            if (!CryptCATAdminCalcHashFromFileHandle(hFile, ref cbHash, hash, 0))
            {
                return false;
            }

            // Перебираем каталоги, содержащие хэш файла.
            while ((hCat = CryptCATAdminEnumCatalogFromHash(admin, hash, cbHash, 0, hPrev)) != IntPtr.Zero)
            {
                var info = new CatalogInfo
                {
                    cbStruct = (uint)Marshal.SizeOf<CatalogInfo>(),
                };

                if (CryptCATCatalogInfoFromContext(hCat, ref info, 0)
                    && !string.IsNullOrEmpty(info.wszCatalogFile))
                {
                    var catPath = info.wszCatalogFile;
                    if (VerifyCatalogFile(catPath, hash, cbHash))
                    {
                        catalogSubject = ExtractCatalogSubject(catPath);
                        return true;
                    }
                }

                if (hPrev != IntPtr.Zero)
                {
                    CryptCATAdminReleaseCatalogContext(admin, hPrev, 0);
                }
                hPrev = hCat;
            }

            return false;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hPrev != IntPtr.Zero)
            {
                CryptCATAdminReleaseCatalogContext(admin, hPrev, 0);
            }
            if (admin != IntPtr.Zero)
            {
                CryptCATAdminReleaseContext(admin, 0);
            }
            if (hFile != IntPtr.Zero && hFile != new IntPtr(-1))
            {
                CloseHandle(hFile);
            }
        }
    }

    /// <summary>Проверяет .cat-файл через WinVerifyTrust с WTD_CHOICE_CATALOG и хэшем файла.</summary>
    private static bool VerifyCatalogFile(string catPath, byte[] fileHash, uint hashSize)
    {
        IntPtr pCatInfo = IntPtr.Zero;
        IntPtr pPath = IntPtr.Zero;
        IntPtr pHash = IntPtr.Zero;
        IntPtr pData = IntPtr.Zero;
        try
        {
            var catalogInfo = new WinTrustCatalogInfo
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrustCatalogInfo>(),
            };

            pPath = Marshal.StringToCoTaskMemUni(catPath);
            catalogInfo.pcwszCatalogFilePath = pPath;
            catalogInfo.pcwszMemberTag = pPath; // тег члена каталога совпадает с путём каталога
            catalogInfo.pcwszMemberFilePath = IntPtr.Zero;
            catalogInfo.hMemberFile = IntPtr.Zero;
            pHash = Marshal.AllocCoTaskMem((int)hashSize);
            Marshal.Copy(fileHash, 0, pHash, (int)hashSize);
            catalogInfo.pbCalculatedFileHash = pHash;
            catalogInfo.cbCalculatedFileHash = hashSize;

            pCatInfo = Marshal.AllocCoTaskMem(Marshal.SizeOf<WinTrustCatalogInfo>());
            Marshal.StructureToPtr(catalogInfo, pCatInfo, false);

            var data = new WintrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
                dwUIChoice = 2,               // WTD_UI_NONE
                fdwRevocationChecks = 0,
                dwUnionChoice = WtdChoiceCatalog,
                pCatalog = pCatInfo,
                dwStateAction = 1,            // WTD_STATEACTION_VERIFY
                dwProvFlags = WtdProvRevocationNone,
            };

            pData = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustData>());
            Marshal.StructureToPtr(data, pData, false);

            var action = ActionGenericVerifyV2;
            return WinVerifyTrust(IntPtr.Zero, ref action, pData) == TrustEOk;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (pData != IntPtr.Zero)
            {
                try
                {
                    var close = Marshal.PtrToStructure<WintrustData>(pData);
                    close.dwStateAction = 2; // WTD_STATEACTION_CLOSE
                    Marshal.StructureToPtr(close, pData, true);
                    var action = ActionGenericVerifyV2;
                    WinVerifyTrust(IntPtr.Zero, ref action, pData);
                }
                catch
                {
                    // best effort
                }
                Marshal.FreeHGlobal(pData);
            }
            if (pCatInfo != IntPtr.Zero) Marshal.FreeCoTaskMem(pCatInfo);
            if (pPath != IntPtr.Zero) Marshal.FreeCoTaskMem(pPath);
            if (pHash != IntPtr.Zero) Marshal.FreeCoTaskMem(pHash);
        }
    }

    /// <summary>Извлекает Subject издателя из embedded-подписи .cat-файла.</summary>
    private static string ExtractCatalogSubject(string catPath)
    {
        try
        {
            var cert = X509Certificate.CreateFromSignedFile(catPath);
            return cert.Subject ?? "";
        }
        catch
        {
            return "";
        }
    }
}