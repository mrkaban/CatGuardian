using System.Runtime.InteropServices;

namespace CatGuardian.Antivirus.Core.Signing;

/// <summary>
/// Проверка цифровой подписи файла через WinVerifyTrust.
/// Перенос логики <c>Sign.pas</c> / <c>CheckFileTrust</c>.
/// </summary>
public static class WinVerifyTrust
{
    private static readonly Guid ActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WinTrustProviderGeneric = 0x1;

    // WTD_STATEACTION_*
    private const uint StateActionVerify = 1; // WTD_STATEACTION_VERIFY
    private const uint StateActionClose = 2;  // WTD_STATEACTION_CLOSE

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WintrustFileInfo
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
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
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
    }

    // Коды возврата WinVerifyTrust / TRUST_E_*.
    private const int TrustEOk = 0;
    private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    private const int TrustEProvUnknownProvider = unchecked((int)0x800B0001);
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustECertExpired = unchecked((int)0x800B0101);

    // Дополнительные коды ошибок криптографии/сертификатов, которые WinVerifyTrust
    // может вернуть при проверке цепочки.
    private const int CertEUntrustedRoot = unchecked((int)0x800B010A);      // корень не доверен
    private const int CryptERevocationOffline = unchecked((int)0x80092013); // сервер отзыва недоступен
    private const int TrustEBadDigest = unchecked((int)0x80096010);         // повреждённая подпись
    private const int TrustECertSignature = unchecked((int)0x80096004);     // подпись сертификата не сошлась

    // ВАЖНО (3.0.0.14): EntryPoint="WinVerifyTrust" ОБЯЗАТЕЛЕН — имя C#-метода
    // (NativeWinVerifyTrust) не совпадает с именем экспорта в wintrust.dll.
    // Без EntryPoint рантайм искал бы несуществующий экспорт NativeWinVerifyTrust,
    // каждый вызов падал с EntryPointNotFoundException и маскировался в Error —
    // из-за этого ВСЕ файлы проходили WinVerifyTrust как «ошибка проверки».
    [DllImport("wintrust.dll", EntryPoint = "WinVerifyTrust", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int NativeWinVerifyTrust(
        IntPtr hwnd,
        ref Guid pgActionID,
        IntPtr pWVTData);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    /// <summary>Проверить доверие к файлу.</summary>
    public static VerifyResult CheckFileTrust(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return VerifyResult.NoSignFound;
        }

        IntPtr filePathPtr = IntPtr.Zero;
        IntPtr fileInfoPtr = IntPtr.Zero;
        IntPtr stateData = IntPtr.Zero;
        int result = -1;
        var action = ActionGenericVerifyV2;

        try
        {
            var fileInfo = new WintrustFileInfo { cbStruct = (uint)Marshal.SizeOf<WintrustFileInfo>() };
            filePathPtr = Marshal.StringToCoTaskMemUni(filePath);
            fileInfo.pcwszFilePath = filePathPtr;

            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WintrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var winTrustData = new WintrustData
            {
                cbStruct = (uint)Marshal.SizeOf<WintrustData>(),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,           // WTD_CHOICE_FILE
                pFile = fileInfoPtr,
                dwStateAction = StateActionVerify,
                // M9: 0x00000010 = WTD_REVOCATION_CHECK_NONE — отключаем сетевую проверку
                // отзыва (CRL/OCSP). Ранее стояло 0x00000040 = WTD_REVOCATION_CHECK_CHAIN:
                // при недоступности серверов отзыва WinVerifyTrust возвращал ошибку даже для
                // валидных подписей, и антивирус показывал «не удалось проверить подпись».
                dwProvFlags = 0x00000010,    // WTD_REVOCATION_CHECK_NONE
            };

            stateData = Marshal.AllocHGlobal(Marshal.SizeOf<WintrustData>());
            Marshal.StructureToPtr(winTrustData, stateData, false);

            result = NativeWinVerifyTrust(IntPtr.Zero, ref action, stateData);

            return result switch
            {
                TrustEOk => VerifyResult.SignOk,
                TrustESubjectNotTrusted => VerifyResult.SignInvalid,
                TrustENoSignature => VerifyResult.NoSignFound,
                TrustECertExpired => VerifyResult.SignExpired,
                CertEUntrustedRoot => VerifyResult.SignUntrustedRoot,
                CryptERevocationOffline => VerifyResult.SignInvalid,
                TrustEBadDigest => VerifyResult.SignInvalid,
                TrustECertSignature => VerifyResult.SignInvalid,
                _ => VerifyResult.Error,
            };
        }
        catch (Exception)
        {
            return VerifyResult.Error;
        }
        finally
        {
            // M9: обязательный повторный вызов с WTD_STATEACTION_CLOSE — освобождает state
            // data, выделенные WinVerifyTrust внутри hWVTStateData (иначе утечка на вызов).
            if (stateData != IntPtr.Zero)
            {
                try
                {
                    var close = Marshal.PtrToStructure<WintrustData>(stateData);
                    close.dwStateAction = StateActionClose;
                    Marshal.StructureToPtr(close, stateData, true);
                    NativeWinVerifyTrust(IntPtr.Zero, ref action, stateData);
                }
                catch
                {
                    // Освобождение — best effort; сама проверка уже выполнена.
                }
            }

            // Все выделения освобождаем в finally — при исключении утечек нет.
            if (stateData != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure(stateData, typeof(WintrustData)); } catch { /* уже освобождено */ }
                Marshal.FreeHGlobal(stateData);
            }
            if (fileInfoPtr != IntPtr.Zero)
            {
                try { Marshal.DestroyStructure(fileInfoPtr, typeof(WintrustFileInfo)); } catch { /* уже освобождено */ }
                Marshal.FreeCoTaskMem(fileInfoPtr);
            }
            if (filePathPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(filePathPtr);
            }
        }
    }
}