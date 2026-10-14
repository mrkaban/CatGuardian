using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Общие P/Invoke-объявления песочницы-lite (3.0.0.39, Restricted-Token Execution).
/// Все операции user-mode: CreateRestrictedToken + Job Objects + WFP + NT API — драйвер не нужен.
/// </summary>
internal static class NativeMethods
{
    // ---- Типы токена / уровней олицетворения ----
    public const int SecurityImpersonation = 2;
    public const int TokenTypePrimary = 1;

    // ---- TokenInformationClass ----
    public const int TokenInfoUser = 1;
    public const int TokenInfoGroups = 2;
    public const int TokenInfoPrivileges = 3;
    public const int TokenInfoOwner = 4;
    public const int TokenInfoPrimaryGroup = 5;
    public const int TokenInfoRestrictedSids = 11;
    public const int TokenInfoSessionId = 12;
    public const int TokenInfoIntegrityLevel = 25;
    public const int TokenInfoMandatoryPolicy = 27;
    public const int TokenInfoAppContainerSid = 29;
    public const int TokenInfoCapabilities = 30;

    // ---- Флаги CreateRestrictedToken ----
    public const uint DisableMaxPrivilege = 0x1;
    public const uint SandboxInert = 0x2;

    // ---- Флаги создания процесса (3.0.0.39-appcontainer-fix) ----
    // КОРНЕВАЯ ПРИЧИНА «AppContainer не применяется» (acSid=none): без
    // EXTENDED_STARTUPINFO_PRESENT lpStartupInfo трактуется как STARTUPINFO, и атрибуты
    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES ИГНОРИРУЮТСЯ ядром. Обязателен для
    // всех путей, передающих STARTUPINFOEX.
    public const uint ExtendStartupInfoPresent = 0x00080000;

    // ---- SE_GROUP_* ----
    public const uint SeGroupEnabled = 0x00000004;
    public const uint SeGroupEnabledByDefault = 0x00000002;

    // ---- Запросы доступа к токену ----
    public const uint MaximumAllowed = 0x02000000;
    public const uint TokenQuery = 0x0008;
    public const uint TokenDuplicate = 0x0002;
    public const uint TokenAssignPrimary = 0x0001;
    public const uint TokenAdjustPrivileges = 0x0020;

    // ---- TokenInformationClass (дополнительно) ----
    public const int TokenInfoElevation = 20;

    // ---- Атрибуты привилегий ----
    public const uint SePrivilegeEnabled = 0x00000002;

    // ---- Атрибут процесса для UpdateProcThreadAttribute (AppContainer, 3.0.0.39) ----
    // ВАЖНО (3.0.0.39-diag-fix): PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
    // (enum ProcThreadAttributeSecurityCapabilities = 9 | PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000).
    // Сырое значение 9 не является валидным атрибутом — UpdateProcThreadAttribute возвращает
    // ERROR_NOT_SUPPORTED (50).
    public static readonly IntPtr ProcThreadAttributeSecurityCapabilities = new IntPtr(0x00020009);

    // ---- SECURITY_INFORMATION: метка целостности (low label профиля, 3.0.0.39-fix) ----
    public const uint LabelSecurityInformation = 0x00000010;

    // ---- Job Object Information Classes ----
    public const int JobInfoBasicLimit = 2;
    public const int JobInfoExtendedLimit = 9;

    // ---- Job Object Limit Flags ----
    public const uint JobObjectLimitKillOnJobClose = 0x2000;
    public const uint JobObjectLimitActiveProcess = 0x0008;
    public const uint JobObjectLimitProcessMemory = 0x0100;
    public const uint JobObjectLimitJobMemory = 0x0200;

    // ---- WFP: GUID слоёв ALE ----
    public static readonly Guid LayerAleAuthConnectV4 = new("c08cb0b8-7130-44dd-9a49-7d5dcdc4b81e");
    public static readonly Guid LayerAleAuthRecvAcceptV4 = new("e1cd9fe7-f4d5-4f50-8bcf-c6bd4cd95e09");
    public static readonly Guid LayerAleAuthConnectV6 = new("6096a7b0-1c10-484e-8871-ae650a37763b");
    // 3.0.0.39-fix6: исправлен GUID слоя FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 (ранее был
    // неверный a9ec1f5f-... — FwpmFilterAdd0 для этого слоя возвращал ошибку, и вся
    // транзакция добавления фильтров откатывалась).
    public static readonly Guid LayerAleAuthRecvAcceptV6 = new("a3b42c97-5d45-416e-85a1-f65beee96821");

    // ---- WFP: GUID слоёв DATAGRAM (3.0.0.39-fix7) ----
    // Исходящие/входящие UDP-датаграммы (QUIC/HTTP3/DNS, sendto без connect) НЕ
    // классифицируются на слоях ALE_AUTH_CONNECT/RECV_ACCEPT — для полной блокировки
    // сети нужны дополнительные BLOCK-фильтры в слоях DATAGRAM_DATA V4/V6.
    public static readonly Guid LayerDatagramDataV4 = new("9ec89e35-0f1c-4b13-a5eb-f4c1e8c25f5b");
    public static readonly Guid LayerDatagramDataV6 = new("9c3ab4b2-0dd6-45ba-9477-7fe8b5f09a8e");

    /// <summary>FWPM_CONDITION_ALE_APP_ID.</summary>
    public static readonly Guid ConditionAleAppId = new("ada4dbb1-4f0b-4a5a-a1cc-5c2a3bdc9c8e");

    /// <summary>FWPM_CONDITION_IP_REMOTE_ADDRESS (для отладки/расширения).</summary>
    public static readonly Guid ConditionIpRemoteAddress = new("d415a49a-9243-4df8-9a78-3c4e6a5e39d2");

    // 3.0.0.39-fix6: значения приведены в соответствие с fwpmtypes.h / fwpstypes.h.
    // Ранее FwpActionBlock=0x1 (это FWPM_ACTION_PERMIT!) — «блокирующие» фильтры на самом
    // деле РАЗРЕШАЛИ трафик, поэтому процесс песочницы свободно выходил в интернет.
    public const uint FwpMatchEqual = 0x00000001;  // FWP_MATCH_EQUAL
    public const uint FwpActionBlock = 0x00004000; // FWPM_ACTION_BLOCK
    public const uint FwpActionPermit = 0x00000001; // FWPM_ACTION_PERMIT
    public const uint FwpV4Address = 0x00000003;   // FWP_UINT32 (тип значения IP-адреса)
    public const uint FwpByteBlobType = 0x0000000A; // FWP_BYTE_BLOB_TYPE (было 0xF = FWP_BYTE_ARRAY6_TYPE)
    public const uint FwpUint64Type = 0x00000004;  // FWP_UINT64 (было 0x7 = FWP_FLOAT: вес читался как double/NaN)

    // ---- File access rights для deny-ACE зон ----
    public const uint FileWriteData = 0x0002;
    public const uint FileAppendData = 0x0004;
    public const uint FileWriteEa = 0x0010;
    public const uint DeleteChild = 0x0040;
    public const uint FileWriteAttributes = 0x0100;
    public const uint Delete = 0x00010000;
    public const uint WriteDac = 0x00040000;
    public const uint WriteOwner = 0x00080000;

    /// <summary>Маска deny-ACE: запись/добавление/атрибуты/удаление в защищаемых зонах.</summary>
    public const uint ZoneDenyMask =
        FileWriteData | FileAppendData | FileWriteEa | DeleteChild |
        FileWriteAttributes | Delete | WriteDac | WriteOwner;

    // ---- SE_OBJECT_TYPE ----
    public const int SeFileObject = 1;

    // ---- SECURITY_INFORMATION ----
    public const uint DaclSecurityInformation = 0x00000004;

    // ---- SDDL ----
    public const uint SddlRevision1 = 1;

    [StructLayout(LayoutKind.Sequential)]
    public struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LuidAndAttributes
    {
        public Luid Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public LuidAndAttributes Privileges;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenElevation
    {
        public uint TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SidAndAttributes
    {
        public IntPtr Sid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenUser
    {
        public SidAndAttributes User;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TokenSource
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public Luid SourceIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    // ---- WFP-структуры (только используемые поля) ----

    [StructLayout(LayoutKind.Sequential)]
    public struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct FwpValueUnion
    {
        [FieldOffset(0)] public byte Uint8;
        [FieldOffset(0)] public ushort Uint16;
        [FieldOffset(0)] public uint Uint32;
        [FieldOffset(0)] public ulong Uint64;
        [FieldOffset(0)] public IntPtr Pointer;      // FWP_BYTE_BLOB* и т.п.
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FwpValue0
    {
        public uint Type;
        public FwpValueUnion Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FwpmFilterCondition0
    {
        public Guid FieldKey;
        public uint MatchType;
        public FwpValue0 ConditionValue;
    }

    /// <summary>
    /// FWPM_SUBLAYER0 (собственный sublayer песочницы).
    /// ВАЖНО: providerKey — это GUID* (указатель), а не GUID: 16 + 16 + 4 + pad4 + 8 + 16 = 64 байта.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct FwpmSubLayer0
    {
        public Guid SubLayerKey;
        public IntPtr DisplayName;          // LPWSTR
        public IntPtr DisplayDescription;   // LPWSTR
        public uint Flags;
        public IntPtr ProviderKey;          // GUID* (NULL)
        public Guid Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ProcessInformation
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct StartupInfo
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    /// <summary>SECURITY_CAPABILITIES (AppContainer): пакетный SID + массив capability-SID (3.0.0.39).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SecurityCapabilities
    {
        public IntPtr AppContainerSid;   // PSID
        public IntPtr Capabilities;      // PSID_AND_ATTRIBUTES*
        public uint CapabilityCount;
        public uint Reserved;
    }

    /// <summary>STARTUPINFOEX: STARTUPINFO + атрибуты (PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public IntPtr LpAttributeList;
    }

    // =====================================================================
    // P/Invoke
    // =====================================================================

    [DllImport("kernel32.dll")]
    public static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSidToSid(string sidString, out IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern uint GetLengthSid(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CopySid(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int impersonationLevel,
        int tokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateRestrictedToken(
        IntPtr hExistingToken,
        uint dwFlags,
        uint disableSidCount,
        IntPtr sidsToDisable,
        uint deletePrivilegeCount,
        IntPtr privilegesToDelete,
        uint restrictedSidCount,
        IntPtr sidsToRestrict,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        uint tokenInformationLength,
        out uint returnLength);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    // ---- AppContainer (userenv.dll, 3.0.0.39: переделка песочницы на AppContainer) ----

    // 3.0.0.39-diag-fix: функция возвращает HRESULT (S_OK = 0), НЕ BOOL.
    // Объявление как bool заставляло CLR трактовать S_OK(0) как FALSE — «успешный» вызов
    // выглядел как отказ (DeriveAppContainerSidFromAppContainerName: код 0).
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int DeriveAppContainerSidFromAppContainerName(
        string appContainerName,
        out IntPtr appContainerSid);

    // 3.0.0.39-appcontainer-fix (РЕГИСТРАЦИЯ ПАКЕТА): CreateAppContainerProfile создаёт
    // профиль AppContainer в системе. БЕЗ регистрации пакета атрибут
    // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES игнорируется ядром — дочерний процесс
    // не получает изоляцию (диагностика: запись в Documents была разрешена). Возвращает
    // HRESULT: S_OK = 0 при создании; ERROR_ALREADY_EXISTS (0x800700B7, как int = -2147024713)
    // при повторном вызове — это тоже УСПЕХ (пакет уже зарегистрирован ранее).
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int CreateAppContainerProfile(
        string pszAppContainerName,
        string pszDisplayName,
        string pszDescription,
        IntPtr pCapabilities,
        uint dwCapabilityCount,
        out IntPtr ppSid);

    // 3.0.0.91-fix (УТЕЧКА ПАКЕТОВ): каждая сессия песочницы регистрирует пакет через
    // CreateAppContainerProfile, но профиль пакета НИКОГДА не удалялся — записи копились
    // в профиле вызывающего пользователя (SYSTEM) бессрочно. DeleteAppContainerProfile
    // удаляет профиль пакета; вызывается при финализации сессии (SandboxEngine).
    // Возвращает HRESULT: S_OK = 0 при успехе.
    [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int DeleteAppContainerProfile(string pszAppContainerName);

    // 3.0.0.91-fix (ДИАГНОСТИКА): код выхода корневого процесса сессии. Для аварийно
    // завершившихся процессов это NTSTATUS (отрицательный int) или код TerminateProcess.
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    // Диагностика lowbox-пути (3.0.0.39-diag): экспорт существует в ntdll.dll, но требует
    // привилегий уровня SYSTEM — даже elevated-администратор получает
    // STATUS_INVALID_PARAMETER (0xC000000D). В production НЕ используется; оставлен для
    // инструментов диагностики.
    [DllImport("ntdll.dll")]
    public static extern int NtCreateLowBoxToken(
        out IntPtr tokenHandle,
        IntPtr originalToken,
        uint desiredAccess,
        IntPtr appContainerSid,
        uint capabilityCount,
        IntPtr capabilities,
        uint handleCount,
        IntPtr handles);

    // ---- Атрибуты потоков/процессов для SECURITY_CAPABILITIES ----
    // 3.0.0.39-diag-fix: Initialize/Update/DeleteProcThreadAttributeList экспортируются
    // ИЗ kernel32.dll (не advapi32!) — EntryPointNotFoundException при вызове.

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool InitializeProcThreadAttributeList(
        IntPtr lpAttributeList,
        uint dwAttributeCount,
        uint dwFlags,
        ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool UpdateProcThreadAttribute(
        IntPtr lpAttributeList,
        uint dwFlags,
        IntPtr attribute,
        IntPtr lpValue,
        IntPtr cbSize,
        IntPtr lpPreviousValue,
        IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern IntPtr FreeSid(IntPtr pSid);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
        IntPtr securityDescriptor,
        uint revision,
        uint securityInformation,
        out IntPtr stringSecurityDescriptor,
        out uint stringLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint revision,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetNamedSecurityInfo(
        string objectName,
        int objectType,
        uint securityInfo,
        out IntPtr ppsidOwner,
        out IntPtr ppsidGroup,
        out IntPtr ppDacl,
        out IntPtr ppSacl,
        out IntPtr ppSecurityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint SetNamedSecurityInfo(
        string objectName,
        int objectType,
        uint securityInfo,
        IntPtr psidOwner,
        IntPtr psidGroup,
        IntPtr pDacl,
        IntPtr pSacl);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern void LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetInformationJobObject(
        IntPtr hJob,
        int jobObjectInformationClass,
        IntPtr lpJobObjectInformation,
        uint cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        StringBuilder? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        IntPtr lpStartupInfo,
        out ProcessInformation lpProcessInformation);

    /// <summary>
    /// CreateProcess от ТЕКУЩЕГО процесса с SECURITY_CAPABILITIES в lpStartupInfo —
    /// способ Chromium (3.0.0.39-diag-fix): AppContainer-процесс создаётся атрибутом
    /// STARTUPINFOEX, отдельный AppContainer-токен не нужен (API CreateAppContainerToken
    /// отсутствует в userenv/kernel32), SeAssignPrimaryTokenPrivilege не требуется.
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcess(
        string? lpApplicationName,
        StringBuilder? lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        IntPtr lpStartupInfo,
        out ProcessInformation lpProcessInformation);

    /// <summary>
    /// Создание процесса с указанным токеном без SeAssignPrimaryTokenPrivilege.
    /// 3.0.0.39-fix2: на машинах с политикой «Replace a process level token», удаляющей
    /// SeAssignPrimaryTokenPrivilege из токенов администраторов, CreateProcessAsUser
    /// недоступен (ERROR_PRIVILEGE_NOT_HELD 1314). CreateProcessWithTokenW требует
    /// только SeImpersonatePrivilege (присутствует у администраторов по умолчанию).
    /// </summary>
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreateProcessWithTokenW(
        IntPtr hToken,
        uint dwLogonFlags,
        string? lpApplicationName,
        StringBuilder? lpCommandLine,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref StartupInfo lpStartupInfo,
        out ProcessInformation lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    // ---- ntdll: NtCreateToken (для жёсткой защиты зон, 3.0.0.39) ----

    [DllImport("ntdll.dll")]
    public static extern int NtCreateToken(
        out IntPtr tokenHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        int tokenType,
        IntPtr authenticationId,
        IntPtr expirationTime,
        IntPtr tokenUser,
        IntPtr tokenGroups,
        IntPtr tokenPrivileges,
        IntPtr tokenOwner,
        IntPtr tokenPrimaryGroup,
        IntPtr tokenDefaultDacl,
        IntPtr tokenSource);

    // ---- WFP (fwpuclnt.dll) ----

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmEngineOpen0(
        IntPtr serverName,
        uint authnService,
        IntPtr authIdentity,
        IntPtr session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out IntPtr appId);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmTransactionBegin0(IntPtr engineHandle, uint flags);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmTransactionCommit0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmTransactionAbort0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        IntPtr subLayer,
        IntPtr sd,
        out uint subLayerId);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmFilterAdd0(
        IntPtr engineHandle,
        IntPtr filter,
        IntPtr sd,
        out ulong filterId);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmFilterDeleteByKey0(
        IntPtr engineHandle,
        ref Guid key);

    [DllImport("fwpuclnt.dll", SetLastError = true)]
    public static extern uint FwpmFreeMemory0(ref IntPtr ptr);

    // ---- Токен текущего процесса / привилегии (3.0.0.39-fix) ----

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(
        string? lpSystemName,
        string lpName,
        out Luid lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        [MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
        IntPtr newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetSecurityDescriptorSacl(
        IntPtr securityDescriptor,
        [MarshalAs(UnmanagedType.Bool)] out bool lpbSaclPresent,
        out IntPtr pSacl,
        [MarshalAs(UnmanagedType.Bool)] out bool lpbSaclDefaulted);

    /// <summary>
    /// Включает перечисленные привилегии в токене текущего процесса (SeAssignPrimaryTokenPrivilege,
    /// SeIncreaseQuotaPrivilege, SeCreateTokenPrivilege и т.п.). Полномочия процесса не меняются —
    /// это стандартное включение имеющихся привилегий у elevated-процесса. Возвращает true, если
    /// хотя бы одна привилегия успешно включена.
    /// </summary>
    public static bool EnablePrivileges(params string[] privilegeNames)
    {
        if (privilegeNames is null || privilegeNames.Length == 0)
        {
            return false;
        }

        IntPtr hToken = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out hToken) ||
                hToken == IntPtr.Zero)
            {
                return false;
            }

            var anyEnabled = false;
            foreach (var name in privilegeNames)
            {
                if (string.IsNullOrEmpty(name) || !LookupPrivilegeValue(null, name, out var luid))
                {
                    continue;
                }

                var tp = new TokenPrivileges
                {
                    PrivilegeCount = 1,
                    Privileges = new LuidAndAttributes { Luid = luid, Attributes = SePrivilegeEnabled },
                };

                var buf = Marshal.AllocHGlobal(Marshal.SizeOf<TokenPrivileges>());
                try
                {
                    Marshal.StructureToPtr(tp, buf, false);
                    if (!AdjustTokenPrivileges(hToken, false, buf, (uint)Marshal.SizeOf<TokenPrivileges>(),
                            IntPtr.Zero, IntPtr.Zero))
                    {
                        continue;
                    }

                    // ERROR_NOT_ALL_ASSIGNED (1300) — привилегия ОТСУТСТВУЕТ в токене:
                    // AdjustTokenPrivileges вернул false; успехом считаем только err==0.
                    var err = Marshal.GetLastWin32Error();
                    if (err == 0)
                    {
                        anyEnabled = true;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }

            return anyEnabled;
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
        }
    }

    /// <summary>
    /// True, если процесс обладает административной привилегией SeAssignPrimaryTokenPrivilege.
    /// 3.0.0.39-fix: флаг TokenElevation на конфигурациях с полным токеном без UAC-флага
    /// (встроенный администратор, автозапуск из elevated-сессии) возвращает 0 даже при
    /// High Integrity — поэтому проверяем состав привилегий токена, а не флаг.
    /// </summary>
    public static bool IsElevated()
    {
        IntPtr hToken = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out hToken) || hToken == IntPtr.Zero)
            {
                return false;
            }

            return HasPrivilege(hToken, "SeAssignPrimaryTokenPrivilege");
        }
        catch
        {
            return false;
        }
        finally
        {
            if (hToken != IntPtr.Zero) CloseHandle(hToken);
        }
    }

    /// <summary>Ищет именованную привилегию в списке привилегий токена (TOKEN_PRIVILEGES).</summary>
    private static bool HasPrivilege(IntPtr token, string privilegeName)
    {
        if (!LookupPrivilegeValue(null, privilegeName, out var target))
        {
            return false;
        }

        if (!GetTokenInformation(token, TokenInfoPrivileges, IntPtr.Zero, 0, out var len))
        {
            var err = Marshal.GetLastWin32Error();
            if (err != 122 /* ERROR_INSUFFICIENT_BUFFER */)
            {
                return false;
            }
        }

        var buf = Marshal.AllocHGlobal((int)len);
        try
        {
            if (!GetTokenInformation(token, TokenInfoPrivileges, buf, len, out _))
            {
                return false;
            }

            var count = Marshal.ReadInt32(buf);
            var itemSize = Marshal.SizeOf<LuidAndAttributes>();
            for (var i = 0; i < count; i++)
            {
                var item = Marshal.PtrToStructure<LuidAndAttributes>(IntPtr.Add(buf, 4 + i * itemSize));
                if (item.Luid.LowPart == target.LowPart && item.Luid.HighPart == target.HighPart)
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }
}

/// <summary>Хендл токена с авто-закрытием.</summary>
internal sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeTokenHandle() : base(true) { }

    public SafeTokenHandle(IntPtr handle) : base(true) => SetHandle(handle);

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}

/// <summary>Хендл Job Object с авто-закрытием (закрытие последнего хендла = kill-on-close).</summary>
internal sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    private SafeJobHandle() : base(true) { }

    public SafeJobHandle(IntPtr handle) : base(true) => SetHandle(handle);

    protected override bool ReleaseHandle() => NativeMethods.CloseHandle(handle);
}