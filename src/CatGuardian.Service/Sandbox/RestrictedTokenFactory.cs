using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using CatGuardian.Antivirus.Core.Configuration;

namespace CatGuardian.Service.Sandbox;

/// <summary>
/// Создание ограниченного токена для песочницы-lite (3.0.0.39, Restricted-Token Execution).
///
/// Базовый режим: CreateRestrictedToken от токена активного пользователя —
/// без привилегий (DISABLE_MAX_PRIVILEGE), с restricted SIDs и Integrity Level Low.
/// Жёсткий режим (зоны): дополнительно NtCreateToken с уникальным маркер-SID,
/// по которому SandboxZoneGuard выдаёт deny-ACE на защищаемые зоны.
/// Токен работает в активной интерактивной сессии пользователя (WTSQueryUserToken).
/// </summary>
internal static class RestrictedTokenFactory
{
    /// <summary>Результат сборки токена.</summary>
    public sealed record TokenResult(
        bool Ok,
        SafeTokenHandle? Token,
        string Error,
        string? MarkerSid,
        bool HardMode);

    /// <summary>Константа Integrity Level Low.</summary>
    private const string LowIntegritySid = "S-1-16-4096";

    /// <summary>SIDs, удаляемые из токена (всегда отключаем админ-группы и сервисы).</summary>
    private static readonly string[] SidsToDisable =
    {
        "S-1-5-32-544",  // Администраторы
        "S-1-5-18",      // SYSTEM
        "S-1-5-19",      // Локальная служба
        "S-1-5-20",      // Сетевая служба
    };

    /// <summary>Генерирует уникальный маркер-SID формата S-1-5-21-<a>-<b>-<c>-<d>.</summary>
    public static string GenerateMarkerSid()
    {
        var rnd = new byte[16];
        System.Security.Cryptography.RandomNumberGenerator.Fill(rnd);
        uint a = BitConverter.ToUInt32(rnd, 0);
        uint b = BitConverter.ToUInt32(rnd, 4);
        uint c = BitConverter.ToUInt32(rnd, 8);
        uint d = BitConverter.ToUInt32(rnd, 12) | 0x80000000u; // старший бит в старшей части — валидность формы
        return $"S-1-5-21-{a}-{b}-{c}-{d}";
    }

    /// <summary>
    /// Собирает ограниченный токен для песочницы. <paramref name="hardZones"/> включает
    /// жёсткий режим (NtCreateToken + маркер-SID); при его недоступности метод
    /// возвращает Ok=false с ошибкой — вызывающий переходит на базовый режим.
    /// </summary>
    public static TokenResult BuildRestrictedToken(bool hardZones)
    {
        IntPtr selfToken = IntPtr.Zero;
        IntPtr primaryToken = IntPtr.Zero;
        try
        {
            // 1. Основа токена — токен ТЕКУЩЕГО процесса (3.0.0.39-fix).
            //    Служба запускается панелью (requireAdministrator) в интерактивной сессии
            //    пользователя, поэтому токен процесса уже принадлежит нужной сессии и
            //    пользователю; WTSQueryUserToken (требует SYSTEM/TCB) не нужен.
            if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(),
                    NativeMethods.MaximumAllowed, out selfToken) || selfToken == IntPtr.Zero)
            {
                return new TokenResult(false, null, "OpenProcessToken: не удалось получить токен процесса", null, false);
            }

            var sessionId = NativeMethods.WTSGetActiveConsoleSessionId();

            // 2. Первичный токен.
            if (!NativeMethods.DuplicateTokenEx(selfToken, NativeMethods.MaximumAllowed, IntPtr.Zero,
                    NativeMethods.SecurityImpersonation, NativeMethods.TokenTypePrimary, out primaryToken)
                || primaryToken == IntPtr.Zero)
            {
                return new TokenResult(false, null, "DuplicateTokenEx: не удалось продублировать токен", null, false);
            }

            SafeTokenHandle? sandboxToken;
            string? markerSid = null;

            if (hardZones)
            {
                markerSid = GenerateMarkerSid();
                var hard = BuildHardTokenWithMarkerSid(primaryToken, sessionId, markerSid);
                if (!hard.Ok)
                {
                    // Жёсткий режим недоступен — сигнализируем о падении на базовый.
                    return new TokenResult(false, null, hard.Error, markerSid, false);
                }

                sandboxToken = hard.Token;
                if (sandboxToken is null)
                {
                    return new TokenResult(false, null, "NtCreateToken: токен не создан", markerSid, false);
                }
            }
            else
            {
                var baseResult = BuildBaseRestrictedToken(primaryToken, sessionId);
                if (!baseResult.Ok || baseResult.Token is null)
                {
                    return new TokenResult(false, null, baseResult.Error, null, false);
                }

                sandboxToken = baseResult.Token;
            }

            // 4. Integrity Level Low + политика «не писать вверх».
            //    fix4: в базовом режиме IL/MandatoryPolicy устанавливаются НА ПЕРВИЧНОМ токене
            //    ДО CreateRestrictedToken (иначе SetTokenInformation(TokenIntegrityLevel) на
            //    restricted-токене возвращает ошибку). Повторная установка здесь некритична.
            var ilOk = SetIntegrityLevelLow(sandboxToken.DangerousGetHandle());
            var mpOk = SetMandatoryNoWriteUp(sandboxToken.DangerousGetHandle());
            _ = SetTokenSessionId(sandboxToken.DangerousGetHandle(), sessionId); // некритично
            if (hardZones && (!ilOk || !mpOk))
            {
                return new TokenResult(false, null,
                    "не удалось настроить integrity level токена (код " + Marshal.GetLastWin32Error() + ")",
                    markerSid, hardZones);
            }

            return new TokenResult(true, sandboxToken, "", markerSid, hardZones);
        }
        finally
        {
            if (selfToken != IntPtr.Zero) NativeMethods.CloseHandle(selfToken);
            if (primaryToken != IntPtr.Zero) NativeMethods.CloseHandle(primaryToken);
        }
    }

    /// <summary>Базовый режим: CreateRestrictedToken.</summary>
    private static (bool Ok, SafeTokenHandle? Token, string Error) BuildBaseRestrictedToken(
        IntPtr primaryToken, uint sessionId)
    {
        // fix4: понижаем Integrity Low и MandatoryPolicy НА ПЕРВИЧНОМ токене ДО создания
        // restricted-токена (CreateRestrictedToken наследует IL; прямое изменение IL на
        // результате даёт ошибку).
        //
        // fix5: restricted SID'ы в базовом режиме НЕ добавляем. Опытным путём установлено,
        // что запуск GUI-приложения (user32/GDI) под токеном с restricted SID'ами
        // (Everyone/Authenticated Users/Users) завершается ошибкой Windows 0xc0000142
        // (STATUS_DLL_INIT_FAILED) ещё на стадии инициализации библиотек. Изоляция в базовом
        // режиме обеспечивается: Integrity Low + редирект профиля + Job Object (kill-on-close) +
        // WFP-блокировка сети + deny-ACE каталогов зон.
        if (!SetIntegrityLevelLow(primaryToken))
        {
            return (false, null, "не удалось настроить integrity level токена (код " +
                                 Marshal.GetLastWin32Error() + ")");
        }

        SetMandatoryNoWriteUp(primaryToken); // некритично: дублируется политикой дочернего токена

        // 3.0.0.39-fix3: CreateRestrictedToken возвращает ERROR_INVALID_PARAMETER (87), если SID
        // из SidsToDisable отсутствует в группах исходного токена (например, S-1-5-18/19/20 нет
        // в токене процесса). Включаем в список ТОЛЬКО реально присутствующие группы.
        var groupSids = ReadTokenGroupSidStrings(primaryToken);

        // SIDs to disable (через SID_AND_ATTRIBUTES с атрибутами SE_GROUP_USE_FOR_DENY_ONLY = 0x10 —
        // без этого атрибута CreateRestrictedToken также возвращает ERROR_INVALID_PARAMETER).
        var disableSids = new List<NativeMethods.SidAndAttributes>();
        foreach (var sidText in SidsToDisable)
        {
            if (!groupSids.Contains(sidText))
            {
                continue;
            }

            var sid = StringSidToIntPtr(sidText);
            if (sid != IntPtr.Zero)
            {
                disableSids.Add(new NativeMethods.SidAndAttributes { Sid = sid, Attributes = 0x10 });
            }
        }

        // fix5: restricted SIDs не используются (см. комментарий выше) — передаём 0/IntPtr.Zero.
        IntPtr disableBuf = BuildSidAndAttributesBuffer(disableSids);
        try
        {
            IntPtr restricted;
            var ok = NativeMethods.CreateRestrictedToken(
                primaryToken,
                NativeMethods.DisableMaxPrivilege | NativeMethods.SandboxInert,
                (uint)disableSids.Count, disableBuf,
                0, IntPtr.Zero,
                0, IntPtr.Zero,
                out restricted);
            if (!ok || restricted == IntPtr.Zero)
            {
                return (false, null, "CreateRestrictedToken: не удалось создать ограниченный токен (код " +
                                     Marshal.GetLastWin32Error() + ")");
            }

            return (true, new SafeTokenHandle(restricted), "");
        }
        finally
        {
            if (disableBuf != IntPtr.Zero) Marshal.FreeHGlobal(disableBuf);
            foreach (var s in disableSids) Marshal.FreeHGlobal(s.Sid);
        }
    }

    /// <summary>Жёсткий режим: NtCreateToken поверх групп пользователя + маркер-SID.</summary>
    private static (bool Ok, SafeTokenHandle? Token, string Error) BuildHardTokenWithMarkerSid(
        IntPtr primaryToken, uint sessionId, string markerSid)
    {
        // 3.0.0.39-fix: NtCreateToken требует SeCreateTokenPrivilege (и SeTcbPrivilege) —
        // включаем их в токене текущего (elevated) процесса до создания токена.
        if (!NativeMethods.EnablePrivileges("SeCreateTokenPrivilege", "SeTcbPrivilege"))
        {
            return (false, null, "нет привилегии SeCreateTokenPrivilege (жёсткий режим недоступен)");
        }

        IntPtr userBuffer = IntPtr.Zero;
        IntPtr groupsBuffer = IntPtr.Zero;
        IntPtr privilegesBuffer = IntPtr.Zero;
        IntPtr ownerBuffer = IntPtr.Zero;
        IntPtr primaryGroupBuffer = IntPtr.Zero;
        IntPtr sourceBuffer = IntPtr.Zero;
        IntPtr markerSidNative = IntPtr.Zero;
        List<IntPtr> copiedSids = new();
        try
        {
            // --- TokenUser ---
            userBuffer = AllocTokenClassBuffer(primaryToken, NativeMethods.TokenInfoUser, out var userSize);
            if (userBuffer == IntPtr.Zero) return (false, null, "не удалось прочитать TokenUser");

            // --- TokenGroups (все группы пользователя, изменим атрибуты для маркера) ---
            // fix3: группы читаются с КОПИЯМИ содержимого SID — иначе указатели указывают
            // на освобождённый буфер TOKEN_GROUPS (висячие SID в NtCreateToken).
            var groups = CopyTokenGroups(primaryToken, copiedSids);
            if (groups is null) return (false, null, "не удалось прочитать TokenGroups");

            // --- TokenOwner / TokenPrimaryGroup ---
            ownerBuffer = AllocTokenClassBuffer(primaryToken, NativeMethods.TokenInfoOwner, out _);
            primaryGroupBuffer = AllocTokenClassBuffer(primaryToken, NativeMethods.TokenInfoPrimaryGroup, out _);
            if (ownerBuffer == IntPtr.Zero || primaryGroupBuffer == IntPtr.Zero)
            {
                return (false, null, "не удалось прочитать владельца/основную группу токена");
            }

            // --- Маркер-SID добавляем в группы как enabled ---
            if (!NativeMethods.ConvertStringSidToSid(markerSid, out markerSidNative) || markerSidNative == IntPtr.Zero)
            {
                return (false, null, "не удалось создать маркер-SID");
            }

            groups.Add(new NativeMethods.SidAndAttributes
            {
                Sid = markerSidNative,
                Attributes = NativeMethods.SeGroupEnabled | NativeMethods.SeGroupEnabledByDefault,
            });

            groupsBuffer = BuildTokenGroupsBuffer(groups);

            // --- Привилегии: пустой список (песочница без привилегий) ---
            privilegesBuffer = Marshal.AllocHGlobal(4);
            Marshal.WriteInt32(privilegesBuffer, 0);

            // --- TokenSource ---
            sourceBuffer = Marshal.AllocHGlobal(16);
            var src = new NativeMethods.TokenSource
            {
                SourceName = new byte[8],
                SourceIdentifier = new NativeMethods.Luid { LowPart = 0, HighPart = 0 },
            };
            var nameBytes = System.Text.Encoding.ASCII.GetBytes("CatGuard");
            Array.Copy(nameBytes, src.SourceName, Math.Min(nameBytes.Length, 8));
            Marshal.StructureToPtr(src, sourceBuffer, false);

            // --- AuthenticationId = SYSTEM_LUID, ExpirationTime = -1 (не истекает) ---
            var authLuid = new NativeMethods.Luid { LowPart = 999, HighPart = 0 };
            IntPtr authBuffer = Marshal.AllocHGlobal(8);
            Marshal.StructureToPtr(authLuid, authBuffer, false);

            IntPtr expBuffer = Marshal.AllocHGlobal(8);
            Marshal.WriteInt64(expBuffer, -1L);

            try
            {
                IntPtr newToken;
                var status = NativeMethods.NtCreateToken(
                    out newToken,
                    NativeMethods.MaximumAllowed,
                    IntPtr.Zero,
                    NativeMethods.TokenTypePrimary,
                    authBuffer,
                    expBuffer,
                    userBuffer,
                    groupsBuffer,
                    privilegesBuffer,
                    ownerBuffer,
                    primaryGroupBuffer,
                    IntPtr.Zero, // TokenDefaultDacl = NULL
                    sourceBuffer);
                if (status != 0 || newToken == IntPtr.Zero)
                {
                    return (false, null, "NtCreateToken: NTSTATUS 0x" + status.ToString("X8"));
                }

                // fix5: restricted SIDs НЕ применяем ни в базовом, ни в жёстком режиме —
                // под restricted-токеном GUI-приложения (user32/GDI) завершаются ошибкой
                // Windows 0xc0000142 (STATUS_DLL_INIT_FAILED). Low IL и MandatoryPolicy
                // устанавливаются ниже, в BuildRestrictedToken.
                return (true, new SafeTokenHandle(newToken), "");
            }
            finally
            {
                if (authBuffer != IntPtr.Zero) Marshal.FreeHGlobal(authBuffer);
                if (expBuffer != IntPtr.Zero) Marshal.FreeHGlobal(expBuffer);
            }
        }
        finally
        {
            if (userBuffer != IntPtr.Zero) Marshal.FreeHGlobal(userBuffer);
            if (groupsBuffer != IntPtr.Zero) Marshal.FreeHGlobal(groupsBuffer);
            if (privilegesBuffer != IntPtr.Zero) Marshal.FreeHGlobal(privilegesBuffer);
            if (ownerBuffer != IntPtr.Zero) Marshal.FreeHGlobal(ownerBuffer);
            if (primaryGroupBuffer != IntPtr.Zero) Marshal.FreeHGlobal(primaryGroupBuffer);
            if (sourceBuffer != IntPtr.Zero) Marshal.FreeHGlobal(sourceBuffer);
            if (markerSidNative != IntPtr.Zero) Marshal.FreeHGlobal(markerSidNative);
            // fix3: копии содержимого SID групп, сделанные для NtCreateToken.
            foreach (var c in copiedSids)
            {
                if (c != IntPtr.Zero) Marshal.FreeHGlobal(c);
            }
        }
    }

    /// <summary>Integrity Level = Low (S-1-16-4096).</summary>
    private static bool SetIntegrityLevelLow(IntPtr token)
    {
        IntPtr sid;
        if (!NativeMethods.ConvertStringSidToSid(LowIntegritySid, out sid) || sid == IntPtr.Zero)
        {
            return false;
        }

        try
        {
            // TOKEN_MANDATORY_LABEL = SID_AND_ATTRIBUTES (атрибут SE_GROUP_INTEGRITY|ENABLED = 0x20|0x40).
            var label = new NativeMethods.SidAndAttributes
            {
                Sid = sid,
                Attributes = 0x20 | 0x40,
            };
            IntPtr buf = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.SidAndAttributes>());
            try
            {
                Marshal.StructureToPtr(label, buf, false);
                return NativeMethods.SetTokenInformation(token, NativeMethods.TokenInfoIntegrityLevel, buf,
                    (uint)Marshal.SizeOf<NativeMethods.SidAndAttributes>());
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(sid);
        }
    }

    /// <summary>TOKEN_MANDATORY_POLICY_NO_WRITE_UP | TOKEN_MANDATORY_POLICY_NEW_PROCESS_MIN.</summary>
    private static bool SetMandatoryNoWriteUp(IntPtr token)
    {
        uint policy = 0x1 | 0x2;
        IntPtr buf = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buf, unchecked((int)policy));
            return NativeMethods.SetTokenInformation(token, NativeMethods.TokenInfoMandatoryPolicy, buf, 4);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>Устанавливает идентификатор сессии токена (иначе процесс уйдёт в другую сессию).</summary>
    private static bool SetTokenSessionId(IntPtr token, uint sessionId)
    {
        IntPtr buf = Marshal.AllocHGlobal(4);
        try
        {
            Marshal.WriteInt32(buf, unchecked((int)sessionId));
            return NativeMethods.SetTokenInformation(token, NativeMethods.TokenInfoSessionId, buf, 4);
        }
        finally
        {
            Marshal.FreeHGlobal(buf);
        }
    }

    /// <summary>
    /// Строит блок переменных среды пользователя с редиректом профиля песочницы.
    /// Строковый блок "K=V\0K=V\0\0", возвращается в неуправляемой памяти
    /// (передаётся в CreateProcessAsUser; освобождать после запуска процесса).
    /// </summary>
    public static IntPtr BuildRedirectedEnvironment(
        IntPtr baseToken, string profileDir, string tempDir, string appDataRoaming, string appDataLocal)
    {
        IntPtr envBlock = IntPtr.Zero;
        if (!NativeMethods.CreateEnvironmentBlock(out envBlock, baseToken, false) || envBlock == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        try
        {
            var env = ReadEnvironmentBlock(envBlock);

            env["USERPROFILE"] = profileDir;
            env["HOMEDRIVE"] = PathForDrive(profileDir);
            env["HOMEPATH"] = PathForHomePath(profileDir);
            env["TEMP"] = tempDir;
            env["TMP"] = tempDir;
            env["APPDATA"] = appDataRoaming;
            env["LOCALAPPDATA"] = appDataLocal;
            env["PUBLIC"] = appDataLocal;

            return WriteEnvironmentBlock(env);
        }
        finally
        {
            NativeMethods.DestroyEnvironmentBlock(envBlock);
        }
    }

    private static Dictionary<string, string> ReadEnvironmentBlock(IntPtr block)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        long offset = 0;
        while (true)
        {
            var raw = Marshal.PtrToStringUni(IntPtr.Add(block, (int)offset));
            if (string.IsNullOrEmpty(raw))
            {
                break;
            }

            var eq = raw.IndexOf('=');
            if (eq > 0)
            {
                result[raw.Substring(0, eq)] = raw.Substring(eq + 1);
            }

            offset += (raw.Length + 1) * 2;
        }

        return result;
    }

    private static IntPtr WriteEnvironmentBlock(Dictionary<string, string> env)
    {
        var total = 2; // финальный \0\0
        var entries = new List<string>(env.Count);
        foreach (var kv in env)
        {
            var line = kv.Key + "=" + kv.Value;
            entries.Add(line);
            total += (line.Length + 1) * 2;
        }

        var buf = Marshal.AllocHGlobal(total);
        long offset = 0;
        foreach (var line in entries)
        {
            var bytes = System.Text.Encoding.Unicode.GetBytes(line);
            Marshal.Copy(bytes, 0, IntPtr.Add(buf, (int)offset), bytes.Length);
            Marshal.WriteInt16(IntPtr.Add(buf, (int)offset + bytes.Length), 0); // \0
            offset += bytes.Length + 2;
        }

        Marshal.WriteInt16(IntPtr.Add(buf, (int)offset), 0); // финальный \0
        return buf;
    }

    private static string PathForDrive(string path)
    {
        try
        {
            return path.Length >= 2 && path[1] == ':' ? path.Substring(0, 2) + "\\" : "";
        }
        catch
        {
            return "";
        }
    }

    private static string PathForHomePath(string path)
    {
        try
        {
            if (path.Length >= 2 && path[1] == ':')
            {
                return path.Substring(2).Replace('\\', '/');
            }
        }
        catch
        {
            // ignore
        }

        return "";
    }

    // ---- marshaling-хелперы ----

    private static IntPtr StringSidToIntPtr(string sidText)
    {
        if (!NativeMethods.ConvertStringSidToSid(sidText, out var sid) || sid == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        return sid;
    }

    /// <summary>
    /// Читает массив групп токена с ПОЛНЫМИ КОПИЯМИ содержимого SID (3.0.0.39-fix3).
    /// Указатели исходного буфера TOKEN_GROUPS валидны только до его освобождения;
    /// для передачи в NtCreateToken нужны независимые копии. Копии регистрируются
    /// в <paramref name="copiedSids"/> для освобождения вызывающим кодом.
    /// </summary>
    private static List<NativeMethods.SidAndAttributes>? CopyTokenGroups(
        IntPtr token, List<IntPtr> copiedSids)
    {
        var size = AllocTokenClassBuffer(token, NativeMethods.TokenInfoGroups, out _);
        if (size == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var count = (int)Marshal.ReadInt32(size);
            var list = new List<NativeMethods.SidAndAttributes>(count);
            var itemSize = Marshal.SizeOf<NativeMethods.SidAndAttributes>();
            for (var i = 0; i < count; i++)
            {
                var item = Marshal.PtrToStructure<NativeMethods.SidAndAttributes>(IntPtr.Add(size, 4 + i * itemSize));
                if (item.Sid == IntPtr.Zero)
                {
                    continue;
                }

                var sidLen = NativeMethods.GetLengthSid(item.Sid);
                if (sidLen == 0)
                {
                    continue;
                }

                var copy = Marshal.AllocHGlobal((int)sidLen);
                if (!NativeMethods.CopySid(sidLen, copy, item.Sid))
                {
                    Marshal.FreeHGlobal(copy);
                    continue;
                }

                copiedSids.Add(copy);
                list.Add(new NativeMethods.SidAndAttributes { Sid = copy, Attributes = item.Attributes });
            }

            return list;
        }
        finally
        {
            Marshal.FreeHGlobal(size);
        }
    }

    /// <summary>Множество SID-строк групп токена (для фильтрации sidsToDisable, fix3).</summary>
    private static HashSet<string> ReadTokenGroupSidStrings(IntPtr token)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var size = AllocTokenClassBuffer(token, NativeMethods.TokenInfoGroups, out _);
        if (size == IntPtr.Zero)
        {
            return result;
        }

        try
        {
            var count = (int)Marshal.ReadInt32(size);
            var itemSize = Marshal.SizeOf<NativeMethods.SidAndAttributes>();
            for (var i = 0; i < count; i++)
            {
                var item = Marshal.PtrToStructure<NativeMethods.SidAndAttributes>(IntPtr.Add(size, 4 + i * itemSize));
                var s = SidToString(item.Sid);
                if (!string.IsNullOrEmpty(s))
                {
                    result.Add(s);
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(size);
        }

        return result;
    }

    /// <summary>SID → строка (ConvertSidToStringSid возвращает ANSI-строку).</summary>
    private static string? SidToString(IntPtr sid)
    {
        IntPtr str = IntPtr.Zero;
        try
        {
            if (sid == IntPtr.Zero ||
                !NativeMethods.ConvertSidToStringSid(sid, out str) || str == IntPtr.Zero)
            {
                return null;
            }

            return Marshal.PtrToStringAnsi(str);
        }
        finally
        {
            if (str != IntPtr.Zero) NativeMethods.LocalFree(str);
        }
    }

    private static IntPtr AllocTokenClassBuffer(IntPtr token, int infoClass, out uint length)
    {
        if (!NativeMethods.GetTokenInformation(token, infoClass, IntPtr.Zero, 0, out length))
        {
            var err = Marshal.GetLastWin32Error();
            if (err != 122 /* ERROR_INSUFFICIENT_BUFFER */)
            {
                return IntPtr.Zero;
            }
        }

        var buf = Marshal.AllocHGlobal((int)length);
        if (!NativeMethods.GetTokenInformation(token, infoClass, buf, length, out _))
        {
            Marshal.FreeHGlobal(buf);
            return IntPtr.Zero;
        }

        return buf;
    }

    /// <summary>Строит буфер TOKEN_GROUPS из массива SID_AND_ATTRIBUTES (Count + элементы).</summary>
    private static IntPtr BuildTokenGroupsBuffer(List<NativeMethods.SidAndAttributes> groups)
    {
        var itemSize = Marshal.SizeOf<NativeMethods.SidAndAttributes>();
        var buf = Marshal.AllocHGlobal(4 + groups.Count * itemSize);
        Marshal.WriteInt32(buf, groups.Count);
        for (var i = 0; i < groups.Count; i++)
        {
            Marshal.StructureToPtr(groups[i], IntPtr.Add(buf, 4 + i * itemSize), false);
        }

        return buf;
    }

    /// <summary>Строит буфер массива SID_AND_ATTRIBUTES (для параметров CreateRestrictedToken).</summary>
    private static IntPtr BuildSidAndAttributesBuffer(List<NativeMethods.SidAndAttributes> items)
    {
        if (items.Count == 0)
        {
            return IntPtr.Zero;
        }

        var itemSize = Marshal.SizeOf<NativeMethods.SidAndAttributes>();
        var buf = Marshal.AllocHGlobal(items.Count * itemSize);
        for (var i = 0; i < items.Count; i++)
        {
            Marshal.StructureToPtr(items[i], IntPtr.Add(buf, i * itemSize), false);
        }

        return buf;
    }
}