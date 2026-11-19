using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Collections.Generic;

public static class AccessToken{

    public enum IntegrityLevel : int
    {
        Same = -2,
        Unknown = -1,
        Untrusted = NativeMethods.SECURITY_MANDATORY_UNTRUSTED_RID,
        Low = NativeMethods.SECURITY_MANDATORY_LOW_RID,
        Medium = NativeMethods.SECURITY_MANDATORY_MEDIUM_RID,
        High = NativeMethods.SECURITY_MANDATORY_HIGH_RID,
        System = NativeMethods.SECURITY_MANDATORY_SYSTEM_RID,
        ProtectedProcess = NativeMethods.SECURITY_MANDATORY_PROTECTED_PROCESS_RID
    }

    private static string convertAttributeToString(UInt32 attribute){
        if(attribute == 0)
            return "Disabled";
        if(attribute == 1)
            return "Enabled Default";
        if(attribute == 2)
            return "Enabled";
        if(attribute == 3)
            return "Enabled|Enabled Default";
        return "Error";
    }

    public static List<string[]> GetTokenPrivileges(IntPtr tHandle){
        List<string[]> privileges = new List<string[]>();
        IntPtr TokenInformation = IntPtr.Zero;
        try {
            uint TokenInfLength = 0;
            NativeMethods.GetTokenInformation(tHandle,
                NativeMethods.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                IntPtr.Zero, TokenInfLength, out TokenInfLength);
            TokenInformation = Marshal.AllocHGlobal((int)TokenInfLength);
            if (!NativeMethods.GetTokenInformation(tHandle,
                    NativeMethods.TOKEN_INFORMATION_CLASS.TokenPrivileges,
                    TokenInformation, TokenInfLength, out TokenInfLength))
                throw new RunExException("GetTokenInformation", true);

            int privCount = Marshal.ReadInt32(TokenInformation);
            int structSize = Marshal.SizeOf(typeof(NativeMethods.LUID_AND_ATTRIBUTES));
            IntPtr arrayStart = new IntPtr(TokenInformation.ToInt64() + 4);

            for (int i = 0; i < privCount; i++) {
                IntPtr entryPtr = new IntPtr(arrayStart.ToInt64() + (i * structSize));
                NativeMethods.LUID_AND_ATTRIBUTES entry =
                    (NativeMethods.LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(
                        entryPtr, typeof(NativeMethods.LUID_AND_ATTRIBUTES));

                string[] privilegeStatus = new string[2];
                IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(entry.Luid));
                try {
                    Marshal.StructureToPtr(entry.Luid, ptrLuid, true);
                    int luidNameLen = 0;
                    NativeMethods.LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen);
                    StringBuilder sb = new StringBuilder(luidNameLen + 1);
                    if (!NativeMethods.LookupPrivilegeName(null, ptrLuid, sb, ref luidNameLen))
                        throw new RunExException("LookupPrivilegeName", true);
                    privilegeStatus[0] = sb.ToString();
                } finally {
                    Marshal.FreeHGlobal(ptrLuid);
                }
                privilegeStatus[1] = convertAttributeToString(entry.Attributes);
                privileges.Add(privilegeStatus);
            }
        } finally {
            if (TokenInformation != IntPtr.Zero)
                Marshal.FreeHGlobal(TokenInformation);
        }
        return privileges;
    }

    public static bool IsFilteredUACToken(IntPtr hToken) {
        bool tokenIsFiltered = false;
        int tokenInfLength = 0;
        // GetTokenInformation(TokenElevation) does not return true in all cases, e.g. when having an High IL token with SeImpersonate privilege
        if (GetTokenIntegrityLevel(hToken) >= IntegrityLevel.High) {
            RunExMainClass.VerboseLog("IsFilteredUACToken: token IL >= High, not filtered");
            return false;
        }
        NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, IntPtr.Zero, tokenInfLength, out tokenInfLength);
        IntPtr tokenElevationPtr = Marshal.AllocHGlobal(tokenInfLength);
        if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, tokenElevationPtr, tokenInfLength, out tokenInfLength))
            throw new RunExException("GetTokenInformation TokenElevation", true);
        NativeMethods.TOKEN_ELEVATION tokenElevation = (NativeMethods.TOKEN_ELEVATION)Marshal.PtrToStructure(tokenElevationPtr, typeof(NativeMethods.TOKEN_ELEVATION));
        if (tokenElevation.TokenIsElevated > 0) {
            tokenIsFiltered = false;
            Marshal.FreeHGlobal(tokenElevationPtr);
        }
        else {
            tokenInfLength = 0;
            NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenElevationTypePtr = Marshal.AllocHGlobal(tokenInfLength);
            if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType, tokenElevationTypePtr, tokenInfLength, out tokenInfLength))
                throw new RunExException("GetTokenInformation TokenElevationType", true);
            NativeMethods.TOKEN_ELEVATION_TYPE tokenElevationType = (NativeMethods.TOKEN_ELEVATION_TYPE)Marshal.PtrToStructure(tokenElevationTypePtr, typeof(NativeMethods.TOKEN_ELEVATION_TYPE));
            if (tokenElevationType.TokenElevationType == 3)  // 3 = TokenElevationTypeLimited
                tokenIsFiltered = true;
            Marshal.FreeHGlobal(tokenElevationTypePtr);
        }
        RunExMainClass.VerboseLog("IsFilteredUACToken: result=" + tokenIsFiltered);
        return tokenIsFiltered;
    }

    // thanks @winlogon0 --> https://github.com/AltF5/MediumToHighIL_Test/blob/main/TestCode2.cs
    public static bool SetTokenIntegrityLevel(IntPtr hToken, IntegrityLevel integrity)
    {
        bool ret = false;
        IntPtr pLabelAuthorityStruct;
        IntPtr pSID;
        IntPtr pLabel;
        int labelSize;
        NativeMethods.TOKEN_MANDATORY_LABEL tokenLabel = new NativeMethods.TOKEN_MANDATORY_LABEL();
        NativeMethods.SID_IDENTIFIER_AUTHORITY authoritySid = new NativeMethods.SID_IDENTIFIER_AUTHORITY();
        authoritySid.Value = NativeMethods.MANDATORY_LABEL_AUTHORITY;
        pLabelAuthorityStruct = Marshal.AllocHGlobal(Marshal.SizeOf(authoritySid));
        Marshal.StructureToPtr(authoritySid, pLabelAuthorityStruct, false);
        bool result = NativeMethods.AllocateAndInitializeSid(pLabelAuthorityStruct, 1, (int)integrity, 0, 0, 0, 0, 0, 0, 0, out pSID);
        tokenLabel.Label.pSID = pSID;
        tokenLabel.Label.Attributes = NativeMethods.TokenGroupAttributes.SE_GROUP_INTEGRITY;
        labelSize = Marshal.SizeOf(tokenLabel);
        pLabel = Marshal.AllocHGlobal(labelSize);
        Marshal.StructureToPtr(tokenLabel, pLabel, false);
        result = NativeMethods.SetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pLabel, labelSize);
        Marshal.FreeHGlobal(pLabel);
        Marshal.FreeHGlobal(pSID);
        Marshal.FreeHGlobal(pLabelAuthorityStruct);
        if (!result)
            throw new RunExException("[!] Failed to set the token's Integrity Level: " + integrity.ToString());
        else
            ret = true;
        return ret;
    }

    public static IntegrityLevel GetTokenIntegrityLevel(IntPtr hToken)
    {
        IntegrityLevel illevel = IntegrityLevel.Unknown;
        IntPtr pb = Marshal.AllocHGlobal(1000);
        uint cb = 1000;
        if (NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenIntegrityLevel, pb, cb, out cb))
        {
            IntPtr pSid = Marshal.ReadIntPtr(pb);
            int dwIntegrityLevel = Marshal.ReadInt32(NativeMethods.GetSidSubAuthority(pSid, (Marshal.ReadByte(NativeMethods.GetSidSubAuthorityCount(pSid)) - 1U)));
            IntegrityLevel result;
            if (dwIntegrityLevel == NativeMethods.SECURITY_MANDATORY_LOW_RID)
            {
                result = IntegrityLevel.Low;
            }
            else if (dwIntegrityLevel >= NativeMethods.SECURITY_MANDATORY_MEDIUM_RID && dwIntegrityLevel < NativeMethods.SECURITY_MANDATORY_HIGH_RID)
            {
                result = IntegrityLevel.Medium;
            }
            else if (dwIntegrityLevel >= NativeMethods.SECURITY_MANDATORY_HIGH_RID)
            {
                result = IntegrityLevel.High;
            }
            else if (dwIntegrityLevel >= NativeMethods.SECURITY_MANDATORY_SYSTEM_RID)
            {
                result = IntegrityLevel.System;
            }
            else
            {
                result = IntegrityLevel.Unknown;
            }
            RunExMainClass.VerboseLog("Token integrity level: " + result);
            return result;
        }
        Marshal.FreeHGlobal(pb);
        RunExMainClass.VerboseLog("Token integrity level: Unknown (query failed)");
        return illevel;
    }

    public static string EnablePrivilege(string privilege, IntPtr token)
    {
        RunExMainClass.VerboseLog("Enabling privilege: " + privilege);
        string output = "";
        NativeMethods.LUID sebLuid = new NativeMethods.LUID();
        NativeMethods.TOKEN_PRIVILEGES_2 tokenp = new NativeMethods.TOKEN_PRIVILEGES_2();
        tokenp.PrivilegeCount = 1;
        NativeMethods.LookupPrivilegeValue(null, privilege, ref sebLuid);
        tokenp.Luid = sebLuid;
        tokenp.Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;
        if (!NativeMethods.AdjustTokenPrivileges(token, false, ref tokenp, 0, 0, 0))
        {
            throw new RunExException("AdjustTokenPrivileges on privilege " + privilege, true);
        }
        output += "\r\nAdjustTokenPrivileges on privilege " + privilege + " succeeded";
        return output;
    }

    public static string EnableAllPrivileges(IntPtr token)
    {
        string output = "";
        string[] privileges = { "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeDelegateSessionUserImpersonatePrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege" };
        foreach (string privilege in privileges)
        {
            output += EnablePrivilege(privilege, token);
        }
        return output;
    }

}
