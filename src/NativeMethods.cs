using System;
using System.Text;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Net.Sockets;

public class RunExException : Exception
{
    private const string error_string = "[-] RunExException: ";

    private static string GetWin32ErrorString()
    {
        Console.Out.Flush();
        string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
        return errorMessage;
    }

    public RunExException(){}

    public RunExException(string message) : base(error_string + message) { }

    public RunExException(string win32FunctionName, bool returnWin32Error) : base(error_string + win32FunctionName + " failed with error code: " + GetWin32ErrorString()) {}
}

internal static partial class NativeMethods
{
    // === Constants (from RunEx) ===
    internal const Int32 Startf_UseStdHandles = 0x00000100;
    internal const int TokenPrimary = 1;
    internal const int TokenImpersonation = 2;
    internal const int LOGON32_PROVIDER_DEFAULT = 0;
    internal const int LOGON32_PROVIDER_WINNT50 = 3;
    internal const int LOGON32_LOGON_INTERACTIVE = 2;
    internal const int LOGON32_LOGON_NETWORK = 3;
    internal const int LOGON32_LOGON_BATCH = 4;
    internal const int LOGON32_LOGON_SERVICE = 5;
    internal const int LOGON32_LOGON_NETWORK_CLEARTEXT = 8;
    internal const int LOGON32_LOGON_NEW_CREDENTIALS = 9;
    internal const int ERROR_LOGON_TYPE_NOT_GRANTED = 1385;
    internal const int BUFFER_SIZE_PIPE = 1048576;
    internal const uint CREATE_NO_WINDOW = 0x08000000;
    internal const uint CREATE_SUSPENDED = 0x00000004;
    internal const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    internal const uint DUPLICATE_SAME_ACCESS = 0x00000002;
    internal const UInt32 LOGON_WITH_PROFILE = 1;
    internal const UInt32 LOGON_NETCREDENTIALS_ONLY = 2;
    internal const int GetCurrentProcess = -1;
    internal const uint STD_INPUT_HANDLE  = unchecked((uint)-10);
    internal const uint STD_OUTPUT_HANDLE = unchecked((uint)-11);
    internal const uint STD_ERROR_HANDLE  = unchecked((uint)-12);

    // === Constants (from WindowStationDACL) ===
    internal const int UOI_NAME = 2;
    internal const int ERROR_INSUFFICIENT_BUFFER = 122;
    internal const uint SECURITY_DESCRIPTOR_REVISION = 1;
    internal const uint ACL_REVISION = 2;
    internal const uint MAXDWORD = 0xffffffff;
    internal const byte ACCESS_ALLOWED_ACE_TYPE = 0x0;
    internal const byte CONTAINER_INHERIT_ACE = 0x2;
    internal const byte INHERIT_ONLY_ACE = 0x8;
    internal const byte OBJECT_INHERIT_ACE = 0x1;
    internal const byte NO_PROPAGATE_INHERIT_ACE = 0x4;
    internal const int NO_ERROR = 0;
    internal const int ERROR_INVALID_FLAGS = 1004;

    // === Constants (from AccessToken) ===
    internal const int SECURITY_MANDATORY_UNTRUSTED_RID = 0;
    internal const int SECURITY_MANDATORY_LOW_RID = 0x1000;
    internal const int SECURITY_MANDATORY_MEDIUM_RID = 0x2000;
    internal const int SECURITY_MANDATORY_HIGH_RID = 0x3000;
    internal const int SECURITY_MANDATORY_SYSTEM_RID = 0x4000;
    internal const int SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x5000;
    internal const uint SE_PRIVILEGE_ENABLED = 0x00000002;
    internal static readonly byte[] MANDATORY_LABEL_AUTHORITY = new byte[] { 0, 0, 0, 0, 0, 16 };

    // Token access rights
    internal const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;
    internal const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
    internal const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
    internal const UInt32 TOKEN_DUPLICATE = 0x0002;
    internal const UInt32 TOKEN_IMPERSONATE = 0x0004;
    internal const UInt32 TOKEN_QUERY = 0x0008;
    internal const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
    internal const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    internal const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
    internal const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
    internal const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
    internal const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
    internal const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
        TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
        TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID);

    // === Structs ===

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
         public Int32 cb;
         public string lpReserved;
         public string lpDesktop;
         public string lpTitle;
         public Int32 dwX;
         public Int32 dwY;
         public Int32 dwXSize;
         public Int32 dwYSize;
         public Int32 dwXCountChars;
         public Int32 dwYCountChars;
         public Int32 dwFillAttribute;
         public Int32 dwFlags;
         public Int16 wShowWindow;
         public Int16 cbReserved2;
         public IntPtr lpReserved2;
         public IntPtr hStdInput;
         public IntPtr hStdOutput;
         public IntPtr hStdError;
    }

    internal struct ProcessInformation
    {
        public IntPtr process;
        public IntPtr thread;
        public int    processId;
        public int    threadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        public int    Length;
        public IntPtr lpSecurityDescriptor;
        public bool   bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WSAData
    {
        internal short wVersion;
        internal short wHighVersion;
        internal short iMaxSockets;
        internal short iMaxUdpDg;
        internal IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        internal string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        internal string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROFILEINFO
    {
        public int dwSize;
        public int dwFlags;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpUserName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpProfilePath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpDefaultPath;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpServerName;
        [MarshalAs(UnmanagedType.LPTStr)]
        public String lpPolicyPath;
        public IntPtr hProfile;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SidIdentifierAuthority
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
        public byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL_SIZE_INFORMATION
    {
        public uint AceCount;
        public uint AclBytesInUse;
        public uint AclBytesFree;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public byte AceType;
        public byte AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES_2
    {
        public UInt32 PrivilegeCount;
        public LUID Luid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr pSID;
        public TokenGroupAttributes Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    internal struct TOKEN_ELEVATION
    {
        public UInt32 TokenIsElevated;
    }

    internal struct TOKEN_ELEVATION_TYPE
    {
        public UInt32 TokenElevationType;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public UInt32 Attributes;
    }

    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    // === Enums ===

    internal enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    internal enum SE_OBJECT_TYPE
    {
        SE_UNKNOWN_OBJECT_TYPE = 0,
        SE_FILE_OBJECT,
        SE_SERVICE,
        SE_PRINTER,
        SE_REGISTRY_KEY,
        SE_LMSHARE,
        SE_KERNEL_OBJECT,
        SE_WINDOW_OBJECT,
        SE_DS_OBJECT,
        SE_DS_OBJECT_ALL,
        SE_PROVIDER_DEFINED_OBJECT,
        SE_WMIGUID_OBJECT,
        SE_REGISTRY_WOW64_32KEY
    }

    [Flags]
    internal enum ACCESS_MASK : uint
    {
        DELETE = 0x00010000,
        READ_CONTROL = 0x00020000,
        WRITE_DAC = 0x00040000,
        WRITE_OWNER = 0x00080000,
        SYNCHRONIZE = 0x00100000,

        STANDARD_RIGHTS_REQUIRED = 0x000F0000,

        STANDARD_RIGHTS_READ = 0x00020000,
        STANDARD_RIGHTS_WRITE = 0x00020000,
        STANDARD_RIGHTS_EXECUTE = 0x00020000,

        STANDARD_RIGHTS_ALL = 0x001F0000,

        SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

        ACCESS_SYSTEM_SECURITY = 0x01000000,

        MAXIMUM_ALLOWED = 0x02000000,

        GENERIC_READ = 0x80000000,
        GENERIC_WRITE = 0x40000000,
        GENERIC_EXECUTE = 0x20000000,
        GENERIC_ALL = 0x10000000,
        GENERIC_ACCESS = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL,

        DESKTOP_READOBJECTS = 0x00000001,
        DESKTOP_CREATEWINDOW = 0x00000002,
        DESKTOP_CREATEMENU = 0x00000004,
        DESKTOP_HOOKCONTROL = 0x00000008,
        DESKTOP_JOURNALRECORD = 0x00000010,
        DESKTOP_JOURNALPLAYBACK = 0x00000020,
        DESKTOP_ENUMERATE = 0x00000040,
        DESKTOP_WRITEOBJECTS = 0x00000080,
        DESKTOP_SWITCHDESKTOP = 0x00000100,
        DESKTOP_ALL = (DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU |
                    DESKTOP_HOOKCONTROL | DESKTOP_JOURNALRECORD | DESKTOP_JOURNALPLAYBACK |
                    DESKTOP_ENUMERATE | DESKTOP_WRITEOBJECTS | DESKTOP_SWITCHDESKTOP |
                    STANDARD_RIGHTS_REQUIRED),

        WINSTA_ENUMDESKTOPS = 0x00000001,
        WINSTA_READATTRIBUTES = 0x00000002,
        WINSTA_ACCESSCLIPBOARD = 0x00000004,
        WINSTA_CREATEDESKTOP = 0x00000008,
        WINSTA_WRITEATTRIBUTES = 0x00000010,
        WINSTA_ACCESSGLOBALATOMS = 0x00000020,
        WINSTA_EXITWINDOWS = 0x00000040,
        WINSTA_ENUMERATE = 0x00000100,
        WINSTA_READSCREEN = 0x00000200,
        WINSTA_ALL =  (WINSTA_ACCESSCLIPBOARD  | WINSTA_ACCESSGLOBALATOMS |
                   WINSTA_CREATEDESKTOP    | WINSTA_ENUMDESKTOPS      |
                   WINSTA_ENUMERATE        | WINSTA_EXITWINDOWS       |
                   WINSTA_READATTRIBUTES   | WINSTA_READSCREEN        |
                   WINSTA_WRITEATTRIBUTES  | DELETE                   |
                   READ_CONTROL            | WRITE_DAC                |
                   WRITE_OWNER)
    }

    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION        = 0x00000001,
        GROUP_SECURITY_INFORMATION        = 0x00000002,
        DACL_SECURITY_INFORMATION         = 0x00000004,
        SACL_SECURITY_INFORMATION         = 0x00000008,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
    }

    internal enum ACL_INFORMATION_CLASS
    {
        AclRevisionInformation = 1,
        AclSizeInformation = 2
    }

    internal enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    internal enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        TokenProcessTrustLevel,
        TokenPrivateNameSpace,
        TokenSingletonAttributes,
        TokenBnoIsolation,
        TokenChildProcessFlags,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        MaxTokenInfoClass
    }

    internal enum TokenGroupAttributes : uint
    {
        Disabled = 0,
        SE_GROUP_MANDATORY = 1,
        SE_GROUP_ENABLED_BY_DEFAULT = 0x2,
        SE_GROUP_ENABLED = 0x4,
        SE_GROUP_OWNER = 0x8,
        SE_GROUP_USE_FOR_DENY_ONLY = 0x10,
        SE_GROUP_INTEGRITY = 0x20,
        SE_GROUP_INTEGRITY_ENABLED = 0x40,
        SE_GROUP_RESOURCE = 0x20000000,
        SE_GROUP_LOGON_ID = 0xC0000000
    }

}
