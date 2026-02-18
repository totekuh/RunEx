using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Net.Sockets;

internal static partial class NativeMethods
{
    // =====================================================================
    // Bootstrap — the only 3 P/Invoke declarations in the assembly
    // =====================================================================

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    private static string D(byte[] e, uint k) {
        byte[] b = new byte[e.Length];
        for (int i = 0; i < e.Length; i++) {
            k += 0x6D2B79F5u;
            uint t = k;
            t = (t ^ (t >> 15)) * 0x2C1B3C6Du;
            t = (t ^ (t >> 12)) * 0x297A2D39u;
            t ^= t >> 15;
            b[i] = (byte)(e[i] ^ (byte)(t >> ((i & 3) << 3)));
        }
        return System.Text.Encoding.ASCII.GetString(b);
    }

    private static T GetDelegate<T>(byte[] dllEnc, uint dllKey, byte[] funcEnc, uint funcKey) where T : class
    {
        string dll = D(dllEnc, dllKey);
        string func = D(funcEnc, funcKey);
        IntPtr mod = GetModuleHandle(dll);
        if (mod == IntPtr.Zero) mod = LoadLibrary(dll);
        IntPtr addr = GetProcAddress(mod, func);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(addr, typeof(T));
    }

    // Encrypted DLL names
    private static readonly byte[] _ek32 = new byte[] { 0xCD, 0x4D, 0x0A, 0x42, 0x3B, 0x15, 0xD6, 0xDC, 0xCD, 0x05, 0x02, 0x66 };
    private const uint _kk32 = 0xDD249B44u;
    private static readonly byte[] _eadv = new byte[] { 0x19, 0x08, 0x1C, 0x5D, 0x52, 0xA9, 0xC0, 0x3D, 0xC2, 0xC0, 0x8B, 0xCD };
    private const uint _kadv = 0xF2C0C03Fu;
    private static readonly byte[] _eu32 = new byte[] { 0xAE, 0x93, 0x6A, 0x6A, 0x27, 0x83, 0x13, 0x11, 0xB3, 0xDF };
    private const uint _ku32 = 0xE628143Du;
    private static readonly byte[] _euenv = new byte[] { 0x56, 0x2D, 0x85, 0x96, 0x86, 0xFC, 0x78, 0x2B, 0x19, 0xCA, 0x5A };
    private const uint _kuenv = 0x2E20BA1Bu;
    private static readonly byte[] _ews2 = new byte[] { 0x12, 0xA3, 0xD1, 0xC1, 0xEA, 0xCC, 0x4A, 0xF2, 0xBA, 0x43 };
    private const uint _kws2 = 0xF1E50204u;

    // =====================================================================
    // Delegate types
    // =====================================================================

    // --- kernel32 ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool CloseHandle_t(IntPtr handle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate UInt32 WaitForSingleObject_t(IntPtr handle, UInt32 milliseconds);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int ResumeThread_t(IntPtr hThread);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool CreateProcess_t(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool CreatePipe_t(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate bool SetNamedPipeHandleState_t(IntPtr hNamedPipe, ref UInt32 lpMode, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool ReadFile_t(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool DuplicateHandle_t(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate IntPtr GetStdHandle_t(uint nStdHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool GetExitCodeProcess_t(IntPtr hProcess, out uint lpExitCode);

    // --- advapi32 ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool ImpersonateLoggedOnUser_t(IntPtr hToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool SetThreadToken_t(ref IntPtr pHandle, IntPtr hToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool RevertToSelf_t();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool LogonUser_t([MarshalAs(UnmanagedType.LPStr)] string pszUserName, [MarshalAs(UnmanagedType.LPStr)] string pszDomain, [MarshalAs(UnmanagedType.LPStr)] string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool DuplicateTokenEx_t(IntPtr ExistingTokenHandle, uint dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, int TokenType, ref IntPtr DuplicateTokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool OpenProcessToken_t(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool CreateProcessWithLogonW_t(String userName, String domain, String password, UInt32 logonFlags, String applicationName, String commandLine, uint creationFlags, UInt32 environment, String currentDirectory, ref STARTUPINFO startupInfo, out ProcessInformation processInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool CreateProcessAsUser_t(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool CreateProcessWithTokenW_t(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate uint SetSecurityInfo_t(IntPtr handle, SE_OBJECT_TYPE ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr FreeSid_t(IntPtr pSid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool GetSecurityDescriptorDacl_t(IntPtr pSecurityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool bDaclPresent, ref IntPtr pDacl, [MarshalAs(UnmanagedType.Bool)] out bool bDaclDefaulted);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool GetAclInformation_t(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInformation, uint nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool InitializeSecurityDescriptor_t(IntPtr SecurityDescriptor, uint dwRevision);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int GetLengthSid_t(IntPtr pSID);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool InitializeAcl_t(IntPtr pAcl, uint nAclLength, uint dwAclRevision);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetAce_t(IntPtr aclPtr, int aceIndex, out IntPtr acePtr);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool AddAce_t(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool SetSecurityDescriptorDacl_t(IntPtr sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool CopySid_t(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool LookupAccountName_t(string lpSystemName, string lpAccountName, [MarshalAs(UnmanagedType.LPArray)] byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetTokenInformation_uint_t(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetTokenInformation_int_t(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool LookupPrivilegeName_t(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool AllocateAndInitializeSid_t(IntPtr pIdentifierAuthority, byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool SetTokenInformation_t(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate IntPtr GetSidSubAuthority_t(IntPtr sid, UInt32 subAuthorityIndex);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate IntPtr GetSidSubAuthorityCount_t(IntPtr sid);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool AdjustTokenPrivileges_t(IntPtr tokenhandle, bool disableprivs, [MarshalAs(UnmanagedType.Struct)] ref TOKEN_PRIVILEGES_2 Newstate, int bufferlength, int PreivousState, int Returnlength);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int LookupPrivilegeValue_t(string lpsystemname, string lpname, [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

    // --- user32 ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate IntPtr GetProcessWindowStation_t();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetUserObjectInformation_t(IntPtr hObj, int nIndex, [Out] byte[] pvInfo, uint nLength, out uint lpnLengthNeeded);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate IntPtr OpenWindowStation_t([MarshalAs(UnmanagedType.LPTStr)] string lpszWinSta, [MarshalAs(UnmanagedType.Bool)] bool fInherit, ACCESS_MASK dwDesiredAccess);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr OpenDesktop_t(string lpszDesktop, uint dwFlags, bool fInherit, ACCESS_MASK dwDesiredAccess);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool CloseWindowStation_t(IntPtr hWinsta);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool CloseDesktop_t(IntPtr hDesktop);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool SetProcessWindowStation_t(IntPtr hWinSta);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool GetUserObjectSecurity_t(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool SetUserObjectSecurity_t(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSD);

    // --- userenv ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool CreateEnvironmentBlock_t(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool DestroyEnvironmentBlock_t(IntPtr lpEnvironment);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool GetUserProfileDirectory_t(IntPtr hToken, StringBuilder path, ref int dwSize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Unicode)]
    private delegate bool LoadUserProfile_t(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate bool UnloadUserProfile_t(IntPtr hToken, IntPtr hProfile);

    // --- ws2_32 ---

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true, CharSet = CharSet.Ansi)]
    private delegate IntPtr WSASocket_t([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int connect_t(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate ushort htons_t(ushort hostshort);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate Int32 WSAGetLastError_t();

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate Int32 WSAStartup_t(Int16 wVersionRequested, out WSAData wsaData);

    [UnmanagedFunctionPointer(CallingConvention.StdCall, SetLastError = true)]
    private delegate int closesocket_t(IntPtr s);

    // =====================================================================
    // Cached delegate fields
    // =====================================================================

    // kernel32
    private static CloseHandle_t _CloseHandle;
    private static WaitForSingleObject_t _WaitForSingleObject;
    private static ResumeThread_t _ResumeThread;
    private static CreateProcess_t _CreateProcess;
    private static CreatePipe_t _CreatePipe;
    private static SetNamedPipeHandleState_t _SetNamedPipeHandleState;
    private static ReadFile_t _ReadFile;
    private static DuplicateHandle_t _DuplicateHandle;
    private static GetStdHandle_t _GetStdHandle;
    private static GetExitCodeProcess_t _GetExitCodeProcess;

    // advapi32
    private static ImpersonateLoggedOnUser_t _ImpersonateLoggedOnUser;
    private static SetThreadToken_t _SetThreadToken;
    private static RevertToSelf_t _RevertToSelf;
    private static LogonUser_t _LogonUser;
    private static DuplicateTokenEx_t _DuplicateTokenEx;
    private static OpenProcessToken_t _OpenProcessToken;
    private static CreateProcessWithLogonW_t _CreateProcessWithLogonW;
    private static CreateProcessAsUser_t _CreateProcessAsUser;
    private static CreateProcessWithTokenW_t _CreateProcessWithTokenW;
    private static SetSecurityInfo_t _SetSecurityInfo;
    private static FreeSid_t _FreeSid;
    private static GetSecurityDescriptorDacl_t _GetSecurityDescriptorDacl;
    private static GetAclInformation_t _GetAclInformation;
    private static InitializeSecurityDescriptor_t _InitializeSecurityDescriptor;
    private static GetLengthSid_t _GetLengthSid;
    private static InitializeAcl_t _InitializeAcl;
    private static GetAce_t _GetAce;
    private static AddAce_t _AddAce;
    private static SetSecurityDescriptorDacl_t _SetSecurityDescriptorDacl;
    private static CopySid_t _CopySid;
    private static LookupAccountName_t _LookupAccountName;
    private static GetTokenInformation_uint_t _GetTokenInformation_uint;
    private static GetTokenInformation_int_t _GetTokenInformation_int;
    private static LookupPrivilegeName_t _LookupPrivilegeName;
    private static AllocateAndInitializeSid_t _AllocateAndInitializeSid;
    private static SetTokenInformation_t _SetTokenInformation;
    private static GetSidSubAuthority_t _GetSidSubAuthority;
    private static GetSidSubAuthorityCount_t _GetSidSubAuthorityCount;
    private static AdjustTokenPrivileges_t _AdjustTokenPrivileges;
    private static LookupPrivilegeValue_t _LookupPrivilegeValue;

    // user32
    private static GetProcessWindowStation_t _GetProcessWindowStation;
    private static GetUserObjectInformation_t _GetUserObjectInformation;
    private static OpenWindowStation_t _OpenWindowStation;
    private static OpenDesktop_t _OpenDesktop;
    private static CloseWindowStation_t _CloseWindowStation;
    private static CloseDesktop_t _CloseDesktop;
    private static SetProcessWindowStation_t _SetProcessWindowStation;
    private static GetUserObjectSecurity_t _GetUserObjectSecurity;
    private static SetUserObjectSecurity_t _SetUserObjectSecurity;

    // userenv
    private static CreateEnvironmentBlock_t _CreateEnvironmentBlock;
    private static DestroyEnvironmentBlock_t _DestroyEnvironmentBlock;
    private static GetUserProfileDirectory_t _GetUserProfileDirectory;
    private static LoadUserProfile_t _LoadUserProfile;
    private static UnloadUserProfile_t _UnloadUserProfile;

    // ws2_32
    private static WSASocket_t _WSASocket;
    private static connect_t _connect;
    private static htons_t _htons;
    private static WSAGetLastError_t _WSAGetLastError;
    private static WSAStartup_t _WSAStartup;
    private static closesocket_t _closesocket;

    // =====================================================================
    // Wrapper methods — same signatures as original P/Invoke declarations
    // =====================================================================

    // --- kernel32 ---

    internal static bool CloseHandle(IntPtr handle) {
        if (_CloseHandle == null) _CloseHandle = GetDelegate<CloseHandle_t>(
            _ek32, _kk32, new byte[] { 0x09, 0xFB, 0x36, 0x07, 0xC6, 0xA2, 0xE9, 0x29, 0x06, 0xBE, 0xA2 }, 0xE3DBD39Cu);
        return _CloseHandle(handle);
    }

    internal static UInt32 WaitForSingleObject(IntPtr handle, UInt32 milliseconds) {
        if (_WaitForSingleObject == null) _WaitForSingleObject = GetDelegate<WaitForSingleObject_t>(
            _ek32, _kk32, new byte[] { 0x4F, 0x86, 0xB1, 0xDB, 0x1E, 0xE3, 0x2C, 0xBC, 0x6D, 0x47, 0x78, 0x6C, 0x5F, 0x23, 0x16, 0xA6, 0x3B, 0xBD, 0x61 }, 0xCA06BFFBu);
        return _WaitForSingleObject(handle, milliseconds);
    }

    internal static int ResumeThread(IntPtr hThread) {
        if (_ResumeThread == null) _ResumeThread = GetDelegate<ResumeThread_t>(
            _ek32, _kk32, new byte[] { 0x12, 0x1D, 0xDA, 0x4B, 0x6E, 0xAB, 0x6B, 0x70, 0x55, 0x13, 0x4B, 0x1B }, 0xA6E71424u);
        return _ResumeThread(hThread);
    }

    internal static bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation) {
        if (_CreateProcess == null) _CreateProcess = GetDelegate<CreateProcess_t>(
            _ek32, _kk32, new byte[] { 0xAB, 0xA6, 0xAC, 0x35, 0x09, 0x71, 0x2A, 0x07, 0x97, 0xF5, 0x11, 0x5A, 0x05, 0x8C }, 0xC227B531u);
        return _CreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
    }

    internal static bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, uint nSize) {
        if (_CreatePipe == null) _CreatePipe = GetDelegate<CreatePipe_t>(
            _ek32, _kk32, new byte[] { 0xCA, 0x4B, 0x0A, 0x48, 0x3E, 0x35, 0xE6, 0xF4, 0x27, 0x4A }, 0x62D7A7AAu);
        return _CreatePipe(out hReadPipe, out hWritePipe, ref lpPipeAttributes, nSize);
    }

    internal static bool SetNamedPipeHandleState(IntPtr hNamedPipe, ref UInt32 lpMode, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout) {
        if (_SetNamedPipeHandleState == null) _SetNamedPipeHandleState = GetDelegate<SetNamedPipeHandleState_t>(
            _ek32, _kk32, new byte[] { 0x16, 0x35, 0xD7, 0xC9, 0xEB, 0x16, 0xDC, 0x56, 0x04, 0x47, 0x80, 0xFF, 0xDC, 0x27, 0x12, 0x83, 0xF9, 0x4A, 0xAF, 0x8C, 0x1E, 0x41, 0x8C }, 0x89128711u);
        return _SetNamedPipeHandleState(hNamedPipe, ref lpMode, lpMaxCollectionCount, lpCollectDataTimeout);
    }

    internal static bool ReadFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped) {
        if (_ReadFile == null) _ReadFile = GetDelegate<ReadFile_t>(
            _ek32, _kk32, new byte[] { 0xB6, 0xED, 0x2A, 0x1E, 0xE2, 0x2C, 0x48, 0xCE }, 0x2A960F3Du);
        return _ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, out lpNumberOfBytesRead, lpOverlapped);
    }

    internal static bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions) {
        if (_DuplicateHandle == null) _DuplicateHandle = GetDelegate<DuplicateHandle_t>(
            _ek32, _kk32, new byte[] { 0xF0, 0xFD, 0xE8, 0xA9, 0x28, 0x0D, 0xC5, 0x2F, 0x00, 0xE7, 0xE2, 0x3D, 0x59, 0x9E, 0x86 }, 0x347842BDu);
        return _DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, out lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
    }

    internal static IntPtr GetStdHandle(uint nStdHandle) {
        if (_GetStdHandle == null) _GetStdHandle = GetDelegate<GetStdHandle_t>(
            _ek32, _kk32, new byte[] { 0xE0, 0xC8, 0xF4, 0x67, 0x40, 0x90, 0xF2, 0x79, 0xF3, 0x0B, 0x13, 0x93 }, 0x88FB3418u);
        return _GetStdHandle(nStdHandle);
    }

    internal static bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode) {
        if (_GetExitCodeProcess == null) _GetExitCodeProcess = GetDelegate<GetExitCodeProcess_t>(
            _ek32, _kk32, new byte[] { 0xBB, 0x5A, 0x99, 0x95, 0x9F, 0x82, 0x1E, 0x8E, 0x7C, 0x3A, 0x18, 0x04, 0xEB, 0x11, 0x38, 0xC0, 0x27, 0xF7 }, 0x15048019u);
        return _GetExitCodeProcess(hProcess, out lpExitCode);
    }

    // --- advapi32 ---

    internal static bool ImpersonateLoggedOnUser(IntPtr hToken) {
        if (_ImpersonateLoggedOnUser == null) _ImpersonateLoggedOnUser = GetDelegate<ImpersonateLoggedOnUser_t>(
            _eadv, _kadv, new byte[] { 0x9F, 0x48, 0x8E, 0x35, 0xDA, 0x19, 0xDB, 0xD4, 0x26, 0xC2, 0xA1, 0xD8, 0x95, 0xDC, 0x11, 0x98, 0x01, 0xFA, 0x1F, 0x67, 0xB0, 0x20, 0xC1 }, 0x3E890848u);
        return _ImpersonateLoggedOnUser(hToken);
    }

    internal static bool SetThreadToken(ref IntPtr pHandle, IntPtr hToken) {
        if (_SetThreadToken == null) _SetThreadToken = GetDelegate<SetThreadToken_t>(
            _eadv, _kadv, new byte[] { 0x8F, 0x4A, 0x85, 0x18, 0x07, 0x50, 0x74, 0x86, 0x5C, 0xEF, 0xC0, 0x7C, 0xD5, 0xE0 }, 0x644C733Cu);
        return _SetThreadToken(ref pHandle, hToken);
    }

    internal static bool RevertToSelf() {
        if (_RevertToSelf == null) _RevertToSelf = GetDelegate<RevertToSelf_t>(
            _eadv, _kadv, new byte[] { 0x88, 0x38, 0xAC, 0x09, 0xC3, 0x00, 0x92, 0x4E, 0x7F, 0x4D, 0x9D, 0x97 }, 0xBEAE0F84u);
        return _RevertToSelf();
    }

    internal static bool LogonUser(string pszUserName, string pszDomain, string pszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken) {
        if (_LogonUser == null) _LogonUser = GetDelegate<LogonUser_t>(
            _eadv, _kadv, new byte[] { 0x46, 0xC4, 0x1D, 0xC0, 0x41, 0x69, 0xA8, 0x25, 0x33, 0x77 }, 0x24EAD1F5u);
        return _LogonUser(pszUserName, pszDomain, pszPassword, dwLogonType, dwLogonProvider, ref phToken);
    }

    internal static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, IntPtr lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, int TokenType, ref IntPtr DuplicateTokenHandle) {
        if (_DuplicateTokenEx == null) _DuplicateTokenEx = GetDelegate<DuplicateTokenEx_t>(
            _eadv, _kadv, new byte[] { 0x2D, 0x76, 0x66, 0x37, 0x5E, 0xF2, 0x52, 0x02, 0xB5, 0x0B, 0x23, 0x2B, 0x5B, 0xBE, 0x19, 0xFA }, 0x2ECCC6D4u);
        return _DuplicateTokenEx(ExistingTokenHandle, dwDesiredAccess, lpThreadAttributes, ImpersonationLevel, TokenType, ref DuplicateTokenHandle);
    }

    internal static bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle) {
        if (_OpenProcessToken == null) _OpenProcessToken = GetDelegate<OpenProcessToken_t>(
            _eadv, _kadv, new byte[] { 0x1A, 0x9B, 0x93, 0x72, 0xA7, 0x2E, 0xAC, 0x54, 0xCF, 0x41, 0xC1, 0x16, 0x1A, 0x42, 0xC3, 0x5C }, 0xE1B73A12u);
        return _OpenProcessToken(ProcessHandle, DesiredAccess, out TokenHandle);
    }

    internal static bool CreateProcessWithLogonW(String userName, String domain, String password, UInt32 logonFlags, String applicationName, String commandLine, uint creationFlags, UInt32 environment, String currentDirectory, ref STARTUPINFO startupInfo, out ProcessInformation processInformation) {
        if (_CreateProcessWithLogonW == null) _CreateProcessWithLogonW = GetDelegate<CreateProcessWithLogonW_t>(
            _eadv, _kadv, new byte[] { 0xEC, 0xA9, 0x6E, 0xF3, 0x49, 0x33, 0xA8, 0x45, 0x83, 0x1B, 0x5C, 0xDB, 0x82, 0xAD, 0x10, 0xBA, 0xA7, 0xDC, 0xCE, 0xDC, 0xC6, 0x4E, 0xBD }, 0x0ABDCE57u);
        return _CreateProcessWithLogonW(userName, domain, password, logonFlags, applicationName, commandLine, creationFlags, environment, currentDirectory, ref startupInfo, out processInformation);
    }

    internal static bool CreateProcessAsUser(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation) {
        if (_CreateProcessAsUser == null) _CreateProcessAsUser = GetDelegate<CreateProcessAsUser_t>(
            _eadv, _kadv, new byte[] { 0xA0, 0x0E, 0x2B, 0x79, 0x25, 0x3E, 0xDA, 0xB2, 0xEE, 0x49, 0x40, 0xC4, 0x3E, 0xC8, 0xC8, 0xF1, 0xC7, 0x4A, 0x53, 0xF5 }, 0x7C5759ACu);
        return _CreateProcessAsUser(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
    }

    internal static bool CreateProcessWithTokenW(IntPtr hToken, uint dwLogonFlags, string lpApplicationName, string lpCommandLine, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInformation lpProcessInformation) {
        if (_CreateProcessWithTokenW == null) _CreateProcessWithTokenW = GetDelegate<CreateProcessWithTokenW_t>(
            _eadv, _kadv, new byte[] { 0x7F, 0x00, 0xDB, 0x4B, 0xF7, 0xEC, 0xE6, 0x87, 0x35, 0x6D, 0xAF, 0x2F, 0xC9, 0x25, 0xB6, 0x59, 0xA0, 0x51, 0x4E, 0x39, 0x72, 0x00, 0xB4 }, 0xB0C77DFFu);
        return _CreateProcessWithTokenW(hToken, dwLogonFlags, lpApplicationName, lpCommandLine, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
    }

    internal static uint SetSecurityInfo(IntPtr handle, SE_OBJECT_TYPE ObjectType, uint SecurityInfo, IntPtr psidOwner, IntPtr psidGroup, IntPtr pDacl, IntPtr pSacl) {
        if (_SetSecurityInfo == null) _SetSecurityInfo = GetDelegate<SetSecurityInfo_t>(
            _eadv, _kadv, new byte[] { 0xE9, 0x4F, 0xD2, 0x27, 0x36, 0x38, 0xE3, 0xA3, 0x86, 0x1D, 0xC7, 0x68, 0x87, 0x21, 0xA1 }, 0xBF008BD0u);
        return _SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
    }

    internal static IntPtr FreeSid(IntPtr pSid) {
        if (_FreeSid == null) _FreeSid = GetDelegate<FreeSid_t>(
            _eadv, _kadv, new byte[] { 0x77, 0x3A, 0x3F, 0x73, 0x77, 0xCD, 0xC6 }, 0x217C45C4u);
        return _FreeSid(pSid);
    }

    internal static bool GetSecurityDescriptorDacl(IntPtr pSecurityDescriptor, out bool bDaclPresent, ref IntPtr pDacl, out bool bDaclDefaulted) {
        if (_GetSecurityDescriptorDacl == null) _GetSecurityDescriptorDacl = GetDelegate<GetSecurityDescriptorDacl_t>(
            _eadv, _kadv, new byte[] { 0x36, 0xB7, 0x17, 0x76, 0xBC, 0x34, 0xE9, 0x8F, 0xCC, 0xED, 0xC9, 0x49, 0xA2, 0x2C, 0xD2, 0x8C, 0x34, 0x69, 0xA4, 0xD1, 0xB6, 0x76, 0xF4, 0x18, 0x8F }, 0x0805F7B8u);
        return _GetSecurityDescriptorDacl(pSecurityDescriptor, out bDaclPresent, ref pDacl, out bDaclDefaulted);
    }

    internal static bool GetAclInformation(IntPtr pAcl, ref ACL_SIZE_INFORMATION pAclInformation, uint nAclInformationLength, ACL_INFORMATION_CLASS dwAclInformationClass) {
        if (_GetAclInformation == null) _GetAclInformation = GetDelegate<GetAclInformation_t>(
            _eadv, _kadv, new byte[] { 0x99, 0xAD, 0x16, 0xE5, 0x20, 0x27, 0xC0, 0x34, 0x1F, 0x10, 0x54, 0xE4, 0x35, 0xA5, 0x18, 0xDE, 0xAA }, 0xE3BF88F1u);
        return _GetAclInformation(pAcl, ref pAclInformation, nAclInformationLength, dwAclInformationClass);
    }

    internal static bool InitializeSecurityDescriptor(IntPtr SecurityDescriptor, uint dwRevision) {
        if (_InitializeSecurityDescriptor == null) _InitializeSecurityDescriptor = GetDelegate<InitializeSecurityDescriptor_t>(
            _eadv, _kadv, new byte[] { 0x00, 0xD7, 0xCB, 0x73, 0x4F, 0xC6, 0x83, 0xB7, 0x0B, 0xBB, 0x05, 0x76, 0x9A, 0xCD, 0x07, 0xBD, 0xF0, 0xB5, 0x96, 0xFD, 0xAF, 0xBB, 0xA5, 0xAA, 0x37, 0x65, 0x59, 0xBA }, 0xF2CF6E36u);
        return _InitializeSecurityDescriptor(SecurityDescriptor, dwRevision);
    }

    internal static int GetLengthSid(IntPtr pSID) {
        if (_GetLengthSid == null) _GetLengthSid = GetDelegate<GetLengthSid_t>(
            _eadv, _kadv, new byte[] { 0xB2, 0xC7, 0x4C, 0xC5, 0xEF, 0x19, 0xB8, 0x11, 0x4B, 0x8D, 0x5A, 0xA5 }, 0x93367AABu);
        return _GetLengthSid(pSID);
    }

    internal static bool InitializeAcl(IntPtr pAcl, uint nAclLength, uint dwAclRevision) {
        if (_InitializeAcl == null) _InitializeAcl = GetDelegate<InitializeAcl_t>(
            _eadv, _kadv, new byte[] { 0x9B, 0xDC, 0xAC, 0x8C, 0x48, 0xA4, 0x1F, 0xC2, 0x3A, 0x6A, 0x6B, 0x95, 0x0C }, 0x866C3943u);
        return _InitializeAcl(pAcl, nAclLength, dwAclRevision);
    }

    internal static bool GetAce(IntPtr aclPtr, int aceIndex, out IntPtr acePtr) {
        if (_GetAce == null) _GetAce = GetDelegate<GetAce_t>(
            _eadv, _kadv, new byte[] { 0xC6, 0x0A, 0x4A, 0xE3, 0xE8, 0x28 }, 0x0C07DF6Fu);
        return _GetAce(aclPtr, aceIndex, out acePtr);
    }

    internal static bool AddAce(IntPtr pAcl, uint dwAceRevision, uint dwStartingAceIndex, IntPtr pAceList, uint nAceListLength) {
        if (_AddAce == null) _AddAce = GetDelegate<AddAce_t>(
            _eadv, _kadv, new byte[] { 0xAB, 0x39, 0x90, 0xEA, 0x29, 0xE1 }, 0xEE6C50B7u);
        return _AddAce(pAcl, dwAceRevision, dwStartingAceIndex, pAceList, nAceListLength);
    }

    internal static bool SetSecurityDescriptorDacl(IntPtr sd, bool daclPresent, IntPtr dacl, bool daclDefaulted) {
        if (_SetSecurityDescriptorDacl == null) _SetSecurityDescriptorDacl = GetDelegate<SetSecurityDescriptorDacl_t>(
            _eadv, _kadv, new byte[] { 0x41, 0x50, 0xBA, 0x3A, 0x77, 0x4D, 0xE9, 0xF2, 0x2B, 0xB5, 0x3C, 0x2E, 0xA2, 0x19, 0x2C, 0x9E, 0x82, 0x91, 0x64, 0x1B, 0x68, 0xA9, 0x4C, 0xDB, 0x9F }, 0x527A31F1u);
        return _SetSecurityDescriptorDacl(sd, daclPresent, dacl, daclDefaulted);
    }

    internal static bool CopySid(uint nDestinationSidLength, IntPtr pDestinationSid, IntPtr pSourceSid) {
        if (_CopySid == null) _CopySid = GetDelegate<CopySid_t>(
            _eadv, _kadv, new byte[] { 0x87, 0x9A, 0xFD, 0xCE, 0x9F, 0x9D, 0xB2 }, 0x4A06A4B4u);
        return _CopySid(nDestinationSidLength, pDestinationSid, pSourceSid);
    }

    internal static bool LookupAccountName(string lpSystemName, string lpAccountName, byte[] Sid, ref uint cbSid, StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out SID_NAME_USE peUse) {
        if (_LookupAccountName == null) _LookupAccountName = GetDelegate<LookupAccountName_t>(
            _eadv, _kadv, new byte[] { 0x78, 0x60, 0xB9, 0xC2, 0x07, 0x21, 0x26, 0x35, 0xAE, 0x6E, 0xDD, 0x4E, 0xE2, 0x07, 0xCA, 0x87, 0x0A, 0x04 }, 0xA733C685u);
        return _LookupAccountName(lpSystemName, lpAccountName, Sid, ref cbSid, ReferencedDomainName, ref cchReferencedDomainName, out peUse);
    }

    internal static bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength) {
        if (_GetTokenInformation_uint == null) _GetTokenInformation_uint = GetDelegate<GetTokenInformation_uint_t>(
            _eadv, _kadv, new byte[] { 0x4D, 0x1A, 0x30, 0x74, 0x51, 0xB7, 0x40, 0x6E, 0x68, 0x75, 0x49, 0x7B, 0xAB, 0x2B, 0xD9, 0xA9, 0xDC, 0x74, 0x40 }, 0xEF1A6D71u);
        return _GetTokenInformation_uint(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, out ReturnLength);
    }

    internal static bool GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength) {
        if (_GetTokenInformation_int == null) _GetTokenInformation_int = GetDelegate<GetTokenInformation_int_t>(
            _eadv, _kadv, new byte[] { 0x7B, 0x98, 0xF0, 0xF4, 0x99, 0xBB, 0x33, 0x11, 0xF2, 0xDC, 0xDF, 0x08, 0x8C, 0xCA, 0x9E, 0xBA, 0xFB, 0xA9, 0x66 }, 0xC1CE0D09u);
        return _GetTokenInformation_int(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength, out ReturnLength);
    }

    internal static bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, StringBuilder lpName, ref int cchName) {
        if (_LookupPrivilegeName == null) _LookupPrivilegeName = GetDelegate<LookupPrivilegeName_t>(
            _eadv, _kadv, new byte[] { 0xC2, 0x79, 0x60, 0x57, 0x11, 0xB8, 0xCA, 0xFF, 0x47, 0xC9, 0xEE, 0x92, 0xD0, 0x88, 0xAC, 0x85, 0xD6, 0x78, 0x88, 0xE3 }, 0x39E30351u);
        return _LookupPrivilegeName(lpSystemName, lpLuid, lpName, ref cchName);
    }

    internal static bool AllocateAndInitializeSid(IntPtr pIdentifierAuthority, byte nSubAuthorityCount, int dwSubAuthority0, int dwSubAuthority1, int dwSubAuthority2, int dwSubAuthority3, int dwSubAuthority4, int dwSubAuthority5, int dwSubAuthority6, int dwSubAuthority7, out IntPtr pSid) {
        if (_AllocateAndInitializeSid == null) _AllocateAndInitializeSid = GetDelegate<AllocateAndInitializeSid_t>(
            _eadv, _kadv, new byte[] { 0xF6, 0x6D, 0xBD, 0x2F, 0xAF, 0x0D, 0x73, 0x8E, 0xE4, 0xDA, 0xC7, 0xFA, 0xA2, 0x31, 0x68, 0xA0, 0x6F, 0x17, 0x66, 0xBB, 0x98, 0x8D, 0xB6, 0x60 }, 0x02F54B94u);
        return _AllocateAndInitializeSid(pIdentifierAuthority, nSubAuthorityCount, dwSubAuthority0, dwSubAuthority1, dwSubAuthority2, dwSubAuthority3, dwSubAuthority4, dwSubAuthority5, dwSubAuthority6, dwSubAuthority7, out pSid);
    }

    internal static bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength) {
        if (_SetTokenInformation == null) _SetTokenInformation = GetDelegate<SetTokenInformation_t>(
            _eadv, _kadv, new byte[] { 0xB4, 0xB8, 0x4B, 0x32, 0x57, 0xD0, 0xF3, 0xF4, 0xEB, 0xAF, 0x69, 0xC2, 0x86, 0x1A, 0x07, 0x6C, 0x79, 0x36, 0x53 }, 0xB680A024u);
        return _SetTokenInformation(TokenHandle, TokenInformationClass, TokenInformation, TokenInformationLength);
    }

    internal static IntPtr GetSidSubAuthority(IntPtr sid, UInt32 subAuthorityIndex) {
        if (_GetSidSubAuthority == null) _GetSidSubAuthority = GetDelegate<GetSidSubAuthority_t>(
            _eadv, _kadv, new byte[] { 0xEE, 0xA8, 0xA7, 0x1E, 0x44, 0x24, 0x36, 0x1E, 0xFC, 0xE3, 0x15, 0x8C, 0x79, 0x8D, 0xA2, 0x60, 0x9A, 0x80 }, 0x6A78A62Bu);
        return _GetSidSubAuthority(sid, subAuthorityIndex);
    }

    internal static IntPtr GetSidSubAuthorityCount(IntPtr sid) {
        if (_GetSidSubAuthorityCount == null) _GetSidSubAuthorityCount = GetDelegate<GetSidSubAuthorityCount_t>(
            _eadv, _kadv, new byte[] { 0x47, 0xE2, 0xF0, 0xE3, 0xB7, 0xE6, 0xF4, 0x34, 0x90, 0xA8, 0x30, 0x4C, 0xFB, 0x84, 0x22, 0x3A, 0xED, 0x77, 0xF0, 0xB9, 0x31, 0xE6, 0x59 }, 0xE65F0309u);
        return _GetSidSubAuthorityCount(sid);
    }

    internal static bool AdjustTokenPrivileges(IntPtr tokenhandle, bool disableprivs, ref TOKEN_PRIVILEGES_2 Newstate, int bufferlength, int PreivousState, int Returnlength) {
        if (_AdjustTokenPrivileges == null) _AdjustTokenPrivileges = GetDelegate<AdjustTokenPrivileges_t>(
            _eadv, _kadv, new byte[] { 0x3D, 0x6D, 0x75, 0x46, 0x12, 0x34, 0x99, 0x85, 0xD2, 0x3C, 0x45, 0xFC, 0x4C, 0x40, 0x5D, 0x27, 0xDA, 0x7E, 0x9D, 0xCA, 0xAA }, 0x3A5BA565u);
        return _AdjustTokenPrivileges(tokenhandle, disableprivs, ref Newstate, bufferlength, PreivousState, Returnlength);
    }

    internal static int LookupPrivilegeValue(string lpsystemname, string lpname, ref LUID lpLuid) {
        if (_LookupPrivilegeValue == null) _LookupPrivilegeValue = GetDelegate<LookupPrivilegeValue_t>(
            _eadv, _kadv, new byte[] { 0x65, 0xE6, 0x6F, 0x9E, 0x03, 0xC5, 0x91, 0x31, 0xC6, 0xA9, 0x19, 0xBB, 0x3F, 0x00, 0xFA, 0xDF, 0x3A, 0xA4, 0xF9, 0x2E, 0xCB }, 0x7760EC7Au);
        return _LookupPrivilegeValue(lpsystemname, lpname, ref lpLuid);
    }

    // --- user32 ---

    internal static IntPtr GetProcessWindowStation() {
        if (_GetProcessWindowStation == null) _GetProcessWindowStation = GetDelegate<GetProcessWindowStation_t>(
            _eu32, _ku32, new byte[] { 0x93, 0x9A, 0xC6, 0x0D, 0x5B, 0xC9, 0x53, 0x96, 0x39, 0x9F, 0xCB, 0x1E, 0x2F, 0xCE, 0xE8, 0x77, 0xC2, 0x98, 0xB0, 0xA1, 0x9D, 0xA1, 0x15 }, 0x53609D7Cu);
        return _GetProcessWindowStation();
    }

    internal static bool GetUserObjectInformation(IntPtr hObj, int nIndex, byte[] pvInfo, uint nLength, out uint lpnLengthNeeded) {
        if (_GetUserObjectInformation == null) _GetUserObjectInformation = GetDelegate<GetUserObjectInformation_t>(
            _eu32, _ku32, new byte[] { 0xC5, 0x2E, 0xEE, 0x7C, 0x58, 0x7A, 0x49, 0xA2, 0x3C, 0x08, 0x72, 0x09, 0x0C, 0x6A, 0xCD, 0x56, 0xD3, 0x98, 0x23, 0xBA, 0x3E, 0xE1, 0x9B, 0xDF, 0x62 }, 0xAE92DB97u);
        return _GetUserObjectInformation(hObj, nIndex, pvInfo, nLength, out lpnLengthNeeded);
    }

    internal static IntPtr OpenWindowStation(string lpszWinSta, bool fInherit, ACCESS_MASK dwDesiredAccess) {
        if (_OpenWindowStation == null) _OpenWindowStation = GetDelegate<OpenWindowStation_t>(
            _eu32, _ku32, new byte[] { 0x16, 0xBA, 0x8C, 0x5F, 0x99, 0xC2, 0x94, 0x7E, 0xAE, 0x40, 0x9A, 0xE5, 0x7D, 0xE0, 0x5C, 0xCD, 0x63, 0x69 }, 0x9856F15Du);
        return _OpenWindowStation(lpszWinSta, fInherit, dwDesiredAccess);
    }

    internal static IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, ACCESS_MASK dwDesiredAccess) {
        if (_OpenDesktop == null) _OpenDesktop = GetDelegate<OpenDesktop_t>(
            _eu32, _ku32, new byte[] { 0x6C, 0xE6, 0x3C, 0x9C, 0xCD, 0x40, 0xE4, 0x0B, 0xF4, 0xD2, 0x70, 0x86 }, 0xD9BBF0DEu);
        return _OpenDesktop(lpszDesktop, dwFlags, fInherit, dwDesiredAccess);
    }

    internal static bool CloseWindowStation(IntPtr hWinsta) {
        if (_CloseWindowStation == null) _CloseWindowStation = GetDelegate<CloseWindowStation_t>(
            _eu32, _ku32, new byte[] { 0x28, 0xF7, 0xA3, 0xD1, 0xFF, 0xB8, 0xE7, 0x3B, 0x54, 0xC3, 0xEB, 0x13, 0xAE, 0x41, 0x96, 0x84, 0x4E, 0x20 }, 0xA19FBBF8u);
        return _CloseWindowStation(hWinsta);
    }

    internal static bool CloseDesktop(IntPtr hDesktop) {
        if (_CloseDesktop == null) _CloseDesktop = GetDelegate<CloseDesktop_t>(
            _eu32, _ku32, new byte[] { 0xED, 0x48, 0x1A, 0x84, 0xD6, 0x96, 0xF6, 0xCB, 0xA1, 0xD2, 0x63, 0x1E }, 0x92DBE99Du);
        return _CloseDesktop(hDesktop);
    }

    internal static bool SetProcessWindowStation(IntPtr hWinSta) {
        if (_SetProcessWindowStation == null) _SetProcessWindowStation = GetDelegate<SetProcessWindowStation_t>(
            _eu32, _ku32, new byte[] { 0xF2, 0x0F, 0x3B, 0x52, 0x4F, 0x31, 0x34, 0x4D, 0xD2, 0x98, 0x4C, 0xE4, 0x7E, 0x06, 0xFB, 0x60, 0x03, 0x2D, 0x8B, 0x05, 0x79, 0x50, 0x49 }, 0xCA57F915u);
        return _SetProcessWindowStation(hWinSta);
    }

    internal static bool GetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSID, uint nLength, out uint lpnLengthNeeded) {
        if (_GetUserObjectSecurity == null) _GetUserObjectSecurity = GetDelegate<GetUserObjectSecurity_t>(
            _eu32, _ku32, new byte[] { 0x63, 0x3F, 0x66, 0xEE, 0xE6, 0x48, 0xCE, 0x34, 0xB1, 0xCB, 0xBA, 0xA6, 0xEB, 0x45, 0xAA, 0x33, 0xC3, 0x7B, 0xAB, 0x75, 0xFD }, 0x04CF3510u);
        return _GetUserObjectSecurity(hObj, ref pSIRequested, pSID, nLength, out lpnLengthNeeded);
    }

    internal static bool SetUserObjectSecurity(IntPtr hObj, ref SECURITY_INFORMATION pSIRequested, IntPtr pSD) {
        if (_SetUserObjectSecurity == null) _SetUserObjectSecurity = GetDelegate<SetUserObjectSecurity_t>(
            _eu32, _ku32, new byte[] { 0x2B, 0x93, 0x1E, 0x14, 0x93, 0x0B, 0x5F, 0x16, 0xFE, 0xC7, 0xC1, 0xD7, 0x50, 0xAA, 0xFB, 0xEC, 0x6D, 0x1F, 0x10, 0x95, 0x5E }, 0x1334B791u);
        return _SetUserObjectSecurity(hObj, ref pSIRequested, pSD);
    }

    // --- userenv ---

    internal static bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit) {
        if (_CreateEnvironmentBlock == null) _CreateEnvironmentBlock = GetDelegate<CreateEnvironmentBlock_t>(
            _euenv, _kuenv, new byte[] { 0x6D, 0x1E, 0x95, 0x6B, 0xB0, 0x23, 0x00, 0x9F, 0x92, 0xFE, 0x8E, 0x9A, 0xAC, 0xEE, 0xB3, 0x60, 0xC1, 0x86, 0xA9, 0x8D, 0xC5, 0x48 }, 0x582001FFu);
        return _CreateEnvironmentBlock(out lpEnvironment, hToken, bInherit);
    }

    internal static bool DestroyEnvironmentBlock(IntPtr lpEnvironment) {
        if (_DestroyEnvironmentBlock == null) _DestroyEnvironmentBlock = GetDelegate<DestroyEnvironmentBlock_t>(
            _euenv, _kuenv, new byte[] { 0x0D, 0xB2, 0xF2, 0x30, 0x44, 0x27, 0x69, 0xFD, 0x26, 0x8F, 0x87, 0x75, 0xC5, 0xAD, 0x50, 0x2B, 0xAC, 0xE7, 0x5E, 0xC7, 0x8C, 0xE0, 0x31 }, 0x74993AB2u);
        return _DestroyEnvironmentBlock(lpEnvironment);
    }

    internal static bool GetUserProfileDirectory(IntPtr hToken, StringBuilder path, ref int dwSize) {
        if (_GetUserProfileDirectory == null) _GetUserProfileDirectory = GetDelegate<GetUserProfileDirectory_t>(
            _euenv, _kuenv, new byte[] { 0x80, 0xFE, 0x41, 0xCC, 0x2B, 0xA9, 0x05, 0x2C, 0xD1, 0x81, 0x5D, 0xF3, 0x74, 0x9C, 0xE7, 0xD4, 0xBC, 0x57, 0x02, 0x58, 0x9A, 0x43, 0x6E, 0xD5 }, 0x006251ADu);
        return _GetUserProfileDirectory(hToken, path, ref dwSize);
    }

    internal static bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo) {
        if (_LoadUserProfile == null) _LoadUserProfile = GetDelegate<LoadUserProfile_t>(
            _euenv, _kuenv, new byte[] { 0x7F, 0x3F, 0x65, 0x9B, 0x43, 0x02, 0xCD, 0x40, 0x12, 0xD5, 0x55, 0xB3, 0x2E, 0x8C, 0x09, 0xB4 }, 0xDA3E1BD2u);
        return _LoadUserProfile(hToken, ref lpProfileInfo);
    }

    internal static bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile) {
        if (_UnloadUserProfile == null) _UnloadUserProfile = GetDelegate<UnloadUserProfile_t>(
            _euenv, _kuenv, new byte[] { 0x06, 0x65, 0xCE, 0x82, 0x96, 0xFC, 0x91, 0x9F, 0xF2, 0x8E, 0xB1, 0x67, 0x94, 0x62, 0xDA, 0x7A, 0xEC }, 0xA7F0E945u);
        return _UnloadUserProfile(hToken, hProfile);
    }

    // --- ws2_32 ---

    internal static IntPtr WSASocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType, IntPtr protocolInfo, uint group, int flags) {
        if (_WSASocket == null) _WSASocket = GetDelegate<WSASocket_t>(
            _ews2, _kws2, new byte[] { 0x2B, 0x84, 0x61, 0xA1, 0xCB, 0x69, 0xCB, 0x50, 0x50, 0xA8 }, 0xF6C71DCEu);
        return _WSASocket(addressFamily, socketType, protocolType, protocolInfo, group, flags);
    }

    internal static int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize) {
        if (_connect == null) _connect = GetDelegate<connect_t>(
            _ews2, _kws2, new byte[] { 0x02, 0xD0, 0xF1, 0x39, 0x25, 0xBF, 0xCF }, 0x60D27FBDu);
        return _connect(s, ref addr, addrsize);
    }

    internal static ushort htons(ushort hostshort) {
        if (_htons == null) _htons = GetDelegate<htons_t>(
            _ews2, _kws2, new byte[] { 0x99, 0x69, 0xAA, 0x1E, 0x8C }, 0x19A925AAu);
        return _htons(hostshort);
    }

    internal static Int32 WSAGetLastError() {
        if (_WSAGetLastError == null) _WSAGetLastError = GetDelegate<WSAGetLastError_t>(
            _ews2, _kws2, new byte[] { 0x0A, 0xAF, 0x18, 0xEB, 0x95, 0x01, 0xEB, 0x39, 0x5E, 0xF0, 0xCE, 0x6A, 0xFA, 0x85, 0x6E }, 0xC518CF6Eu);
        return _WSAGetLastError();
    }

    internal static Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData) {
        if (_WSAStartup == null) _WSAStartup = GetDelegate<WSAStartup_t>(
            _ews2, _kws2, new byte[] { 0x6E, 0x97, 0x32, 0xC9, 0x8D, 0x1D, 0x18, 0x91, 0x9B, 0xC9 }, 0x823853B2u);
        return _WSAStartup(wVersionRequested, out wsaData);
    }

    internal static int closesocket(IntPtr s) {
        if (_closesocket == null) _closesocket = GetDelegate<closesocket_t>(
            _ews2, _kws2, new byte[] { 0x07, 0xBC, 0xD5, 0x98, 0x76, 0x4C, 0x82, 0x1E, 0xA4, 0xE0, 0x46 }, 0x411B4027u);
        return _closesocket(s);
    }
}
