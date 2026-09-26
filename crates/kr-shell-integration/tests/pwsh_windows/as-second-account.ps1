# Holds a named pipe as a second local account, for the bridge client's account check.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# The endpoint namespace is shared by every account, so a pipe another account created first can sit
# at the name a worker exported. This script makes one: it creates the pipe under a real logon token
# of the second account, which its thread holds while it creates it, so the second account owns the
# pipe. The pipe's list admits this account too, so the bridge client can open it, and the client's
# own check is then the only thing between its hello and the other account.
#
# A console process started under another account from the non-interactive session the tests run
# in cannot reach that session's window station, so the second account's identity is carried the
# way a pipe sees it: the logon token, held by a thread while the pipe is created. The account's
# name and password come from this process's environment, which the machine's own test script set
# for this session, and are never written anywhere.
#
# It reports into the status file: `ready` once the pipe exists, then `received=<count>` with how
# many bytes the one client that connects sent before it left, or `received=none` when nothing came
# within ten seconds of the connection.

param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Status)

Set-Content -Path $Status -Value 'started'
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class KrSecondAccount
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUserW(string user, string domain, string password, int type,
        int provider, out IntPtr token);

    public static SafeAccessTokenHandle Network(string user, string password)
    {
        IntPtr token;
        // LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT: an impersonation token of the account.
        if (!LogonUserW(user, ".", password, 3, 0, out token))
        {
            throw new System.ComponentModel.Win32Exception();
        }
        return new SafeAccessTokenHandle(token);
    }
}
'@
    $token = [KrSecondAccount]::Network($env:KR_TEST_SECOND_USER, $env:KR_TEST_SECOND_PASS)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $list = [System.IO.Pipes.PipeSecurity]::new()
    $list.SetAccessRuleProtection($true, $false)
    $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
        $me, [System.IO.Pipes.PipeAccessRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
        [System.Security.Principal.SecurityIdentifier]::new('S-1-3-4'),
        [System.IO.Pipes.PipeAccessRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $server = [System.Security.Principal.WindowsIdentity]::RunImpersonated($token, [Func[object]]{
        [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($Name, 'InOut', 1, 'Byte',
            'Asynchronous', 0, 0, $list)
    })
    Add-Content -Path $Status -Value 'ready'
    $server.WaitForConnection()
    $buffer = New-Object byte[] 64
    $read = $server.ReadAsync($buffer, 0, 64)
    if ($read.Wait(10000)) { $count = $read.Result } else { $count = 'none' }
    Add-Content -Path $Status -Value ('received=' + $count)
    Start-Sleep -Seconds 5
    $server.Dispose()
} catch {
    Add-Content -Path $Status -Value ('error=' + $_.Exception.Message)
}
