# Reports the impersonation level the bridge client grants the server it reaches.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# It creates a pipe owned by this account and listing no other, as a worker's pipe is, waits for one
# client, reads the first byte the client sends and then reads the client's token from the
# connection. The byte comes first: the platform reads a named-pipe client's context only once the
# server has read something the client sent. The level is read in compiled code, because while the
# thread holds an identification-only token PowerShell itself cannot load a command from disk.
#
# It reports into the status file: `ready` once the pipe exists, then `level=<level>`.

param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Status)

Set-Content -Path $Status -Value 'started'
$ErrorActionPreference = 'Stop'
try {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $list = [System.IO.Pipes.PipeSecurity]::new()
    $list.SetAccessRuleProtection($true, $false)
    $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
        $me, [System.IO.Pipes.PipeAccessRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($Name, 'InOut', 1, 'Byte',
        'Asynchronous', 0, 0, $list)
    Add-Content -Path $Status -Value 'ready'
    $server.WaitForConnection()
    [void]$server.ReadByte()
    Add-Type -TypeDefinition @'
using System.IO.Pipes;
using System.Security.Principal;
public static class KrClientLevel
{
    public static string Of(NamedPipeServerStream server)
    {
        string level = "unknown";
        server.RunAsClient(() => { level = WindowsIdentity.GetCurrent(true).ImpersonationLevel.ToString(); });
        return level;
    }
}
'@
    $level = [KrClientLevel]::Of($server)
    Add-Content -Path $Status -Value ('level=' + $level)
    $server.Dispose()
} catch {
    Add-Content -Path $Status -Value ('error=' + $_.Exception.Message)
}
