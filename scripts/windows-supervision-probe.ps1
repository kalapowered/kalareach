# Windows supervision evidence: which creators leave a started process
# outside every job its requester is in, and what the Task Scheduler does with an on-demand
# per-user task.
#
#   -Mode Main     the Windows test machine, in a scheduled task with no job, as its administrator.
#   -Mode SignOut  the Windows test machine, once -Account exists and a remote desktop client has
#                  signed it in: that standard user registers and runs its own task in its own
#                  session, the session signs out, and the account, its group membership and its
#                  profile are removed.
#   -Mode Runner   a hosted continuous-integration runner (E8).
#
# It registers and deletes only tasks named KalaReachProbe-<run>-*, ends only processes it
# recorded (each checked by identifier and creation time first), and removes its own directory.
# -RemoveScript also removes this file, so the machine is left as it was found.
param(
  [ValidateSet('Main', 'SignOut', 'Runner')][string]$Mode = 'Main',
  [string]$Account = '',
  [string]$Root = 'C:\kala\bin\winsup',
  [int]$Hold = 600,
  [switch]$RemoveScript
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$run = 'kr' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$dir = Join-Path $Root $run
$out = Join-Path $dir 'results.txt'
$exe = Join-Path $dir 'krprobe.exe'
$schtasks = Join-Path $env:SystemRoot 'System32\schtasks.exe'
$tasks = [System.Collections.Generic.List[string]]::new()
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# To the host, never the pipeline: a function that says something and returns a value must return
# only the value.
function Say([string]$Line) { Write-Host ('== ' + $Line) }

function New-Start([string]$Arguments) {
  # A plain create, never Start-Process -Wait, which can put what it starts in a job of its own.
  $start = [System.Diagnostics.ProcessStartInfo]::new($exe, $Arguments)
  $start.UseShellExecute = $false
  $start.CreateNoWindow = $true
  $start
}

function Invoke-Probe([string]$Arguments, [int]$Seconds = 600) {
  $process = [System.Diagnostics.Process]::Start((New-Start $Arguments))
  if (-not $process.WaitForExit($Seconds * 1000)) {
    $process.Kill()
    throw "krprobe $Arguments did not finish in $Seconds s"
  }
  $process.ExitCode
}

function Invoke-Schtasks([string[]]$Arguments) {
  $said = & $schtasks @Arguments 2>&1 | Out-String
  'exit=' + $LASTEXITCODE + ' said=' + (($said -replace '\s+', ' ').Trim())
}

function Get-Lines { if (Test-Path -LiteralPath $out) { @(Get-Content -LiteralPath $out) } else { @() } }

function Wait-Line([string]$Prefix, [int]$Seconds) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    if (Get-Lines | Where-Object { $_.StartsWith($Prefix) }) { return $true }
    Start-Sleep -Milliseconds 300
  }
  $false
}

function Get-TaskXml([string]$User, [string]$Logon, [int]$Priority, [string]$Arguments) {
  $command = [System.Security.SecurityElement]::Escape($exe)
  $argumentText = [System.Security.SecurityElement]::Escape($Arguments)
  $directory = [System.Security.SecurityElement]::Escape($dir)
  @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<RegistrationInfo><Description>supervision evidence probe</Description></RegistrationInfo>
<Triggers />
<Principals><Principal id="Author"><UserId>$User</UserId><LogonType>$Logon</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
<Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable><RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings><AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>$Priority</Priority></Settings>
<Actions Context="Author"><Exec><Command>$command</Command><Arguments>$argumentText</Arguments><WorkingDirectory>$directory</WorkingDirectory></Exec></Actions>
</Task>
"@
}

# Registers one task for $User (this account unless given), naming it for the cleanup first.
function Register-Probe([string]$Case, [string]$Logon, [int]$Priority, [string]$Arguments, [string]$User = $sid) {
  $name = "KalaReachProbe-$run-$Case"
  $tasks.Add($name)
  $file = Join-Path $dir "$Case.xml"
  [System.IO.File]::WriteAllText($file, (Get-TaskXml $User $Logon $Priority $Arguments), [System.Text.Encoding]::Unicode)
  Say ("register $name logon=$Logon priority=$Priority " + (Invoke-Schtasks @('/Create', '/TN', $name, '/XML', $file, '/F')))
  $name
}

function Start-Probe([string]$Name) { Say ("run $Name " + (Invoke-Schtasks @('/Run', '/TN', $Name))) }

function Show-Query([string]$Name) { Say ("query $Name " + (Invoke-Schtasks @('/Query', '/TN', $Name, '/V', '/FO', 'CSV', '/NH'))) }

function Get-Record([string]$Prefix) { Get-Lines | Where-Object { $_.StartsWith($Prefix + ' ') } | Select-Object -First 1 }

function Test-Alive([string]$Line) {
  if (-not $Line) { return 'none' }
  $processId = if ($Line -match ' (?:child|pid)=(\d+)') { [int]$Matches[1] } else { 0 }
  $created = if ($Line -match ' created=(\d+)') { [long]$Matches[1] } else { 0 }
  if ($processId -eq 0) { return 'none' }
  $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
  if (-not $process) { return 'no' }
  try { if ($process.StartTime.ToFileTimeUtc() -ne $created) { return 'no(reused)' } } catch { return 'unknown' }
  'yes'
}

function Build-Probe {
  New-Item -ItemType Directory -Force -Path $dir, (Join-Path $dir 'out dir') | Out-Null
  $source = Join-Path $dir 'krprobe.cs'
  [System.IO.File]::WriteAllText($source, $probeSource, [System.Text.UTF8Encoding]::new($false))
  $csc = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
  ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
  if (-not $csc) { throw 'no .NET Framework csc.exe under Microsoft.NET' }
  $said = & $csc /nologo /target:winexe /platform:x64 /optimize+ /r:System.Management.dll "/out:$exe" $source 2>&1 | Out-String
  if ($LASTEXITCODE -ne 0) { throw "csc failed ($LASTEXITCODE): $said" }
  Say "probe built with $csc"
}

function Show-Context {
  Say ('os ' + [System.Environment]::OSVersion.VersionString + ' pwsh ' + $PSVersionTable.PSVersion + ' user ' + [System.Security.Principal.WindowsIdentity]::GetCurrent().Name + ' sid ' + $sid)
  $null = Invoke-Probe "report `"$out`" ctx KalaReachProbe-$run-credential"
  $null = Invoke-Probe "sessions `"$out`" session"
  $server = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
  $tcp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
  $service = Get-Service TermService -ErrorAction SilentlyContinue
  $listening = @(Get-NetTCPConnection -LocalPort 3389 -State Listen -ErrorAction SilentlyContinue).Count
  $rules = @(Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' }).Count
  $deny = if ($server) { $server.fDenyTSConnections } else { 'unread' }
  $nla = if ($tcp) { $tcp.UserAuthentication } else { 'unread' }
  $state = if ($service) { $service.Status } else { 'absent' }
  Say "remote desktop, read only: fDenyTSConnections=$deny nla=$nla service=$state listening3389=$listening enabled_inbound_rules=$rules"
}

# One requester in one set of jobs; its children, and the task's, looked at after the jobs close.
function Invoke-Nest([string]$Case, [string]$Outer, [string]$Inner, [int]$Borrow) {
  $task = Register-Probe $Case 'S4U' 5 "starter `"$out`" $Case.task $Hold"
  Say "nest $Case outer=$Outer inner=$Inner"
  $null = Invoke-Probe "nest `"$out`" $Case $Outer $Inner $task $Borrow - $Hold" 400
}

# After a task's starter has completed (so the child faced the task ending, not just the daemon):
# whether the starter's plain and breakaway children survived, and where each landed.
function Test-Survival([string]$Tag, [int]$Seconds = 90) {
  if (-not (Wait-Line "$Tag.self " $Seconds)) { Say ('' + $Tag + ': no starter within ' + $Seconds + ' s'); return }
  $self = Get-Record "$Tag.self"
  $selfPid = if ($self -match ' pid=(\d+)') { [int]$Matches[1] } else { 0 }
  # Wait for the starter to exit, i.e. the task to complete on its own.
  $deadline = (Get-Date).AddSeconds(60)
  while ($selfPid -gt 0 -and (Get-Process -Id $selfPid -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
  Start-Sleep -Seconds 3
  $flags = if ($self -match ' flags=(\S+)') { $Matches[1] } else { '?' }
  $session = if ($self -match ' session=(\S+)') { $Matches[1] } else { '?' }
  Say "$Tag.self task_job_flags=$flags session=$session starter_gone=$($selfPid -gt 0 -and -not (Get-Process -Id $selfPid -ErrorAction SilentlyContinue))"
  foreach ($kind in 'plain', 'brk') {
    $record = Get-Record "$Tag.$kind"
    if ($record) {
      $injob = if ($record -match ' injob=(\S+)') { $Matches[1] } else { '?' }
      $suspended = if ($record -match ' injob_suspended=(\S+)') { $Matches[1] } else { '?' }
      $child = if ($record -match ' child=(\d+)') { $Matches[1] } else { '0' }
      $childError = if ($record -match ' error=(\S+)') { $Matches[1] } else { '' }
      Say "$Tag.$kind child=$child injob_suspended=$suspended injob=$injob error=$childError survived_task_end=$(Test-Alive $record)"
    }
  }
}

function Invoke-Main {
  Show-Context
  $signedIn = @(Get-Lines | Where-Object { $_ -match '^session ' -and $_ -match ' state=(0|4) ' -and $_ -match ('user=' + [regex]::Escape($env:USERNAME) + '$') }).Count -gt 0

  Say "E1 the task's job, its plain and breakaway children, whether each survives the task's end; priority 5 and 7"
  Start-Probe (Register-Probe 's4u' 'S4U' 5 "starter `"$out`" s4u $Hold both nohold KalaReachProbe-$run-credential-s4u")
  Test-Survival 's4u'
  Start-Probe (Register-Probe 'p7' 'S4U' 7 "starter `"$out`" p7 $Hold both")
  Test-Survival 'p7'

  Say 'E4 three runs start three starters'
  $parallel = Register-Probe 'par' 'S4U' 5 "starter `"$out`" par $Hold"
  1..3 | ForEach-Object { Start-Probe $parallel }
  Start-Sleep -Seconds 20
  Say ('parallel starters: ' + @(Get-Lines | Where-Object { $_.StartsWith('par.self ') }).Count)

  Say 'E4 /End and /Delete while the starter is still running'
  $ended = Register-Probe 'end' 'S4U' 5 "starter `"$out`" end $Hold hold"
  Start-Probe $ended
  $null = Wait-Line 'end.child ' 60
  Say ('end ' + (Invoke-Schtasks @('/End', '/TN', $ended)))
  Start-Sleep -Seconds 5
  Say ('after /End: starter alive=' + (Test-Alive (Get-Record 'end.self')) + ' child alive=' + (Test-Alive (Get-Record 'end.child')))
  $deleted = Register-Probe 'del' 'S4U' 5 "starter `"$out`" del $Hold hold"
  Start-Probe $deleted
  $null = Wait-Line 'del.child ' 60
  Say ('delete-while-running ' + (Invoke-Schtasks @('/Delete', '/TN', $deleted, '/F')))
  Start-Sleep -Seconds 5
  Say ('after /Delete: starter alive=' + (Test-Alive (Get-Record 'del.self')) + ' child alive=' + (Test-Alive (Get-Record 'del.child')))

  Say "E7 a path with a space and a trailing backslash through the task's command line"
  $argvOut = Join-Path $dir 'out dir\argv.txt'
  Start-Probe (Register-Probe 'argv' 'S4U' 5 "argv `"$argvOut`" argv `"C:\a b\c\\`"")
  $deadline = (Get-Date).AddSeconds(45)
  while (-not (Test-Path -LiteralPath $argvOut) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
  $argvLine = if (Test-Path -LiteralPath $argvOut) { Get-Content -LiteralPath $argvOut | Select-Object -First 1 } else { 'argv none' }
  Say ('argv ' + $argvLine + ' whole=' + $argvLine.EndsWith('|C:\a b\c\]'))

  Say 'E6 an InteractiveToken run: its job, its children and their survival'
  if ($signedIn) {
    Say "skipped: this account already has a signed-in session here, which is not this run's to use; the signed-in case runs in -Mode SignOut as a temporary account"
  } else {
    $interactive = Register-Probe 'it' 'InteractiveToken' 5 "starter `"$out`" it $Hold both nohold KalaReachProbe-$run-credential-it"
    Start-Probe $interactive
    if (Wait-Line 'it.self ' 30) { Test-Survival 'it' } else { Say 'it: no InteractiveToken run within 30 s (no session for it)'; Show-Query $interactive }
  }

  Say 'E2, E3 a requester in each set of jobs, ended by closing them'
  # A process in no job, started here, for the borrowed-parent attribute to name.
  $borrow = [System.Diagnostics.Process]::Start((New-Start "sleep $Hold"))
  Add-Content -LiteralPath $out -Value ('borrow child=' + $borrow.Id + ' created=' + $borrow.StartTime.ToFileTimeUtc())
  Invoke-Nest 'n0' 'none' 'none' $borrow.Id
  Invoke-Nest 'n2' '0x2000' 'none' $borrow.Id
  Invoke-Nest 'n1' '0x2000' '0x800' $borrow.Id
  Invoke-Nest 'n3' '0x2800' '0x800' $borrow.Id
}

function Invoke-Runner {
  Show-Context
  Say "E8 the runner: an S4U and an InteractiveToken task, each task's job, its children and their survival, and the forbidding-ancestor nesting"
  Start-Probe (Register-Probe 's4u' 'S4U' 5 "starter `"$out`" s4u $Hold both nohold KalaReachProbe-$run-credential-s4u")
  Test-Survival 's4u'
  $interactive = Register-Probe 'it' 'InteractiveToken' 5 "starter `"$out`" it $Hold both nohold KalaReachProbe-$run-credential-it"
  Start-Probe $interactive
  if (Wait-Line 'it.self ' 30) { Test-Survival 'it' } else { Say 'it: no InteractiveToken run within 30 s'; Show-Query $interactive }
  Invoke-Nest 'n1' '0x2000' '0x800' 0
}

function Get-AccountSession {
  # The probe reads the sessions through the terminal-services API; without it, quser's table.
  if (Test-Path -LiteralPath $exe) {
    Remove-Item -LiteralPath (Join-Path $dir 'sessions.txt') -ErrorAction SilentlyContinue
    $null = Invoke-Probe "sessions `"$(Join-Path $dir 'sessions.txt')`" now" 60
    $line = @(Get-Content -LiteralPath (Join-Path $dir 'sessions.txt') -ErrorAction SilentlyContinue | Where-Object { $_ -match ('user=' + [regex]::Escape($Account) + '$') }) | Select-Object -First 1
    if ($line -and $line -match ' id=(\d+) ') { return [int]$Matches[1] }
    return -1
  }
  $row = @(& quser 2>$null | Where-Object { $_ -match ('^\s*>?' + [regex]::Escape($Account) + '\s') }) | Select-Object -First 1
  if ($row -and $row -match '\s(\d+)\s+(Active|Disc)') { [int]$Matches[1] } else { -1 }
}

function Invoke-SignOut {
  $user = Get-LocalUser -Name $Account
  $accountSid = $user.SID.Value
  Say ("account $Account sid $accountSid enabled " + $user.Enabled)
  Show-Context
  $sessionId = Get-AccountSession
  if ($sessionId -lt 0) { throw "$Account has no session here: the remote desktop sign-in did not happen" }
  Say "session of ${Account}: $sessionId"
  # The standard account writes its results and its own task definitions here, and nowhere else.
  & icacls $dir /grant "*${accountSid}:(OI)(CI)M" | Out-Null
  Say 'a standard user registers and runs its own task in its own session'
  $starter = Register-Probe 'stdu' 'InteractiveToken' 5 "stduser `"$out`" $run $Hold" $accountSid
  $tasks.Add("KalaReachProbe-$run-own-InteractiveToken")
  $tasks.Add("KalaReachProbe-$run-own-S4U")
  Start-Probe $starter
  Say ('standard user finished within 180 s: ' + (Wait-Line 'stdu.done' 180))
  Say "sign-out of session $sessionId"
  & logoff $sessionId 2>&1 | ForEach-Object { Say "logoff: $_" }
  $deadline = (Get-Date).AddSeconds(60)
  do { Start-Sleep -Seconds 2; $left = Get-AccountSession } while ($left -ge 0 -and (Get-Date) -lt $deadline)
  Say ("session $sessionId gone: " + ($left -lt 0))
  Start-Sleep -Seconds 3
  foreach ($prefix in 'stdu.self', 'stdu.own.self', 'stdu.own.child', 'stdu.s4u.self', 'stdu.s4u.child') {
    Say ("after sign-out $prefix alive=" + (Test-Alive (Get-Record $prefix)))
  }
}

# However the sign-out run ended: its session signed out, then the account, its group membership
# and its profile removed, each shown gone.
function Remove-Account {
  $user = Get-LocalUser -Name $Account -ErrorAction SilentlyContinue
  if (-not $user) { Say "account $Account not present"; return }
  $accountSid = $user.SID.Value
  $sessionId = Get-AccountSession
  if ($sessionId -ge 0) {
    Say "signing out the remaining session $sessionId"
    & logoff $sessionId 2>&1 | ForEach-Object { Say "logoff: $_" }
    $deadline = (Get-Date).AddSeconds(60)
    do { Start-Sleep -Seconds 2 } while ((Get-AccountSession) -ge 0 -and (Get-Date) -lt $deadline)
  }
  foreach ($group in Get-LocalGroup) {
    if (Get-LocalGroupMember -Group $group -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $user.SID }) {
      Remove-LocalGroupMember -Group $group -Member $user.SID
      Say ('left group ' + $group.SID.Value)
    }
  }
  Remove-LocalUser -SID $user.SID
  foreach ($profile in @(Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $accountSid })) {
    Say ('removing profile ' + $profile.LocalPath)
    Remove-CimInstance -InputObject $profile
  }
  Say ('account present: ' + [bool](Get-LocalUser -SID $user.SID -ErrorAction SilentlyContinue))
  Say ('profile present: ' + [bool](Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $accountSid }))
}

function Invoke-Cleanup {
  Say 'cleanup'
  # Each step is attempted whatever the one before did: a failure is reported, never allowed to
  # leave a task, a process or the account behind.
  foreach ($name in $tasks) {
    try { Say ("delete $name " + (Invoke-Schtasks @('/Delete', '/TN', $name, '/F'))) } catch { Say ("delete $name failed: " + $_.Exception.Message) }
  }
  try { if (Test-Path -LiteralPath $exe) { $null = Invoke-Probe "reap `"$out`"" 120 } } catch { Say ('reap failed: ' + $_.Exception.Message) }
  Start-Sleep -Seconds 2
  if ($Mode -eq 'SignOut' -and $Account) {
    try { Remove-Account } catch { Say ('account removal failed: ' + $_.Exception.Message) }
  }
  Say 'results:'
  Get-Lines | ForEach-Object { Write-Output $_ }
  Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
  if ($RemoveScript -and $PSCommandPath) { Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue }
  Say 'clean state:'
  Say ('probe tasks left: ' + @(& $schtasks /Query /FO CSV /NH 2>$null | Select-String 'KalaReachProbe-').Count)
  Say ('probe processes left: ' + @(Get-Process -Name krprobe -ErrorAction SilentlyContinue).Count)
  Say ('work directory present: ' + (Test-Path -LiteralPath $dir))
  if ($RemoveScript) { Say ('script present: ' + (Test-Path -LiteralPath $PSCommandPath)) }
  if (Test-Path -LiteralPath $Root) { Say ("entries left under ${Root}: " + @(Get-ChildItem -LiteralPath $Root -Force -ErrorAction SilentlyContinue).Count) }
}

$probeSource = @'
// krprobe: one small program that plays each process in the Windows supervision evidence.
//
// Every mode appends one-line records to a results file ("<tag> key=value ..."), which the driver
// script reads. Built with the .NET Framework's csc.exe as a Windows-subsystem program, so no
// console window appears in any session it runs in. C# 5: the compiler on every Windows machine.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;

public static class KrProbe
{
    const uint DETACHED_PROCESS = 0x00000008;
    const uint CREATE_SUSPENDED = 0x00000004;
    const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
    const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    const uint PROCESS_TERMINATE = 0x0001;
    const uint PROCESS_CREATE_PROCESS = 0x0080;
    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint SYNCHRONIZE = 0x00100000;
    const uint TOKEN_QUERY = 0x0008;
    const int JobObjectExtendedLimitInformation = 9;
    const int TokenElevation = 20;
    const int TokenStatistics = 10;
    const uint STILL_ACTIVE = 259;
    const int CRED_TYPE_GENERIC = 1;
    const int CRED_PERSIST_LOCAL_MACHINE = 2;
    static readonly IntPtr PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = new IntPtr(0x00020000);

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION Basic;
        public IO_COUNTERS Io;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_LOGON_SESSION_DATA
    {
        public uint Size;
        public LUID LogonId;
        public LSA_UNICODE_STRING UserName;
        public LSA_UNICODE_STRING LogonDomain;
        public LSA_UNICODE_STRING AuthenticationPackage;
        public uint LogonType;
        public uint Session;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        public string TargetName;
        public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WTS_SESSION_INFO
    {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }

    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int length, IntPtr returnLength);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int length);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint GetPriorityClass(IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool ProcessIdToSessionId(uint pid, out uint session);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION information);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CredEnumerateW(string filter, int flags, out int count, out IntPtr credentials);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CredWriteW(ref CREDENTIAL credential, int flags);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CredDeleteW(string target, int type, int flags);
    [DllImport("advapi32.dll")] static extern void CredFree(IntPtr buffer);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr information, int length, out int returned);
    [DllImport("secur32.dll")] static extern int LsaGetLogonSessionData(IntPtr logonId, out IntPtr data);
    [DllImport("secur32.dll")] static extern int LsaFreeReturnBuffer(IntPtr buffer);
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", SetLastError = true)] static extern bool WTSQuerySessionInformationW(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr memory);

    static string Out;
    static string Exe;

    // --- The results file -------------------------------------------------------------------

    static void Write(string line)
    {
        byte[] bytes = new UTF8Encoding(false).GetBytes(line + "\n");
        for (int attempt = 0; attempt < 400; attempt++)
        {
            try
            {
                using (FileStream stream = new FileStream(Out, FileMode.Append, FileAccess.Write, FileShare.Read))
                {
                    stream.Write(bytes, 0, bytes.Length);
                }
                return;
            }
            catch (IOException)
            {
                Thread.Sleep(25);
            }
        }
    }

    static List<string> Lines()
    {
        for (int attempt = 0; attempt < 400; attempt++)
        {
            try
            {
                List<string> lines = new List<string>();
                using (FileStream stream = new FileStream(Out, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        lines.Add(line);
                    }
                }
                return lines;
            }
            catch (FileNotFoundException)
            {
                return new List<string>();
            }
            catch (IOException)
            {
                Thread.Sleep(25);
            }
        }
        return new List<string>();
    }

    static bool WaitFor(string prefix, int seconds)
    {
        DateTime deadline = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < deadline)
        {
            foreach (string line in Lines())
            {
                if (line.StartsWith(prefix, StringComparison.Ordinal))
                {
                    return true;
                }
            }
            Thread.Sleep(200);
        }
        return false;
    }

    static string Field(string line, string key)
    {
        foreach (string part in line.Split(' '))
        {
            if (part.StartsWith(key + "=", StringComparison.Ordinal))
            {
                return part.Substring(key.Length + 1);
            }
        }
        return null;
    }

    static string Flat(string text)
    {
        return (text ?? "").Trim().Replace("\r", "").Replace("\n", "/").Replace(' ', '_');
    }

    // --- What the kernel says about a process ------------------------------------------------

    static long Created(IntPtr process)
    {
        long creation, exit, kernel, user;
        return GetProcessTimes(process, out creation, out exit, out kernel, out user) ? creation : 0;
    }

    static string InJob(IntPtr process)
    {
        bool result;
        if (!IsProcessInJob(process, IntPtr.Zero, out result))
        {
            return "error" + Marshal.GetLastWin32Error();
        }
        return result ? "yes" : "no";
    }

    static string OwnJobFlags()
    {
        bool inJob;
        if (!IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob))
        {
            return "error" + Marshal.GetLastWin32Error();
        }
        if (!inJob)
        {
            return "none";
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information;
        if (!QueryInformationJobObject(IntPtr.Zero, JobObjectExtendedLimitInformation, out information, Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)), IntPtr.Zero))
        {
            return "error" + Marshal.GetLastWin32Error();
        }
        return "0x" + information.Basic.LimitFlags.ToString("x");
    }

    static uint SessionOf(uint pid)
    {
        uint session;
        return ProcessIdToSessionId(pid, out session) ? session : uint.MaxValue;
    }

    static string TokenFacts()
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, out token))
        {
            return "logon=error" + Marshal.GetLastWin32Error();
        }
        IntPtr buffer = Marshal.AllocHGlobal(256);
        try
        {
            string elevated = "unknown";
            int returned;
            if (GetTokenInformation(token, TokenElevation, buffer, 4, out returned))
            {
                elevated = Marshal.ReadInt32(buffer) != 0 ? "yes" : "no";
            }
            string logon = "unknown";
            if (GetTokenInformation(token, TokenStatistics, buffer, 256, out returned))
            {
                IntPtr data;
                int status = LsaGetLogonSessionData(IntPtr.Add(buffer, 8), out data);
                if (status == 0)
                {
                    SECURITY_LOGON_SESSION_DATA session = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(data, typeof(SECURITY_LOGON_SESSION_DATA));
                    logon = session.LogonType.ToString();
                    LsaFreeReturnBuffer(data);
                }
                else
                {
                    logon = "nt0x" + status.ToString("x");
                }
            }
            return "logon=" + logon + " elevated=" + elevated;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            CloseHandle(token);
        }
    }

    // What this logon's credential store gives: a read, then a first write and its removal.
    static string CredentialStore(string target)
    {
        string read;
        int count;
        IntPtr list;
        if (CredEnumerateW(null, 0, out count, out list))
        {
            CredFree(list);
            read = "ok" + count;
        }
        else
        {
            read = "error" + Marshal.GetLastWin32Error();
        }
        byte[] secret = Encoding.Unicode.GetBytes("probe");
        IntPtr blob = Marshal.AllocHGlobal(secret.Length);
        string write;
        try
        {
            Marshal.Copy(secret, 0, blob, secret.Length);
            CREDENTIAL credential = new CREDENTIAL();
            credential.Type = CRED_TYPE_GENERIC;
            credential.TargetName = target;
            credential.CredentialBlobSize = secret.Length;
            credential.CredentialBlob = blob;
            credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
            credential.UserName = "probe";
            if (CredWriteW(ref credential, 0))
            {
                write = CredDeleteW(target, CRED_TYPE_GENERIC, 0) ? "ok" : "ok-undeleted" + Marshal.GetLastWin32Error();
            }
            else
            {
                write = "error" + Marshal.GetLastWin32Error();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
        }
        return "cred_read=" + read + " cred_write=" + write;
    }

    static void Report(string tag, string credentialTarget)
    {
        IntPtr self = GetCurrentProcess();
        uint pid = (uint)Process.GetCurrentProcess().Id;
        string line = tag + " pid=" + pid + " created=" + Created(self) + " injob=" + InJob(self) +
            " flags=" + OwnJobFlags() + " session=" + SessionOf(pid) + " prio=0x" + GetPriorityClass(self).ToString("x") +
            " " + TokenFacts() + " user=" + Flat(Environment.UserDomainName + "\\" + Environment.UserName);
        if (credentialTarget != null)
        {
            line += " " + CredentialStore(credentialTarget);
        }
        Write(line);
    }

    // --- Starting processes -------------------------------------------------------------------

    static PROCESS_INFORMATION Create(string arguments, uint flags, IntPtr parent, out int error)
    {
        STARTUPINFOEX startup = new STARTUPINFOEX();
        IntPtr list = IntPtr.Zero;
        IntPtr parentBox = IntPtr.Zero;
        try
        {
            if (parent != IntPtr.Zero)
            {
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
                list = Marshal.AllocHGlobal(size);
                if (!InitializeProcThreadAttributeList(list, 1, 0, ref size))
                {
                    error = Marshal.GetLastWin32Error();
                    Marshal.FreeHGlobal(list);
                    list = IntPtr.Zero;
                    return new PROCESS_INFORMATION();
                }
                parentBox = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(parentBox, parent);
                if (!UpdateProcThreadAttribute(list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, parentBox, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero))
                {
                    error = Marshal.GetLastWin32Error();
                    return new PROCESS_INFORMATION();
                }
                startup.lpAttributeList = list;
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                flags |= EXTENDED_STARTUPINFO_PRESENT;
            }
            else
            {
                startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            }
            StringBuilder commandLine = new StringBuilder("\"" + Exe + "\" " + arguments);
            PROCESS_INFORMATION information;
            bool created = CreateProcessW(Exe, commandLine, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, Path.GetDirectoryName(Exe), ref startup, out information);
            error = created ? 0 : Marshal.GetLastWin32Error();
            return information;
        }
        finally
        {
            if (list != IntPtr.Zero)
            {
                DeleteProcThreadAttributeList(list);
                Marshal.FreeHGlobal(list);
            }
            if (parentBox != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(parentBox);
            }
        }
    }

    // Starts `sleep <hold>` and records it. `mode` is plain, breakaway, suspended and
    // suspended-breakaway (created suspended, checked, then resumed: the starter's create, without
    // or with a request to leave the task's job) or parent:<pid> (the borrowed-parent attribute).
    static void Spawn(string tag, string mode, string hold)
    {
        uint flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT;
        IntPtr parent = IntPtr.Zero;
        bool suspended = mode == "suspended" || mode == "suspended-breakaway";
        if (mode == "breakaway" || mode == "suspended-breakaway")
        {
            flags |= CREATE_BREAKAWAY_FROM_JOB;
        }
        if (suspended)
        {
            flags |= CREATE_SUSPENDED;
        }
        if (mode.StartsWith("parent:", StringComparison.Ordinal))
        {
            uint borrowed = uint.Parse(mode.Substring(7));
            parent = OpenProcess(PROCESS_CREATE_PROCESS | PROCESS_QUERY_LIMITED_INFORMATION, false, borrowed);
            if (parent == IntPtr.Zero)
            {
                Write(tag + " child=0 error=open" + Marshal.GetLastWin32Error());
                return;
            }
        }
        int error;
        PROCESS_INFORMATION information = Create("sleep " + hold, flags, parent, out error);
        if (parent != IntPtr.Zero)
        {
            CloseHandle(parent);
        }
        if (error != 0)
        {
            Write(tag + " child=0 error=" + error);
            return;
        }
        // The evidence observes where the child landed; it does not judge it. So a suspended child
        // is checked from its handle, then resumed and left to be watched, in every job state. The
        // product's own decision (terminate a child a kill-on-close job would take) is a matter for
        // the supervisor's code, not for what the measurements are allowed to see.
        string before = "";
        if (suspended)
        {
            before = " injob_suspended=" + InJob(information.hProcess);
            ResumeThread(information.hThread);
        }
        Write(tag + " child=" + information.dwProcessId + " created=" + Created(information.hProcess) + before +
            " injob=" + InJob(information.hProcess) + " session=" + SessionOf(information.dwProcessId) +
            " prio=0x" + GetPriorityClass(information.hProcess).ToString("x"));
        CloseHandle(information.hThread);
        CloseHandle(information.hProcess);
    }

    static void Wmi(string tag, string hold)
    {
        try
        {
            using (ManagementClass processes = new ManagementClass(@"root\cimv2", "Win32_Process", null))
            {
                ManagementBaseObject input = processes.GetMethodParameters("Create");
                input["CommandLine"] = "\"" + Exe + "\" sleep " + hold;
                input["CurrentDirectory"] = Path.GetDirectoryName(Exe);
                ManagementBaseObject output = processes.InvokeMethod("Create", input, null);
                uint answer = (uint)output["ReturnValue"];
                if (answer != 0)
                {
                    Write(tag + " child=0 error=wmi" + answer);
                    return;
                }
                uint pid = (uint)output["ProcessId"];
                IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                if (handle == IntPtr.Zero)
                {
                    Write(tag + " child=" + pid + " created=0 error=open" + Marshal.GetLastWin32Error());
                    return;
                }
                Write(tag + " child=" + pid + " created=" + Created(handle) + " injob=" + InJob(handle) + " session=" + SessionOf(pid));
                CloseHandle(handle);
            }
        }
        catch (Exception failure)
        {
            Write(tag + " child=0 error=" + failure.GetType().Name + ":" + Flat(failure.Message));
        }
    }

    static string Schtasks(string arguments)
    {
        ProcessStartInfo start = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"), arguments);
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        using (Process process = Process.Start(start))
        {
            string said = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit(60000);
            return "exit=" + process.ExitCode + " said=" + Flat(said);
        }
    }

    // --- Modes --------------------------------------------------------------------------------

    // The process a daemon would be: inside the jobs the harness put it in, it starts one child
    // each way, and asks the Task Scheduler to start a starter.
    static void Daemon(string name, string task, string borrow, string interactiveTask, string hold)
    {
        Report(name + ".daemon", null);
        Spawn(name + ".breakaway", "breakaway", hold);
        Spawn(name + ".plain", "plain", hold);
        if (borrow != "0")
        {
            Spawn(name + ".parent", "parent:" + borrow, hold);
        }
        Wmi(name + ".wmi", hold);
        if (task != "-")
        {
            Write(name + ".run " + Schtasks("/Run /TN \"" + task + "\""));
            if (!WaitFor(name + ".task.child ", 90))
            {
                Write(name + ".task.child child=0 error=no-starter-in-90s");
            }
        }
        if (interactiveTask != "-")
        {
            Write(name + ".itrun " + Schtasks("/Run /TN \"" + interactiveTask + "\""));
            if (!WaitFor(name + ".it.child ", 45))
            {
                Write(name + ".it.child child=0 error=no-starter-in-45s");
            }
        }
        Write(name + ".ready");
        Thread.Sleep(int.Parse(hold) * 1000);
    }

    static IntPtr NewJob(string flags)
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new InvalidOperationException("CreateJobObject " + Marshal.GetLastWin32Error());
        }
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.Basic.LimitFlags = Convert.ToUInt32(flags, 16);
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref information, Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
        {
            throw new InvalidOperationException("SetInformationJobObject " + Marshal.GetLastWin32Error());
        }
        return job;
    }

    // The requester's jobs: `outer` (and `inner` nested in it) hold the daemon; closing the handles
    // ends it, or, with no job, it is ended directly. Then every child it recorded is looked at.
    static void Nest(string name, string outerFlags, string innerFlags, string task, string borrow, string interactiveTask, string hold)
    {
        IntPtr outer = outerFlags == "none" ? IntPtr.Zero : NewJob(outerFlags);
        IntPtr inner = innerFlags == "none" ? IntPtr.Zero : NewJob(innerFlags);
        string arguments = "daemon \"" + Out + "\" " + name + " " + task + " " + borrow + " " + interactiveTask + " " + hold;
        int error;
        PROCESS_INFORMATION daemon = Create(arguments, CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT, IntPtr.Zero, out error);
        if (error != 0)
        {
            Write(name + ".nest error=create" + error);
            return;
        }
        if (outer != IntPtr.Zero && !AssignProcessToJobObject(outer, daemon.hProcess))
        {
            Write(name + ".nest error=assign-outer" + Marshal.GetLastWin32Error());
        }
        if (inner != IntPtr.Zero && !AssignProcessToJobObject(inner, daemon.hProcess))
        {
            Write(name + ".nest error=assign-inner" + Marshal.GetLastWin32Error());
        }
        ResumeThread(daemon.hThread);
        bool ready = WaitFor(name + ".ready", 240);
        Write(name + ".nest ready=" + (ready ? "yes" : "no") + " daemon=" + daemon.dwProcessId + " outer=" + outerFlags + " inner=" + innerFlags);
        if (inner != IntPtr.Zero)
        {
            CloseHandle(inner);
        }
        if (outer != IntPtr.Zero)
        {
            CloseHandle(outer);
        }
        if (outer == IntPtr.Zero && inner == IntPtr.Zero)
        {
            TerminateProcess(daemon.hProcess, 1);
        }
        uint waited = WaitForSingleObject(daemon.hProcess, 20000);
        Write(name + ".nest daemon_ended=" + (waited == 0 ? "yes" : "no"));
        CloseHandle(daemon.hThread);
        CloseHandle(daemon.hProcess);
        Thread.Sleep(3000);
        foreach (string line in Lines())
        {
            if (!line.StartsWith(name + ".", StringComparison.Ordinal))
            {
                continue;
            }
            string child = Field(line, "child");
            string created = Field(line, "created");
            if (child == null || child == "0" || created == null)
            {
                continue;
            }
            string what = line.Substring(0, line.IndexOf(' '));
            Write(name + ".after " + what + " pid=" + child + " alive=" + Alive(uint.Parse(child), long.Parse(created)));
        }
    }

    static string Alive(uint pid, long created)
    {
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
        {
            return "no";
        }
        try
        {
            if (Created(handle) != created)
            {
                return "no(reused)";
            }
            uint code;
            if (!GetExitCodeProcess(handle, out code))
            {
                return "unknown" + Marshal.GetLastWin32Error();
            }
            return code == STILL_ACTIVE ? "yes" : "no";
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // Ends every process this run recorded that is still the process recorded, by identifier and
    // creation time, and nothing else.
    static void Reap()
    {
        HashSet<string> seen = new HashSet<string>();
        foreach (string line in Lines())
        {
            string pid = Field(line, "child") ?? Field(line, "pid");
            string created = Field(line, "created");
            if (pid == null || pid == "0" || created == null || created == "0" || !seen.Add(pid + "/" + created))
            {
                continue;
            }
            uint id = uint.Parse(pid);
            if (id == (uint)Process.GetCurrentProcess().Id)
            {
                continue;
            }
            IntPtr handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, id);
            if (handle == IntPtr.Zero)
            {
                continue;
            }
            uint code;
            if (Created(handle) == long.Parse(created) && GetExitCodeProcess(handle, out code) && code == STILL_ACTIVE)
            {
                Write("reap pid=" + pid + " ended=" + (TerminateProcess(handle, 1) ? "yes" : "error" + Marshal.GetLastWin32Error()));
            }
            CloseHandle(handle);
        }
    }

    // Every session on this machine: its number, state and user.
    static void Sessions(string tag)
    {
        IntPtr sessions;
        int count;
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out sessions, out count))
        {
            Write(tag + " error=" + Marshal.GetLastWin32Error());
            return;
        }
        int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
        for (int index = 0; index < count; index++)
        {
            WTS_SESSION_INFO session = (WTS_SESSION_INFO)Marshal.PtrToStructure(IntPtr.Add(sessions, index * size), typeof(WTS_SESSION_INFO));
            IntPtr buffer;
            int bytes;
            string user = "";
            // 5 is WTSUserName.
            if (WTSQuerySessionInformationW(IntPtr.Zero, session.SessionId, 5, out buffer, out bytes))
            {
                user = Marshal.PtrToStringUni(buffer);
                WTSFreeMemory(buffer);
            }
            Write(tag + " id=" + session.SessionId + " state=" + session.State + " station=" + Flat(Marshal.PtrToStringUni(session.pWinStationName)) + " user=" + Flat(user));
        }
        WTSFreeMemory(sessions);
    }

    // Run as a standard user inside that user's own signed-in session: it registers its own
    // task, as the product's setup step would, with no elevation and no password, and runs it.
    static void StandardUser(string run, string hold)
    {
        Report("stdu.self", "KalaReachProbe-" + run + "-credential");
        string sid = WindowsIdentity.GetCurrent().User.Value;
        string directory = Path.GetDirectoryName(Out);
        foreach (string logon in new string[] { "InteractiveToken", "S4U" })
        {
            string task = "KalaReachProbe-" + run + "-own-" + logon;
            string tag = logon == "S4U" ? "stdu.s4u" : "stdu.own";
            string xml = TaskXml(sid, logon, 5, "starter \"" + Out + "\" " + tag + " " + hold, directory);
            string file = Path.Combine(directory, task + ".xml");
            File.WriteAllText(file, xml, Encoding.Unicode);
            Write(tag + ".register " + Schtasks("/Create /TN \"" + task + "\" /XML \"" + file + "\" /F"));
            Write(tag + ".runresult " + Schtasks("/Run /TN \"" + task + "\""));
            if (!WaitFor(tag + ".child ", 45))
            {
                Write(tag + ".child child=0 error=no-starter-in-45s");
                Write(tag + ".query " + Schtasks("/Query /TN \"" + task + "\" /V /FO CSV /NH"));
            }
        }
        Write("stdu.done");
    }

    static string TaskXml(string sid, string logon, int priority, string arguments, string directory)
    {
        return "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n" +
            "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n" +
            "<RegistrationInfo><Description>supervision evidence probe</Description></RegistrationInfo>\r\n" +
            "<Triggers />\r\n" +
            "<Principals><Principal id=\"Author\"><UserId>" + sid + "</UserId><LogonType>" + logon + "</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\r\n" +
            "<Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" +
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable>" +
            "<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable><IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>" +
            "<AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden><RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>" +
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>" + priority + "</Priority></Settings>\r\n" +
            "<Actions Context=\"Author\"><Exec><Command>" + System.Security.SecurityElement.Escape(Exe) + "</Command>" +
            "<Arguments>" + System.Security.SecurityElement.Escape(arguments) + "</Arguments>" +
            "<WorkingDirectory>" + System.Security.SecurityElement.Escape(directory) + "</WorkingDirectory></Exec></Actions>\r\n" +
            "</Task>\r\n";
    }

    public static int Main(string[] args)
    {
        Exe = Process.GetCurrentProcess().MainModule.FileName;
        try
        {
            string mode = args[0];
            if (mode == "sleep")
            {
                Thread.Sleep(int.Parse(args[1]) * 1000);
                return 0;
            }
            Out = args[1];
            switch (mode)
            {
                case "report":
                    Report(args[2], args.Length > 3 ? args[3] : null);
                    return 0;
                case "starter":
                    // What the product's starter does, and the evidence its behaviour needs: a
                    // report of itself (its own job, the one the Task Scheduler put it in), then a
                    // child created suspended and checked each way. "plain" takes no breakaway;
                    // "breakaway" asks to leave the task's job; "both" does each; "hold" keeps the
                    // starter alive to be ended rather than letting it complete.
                    string childMode = args.Length > 4 ? args[4] : "both";
                    bool holdStarter = childMode == "hold" || (args.Length > 5 && args[5] == "hold");
                    Report(args[2] + ".self", args.Length > 6 ? args[6] : null);
                    if (childMode == "plain" || childMode == "both" || childMode == "hold")
                    {
                        Spawn(args[2] + ".plain", "suspended", args[3]);
                    }
                    if (childMode == "breakaway" || childMode == "both")
                    {
                        Spawn(args[2] + ".brk", "suspended-breakaway", args[3]);
                    }
                    if (holdStarter)
                    {
                        Thread.Sleep(int.Parse(args[3]) * 1000);
                    }
                    return 0;
                case "daemon":
                    Daemon(args[2], args[3], args[4], args[5], args[6]);
                    return 0;
                case "nest":
                    Nest(args[2], args[3], args[4], args[5], args[6], args[7], args[8]);
                    return 0;
                case "reap":
                    Reap();
                    return 0;
                case "sessions":
                    Sessions(args[2]);
                    return 0;
                case "argv":
                    Write(args[2] + " argv=[" + string.Join("|", args) + "]");
                    return 0;
                case "stduser":
                    StandardUser(args[2], args[3]);
                    return 0;
                case "taskxml":
                    // The definition the driver registers: the same text the standard user writes.
                    File.WriteAllText(args[2], TaskXml(args[3], args[4], int.Parse(args[5]), args[6], args[7]), Encoding.Unicode);
                    return 0;
            }
            return 2;
        }
        catch (Exception failure)
        {
            try
            {
                Write("error mode=" + (args.Length > 0 ? args[0] : "none") + " " + Flat(failure.ToString()));
            }
            catch
            {
            }
            return 1;
        }
    }
}
'@

$failed = $false
try {
  if ($Mode -eq 'SignOut' -and -not $Account) { throw '-Account names the temporary standard account' }
  Build-Probe
  switch ($Mode) {
    'Main' { Invoke-Main }
    'Runner' { Invoke-Runner }
    'SignOut' { Invoke-SignOut }
  }
} catch {
  $failed = $true
  Say ('failed: ' + $_.Exception.Message)
} finally {
  Invoke-Cleanup
}
if ($failed) { exit 1 }
exit 0
