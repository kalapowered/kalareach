# The root-editor bridge: the endpoint, the handshake, the reader's events and its mailbox.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# The contract is the same one every managed package answers; what is particular here is the
# mechanism. This reader has no patch behind it and no asynchronous editing method of its own, so
# the module supplies the queue and reads it where the editor reads its own: between the reader's
# operations, on the reader's own thread. Nothing here blocks the reader: the Unix socket is
# non-blocking and the Windows pipe keeps one asynchronous read in flight, so a request that
# arrives at a parked reader waits for its next step.

Set-StrictMode -Version 3.0

$script:KR_PROTOCOL = 'kr-shell-bridge/1'
$script:KR_ENDPOINT_VARIABLE = 'KR_SHELL_BRIDGE'
$script:KR_SECRET_VARIABLE = 'KR_SHELL_BRIDGE_SECRET'
$script:KR_SESSION_VARIABLE = 'KR_SESSION'
$script:KR_HANDSHAKE_WAIT_MS = 5000
$script:KR_MAX_FRAME = 1048576
# The most one read of the endpoint takes before it gives the reader its thread back. A worker that
# writes without pause would otherwise keep a drain loop going for as long as it kept writing, and a
# reader that does not return between operations is a reader whose delivery fence nothing can prove.
# What is left on the endpoint stays there, and the next step between operations takes it.
$script:KR_READ_BUDGET = 65536
$script:KR_REVOKED_MAX = 16

$script:Kr = @{
    Socket             = $null
    Incoming           = [System.Collections.Generic.List[byte]]::new()
    Registered         = $false
    Managed            = $false
    Session            = [byte[]]::new(16)
    Secret             = [byte[]]::new(0)
    Endpoint           = ''
    EventCounter       = [uint64]0
    FenceLive          = $false
    FenceId            = [byte[]]::new(16)
    FenceAttachment    = [byte[]]::new(16)
    FencePrompt        = [uint64]0
    FenceReader        = [uint64]0
    FenceEpoch         = [uint64]0
    GestureDisabled    = $false
    GestureByte        = [uint64]4
    GestureChord       = $null
    PendingGesture     = $false
    PendingDisabled    = $false
    PendingByte        = [uint64]4
    PendingChord       = $null
    PendingAt          = [uint64]0
    Hint               = 'Use kr detach --attachment <id> to detach.'
    Hinted             = $false
    HintedPrompt       = [uint64]0
    LaunchPending      = $false
    LaunchTransaction  = [byte[]]::new(16)
    Revoked            = [System.Collections.Generic.List[string]]::new()
    FrameAtMs          = [uint64]0
    Servicing          = $false
    # The one outstanding read on an asynchronous named pipe, and the array it fills. A pipe has
    # no readiness test of its own, so the read that answers "is anything there" is started before
    # anything is there and collected when it completes.
    PipeRead           = $null
    PipeBuffer         = $null
}

$script:State = @{
    PromptGeneration = [uint64]0
    ReaderRevision   = [uint64]0
    BufferRevision   = [uint64]0
    BufferSeen       = ''
    CwdRevision      = [uint64]0
    CwdSeen          = ''
    InsideReader     = 0
    InvokingKeys     = [byte[]]::new(0)
    Cancelled        = $false
    LastStatus       = $true
    Installed        = ''
    AcceptRequested  = $false
    IdleReported     = $false
    Reading          = $false
    EditMode         = 'Emacs'
    ReaderThreadId   = 0
}

# A line of diagnostics, when the session asked for them.
#
# The integration says what it did and why when something asks it to, and says nothing at all
# otherwise: a managed root shell writes no file of its own unless the person turned this on.
function Write-KrTrace {
    param([string]$Line)
    if ([string]::IsNullOrEmpty($env:KR_SHELL_BRIDGE_TRACE)) { return }
    try {
        [System.IO.File]::AppendAllText(
            $env:KR_SHELL_BRIDGE_TRACE,
            ("{0} {1}`n" -f [DateTimeOffset]::Now.ToString('o'), $Line))
    } catch { }
}

function Get-KrNowMs {
    [uint64][Math]::Floor([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
}

# Milliseconds on a clock that only goes forward, for the budgets a decision is measured against.
#
# The time of day can be set while a reader is waiting, and a launch's deadline is a duration
# rather than a moment.
function Get-KrTickMs {
    [uint64]([System.Diagnostics.Stopwatch]::GetTimestamp() /
        ([System.Diagnostics.Stopwatch]::Frequency / 1000))
}

function Get-KrProcessIdentity {
    $process = [System.Diagnostics.Process]::GetCurrentProcess()
    if ($IsLinux) {
        # /proc/self/stat field 22, counted after the comm field, which may itself hold spaces.
        $stat = [System.IO.File]::ReadAllText('/proc/self/stat')
        $tail = $stat.Substring($stat.LastIndexOf(')') + 1).Trim()
        $fields = $tail -split '\s+'
        return @{
            pid         = [uint64]$process.Id
            source      = 'linux_proc_stat'
            start_value = [uint64]$fields[19]
        }
    }
    if ($IsWindows) {
        # The creation time the kernel records, in its own hundreds of nanoseconds, counted from
        # 1970 rather than 1601. .NET reads it through GetProcessTimes as the worker does, and a
        # DateTime tick is the same hundred nanoseconds, so nothing is divided and nothing rounds:
        # the value is the one the worker reads, or the handshake refuses a different process.
        $created = $process.StartTime.ToUniversalTime().Ticks - [DateTime]::UnixEpoch.Ticks
        return @{
            pid         = [uint64]$process.Id
            source      = 'windows_process_creation_time'
            start_value = [uint64]$created
        }
    }
    $ticks = ([System.DateTimeOffset]$process.StartTime).UtcTicks -
             [System.DateTimeOffset]::UnixEpoch.UtcTicks
    # This platform's kernel records microseconds, and reports the value truncated. The truncation
    # is written out because PowerShell divides whole numbers as doubles and a cast to an integer
    # rounds the result: a shell started after the half unit would name a start one unit later than
    # the one the worker read from the kernel, and the handshake would be refused as a different
    # process.
    $start = [uint64][Math]::Floor([decimal]$ticks / [decimal]10)
    @{ pid = [uint64]$process.Id; source = 'macos_proc_bsd_info'; start_value = $start }
}

function ConvertFrom-KrBase64Url {
    param([string]$Text)
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { return $null }
    }
    try { [Convert]::FromBase64String($padded) } catch { $null }
}

function ConvertFrom-KrUuidText {
    param([string]$Text)
    try { , ([guid]::Parse($Text)).ToByteArray($true) } catch { $null }
}

# ---- the endpoint -------------------------------------------------------------------------------

# The accounts a pipe's list may grant besides its owner's own: the machine's own accounts (SYSTEM
# and the Administrators group), which already hold the machine, and the two placeholders that stand
# for the owner (CREATOR OWNER and OWNER RIGHTS).
$script:KR_TRUSTED_ACCOUNTS = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-3-4')

# The type that holds the calls below, once a shell has defined it.
$script:KrSecurityCalls = $null

# The platform calls that read a kernel object's security descriptor as the kernel stores it,
# defined once per shell with System.Reflection.Emit, which runs no compiler at shell start.
#
# .NET's own reading of a pipe's descriptor, PipeSecurity, rebuilds it and leaves out entries it
# judges to grant nothing, among them an allow entry with an empty mask or one that only passes to
# children, and it reads a missing list as one that admits everyone. The check below judges every
# entry as the kernel stores it, as the host's own client does, so it reads the bytes itself.
function Get-KrSecurityCalls {
    if ($null -ne $script:KrSecurityCalls) { return $script:KrSecurityCalls }
    $name = [System.Reflection.AssemblyName]::new('KalaReach.ShellBridge.Security')
    $assembly = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly(
        $name, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $module = $assembly.DefineDynamicModule($name.Name)
    $type = $module.DefineType('KalaReach.ShellBridge.Security',
        [System.Reflection.TypeAttributes]'Public, Abstract, Sealed')
    $pointer = [IntPtr]
    foreach ($call in @(
            # The descriptor of the object `handle` names, allocated for the caller: SE_FILE_OBJECT
            # and the parts asked for; the four part pointers are not asked for.
            @{ Library = 'advapi32.dll'; Name = 'GetSecurityInfo'; Returns = [uint32]; Parameters = [Type[]]@(
                    [System.Runtime.InteropServices.SafeHandle], [uint32], [uint32],
                    $pointer, $pointer, $pointer, $pointer, $pointer.MakeByRefType()) },
            @{ Library = 'advapi32.dll'; Name = 'GetSecurityDescriptorLength'; Returns = [uint32]; Parameters = [Type[]]@($pointer) },
            @{ Library = 'kernel32.dll'; Name = 'LocalFree'; Returns = $pointer; Parameters = [Type[]]@($pointer) }
        )) {
        $method = $type.DefinePInvokeMethod($call.Name, $call.Library,
            [System.Reflection.MethodAttributes]'Public, Static, PinvokeImpl, HideBySig',
            [System.Reflection.CallingConventions]::Standard, $call.Returns, $call.Parameters,
            [System.Runtime.InteropServices.CallingConvention]::Winapi,
            [System.Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags([System.Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:KrSecurityCalls = $type.CreateType()
    $script:KrSecurityCalls
}

# Reads a connected pipe's owner and discretionary list as the kernel stores them.
#
# The handle goes to the platform as the pipe's own SafeHandle, which keeps it open for the call.
# The descriptor is copied out of the platform's allocation before that allocation is freed, once.
function Read-KrPipeDescriptor {
    param([System.IO.Pipes.PipeStream]$Pipe)
    $calls = Get-KrSecurityCalls
    $descriptor = [IntPtr]::Zero
    # SE_FILE_OBJECT (1); OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION (5).
    $status = $calls::GetSecurityInfo($Pipe.SafePipeHandle, [uint32]1, [uint32]5,
        [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$descriptor)
    if ($status -ne 0) { throw [System.ComponentModel.Win32Exception]::new([int]$status) }
    try {
        $length = [int]$calls::GetSecurityDescriptorLength($descriptor)
        $bytes = [byte[]]::new($length)
        [System.Runtime.InteropServices.Marshal]::Copy($descriptor, $bytes, 0, $length)
    } finally {
        [void]$calls::LocalFree($descriptor)
    }
    [System.Security.AccessControl.RawSecurityDescriptor]::new($bytes, 0)
}

# Returns why a pipe's descriptor is not one this shell may send its hello to, or nothing when it is.
#
# The host's own client's rule, applied to the descriptor as the kernel stores it: the owner is this
# account's user or the owner this process's new objects receive (`Own`, as identifiers); the list is
# present and protected from what anything above it passes down; every allow entry, whatever its
# mask or flags, names one of those two or an account that already holds the machine; denial, audit
# and alarm entries grant nothing and pass; an entry of any other kind is one this rule does not read,
# and refuses.
function Test-KrPipeDescriptor {
    param([System.Security.AccessControl.RawSecurityDescriptor]$Descriptor, [string[]]$Own)
    $owner = $Descriptor.Owner
    if ($null -eq $owner) { return 'it records no owner' }
    if ($Own -notcontains $owner.Value) {
        return "it belongs to $($owner.Value), and this shell runs as another account"
    }
    $protected = [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected
    if (($Descriptor.ControlFlags -band $protected) -ne $protected) {
        return 'it inherits its access-control list from above it, which can widen it at any time'
    }
    $list = $Descriptor.DiscretionaryAcl
    if ($null -eq $list) {
        return 'it carries no access-control list, which grants every account full access'
    }
    foreach ($entry in $list) {
        $kind = [int]$entry.AceType
        # Access denied, system audit and system alarm.
        if ($kind -in 1, 2, 3) { continue }
        if ($kind -ne 0) {
            return "its access-control list carries a type-$kind entry, which this shell does not evaluate"
        }
        $account = $entry.SecurityIdentifier.Value
        if ($Own -notcontains $account -and $script:KR_TRUSTED_ACCOUNTS -notcontains $account) {
            return "its access-control list grants access to $account, which is neither its owner nor an account that already holds this machine"
        }
    }
    $null
}

# Returns why the pipe this client reached is not this account's own, or nothing when it is.
function Test-KrPipeServer {
    param([System.IO.Pipes.PipeStream]$Pipe)
    try {
        $descriptor = Read-KrPipeDescriptor $Pipe
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $own = @($identity.User, $identity.Owner) |
                Where-Object { $null -ne $_ } | ForEach-Object { $_.Value }
        } finally { $identity.Dispose() }
    } catch {
        return "its owner and access-control list could not be read: $($_.Exception.Message)"
    }
    Test-KrPipeDescriptor $descriptor @($own)
}

function Connect-KrEndpoint {
    param([string]$Path)
    try {
        if ($IsWindows) {
            # The bootstrap address holds the full `\\.\pipe\` path an external client connects to.
            # NamedPipeClientStream expects the pipe name alone and supplies the server and
            # namespace itself, so connecting with the prefix passes it twice and fails. Strip the
            # prefix for the connection while preserving the full address in the handshake proof.
            $name = if ($Path -like '\\.\pipe\*') {
                $Path.Substring(9)
            } else {
                $Path
            }
            # The pipe namespace is shared by every account, so the name the worker exported can be
            # held by a pipe another account created first. The pipe is opened for identification
            # only: the server may read which account this is, as the worker does to prove it, and
            # never act as this account. Then, before a byte is written, the pipe itself has to be
            # this account's own; one that is not gets nothing, and the shell carries on without
            # integration as it does when the connect fails.
            $pipe = [System.IO.Pipes.NamedPipeClientStream]::new(
                '.', $name, [System.IO.Pipes.PipeDirection]::InOut,
                [System.IO.Pipes.PipeOptions]::Asynchronous,
                [System.Security.Principal.TokenImpersonationLevel]::Identification)
            try {
                $pipe.Connect(2000)
            } catch {
                $pipe.Dispose()
                return $null
            }
            $refused = Test-KrPipeServer $pipe
            if ($null -ne $refused) {
                Write-KrTrace "the endpoint was refused before the hello: $refused"
                $pipe.Dispose()
                return $null
            }
            return $pipe
        }
        $endpoint = [System.Net.Sockets.UnixDomainSocketEndPoint]::new($Path)
        $socket = [System.Net.Sockets.Socket]::new(
            [System.Net.Sockets.AddressFamily]::Unix,
            [System.Net.Sockets.SocketType]::Stream,
            [System.Net.Sockets.ProtocolType]::Unspecified)
        $socket.Connect($endpoint)
        $socket.Blocking = $false
        return $socket
    } catch {
        return $null
    }
}

function Disconnect-KrEndpoint {
    param([string]$Loss = 'bridge_disconnected')
    if ($null -ne $script:Kr.Socket) {
        try { $script:Kr.Socket.Dispose() } catch { }
    }
    $script:Kr.Socket = $null
    $script:Kr.Registered = $false
    $script:Kr.FenceLive = $false
    $script:Kr.Incoming.Clear()
    # The outstanding read belongs to the handle that has just gone. Dropping it here is what keeps
    # a later connection from collecting the previous one's completion.
    $script:Kr.PipeRead = $null
    $script:Kr.PipeBuffer = $null
}

function Send-KrBytes {
    param([byte[]]$Bytes)
    $socket = $script:Kr.Socket
    if ($null -eq $socket) { return $false }
    $sent = 0
    $deadline = (Get-KrNowMs) + 2000
    while ($sent -lt $Bytes.Length) {
        try {
            if ($socket -is [System.IO.Pipes.NamedPipeClientStream]) {
                $socket.Write($Bytes, $sent, $Bytes.Length - $sent)
                $socket.Flush()
                $sent = $Bytes.Length
                break
            }
            $count = $socket.Send($Bytes, $sent, $Bytes.Length - $sent, 'None')
            if ($count -le 0) { throw 'the worker closed the endpoint' }
            $sent += $count
        } catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -ne [System.Net.Sockets.SocketError]::WouldBlock) {
                Disconnect-KrEndpoint
                return $false
            }
            if ((Get-KrNowMs) -gt $deadline) { Disconnect-KrEndpoint; return $false }
            [System.Threading.Thread]::Sleep(1)
        } catch {
            Disconnect-KrEndpoint
            return $false
        }
    }
    $true
}

function Send-KrFrame {
    param($Value)
    $body = ConvertTo-KrCbor $Value
    if ($body.Length -gt $script:KR_MAX_FRAME) { return $false }
    $framed = [byte[]]::new($body.Length + 4)
    $framed[0] = [byte](($body.Length -shr 24) -band 0xFF)
    $framed[1] = [byte](($body.Length -shr 16) -band 0xFF)
    $framed[2] = [byte](($body.Length -shr 8) -band 0xFF)
    $framed[3] = [byte]($body.Length -band 0xFF)
    [Array]::Copy($body, 0, $framed, 4, $body.Length)
    Send-KrBytes $framed
}

# Takes whatever the pipe has already delivered, and leaves one read outstanding for the next.
#
# A named pipe answers no readiness question: `IsConnected` says the handle is open, never that
# bytes are waiting, so a reader that asks it learns nothing and a reader that waits for bytes
# stops the editor. The handle is opened asynchronous for this reason. One read is kept in flight;
# each completion is drained here, on the reader's own thread, and the next read is started before
# this function returns, so the bytes that arrive while the reader is busy are already collected
# when it next looks.
#
# A completion of zero bytes and a faulted read both mean the worker has gone, which is the same
# end as a closed socket on the other platforms.
function Receive-KrPipeAvailable {
    param([System.IO.Pipes.NamedPipeClientStream]$Pipe)
    $taken = 0
    while ($true) {
        $pending = $script:Kr.PipeRead
        if ($null -eq $pending) {
            if (-not $Pipe.IsConnected) { Disconnect-KrEndpoint; return $false }
            if ($null -eq $script:Kr.PipeBuffer) { $script:Kr.PipeBuffer = [byte[]]::new(8192) }
            try {
                $pending = $Pipe.ReadAsync(
                    $script:Kr.PipeBuffer, 0, $script:Kr.PipeBuffer.Length)
            } catch {
                Disconnect-KrEndpoint
                return $false
            }
            $script:Kr.PipeRead = $pending
        }
        # The budget is spent. The read started above stays in flight, so whatever arrives from now
        # on is collected at the reader's next step between operations rather than here.
        if ($taken -ge $script:KR_READ_BUDGET) { return $true }
        # Nothing has arrived. The read stays in flight and the reader goes back to its own work.
        if (-not $pending.IsCompleted) { return $true }
        $script:Kr.PipeRead = $null
        if ($pending.IsFaulted -or $pending.IsCanceled) { Disconnect-KrEndpoint; return $false }
        $count = $pending.Result
        if ($count -le 0) { Disconnect-KrEndpoint; return $false }
        $buffer = $script:Kr.PipeBuffer
        for ($i = 0; $i -lt $count; $i++) { $script:Kr.Incoming.Add($buffer[$i]) }
        $taken += $count
        # The buffer is free again, so the next read starts now rather than at the next callback.
    }
}

# Reads whatever the endpoint has without waiting for more.
function Receive-KrAvailable {
    $socket = $script:Kr.Socket
    if ($null -eq $socket) { return $false }
    if ($socket -is [System.IO.Pipes.NamedPipeClientStream]) {
        return (Receive-KrPipeAvailable $socket)
    }
    $buffer = [byte[]]::new(8192)
    while ($true) {
        try {
            if (-not $socket.Poll(0, [System.Net.Sockets.SelectMode]::SelectRead)) { break }
            $count = $socket.Receive($buffer, 0, $buffer.Length, 'None')
            if ($count -eq 0) { Disconnect-KrEndpoint; return $false }
            for ($i = 0; $i -lt $count; $i++) { $script:Kr.Incoming.Add($buffer[$i]) }
        } catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq [System.Net.Sockets.SocketError]::WouldBlock) { break }
            Disconnect-KrEndpoint
            return $false
        } catch {
            Disconnect-KrEndpoint
            return $false
        }
    }
    $true
}

# The next complete frame's body, or $null.
function Read-KrFrame {
    if ($script:Kr.Incoming.Count -lt 4) { return $null }
    $length = ([int]$script:Kr.Incoming[0] -shl 24) -bor ([int]$script:Kr.Incoming[1] -shl 16) -bor
              ([int]$script:Kr.Incoming[2] -shl 8) -bor [int]$script:Kr.Incoming[3]
    if ($length -le 0 -or $length -gt $script:KR_MAX_FRAME) {
        Disconnect-KrEndpoint
        return $null
    }
    if ($script:Kr.Incoming.Count -lt 4 + $length) { return $null }
    $body = [byte[]]::new($length)
    $script:Kr.Incoming.CopyTo(4, $body, 0, $length)
    $script:Kr.Incoming.RemoveRange(0, 4 + $length)
    , $body
}

# ---- the contract's own shapes -------------------------------------------------------------------

function New-KrEditor {
    param([hashtable]$Reader)
    @{
        keymap          = $Reader.keymap
        pending         = $Reader.pending
        buffer_empty    = $Reader.buffer_empty
        buffer_revision = $Reader.buffer_revision
    }
}

function New-KrSnapshot {
    param([hashtable]$Reader)
    @{
        keys          = $Reader.keys
        queued_keys   = $Reader.queued_keys
        pending_bytes = $Reader.pending_bytes
    }
}

function New-KrQueues {
    param([hashtable]$Reader)
    @{
        macro_input_drained   = $Reader.macro_input_drained
        partial_key_drained   = $Reader.partial_key_drained
        tty_typeahead_drained = $Reader.tty_typeahead_drained
    }
}

function New-KrGesture {
    param([bool]$Disabled, [uint64]$Byte, $Chord)
    if ($Disabled) { return 'disabled' }
    if ($null -ne $Chord) { return @{ chord = @{ keys = [string[]]@($Chord) } } }
    @{ terminal_eof = @{ byte = $Byte } }
}

function Send-KrEvent {
    param([string]$Name, [hashtable]$Payload)
    if (-not $script:Kr.Registered) { return }
    $script:Kr.EventCounter++
    Send-KrFrame @{
        event = @{
            id    = $script:Kr.EventCounter
            event = @{ $Name = $Payload }
        }
    } | Out-Null
}

function Send-KrAnswer {
    param([uint64]$Id, [string]$Name, $Payload)
    Send-KrFrame @{
        answer = @{
            id     = $Id
            answer = @{ $Name = $Payload }
        }
    } | Out-Null
}

# ---- the handshake --------------------------------------------------------------------------------

function New-KrHello {
    param([hashtable]$Identity, [byte[]]$Proof, [hashtable]$Package)
    @{
        protocol      = $script:KR_PROTOCOL
        session_id    = $script:Kr.Session
        shell_process = $Identity
        shell         = @{
            kind                = 'powershell'
            executable          = $Package.executable
            upstream_version    = $Package.upstream_version
            editor_abi          = $Package.editor_abi
            integration_version = $Package.integration_version
            patches             = @($Package.patches)
            modules             = @($Package.modules)
        }
        abi           = @{
            mailbox         = 'reader_thread_queue'
            pre_eof         = 'reader_state_handler'
            fence_proof     = 'atomic_reader_state'
            cancellation    = 'non_destructive_key_wait'
            launch_delivery = 'reader_mailbox'
        }
        proof         = $Proof
    }
}

function Get-KrTranscript {
    param([hashtable]$Identity, [string]$IntegrationVersion)
    ConvertTo-KrCbor @(
        $script:KR_PROTOCOL,
        $script:Kr.Session,
        $script:Kr.Endpoint,
        $Identity,
        $IntegrationVersion
    )
}

function Read-KrAccept {
    param([hashtable]$Accepted)
    $script:Kr.GestureDisabled = $false
    $script:Kr.GestureByte = [uint64]4
    $script:Kr.GestureChord = $null
    if ($Accepted.PSBase.ContainsKey('gesture')) {
        $variant = Get-KrVariant $Accepted['gesture']
        if ($null -ne $variant) {
            switch ($variant.Name) {
                'disabled' { $script:Kr.GestureDisabled = $true }
                'terminal_eof' { $script:Kr.GestureByte = [uint64]$variant.Payload['byte'] }
                'chord' { $script:Kr.GestureChord = @($variant.Payload['keys'])[0] }
            }
        }
    }
    if ($Accepted.PSBase.ContainsKey('hint') -and $Accepted['hint'] -is [string]) {
        $script:Kr.Hint = $Accepted['hint']
    }
}

function Wait-KrHandshake {
    $deadline = (Get-KrNowMs) + $script:KR_HANDSHAKE_WAIT_MS
    while ($true) {
        $frame = Read-KrFrame
        if ($null -ne $frame) {
            $value = try { ConvertFrom-KrCbor $frame } catch { Write-KrTrace "the accept did not decode: $_"; $null }
            $outcome = if ($null -eq $value) { $null } else { Get-KrVariant $value }
            if ($null -eq $outcome -or $outcome.Name -ne 'handshake') {
                Write-KrTrace "not a handshake: $($outcome.Name)"
                return $false
            }
            $verdict = Get-KrVariant $outcome.Payload
            if ($null -eq $verdict -or $verdict.Name -ne 'accepted') {
                Write-KrTrace "refused: $($verdict.Name)"
                return $false
            }
            Read-KrAccept $verdict.Payload
            Write-KrTrace 'accepted'
            return $true
        }
        if ($null -eq $script:Kr.Socket) { return $false }
        if ((Get-KrNowMs) -gt $deadline) { return $false }
        if (-not (Receive-KrAvailable)) { return $false }
        [System.Threading.Thread]::Sleep(2)
    }
}

# ---- the reader's events --------------------------------------------------------------------------

# A reassigned gesture is a user change, and it takes effect at the prompt that is starting.
function Update-KrGesture {
    param([uint64]$PromptGeneration)
    $eof = Get-KrTerminalEof
    $disabled = ($eof -lt 0)
    $byte = if ($disabled) { [uint64]0 } else { [uint64]$eof }
    if ($null -ne $script:Kr.GestureChord) { return }
    if ($disabled -eq $script:Kr.GestureDisabled -and ($disabled -or $byte -eq $script:Kr.GestureByte)) {
        return
    }
    if ($script:Kr.PendingGesture -and $script:Kr.PendingDisabled -eq $disabled -and
        ($disabled -or $script:Kr.PendingByte -eq $byte)) {
        return
    }
    $script:Kr.PendingGesture = $true
    $script:Kr.PendingDisabled = $disabled
    $script:Kr.PendingByte = $byte
    $script:Kr.PendingAt = $PromptGeneration
    Send-KrEvent 'gesture_changed' @{
        gesture      = New-KrGesture $disabled $byte $null
        session_id   = $script:Kr.Session
        effective_at = $PromptGeneration
    }
}

function Invoke-KrPromoteGesture {
    param([uint64]$PromptGeneration)
    if (-not $script:Kr.PendingGesture -or $PromptGeneration -lt $script:Kr.PendingAt) { return }
    $script:Kr.GestureDisabled = $script:Kr.PendingDisabled
    $script:Kr.GestureByte = $script:Kr.PendingByte
    $script:Kr.PendingGesture = $false
    # The decision belongs on the key the terminal now names, and the key it was on goes back to
    # what it was doing.
    if ($script:Hooks.Activated) { Sync-KrGestureHandler }
}

function Send-KrEditorEnter {
    if (-not $script:Kr.Registered) { return }
    $reader = Get-KrReaderState $script:State
    # A gesture the person changed takes effect at the prompt it named, which is this one.
    Invoke-KrPromoteGesture $reader.prompt_generation
    Update-KrGesture $reader.prompt_generation
    Send-KrEvent 'editor_enter' @{
        editor            = New-KrEditor $reader
        session_id        = $script:Kr.Session
        cwd_revision      = $reader.cwd_revision
        root_process      = $script:Kr.Identity
        reader_context    = $reader.reader_context
        reader_revision   = $reader.reader_revision
        prompt_generation = $reader.prompt_generation
    }
    Invoke-KrService
}

function Send-KrEditorLeave {
    param([string]$Reason)
    if (-not $script:Kr.Registered) { return }
    $script:Kr.LaunchPending = $false
    $reader = Get-KrReaderState $script:State
    Send-KrEvent 'editor_leave' @{
        reason            = $Reason
        session_id        = $script:Kr.Session
        reader_revision   = $reader.reader_revision
        prompt_generation = $reader.prompt_generation
    }
}

function Send-KrReaderIdle {
    if (-not $script:Kr.Registered) { return }
    $reader = Get-KrReaderState $script:State
    Send-KrEvent 'reader_idle' @{
        editor            = New-KrEditor $reader
        snapshot          = New-KrSnapshot $reader
        session_id        = $script:Kr.Session
        cwd_revision      = $reader.cwd_revision
        reader_context    = $reader.reader_context
        reader_revision   = $reader.reader_revision
        prompt_generation = $reader.prompt_generation
    }
}

function Send-KrCommandAccepted {
    if (-not $script:Kr.Registered) { return }
    $reader = Get-KrReaderState $script:State
    $fenced = $script:Kr.FenceLive -and
              $script:Kr.FencePrompt -eq $reader.prompt_generation -and
              $script:Kr.FenceReader -eq $reader.reader_revision
    $origin = if ($fenced) {
        @{ fenced = @{ input_epoch = $script:Kr.FenceEpoch; attachment_id = $script:Kr.FenceAttachment } }
    } else { 'unverifiable' }
    # Assigned rather than written inline: a subexpression takes a byte string apart into its own
    # numbers, and the fence this names would go out as a list of them.
    $fenceId = $null
    if ($fenced) { $fenceId = $script:Kr.FenceId }
    Send-KrEvent 'command_accepted' @{
        origin            = $origin
        fence_id          = $fenceId
        session_id        = $script:Kr.Session
        prompt_generation = $reader.prompt_generation
    }
}

function Send-KrHooksActivated {
    param([uint64]$PromptGeneration)
    if (-not $script:Kr.Registered) { return }
    Send-KrEvent 'hooks_activated' @{
        session_id        = $script:Kr.Session
        prompt_generation = $PromptGeneration
    }
}

function Send-KrIntegrationLost {
    param([string]$Loss, [string]$Detail = '')
    if (-not $script:Kr.Registered) { return }
    Send-KrEvent 'integration_lost' @{
        loss       = $Loss
        detail     = $Detail
        session_id = $script:Kr.Session
    }
}

function Send-KrPreEofConsumed {
    param([uint64]$PromptGeneration, [string]$Reason, [bool]$HintPrinted)
    Send-KrEvent 'pre_eof_consumed' @{
        reason            = $Reason
        session_id        = $script:Kr.Session
        hint_printed      = $HintPrinted
        prompt_generation = $PromptGeneration
    }
}

# ---- the pre-EOF decision -------------------------------------------------------------------------

# `detach_eligibility`, in the contract's own order.
function Test-KrDetachEligible {
    param([hashtable]$Reader, [string]$Source)
    if ($Reader.reader_context -ne 'primary') { return $false }
    if ($Source -eq 'macro' -or $Source -eq 'pushed_back' -or $Source -eq 'paste') { return $false }
    if (-not $Reader.buffer_empty) { return $false }
    foreach ($flag in $Reader.pending.PSBase.Values) { if ($flag) { return $false } }
    $true
}

function Invoke-KrConsume {
    param([uint64]$PromptGeneration, [string]$Reason)
    $printed = $false
    if (-not $script:Kr.Hinted -or $script:Kr.HintedPrompt -ne $PromptGeneration) {
        $script:Kr.Hinted = $true
        $script:Kr.HintedPrompt = $PromptGeneration
        Write-KrHint $script:Kr.Hint
        $printed = $true
    }
    Send-KrPreEofConsumed $PromptGeneration $Reason $printed
    'consume'
}

# The end-of-file decision, taken with the actual reader context. Returns 'native' or 'consume'.
function Invoke-KrPreEof {
    param([int]$Key, [string]$Source)
    if (-not $script:Kr.Managed) { return 'native' }
    $reader = Get-KrReaderState $script:State
    Invoke-KrPromoteGesture $reader.prompt_generation

    if ($script:Kr.GestureDisabled) { return 'native' }
    if ($null -eq $script:Kr.GestureChord -and [uint64]$Key -ne $script:Kr.GestureByte) {
        return 'native'
    }
    if (-not (Test-KrDetachEligible $reader $Source)) { return 'native' }
    if (-not $script:Kr.FenceLive) {
        return Invoke-KrConsume $reader.prompt_generation 'fence_missing'
    }
    if ($script:Kr.FencePrompt -ne $reader.prompt_generation -or
        $script:Kr.FenceReader -ne $reader.reader_revision) {
        return Invoke-KrConsume $reader.prompt_generation 'fence_stale'
    }
    Send-KrEvent 'eof_detach' @{
        fence_id          = $script:Kr.FenceId
        session_id        = $script:Kr.Session
        input_epoch       = $script:Kr.FenceEpoch
        prompt_generation = $script:Kr.FencePrompt
    }
    'consume'
}

# The gesture has already left the reader, so a refused detach is consumed with the hint.
function Invoke-KrDetachRefused {
    $script:Kr.FenceLive = $false
    $reader = Get-KrReaderState $script:State
    Invoke-KrConsume $reader.prompt_generation 'fence_stale' | Out-Null
}

# ---- answering the reader's mailbox -----------------------------------------------------------------

function Invoke-KrAnswerFence {
    param([uint64]$Id, [hashtable]$Params)
    $fenceId = [byte[]]$Params['fence_id']
    if ($null -eq $fenceId -or $fenceId.Length -ne 16) { return }
    $prompt = [uint64]$Params['prompt_generation']
    $readerRevision = [uint64]$Params['reader_revision']
    $reader = Get-KrReaderState $script:State

    if ($prompt -ne $reader.prompt_generation -or $readerRevision -ne $reader.reader_revision) {
        # A report about a reader that is not running now says nothing about the one that is.
        Send-KrAnswer $Id 'fence' @{
            refused = @{
                reason         = 'reader_moved'
                fence_id       = $fenceId
                snapshot       = New-KrSnapshot $reader
                reader_context = $reader.reader_context
            }
        }
        return
    }
    # Each queue is reported separately: a worker that learns which one still holds input can retry,
    # and one that learns only that the transition failed cannot.
    Send-KrAnswer $Id 'fence' @{
        acknowledged = @{
            editor            = New-KrEditor $reader
            queues            = New-KrQueues $reader
            fence_id          = $fenceId
            snapshot          = New-KrSnapshot $reader
            cwd_revision      = $reader.cwd_revision
            reader_context    = $reader.reader_context
            reader_revision   = $reader.reader_revision
            prompt_generation = $reader.prompt_generation
        }
    }
}

function Send-KrLaunchRejection {
    param([uint64]$Id, [byte[]]$Transaction, [byte[]]$FenceId, [string]$Reason, [hashtable]$Reader)
    Send-KrAnswer $Id 'launch' @{
        rejected = @{
            reason            = $Reason
            fence_id          = $FenceId
            transaction       = $Transaction
            buffer_revision   = $Reader.buffer_revision
            prompt_generation = $Reader.prompt_generation
        }
    }
}

# The line the reader installs: an argument vector quoted for this shell, or a command the caller
# already quoted. Nothing is assembled by interpolation.
function Get-KrLaunchText {
    param($Command)
    $variant = Get-KrVariant $Command
    if ($null -eq $variant) { return $null }
    if ($variant.Name -eq 'quoted_command') {
        if ($variant.Payload -is [string]) { return $variant.Payload }
        return $null
    }
    if ($variant.Name -ne 'arguments') { return $null }
    $parts = @()
    foreach ($argument in @($variant.Payload)) {
        if ($argument -isnot [string]) { return $null }
        $parts += Get-KrQuotedArgument $argument
    }
    if ($parts.Count -eq 0) { return '' }
    # The call operator, because the first argument is quoted like the rest: a quoted word at the
    # start of a line is a string of this shell's rather than the name of what to run.
    '& ' + ($parts -join ' ')
}

# `decide_launch`, on the reader's own thread, in the order the reasons matter.
function Invoke-KrAnswerLaunch {
    param([uint64]$Id, [hashtable]$Request, [bool]$Revoked)
    $transaction = [byte[]]$Request['transaction']
    $fenceId = [byte[]]$Request['fence_id']
    if ($null -eq $transaction -or $transaction.Length -ne 16) { Write-KrTrace 'launch: no transaction'; return }
    if ($null -eq $fenceId -or $fenceId.Length -ne 16) { Write-KrTrace 'launch: no fence'; return }
    $expectedPrompt = [uint64]$Request['expected_prompt_generation']
    $expectedBuffer = [uint64]$Request['expected_buffer_revision']
    $expectedCwd = [uint64]$Request['expected_cwd_revision']
    $deadline = [uint64]$Request['deadline_ms']
    $waited = (Get-KrTickMs) - $script:Kr.FrameAtMs
    $reader = Get-KrReaderState $script:State

    if ($Revoked) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'revoked' $reader; return
    }
    if (-not $script:Kr.FenceLive -or
        -not [System.Linq.Enumerable]::SequenceEqual([byte[]]$script:Kr.FenceId, $fenceId)) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'fence_invalid' $reader; return
    }
    if ($reader.reader_context -ne 'primary') {
        Send-KrLaunchRejection $Id $transaction $fenceId 'not_primary_reader' $reader; return
    }
    if ($waited -ge $deadline) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'timeout' $reader; return
    }
    if (-not $reader.tty_typeahead_drained -or -not $reader.macro_input_drained -or
        -not $reader.partial_key_drained -or $reader.queued_keys -gt 0 -or
        $reader.pending_bytes -gt 0 -or $reader.pending.macro_input) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'queued_prior_input' $reader; return
    }
    if ($reader.prompt_generation -ne $expectedPrompt) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'prompt_generation_mismatch' $reader; return
    }
    if ($reader.cwd_revision -ne $expectedCwd) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'cwd_revision_mismatch' $reader; return
    }
    if (-not $reader.buffer_empty) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'buffer_not_empty' $reader; return
    }
    if ($reader.buffer_revision -ne $expectedBuffer) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'buffer_revision_mismatch' $reader; return
    }

    $text = Get-KrLaunchText $Request['command']
    if ($null -eq $text) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'buffer_not_empty' $reader; return
    }
    # Building the line took time of its own. Past the budget nothing is installed, which is what
    # makes "install no command" a fact rather than a hope.
    if (((Get-KrTickMs) - $script:Kr.FrameAtMs) -ge $deadline) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'timeout' $reader; return
    }
    if (-not (Invoke-KrInstallCommand $script:State $text)) {
        Send-KrLaunchRejection $Id $transaction $fenceId 'buffer_not_empty' $reader; return
    }

    $script:Kr.LaunchPending = $true
    $script:Kr.LaunchTransaction = $transaction

    Send-KrAnswer $Id 'launch' @{
        accepted = @{
            fence_id          = $fenceId
            installed         = $Request['command']
            transaction       = $transaction
            buffer_revision   = [uint64]($reader.buffer_revision + 1)
            reader_revision   = $reader.reader_revision
            prompt_generation = $reader.prompt_generation
        }
    }
    # Installed and accepted. The transaction stays this bridge's own until the reader actually
    # leaves, because a revocation that arrives in that window still has text to take back out.
    $script:State.AcceptRequested = $true
}

function Invoke-KrAnswerCancel {
    param([uint64]$Id, [hashtable]$Params)
    $sequence = [uint64]$Params['sequence']
    $epoch = [uint64]$Params['epoch']
    $prompt = [uint64]$Params['prompt_generation']
    $readerRevision = [uint64]$Params['reader_revision']

    $reader = Get-KrReaderState $script:State
    $ended = @{
        partial_escape    = $false
        quoted_insertion  = $false
        vi_motion         = $false
        multikey_sequence = $false
        macro_input       = $false
        buffer_preserved  = $true
        discarded_bytes   = [uint64]0
    }
    # A cancellation for a reader that is not the one running would end an operation the worker
    # never asked about. It is answered, so the worker can match and discard it, and nothing ends.
    if ($prompt -eq $reader.prompt_generation -and $readerRevision -eq $reader.reader_revision) {
        $ended = Invoke-KrCancelKeyWait $script:State
        $reader = Get-KrReaderState $script:State
    }

    $reportedReader = if ($readerRevision -ne 0) { $readerRevision } else { $reader.reader_revision }
    $reportedPrompt = if ($prompt -ne 0) { $prompt } else { $reader.prompt_generation }
    Send-KrFrame @{
        answer = @{
            id     = $Id
            answer = @{
                cancel = @{
                    epoch             = $epoch
                    sequence          = $sequence
                    cancelled         = @{
                        vi_motion         = $ended.vi_motion
                        macro_input       = $ended.macro_input
                        partial_escape    = $ended.partial_escape
                        quoted_insertion  = $ended.quoted_insertion
                        multikey_sequence = $ended.multikey_sequence
                    }
                    discarded_bytes   = $ended.discarded_bytes
                    reader_revision   = $reportedReader
                    buffer_preserved  = $ended.buffer_preserved
                    prompt_generation = $reportedPrompt
                }
            }
        }
    } | Out-Null
}

# ---- reading the mailbox ------------------------------------------------------------------------

function Read-KrPublication {
    param($Publication)
    $variant = Get-KrVariant $Publication
    if ($null -eq $variant) { return }
    if ($variant.Name -eq 'published') {
        $fenceId = [byte[]]$variant.Payload['fence_id']
        $attachment = [byte[]]$variant.Payload['originating_attachment']
        if ($null -eq $fenceId -or $fenceId.Length -ne 16) { return }
        if ($null -eq $attachment -or $attachment.Length -ne 16) { return }
        $script:Kr.FenceId = $fenceId
        $script:Kr.FenceAttachment = $attachment
        $script:Kr.FencePrompt = [uint64]$variant.Payload['prompt_generation']
        $script:Kr.FenceReader = [uint64]$variant.Payload['reader_revision']
        $script:Kr.FenceEpoch = [uint64]$variant.Payload['input_epoch']
        $script:Kr.FenceLive = $true
        return
    }
    # Withheld and invalidated both mean the bridge holds no fence.
    $script:Kr.FenceLive = $false
}

function Read-KrEventResult {
    param($Result)
    $variant = Get-KrVariant $Result
    if ($null -eq $variant) { return }
    if ($variant.Name -eq 'refused') {
        # The one refusal every bridge must handle: the detach the gesture had already left the
        # reader for.
        Invoke-KrDetachRefused
        return
    }
    if ($variant.Name -eq 'detached') {
        # After a successful detach the bridge drops its fence, so a repeated gesture cannot take
        # on the next attachment's identity.
        $script:Kr.FenceLive = $false
    }
}

function Add-KrRevocation {
    param([byte[]]$Transaction)
    $key = [Convert]::ToBase64String($Transaction)
    if ($script:Kr.Revoked.Contains($key)) { return }
    if ($script:Kr.Revoked.Count -ge $script:KR_REVOKED_MAX) { $script:Kr.Revoked.RemoveAt(0) }
    $script:Kr.Revoked.Add($key)
}

# Whether a revocation for this transaction is in the frames this step has read, which the ordered
# endpoint makes the same question as whether the worker sent one before this step.
function Test-KrRevoked {
    param([byte[]]$Transaction)
    $key = [Convert]::ToBase64String($Transaction)
    if ($script:Kr.Revoked.Contains($key)) { return $true }
    $at = 0
    while ($script:Kr.Incoming.Count - $at -ge 4) {
        $length = ([int]$script:Kr.Incoming[$at] -shl 24) -bor ([int]$script:Kr.Incoming[$at + 1] -shl 16) -bor
                  ([int]$script:Kr.Incoming[$at + 2] -shl 8) -bor [int]$script:Kr.Incoming[$at + 3]
        if ($length -le 0 -or $length -gt $script:KR_MAX_FRAME) { return $false }
        if ($script:Kr.Incoming.Count - $at -lt 4 + $length) { return $false }
        $body = [byte[]]::new($length)
        $script:Kr.Incoming.CopyTo($at + 4, $body, 0, $length)
        $value = try { ConvertFrom-KrCbor $body } catch { $null }
        $variant = if ($null -eq $value) { $null } else { Get-KrVariant $value }
        if ($null -ne $variant -and $variant.Name -eq 'launch_revoked') {
            $named = [byte[]]$variant.Payload['transaction']
            if ($null -ne $named -and $named.Length -eq 16 -and
                [Convert]::ToBase64String($named) -eq $key) {
                return $true
            }
        }
        $at += 4 + $length
    }
    $false
}

function Read-KrRevocation {
    param([hashtable]$Frame)
    $transaction = [byte[]]$Frame['transaction']
    if ($null -eq $transaction -or $transaction.Length -ne 16) { return }
    Add-KrRevocation $transaction
    if ($script:Kr.LaunchPending -and
        [System.Linq.Enumerable]::SequenceEqual([byte[]]$script:Kr.LaunchTransaction, $transaction)) {
        # Installed but not accepted: the text comes out, so a revoked launch leaves nothing behind.
        Invoke-KrRemoveInstalled $script:State | Out-Null
        $script:Kr.LaunchPending = $false
    }
}

function Invoke-KrFrame {
    param([byte[]]$Body)
    $value = try { ConvertFrom-KrCbor $Body } catch { $null }
    $variant = if ($null -eq $value) { $null } else { Get-KrVariant $value }
    if ($null -eq $variant) { Disconnect-KrEndpoint; return }

    switch ($variant.Name) {
        'fence_published' { Read-KrPublication $variant.Payload; return }
        'launch_revoked' { Read-KrRevocation $variant.Payload; return }
        'event_result' { Read-KrEventResult $variant.Payload['result']; return }
        'request' {
            $id = [uint64]$variant.Payload['id']
            $request = Get-KrVariant $variant.Payload['request']
            if ($null -eq $request) { return }
            switch ($request.Name) {
                'fence' { Invoke-KrAnswerFence $id $request.Payload }
                'launch' {
                    $transaction = [byte[]]$request.Payload['transaction']
                    $already = ($null -ne $transaction -and $transaction.Length -eq 16 -and
                                (Test-KrRevoked $transaction))
                    Invoke-KrAnswerLaunch $id $request.Payload $already
                }
                'cancel' { Invoke-KrAnswerCancel $id $request.Payload }
            }
            return
        }
        default {
            # A worker never sends a hello, an event or an answer. A frame that does not belong on
            # this endpoint ends the connection rather than being ignored.
            Disconnect-KrEndpoint
        }
    }
}

# Reads the mailbox and answers what is in it.
#
# Safe only where the reader is between operations, which is where every caller of this is.
function Invoke-KrService {
    if (-not $script:Kr.Registered -or $null -eq $script:Kr.Socket) { return }
    if ($script:Kr.Servicing) { return }
    $script:Kr.Servicing = $true
    try {
        if (-not (Receive-KrAvailable)) { return }
        # Every frame this read took off the endpoint arrived by now, so each one is judged
        # against the time the reader reached them rather than the time its turn came.
        $arrived = Get-KrTickMs
        while ($true) {
            $body = Read-KrFrame
            if ($null -eq $body -or -not $script:Kr.Registered) { break }
            $script:Kr.FrameAtMs = $arrived
            Invoke-KrFrame $body
        }
    } finally {
        $script:Kr.Servicing = $false
    }
    if ($script:State.AcceptRequested) {
        $script:State.AcceptRequested = $false
        Invoke-KrAcceptLine $script:State | Out-Null
    }
}
