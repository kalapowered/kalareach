# The KalaReach root-editor bridge for PowerShell, bound into the installed PSReadLine.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# This package rebuilds no shell. PSReadLine is the line editor the person already has, and this
# module binds into it: it wraps the host's read-line entry point for the reader's own boundaries,
# it wraps the editor's own functions to observe the operations that wait for another key, and it
# puts its end-of-file decision on the configured gesture in front of whatever was bound there.
# Nothing it wraps is replaced, and everything it installs comes off again with the module.
#
# The reader thread is where all of it runs. A timer raises an engine event, the host delivers that
# event on the reader's own thread inside its read loop, and the mailbox is read there with the
# editor's real buffer and invocation state in hand.

Set-StrictMode -Version 3.0

$script:ModuleRoot = $PSScriptRoot
. (Join-Path $script:ModuleRoot 'KrCbor.ps1')
. (Join-Path $script:ModuleRoot 'KrReader.ps1')
. (Join-Path $script:ModuleRoot 'KrBridge.ps1')

# The PSReadLine versions this package was qualified against.
$script:QualifiedFrom = [version]'2.3.4'
$script:QualifiedBefore = [version]'3.0.0'
$script:IntegrationVersion = '1'
$script:SignalIntervalMs = 25

$script:Hooks = @{
    Activated      = $false
    Timer          = $null
    Subscription   = $null
    GestureChord   = $null
    GestureBefore  = $null
    Wrapped        = [System.Collections.Generic.List[string]]::new()
    InnerReadLine  = $null
}

# The operations whose key wait this module observes by wrapping them. Each runs its own read loop
# inside the handler, so being inside the wrapper is exactly being in the middle of the operation.
$script:Observed = @(
    @{ Function = 'ReverseSearchHistory'; Pending = 'search' }
    @{ Function = 'ForwardSearchHistory'; Pending = 'search' }
    @{ Function = 'HistorySearchBackward'; Pending = 'search' }
    @{ Function = 'HistorySearchForward'; Pending = 'search' }
    @{ Function = 'ViSearchHistoryBackward'; Pending = 'search' }
    @{ Function = 'DigitArgument'; Pending = 'numeric_argument' }
    @{ Function = 'ViDigitArgumentInChord'; Pending = 'numeric_argument' }
    @{ Function = 'CharacterSearch'; Pending = 'vi_motion' }
    @{ Function = 'CharacterSearchBackward'; Pending = 'vi_motion' }
    @{ Function = 'ViDeleteToChar'; Pending = 'vi_motion' }
    @{ Function = 'ViDeleteToCharBackward'; Pending = 'vi_motion' }
    @{ Function = 'ViDeleteToBeforeChar'; Pending = 'vi_motion' }
    @{ Function = 'ViDeleteToBeforeCharBackward'; Pending = 'vi_motion' }
    @{ Function = 'ViReplaceToChar'; Pending = 'vi_motion' }
    @{ Function = 'ViReplaceToCharBackward'; Pending = 'vi_motion' }
    @{ Function = 'Paste'; Pending = 'paste' }
)

function Get-KrPSReadLineVersion {
    $module = Get-Module PSReadLine
    if ($null -eq $module) { $module = Get-Module PSReadLine -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1 }
    if ($null -eq $module) { return $null }
    $module.Version
}

function Get-KrPackageIdentity {
    $version = Get-KrPSReadLineVersion
    $abi = if ($null -eq $version) { 'psreadline-unknown' } else { "psreadline-$($version.Major).$($version.Minor)" }
    $executable = try {
        [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    } catch {
        Join-Path $PSHOME 'pwsh'
    }
    $psrlPath = try { (Get-Module PSReadLine).ModuleBase } catch { '' }
    @{
        executable          = $executable
        upstream_version    = $PSVersionTable.PSVersion.ToString()
        editor_abi          = $abi
        integration_version = $script:IntegrationVersion
        patches             = @()
        modules             = @(
            @{ name = 'KalaReach.ShellBridge'; search_path = $script:ModuleRoot; editor_abi = $abi }
            @{ name = 'PSReadLine'; search_path = "$psrlPath"; editor_abi = $abi }
        )
    }
}

function Test-KrQualifiedEditor {
    $version = Get-KrPSReadLineVersion
    if ($null -eq $version) {
        return @{ Ok = $false; Reason = 'psreadline_absent'; Detail = 'PSReadLine is not loaded' }
    }
    if ($version -lt $script:QualifiedFrom -or $version -ge $script:QualifiedBefore) {
        return @{
            Ok     = $false
            Reason = 'psreadline_version_unqualified'
            Detail = "PSReadLine $version is outside $($script:QualifiedFrom) to $($script:QualifiedBefore)"
        }
    }
    if (-not (Test-KrQueueReadable)) {
        # A fence rests on the reader's own queue, and a build that does not keep one where this
        # package was qualified to find it cannot prove one.
        return @{
            Ok     = $false
            Reason = 'psreadline_queue_unreadable'
            Detail = "PSReadLine $version keeps no reader queue this package can read"
        }
    }
    @{ Ok = $true; Reason = ''; Detail = '' }
}

function Write-KrDiagnostic {
    param([string]$Reason, [string]$Detail)
    # A named qualification error, never a false ready state.
    [Console]::Error.WriteLine("kalareach: ${Reason}: ${Detail}")
}

# ---- activation ------------------------------------------------------------------------------------

function Initialize-KalaReachBridge {
    <#
    .SYNOPSIS
    Attempts the handshake, unless the bootstrap variables say there is nothing to attempt.
    #>
    [CmdletBinding()]
    param()

    if ($script:Kr.Registered -or $null -ne $script:Kr.Socket) { return }

    $endpoint = $env:KR_SHELL_BRIDGE
    $secret = $env:KR_SHELL_BRIDGE_SECRET
    $session = $env:KR_SESSION
    # Without both bootstrap values there is nothing to attempt, which is what keeps the guarded
    # startup entry inert in every child shell.
    if ([string]::IsNullOrEmpty($endpoint) -or [string]::IsNullOrEmpty($secret)) { return }
    if ([string]::IsNullOrEmpty($session)) { return }

    $qualified = Test-KrQualifiedEditor
    if (-not $qualified.Ok) {
        Write-KrDiagnostic $qualified.Reason $qualified.Detail
        return
    }

    $sessionBytes = ConvertFrom-KrUuidText $session
    if ($null -eq $sessionBytes) { return }
    $secretBytes = ConvertFrom-KrBase64Url $secret
    if ($null -eq $secretBytes -or $secretBytes.Length -eq 0) { return }

    $script:Kr.Session = $sessionBytes
    $script:Kr.Secret = $secretBytes
    $script:Kr.Endpoint = $endpoint
    $script:Kr.Identity = Get-KrProcessIdentity
    $script:Kr.Package = Get-KrPackageIdentity

    $script:Kr.Socket = Connect-KrEndpoint $endpoint
    if ($null -eq $script:Kr.Socket) {
        $script:Kr.Secret = [byte[]]::new(0)
        return
    }

    $transcript = Get-KrTranscript $script:Kr.Identity $script:Kr.Package.integration_version
    $mac = [System.Security.Cryptography.HMACSHA256]::new($script:Kr.Secret)
    try { $proof = $mac.ComputeHash($transcript) } finally { $mac.Dispose() }

    if (-not (Send-KrFrame @{ hello = (New-KrHello $script:Kr.Identity $proof $script:Kr.Package) })) {
        Disconnect-KrEndpoint
        $script:Kr.Secret = [byte[]]::new(0)
        return
    }
    if (-not (Wait-KrHandshake)) {
        Disconnect-KrEndpoint
        $script:Kr.Secret = [byte[]]::new(0)
        return
    }
    $script:Kr.Registered = $true
    $script:Kr.Managed = $true
    Write-KrTrace 'registered'

    # The secret leaves the exported environment and stays in this module's own memory, where a
    # child process and a user's profile cannot reach it. The integration keeps it because a reader
    # re-established inside the same shell needs it again.
    Remove-Item -Path ('Env:' + $script:KR_ENDPOINT_VARIABLE) -ErrorAction SilentlyContinue
    Remove-Item -Path ('Env:' + $script:KR_SECRET_VARIABLE) -ErrorAction SilentlyContinue

    Install-KrReadLineWrapper
    Start-KrSignal
}

# The host's own read-line entry point, with the reader's boundaries around it.
function Install-KrReadLineWrapper {
    $existing = Get-Command -Name 'PSConsoleHostReadLine' -CommandType Function -ErrorAction SilentlyContinue
    if ($null -ne $existing) { $script:Hooks.InnerReadLine = $existing.ScriptBlock }
    Set-Item -Path function:global:PSConsoleHostReadLine -Value {
        Invoke-KalaReachReadLine
    }
}

function Start-KrSignal {
    if ($null -ne $script:Hooks.Timer) { return }
    $timer = [System.Timers.Timer]::new()
    $timer.Interval = $script:SignalIntervalMs
    # The signal keeps coming on its own. The work behind it is a poll of a socket and nothing
    # else: no command of this module's runs on the reader's thread, so a signal the reader takes
    # a moment to reach is answered rather than piling up behind one that never arrives.
    $timer.AutoReset = $true
    # The signal: the host delivers this event on the reader's own thread, inside its read loop,
    # which is where the mailbox can be answered with the editor's real state.
    $script:Hooks.Subscription = Register-ObjectEvent -InputObject $timer -EventName Elapsed `
        -SourceIdentifier 'KalaReach.ShellBridge.Signal' -Action { Invoke-KalaReachService }
    $timer.Start()
    $script:Hooks.Timer = $timer
}

function Stop-KrSignal {
    if ($null -ne $script:Hooks.Timer) {
        try { $script:Hooks.Timer.Stop(); $script:Hooks.Timer.Dispose() } catch { }
        $script:Hooks.Timer = $null
    }
    if ($null -ne $script:Hooks.Subscription) {
        try { Unregister-Event -SourceIdentifier 'KalaReach.ShellBridge.Signal' -ErrorAction SilentlyContinue } catch { }
        $script:Hooks.Subscription = $null
    }
}

# ---- the user-facing hooks, after the profile has run -----------------------------------------------

function Enable-KalaReachHooks {
    <#
    .SYNOPSIS
    Says, once, that the user-facing hooks are live, after the profile and before the first reader.
    #>
    [CmdletBinding()]
    param()

    if ($script:Hooks.Activated -or -not $script:Kr.Registered) { return }
    $script:Hooks.Activated = $true

    $installed = Install-KrObservedHandlers
    Write-KrTrace ("wrapped " + (@($installed) -join ' '))
    $gesture = Install-KrGestureHandler
    Write-KrTrace ("gesture chord=$($script:Hooks.GestureChord) ok=$($gesture.Ok) $($gesture.Reason) $($gesture.Detail)")
    Send-KrHooksActivated ([uint64]($script:State.PromptGeneration + 1))

    if (-not $gesture.Ok) {
        # An explicitly incompatible binding is diagnosed rather than silently replaced.
        Send-KrIntegrationLost 'post_startup_failure' $gesture.Detail
        Write-KrDiagnostic $gesture.Reason $gesture.Detail
    }
    $script:Hooks.Wrapped = $installed
}

function Install-KrObservedHandlers {
    $wrapped = [System.Collections.Generic.List[string]]::new()
    $bound = try { Get-PSReadLineKeyHandler -Bound } catch { @() }
    foreach ($observed in $script:Observed) {
        foreach ($binding in @($bound | Where-Object { $_.Function -eq $observed.Function })) {
            $chord = $binding.Key
            $name = $observed.Function
            $pending = $observed.Pending
            $block = [scriptblock]::Create(
                "param(`$key, `$arg) Invoke-KalaReachPending -Function '$name' -Pending '$pending' -Key `$key -Argument `$arg")
            try {
                Set-PSReadLineKeyHandler -Chord $chord -ScriptBlock $block `
                    -BriefDescription $name -Description "KalaReach: $name"
                $wrapped.Add("$chord=$name")
            } catch {
                Write-KrTrace "wrap failed $chord $name : $($_.Exception.Message)"
            }
        }
    }
    $wrapped
}

# The named handler: this module's decision goes in front of whatever was on the gesture key.
function Install-KrGestureHandler {
    $chord = $script:Kr.GestureChord
    if ($null -eq $chord) {
        if ($script:Kr.GestureDisabled) { return @{ Ok = $true; Reason = ''; Detail = '' } }
        $chord = Get-KrChordForByte ([int]$script:Kr.GestureByte)
    }
    if ($null -eq $chord) {
        return @{ Ok = $false; Reason = 'gesture_unmappable'
                  Detail = "the configured gesture has no chord on this editor" }
    }

    $previous = try { Get-PSReadLineKeyHandler -Chord $chord -ErrorAction SilentlyContinue } catch { $null }
    $before = $null
    if ($null -ne $previous) {
        if ($previous.Function -eq 'CustomAction') {
            $before = Get-KrCustomHandler $chord
            if ($null -eq $before) {
                return @{ Ok = $false; Reason = 'gesture_handler_unreadable'
                          Detail = "a user handler on $chord could not be preserved" }
            }
        } else {
            $before = $previous.Function
        }
    }
    $script:Hooks.GestureBefore = $before
    $script:Hooks.GestureChord = $chord
    try {
        Set-PSReadLineKeyHandler -Chord $chord -ScriptBlock { param($key, $arg) Invoke-KalaReachGesture -Key $key -Argument $arg } `
            -BriefDescription 'KalaReachDetach' -Description 'KalaReach: detach at an empty root prompt'
    } catch {
        return @{ Ok = $false; Reason = 'gesture_bind_failed'; Detail = "$($_.Exception.Message)" }
    }
    @{ Ok = $true; Reason = ''; Detail = '' }
}

# The script block behind a user's own handler, so it keeps running outside the detach condition.
function Get-KrCustomHandler {
    param([string]$Chord)
    try {
        $type = [Microsoft.PowerShell.PSConsoleReadLine]
        $singleton = $type.GetField('_singleton', 'NonPublic,Static').GetValue($null)
        $table = $type.GetField('_dispatchTable', 'NonPublic,Instance').GetValue($singleton)
        foreach ($entry in $table.GetEnumerator()) {
            if ("$($entry.Key)" -eq $Chord -and $null -ne $entry.Value.ScriptBlock) {
                return $entry.Value.ScriptBlock
            }
        }
    } catch { }
    $null
}

function Restore-KrGestureHandler {
    $chord = $script:Hooks.GestureChord
    if ($null -eq $chord) { return }
    $before = $script:Hooks.GestureBefore
    try {
        if ($null -eq $before) {
            Remove-PSReadLineKeyHandler -Chord $chord -ErrorAction SilentlyContinue
        } elseif ($before -is [scriptblock]) {
            Set-PSReadLineKeyHandler -Chord $chord -ScriptBlock $before
        } else {
            Set-PSReadLineKeyHandler -Chord $chord -Function $before
        }
    } catch { }
    $script:Hooks.GestureChord = $null
    $script:Hooks.GestureBefore = $null
}

# ---- what the reader calls ---------------------------------------------------------------------------

function Invoke-KalaReachReadLine {
    <#
    .SYNOPSIS
    The host's read-line entry point, with the reader's own boundaries around it.
    #>
    [CmdletBinding()]
    param()

    Write-KrTrace 'readline wrapper entered'
    if (-not $script:Hooks.Activated) {
        # The profile has run by the time the host asks for a line, and the reader has not started.
        Enable-KalaReachHooks
    }
    $script:State.PromptGeneration++
    $script:State.ReaderRevision++
    $script:State.InsideReader++
    $script:State.Installed = ''
    $script:State.AcceptRequested = $false
    $script:State.CancelRequested = $false
    $script:State.IdleReported = $false
    $script:State.InvokingKeys = [byte[]]::new(0)
    $script:State.EntryReported = $false
    $script:State.ReaderThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $script:State.BufferSeen = ''
    $script:State.BufferRevision++
    # Read here, where the runspace is this function's own, and used by the reader's own thread.
    $script:State.EditMode = try { "$((Get-PSReadLineOption).EditMode)" } catch { 'Emacs' }
    Send-KrEditorEnter
    $script:State.EntryReported = $true

    $accepted = $false
    try {
        $line = [Microsoft.PowerShell.PSConsoleReadLine]::ReadLine($Host.Runspace, $ExecutionContext, $true)
        $accepted = $null -ne $line
        $line
    } finally {
        $script:State.InsideReader--
        $script:State.EntryReported = $false
        if ($script:Kr.Registered) {
            if ($accepted) {
                # The accepted line is reported from inside the fence, before the leave that
                # invalidates it.
                Send-KrCommandAccepted
                Send-KrEditorLeave 'command_accepted'
            } else {
                Send-KrEditorLeave 'cancellation'
            }
        }
        $script:Kr.Hinted = $false
    }
}

function Invoke-KalaReachService {
    <#
    .SYNOPSIS
    Reads the mailbox and answers what is in it, on the reader's own thread.
    #>
    [CmdletBinding()]
    param()

    # The reader's own thread and no other. The host decides where it delivers this signal, and
    # the editor's state belongs to the thread that is reading: touching it from anywhere else
    # would be reaching into a reader that is running.
    if ([System.Threading.Thread]::CurrentThread.ManagedThreadId -ne $script:State.ReaderThreadId) {
        return
    }
    try {
        if (-not $script:Kr.Registered) { return }
        if ($script:State.InsideReader -le 0 -or -not $script:State.EntryReported) { return }
        if (-not $script:State.IdleReported) {
            # The reader has nothing left to read, which is one of the three points a worker
            # retries a withheld fence at.
            $script:State.IdleReported = $true
            Send-KrReaderIdle
        }
        Invoke-KrService
    } catch {
        # The reader is never left without its signal because one answer went wrong.
        Write-KrTrace "service failed: $($_.Exception.GetType().FullName): $($_.Exception.Message)"
    }
}

function Invoke-KalaReachPending {
    <#
    .SYNOPSIS
    Runs one of the editor's own operations with the state it waits in recorded.
    #>
    [CmdletBinding()]
    param([string]$Function, [string]$Pending, $Key, $Argument)

    $script:Pending[$Pending]++
    $script:State.IdleReported = $false
    # The sequence that invoked this operation is what the reader is in the middle of, and it is
    # the person's own: anything the worker asks for waits behind it.
    $previousKeys = $script:State.InvokingKeys
    if ($null -ne $Key -and $Key.KeyChar -ne [char]0) {
        $script:State.InvokingKeys = [byte[]]@([byte]([int]$Key.KeyChar -band 0xFF))
    } else {
        $script:State.InvokingKeys = [byte[]]@([byte]0x1b)
    }
    try {
        $type = [Microsoft.PowerShell.PSConsoleReadLine]
        $method = $type.GetMethod($Function, [type[]]@([System.Nullable[System.ConsoleKeyInfo]], [object]))
        if ($null -ne $method) { $method.Invoke($null, @($Key, $Argument)) | Out-Null }
    } finally {
        $script:Pending[$Pending]--
        $script:State.InvokingKeys = $previousKeys
        $script:State.CancelRequested = $false
        $script:State.IdleReported = $false
    }
}

function Invoke-KalaReachGesture {
    <#
    .SYNOPSIS
    The end-of-file decision, taken with the actual reader context.
    #>
    [CmdletBinding()]
    param($Key, $Argument)

    # The mailbox is read first: the fence this decision rests on is the one the worker last
    # published, and a frame already on the endpoint belongs before this key.
    Invoke-KrService

    $byte = 0
    if ($null -ne $Key -and $Key.KeyChar -ne [char]0) { $byte = [int]$Key.KeyChar }
    $script:State.InvokingKeys = [byte[]]@([byte]($byte -band 0xFF))
    $decision = Invoke-KrPreEof $byte 'terminal'
    if ($decision -eq 'consume') { return }

    # Outside the detach condition the previous function or script block runs.
    $before = $script:Hooks.GestureBefore
    if ($null -eq $before) {
        try { [Microsoft.PowerShell.PSConsoleReadLine]::DeleteCharOrExit($Key, $Argument) } catch { }
        return
    }
    if ($before -is [scriptblock]) {
        & $before $Key $Argument
        return
    }
    $type = [Microsoft.PowerShell.PSConsoleReadLine]
    $method = $type.GetMethod([string]$before, [type[]]@([System.Nullable[System.ConsoleKeyInfo]], [object]))
    if ($null -ne $method) { $method.Invoke($null, @($Key, $Argument)) | Out-Null }
}

function Test-KalaReachBridge {
    <#
    .SYNOPSIS
    Whether this shell registered as a managed root shell.
    #>
    [CmdletBinding()]
    param()
    $script:Kr.Registered
}

function Write-KalaReachLoss {
    <#
    .SYNOPSIS
    Reports that the ground the integration stood on has gone.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('post_startup_failure', 'semantic_hook_loss', 'bridge_disconnected',
                     'unqualified_root_replacement')]
        [string]$Loss = 'semantic_hook_loss',
        [string]$Detail = ''
    )
    Send-KrIntegrationLost $Loss $Detail
}

# ---- publishing the qualification ------------------------------------------------------------------

function Get-KrCacheRoot {
    if ($env:KR_SHELL_PREFIX) { return $env:KR_SHELL_PREFIX }
    if ($IsMacOS) { return (Join-Path $HOME 'Library/Caches/kalareach/shells') }
    if ($env:XDG_CACHE_HOME) { return (Join-Path $env:XDG_CACHE_HOME 'kalareach/shells') }
    Join-Path $HOME '.cache/kalareach/shells'
}

function Get-KrFileDigest {
    param([string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# What the recorded executable needs in its environment to start at all.
function Get-KrLaunchEnvironment {
    $environment = [ordered]@{}
    foreach ($name in @('DOTNET_ROOT', "DOTNET_ROOT_$($env:PROCESSOR_ARCHITECTURE)", 'DOTNET_ROOT_ARM64', 'DOTNET_ROOT_X64')) {
        if ([string]::IsNullOrEmpty($name)) { continue }
        $value = [Environment]::GetEnvironmentVariable($name)
        if (-not [string]::IsNullOrEmpty($value) -and -not $environment.Contains($name)) {
            $environment[$name] = $value
        }
    }
    $environment
}

function Publish-KalaReachQualification {
    <#
    .SYNOPSIS
    Qualifies this host's PowerShell and PSReadLine against the package and records what it found.

    .DESCRIPTION
    This package builds no shell, so there is nothing to compile and nothing to install into the
    shell's own tree. What it publishes instead is the qualification: the editor it binds into, the
    versions it was qualified against, and a digest of the module and the manifest that were
    qualified, so the same inputs name the same package and a rebuilt module is a different one.
    #>
    [CmdletBinding()]
    param([string]$Prefix)

    $packageRoot = Split-Path -Parent $script:ModuleRoot
    $manifestPath = Join-Path $packageRoot 'manifest.json'
    $manifest = Get-Content -Raw -Path $manifestPath | ConvertFrom-Json

    $qualified = Test-KrQualifiedEditor
    if (-not $qualified.Ok) {
        throw "kalareach: $($qualified.Reason): $($qualified.Detail)"
    }
    $identityInfo = Get-KrPackageIdentity
    $psrl = Get-KrPSReadLineVersion

    $inputs = [System.Collections.Generic.List[string]]::new()
    $inputs.Add('kr-shell-package/1')
    $inputs.Add("shell=$($manifest.shell)")
    $inputs.Add("manifest=$(Get-KrFileDigest $manifestPath)")
    foreach ($file in (Get-ChildItem -Path $script:ModuleRoot -File | Sort-Object Name)) {
        $inputs.Add("module=$(Get-KrFileDigest $file.FullName) $($file.Name)")
    }
    $startupSource = Join-Path $packageRoot $manifest.startup.file
    $inputs.Add("startup=$(Get-KrFileDigest $startupSource) $($manifest.startup.file)")
    $inputs.Add("powershell=$($PSVersionTable.PSVersion)")
    $inputs.Add("psreadline=$psrl")
    $inputs.Add("executable=$($identityInfo.executable)")

    $blob = [System.Text.Encoding]::UTF8.GetBytes(($inputs -join "`n") + "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = ($sha.ComputeHash($blob) | ForEach-Object { $_.ToString('x2') }) -join '' }
    finally { $sha.Dispose() }
    $identity = $digest.Substring(0, 16)

    if ([string]::IsNullOrEmpty($Prefix)) { $Prefix = Get-KrCacheRoot }
    $destination = Join-Path (Join-Path $Prefix $manifest.shell) $identity
    if (Test-Path $destination) { Remove-Item -Recurse -Force $destination }
    # The module goes where a module path can find it by name, so the marked profile block needs
    # no path of its own and the person's own module path is added to rather than replaced.
    $modules = Join-Path (Join-Path $destination 'modules') 'KalaReach.ShellBridge'
    New-Item -ItemType Directory -Force -Path $modules | Out-Null
    New-Item -ItemType Directory -Force -Path (Join-Path $destination 'startup') | Out-Null
    Copy-Item -Path (Join-Path $script:ModuleRoot '*') -Destination $modules -Recurse -Force
    Copy-Item -Path $startupSource -Destination (Join-Path $destination 'startup') -Force

    $record = [ordered]@{
        identity      = $identity
        shell         = [ordered]@{
            kind                = $manifest.shell
            executable          = $identityInfo.executable
            upstream_version    = $identityInfo.upstream_version
            editor_abi          = $identityInfo.editor_abi
            integration_version = $identityInfo.integration_version
            patches             = @()
            modules             = @(
                [ordered]@{ name = 'KalaReach.ShellBridge'
                            search_path = (Join-Path $destination 'modules')
                            editor_abi = $identityInfo.editor_abi }
                [ordered]@{ name = 'PSReadLine'
                            search_path = "$((Get-Module PSReadLine -ListAvailable | Sort-Object Version -Descending | Select-Object -First 1).ModuleBase)"
                            editor_abi = $identityInfo.editor_abi }
            )
        }
        abi           = [ordered]@{
            mailbox         = $manifest.mailbox_mechanism
            pre_eof         = $manifest.pre_eof_mechanism
            fence_proof     = 'atomic_reader_state'
            cancellation    = 'non_destructive_key_wait'
            launch_delivery = 'reader_mailbox'
        }
        build         = [ordered]@{
            upstream       = [ordered]@{
                archive = ''
                url     = $manifest.upstream.url
                sha256  = ''
            }
            configure      = @()
            cflags         = @()
            inputs_sha256  = $digest
            toolchain      = "powershell $($PSVersionTable.PSVersion); psreadline $psrl"
            upstream_tests = 'not run: this package builds no shell'
        }
        startup_entry = [ordered]@{
            file       = $manifest.startup.file
            target     = $manifest.startup.target
            marker     = $manifest.startup.marker
            end_marker = $manifest.startup.end_marker
        }
        qualified     = [ordered]@{
            psreadline_from   = $script:QualifiedFrom.ToString()
            psreadline_before = $script:QualifiedBefore.ToString()
            psreadline_found  = "$psrl"
        }
        # The host's own image needs its runtime's location, which the launcher that started this
        # one passed in. A worker that starts the recorded executable directly needs the same.
        launch        = [ordered]@{
            environment = Get-KrLaunchEnvironment
        }
    }
    $record | ConvertTo-Json -Depth 8 | Set-Content -Path (Join-Path $destination 'kr-shell-identity.json')
    Set-Content -Path (Join-Path (Join-Path $Prefix $manifest.shell) 'current') -Value $identity

    [pscustomobject]@{
        Identity   = $identity
        Directory  = $destination
        Executable = $identityInfo.executable
        EditorAbi  = $identityInfo.editor_abi
        PSReadLine = "$psrl"
    }
}

function Remove-KalaReachHooks {
    <#
    .SYNOPSIS
    Takes off everything this module installed, leaving the editor as it found it.
    #>
    [CmdletBinding()]
    param()
    Stop-KrSignal
    Restore-KrGestureHandler
    if ($null -ne $script:Hooks.InnerReadLine) {
        Set-Item -Path function:global:PSConsoleHostReadLine -Value $script:Hooks.InnerReadLine
    }
    $script:Hooks.Activated = $false
}

$ExecutionContext.SessionState.Module.OnRemove = { Remove-KalaReachHooks }

Export-ModuleMember -Function @(
    'Initialize-KalaReachBridge'
    'Enable-KalaReachHooks'
    'Invoke-KalaReachReadLine'
    'Invoke-KalaReachService'
    'Invoke-KalaReachPending'
    'Invoke-KalaReachGesture'
    'Test-KalaReachBridge'
    'Write-KalaReachLoss'
    'Publish-KalaReachQualification'
    'Remove-KalaReachHooks'
)

# The bridge loads with the module: the marked profile block imports it before the first prompt.
Write-KrTrace 'module loaded'
Initialize-KalaReachBridge
