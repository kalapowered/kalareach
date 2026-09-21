# The KalaReach root-editor bridge for PowerShell, bound into the installed PSReadLine.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# This package rebuilds no shell. PSReadLine is the line editor the person already has, and this
# module binds into it: it wraps the host's read-line entry point for the reader's own boundaries,
# it wraps the editor's own functions to observe the operations that wait for another key, and it
# puts its end-of-file decision on the configured gesture in front of whatever was bound there.
# A handler the person wrote themselves is never replaced, and everything this module installs
# comes off again with it.
#
# The reader thread is where all of it runs, and only where the reader is between operations: at
# the read-line entry, after each of the editor's own operations has run, and in the gesture
# handler. This editor publishes no asynchronous editing method, so a request that reaches a
# parked reader is answered at its next step rather than at once.

Set-StrictMode -Version 3.0

$script:ModuleRoot = $PSScriptRoot
. (Join-Path $script:ModuleRoot 'KrCbor.ps1')
. (Join-Path $script:ModuleRoot 'KrReader.ps1')
. (Join-Path $script:ModuleRoot 'KrBridge.ps1')

# The PSReadLine versions this package was qualified against.
$script:QualifiedFrom = [version]'2.3.4'
$script:QualifiedBefore = [version]'3.0.0'
$script:IntegrationVersion = '1'

$script:Hooks = @{
    Activated          = $false
    GestureChord       = $null
    GestureBefore      = $null
    Wrapped            = [System.Collections.Generic.List[hashtable]]::new()
    InnerReadLine      = $null
    ReadLineInstalled  = $false
}

# The operations whose key wait this module observes by wrapping them. Each runs its own read loop
# inside the handler, so being inside the wrapper is exactly being in the middle of the operation.
# Everything else the editor has bound is wrapped too, so that the reader has a boundary of its own
# to answer at once the key has run.
# The editor's own ways of ending a read without a line: what follows them is a cancellation
# rather than an accepted command.
$script:Cancelling = @('CancelLine', 'CopyOrCancelLine')

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

function Get-KrPackageRoot {
    <#
    .SYNOPSIS
    The installed package this module was imported from, or nothing when it was not.

    .DESCRIPTION
    A published package holds the module at <package>/modules/KalaReach.ShellBridge, so the
    package is two directories up and its identity record sits there. A module imported from the
    source tree has neither, and says so by answering with nothing.
    #>
    $root = Split-Path -Parent (Split-Path -Parent $script:ModuleRoot)
    if ([string]::IsNullOrEmpty($root)) { return $null }
    if (-not (Test-Path (Join-Path $root 'kr-shell-identity.json'))) { return $null }
    $root
}

function Get-KrLauncherName {
    'pwsh'
}

function ConvertTo-KrShellWord {
    <#
    .SYNOPSIS
    One literal word for a POSIX shell, whatever it holds.

    .DESCRIPTION
    Single quotes make everything literal except a single quote, which is written by closing the
    quoting, escaping the character and opening it again. A path with an apostrophe in it is a
    path, not a syntax error.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    "'" + $Value.Replace("'", "'\''") + "'"
}

function Get-KrPackageIdentity {
    <#
    .SYNOPSIS
    What this package declares about itself.

    .DESCRIPTION
    Every path here is the package's own. This package builds no shell: what it installs is the
    launcher that starts the host it was qualified against, the module that binds into that host's
    editor, and the marked startup entry. The host and the editor it qualified are recorded as
    what was qualified rather than as things this package ships, because they are the person's.
    #>
    $version = Get-KrPSReadLineVersion
    $abi = if ($null -eq $version) { 'psreadline-unknown' } else { "psreadline-$($version.Major).$($version.Minor)" }
    $root = Get-KrPackageRoot
    $executable = if ($null -eq $root) {
        try { [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
        catch { Join-Path $PSHOME 'pwsh' }
    } else {
        Join-Path (Join-Path $root 'bin') (Get-KrLauncherName)
    }
    $searchPath = if ($null -eq $root) { $script:ModuleRoot } else { Join-Path $root 'modules' }
    @{
        executable          = $executable
        upstream_version    = $PSVersionTable.PSVersion.ToString()
        editor_abi          = $abi
        integration_version = $script:IntegrationVersion
        patches             = @()
        modules             = @(
            @{ name = 'KalaReach.ShellBridge'; search_path = $searchPath; editor_abi = $abi }
        )
    }
}

function Get-KrQualifiedHost {
    <#
    .SYNOPSIS
    The host and the editor this package was qualified against, as this process found them.
    #>
    $executable = try {
        [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    } catch {
        Join-Path $PSHOME 'pwsh'
    }
    $psrlPath = try { (Get-Module PSReadLine).ModuleBase } catch { '' }
    @{ executable = $executable; psreadline_module_base = "$psrlPath" }
}

function Get-KrPublishedQualification {
    <#
    .SYNOPSIS
    What the installed package this module was imported from says it was qualified against.

    .DESCRIPTION
    A published package records the editor the qualification ran against, which is the person's
    own PSReadLine rather than anything the package installs. This reads that record back so the
    editor in this process can be compared with it. A module imported from the source tree belongs
    to no package and answers with nothing.
    #>
    $root = Get-KrPackageRoot
    if ($null -eq $root) { return $null }
    $record = Join-Path $root 'kr-shell-identity.json'
    $answer = @{ Path = $record; ModuleBase = ''; Version = '' }
    $qualified = try {
        (Get-Content -Raw -Path $record | ConvertFrom-Json).PSObject.Properties['qualified']
    } catch { $null }
    if ($null -eq $qualified -or $null -eq $qualified.Value) { return $answer }
    # Each field is taken from the record's own property list rather than read off it by name: a
    # record that holds a qualification with a field missing is a record that says nothing about
    # that field, and asking for it by name would end this function rather than answer it.
    foreach ($field in @(@{ From = 'psreadline_module_base'; To = 'ModuleBase' },
                         @{ From = 'psreadline_found'; To = 'Version' })) {
        $property = $qualified.Value.PSObject.Properties[$field.From]
        if ($null -ne $property) { $answer[$field.To] = "$($property.Value)" }
    }
    $answer
}

function Get-KrResolvedPath {
    <#
    .SYNOPSIS
    A path with every link on the way to it followed, not only one at its end.

    .DESCRIPTION
    Used where the filesystem will not name a directory for this module: each component is resolved
    from the last back to the root, so a link anywhere above the name is followed as well, and each
    name is then replaced by the one the directory above it holds. A filesystem that matches a name
    without regard to case answers one spelling for both, and one that keeps two names differing
    only in case answers each of them for itself, because a name it holds exactly as asked is the
    one it means. The recursion is bounded, and a component nothing can be read for is left as it
    was written.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path, [int]$Depth = 0)

    if ([string]::IsNullOrEmpty($Path) -or $Depth -ge 64) { return $Path }
    $item = try { Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { $null }
    if ($null -eq $item) { return $Path }
    $target = try { $item.ResolveLinkTarget($true) } catch { $null }
    if ($null -ne $target) { $item = $target }
    $full = "$($item.FullName)"
    $parent = try { [System.IO.Path]::GetDirectoryName($full) } catch { '' }
    $name = try { [System.IO.Path]::GetFileName($full) } catch { '' }
    if ([string]::IsNullOrEmpty($parent) -or [string]::IsNullOrEmpty($name)) { return $full }
    $above = Get-KrResolvedPath -Path $parent -Depth ($Depth + 1)
    [System.IO.Path]::Combine($above, (Get-KrSpelling $above $name))
}

function Get-KrSpelling {
    <#
    .SYNOPSIS
    How the directory `Above` spells the name `Name`, as that directory itself answers it.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Above,
          [Parameter(Mandatory)][AllowEmptyString()][string]$Name)

    $entries = try {
        [System.IO.Directory]::GetFileSystemEntries($Above, $Name)
    } catch { @() }
    $spellings = @()
    foreach ($entry in @($entries)) {
        $spelt = "$([System.IO.Path]::GetFileName($entry))"
        # Held exactly as asked for, so this directory means this name and no other.
        if ([string]::Equals($spelt, $Name, [System.StringComparison]::Ordinal)) { return $Name }
        if ([string]::Equals($spelt, $Name, [System.StringComparison]::OrdinalIgnoreCase)) {
            $spellings += $spelt
        }
    }
    # One entry under another case is that name reached by another spelling. Several would be a
    # directory that keeps them apart, which the exact match above would have answered.
    if ($spellings.Count -eq 1) { return $spellings[0] }
    $Name
}

function Get-KrPathIdentity {
    <#
    .SYNOPSIS
    What the filesystem says a directory is, rather than how the path to it is spelt.

    .DESCRIPTION
    One directory has many paths: a link at the end of the path, a link in one of the directories
    above it, or a name this filesystem matches without regard to case. Two directories stay two
    directories even where their names differ only in case, wherever the filesystem keeps both.
    Nothing in a path says which of those two situations a pair of spellings is in, so the
    filesystem is asked instead: the device and the inode it reports name one directory whatever
    path led to it, and the read that gets them follows the links above the name for free. Where it
    reports neither, which is every filesystem that is not a Unix one, the answer is the path with
    every link followed and every name spelt as the directory holding it spells it. A path nothing
    can be read for is its own identity, equal to itself and to no other.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return '' }
    $item = try { Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { $null }
    if ($null -eq $item) { return "path $Path" }
    # A link at the end of the path is followed to what it names: the directory the editor was
    # loaded from is the question, not the link somebody reached it through.
    $target = try { $item.ResolveLinkTarget($true) } catch { $null }
    if ($null -ne $target) {
        $item = try { Get-Item -LiteralPath $target.FullName -Force -ErrorAction Stop } catch { $item }
    }
    $stat = $item.PSObject.Properties['UnixStat']
    if ($null -ne $stat -and $null -ne $stat.Value) {
        return "device $($stat.Value.DeviceId) inode $($stat.Value.Inode)"
    }
    "path $(Get-KrResolvedPath "$($item.FullName)")"
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
    # This package builds no editor: it binds into the one the person has, and the qualification
    # it publishes names exactly which one that was. A supported range is not that answer, because
    # two installations can be in one range and only one of them was qualified. So a package says
    # yes only to an editor at the directory the record names, at the version it names. What the
    # record holds is that directory and that version, so an editor loaded from somewhere else, or
    # at another version, is diagnosed here; a different installation put at the recorded directory
    # under the recorded version is not something this record can tell apart.
    $published = Get-KrPublishedQualification
    if ($null -ne $published) {
        if ([string]::IsNullOrEmpty($published.ModuleBase) -or
            [string]::IsNullOrEmpty($published.Version)) {
            return @{
                Ok     = $false
                Reason = 'package_qualification_unreadable'
                Detail = "$($published.Path) does not say which editor this package was qualified against"
            }
        }
        $base = try { "$((Get-Module PSReadLine).ModuleBase)" } catch { '' }
        # What the filesystem calls each directory, rather than how each path is spelt: a module
        # search path can reach one editor by several spellings, and a filesystem that keeps two
        # directories whose names differ only in case keeps two editors.
        $here = Get-KrPathIdentity $base
        $there = Get-KrPathIdentity $published.ModuleBase
        if (-not [string]::Equals("$version", $published.Version, [System.StringComparison]::Ordinal) -or
            -not [string]::Equals($here, $there, [System.StringComparison]::Ordinal)) {
            return @{
                Ok     = $false
                Reason = 'psreadline_not_the_qualified_editor'
                Detail = "PSReadLine $version at '$base' is not the $($published.Version) at '$($published.ModuleBase)' this package was qualified against"
            }
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
}

# The host's own read-line entry point, with the reader's boundaries around it.
function Install-KrReadLineWrapper {
    $existing = Get-Command -Name 'PSConsoleHostReadLine' -CommandType Function -ErrorAction SilentlyContinue
    if ($null -ne $existing) { $script:Hooks.InnerReadLine = $existing.ScriptBlock }
    # `$?` is the status of the command the person just ran, and this editor shows it. It is read
    # here, as the host's own entry point does, because anything else run first would replace it.
    Set-Item -Path function:global:PSConsoleHostReadLine -Value {
        Invoke-KalaReachReadLine -LastStatus $?
    }
    $script:Hooks.ReadLineInstalled = $true
}

# True when the read-line entry point this module went in front of is this editor's own.
#
# A reader of somebody else's is a root-shell replacement rather than the editor this package was
# qualified against, and it is reported by name instead of being bypassed.
function Test-KrInnerReadLine {
    $inner = $script:Hooks.InnerReadLine
    if ($null -eq $inner) { return $true }
    "$inner" -match 'PSConsoleReadLine\]::ReadLine'
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

    if (-not (Test-KrInnerReadLine)) {
        # Somebody else's reader was already the host's entry point, so the editor this package
        # was qualified against is not the one reading this shell.
        Send-KrIntegrationLost 'post_startup_failure' 'another read-line entry point is installed'
        Write-KrDiagnostic 'reader_replaced' 'another read-line entry point is installed'
        Send-KrHooksActivated ([uint64]($script:State.PromptGeneration + 1))
        return
    }

    $installed = Install-KrObservedHandlers
    Write-KrTrace ("wrapped " + ((@($installed) | ForEach-Object { "$($_.Chord)=$($_.Function)" }) -join ' '))
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

# Puts this module in front of every key the editor has a binding for.
#
# This is where the reader reaches its own queue: the wrapper reads the mailbox and then runs the
# editor's own function, so a request the worker sent is answered at the reader's next key, on the
# reader's own thread, with the editor between operations. The few operations that run an inner
# read loop also record the state they wait in. A handler the person wrote themselves is left
# exactly as it is.
function Install-KrObservedHandlers {
    $wrapped = [System.Collections.Generic.List[hashtable]]::new()
    $bound = try { Get-PSReadLineKeyHandler -Bound } catch { @() }
    $pendingFor = @{}
    foreach ($observed in $script:Observed) { $pendingFor[$observed.Function] = $observed.Pending }
    # What the person wrote themselves, read from the editor's own table rather than from the
    # description a handler carries: a script of theirs can be described by any name at all,
    # including the name of one of the editor's own operations.
    $theirs = Get-KrScriptChords
    foreach ($binding in @($bound)) {
        $name = "$($binding.Function)"
        $chord = "$($binding.Key)"
        if ([string]::IsNullOrEmpty($name) -or $name -eq 'CustomAction') { continue }
        if ($theirs.PSBase.ContainsKey($chord)) { continue }
        if ($null -eq [Microsoft.PowerShell.PSConsoleReadLine].GetMethod(
                $name, [type[]]@([System.Nullable[System.ConsoleKeyInfo]], [object]))) {
            # Not one of this editor's own operations, whatever it is called.
            continue
        }
        $pending = if ($pendingFor.PSBase.ContainsKey($name)) { $pendingFor[$name] } else { '' }
        $block = [scriptblock]::Create(
            "param(`$key, `$arg) Invoke-KalaReachPending -Function '$name' -Pending '$pending' -Key `$key -Argument `$arg")
        try {
            Set-PSReadLineKeyHandler -Chord $chord -ScriptBlock $block `
                -BriefDescription $name -Description "KalaReach: $name"
            $wrapped.Add(@{ Chord = $chord; Function = $name })
        } catch {
            Write-KrTrace "wrap failed $chord $name : $($_.Exception.Message)"
        }
    }
    $wrapped
}

# Puts back every operation of the editor's own that this module went in front of.
#
# Only the ones it still owns: a chord the person has bound since is theirs, and it stays as they
# left it.
function Restore-KrObservedHandlers {
    foreach ($entry in @($script:Hooks.Wrapped)) {
        $current = try {
            Get-PSReadLineKeyHandler -Chord $entry.Chord -ErrorAction SilentlyContinue
        } catch { $null }
        if ($null -eq $current -or "$($current.Description)" -ne "KalaReach: $($entry.Function)") {
            continue
        }
        try { Set-PSReadLineKeyHandler -Chord $entry.Chord -Function $entry.Function } catch {
            Write-KrTrace "restore failed $($entry.Chord): $($_.Exception.Message)"
        }
    }
    $script:Hooks.Wrapped = @()
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
    # A script of the person's is theirs whatever it is called, so it is read from the editor's own
    # table rather than from the description the binding carries.
    $before = Get-KrCustomHandler $chord
    if ($null -eq $before -and $null -ne $previous) {
        if ($previous.Function -eq 'CustomAction') {
            return @{ Ok = $false; Reason = 'gesture_handler_unreadable'
                      Detail = "a user handler on $chord could not be preserved" }
        }
        $before = $previous.Function
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

# Every chord the person has put a script of their own on, with the script.
function Get-KrScriptChords {
    $chords = @{}
    try {
        $type = [Microsoft.PowerShell.PSConsoleReadLine]
        $singleton = $type.GetField('_singleton', 'NonPublic,Static').GetValue($null)
        $table = $type.GetField('_dispatchTable', 'NonPublic,Instance').GetValue($singleton)
        foreach ($entry in $table.GetEnumerator()) {
            if ($null -ne $entry.Value.ScriptBlock) { $chords["$($entry.Key)"] = $entry.Value.ScriptBlock }
        }
        # The two-key chords are a table of their own, and a script of the person's on one of them
        # is theirs in the same way.
        $chordTable = $type.GetField('_chordDispatchTable', 'NonPublic,Instance').GetValue($singleton)
        foreach ($first in $chordTable.GetEnumerator()) {
            foreach ($second in $first.Value.GetEnumerator()) {
                if ($null -ne $second.Value.ScriptBlock) {
                    $chords["$($first.Key),$($second.Key)"] = $second.Value.ScriptBlock
                }
            }
        }
    } catch { }
    $chords
}

# The script block behind a user's own handler, so it keeps running outside the detach condition.
function Get-KrCustomHandler {
    param([string]$Chord)
    $chords = Get-KrScriptChords
    if ($chords.PSBase.ContainsKey($Chord)) { return $chords[$Chord] }
    $null
}

# Moves the gesture to the key the terminal now names, keeping whatever was bound to either.
#
# A person who changes their terminal's own end-of-file character changes which key this decision
# belongs on. The one it was on goes back to what it was doing before.
function Sync-KrGestureHandler {
    $wanted = if ($script:Kr.GestureDisabled) { $null } else {
        if ($null -ne $script:Kr.GestureChord) { $script:Kr.GestureChord }
        else { Get-KrChordForByte ([int]$script:Kr.GestureByte) }
    }
    if ("$wanted" -eq "$($script:Hooks.GestureChord)") { return }
    Restore-KrGestureHandler
    if ($null -eq $wanted) { return }
    $gesture = Install-KrGestureHandler
    if (-not $gesture.Ok) {
        Send-KrIntegrationLost 'post_startup_failure' $gesture.Detail
        Write-KrDiagnostic $gesture.Reason $gesture.Detail
    }
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
    param([bool]$LastStatus = $true)

    $script:State.LastStatus = $LastStatus
    if (-not $script:Hooks.Activated) {
        # The profile has run by the time the host asks for a line, and the reader has not started.
        Enable-KalaReachHooks
    }
    $script:State.PromptGeneration++
    $script:State.ReaderRevision++
    $script:State.InsideReader++
    $script:State.Installed = ''
    $script:State.AcceptRequested = $false
    $script:State.IdleReported = $false
    $script:State.InvokingKeys = [byte[]]::new(0)
    $script:State.Reading = $false
    $script:State.Cancelled = $false
    $script:State.ReaderThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
    $script:State.BufferSeen = ''
    $script:State.BufferRevision++
    # Read here, where the runspace is this function's own, and used by the reader's own thread.
    $script:State.EditMode = try { "$((Get-PSReadLineOption).EditMode)" } catch { 'Emacs' }
    Send-KrEditorEnter
    # The reader is about to read and has nothing left, which is one of the three points a worker
    # retries a withheld fence at. Only the report goes out here: the editor clears its buffer when
    # its read starts, so a line installed before that is a line nobody would ever run, and the
    # mailbox is read at the reader's own next boundary instead.
    Send-KrReaderIdle
    $script:State.IdleReported = $true

    $accepted = $false
    try {
        $line = [Microsoft.PowerShell.PSConsoleReadLine]::ReadLine(
            $Host.Runspace, $ExecutionContext, $script:State.LastStatus)
        # This editor ends an interrupted read the same way it ends an accepted empty one, so what
        # separates them is the operation the person's key ran.
        $accepted = ($null -ne $line) -and -not $script:State.Cancelled
        $line
    } finally {
        $script:State.InsideReader--
        $script:State.Reading = $false
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
    if ($script:State.ReaderThreadId -eq 0 -or
        [System.Threading.Thread]::CurrentThread.ManagedThreadId -ne $script:State.ReaderThreadId) {
        return
    }
    try {
        if (-not $script:Kr.Registered) { return }
        if ($script:State.InsideReader -le 0) { return }
        # What the person typed is theirs and goes first: nothing of the worker's is answered
        # while the editor still has keys of its own to act on.
        if ((Get-KrQueuedKeys) -gt 0) { return }
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

    # The reader is between operations here, which is where its own queue is read. Whatever
    # happens there, the key the person pressed still does what the editor says it does.
    # The editor is reading, which is what makes its buffer this reader's own.
    $script:State.Reading = $true
    if (-not [string]::IsNullOrEmpty($Pending)) { $script:Pending[$Pending]++ }
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
        if (-not [string]::IsNullOrEmpty($Pending)) { $script:Pending[$Pending]-- }
        $script:State.InvokingKeys = $previousKeys
        $script:State.IdleReported = $false
        # The person's key has run and the reader is between operations, which is where its own
        # queue is read. Nothing of the worker's is answered while a key of theirs is still
        # waiting to run: what it would be told, and what it would install, is not what the
        # reader is about to have.
        if ($script:Cancelling -contains $Function) { $script:State.Cancelled = $true }
        try { Invoke-KalaReachService } catch {
            Write-KrTrace "the key boundary did not read the mailbox: $($_.Exception.Message)"
        }
    }
}

function Invoke-KalaReachGesture {
    <#
    .SYNOPSIS
    The end-of-file decision, taken with the actual reader context.
    #>
    [CmdletBinding()]
    param($Key, $Argument)

    # The editor is reading, which is what makes its buffer this reader's own.
    $script:State.Reading = $true
    # The mailbox is read first: the fence this decision rests on is the one the worker last
    # published, and a frame already on the endpoint belongs before this key. Whatever happens
    # there, the key the person pressed still does what the editor says it does.
    try { Invoke-KrService } catch {
        Write-KrTrace "the gesture did not read the mailbox: $($_.Exception.Message)"
    }

    $byte = 0
    if ($null -ne $Key -and $Key.KeyChar -ne [char]0) { $byte = [int]$Key.KeyChar }
    $script:State.InvokingKeys = [byte[]]@([byte]($byte -band 0xFF))
    $decision = Invoke-KrPreEof $byte 'terminal'
    if ($decision -eq 'consume') { return }

    # Outside the detach condition the previous function or script block runs. A key that had
    # nothing bound to it does what this editor does with an unbound key: a printable one goes
    # into the line, and the end-of-file key ends the shell.
    $before = $script:Hooks.GestureBefore
    if ($null -eq $before) {
        $chord = "$($script:Hooks.GestureChord)"
        $native = if ($chord.Length -eq 1) { 'SelfInsert' } else { 'DeleteCharOrExit' }
        try {
            [Microsoft.PowerShell.PSConsoleReadLine]::$native($Key, $Argument)
        } catch { }
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

    # The launcher this package installs, and the only executable it has of its own. It starts the
    # host this qualification found, with the runtime location that host needs: the host itself is
    # the person's and lives wherever they installed it, and a package that recorded their path as
    # its own would be describing an installation it does not hold.
    $qualifiedHost = Get-KrQualifiedHost
    $launchEnvironment = Get-KrLaunchEnvironment
    if ($IsWindows) {
        # A launcher on this platform has to be something the host can start directly, and a batch
        # file is not: the process that starts is the interpreter, and the bridge would then speak
        # from a child of the root process rather than from it. This platform's launch shape is
        # not settled yet, so this publishes no package here rather than one that cannot be
        # launched.
        throw 'kalareach: this package has no Windows launcher yet, so there is nothing to publish on this platform'
    }
    $binaries = Join-Path $destination 'bin'
    New-Item -ItemType Directory -Force -Path $binaries | Out-Null
    $launcher = Join-Path $binaries (Get-KrLauncherName)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('#!/bin/sh')
    $lines.Add('# Starts the PowerShell host this package was qualified against, with the runtime')
    $lines.Add('# location that host needs, and the module this package holds where the host looks')
    $lines.Add('# for modules by name. `exec` keeps the process, so the shell the worker started is')
    $lines.Add('# the one the bridge speaks from.')
    foreach ($name in $launchEnvironment.Keys) {
        $lines.Add("$name=$(ConvertTo-KrShellWord $launchEnvironment[$name]); export $name")
    }
    # Added only when it is not already there. A host started with this package's modules already
    # on its search path would otherwise find the module under two paths, load it twice, and run
    # two sets of hooks over one editor.
    $packageModules = Join-Path $destination 'modules'
    $quotedModules = ConvertTo-KrShellWord $packageModules
    $lines.Add("case `":`${PSModulePath:-}:`" in")
    $lines.Add("    *`":`"$quotedModules`":`"*) ;;")
    $lines.Add("    *) PSModulePath=$quotedModules`"`${PSModulePath:+:`$PSModulePath}`"; export PSModulePath ;;")
    $lines.Add('esac')
    $lines.Add("exec $(ConvertTo-KrShellWord $qualifiedHost.executable) `"`$@`"")
    Set-Content -Path $launcher -Value $lines -Encoding utf8NoBOM
    if (Get-Command chmod -ErrorAction SilentlyContinue) { & chmod 755 $launcher | Out-Null }

    $record = [ordered]@{
        identity      = $identity
        shell         = [ordered]@{
            kind                = $manifest.shell
            executable          = $launcher
            upstream_version    = $identityInfo.upstream_version
            editor_abi          = $identityInfo.editor_abi
            integration_version = $identityInfo.integration_version
            patches             = @()
            modules             = @(
                [ordered]@{ name = 'KalaReach.ShellBridge'
                            search_path = (Join-Path $destination 'modules')
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
        # What this package was qualified against, which is the person's own host and editor. It
        # is recorded here rather than among the paths this package holds, because it is neither
        # installed nor replaced by this package.
        qualified     = [ordered]@{
            psreadline_from        = $script:QualifiedFrom.ToString()
            psreadline_before      = $script:QualifiedBefore.ToString()
            psreadline_found       = "$psrl"
            powershell_executable  = $qualifiedHost.executable
            psreadline_module_base = $qualifiedHost.psreadline_module_base
        }
        # The host's own image needs its runtime's location, which the launcher that started this
        # one passed in. The launcher this package installs sets it, and it is recorded here as
        # well so a worker can see what the launcher does.
        launch        = [ordered]@{
            environment = $launchEnvironment
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
    Restore-KrGestureHandler
    Restore-KrObservedHandlers
    if ($script:Hooks.ReadLineInstalled) {
        if ($null -ne $script:Hooks.InnerReadLine) {
            Set-Item -Path function:global:PSConsoleHostReadLine -Value $script:Hooks.InnerReadLine
        } else {
            Remove-Item -Path function:global:PSConsoleHostReadLine -ErrorAction SilentlyContinue
        }
        $script:Hooks.ReadLineInstalled = $false
    }
    $script:Hooks.Activated = $false
    Disconnect-KrEndpoint
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
Initialize-KalaReachBridge
