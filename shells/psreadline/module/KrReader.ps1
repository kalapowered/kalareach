# PSReadLine's buffer and invocation state, as the contract asks the reader about it.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# Everything the contract asks a package to prove about its reader is read here in one operation,
# at the instant the reader is asked. PSReadLine keeps no counters of its own for a prompt
# generation, a reader revision or a buffer revision, so this file keeps them, and it observes the
# operations that wait for another key by wrapping them rather than by guessing at their state:
# a search, a numeric argument, a character search and a paste all run an inner read loop inside
# the handler this module put in front of them, so "the reader is in the middle of one" is exactly
# "this module is inside that wrapper".

Set-StrictMode -Version 3.0

$script:Rl = [Microsoft.PowerShell.PSConsoleReadLine]

# The states the reader can be in the middle of, counted rather than flagged: a wrapper can nest.
$script:Pending = @{
    search            = 0
    numeric_argument  = 0
    vi_motion         = 0
    paste             = 0
    quoted_insertion  = 0
    multikey_sequence = 0
    macro_input       = 0
}

function Get-KrBufferText {
    $line = $null
    $cursor = 0
    try {
        $script:Rl::GetBufferState([ref]$line, [ref]$cursor)
    } catch {
        return ''
    }
    if ($null -eq $line) { '' } else { $line }
}

function Get-KrBufferCursor {
    $line = $null
    $cursor = 0
    try { $script:Rl::GetBufferState([ref]$line, [ref]$cursor) } catch { return 0 }
    $cursor
}

# The keymap the editor is in.
#
# Read from the editor's own statics, and from the edit mode the reader recorded at its boundary:
# asking the editor for its options runs a command, and the reader's own thread is inside the read
# loop when this is asked, where a command of ours would wait for the runspace holding it.
function Get-KrKeymap {
    param([string]$EditMode)
    try {
        if ($script:Rl::InViCommandMode()) { return 'vi_command' }
        if ($script:Rl::InViInsertMode()) { return 'vi_insert' }
    } catch { }
    switch ($EditMode) {
        'Vi' { 'vi_insert' }
        'Emacs' { 'emacs' }
        'Windows' { 'emacs' }
        default { 'custom' }
    }
}

$script:QueuedKeysField = $null
$script:SingletonField = $null

# How many keys the reader has taken and not yet acted on.
#
# The editor reads keys on a thread of its own and holds them in its own queue, and it publishes no
# count of them. The queue itself is what a fence rests on, so it is read directly, under the
# version range this package was qualified against; asking the console whether a key is available
# instead would take the lock the editor's own read is holding, and the reader would wait for
# itself.
function Get-KrQueuedKeys {
    try {
        if ($null -eq $script:SingletonField) {
            $script:SingletonField = $script:Rl.GetField('_singleton', 'NonPublic,Static')
            $script:QueuedKeysField = $script:Rl.GetField('_queuedKeys', 'NonPublic,Instance')
        }
        if ($null -eq $script:SingletonField -or $null -eq $script:QueuedKeysField) { return [uint64]0 }
        $singleton = $script:SingletonField.GetValue($null)
        if ($null -eq $singleton) { return [uint64]0 }
        $queue = $script:QueuedKeysField.GetValue($singleton)
        if ($null -eq $queue) { return [uint64]0 }
        return [uint64]$queue.Count
    } catch {
        return [uint64]0
    }
}

$script:SearchCountField = $null
$script:StatusPromptField = $null

# The modes the editor enters rather than the operations it runs.
#
# A history search and a numeric argument are states of the editor between keys, not nested reads,
# so there is no handler of this package's to be inside while one is running. The editor keeps them
# where this package was qualified to find them.
function Get-KrEditorModes {
    $modes = @{ search = $false; numeric_argument = $false }
    try {
        if ($null -eq $script:SearchCountField) {
            $script:SearchCountField = $script:Rl.GetField('_searchHistoryCommandCount', 'NonPublic,Instance')
            $script:StatusPromptField = $script:Rl.GetField('_statusLinePrompt', 'NonPublic,Instance')
        }
        $singleton = $script:SingletonField.GetValue($null)
        if ($null -eq $singleton) { return $modes }
        if ($null -ne $script:SearchCountField) {
            $modes.search = ([int]$script:SearchCountField.GetValue($singleton)) -gt 0
        }
        if ($null -ne $script:StatusPromptField) {
            $prompt = "$($script:StatusPromptField.GetValue($singleton))"
            if ($prompt -like '*i-search*') { $modes.search = $true }
            if ($prompt -like 'digit-argument*') { $modes.numeric_argument = $true }
        }
    } catch { }
    $modes
}

# Whether the editor's own key queue can be read at all, which is what a fence rests on here.
function Test-KrQueueReadable {
    try {
        $singleton = $script:Rl.GetField('_singleton', 'NonPublic,Static')
        $queued = $script:Rl.GetField('_queuedKeys', 'NonPublic,Instance')
        return ($null -ne $singleton -and $null -ne $queued)
    } catch {
        return $false
    }
}

# One revision per observed change, counted where it is read.
function Update-KrRevisions {
    param([hashtable]$State)
    # The buffer belongs to the reader that is reading it. Between one line being accepted and the
    # next read starting, the editor still holds the line that has just gone, and the buffer this
    # reader is about to have is empty.
    $text = if ($State.Reading) { Get-KrBufferText } else { '' }
    if ($text -ne $State.BufferSeen) {
        $State.BufferSeen = $text
        $State.BufferRevision++
    }
    $here = try { $PWD.ProviderPath } catch { '' }
    if ($here -ne $State.CwdSeen) {
        $State.CwdSeen = $here
        $State.CwdRevision++
    }
}

# The reader's own state, read in one operation at one instant.
function Get-KrReaderState {
    param([hashtable]$State)

    Update-KrRevisions $State
    $text = $State.BufferSeen
    $queued = Get-KrQueuedKeys
    $typeahead = $queued
    if ($State.KeySelected) { $typeahead++ }
    $modes = Get-KrEditorModes

    @{
        prompt_generation = [uint64]$State.PromptGeneration
        reader_revision   = [uint64]$State.ReaderRevision
        # The only other reader this host starts does not read through this editor at all.
        reader_context    = 'primary'
        buffer_revision   = [uint64]$State.BufferRevision
        buffer_empty      = [bool]($text.Length -eq 0)
        keymap            = Get-KrKeymap $State.EditMode
        pending           = @{
            quoted_insertion  = [bool]($script:Pending.quoted_insertion -gt 0)
            macro_input       = [bool]($script:Pending.macro_input -gt 0)
            search            = [bool](($script:Pending.search -gt 0) -or $modes.search)
            numeric_argument  = [bool](($script:Pending.numeric_argument -gt 0) -or $modes.numeric_argument)
            multikey_sequence = [bool]($script:Pending.multikey_sequence -gt 0)
            vi_motion         = [bool]($script:Pending.vi_motion -gt 0)
            paste             = [bool]($script:Pending.paste -gt 0)
        }
        keys              = [byte[]]$State.InvokingKeys
        queued_keys       = [uint64]$queued
        pending_bytes     = [uint64]$typeahead
        tty_typeahead_drained = [bool]($typeahead -eq 0)
        macro_input_drained   = [bool]($queued -eq 0 -and $script:Pending.macro_input -eq 0)
        partial_key_drained   = [bool]($script:Pending.multikey_sequence -eq 0)
        cwd_revision      = [uint64]$State.CwdRevision
    }
}

# Installs a launch's command in the empty edit buffer. Returns whether it went in.
function Invoke-KrInstallCommand {
    param([hashtable]$State, [string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ((Get-KrBufferText).Length -ne 0) { return $false }
    try {
        $script:Rl::Insert($Text)
    } catch {
        return $false
    }
    $installed = Get-KrBufferText
    if ($installed.Length -eq 0) { return $false }
    $State.Installed = $installed
    $State.BufferSeen = $installed
    $State.BufferRevision++
    $true
}

# Takes text a launch installed back out, while it is still all there.
function Invoke-KrRemoveInstalled {
    param([hashtable]$State)
    if ([string]::IsNullOrEmpty($State.Installed)) { return $false }
    $installed = $State.Installed
    $State.Installed = ''
    $State.AcceptRequested = $false
    if ((Get-KrBufferText) -ne $installed) { return $false }
    try {
        $script:Rl::Replace(0, $installed.Length, '')
    } catch {
        return $false
    }
    $State.BufferSeen = Get-KrBufferText
    $State.BufferRevision++
    $true
}

$script:KeyFromConsoleKey = $null

# Accepts the installed line through the editor's own acceptance.
#
# The acceptance is submitted twice over, because this editor completes it at its own next step
# rather than where it is asked: the editor's own accept is called, and its own return key goes
# into its own key queue, which is drained before anything the terminal has. The module claims no
# asynchronous editing method the editor does not have, so a line installed while the reader is
# waiting for a key is accepted when the reader next steps.
function Invoke-KrAcceptLine {
    param([hashtable]$State)
    $State.Installed = ''
    try {
        if ($null -eq $script:KeyFromConsoleKey) {
            $keyInfo = $script:Rl.Assembly.GetType('Microsoft.PowerShell.PSKeyInfo')
            if ($null -ne $keyInfo) {
                $script:KeyFromConsoleKey = $keyInfo.GetMethod(
                    'From', 'Public,NonPublic,Static', $null, [type[]]@([System.ConsoleKey]), $null)
            }
        }
        if ($null -ne $script:KeyFromConsoleKey) {
            $singleton = $script:SingletonField.GetValue($null)
            $queue = $script:QueuedKeysField.GetValue($singleton)
            $queue.Enqueue($script:KeyFromConsoleKey.Invoke($null, @([System.ConsoleKey]::Enter)))
        }
    } catch {
        Write-KrTrace "queueing the acceptance failed: $($_.Exception.Message)"
    }
    try { $script:Rl::AcceptLine() } catch {
        Write-KrTrace "accept failed: $($_.Exception.Message)"
        return $false
    }
    $true
}

# Ends a pending key wait without losing the edit buffer, reporting what it ended.
#
# Every operation this reader can be waiting inside runs its own read loop inside the wrapper this
# module put in front of it, and each wrapper watches for the cancellation the same way. Nothing
# here touches the line.
function Invoke-KrCancelKeyWait {
    param([hashtable]$State)
    $ended = @{
        partial_escape    = $false
        quoted_insertion  = [bool]($script:Pending.quoted_insertion -gt 0)
        vi_motion         = [bool]($script:Pending.vi_motion -gt 0)
        multikey_sequence = [bool]($script:Pending.multikey_sequence -gt 0)
        macro_input       = [bool]($script:Pending.macro_input -gt 0)
        buffer_preserved  = $true
        discarded_bytes   = [uint64]0
    }
    $inside = $ended.quoted_insertion -or $ended.vi_motion -or $ended.multikey_sequence -or
              $ended.macro_input -or ($script:Pending.search -gt 0) -or ($script:Pending.paste -gt 0)
    if ($inside) {
        # The wrappers watch this: the one that is running comes out at its next key, leaving the
        # buffer as it found it.
        $State.CancelRequested = $true
        $ended.discarded_bytes = Get-KrQueuedKeys
    }
    $ended
}

# `argument` as one literal argument of this shell.
#
# Every argument is quoted, including the first: an argument vector is installed as literal
# arguments, and a bare word at command position would be a function, an alias or an application
# resolved from the path rather than the name the caller asked to run. Inside this shell's single
# quotes only the quote itself means anything, and it is written twice.
function Get-KrQuotedArgument {
    param([string]$Argument)
    "'" + $Argument.Replace("'", "''") + "'"
}

# Prints one line above the prompt and draws the prompt again below it.
function Write-KrHint {
    param([string]$Line)
    try {
        $script:Rl::InvokePrompt($null, -1)
    } catch { }
    try {
        [Console]::Out.Write("`r`n" + $Line + "`n")
        [Console]::Out.Flush()
        $script:Rl::InvokePrompt()
    } catch { }
}

# The terminal's own end-of-file character, or -1 when it has none.
#
# The host reads keys rather than the line discipline's own characters, so the gesture is read from
# the terminal and matched against the key the reader was given. `stty` is what a shell has here;
# it is asked once per prompt rather than once per key.
function Get-KrTerminalEof {
    if ($IsWindows) { return -1 }
    $settings = try { & stty -a 2>$null } catch { $null }
    if (-not $settings) { return -1 }
    $text = ($settings -join ' ')
    if ($text -notmatch 'eof\s*=\s*([^;]+);') { return -1 }
    $value = $Matches[1].Trim()
    if ($value -eq '<undef>' -or $value -eq 'undef' -or $value -eq '^-') { return -1 }
    if ($value -match '^\^(.)$') {
        $letter = [int][char]$Matches[1].ToUpperInvariant()
        if ($letter -eq 63) { return 127 }
        return $letter - 64
    }
    if ($value.Length -eq 1) { return [int][char]$value }
    -1
}

# The chord a byte from the line discipline corresponds to, as this reader names its keys.
function Get-KrChordForByte {
    param([int]$Byte)
    if ($Byte -lt 1 -or $Byte -gt 31) { return $null }
    $letter = [char](64 + $Byte)
    'Ctrl+' + ([string]$letter).ToLowerInvariant()
}
