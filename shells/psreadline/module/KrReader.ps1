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
    # The keys this editor has read and not yet acted on. The module answers only where the
    # reader is between operations, so there is never one selected and unrun on top of these.
    $queued = Get-KrQueuedKeys
    $typeahead = $queued
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


# Accepts the installed line through the editor's own acceptance, once.
#
# The editor's own accept is what ends a read, and it takes effect when the operation it was
# called from returns. Everything this module answers is answered inside that dispatch, which is
# why there is one path here and not two: a line installed before the read starts would be
# cleared by the editor's own initialisation, so no launch is decided there at all.
function Invoke-KrAcceptLine {
    param([hashtable]$State)
    $State.Installed = ''
    if (-not $State.Reading) {
        Write-KrTrace 'the acceptance was asked for outside the reader'
        return $false
    }
    try { $script:Rl::AcceptLine() } catch {
        Write-KrTrace "accept failed: $($_.Exception.Message)"
        return $false
    }
    $true
}

# Reports what a cancellation ended here, which is nothing this editor is inside.
#
# Every operation that waits for another key runs this editor's own read loop, and nothing of this
# module's runs on the reader's thread while one of them is running: the mailbox is read between
# operations, so a cancellation arrives after the operation it was meant for has finished or not
# at all. There is no published way to bring this reader out of one from anywhere else.
#
# So this ends nothing and says so, which is the fail-safe answer: the worker withholds the fence
# until the reader's own queues drain, and the person's line and their typed-ahead keys are left
# exactly as they are.
function Invoke-KrCancelKeyWait {
    param([hashtable]$State)
    @{
        partial_escape    = $false
        quoted_insertion  = $false
        vi_motion         = $false
        multikey_sequence = $false
        macro_input       = $false
        buffer_preserved  = $true
        discarded_bytes   = [uint64]0
    }
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
    if ($Byte -eq 127) { return 'Backspace' }
    if ($Byte -ge 32 -and $Byte -le 126) { return [string][char]$Byte }
    if ($Byte -lt 1 -or $Byte -gt 31) { return $null }
    $letter = [char](64 + $Byte)
    'Ctrl+' + ([string]$letter).ToLowerInvariant()
}
