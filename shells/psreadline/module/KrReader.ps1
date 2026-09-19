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

function Get-KrKeymap {
    try {
        if ($script:Rl::InViCommandMode()) { return 'vi_command' }
        if ($script:Rl::InViInsertMode()) { return 'vi_insert' }
    } catch { }
    $mode = try { (Get-PSReadLineOption).EditMode } catch { $null }
    switch ("$mode") {
        'Vi' { 'vi_insert' }
        'Emacs' { 'emacs' }
        'Windows' { 'emacs' }
        default { 'custom' }
    }
}

# How many bytes the terminal is still holding for this reader.
#
# The host reads keys rather than bytes, so this is the console's own answer to whether anything is
# waiting: what matters to a fence is whether the queue is clear, and a lower bound of one says so
# exactly when it is not.
function Get-KrTypeahead {
    try {
        if ([Console]::KeyAvailable) { return [uint64]1 }
    } catch { }
    [uint64]0
}

# One revision per observed change, counted where it is read.
function Update-KrRevisions {
    param([hashtable]$State)
    $text = Get-KrBufferText
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
    $typeahead = Get-KrTypeahead
    if ($State.KeySelected) { $typeahead++ }

    @{
        prompt_generation = [uint64]$State.PromptGeneration
        reader_revision   = [uint64]$State.ReaderRevision
        reader_context    = $(if ($State.InsideReader -gt 0) { 'primary' } else { 'primary' })
        buffer_revision   = [uint64]$State.BufferRevision
        buffer_empty      = [bool]($text.Length -eq 0)
        keymap            = Get-KrKeymap
        pending           = @{
            quoted_insertion  = [bool]($script:Pending.quoted_insertion -gt 0)
            macro_input       = [bool]($script:Pending.macro_input -gt 0)
            search            = [bool]($script:Pending.search -gt 0)
            numeric_argument  = [bool]($script:Pending.numeric_argument -gt 0)
            multikey_sequence = [bool]($script:Pending.multikey_sequence -gt 0)
            vi_motion         = [bool]($script:Pending.vi_motion -gt 0)
            paste             = [bool]($script:Pending.paste -gt 0)
        }
        keys              = [byte[]]$State.InvokingKeys
        queued_keys       = [uint64]0
        pending_bytes     = [uint64]$typeahead
        tty_typeahead_drained = [bool]($typeahead -eq 0)
        macro_input_drained   = [bool]($script:Pending.macro_input -eq 0)
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

# Accepts the installed line through the editor's own acceptance.
function Invoke-KrAcceptLine {
    param([hashtable]$State)
    $State.Installed = ''
    try { $script:Rl::AcceptLine() } catch { return $false }
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
        $ended.discarded_bytes = [uint64](Get-KrTypeahead)
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
