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

# The editor's own queue of keys it has taken and not yet acted on, or nothing when this editor
# keeps none this package can read.
#
# The editor reads keys on a thread of its own and holds them in its own queue, and it publishes no
# count of them. The queue itself is what a fence rests on, so it is read directly, under the
# version range this package was qualified against; asking the console whether a key is available
# instead would take the lock the editor's own read is holding, and the reader would wait for
# itself.
#
# Nothing is assumed of the editor beyond what is read here: the two fields exist, the editor has
# an instance, the instance has a queue, and the queue answers with a count. Any of those failing
# is an editor that cannot prove its queue is clear.
function Get-KrKeyQueue {
    try {
        if ($null -eq $script:SingletonField -or $null -eq $script:QueuedKeysField) {
            $script:SingletonField = $script:Rl.GetField('_singleton', 'NonPublic,Static')
            $script:QueuedKeysField = $script:Rl.GetField('_queuedKeys', 'NonPublic,Instance')
        }
        if ($null -eq $script:SingletonField -or $null -eq $script:QueuedKeysField) { return $null }
        $singleton = $script:SingletonField.GetValue($null)
        if ($null -eq $singleton) { return $null }
        $queue = $script:QueuedKeysField.GetValue($singleton)
        if ($null -eq $queue) { return $null }
        # A collection and not anything that merely answers to `Count`: a scalar has one too.
        if ($queue -isnot [System.Collections.ICollection]) { return $null }
        # As one value: a function's output is enumerated, and the queue would come out as its keys.
        return , $queue
    } catch {
        return $null
    }
}

# How many keys that queue holds, or nothing when it cannot be read.
function Read-KrQueuedKeys {
    $queue = Get-KrKeyQueue
    if ($null -eq $queue) { return $null }
    [uint64]([System.Collections.ICollection]$queue).Count
}

# How many keys the reader has taken and not yet acted on.
function Get-KrQueuedKeys {
    $queued = Read-KrQueuedKeys
    if ($null -eq $queued) { return [uint64]0 }
    $queued
}

$script:KeyReadMethod = $null

# The editor's own read of the next key, or nothing when this editor keeps none this package can
# call, or one whose result and queue this package cannot use.
#
# Every part of the editor that needs another key reads it here: the second key of a chord, and each
# key of a search or of a numeric argument. A handler that reads its keys here takes them in the
# order the editor would have met them, from the editor's queue and, once that is empty, from the
# terminal, where it waits for one: `Skip-KrReply` reads only when a key is there to be read. The
# result has to answer for its character and for the key as the console reports it, and the queue
# has to take keys back at its front, which is how a key that is no part of a reply is given back.
function Get-KrKeyRead {
    if ($null -ne $script:KeyReadMethod) { return $script:KeyReadMethod }
    try {
        $method = $script:Rl.GetMethod('ReadKey', [System.Reflection.BindingFlags]'NonPublic,Static',
            $null, [type[]]@(), $null)
        if ($null -eq $method) { return $null }
        $returned = $method.ReturnType
        $public = [System.Reflection.BindingFlags]'Public,Instance'
        if ($returned.GetMember('KeyChar', $public).Count -eq 0) { return $null }
        if ($null -eq $returned.GetMethod('AsConsoleKeyInfo', $public, $null, [type[]]@(), $null)) { return $null }
        $queue = Get-KrKeyQueue
        if ($null -eq $queue) { return $null }
        foreach ($name in 'Enqueue', 'Clear', 'ToArray') {
            if ($null -eq $queue.GetType().GetMethod($name)) { return $null }
        }
        $script:KeyReadMethod = $method
        $method
    } catch {
        $null
    }
}

# Whether the editor's own read of the next key can be called, which is what taking a host's answer
# out of its keys rests on.
function Test-KrKeyReadable {
    $null -ne (Get-KrKeyRead)
}

# The next key, read the way the editor reads it.
function Read-KrKey {
    (Get-KrKeyRead).Invoke($null, @())
}

# Whether the terminal has delivered a key that the editor has not met: one in the editor's queue,
# or input the runtime holds or the terminal still has. A read of the next key waits when there is
# none, so the keys of a reply are read only while this says there are some. The first byte of a
# character that the runtime has read without the rest is no key, and a read of the next key would
# wait for the rest of the character, so the bytes the runtime's decoder holds are not counted here.
function Test-KrKeyWaiting {
    if ((Get-KrQueuedKeys) -gt 0) { return $true }
    $unread = Read-KrRuntimeUnread -Keys
    $null -ne $unread -and $unread -gt 0
}

# Puts keys back at the front of the editor's queue, in the order given.
function Restore-KrKeys {
    param([object[]]$Keys)
    $queue = Get-KrKeyQueue
    $rest = $queue.ToArray()
    $queue.Clear()
    foreach ($key in $Keys) { $queue.Enqueue($key) }
    foreach ($key in $rest) { $queue.Enqueue($key) }
}

# The chord of the key the module queues for itself ahead of every read, and the key the editor makes
# of it. No terminal sends such a key, and the module binds the chord only where nothing is bound.
$script:StartChord = 'Ctrl+Alt+F24'
$script:StartKey = $null

# The editor's key for that chord, made the way the editor makes the key of a chord it binds, or
# nothing when the editor does not say.
function Get-KrStartKey {
    if ($null -ne $script:StartKey) { return $script:StartKey }
    try {
        $assembly = $script:Rl.Assembly
        $keys = $assembly.GetType('Microsoft.PowerShell.ConsoleKeyChordConverter').GetMethod(
            'Convert', [type[]]@([string])).Invoke($null, @($script:StartChord))
        $key = $assembly.GetType('Microsoft.PowerShell.PSKeyInfo').GetMethod(
            'FromConsoleKeyInfo', [type[]]@([System.ConsoleKeyInfo])).Invoke($null, @(@($keys)[0]))
        $script:StartKey = $key
        $key
    } catch {
        $null
    }
}

$script:NextHistoryField = $null

# The history entry the editor loads into the read that is about to start, as an index, or nothing
# when this editor keeps none this package can read.
#
# It is above zero only after a line accepted with AcceptAndGetNext (Ctrl+o): the editor loads the
# entry after the one that ran into the next read, and carries the person's history search over to
# it, so that the next search key goes on from there.
function Read-KrNextHistoryIndex {
    try {
        if ($null -eq $script:SingletonField) {
            $script:SingletonField = $script:Rl.GetField('_singleton', 'NonPublic,Static')
        }
        if ($null -eq $script:NextHistoryField) {
            $script:NextHistoryField = $script:Rl.GetField('_getNextHistoryIndex', 'NonPublic,Instance')
        }
        if ($null -eq $script:SingletonField -or $null -eq $script:NextHistoryField) { return $null }
        $singleton = $script:SingletonField.GetValue($null)
        if ($null -eq $singleton) { return $null }
        [int]$script:NextHistoryField.GetValue($singleton)
    } catch {
        $null
    }
}

# Queues the module's own key for the read that is about to start, and says whether it did.
#
# The key is the first thing the editor runs once it has started: it asks the terminal where the
# cursor is, from the same input as every other byte, and then reads its first key. Until the module's
# handler for the key runs, the queue is not empty, so no fence is proved over a reader whose editor
# has not asked yet, and the reader reports itself idle from the handler, which is where the worker
# asks for a fence again. Where the key cannot be queued the reader reports nothing at the entry, and
# reports itself idle from the first key that reaches one of the module's boundaries instead, which
# is after the editor has asked.
#
# The key is queued only where it cannot change what the person's keys do or fail to run.
# - The queue is empty. A key the person typed ahead is in it first, and a key of the module's behind
#   it can be taken as the second key of a chord they began with an Escape, and never runs. The queue
#   is not clear in that case either, and the editor asks where the cursor is before it runs any key
#   in it, so no fence is proved before it has asked.
# - The read starts in the insert table. After a line cancelled from the Vi command table the read
#   starts in the command table, which has nothing bound on the key: the handler would not run and the
#   reader would report nothing until a bound key.
# - The read does not follow a line accepted with AcceptAndGetNext. The editor loads the next history
#   entry into such a read and carries the person's history search over to it, and any key it runs
#   ahead of the person's ends that search, so their next search key would start again.
function Add-KrStartKey {
    if ($IsWindows -or -not $script:Hooks.Start) { return $false }
    try {
        $key = Get-KrStartKey
        $queue = Get-KrKeyQueue
        if ($null -eq $key -or $null -eq $queue) { return $false }
        if ($queue.Count -gt 0) { return $false }
        if ($script:Rl::InViCommandMode()) { return $false }
        $next = Read-KrNextHistoryIndex
        if ($null -eq $next -or $next -gt 0) { return $false }
        $table = (Get-KrBindingTables).Keys
        if (-not $table.ContainsKey($key) -or "$($table[$key].LongDescription)" -cne $script:StartDescription) {
            return $false
        }
        $queue.Enqueue($key)
        return $true
    } catch {
        return $false
    }
}

# Takes the module's own key out of the editor's queue where it is still there, and leaves every
# other key in the place and the order it had.
#
# The key stays queued when the read it was queued for ended before the editor ran it. Once the
# module's binding is off, it would reach an editor with nothing bound on it, or with a binding of the
# person's made since, which would then run without a press.
function Remove-KrStartKeys {
    try {
        $key = Get-KrStartKey
        $queue = Get-KrKeyQueue
        if ($null -eq $key -or $null -eq $queue) { return }
        $held = $queue.ToArray()
        if (@($held | Where-Object { $key.Equals($_) }).Count -eq 0) { return }
        $queue.Clear()
        foreach ($each in $held) {
            if (-not $key.Equals($each)) { $queue.Enqueue($each) }
        }
    } catch {
        Write-KrTrace "the start key was not taken out of the queue: $($_.Exception.Message)"
    }
}

# What each reply to a question of the terminal's opens with, after its Escape: a control sequence
# (`CSI ? 62 ; 22 c`, the terminal's attributes), an operating system command (`OSC 11 ; rgb:... ST`,
# a colour) and a device control string (`DCS > | name ST`, the terminal's version).
$script:ReplyShapes = @{
    '[' = 'control'
    ']' = 'system'
    'P' = 'device'
}

# The most keys that are read as one reply: the most the host's response lane writes for one.
$script:ReplyKeysMax = 8192

# Whether a key is the bell, which ends an operating system command. The editor reports it as the
# key G with Control held and no character.
function Test-KrBell {
    param($Key)
    if ([int]$Key.KeyChar -eq 0x07) { return $true }
    $info = if ($Key -is [System.ConsoleKeyInfo]) { $Key } else { $Key.AsConsoleKeyInfo() }
    ($info.Key -eq [System.ConsoleKey]::G) -and (($info.Modifiers -band [System.ConsoleModifiers]::Control) -ne 0)
}

# Reads the rest of a reply whose introducing character the editor has taken, and drops it.
#
# An application asks the terminal something (what it is, where the cursor is, what colour its
# background is) and the host answers in the terminal's input, in one write. When the application
# has ended by then, the shell reads the answer at its prompt. It is no key and nobody typed it, but
# the runtime has no key for such a sequence and hands the editor each part of it as a key of its
# own: the Escape, the character that introduces the sequence, and every character after it. The
# editor would put those characters into the line and draw each one.
#
# A control sequence ends at its first character from `@` to `~`. An operating system command ends
# at the bell or at a backslash, and a device control string at a backslash: the runtime delivers a
# string's terminator, an Escape and a backslash, as the backslash alone. The reply is read only
# while the terminal has delivered keys, never waited for, so an Escape and a bracket a person
# pressed take nothing from what they press next; what a read splits is left to the editor. A key
# that no reply holds, a control character or the Escape of something else, ends the reply early and
# goes back to the front of the editor's queue. A run longer than the most keys a reply is read as
# is let go.
function Skip-KrReply {
    param(
        [char]$Introducer,
        # Where the keys come from: whether one has been delivered, the next one, and where a key
        # that is no part of the reply goes back to. The editor's own, unless a caller reads the
        # terminal before the editor has started.
        [scriptblock]$Waiting = { Test-KrKeyWaiting },
        [scriptblock]$Read = { Read-KrKey },
        [scriptblock]$Restore = { param($Keys) Restore-KrKeys $Keys }
    )
    $shape = $script:ReplyShapes["$Introducer"]
    if ($null -eq $shape) { return $false }
    $escape = $null
    for ($taken = 0; $taken -lt $script:ReplyKeysMax; $taken++) {
        if (-not (& $Waiting)) {
            if ($null -ne $escape) { & $Restore @($escape) }
            return $false
        }
        $key = & $Read
        $code = [int]$key.KeyChar
        if ($shape -eq 'control') {
            if ($code -ge 0x20 -and $code -le 0x3F) { continue }
            if ($code -ge 0x40 -and $code -le 0x7E) { return $true }
            & $Restore @($key)
            return $false
        }
        if ($null -ne $escape) {
            if ($code -ne 0x5C) {
                & $Restore @($escape, $key)
                return $false
            }
            return $true
        }
        if ($code -eq 0x5C) { return $true }
        if ($code -eq 0x1B) { $escape = $key; continue }
        if ($shape -eq 'system' -and (Test-KrBell $key)) { return $true }
        if ($code -lt 0x20 -or $code -eq 0x7F) {
            & $Restore @($key)
            return $false
        }
    }
    $false
}

# Takes the host's answers that are already in the terminal's input out of it before the editor
# starts to read.
#
# The editor asks the terminal where the cursor is as it starts, and the runtime reads the reply
# from the same input as every other byte, joining into it every digit that comes ahead of it. The
# worker holds back every answer it writes for the terminal from the moment it has applied the read's
# entry until it has written that reply, but an answer it had already handed to its writer before then
# is on its way to the terminal, or in it, and no hold reaches it. It is read here, with the console's
# own reads, which are the ones the editor makes once it has started: the editor's own read of the
# next key cannot be called before its read has begun.
#
# What is taken is what the chords take in the editor, and only where those chords are the module's:
# in the Emacs edit mode, for an introducer whose chord (`Escape,[`, `Escape,]` or `Escape,P`) the
# module bound and the editor still holds, read from the editor's tables at each read. In the Vi and
# Windows edit modes, and where the person has bound the chord or the Escape key since, an Escape and
# the key behind it are theirs, so nothing is read there. The introducer is compared as typed:
# `Escape,p` is another chord. An Escape that is followed at once by an introducer is the start of an
# answer, taken to the end of the sequence, and one that is followed by another Escape starts again
# at the later one, so an Escape the person pressed does not hide an answer behind it. Nothing is
# waited for: only keys the terminal has delivered are read, and every other key, the Escape of a key
# that is no answer included, is put into the editor's queue in the order it came in, behind the
# module's own key. A run that turns out to be no answer gives its Escape and its introducer to the
# editor and its other keys back to the reading, which starts again at the first of them: an Escape
# among them may begin an answer of its own. When the read fails part way, every key it had taken is
# put into the queue, in order, the ones of the answer it was reading included. A key typed ahead is
# therefore met by the editor as it would have been in the terminal.
function Clear-KrStaleReplies {
    if ($IsWindows -or -not $script:Kr.Registered -or $script:State.EditMode -cne 'Emacs') { return }
    $introducers = @(Get-KrOwnReplyIntroducers)
    if ($introducers.Count -eq 0) { return }
    try {
        $queue = Get-KrKeyQueue
        if ($null -eq $queue) { return }
        $convert = $script:Rl.Assembly.GetType('Microsoft.PowerShell.PSKeyInfo').GetMethod(
            'FromConsoleKeyInfo', [type[]]@([System.ConsoleKeyInfo]))
        if ($null -eq $convert) { return }
        # The keys the editor is to have, in the order they came in.
        $kept = [System.Collections.Generic.List[object]]::new()
        # Keys taken from the terminal or from `$ahead` that are neither the editor's nor dropped yet.
        $undecided = [System.Collections.Generic.List[object]]::new()
        # Keys taken and to be looked at again, the next first.
        $ahead = [System.Collections.Generic.LinkedList[object]]::new()
        $waiting = { $ahead.Count -gt 0 -or [Console]::KeyAvailable }.GetNewClosure()
        $take = {
            $each = if ($ahead.Count -gt 0) {
                $first = $ahead.First.Value
                $ahead.RemoveFirst()
                $first
            } else {
                [Console]::ReadKey($true)
            }
            $undecided.Add($each)
            $each
        }.GetNewClosure()
        $dropped = 0
        try {
            for ($taken = 0; $taken -lt $script:ReplyKeysMax; $taken++) {
                if (-not (& $waiting)) { break }
                $key = & $take
                if ([int]$key.KeyChar -ne 0x1B -or -not (& $waiting)) {
                    $kept.AddRange($undecided)
                    $undecided.Clear()
                    continue
                }
                $next = & $take
                if ([int]$next.KeyChar -eq 0x1B) {
                    # The first Escape is the person's, and an answer starts at the later one.
                    $undecided.RemoveAt($undecided.Count - 1)
                    $kept.AddRange($undecided)
                    $undecided.Clear()
                    $null = $ahead.AddFirst($next)
                    continue
                }
                if ($introducers -cnotcontains "$($next.KeyChar)") {
                    $kept.AddRange($undecided)
                    $undecided.Clear()
                    continue
                }
                $whole = Skip-KrReply ([char]$next.KeyChar) -Waiting $waiting -Read $take -Restore { param($Keys) }
                if ($whole) {
                    $dropped++
                } else {
                    # Not a whole answer: an Escape and a bracket that something else follows, or the
                    # start of one that has not been delivered whole. The Escape and the introducer
                    # are the editor's, and the keys the attempt read after them are looked at again
                    # from the first: one of them may be the Escape of an answer.
                    $kept.Add($undecided[0])
                    $kept.Add($undecided[1])
                    for ($index = $undecided.Count - 1; $index -ge 2; $index--) {
                        $null = $ahead.AddFirst($undecided[$index])
                    }
                }
                $undecided.Clear()
            }
        } finally {
            # However the loop ends, no key taken is lost: the ones not decided on, then the ones to
            # be looked at again, go behind the ones already kept.
            $kept.AddRange($undecided)
            foreach ($key in $ahead) { $kept.Add($key) }
            foreach ($key in $kept) {
                try { $queue.Enqueue($convert.Invoke($null, @($key))) } catch {
                    Write-KrTrace "a key typed ahead was not given back to the editor: $($_.Exception.Message)"
                }
            }
        }
        if ($dropped -gt 0) { Write-KrTrace "$dropped host answers were in the terminal's input when the read began" }
    } catch {
        Write-KrTrace "the terminal's input was not cleared of host answers: $($_.Exception.Message)"
    }
}

# The members of the runtime's own reader of the terminal, resolved once, or nothing when this
# runtime keeps none this package can read.
#
# A key the editor has not queued is not necessarily one nobody has read. The runtime reads the
# terminal in chunks: what a chunk holds beyond the key being returned stays in the runtime's own
# buffer, the first bytes of a character the chunk ends inside stay in its decoder, and what has
# not been read at all is still in the terminal's queue. All of it is input the editor has not met
# yet, and none of it is in the editor's queue. Asking the console whether a key is available
# would take the lock the editor's reading thread holds while it waits for one, so the runtime's
# buffer and decoder are read where they lie, and the terminal's queue is asked through the
# runtime's own poll of the input it was started with, which takes the runtime's console lock for
# the length of the poll and not the lock a read of the editor's holds.
$script:RuntimeReader = $null

function Get-KrRuntimeReader {
    if ($null -ne $script:RuntimeReader) { return $script:RuntimeReader }
    try {
        $assembly = [System.Console].Assembly
        $static = [System.Reflection.BindingFlags]'NonPublic,Static'
        $instance = [System.Reflection.BindingFlags]'NonPublic,Instance'
        $pal = $assembly.GetType('System.ConsolePal')
        $sys = $assembly.GetType('Interop+Sys')
        $synchronised = $assembly.GetType('System.IO.SyncTextReader')
        $reader = $assembly.GetType('System.IO.StdInReader')
        if ($null -eq $pal -or $null -eq $sys -or $null -eq $synchronised -or $null -eq $reader) { return $null }
        $members = @{
            Held      = $pal.GetField('s_stdInReader', $static)
            Ready     = $sys.GetMethod('StdinReady', $static)
            Inner     = $synchronised.GetField('_in', $instance)
            Start     = $reader.GetField('_startIndex', $instance)
            End       = $reader.GetField('_endIndex', $instance)
            Available = $reader.GetField('_availableKeys', $instance)
            Pending   = $reader.GetField('_tmpKeys', $instance)
            Decoder   = $reader.GetField('_decoder', $instance)
            # The decoder's count of bytes it holds for a character not yet whole, on the type the
            # decoder of a UTF-8 terminal has.
            Leftover  = [System.Text.Encoding]::UTF8.GetDecoder().GetType().GetField('_leftoverByteCount', $instance)
        }
        foreach ($member in $members.Values) { if ($null -eq $member) { return $null } }
        $script:RuntimeReader = $members
        $members
    } catch {
        $null
    }
}

# How many characters the runtime has read from the terminal and the editor has not been given, or
# nothing when that cannot be read.
#
# The terminal's queue counts as one when it holds anything, since the runtime offers no more than
# whether there is input. The runtime's buffer is counted by what it holds, and so are the keys it
# has made of it and not handed over and the bytes its decoder holds for a character not yet whole.
# The module reads where the editor's reading thread is idle, between operations, so nothing moves
# from one of these to the next while they are read.
#
# With `-Keys` the bytes the decoder holds are left out: they make no key until the rest of their
# character comes, and what the caller asks is whether a key can be read now.
#
# A Windows console is read through its own records, which this does not see: there the editor's
# queue is the only count.
function Read-KrRuntimeUnread {
    param([switch]$Keys)
    if ($IsWindows) { return [uint64]0 }
    $members = Get-KrRuntimeReader
    if ($null -eq $members) { return $null }
    try {
        $unread = [uint64]0
        if ([bool]$members.Ready.Invoke($null, @())) { $unread = [uint64]1 }
        # The runtime makes its reader on the first key it is asked for. Before that there is
        # nothing it has read.
        $reading = $members.Held.GetValue($null)
        if ($null -eq $reading) { return $unread }
        $inner = $members.Inner.GetValue($reading)
        if ($null -eq $inner) { return $null }
        $buffered = [int]$members.End.GetValue($inner) - [int]$members.Start.GetValue($inner)
        if ($buffered -gt 0) { $unread += [uint64]$buffered }
        $unread += [uint64]([System.Collections.ICollection]$members.Available.GetValue($inner)).Count
        $unread += [uint64]([System.Collections.ICollection]$members.Pending.GetValue($inner)).Count
        $decoder = $members.Decoder.GetValue($inner)
        if ($null -ne $decoder -and -not $Keys) {
            $held = [int]$members.Leftover.GetValue($decoder)
            if ($held -gt 0) { $unread += [uint64]$held }
        }
        $unread
    } catch {
        $null
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

# Whether the runtime's own reader of the terminal can be read where this package counts what it
# holds. A Windows console is read through its records, which nothing here counts, so there is
# nothing to read.
function Test-KrRuntimeReadable {
    if ($IsWindows) { return $true }
    $null -ne (Get-KrRuntimeReader)
}

# Whether the editor's own key queue can be read, which is what a fence rests on here.
#
# It reads the live queue through the function a fence reads it with, so a build whose queue is
# renamed, absent, not yet made or not a queue at all is refused here rather than read as empty.
function Test-KrQueueReadable {
    $null -ne (Read-KrQueuedKeys)
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
    # A queue this editor no longer lets this package read is not an empty one: the reader says
    # its queues are not drained, so no fence is proved over keys it could not count.
    $known = Read-KrQueuedKeys
    $queued = if ($null -eq $known) { [uint64]0 } else { $known }
    # Input the runtime has read from the terminal, or has yet to, is input the editor has not met,
    # whoever it came from: a person, or the host answering a question an application asked. A
    # runtime that cannot say is not read as having none, and says so for the terminal's typeahead
    # alone: the editor's macros are counted from the editor's queue.
    $unread = Read-KrRuntimeUnread
    $terminalKnown = $null -ne $known -and $null -ne $unread
    if ($null -eq $unread) { $unread = [uint64]0 }
    $typeahead = $queued + $unread
    $modes = Get-KrEditorModes

    @{
        prompt_generation = [uint64]$State.PromptGeneration
        reader_revision   = [uint64]$State.ReaderRevision
        # A prompt a running line opens itself (a debugger's, or `$Host.EnterNestedPrompt()`'s) is
        # read through this editor too, and is not the root editor's: it is the line's own.
        reader_context    = if ($State.Nested) { 'read_builtin' } else { 'primary' }
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
        tty_typeahead_drained = [bool]($terminalKnown -and $typeahead -eq 0)
        macro_input_drained   = [bool]($null -ne $known -and $queued -eq 0 -and $script:Pending.macro_input -eq 0)
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
    $State.BufferSeen = $installed
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
# Every argument is quoted, including the first, so that nothing a word holds is read as syntax.
# Quoting a word does not decide what runs: the call operator looks a quoted word up as a command
# all the same, and a function or an alias of that name would run in the application's place, so a
# launch names its program as `Get-KrLaunchProgram` says. Inside this shell's single quotes only a
# quote means anything, and it is written twice.
# This shell reads five characters as a single quote: the ASCII one (U+0027) and the typographic
# ones U+2018, U+2019, U+201A and U+201B, and any of them ends the string unless it is doubled.
function Get-KrQuotedArgument {
    param([string]$Argument)
    "'" + [regex]::Replace($Argument, '([\u0027\u2018\u2019\u201A\u201B])', '$1$1') + "'"
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
    # `stty` leaves its own exit code in `$LASTEXITCODE`, which is the code of the last program the
    # person ran and stays theirs: it is put back as it was, or taken out if there was none.
    $before = $ExecutionContext.SessionState.PSVariable.GetValue('LASTEXITCODE')
    $settings = try { & stty -a 2>$null } catch { $null }
    if ($null -ne $before) {
        $global:LASTEXITCODE = $before
    } else {
        Remove-Variable -Name LASTEXITCODE -Scope Global -ErrorAction Ignore
    }
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
