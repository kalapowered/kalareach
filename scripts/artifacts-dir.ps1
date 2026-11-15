# Where a test run keeps its evidence: the one reader of KR_TEST_ARTIFACTS_DIR for PowerShell.
#
# Section 27 puts every screenshot and evidence file of a release test run in one directory,
# KR_TEST_ARTIFACTS_DIR, set under a temporary folder for the build. A PowerShell step reads the
# variable only through this script, so a value outside this platform's temporary roots is refused
# where it is used, whatever way the value took:
#
#   $evidence = & ./scripts/artifacts-dir.ps1
#
# The script writes the resolved evidence directory to the pipeline, sets KR_TEST_ARTIFACTS_DIR to
# the same value for the programs the step starts, and throws the words below when the value is
# refused (which ends a step that stops on errors, as a workflow's pwsh step does).
#
# The temporary roots are the folder the system names for the user's temporary files (TMPDIR on
# Unix, TEMP on Windows), the folder RUNNER_TEMP names, and on Unix /tmp, where each is a fully
# qualified path to a directory (on Windows C:\... or C:/..., \\server\share\... or //server/share/...,
# either of those behind \\?\ with backslashes only; any other spelling is none of them, and the
# refusal's words say which are taken: a device path, a server with no share, three separators at
# the start, a path that depends on the current drive and one that depends on a drive's current
# directory). A root is resolved through its links as the platform resolves it (/tmp is
# /private/tmp on macOS, a short Windows name is its long one), and so is the part of the value
# that exists, so a link inside a root that leads out of it is refused and a root that is itself
# behind a link is honoured. A value is compared with a root by path components, never by text:
# /tmpfoo is not inside /tmp. A relative value, an empty value and a value with a `..` in it are
# refused, and so is a root itself.
#
# Off Windows a value that holds a backslash is refused, in words that say that a backslash is not
# taken in the folder's path on this platform, before any other read of it, and a temporary
# variable that holds one is passed over as a root: PowerShell's own path commands read a backslash
# as a separator on every platform, so a folder whose name holds one cannot be kept as written
# by every reader and by the scripts that use the path they return, and a value that the four
# readers cannot read as one folder is refused by all four.
#
# Where the variable is not set, the script makes a directory of its own under the temporary folder
# (the folder the system names for it, and /tmp where that holds a backslash off Windows) and says
# where it is on the error stream.
#
# The reader guards a test run against a mistake: for any value of the evidence variable, and any
# temporary variable as a platform, a runner, one of our scripts or a developer's shell sets it,
# with folders and links as tools make them, it returns a folder inside the roots or refuses, and
# it refuses nothing that the run set right. It is no boundary against a process of the same
# account, which can write wherever the run can and can change a link or a folder while the reader
# reads. It does not close a case that somebody arranges: a link whose target climbs through
# another link, which this reader settles by the target's text.
# On Windows the comparison ignores letter case, so a folder made case-sensitive, and a letter that
# the disk and the reader do not fold alike, are not told apart.
#
# On Windows this reader takes the temporary folder from TMP first and then TEMP, as the platform's
# own call does, and so does the Rust reader; the TypeScript reader takes TEMP first and the shell
# reader takes TEMP. Where TMP and TEMP differ, only a value under the runner's folder satisfies
# all four readers.

$ErrorActionPreference = 'Stop'
$variable = 'KR_TEST_ARTIFACTS_DIR'
$windows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$comparison = if ($windows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
# Both separators on every platform: PowerShell's own path commands (Join-Path, Test-Path, Get-Item)
# read a backslash as a separator off Windows too, so a walk that split on the slash alone would
# read a path another way than the commands it then joins it with.
$separators = [char[]] @('\', '/')

# The spellings of an absolute path that this reader takes on Windows, for the words of a refusal.
$takes = 'on Windows this reader takes C:\folder or C:/folder, \\server\share\folder or //server/share/folder, and either behind \\?\, as \\?\C:\folder or \\?\UNC\server\share\folder'

# How the Windows path $Path is written: 'taken' for a spelling this reader takes (a drive with a
# root, or a share with a server and a name, with either separator or both; either one behind \\?\
# with backslashes only, since Windows reads a slash behind \\?\ as a letter of a name),
# 'not-absolute' for a relative path, \folder or C:folder, and 'kind' for any other spelling: a
# device path (\\.\ or \\?\ with anything but a drive or a share behind it), a server with no share,
# three separators at the start.
function Get-Spelling {
    param([string] $Path)
    if ($Path.StartsWith('\\?\', [System.StringComparison]::Ordinal)) {
        $rest = $Path.Substring(4)
        if ($rest.Contains('/')) { return 'kind' }
        if ($rest -match '^unc\\.') { $Path = '\\' + $rest.Substring(4) }
        elseif ($rest -match '^[A-Za-z]:\\') { $Path = $rest }
        else { return 'kind' }
    }
    if ($Path -match '^[\\/]{2}[.?]([\\/]|$)') { return 'kind' }
    if ($Path -match '^[\\/]{3}') { return 'kind' }
    if ($Path -match '^[\\/]{2}') {
        if ($Path -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+') { return 'taken' }
        return 'kind'
    }
    if ($Path -match '^[A-Za-z]:[\\/]') { return 'taken' }
    return 'not-absolute'
}

# A path in the extended-length form (\\?\C:\... or \\?\UNC\server\share\...) as the ordinary form the
# platform's temporary folder is given in; any other path as it is.
function Remove-ExtendedPrefix {
    param([string] $Path)
    if (-not $windows) { return $Path }
    if ($Path.StartsWith('\\?\UNC\', [System.StringComparison]::OrdinalIgnoreCase)) { return '\\' + $Path.Substring(8) }
    if ($Path.StartsWith('\\?\')) { return $Path.Substring(4) }
    return $Path
}

# The path with every link in it resolved, as the platform resolves them. The part that does not
# exist yet is kept as written.
function Get-RealPath {
    param([string] $Path)
    $current = [System.IO.Path]::GetPathRoot($Path)
    $remaining = [System.Collections.Generic.List[string]]::new()
    $remaining.AddRange([string[]] $Path.Substring($current.Length).Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries))
    $hops = 0
    while ($remaining.Count -gt 0) {
        $name = $remaining[0]
        $remaining.RemoveAt(0)
        $next = Join-Path $current $name
        $item = Get-Item -LiteralPath $next -Force -ErrorAction SilentlyContinue
        if ($null -eq $item) {
            $current = $next
            foreach ($rest in $remaining) { $current = Join-Path $current $rest }
            break
        }
        if ($item.LinkTarget) {
            $hops++
            if ($hops -gt 40) { throw "$Path passes through more than 40 links" }
            $target = [System.IO.Path]::GetFullPath($item.LinkTarget, $current)
            $current = [System.IO.Path]::GetPathRoot($target)
            $remaining.InsertRange(0, [string[]] $target.Substring($current.Length).Split($separators, [System.StringSplitOptions]::RemoveEmptyEntries))
            continue
        }
        $current = $item.FullName
    }
    return $current
}

# Each temporary root that exists, resolved through its links.
function Get-TemporaryRoots {
    $named = @([System.IO.Path]::GetTempPath(), $env:RUNNER_TEMP)
    if (-not $windows) { $named += '/tmp' }
    $roots = @()
    foreach ($candidate in $named) {
        # A path that depends on the current drive (\folder) or on a drive's current directory
        # (C:folder) is rooted but names no one place, and a spelling this reader does not take names
        # none that it reads: neither is a root.
        if ([string]::IsNullOrEmpty($candidate)) { continue }
        # Off Windows a temporary variable that holds a backslash names no root.
        if (-not $windows -and $candidate.Contains('\')) { continue }
        if ($windows) {
            if ((Get-Spelling $candidate) -ne 'taken') { continue }
        } elseif (-not [System.IO.Path]::IsPathFullyQualified($candidate)) { continue }
        $candidate = Remove-ExtendedPrefix $candidate
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $found = Get-RealPath $candidate
        # A temporary folder that is a filesystem root (/, C:\, a share's top) would admit every
        # path on its disk.
        if ($found.TrimEnd($separators) -eq [System.IO.Path]::GetPathRoot($found).TrimEnd($separators)) { continue }
        $real = $found.TrimEnd($separators)
        # Two names for one folder are one root; the comparison is the one that confines a value, so
        # roots that differ in letter case alone are two where the disk tells them apart.
        $known = $false
        foreach ($root in $roots) { if ($root.Equals($real, $comparison)) { $known = $true } }
        if (-not $known) { $roots += $real }
    }
    return $roots
}

# Throws why $Value is refused. With $Folder, $Value is a name that was to be made under the
# temporary folder $Folder for the run's own directory, and it is the folder that is refused:
# nothing was set, so the words do not tell the caller to leave it unset.
function Stop-Refused {
    param([string] $Value, [string] $Why, $Folder)
    $roots = (Get-TemporaryRoots) -join ', '
    if (-not $roots) { $roots = 'none: no folder that a temporary variable names exists' }
    if ($null -ne $Folder) {
        throw "kr-artifacts: no directory of this run's own can be made for its evidence: the temporary folder '$Folder' is refused: $Why. It has to be an absolute path to a folder inside one of this platform's temporary roots ($roots). Point TMPDIR (on Windows, TMP) at such a folder, or set $variable to a folder under one of the roots."
    }
    throw "kr-artifacts: the evidence directory '$Value' ($variable) is refused: $Why. It has to be an absolute path inside one of this platform's temporary roots ($roots). Set it to a folder under one of them, or leave it unset and the run makes a directory of its own."
}

# The real path of $Value, which has to be inside one of the temporary roots. With $Folder, $Value
# is a name under the temporary folder $Folder for the run's own directory.
function Confine-Value {
    param([string] $Value, $Folder)
    if ([string]::IsNullOrEmpty($Value)) { Stop-Refused $Value 'it is empty' $Folder }
    if (-not $windows -and $Value.Contains('\')) { Stop-Refused $Value "it holds a backslash, and a backslash is not taken in the folder's path on this platform" $Folder }
    if ($windows) {
        switch (Get-Spelling $Value) {
            'not-absolute' { Stop-Refused $Value "it is not an absolute path ($takes)" $Folder }
            'kind' { Stop-Refused $Value "it is a Windows path of a kind this reader does not take ($takes)" $Folder }
        }
    } elseif (-not [System.IO.Path]::IsPathFullyQualified($Value)) { Stop-Refused $Value 'it is not an absolute path' $Folder }
    # PowerShell's own path commands read a backslash as a separator on every platform, so a `..` behind one
    # climbs out of a folder here too.
    if ($Value.Split([char[]] @('\', '/')) -contains '..') { Stop-Refused $Value 'it steps up a directory with `..`' $Folder }
    $real = (Get-RealPath (Remove-ExtendedPrefix $Value)).TrimEnd($separators)
    foreach ($root in (Get-TemporaryRoots)) {
        if ($real.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, $comparison)) { return $real }
    }
    Stop-Refused $Value 'it is not inside a temporary root' $Folder
}

$named = [System.Environment]::GetEnvironmentVariable($variable)
if ($null -ne $named) {
    $directory = Confine-Value $named
} else {
    $temporary = [System.IO.Path]::GetTempPath()
    # Off Windows a temporary folder that holds a backslash is passed over: the directory goes under /tmp.
    if (-not $windows -and $temporary.Contains('\')) { $temporary = '/tmp' }
    $made = Join-Path $temporary ('kr-test-artifacts-' + [System.Guid]::NewGuid().ToString('N'))
    # The folder is checked before the directory is made in it, so that a temporary folder that is
    # no root is left as it was.
    Confine-Value $made $temporary | Out-Null
    [System.IO.Directory]::CreateDirectory($made) | Out-Null
    $directory = Confine-Value $made $temporary
    [Console]::Error.WriteLine("$variable is not set: this run keeps its evidence in $directory")
}
[System.Environment]::SetEnvironmentVariable($variable, $directory)
$directory
