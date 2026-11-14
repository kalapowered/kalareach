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
# Unix, TEMP on Windows), the folder RUNNER_TEMP names, and on Unix /tmp, where each is an absolute
# path to a directory. A root is resolved through its links as the platform resolves it (/tmp is
# /private/tmp on macOS, a short Windows name is its long one), and so is the part of the value
# that exists, so a link inside a root that leads out of it is refused and a root that is itself
# behind a link is honoured. A value is compared with a root by path components, never by text:
# /tmpfoo is not inside /tmp. A relative value, an empty value and a value with a `..` in it are
# refused, and so is a root itself.
#
# Where the variable is not set, the script makes a directory of its own under the temporary folder
# and says where it is on the error stream.

$ErrorActionPreference = 'Stop'
$variable = 'KR_TEST_ARTIFACTS_DIR'
$windows = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$comparison = if ($windows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
$separators = [char[]] @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)

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
        if ([string]::IsNullOrEmpty($candidate) -or -not [System.IO.Path]::IsPathRooted($candidate)) { continue }
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $real = (Get-RealPath $candidate).TrimEnd($separators)
        if ($real -and -not ($roots -contains $real)) { $roots += $real }
    }
    return $roots
}

function Stop-Refused {
    param([string] $Value, [string] $Why)
    $roots = (Get-TemporaryRoots) -join ', '
    throw "kr-artifacts: the evidence directory '$Value' ($variable) is refused: $Why. It has to be an absolute path inside one of this platform's temporary roots ($roots). Set it to a folder under one of them, or leave it unset and the run makes a directory of its own."
}

# The real path of $Value, which has to be inside one of the temporary roots.
function Confine-Value {
    param([string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { Stop-Refused $Value 'it is empty' }
    if (-not [System.IO.Path]::IsPathRooted($Value) -or ($windows -and $Value -notmatch '^[A-Za-z]:[\\/]')) {
        Stop-Refused $Value 'it is not an absolute path'
    }
    if ($Value.Split($separators) -contains '..') { Stop-Refused $Value 'it steps up a directory with `..`' }
    $real = (Get-RealPath $Value).TrimEnd($separators)
    foreach ($root in (Get-TemporaryRoots)) {
        if ($real.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, $comparison)) { return $real }
    }
    Stop-Refused $Value 'it is not inside a temporary root'
}

$named = [System.Environment]::GetEnvironmentVariable($variable)
if ($null -ne $named) {
    $directory = Confine-Value $named
} else {
    $made = Join-Path ([System.IO.Path]::GetTempPath()) ('kr-test-artifacts-' + [System.Guid]::NewGuid().ToString('N'))
    [System.IO.Directory]::CreateDirectory($made) | Out-Null
    $directory = Confine-Value $made
    [Console]::Error.WriteLine("$variable is not set: this run keeps its evidence in $directory")
}
[System.Environment]::SetEnvironmentVariable($variable, $directory)
$directory
