<#
.SYNOPSIS
Refuses a Windows release archive that lacks an executable an installed host cannot do without.

.DESCRIPTION
`.github/workflows/release-windows.yml` packs the executables it staged and then reads the finished
archive back against what it packed, which a build that left an executable out would still match.
This holds the archive to the executables a release has to carry instead, each as a file at the
archive's top level: the command line, its terminal restoration guard, the worker, the control
daemon, the description process, the forwarder agents run their hooks through, and the plugin host.
An archive that lacks one is refused, and the refusal names every one it lacks. An archive this
check cannot read is refused as well.

  check-windows-archive.ps1 -Archive <path to the .zip>
  check-windows-archive.ps1 -SelfTest

`-SelfTest` drives the check with archives made to fail, one for each executable, beside a control
it must accept: a check that passes everything looks exactly like a check that works. It signs and
publishes nothing, and it needs nothing but the archives it makes in a directory of its own.

The exit code is 0 when the archive is accepted and 1 when it is refused.
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(ParameterSetName = 'Check', Mandatory)]
    [string] $Archive,

    [Parameter(ParameterSetName = 'SelfTest', Mandatory)]
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# By file name, as the release job stages them. Keep this list the one `release-windows.yml` builds
# and stages.
$required = @(
    'kr.exe',
    'kr-attach-guard.exe',
    'kr-worker.exe',
    'kr-controller.exe',
    'kr-describe-inference.exe',
    'kr-hook.exe',
    'kr-plugin-host.exe'
)

# The files of an archive, by the path they are stored under with a slash for a separator. A
# directory entry names no file.
function Get-ArchiveFiles {
    param([string] $Path)

    $zip = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        return @(
            $zip.Entries |
                Where-Object { $_.Name } |
                ForEach-Object { $_.FullName -replace '\\', '/' }
        )
    } finally {
        $zip.Dispose()
    }
}

function Test-Archive {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Host "REFUSED: $Path is not there"
        return 1
    }
    try {
        $files = Get-ArchiveFiles -Path $Path
    } catch {
        Write-Host "REFUSED: $Path cannot be read as an archive: $($_.Exception.Message)"
        return 1
    }

    $lacking = @($required | Where-Object { $files -cnotcontains $_ })
    foreach ($name in $lacking) {
        Write-Host "REFUSED: $Path lacks $name"
    }
    if ($lacking.Count -ne 0) {
        return 1
    }
    Write-Host "ACCEPTED: $Path carries all $($required.Count) executables"
    return 0
}

function Invoke-SelfTest {
    $host7 = (Get-Process -Id $PID).Path
    $work = Join-Path ([System.IO.Path]::GetTempPath()) ("kr-archive-check-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $script:passed = 0
    $script:failed = 0

    # A stand-in for a release archive that holds the files it is given, each stored under the path
    # it is named by.
    function New-Archive {
        param([string] $Name, [string[]] $Files)
        $path = Join-Path $work "$Name.zip"
        $zip = [System.IO.Compression.ZipFile]::Open($path, 'Create')
        try {
            foreach ($file in $Files) {
                $entry = $zip.CreateEntry($file)
                $stream = $entry.Open()
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes("a stand-in for $file")
                    $stream.Write($bytes, 0, $bytes.Length)
                } finally {
                    $stream.Dispose()
                }
            }
        } finally {
            $zip.Dispose()
        }
        return $path
    }

    # The check runs as a separate process, so its exit code and words are exactly what a workflow
    # step reads.
    function Test-Case {
        param([string] $Case, [string] $Path, [bool] $Accepted, [string] $Names)
        $output = (& $host7 -NoProfile -File $PSCommandPath -Archive $Path 2>&1 | Out-String)
        $code = $LASTEXITCODE
        if ($Accepted) {
            $ok = ($code -eq 0)
        } else {
            $ok = ($code -eq 1) -and ($output -match 'REFUSED')
            foreach ($name in ($Names -split ',' | Where-Object { $_ })) {
                $ok = $ok -and $output.Contains("lacks $name")
            }
        }
        if ($ok) {
            Write-Host "PASS $Case"
            $script:passed += 1
        } else {
            Write-Host "FAIL ${Case}: wanted it $(if ($Accepted) { 'accepted' } else { 'refused' }), and the check exited ${code}:"
            Write-Host (($output.TrimEnd() -split "`r?`n" | ForEach-Object { "    $_" }) -join "`n")
            $script:failed += 1
        }
    }

    try {
        # Written out again here rather than read from the list above, so that a name dropped from
        # that list makes an archive without it pass, and a case below fail.
        $carried = @(
            'kr.exe',
            'kr-attach-guard.exe',
            'kr-worker.exe',
            'kr-controller.exe',
            'kr-describe-inference.exe',
            'kr-hook.exe',
            'kr-plugin-host.exe'
        )
        $everything = $carried + @('signatures.txt', 'SHA256SUMS')
        $control = New-Archive -Name 'control' -Files $everything
        Test-Case -Case 'an archive that carries every executable is accepted' -Path $control -Accepted $true

        foreach ($name in $carried) {
            $without = New-Archive -Name "without-$name" -Files @($everything | Where-Object { $_ -ne $name })
            Test-Case -Case "an archive without $name is refused" -Path $without -Accepted $false -Names $name
        }

        $both = New-Archive -Name 'without-both' -Files @($everything | Where-Object { $_ -notin @('kr-hook.exe', 'kr-plugin-host.exe') })
        Test-Case -Case 'an archive without the forwarder and the plugin host is refused naming both' -Path $both -Accepted $false -Names 'kr-hook.exe,kr-plugin-host.exe'

        $below = New-Archive -Name 'below-the-top' -Files @(@($everything | Where-Object { $_ -ne 'kr-hook.exe' }) + @('bin/kr-hook.exe'))
        Test-Case -Case 'an executable below the top level does not count' -Path $below -Accepted $false -Names 'kr-hook.exe'

        $notAnArchive = Join-Path $work 'not-an-archive.zip'
        Set-Content -LiteralPath $notAnArchive -Value 'not an archive'
        Test-Case -Case 'a file that is not an archive is refused' -Path $notAnArchive -Accepted $false
        Test-Case -Case 'an archive that is not there is refused' -Path (Join-Path $work 'not-there.zip') -Accepted $false
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }

    Write-Host "$($script:passed) passed, $($script:failed) failed"
    if ($script:failed -ne 0 -or $script:passed -eq 0) {
        return 1
    }
    return 0
}

if ($SelfTest) {
    exit (Invoke-SelfTest)
}
exit (Test-Archive -Path $Archive)
