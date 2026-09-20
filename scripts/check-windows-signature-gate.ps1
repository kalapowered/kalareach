<#
.SYNOPSIS
Proves that the Windows signature gate refuses what it is there to refuse.

.DESCRIPTION
`scripts/verify-windows-signatures.ps1` stands between a build and a release, and a gate that
passes everything looks exactly like a gate that works. This drives it with artefacts made to
fail, one condition at a time, and fails if any of them gets through:

  an empty directory                       a build that produced nothing is not a clean run
  a file with no signature                 refused as `unsigned`
  a signature from an untrusted signer     refused as `untrusted`, timestamp and all
  the same signature without a timestamp   refused as `untrusted` and `untimestamped`
  a file altered after it was signed       refused as `untrusted`
  a signed PowerShell module, untrusted    refused as `untrusted`, which is the whole point:
                                           the gate reads a script signature rather than
                                           mistaking a signed script for an unsigned file

and, where the machine has one to offer, an executable and a PowerShell module that Microsoft
signed and timestamped, which the gate must accept.

The untrusted fixtures are signed with a certificate this script creates in the current user's
store and deletes before it returns. It signs nothing that is published, it is never exported,
and it has no trust anywhere: that is what makes it useful here. The release signing identity is
a different thing entirely and is not touched.
#>
[CmdletBinding()]
param(
    [string] $Gate = (Join-Path $PSScriptRoot 'verify-windows-signatures.ps1'),
    [string] $WorkRoot = $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [System.IO.Path]::GetTempPath() })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Gate -PathType Leaf)) {
    throw "The gate is not at $Gate."
}

$script:passed = 0
$script:failed = 0
$host7 = (Get-Process -Id $PID).Path

function Write-Result {
    param([bool] $Ok, [string] $Case, [string] $Detail)
    if ($Ok) {
        Write-Host "PASS $Case"
        $script:passed += 1
    } else {
        Write-Host "FAIL ${Case}: $Detail"
        $script:failed += 1
    }
}

# The gate's own exit code and output, from a separate process, so that what this reads is exactly
# what a workflow step would read.
function Invoke-Gate {
    param([string] $Directory, [string] $Receipt)

    $arguments = @('-NoProfile', '-File', $Gate, '-Path', $Directory)
    if ($Receipt) {
        $arguments += @('-Receipt', $Receipt)
    }

    $output = (& $host7 @arguments 2>&1 | Out-String)
    return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Output = $output }
}

# The reasons the gate gave for one artefact, as a sorted set, read back off its own output.
function Get-ReportedReasons {
    param([string] $Output, [string] $FileName)

    $reasons = [System.Collections.Generic.SortedSet[string]]::new()
    foreach ($line in ($Output -split "`r?`n")) {
        if ($line -match ('^REFUSED\s+' + [regex]::Escape($FileName) + '\s+\(([a-z]+)\)')) {
            [void]$reasons.Add($Matches[1])
        }
    }
    return ($reasons -join ',')
}

# One file per case, so that a refusal is unambiguous about which artefact it refused.
function New-CaseDirectory {
    param([string] $Name)
    $directory = Join-Path $work $Name
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    return $directory
}

# A file the machine trusts, signed in the file rather than through a catalogue, and timestamped:
# the control that shows the gate says yes to something.
function Find-TrustedArtefact {
    param([string[]] $Candidates)

    foreach ($candidate in $Candidates) {
        if (-not $candidate -or -not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            continue
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $candidate
        if ($signature.Status -ne 'Valid') { continue }
        if ([string]$signature.SignatureType -ne 'Authenticode') { continue }
        if ($null -eq $signature.TimeStamperCertificate) { continue }
        return $candidate
    }
    return $null
}

$work = Join-Path $WorkRoot ('kr-signature-gate-' + [System.Guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $work -Force | Out-Null

$certificate = $null
try {
    Write-Host "Gate under test: $Gate"
    Write-Host "Fixtures: $work"
    Write-Host ''

    # 1. Nothing to verify.
    $empty = New-CaseDirectory 'empty'
    $result = Invoke-Gate -Directory $empty
    Write-Result -Ok ($result.ExitCode -ne 0 -and $result.Output -match 'holds no files') `
        -Case 'an empty directory is refused' -Detail "exit $($result.ExitCode)"

    # A real executable with no signature of any kind. A copy of a system binary still verifies
    # through the catalogue that covers the original, so one byte of it is changed: that leaves a
    # well-formed executable which nothing has ever signed, which is what an unsigned build output
    # is.
    $source = Find-TrustedArtefact -Candidates @(
        (Join-Path $env:SystemRoot 'System32\where.exe'),
        (Join-Path $env:SystemRoot 'System32\find.exe'),
        (Join-Path $env:SystemRoot 'System32\hostname.exe')
    )
    if (-not $source) {
        $source = (Join-Path $env:SystemRoot 'System32\where.exe')
    }
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "No executable to build the fixtures from; looked for $source."
    }

    $bytes = [System.IO.File]::ReadAllBytes($source)
    $bytes[[int]($bytes.Length / 2)] = [byte](($bytes[[int]($bytes.Length / 2)] + 1) % 256)
    $unsignedDirectory = New-CaseDirectory 'unsigned'
    $unsigned = Join-Path $unsignedDirectory 'kr-fixture.exe'
    [System.IO.File]::WriteAllBytes($unsigned, $bytes)

    # 2. No signature at all.
    $result = Invoke-Gate -Directory $unsignedDirectory
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'unsigned') `
        -Case 'a file with no signature is refused as unsigned' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # The throwaway signer. Nothing trusts it, which is exactly what the next three cases need.
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject 'CN=KalaReach signature gate fixture, O=KalaReach signature gate fixture' `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddDays(2) `
        -KeyExportPolicy NonExportable
    Write-Host "Fixture signer: $($certificate.Thumbprint) (deleted before this script returns)"

    $timestampServers = @('http://timestamp.acs.microsoft.com', 'http://timestamp.digicert.com')

    function New-SignedFixture {
        param([string] $Directory, [bool] $Timestamped)

        $target = Join-Path $Directory 'kr-fixture.exe'
        Copy-Item -LiteralPath $unsigned -Destination $target

        if (-not $Timestamped) {
            $signed = Set-AuthenticodeSignature -LiteralPath $target -Certificate $certificate `
                -HashAlgorithm SHA256
            if ($signed.Status -ne 'UnknownError' -and $signed.Status -ne 'Valid') {
                throw "Signing the fixture reported $($signed.Status): $($signed.StatusMessage)"
            }
            return $target
        }

        foreach ($server in $timestampServers) {
            Set-AuthenticodeSignature -LiteralPath $target -Certificate $certificate `
                -HashAlgorithm SHA256 -TimestampServer $server -ErrorAction SilentlyContinue | Out-Null
            if ($null -ne (Get-AuthenticodeSignature -LiteralPath $target).TimeStamperCertificate) {
                Write-Host "Fixture timestamped by $server"
                return $target
            }
        }

        throw (
            'None of the timestamping services answered, so the timestamped fixtures cannot be ' +
            "made: $($timestampServers -join ', ')"
        )
    }

    # 3. Signed and timestamped, by a signer nothing trusts.
    $untrustedDirectory = New-CaseDirectory 'untrusted'
    $untrusted = New-SignedFixture -Directory $untrustedDirectory -Timestamped $true
    $result = Invoke-Gate -Directory $untrustedDirectory
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untrusted') `
        -Case 'a signature that does not chain to a trusted root is refused as untrusted' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 4. The same signature with no timestamp: both conditions reported, neither hiding the other.
    $untimestampedDirectory = New-CaseDirectory 'untimestamped'
    New-SignedFixture -Directory $untimestampedDirectory -Timestamped $false | Out-Null
    $result = Invoke-Gate -Directory $untimestampedDirectory
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untimestamped,untrusted') `
        -Case 'a signature with no timestamp is refused as untimestamped' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 5. Altered after signing. The same refusal as an untrusted signer, because from the policy's
    # side it is the same answer: this signature does not hold for this file.
    $alteredDirectory = New-CaseDirectory 'altered'
    $altered = Join-Path $alteredDirectory 'kr-fixture.exe'
    Copy-Item -LiteralPath $untrusted -Destination $altered
    $alteredBytes = [System.IO.File]::ReadAllBytes($altered)
    $alteredBytes[[int]($alteredBytes.Length / 3)] = [byte](($alteredBytes[[int]($alteredBytes.Length / 3)] + 1) % 256)
    [System.IO.File]::WriteAllBytes($altered, $alteredBytes)
    $result = Invoke-Gate -Directory $alteredDirectory
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -match 'untrusted') `
        -Case 'a file altered after it was signed is refused' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 6. A PowerShell module carries its signature in the file itself rather than in a certificate
    # table, and a gate that cannot read one would call every signed module unsigned. This proves
    # the gate reads it: the module is signed by the untrusted fixture signer, so the answer has
    # to be `untrusted` and nothing else.
    $moduleDirectory = New-CaseDirectory 'module'
    $module = Join-Path $moduleDirectory 'KrFixture.psm1'
    Set-Content -LiteralPath $module -Value @(
        '# A module that exists to be signed.',
        'function Get-KrFixture { 1 }'
    ) -Encoding utf8NoBOM
    $moduleSigned = $false
    foreach ($server in $timestampServers) {
        Set-AuthenticodeSignature -LiteralPath $module -Certificate $certificate `
            -HashAlgorithm SHA256 -TimestampServer $server -ErrorAction SilentlyContinue | Out-Null
        if ($null -ne (Get-AuthenticodeSignature -LiteralPath $module).TimeStamperCertificate) {
            $moduleSigned = $true
            break
        }
    }
    if ($moduleSigned) {
        $result = Invoke-Gate -Directory $moduleDirectory
        $reasons = Get-ReportedReasons -Output $result.Output -FileName 'KrFixture.psm1'
        Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untrusted') `
            -Case 'a signed PowerShell module is read as signed, and refused on its signer' `
            -Detail "exit $($result.ExitCode), reasons [$reasons]"
    } else {
        Write-Result -Ok $false -Case 'a signed PowerShell module is read as signed' `
            -Detail 'the module could not be signed and timestamped on this machine'
    }

    # 7 and 8. What the gate says yes to. Whatever this machine happens to carry that Microsoft
    # signed in the file and timestamped: an executable, and a module, because the two take
    # different paths through the policy.
    $signtool = Get-Command -Name 'signtool.exe' -CommandType Application -ErrorAction Ignore |
        Select-Object -First 1
    $trustedExecutable = Find-TrustedArtefact -Candidates @(
        (Join-Path $PSHOME 'pwsh.exe'),
        $(if ($signtool) { $signtool.Source } else { $null }),
        (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
        (Join-Path $env:ProgramFiles 'Git\bin\git.exe')
    )
    $trustedModule = $null
    foreach ($modulesRoot in @((Join-Path $PSHOME 'Modules'), (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'))) {
        if (-not (Test-Path -LiteralPath $modulesRoot -PathType Container)) { continue }
        $candidates = Get-ChildItem -LiteralPath $modulesRoot -Filter '*.psm1' -Recurse -File -ErrorAction Ignore |
            Select-Object -ExpandProperty FullName -First 40
        $trustedModule = Find-TrustedArtefact -Candidates @($candidates)
        if ($trustedModule) { break }
    }

    foreach ($pair in @(
            @{ Name = 'executable'; Path = $trustedExecutable },
            @{ Name = 'PowerShell module'; Path = $trustedModule })) {
        if (-not $pair.Path) {
            Write-Host "NOTE this machine carries no signed and timestamped $($pair.Name) to accept, so that case is not proven here."
            continue
        }
        $acceptDirectory = New-CaseDirectory ('accepted-' + ($pair.Name -replace '\W', '-'))
        Copy-Item -LiteralPath $pair.Path -Destination $acceptDirectory
        $receipt = Join-Path $acceptDirectory 'receipt.txt'
        $result = Invoke-Gate -Directory $acceptDirectory -Receipt $receipt
        Write-Result -Ok ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $receipt -PathType Leaf)) `
            -Case "a signed and timestamped $($pair.Name) is accepted and recorded" `
            -Detail "exit $($result.ExitCode) over $($pair.Path)"
    }
} finally {
    if ($certificate) {
        $stored = Join-Path 'Cert:\CurrentUser\My' $certificate.Thumbprint
        if (Test-Path -LiteralPath $stored) {
            Remove-Item -LiteralPath $stored -DeleteKey -Force
        }
        if (Test-Path -LiteralPath $stored) {
            Write-Host "WARNING the fixture certificate $($certificate.Thumbprint) is still in Cert:\CurrentUser\My; remove it by hand."
        } else {
            Write-Host "Fixture signer $($certificate.Thumbprint) removed from Cert:\CurrentUser\My."
        }
    }
    if ($work -and (Test-Path -LiteralPath $work -PathType Container)) {
        Remove-Item -LiteralPath $work -Recurse -Force
    }
}

Write-Host ''
Write-Host "$script:passed passed, $script:failed failed."
if ($script:failed -gt 0) {
    exit 1
}
exit 0
