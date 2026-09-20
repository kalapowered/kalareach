<#
.SYNOPSIS
Proves that the Windows signature gate refuses what it is there to refuse.

.DESCRIPTION
`scripts/verify-windows-signatures.ps1` stands between a build and a release, and a gate that passes
everything looks exactly like a gate that works. This drives it with real files on a real Windows
machine, one condition at a time, and fails if any of them gets through:

  an empty directory                        a build that produced nothing is not a clean run
  a file with no signature                  refused as `unsigned`
  a signature from an untrusted signer      refused as `untrusted`, timestamp and all
  the same signature without a timestamp    refused as `untrusted` and `untimestamped`
  a trusted signature from another          refused as `wrong-publisher`, because a signature
  publisher                                 somebody else made is not ours
  a file altered after it was signed        refused, starting from a file the gate had accepted
  a signed PowerShell module                read as signed and refused on its signer, rather than
                                            mistaken for an unsigned file

and, for the other side of it, an executable and a PowerShell module that Microsoft signed and
timestamped, each of which the gate must accept when it is told to expect that publisher. Both
controls are required: without them this proves only that the gate says no.

The untrusted fixtures are signed with a certificate this script creates in the current user's store
and deletes before it returns. It signs nothing that is published, it is never exported, and it has
no trust anywhere: that is what makes it useful here. The release signing identity is a different
thing entirely and is not touched. Nothing here reaches it, and the job that runs this holds no
permission that could.
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

# The publisher a release signs as. Used here only as a name the fixtures are not, so that the
# gate's publisher check has something real to disagree with.
$releasePublisher = 'CN=Kala Holdings Inc., O=Kala Holdings Inc., L=Newark, S=Delaware, C=US'
$fixturePublisher = 'CN=KalaReach signature gate fixture, O=KalaReach signature gate fixture'

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
    param([string] $Directory, [string] $ExpectedSubject, [string] $Receipt)

    $arguments = @('-NoProfile', '-File', $Gate, '-Path', $Directory, '-ExpectedSubject', $ExpectedSubject)
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
        if ($line -match ('^REFUSED\s+' + [regex]::Escape($FileName) + '\s+\(([a-z-]+)\)')) {
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

# A file the machine trusts, signed in the file rather than through a catalogue, and timestamped.
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

function Copy-WithAlteredByte {
    param([string] $Source, [string] $Destination, [double] $At)

    $bytes = [System.IO.File]::ReadAllBytes($Source)
    $index = [int]($bytes.Length * $At)
    $bytes[$index] = [byte](($bytes[$index] + 1) % 256)
    [System.IO.File]::WriteAllBytes($Destination, $bytes)
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
    $result = Invoke-Gate -Directory $empty -ExpectedSubject $releasePublisher
    Write-Result -Ok ($result.ExitCode -ne 0 -and $result.Output -match 'holds no files') `
        -Case 'an empty directory is refused' -Detail "exit $($result.ExitCode)"

    # The controls come first, because two of the cases below are built from one of them. Both are
    # required: a gate proved only against failures has not been proved to accept anything.
    $signtool = Get-Command -Name 'signtool.exe' -CommandType Application -ErrorAction Ignore |
        Select-Object -First 1
    $trustedExecutable = Find-TrustedArtefact -Candidates @(
        (Join-Path $PSHOME 'pwsh.exe'),
        $(if ($signtool) { $signtool.Source } else { $null }),
        (Join-Path $env:ProgramFiles 'Git\cmd\git.exe'),
        (Join-Path $env:ProgramFiles 'Git\bin\git.exe'),
        (Join-Path $env:ProgramFiles 'Git\mingw64\bin\git.exe')
    )
    $trustedModule = $null
    foreach ($modulesRoot in @(
            (Join-Path $PSHOME 'Modules'),
            (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\Modules'))) {
        if (-not (Test-Path -LiteralPath $modulesRoot -PathType Container)) { continue }
        $candidates = @(
            Get-ChildItem -LiteralPath $modulesRoot -Include '*.psm1', '*.ps1' -Recurse -File -Force -ErrorAction Ignore |
                Sort-Object -Property FullName |
                Select-Object -ExpandProperty FullName -First 200
        )
        $trustedModule = Find-TrustedArtefact -Candidates $candidates
        if ($trustedModule) { break }
    }

    if (-not $trustedExecutable) {
        Write-Result -Ok $false -Case 'this machine carries a signed and timestamped executable to accept' `
            -Detail 'none of the candidates was signed in the file and timestamped'
    }
    if (-not $trustedModule) {
        Write-Result -Ok $false -Case 'this machine carries a signed and timestamped PowerShell file to accept' `
            -Detail 'none of the installed modules was signed in the file and timestamped'
    }

    # 2. A real executable with no signature of any kind. A copy of a system binary still verifies
    # through the catalogue that covers the original, so one byte of it is changed: that leaves a
    # well-formed executable which nothing has ever signed, which is what an unsigned build output
    # is. The source is deliberately one of the catalogue-covered system binaries rather than a
    # file signed in itself, because altering one of those would leave a broken signature instead
    # of no signature, and the assertion below says so either way.
    $source = @(
        (Join-Path $env:SystemRoot 'System32\where.exe'),
        (Join-Path $env:SystemRoot 'System32\find.exe'),
        (Join-Path $env:SystemRoot 'System32\hostname.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $source) {
        throw 'No system executable to build the fixtures from.'
    }

    $unsignedDirectory = New-CaseDirectory 'unsigned'
    $unsigned = Join-Path $unsignedDirectory 'kr-fixture.exe'
    Copy-WithAlteredByte -Source $source -Destination $unsigned -At 0.5

    $unsignedStatus = [string](Get-AuthenticodeSignature -LiteralPath $unsigned).Status
    if ($unsignedStatus -ne 'NotSigned') {
        Write-Result -Ok $false -Case 'the unsigned fixture really is unsigned' `
            -Detail "Windows reports $unsignedStatus for it, so the case below would prove something else"
    } else {
        $result = Invoke-Gate -Directory $unsignedDirectory -ExpectedSubject $releasePublisher
        $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
        Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'unsigned') `
            -Case 'a file with no signature is refused as unsigned' `
            -Detail "exit $($result.ExitCode), reasons [$reasons]"
    }

    # The throwaway signer. Nothing trusts it, which is exactly what the next cases need.
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $fixturePublisher `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddDays(2) `
        -KeyExportPolicy NonExportable
    Write-Host "Fixture signer: $($certificate.Thumbprint) (deleted before this script returns)"

    $timestampServers = @('http://timestamp.acs.microsoft.com', 'http://timestamp.digicert.com')

    function Add-FixtureSignature {
        param([string] $Target, [bool] $Timestamped)

        if (-not $Timestamped) {
            Set-AuthenticodeSignature -LiteralPath $Target -Certificate $certificate `
                -HashAlgorithm SHA256 | Out-Null
            if ([string](Get-AuthenticodeSignature -LiteralPath $Target).Status -eq 'NotSigned') {
                throw "Signing $Target left it unsigned."
            }
            return
        }

        foreach ($server in $timestampServers) {
            Set-AuthenticodeSignature -LiteralPath $Target -Certificate $certificate `
                -HashAlgorithm SHA256 -TimestampServer $server -ErrorAction SilentlyContinue | Out-Null
            if ($null -ne (Get-AuthenticodeSignature -LiteralPath $Target).TimeStamperCertificate) {
                Write-Host "Fixture timestamped by $server"
                return
            }
        }

        throw (
            'None of the timestamping services answered, so the timestamped fixtures cannot be ' +
            "made: $($timestampServers -join ', ')"
        )
    }

    function New-SignedFixture {
        param([string] $Directory, [bool] $Timestamped, [string] $Name = 'kr-fixture.exe')

        $target = Join-Path $Directory $Name
        Copy-Item -LiteralPath $unsigned -Destination $target
        Add-FixtureSignature -Target $target -Timestamped $Timestamped
        return $target
    }

    # 3. Signed and timestamped by a signer nothing trusts, held to that signer's own name, so the
    # only thing wrong with it is the trust.
    $untrustedDirectory = New-CaseDirectory 'untrusted'
    $untrusted = New-SignedFixture -Directory $untrustedDirectory -Timestamped $true
    $result = Invoke-Gate -Directory $untrustedDirectory -ExpectedSubject $fixturePublisher
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untrusted') `
        -Case 'a signature that does not chain to a trusted root is refused as untrusted' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 4. The same file held to the name a release signs as: now the publisher is wrong too, and both
    # are reported.
    $result = Invoke-Gate -Directory $untrustedDirectory -ExpectedSubject $releasePublisher
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untrusted,wrong-publisher') `
        -Case 'a signature made by another publisher is refused as wrong-publisher' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 5. The same signature with no timestamp: both conditions reported, neither hiding the other.
    $untimestampedDirectory = New-CaseDirectory 'untimestamped'
    New-SignedFixture -Directory $untimestampedDirectory -Timestamped $false | Out-Null
    $result = Invoke-Gate -Directory $untimestampedDirectory -ExpectedSubject $fixturePublisher
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'kr-fixture.exe'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untimestamped,untrusted') `
        -Case 'a signature with no timestamp is refused as untimestamped' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 6. A PowerShell file carries its signature in the file itself rather than in a certificate
    # table, and a gate that cannot read one would call every signed module unsigned. This proves
    # the gate reads it: the module is signed by the fixture signer and held to that signer's name,
    # so the answer has to be `untrusted` and nothing else.
    $moduleDirectory = New-CaseDirectory 'module'
    $module = Join-Path $moduleDirectory 'KrFixture.psm1'
    Set-Content -LiteralPath $module -Value @(
        '# A module that exists to be signed.',
        'function Get-KrFixture { 1 }'
    ) -Encoding utf8NoBOM
    Add-FixtureSignature -Target $module -Timestamped $true
    $result = Invoke-Gate -Directory $moduleDirectory -ExpectedSubject $fixturePublisher
    $reasons = Get-ReportedReasons -Output $result.Output -FileName 'KrFixture.psm1'
    Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'untrusted') `
        -Case 'a signed PowerShell module is read as signed, and refused on its signer' `
        -Detail "exit $($result.ExitCode), reasons [$reasons]"

    # 7 and 8. What the gate says yes to, and the record it writes when it does.
    foreach ($control in @(
            @{ Name = 'executable'; Path = $trustedExecutable },
            @{ Name = 'PowerShell file'; Path = $trustedModule })) {
        if (-not $control.Path) { continue }

        $subject = (Get-AuthenticodeSignature -LiteralPath $control.Path).SignerCertificate.Subject
        $acceptDirectory = New-CaseDirectory ('accepted-' + ($control.Name -replace '\W', '-'))
        Copy-Item -LiteralPath $control.Path -Destination $acceptDirectory
        $receipt = Join-Path $work ('receipt-' + ($control.Name -replace '\W', '-') + '.txt')
        $result = Invoke-Gate -Directory $acceptDirectory -ExpectedSubject $subject -Receipt $receipt
        Write-Result -Ok ($result.ExitCode -eq 0 -and (Test-Path -LiteralPath $receipt -PathType Leaf)) `
            -Case "a signed and timestamped $($control.Name) is accepted and recorded" `
            -Detail "exit $($result.ExitCode) over $($control.Path)"

        # 9. The same file, held to the name a release signs as. Trusted is not the same as ours.
        $result = Invoke-Gate -Directory $acceptDirectory -ExpectedSubject $releasePublisher
        $reasons = Get-ReportedReasons -Output $result.Output -FileName (Split-Path -Leaf $control.Path)
        Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -eq 'wrong-publisher') `
            -Case "a trusted $($control.Name) signed by somebody else is refused as wrong-publisher" `
            -Detail "exit $($result.ExitCode), reasons [$reasons]"
    }

    # 10. Altered after it was signed, starting from a file the gate accepted a moment ago and held
    # to that same publisher, so the alteration is the only thing that changed.
    if ($trustedExecutable) {
        $subject = (Get-AuthenticodeSignature -LiteralPath $trustedExecutable).SignerCertificate.Subject
        $alteredDirectory = New-CaseDirectory 'altered'
        $altered = Join-Path $alteredDirectory (Split-Path -Leaf $trustedExecutable)
        Copy-WithAlteredByte -Source $trustedExecutable -Destination $altered -At 0.4
        $result = Invoke-Gate -Directory $alteredDirectory -ExpectedSubject $subject
        $reasons = Get-ReportedReasons -Output $result.Output -FileName (Split-Path -Leaf $trustedExecutable)
        Write-Result -Ok ($result.ExitCode -ne 0 -and $reasons -match 'unsigned|untrusted') `
            -Case 'a file altered after it was signed is refused' `
            -Detail "exit $($result.ExitCode), reasons [$reasons]"
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
