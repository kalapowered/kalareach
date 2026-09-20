<#
.SYNOPSIS
Refuses a Windows release artefact that is not signed the way a release requires.

.DESCRIPTION
Every file under -Path is held to three conditions, and a file that fails any of them is named
with the condition it failed:

  unsigned       it carries no signature at all;
  untrusted      its signature is not accepted by the default Authenticode policy, which is what
                 a signature that does not chain to a trusted root looks like from here, and what
                 an altered file looks like too;
  untimestamped  it is signed without a timestamp, so the signature stops verifying when the
                 signing certificate expires. The certificates this release signs with are valid
                 for three days, so an untimestamped artefact is worthless by the end of the week.

A file can fail more than one, and all of them are reported. `signtool verify /pa /v` is run over
every file and its whole output is printed, so the run's log carries the verdict this script acted
on rather than a summary of it.

Nothing is published from this script. What it writes instead, with -Receipt, is a record of what
it accepted: one line per artefact with its SHA-256, the certificate that signed it and the
timestamp it carries. The step that assembles a release archive takes its file list from that
record, so an artefact that did not pass through here has no way into the archive.

An empty directory is a refusal. A build that produced nothing must not read as a clean run.

.PARAMETER Path
The directory holding the artefacts. Every file below it is verified, at any depth.

.PARAMETER Receipt
Where to write the record of what was accepted. Written only when every artefact passed.

.PARAMETER SignToolPath
signtool.exe, when it is somewhere this script would not find it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path,

    [string] $Receipt,

    [string] $SignToolPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The whole of the judgement, kept apart from the machinery that gathers the facts so that each of
# the three refusals can be reached on its own and checked without a signing identity, a Windows
# API or a file. `scripts/check-windows-signature-gate.ps1` drives it with real files; the release
# rehearsal drives this function directly.
function Get-SignatureRefusal {
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Status,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $StatusMessage,
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $SignatureType,
        [Parameter(Mandatory)] [bool] $PolicyAccepted,
        [Parameter(Mandatory)] [bool] $HasTimestamp
    )

    $refusals = @()

    # Nothing else can be said about a file with no signature, and saying it has no timestamp
    # either would only bury the one fact that matters.
    if ($Status -eq 'NotSigned') {
        $refusals += [pscustomobject]@{
            Reason = 'unsigned'
            Detail = 'it carries no signature at all'
        }
        return , $refusals
    }

    if ($Status -ne 'Valid' -or -not $PolicyAccepted -or $SignatureType -ne 'Authenticode') {
        $refusals += [pscustomobject]@{
            Reason = 'untrusted'
            Detail = (
                'its signature is not accepted by the default Authenticode policy ' +
                "(status $Status, signature type $SignatureType, signtool " +
                "$(if ($PolicyAccepted) { 'accepted it' } else { 'refused it' })): $StatusMessage"
            )
        }
    }

    if (-not $HasTimestamp) {
        $refusals += [pscustomobject]@{
            Reason = 'untimestamped'
            Detail = (
                'it is signed without a timestamp, so its signature stops verifying when the ' +
                'signing certificate expires'
            )
        }
    }

    return , $refusals
}

function Resolve-SignTool {
    param([string] $Preferred)

    if ($Preferred) {
        if (-not (Test-Path -LiteralPath $Preferred -PathType Leaf)) {
            throw "signtool.exe is not at the path this run was given: $Preferred"
        }
        return (Resolve-Path -LiteralPath $Preferred).Path
    }

    $onPath = Get-Command -Name 'signtool.exe' -CommandType Application -ErrorAction Ignore |
        Select-Object -First 1
    if ($onPath) {
        return $onPath.Source
    }

    # The Windows SDK, and the build-tools package the signing action unpacks for itself. Newest
    # first, x64 before x86, because that is the pair the signing side of a release uses.
    $roots = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'),
        (Join-Path $env:ProgramFiles 'Windows Kits\10\bin'),
        (Join-Path $env:LOCALAPPDATA 'ArtifactSigning\Microsoft.Windows.SDK.BuildTools')
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }

    foreach ($root in $roots) {
        $found = Get-ChildItem -LiteralPath $root -Filter 'signtool.exe' -Recurse -File -ErrorAction Ignore |
            Where-Object { $_.FullName -match '\\x64\\' } |
            Sort-Object -Property FullName -Descending |
            Select-Object -First 1
        if ($found) {
            return $found.FullName
        }
    }

    throw (
        'signtool.exe was not found. It comes with the Windows SDK build tools ' +
        '(Microsoft.Windows.SDK.BuildTools, 10.0.2261.755 or newer); install it or pass ' +
        '-SignToolPath.'
    )
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    Write-Host "REFUSED: $Path is not a directory, so there is nothing to verify."
    exit 1
}

$root = (Resolve-Path -LiteralPath $Path).Path
$signtool = Resolve-SignTool -Preferred $SignToolPath

Write-Host "Verifying every artefact under $root"
Write-Host "signtool: $signtool"
Write-Host ''

$artefacts = @(Get-ChildItem -LiteralPath $root -File -Recurse | Sort-Object -Property FullName)

# A run that built nothing must not read as a run that verified everything it built.
if ($artefacts.Count -eq 0) {
    Write-Host "REFUSED: $root holds no files. A release that signed nothing is not a release."
    exit 1
}

$accepted = @()
$refused = 0

foreach ($artefact in $artefacts) {
    $relative = $artefact.FullName.Substring($root.Length).TrimStart('\', '/')

    Write-Host "--- $relative"

    # The whole of signtool's verdict, in the run's log, for every artefact. `/pa` is the default
    # Authenticode policy: the chain a person's machine will apply when it opens the file.
    $output = (& $signtool verify /pa /v $artefact.FullName 2>&1 | Out-String)
    $policyAccepted = ($LASTEXITCODE -eq 0)
    Write-Host $output.TrimEnd()

    $signature = Get-AuthenticodeSignature -LiteralPath $artefact.FullName
    $timestamp = $signature.TimeStamperCertificate

    $refusals = Get-SignatureRefusal `
        -Status ([string]$signature.Status) `
        -StatusMessage ([string]$signature.StatusMessage) `
        -SignatureType ([string]$signature.SignatureType) `
        -PolicyAccepted $policyAccepted `
        -HasTimestamp ($null -ne $timestamp)

    if ($refusals.Count -gt 0) {
        foreach ($refusal in $refusals) {
            Write-Host "REFUSED $relative ($($refusal.Reason)): $($refusal.Detail)"
        }
        $refused += 1
        continue
    }

    $accepted += [pscustomobject]@{
        Path        = $relative
        Sha256      = (Get-FileHash -LiteralPath $artefact.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        Signer      = $signature.SignerCertificate.Subject
        Thumbprint  = $signature.SignerCertificate.Thumbprint
        NotAfter    = $signature.SignerCertificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        TimestampBy = $timestamp.Subject
    }

    Write-Host "ACCEPTED $relative"
    Write-Host ''
}

Write-Host ''
Write-Host "$($accepted.Count) artefact(s) accepted, $refused refused, out of $($artefacts.Count)."

if ($refused -gt 0) {
    Write-Host 'REFUSED: nothing is published from this run.'
    exit 1
}

if ($Receipt) {
    $receiptDirectory = Split-Path -Parent $Receipt
    if ($receiptDirectory -and -not (Test-Path -LiteralPath $receiptDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $receiptDirectory -Force | Out-Null
    }

    $lines = @(
        '# The Windows artefacts this release signed, and what each signature is.',
        '#',
        '# Every artefact below carries an Authenticode signature that the default policy accepts',
        '# and an RFC 3161 timestamp, checked on the machine that built it before anything was',
        '# published. Verify a downloaded copy for yourself with:',
        '#',
        '#     Get-AuthenticodeSignature .\kr.exe | Format-List',
        '#     signtool verify /pa /v .\kr.exe',
        '#',
        "# sha256  path  signer  thumbprint  certificate expires  timestamped by"
    )
    foreach ($entry in $accepted) {
        $lines += (
            '{0}  {1}  {2}  {3}  {4}  {5}' -f
            $entry.Sha256, $entry.Path, $entry.Signer, $entry.Thumbprint, $entry.NotAfter, $entry.TimestampBy
        )
    }

    Set-Content -LiteralPath $Receipt -Value $lines -Encoding utf8NoBOM
    Write-Host "Record of what was accepted: $Receipt"
}

exit 0
