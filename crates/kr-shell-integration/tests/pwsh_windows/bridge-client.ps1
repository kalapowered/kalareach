# Drives the PSReadLine package's bridge client against a worker endpoint, without the editor.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# The module's endpoint, framing and handshake live in KrBridge.ps1 and are what this exercises:
# it connects to the address the worker exported, sends the hello with the proof over the bootstrap
# transcript, reads the worker's reply, reports one reader event and then either collects the
# answer or waits for the worker to close the endpoint. Nothing here re-implements the module; each
# step is one of the module's own functions.
#
# The editor is deliberately absent. The reader's own state needs a live PSReadLine, and what is
# under test is the transport beneath it, so the package identity comes from the environment the
# caller set rather than from an installed module. Every observation is appended to the report file
# the caller named, so a failure says which step it stopped at.

[CmdletBinding()]
param(
    # Where this package's module files are, in the checkout under test.
    [Parameter(Mandatory)][string]$ModuleDirectory,
    # Where to write what each step observed.
    [Parameter(Mandatory)][string]$Report,
    # `exchange` collects the worker's answer to the event; `closed` waits for the worker to go.
    [Parameter(Mandatory)][ValidateSet('exchange', 'closed')][string]$Mode
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Write-Report {
    param([string]$Line)
    [System.IO.File]::AppendAllText($Report, "$Line`n")
}

function Stop-WithReason {
    param([string]$Line)
    Write-Report "failed $Line"
    exit 1
}

. (Join-Path $ModuleDirectory 'KrCbor.ps1')
. (Join-Path $ModuleDirectory 'KrBridge.ps1')

$endpoint = $env:KR_SHELL_BRIDGE
$secret = $env:KR_SHELL_BRIDGE_SECRET
$session = $env:KR_SESSION
if ([string]::IsNullOrEmpty($endpoint)) { Stop-WithReason 'no endpoint was exported' }
if ([string]::IsNullOrEmpty($secret)) { Stop-WithReason 'no secret was exported' }
if ([string]::IsNullOrEmpty($session)) { Stop-WithReason 'no session was exported' }

$sessionBytes = ConvertFrom-KrUuidText $session
if ($null -eq $sessionBytes) { Stop-WithReason "the session identifier did not parse: $session" }
$secretBytes = ConvertFrom-KrBase64Url $secret
if ($null -eq $secretBytes -or $secretBytes.Length -eq 0) { Stop-WithReason 'the secret did not decode' }

$script:Kr.Session = $sessionBytes
$script:Kr.Secret = $secretBytes
$script:Kr.Endpoint = $endpoint
$script:Kr.Identity = Get-KrProcessIdentity
Write-Report ("identity pid={0} source={1} start={2}" -f
    $script:Kr.Identity.pid, $script:Kr.Identity.source, $script:Kr.Identity.start_value)

# The package identity a qualified installation publishes. It is supplied here because this test
# proves the transport rather than the editor: an installed PSReadLine would make the result depend
# on a machine state nothing in this repository records.
$package = @{
    executable          = $env:KR_BRIDGE_EXECUTABLE
    upstream_version    = $env:KR_BRIDGE_UPSTREAM_VERSION
    editor_abi          = $env:KR_BRIDGE_EDITOR_ABI
    integration_version = $env:KR_BRIDGE_INTEGRATION_VERSION
    patches             = @()
    modules             = @()
}

$script:Kr.Socket = Connect-KrEndpoint $endpoint
if ($null -eq $script:Kr.Socket) { Stop-WithReason "the endpoint refused the connection: $endpoint" }
Write-Report 'connected'

$transcript = Get-KrTranscript $script:Kr.Identity $package.integration_version
$mac = [System.Security.Cryptography.HMACSHA256]::new($script:Kr.Secret)
try { $proof = $mac.ComputeHash($transcript) } finally { $mac.Dispose() }

if (-not (Send-KrFrame @{ hello = (New-KrHello $script:Kr.Identity $proof $package) })) {
    Stop-WithReason 'the hello was not sent'
}
Write-Report 'hello sent'

if (-not (Wait-KrHandshake)) { Stop-WithReason 'no handshake reply was read' }
Write-Report ("accepted hint={0} gesture_byte={1}" -f $script:Kr.Hint, $script:Kr.GestureByte)

$script:Kr.Registered = $true
$script:Kr.Managed = $true
Send-KrEvent 'hooks_activated' @{
    session_id        = $script:Kr.Session
    prompt_generation = [uint64]1
}
if ($null -eq $script:Kr.Socket) { Stop-WithReason 'the event closed the endpoint' }
Write-Report "event sent id=$($script:Kr.EventCounter)"

# Neither branch waits on the endpoint: each one asks the module for what has already arrived,
# exactly as a reader between operations does, and gives up on a deadline of its own.
$deadline = (Get-KrNowMs) + 30000
if ($Mode -eq 'exchange') {
    while ($true) {
        $body = Read-KrFrame
        if ($null -ne $body) {
            $value = ConvertFrom-KrCbor $body
            $variant = Get-KrVariant $value
            if ($null -eq $variant) { Stop-WithReason 'the answer did not decode' }
            Write-Report "answer $($variant.Name)"
            break
        }
        if ((Get-KrNowMs) -gt $deadline) { Stop-WithReason 'the answer never arrived' }
        if (-not (Receive-KrAvailable)) { Stop-WithReason 'the endpoint went before the answer' }
        [System.Threading.Thread]::Sleep(5)
    }
    Disconnect-KrEndpoint
    Write-Report 'disconnected'
    exit 0
}

while ($true) {
    if (-not (Receive-KrAvailable)) { break }
    if ((Get-KrNowMs) -gt $deadline) { Stop-WithReason 'the closed endpoint was never reported' }
    [System.Threading.Thread]::Sleep(5)
}
if ($null -ne $script:Kr.Socket) { Stop-WithReason 'the endpoint was not dropped' }
if ($script:Kr.Registered) { Stop-WithReason 'the registration outlived the endpoint' }
Write-Report 'loss reported'
exit 0
