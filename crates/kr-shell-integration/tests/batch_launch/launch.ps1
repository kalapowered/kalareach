# Builds the line a launch installs for an argument vector, runs it, and reports what became of it.
#
# Copyright (c) Kala Powered. Distributed under the BSD 3-Clause Licence in the repository root.
#
# The line comes from the module's own `Get-KrLaunchText`, the function the reader calls when a
# launch arrives, and is then run with `Invoke-Expression`, which binds the arguments of a native
# program as an accepted line does. The editor is absent: what is under test is the line and what
# the program makes of it. On a platform with no batch files `-AsBatch` makes every program one, so
# that the decision about the words can be run there too.
#
# Each case is a program and the words after it. The program writes what it received to the file
# named by `KR_CASE_OUT`, so a case that was refused leaves no file. The report holds one line per
# case: `case <n> refused` when the module built no line, otherwise `case <n> ran` and then
# `case <n> line <the line>`.

[CmdletBinding()]
param(
    # Where this package's module files are, in the checkout under test.
    [Parameter(Mandatory)][string]$ModuleDirectory,
    # A JSON file: an array of `{ "program": "...", "words": ["..."] }`.
    [Parameter(Mandatory)][string]$Cases,
    # Where each case's program writes, as `case-<n>.txt`, and where the report goes.
    [Parameter(Mandatory)][string]$Directory,
    # A directory put in front of the search path, for a program named without a path.
    [string]$SearchDirectory,
    # Treats every program as a batch file, for a platform that has none.
    [switch]$AsBatch
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

. (Join-Path $ModuleDirectory 'KrCbor.ps1')
. (Join-Path $ModuleDirectory 'KrBridge.ps1')

# The word quoting lives in the reader's file, which binds the editor's own type as it is loaded
# and so needs an editor this helper does not have. The function itself is taken out of the file
# as it stands.
$readerFile = Join-Path $ModuleDirectory 'KrReader.ps1'
$tree = [System.Management.Automation.Language.Parser]::ParseFile($readerFile, [ref]$null, [ref]$null)
$quoting = $tree.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-KrQuotedArgument'
    }, $true)
if ($null -eq $quoting) { throw 'the reader file has no Get-KrQuotedArgument' }
. ([scriptblock]::Create($quoting.Extent.Text))

if ($AsBatch) {
    function Test-KrBatchProgram { param([string]$Path) $true }
}

$report = Join-Path $Directory 'report.txt'
function Write-Report {
    param([string]$Line)
    [System.IO.File]::AppendAllText($report, "$Line`n")
}

if ($SearchDirectory) {
    $env:PATH = $SearchDirectory + [System.IO.Path]::PathSeparator + $env:PATH
}

$list = @(ConvertFrom-Json ([System.IO.File]::ReadAllText($Cases, [System.Text.Encoding]::UTF8)) -NoEnumerate)
$number = 0
foreach ($case in $list[0]) {
    $number++
    $vector = @([string]$case.program)
    foreach ($word in @($case.words)) { $vector += [string]$word }
    $text = Get-KrLaunchText @{ arguments = $vector }
    if ($null -eq $text) {
        Write-Report "case $number refused"
        continue
    }
    Write-Report "case $number ran"
    Write-Report "case $number line $text"
    $env:KR_CASE_OUT = Join-Path $Directory "case-$number.txt"
    Invoke-Expression $text
}
Write-Report 'done'
exit 0
