Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-top'

function global:prompt { 'KR> ' }
$global:KR_TEST_USER_CONFIGURATION = 1
Set-PSReadLineOption -HistorySaveStyle SaveNothing
Set-PSReadLineOption -PredictionSource None
Set-PSReadLineKeyHandler -Chord Ctrl+j -Function AcceptLine
# This person deletes with the key rather than leaving the session with it. The integration
# decides before the editor's own handler runs, so what the key does is still theirs.
Set-PSReadLineKeyHandler -Chord Ctrl+d -Function DeleteChar

# A binary module of the person's own, ahead of this runtime's own module path. It cannot be
# loaded here, and what the person gets is the runtime saying so rather than a session that
# carries on as though the module were there.
$env:PSModulePath = (Join-Path $HOME 'modules') + [System.IO.Path]::PathSeparator + $env:PSModulePath
try {
    Import-Module KrWrongAbi -ErrorAction Stop
    Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'kr-module-loaded'
} catch {
    Set-Content -LiteralPath (Join-Path $HOME 'module-error') -Value $_.Exception.Message
    Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'kr-module-refused'
}
# What the session ended up with, rather than what the import returned.
if (Get-Module -Name KrWrongAbi) {
    Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'kr-module-listed'
} else {
    Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'kr-module-absent'
}
Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'stack'

Set-PSReadLineKeyHandler -Chord Alt+q -BriefDescription 'kr-user-binding' -LongDescription 'the binding this person made' -ScriptBlock {
    [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert('kr-user-binding-ran')
}

Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-bottom'
# {kalareach-entry}
