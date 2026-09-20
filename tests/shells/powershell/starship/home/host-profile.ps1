Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-top'

$global:KR_TEST_USER_CONFIGURATION = 1
Set-PSReadLineOption -HistorySaveStyle SaveNothing
Set-PSReadLineOption -PredictionSource None
Set-PSReadLineKeyHandler -Chord Ctrl+j -Function AcceptLine
# This person deletes with the key rather than leaving the session with it. The integration
# decides before the editor's own handler runs, so what the key does is still theirs.
Set-PSReadLineKeyHandler -Chord Ctrl+d -Function DeleteChar

$env:STARSHIP_CONFIG = Join-Path $HOME '.config/starship.toml'
$env:STARSHIP_CACHE = Join-Path $HOME '.cache/starship'
Invoke-Expression (& (Join-Path $env:KR_STACK_STARSHIP 'starship') init powershell)
Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'stack'

Set-PSReadLineKeyHandler -Chord Alt+q -BriefDescription 'kr-user-binding' -LongDescription 'the binding this person made' -ScriptBlock {
    [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert('kr-user-binding-ran')
}

Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-bottom'
# {kalareach-entry}
