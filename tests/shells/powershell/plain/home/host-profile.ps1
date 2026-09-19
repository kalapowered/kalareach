Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-top'

function global:prompt { 'KR> ' }
$global:KR_TEST_USER_CONFIGURATION = 1
Set-PSReadLineOption -HistorySaveStyle SaveNothing
Set-PSReadLineOption -PredictionSource None
# A line typed before this editor takes the terminal arrives through the terminal's own line
# discipline, which sends a line feed where the return was. This person has bound that to the same
# acceptance, so a line they type a moment early is still theirs.
Set-PSReadLineKeyHandler -Chord Ctrl+j -Function AcceptLine

# A handler of the person's own, on a chord nothing in the integration claims.
Set-PSReadLineKeyHandler -Chord Alt+q -BriefDescription 'kr-user-binding' -LongDescription 'the person own binding' -ScriptBlock {
    [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert('kr-user-binding-ran')
}

Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-bottom'
# {kalareach-entry}
