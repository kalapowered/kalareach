Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-top'

function global:prompt { 'KR> ' }
$global:KR_TEST_USER_CONFIGURATION = 1
Set-PSReadLineOption -HistorySaveStyle SaveNothing
Set-PSReadLineOption -PredictionSource History
Set-PSReadLineOption -PredictionViewStyle InlineView
Set-PSReadLineOption -BellStyle None
Set-PSReadLineOption -EditMode Emacs
Set-PSReadLineKeyHandler -Chord Ctrl+j -Function AcceptLine
Set-PSReadLineKeyHandler -Chord Ctrl+w -Function BackwardDeleteWord
Set-PSReadLineKeyHandler -Chord Alt+d -Function DeleteWord

Set-PSReadLineKeyHandler -Chord Alt+q -BriefDescription 'kr-user-binding' -LongDescription 'the person own binding' -ScriptBlock {
    [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
    [Microsoft.PowerShell.PSConsoleReadLine]::Insert('kr-user-binding-ran')
}

Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'user-bottom'
# {kalareach-entry}
