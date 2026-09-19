# The profile every host of this shell runs, which comes before the one for this host alone.
Add-Content -LiteralPath $env:KR_TEST_ORDER -Value 'all-hosts'
