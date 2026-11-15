#!/bin/bash
# The last step: every probe line of the job once more, the failures first, and a status.
set -u
lines="${RUNNER_TEMP:?}/probe-lines.txt"
[ -s "$lines" ] || { echo "PROBE-TOTAL no probe lines"; exit 1; }
fails=$(grep -c '^PROBE [^ ]* FAIL ' "$lines")
oks=$(grep -c '^PROBE [^ ]* ok ' "$lines")
grep '^PROBE [^ ]* FAIL ' "$lines" || true
echo "PROBE-TOTAL ok=$oks FAIL=$fails"
[ "$fails" -eq 0 ]
