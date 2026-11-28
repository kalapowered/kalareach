#!/usr/bin/env bash
# Holds the refusal of scripts/window-leg-macos.sh to what it promises, without running anything else
# of that script: the script writes a real account's Terminal preferences, so only the text between
# its `guard begin` and `guard end` lines is run, each time in an empty environment, and the lines
# before the guard are read as text. The guard only reads. Two cases name the machine's real
# account, where the guard must refuse; the others stand in for the account (a function `id` that
# answers runner, a function `uname` that answers Darwin, and this file for the hosted agent's file), so that each condition of the guard
# alone is what refuses.
#
#   scripts/window-leg-guard-test.sh

set -uo pipefail

script="$(dirname "$0")/window-leg-macos.sh"
guard="$(awk '/^# guard begin$/{on=1; next} /^# guard end$/{on=0} on' "$script")"
failed=0
fail() { echo "window-leg-guard-test: FAIL: $*"; failed=1; }

[ -n "$guard" ] || { echo "window-leg-guard-test: no guard in $script"; exit 1; }

# The guard is the script's first statement: before it, only comments, blank lines and `set`.
stray="$(awk '/^# guard begin$/{exit} !/^#/ && !/^[[:space:]]*$/ && !/^set -uo pipefail$/' "$script")"
[ -z "$stray" ] || fail "a line comes before the guard: $stray"

stand_in="${guard//\/opt\/hca\/hosted-compute-agent/$0}"
[ "$stand_in" != "$guard" ] || fail "the guard names no agent file"
as_runner='id() { echo runner; }; uname() { echo Darwin; }'
hosted=(GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUNNER_OS=macOS KR_WINDOW_LEG=1 HOME=/Users/runner)

# `refuses <label> <text> <variable assignments...>` runs the text under exactly those variables.
refuses() {
    local label=$1 text=$2 out status
    shift 2
    out="$(env -i PATH=/usr/bin:/bin "$@" bash -c "$text" 2>&1)"
    status=$?
    if [ "$status" -ne 2 ] || [ -z "$out" ]; then fail "$label: exit $status, said: $out"; else echo "ok: $label refuses (exit 2)"; fi
}
# The real account of this machine: a hosted runner's own account is the one place this would pass.
if [ "$(id -un)" = runner ] && [ "$HOME" = /Users/runner ] && [ -e /opt/hca/hosted-compute-agent ]; then
    echo "skipped: the real account is a hosted runner's"
else
    refuses "an empty environment, the real account" "$guard"
    refuses "every hosted variable, the real account" "$guard" "${hosted[@]}"
fi
# With the account stood in for, the hosted values pass, and each one alone is what refuses.
out="$(env -i PATH=/usr/bin:/bin "${hosted[@]}" bash -c "$as_runner; $stand_in" 2>&1)"
status=$?
if [ "$status" -eq 0 ] && [ -z "$out" ]; then echo "ok: every condition met passes, silently"; else fail "the conditions met did not pass: $out"; fi
for name in GITHUB_ACTIONS RUNNER_ENVIRONMENT RUNNER_OS KR_WINDOW_LEG HOME; do
    others=()
    for pair in "${hosted[@]}"; do [ "${pair%%=*}" = "$name" ] || others+=("$pair"); done
    refuses "$name missing" "$as_runner; $stand_in" "${others[@]}"
done
refuses "a self-hosted runner" "$as_runner; $stand_in" "${hosted[@]/github-hosted/self-hosted}"
refuses "another home" "$as_runner; $stand_in" "${hosted[@]/\/Users\/runner/\/Users\/someone}"
refuses "another account" "id() { echo someone; }; uname() { echo Darwin; }; $stand_in" "${hosted[@]}"
refuses "another system" "$as_runner; uname() { echo Linux; }; $stand_in" "${hosted[@]}"
refuses "no agent file" "$as_runner; ${guard//\/opt\/hca\/hosted-compute-agent/$0.absent}" "${hosted[@]}"
refuses "a preferences variable set to a directory" "$as_runner; $stand_in" "${hosted[@]}" KR_TERMINAL_PREFERENCES_DIR=/tmp
refuses "a preferences variable set to an empty value" "$as_runner; $stand_in" "${hosted[@]}" KR_TERMINAL_PREFERENCES_DIR=

# After the refusal nothing else runs: the trace of a refusal ends at its exit.
trace="$(env -i PATH=/usr/bin:/bin bash -x -c "$guard" 2>&1 > /dev/null)"
[ "$(printf '%s\n' "$trace" | tail -1)" = "+ exit 2" ] || fail "the trace does not end at the refusal's exit"
echo "programs the guard names without a path:"
printf '%s\n' "$guard" | grep -oE '\$\([a-z]+' | sort -u
exit "$failed"
