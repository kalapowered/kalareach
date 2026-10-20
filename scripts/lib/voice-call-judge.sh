#!/usr/bin/env bash
# Decides a run of the voice call's device scripts from the lines the application wrote.
#
# Sourced by `scripts/e2e-voice-call-device.sh` and `scripts/e2e-voice-call-bridge.sh`. The caller
# defines `say`, which prints a line to its log, and calls `judge_voice_call_result`.
#
# A line is `check=<name> ok=<0 or 1> detail=<text>`. A check's name holds no "=", so its verdict is
# the one right after the name, whatever the detail says: a detail that reads " ok=1 " is not a
# pass. A result with a check missing is a run that stopped short, so each name the caller requires
# must appear with verdict 1, and the result must say `done=1` and name this run.

# judge_voice_call_result <result file> <run> <required check name>...
#
# Returns 0 when every check passed and every required check was made, and 2 otherwise.
judge_voice_call_result() {
    local file=$1 run=$2 bad=0 line name
    shift 2
    [ -s "$file" ] || { say "the application wrote no result"; return 2; }
    grep -q "^run=$run\$" "$file" || { say "the result names another run"; return 2; }
    while IFS= read -r line; do
        say "$line"
        case "$line" in
            check=*)
                [ "$(printf '%s' "$line" | sed -n 's/^check=[^=]* ok=\([01]\) detail=.*/\1/p')" = 1 ] || bad=1
                ;;
        esac
    done <"$file"
    grep -q '^done=1$' "$file" || { say "the result never says done"; return 2; }
    [ "$bad" = 0 ] || { say "a check did not pass"; return 2; }
    for name in "$@"; do
        awk -v want="check=$name ok=1 detail=" 'index($0, want) == 1 { found = 1 } END { exit !found }' "$file" \
            || { say "the check '$name' was not made"; return 2; }
    done
    say "every check of the application passed"
}
