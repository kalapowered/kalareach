#!/usr/bin/env bash
# Decides a run of the voice call's device scripts from the lines the application wrote.
#
# Sourced by `scripts/e2e-voice-call-device.sh` and `scripts/e2e-voice-call-bridge.sh`. The caller
# defines `say`, which prints a line to its log, and calls `judge_voice_call_result`.
#
# A line is `check=<name> ok=<0, 1 or 2> detail=<text>`: 1 is a pass, 0 a failure, and 2 says the
# check could not measure what it asks about (a direction of audio the machine has no hardware to
# make, for instance). A check's name holds no "=", so its verdict is the one right after the name,
# whatever the detail says: a detail that reads " ok=1 " is not a pass. A result with a check
# missing is a run that stopped short, so each name the caller requires must appear, and the result
# must say `done=1` and name this run. A required name ends in "?" when it may be unmeasured; any
# other required name must pass, and a 2 on it fails the run.

# judge_voice_call_result <result file> <run> <required check name>...
#
# Returns 0 when every check passed and every required check was made and passed; 4 when every
# check that measured passed and some check that may be unmeasured was not measured (the run is
# partial evidence, and the names are said); and 2 otherwise.
judge_voice_call_result() {
    local file=$1 run=$2 bad=0 line name verdict unmeasurable unmeasured=()
    shift 2
    [ -s "$file" ] || { say "the application wrote no result"; return 2; }
    grep -q "^run=$run\$" "$file" || { say "the result names another run"; return 2; }
    while IFS= read -r line; do
        say "$line"
        case "$line" in
            check=*)
                verdict="$(printf '%s' "$line" | sed -n 's/^check=[^=]* ok=\([012]\) detail=.*/\1/p')"
                [ "$verdict" = 0 ] || [ "$verdict" = 1 ] || [ "$verdict" = 2 ] || bad=1
                [ "$verdict" != 0 ] || bad=1
                ;;
        esac
    done <"$file"
    grep -q '^done=1$' "$file" || { say "the result never says done"; return 2; }
    [ "$bad" = 0 ] || { say "a check did not pass"; return 2; }
    for name in "$@"; do
        unmeasurable=0
        case "$name" in *\?) unmeasurable=1; name="${name%\?}" ;; esac
        if awk -v want="check=$name ok=1 detail=" 'index($0, want) == 1 { found = 1 } END { exit !found }' "$file"; then
            continue
        fi
        if awk -v want="check=$name ok=2 detail=" 'index($0, want) == 1 { found = 1 } END { exit !found }' "$file"; then
            [ "$unmeasurable" = 1 ] || { say "the check '$name' could not measure, and this run needs it"; return 2; }
            unmeasured+=("$name")
            continue
        fi
        say "the check '$name' was not made"
        return 2
    done
    if [ "${#unmeasured[@]}" -gt 0 ]; then
        for name in "${unmeasured[@]}"; do say "not measured: $name"; done
        say "every check that measured passed, and ${#unmeasured[@]} could not measure"
        return 4
    fi
    say "every check of the application passed"
}

# Whether a leg's attempt may be played again on a new call: its result is complete (it says done), every
# check it failed names the call's own recorder as having broken by itself, and no host check failed
# but the ones an early stop of the leg always fails (what the model was told of a delegation, and of a
# call that can no longer act). Anything else failed in the attempt is not the recorder's, and a later
# clean attempt must not hide it.
leg_is_replayable() { # <result file> <run log>
    local result=$1 runlog=$2 failed marked independent
    grep -q '^done=1$' "$result" 2>/dev/null || return 1
    failed=$(grep -c ' ok=0 detail=' "$result" 2>/dev/null)
    marked=$(grep -c ' ok=0 detail=.*the recorder broke by itself' "$result" 2>/dev/null)
    { [ "${marked:-0}" -gt 0 ] && [ "${failed:-0}" = "$marked" ]; } || return 1
    independent=$(grep -h ' host check=.* ok=0 ' "$runlog" 2>/dev/null |
        grep -c -v -E 'host check=the model was (told what became of|told once that the call can no longer act|never told the call can no longer act)')
    [ "${independent:-0}" = 0 ]
}
