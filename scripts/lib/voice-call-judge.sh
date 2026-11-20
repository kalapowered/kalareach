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

# Whether the system ended the application's process for the install of a package (the emulator's Play
# Store updating the WebView ends every application that shows one), which a leg did not make and no
# call survives: the wait for the result says so, naming the system's record, and the result stops
# where the process did. Every check the application made before then must have passed, and the host
# judge must have given a verdict (its exit status is 0, 2 or 4). The host checks that failed are not
# read: a call that ends early leaves the host with what it did not see, so they fail whatever the
# product did. Nothing is hidden by that, since the attempt is kept under its own name, the leg ends
# partial (a replay is never a pass), and the replay's own result and host checks stand on their own.
# The process ending for any other reason, or for none that the system recorded, is the leg's.
system_ended_the_application() { # <result file> <run log> <host judge status file>
    local verdict
    grep -q "the application's process ended before the result said done: .*installPackageLI" "$2" 2>/dev/null || return 1
    ! grep -q ' ok=0 detail=' "$1" 2>/dev/null || return 1
    verdict=$(cat "$3" 2>/dev/null)
    case "$verdict" in 0 | 2 | 4) ;; *) return 1 ;; esac
}

# Whether a leg's attempt may be played again on a new call: its result is complete (it says done), every
# check it failed names the call's own recorder as having broken by itself, the host judge gave a verdict
# (its exit status is 0, 2 or 4: a missing report or a judge that stopped leaves none), and every host
# check that failed is one an early stop or the break itself makes fail: a delegation never answered
# ("told nothing") or answered as a tainted call ("told tainted"), and the telling of the taint, once.
# A wrong or doubled reply to a delegation, a stray delegation, the attach words, the call, the token
# and the peer's answer are not the break's, and a later clean attempt must not hide them.
leg_is_replayable() { # <result file> <run log> <host judge status file>
    local result=$1 runlog=$2 hostrc=$3 failed marked verdict independent
    grep -q '^done=1$' "$result" 2>/dev/null || { system_ended_the_application "$result" "$runlog" "$hostrc"; return; }
    failed=$(grep -c ' ok=0 detail=' "$result" 2>/dev/null)
    marked=$(grep -c ' ok=0 detail=.*the recorder broke by itself' "$result" 2>/dev/null)
    { [ "${marked:-0}" -gt 0 ] && [ "${failed:-0}" = "$marked" ]; } || return 1
    verdict=$(cat "$hostrc" 2>/dev/null)
    case "$verdict" in 0 | 2 | 4) ;; *) return 1 ;; esac
    independent=$(grep -h ' host check=.* ok=0 ' "$runlog" 2>/dev/null |
        grep -c -v -E 'host check=the model was told what became of d-[0-9]+ ok=0 detail=told (nothing|tainted), expected |host check=the model was told once that the call can no longer act ok=0 detail=0 times|host check=the model was never told the call can no longer act ok=0 detail=1 times')
    [ "${independent:-0}" = 0 ]
}

# Waits for the application's result to say `done=1`, for at most <limit> seconds, looking every
# <interval> seconds. The caller supplies four commands: <reader> prints the lines the application
# has written so far, <alive> succeeds while the application's process runs, <cue> is given the lines
# read at each look (a leg acts on a line it reads), and <why> prints the system's record of why the
# process ended, if it has one. The last lines read stay in `waited_text`.
#
# Returns 0 when the result says done; 1 when the limit passed first; and 5 when the process was gone
# at two looks in a row and the result did not say done, which it says, with the system's record. A
# process that has ended writes nothing more, and its file stays readable, so only the process
# says that the wait is over.
wait_for_result() { # <limit> <interval> <reader> <alive> <cue> <why>
    local until=$((SECONDS + $1)) interval=$2 reader=$3 alive=$4 cue=$5 why=$6 gone=0 reason
    waited_text=""
    while :; do
        waited_text="$("$reader")"
        case "$waited_text" in *done=1*) return 0 ;; esac
        "$cue" "$waited_text"
        if "$alive"; then
            gone=0
        else
            gone=$((gone + 1))
        fi
        if [ "$gone" -ge 2 ]; then
            reason="$("$why")"
            say "the application's process ended before the result said done${reason:+: $reason}"
            return 5
        fi
        sleep "$interval"
        [ "$SECONDS" -lt "$until" ] || return 1
    done
}
