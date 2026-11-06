#!/usr/bin/env bash
# Shows that the voice call scripts' judges fail a run that did not make or pass every required
# check, pass one that did, and call a run partial when a check that may go unmeasured did.
#
#   bash scripts/lib/voice-call-judge-check.sh
#
# It judges result files made here: a good one, one with a failing check, one whose failing check
# says " ok=1 " in its detail, one missing a required check, one that never says done, one that
# names another run, an empty one, one whose check that may go unmeasured did (partial), one whose
# check that must be measured did not, and one with a verdict that is not 0, 1 or 2. It judges the
# machine side's reports too: a good run, a run whose voice service never went away, a peer that
# heard nothing, a peer that heard nothing from a phone that could not send, and a lock screen that
# still offers a control after the end. It exits non-zero if any verdict is not the expected one.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say() { :; }
# shellcheck source=scripts/lib/voice-call-judge.sh
. "$here/voice-call-judge.sh"

dir="$(mktemp -d "${TMPDIR:-/tmp}/kr-judge-check.XXXXXX")"
trap 'rm -rf "${dir:?}"' EXIT
run=RUN1
required=("open" "a name with (parentheses) and 'quotes'" "the end is told" "audio reaches the call?")

good() {
    echo "run=$run"
    for name in "open" "a name with (parentheses) and 'quotes'" "the end is told" "audio reaches the call"; do
        echo "check=$name ok=1 detail=fine"
    done
    echo "done=1"
}

good >"$dir/good.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=0 detail=bad/" >"$dir/failing.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=0 detail=bad ok=1 detail=/" >"$dir/lying.txt"
good | grep -v "the end is told" >"$dir/short.txt"
good | grep -v '^done=1$' >"$dir/undone.txt"
good | sed "s/^run=$run\$/run=OTHER/" >"$dir/other.txt"
good | sed "s/^check=audio reaches the call ok=1 detail=fine/check=audio reaches the call ok=2 detail=no microphone/" >"$dir/partial.txt"
good | sed "s/^check=the end is told ok=1 detail=fine/check=the end is told ok=2 detail=not measured/" >"$dir/unmeasured-required.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=3 detail=odd/" >"$dir/odd.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=2 detail=fine ok=1/" >"$dir/lying-unmeasured.txt"
: >"$dir/empty.txt"

failed=0
expect() { # <file> <expected status>
    local status=0
    judge_voice_call_result "$dir/$1.txt" "$run" "${required[@]}" || status=$?
    if [ "$status" != "$2" ]; then
        echo "FAILED: $1 judged $status, expected $2"
        failed=1
    fi
}
expect good 0
expect failing 2
expect lying 2
expect short 2
expect undone 2
expect other 2
expect empty 2
expect partial 4
expect unmeasured-required 2
expect odd 2
expect lying-unmeasured 2

# The machine side's report of an outage run on each platform.
report() { # <name> <python expression editing `r`>
    python3 - "$dir/$1.json" "$2" <<'PY'
import json
import sys

out, edit = sys.argv[1], sys.argv[2]
sample = lambda seconds, **figures: {"seconds": seconds, "figures": figures}
r = {
    "creations": 1,
    "host_closes": 0,
    "control_tokens": ["Bearer t"],
    "control_commands": [],
    "token": "t",
    "went_down": True,
    "peer": {
        "relayed": 1,
        "answered": 1,
        "errors": [],
        "figures": [
            sample(1, packetsReceived=0, packetsSent=10, recorderStarted=True, errors=[],
                   lockScreen={"pauseOffered": True, "stopOffered": True, "playOffered": False, "toggleOffered": False, "title": "Kala Reach voice call", "rate": 1.0}),
            sample(9, packetsReceived=400, packetsSent=450, recorderStarted=True, errors=[],
                   lockScreen={"pauseOffered": False, "stopOffered": False, "playOffered": False, "toggleOffered": False, "title": None, "rate": None}),
        ],
    },
}
exec(edit)
json.dump(r, open(out, "w"))
PY
}
judge_report() { # <name> <platform> <expected status> [flags]
    local status=0 name=$1 platform=$2 want=$3
    shift 3
    python3 "$here/voice-call-host-judge.py" "$dir/$name.json" outage "$platform" "$@" >/dev/null || status=$?
    if [ "$status" != "$want" ]; then
        echo "FAILED: the report $name on $platform judged $status, expected $want"
        failed=1
    fi
}
report good "pass"
report never-down "r['went_down'] = False"
report deaf-peer "r['peer']['figures'] = [f for f in r['peer']['figures']]; [f['figures'].update(packetsReceived=3) for f in r['peer']['figures']]"
report lock-screen-stays "r['peer']['figures'][-1]['figures']['lockScreen']['pauseOffered'] = True"
report never-offered "[f['figures']['lockScreen'].update(pauseOffered=False, stopOffered=False, title=None, rate=None) for f in r['peer']['figures']]"
report never-offered-unheard "[f['figures']['lockScreen'].update(pauseOffered=False, stopOffered=False, title=None, rate=None) for f in r['peer']['figures']]; [f['figures'].update(packetsReceived=3) for f in r['peer']['figures']]"
report play-offered "r['peer']['figures'][0]['figures']['lockScreen']['playOffered'] = True"
report toggle-offered "r['peer']['figures'][0]['figures']['lockScreen']['toggleOffered'] = True"
report stop-not-offered "r['peer']['figures'][0]['figures']['lockScreen']['stopOffered'] = False"
report wrong-title "r['peer']['figures'][0]['figures']['lockScreen']['title'] = 'Someone else'"
report rate-against-pause "r['peer']['figures'][0]['figures']['lockScreen']['rate'] = 0"
report unanswered "r['peer']['answered'] = 0; r['peer']['errors'] = ['no connection to the peer']"
judge_report good android 0
judge_report good ios 0
judge_report never-down android 2
judge_report deaf-peer android 2
judge_report deaf-peer android 4 --send-unmeasured
judge_report lock-screen-stays ios 2
judge_report never-offered ios 2
judge_report play-offered ios 2
judge_report toggle-offered ios 2
judge_report stop-not-offered ios 2
judge_report wrong-title ios 2
judge_report rate-against-pause ios 2
judge_report never-offered-unheard ios 4 --send-unmeasured
judge_report unanswered android 2

[ "$failed" = 0 ] && echo "the judges decide every case as they should"
exit "$failed"
