#!/usr/bin/env bash
# Shows that the voice call scripts' judge fails a run that did not make or pass every required
# check, and passes one that did.
#
#   bash scripts/lib/voice-call-judge-check.sh
#
# It judges result files made here: a good one, one with a failing check, one whose failing check
# says " ok=1 " in its detail, one missing a required check, one that never says done, one that
# names another run, and an empty one. It exits non-zero if any verdict is not the expected one.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
say() { :; }
# shellcheck source=scripts/lib/voice-call-judge.sh
. "$here/voice-call-judge.sh"

dir="$(mktemp -d "${TMPDIR:-/tmp}/kr-judge-check.XXXXXX")"
trap 'rm -rf "${dir:?}"' EXIT
run=RUN1
required=("open" "a name with (parentheses) and 'quotes'" "the end is told")

good() {
    echo "run=$run"
    for name in "${required[@]}"; do echo "check=$name ok=1 detail=fine"; done
    echo "done=1"
}

good >"$dir/good.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=0 detail=bad/" >"$dir/failing.txt"
good | sed "s/^check=open ok=1 detail=fine/check=open ok=0 detail=bad ok=1 detail=/" >"$dir/lying.txt"
good | grep -v "the end is told" >"$dir/short.txt"
good | grep -v '^done=1$' >"$dir/undone.txt"
good | sed "s/^run=$run\$/run=OTHER/" >"$dir/other.txt"
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

[ "$failed" = 0 ] && echo "the judge decides every case as it should"
exit "$failed"
