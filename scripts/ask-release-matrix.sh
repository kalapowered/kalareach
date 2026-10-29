#!/usr/bin/env bash
# Asks the signed release matrix whether it lists this release, with the program a job built earlier.
#
#   scripts/ask-release-matrix.sh <directory that holds kr-release-matrix-check and its .sha256> <its SHA-256>
#   scripts/ask-release-matrix.sh self-test
#
# The program is held to the sum beside it, and to the SHA-256 the job that built it stated as an
# output, which is required (the sum beside it is in the same artefact, so it shows damage and not a
# replacement), and run against the managed service, in the way the other
# publication jobs run the one they build: a refusal (exit 1) is final, and a service that did not
# answer (exit 2) is asked again twice, a minute apart. KR_MATRIX_RETRY_SECONDS shortens the minute
# for the self-test. The job that writes a release runs this before it writes anything and in every
# attempt, so a re-run never goes on an earlier answer.

set -uo pipefail

origin="https://reach.kala.to"

ask() { # <directory> [<SHA-256 of the program>]
    local directory="${1:?name the directory}" program attempt code pause="${KR_MATRIX_RETRY_SECONDS:-60}"
    program="$directory/kr-release-matrix-check"
    (cd "$directory" && sha256sum -c kr-release-matrix-check.sha256) || return 1
    if [ -n "${2:-}" ] && [ "$(sha256sum "$program" | cut -d' ' -f1)" != "$2" ]; then
        echo "ask-release-matrix: the program is not the one the job that built it stated" >&2
        return 1
    fi
    chmod +x "$program"
    for attempt in 1 2 3; do
        "$program" --origin "$origin" && return 0
        code=$?
        [ "$code" -eq 2 ] || return "$code"
        [ "$attempt" -lt 3 ] && sleep "$pause"
    done
    return 2
}

self_test() {
    local work status=0 me
    me="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-ask-matrix.XXXXXX")"
    trap 'rm -rf "${work:?}"' RETURN
    export KR_MATRIX_RETRY_SECONDS=0
    # A stand-in program: it answers with the codes listed in $work/codes, one for each time it is run.
    stand_in() { # <codes...>
        rm -rf "${work:?}/program"
        mkdir -p "$work/program"
        printf '%s\n' "$@" > "$work/codes"
        printf '0\n' > "$work/runs"
        cat > "$work/program/kr-release-matrix-check" << 'PROGRAM'
#!/usr/bin/env bash
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runs=$(( $(cat "$dir/runs") + 1 )); echo "$runs" > "$dir/runs"
code="$(sed -n "${runs}p" "$dir/codes")"
exit "${code:-0}"
PROGRAM
        (cd "$work/program" && sha256sum kr-release-matrix-check > kr-release-matrix-check.sha256)
    }
    check() { # <name> <expected exit> <expected runs> [<SHA-256 the program is expected to have>]
        local got runs
        # By the command line, as the workflow runs it; without a digest, the first argument alone.
        if [ -n "${4:-}" ]; then
            bash "$me" "$work/program" "$4" > /dev/null 2>&1; got=$?
        else
            ask "$work/program" > /dev/null 2>&1; got=$?
        fi
        runs="$(cat "$work/runs")"
        if [ "$got" = "$2" ] && [ "$runs" = "$3" ]; then
            echo "self-test ok: $1"
        else
            echo "self-test FAILED: $1 (exit $got after $runs runs; wanted $2 after $3)"
            status=1
        fi
    }
    stand_in 0;       check "a matrix that lists the release is accepted at once" 0 1
    stand_in 1 0;     check "a refusal is final and is not asked again" 1 1
    stand_in 2 2 0;   check "a service that does not answer is asked again, and the third answer counts" 0 3
    stand_in 2 2 2 0; check "a service that does not answer three times ends the run with exit 2" 2 3
    stand_in 0
    # A program that counts its runs, in place of the one whose sum was recorded.
    cat > "$work/program/kr-release-matrix-check" << 'PROGRAM'
#!/usr/bin/env bash
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo $(( $(cat "$dir/runs") + 1 )) > "$dir/runs"
exit 0
PROGRAM
    check "a program that is not the one whose sum was recorded is refused and not run" 1 0
    stand_in 0
    check "a program whose sum is right and whose SHA-256 is not the one stated is refused and not run" 1 0 "$(printf x | sha256sum | cut -d' ' -f1)"
    check "a program whose SHA-256 is the one stated is run" 0 1 "$(sha256sum "$work/program/kr-release-matrix-check" | cut -d' ' -f1)"
    stand_in 0
    bash "$me" "$work/program" > /dev/null 2>&1 && { echo "self-test FAILED: the program was run with no digest stated"; status=1; } || echo "self-test ok: no digest stated is a refusal from the command line"
    [ "$status" -eq 0 ] && echo "ask-release-matrix: the self-test passed"
    return "$status"
}

case "${1:-}" in
    self-test) self_test ;;
    *) ask "${1:?name the directory that holds the program}" "${2:?name the SHA-256 the job that built the program stated}" ;;
esac
