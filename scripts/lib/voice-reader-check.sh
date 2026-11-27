#!/usr/bin/env bash
# Shows what `scripts/e2e-voice-device.sh reader` decides about the text reader, with a stand-in for
# the Swift compiler and a stand-in reader that answers from the texts kept beside the pictures:
#
#   bash scripts/lib/voice-reader-check.sh
#
# Each case runs the script in a copy of the files it reads, in a folder of its own under one
# temporary folder, and judges the script's log, its exit code and what the stand-ins recorded. The
# stand-ins show the script's own decisions: which pictures it requires, when it builds again and when
# it stops. They show nothing of the system's text recognition; the real reader does that.
#
# Nothing here removes anything outside the temporary folder this run made: the script's removal goes
# through a stand-in `rm` that records each call and refuses a path outside that folder, and the
# folder itself is removed at the end only when every case passed. It exits non-zero if any
# assertion failed.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixtures_of_repo="$here/apps/companion/test/voice/reader-fixtures"
root="$(mktemp -d "${TMPDIR:-/tmp}/kr-voice-reader-check.XXXXXX")" || exit 1
root="$(cd "$root" && pwd -P)" || exit 1
failures=0

cleanup() {
    if [ "$failures" -ne 0 ]; then
        printf 'the cases that failed are kept in %s\n' "$root"
        return 0
    fi
    case "$root" in
        */kr-voice-reader-check.??????) [ -d "$root" ] && [ ! -L "$root" ] && rm -rf -- "$root" ;;
    esac
    return 0
}
trap cleanup EXIT

expect() {
    local what=$1
    shift
    if "$@"; then
        printf 'ok   %s\n' "$what"
    else
        printf 'FAIL %s\n' "$what"
        failures=$((failures + 1))
    fi
}

# ---- The stand-ins -------------------------------------------------------------------------------

mkdir -p "$root/bin"

# The Swift compiler: records the environment it was started in and the path it was asked to write,
# and writes the stand-in reader there.
cat >"$root/bin/swiftc" <<'STANDIN'
#!/bin/bash
out=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then out=$2; shift; fi
    shift
done
printf 'CFFIXED_USER_HOME=%s\n' "${CFFIXED_USER_HOME-unset}" >>"$FAKE_DIR/swiftc.log"
printf '%s\n' "$out" >>"$FAKE_DIR/swiftc-out.log"
cp "$READER_STANDIN" "$out" && chmod +x "$out"
STANDIN
chmod +x "$root/bin/swiftc"

# `rm`: records each call, and removes only inside the folder this run made.
cat >"$root/bin/rm" <<'STANDIN'
#!/bin/bash
printf '%s\n' "$*" >>"$FAKE_DIR/rm.log"
for argument in "$@"; do
    case "$argument" in
        -*) ;;
        *..*) printf 'stand-in rm refuses %s\n' "$argument" >&2; exit 1 ;;
        "$FAKE_ROOT"/?*) ;;
        *) printf 'stand-in rm refuses %s\n' "$argument" >&2; exit 1 ;;
    esac
done
exec /bin/rm "$@"
STANDIN
chmod +x "$root/bin/rm"

# The reader. It prints the text kept beside the picture it is given. Every read is recorded with the
# home it was started with. FAKE_READER=fails makes each read fail (exit 2). FAKE_BAD_FIRST=N makes
# the first N folders (by KR_READER_HOME, in the order they are first used) read wrong, leaving out
# the first line of every text, as a wrong build of the system's programs leaves rows out.
cat >"$root/reader-standin.sh" <<'STANDIN'
#!/bin/bash
image=$1
name=${image##*/}
home=${KR_READER_HOME-unset}
printf '%s home=%s cffixed=%s\n' "$name" "$home" "${CFFIXED_USER_HOME-unset}" >>"$FAKE_DIR/reads.log"
[ "${FAKE_READER:-good}" != fails ] || exit 2
if ! grep -qxF -- "$home" "$FAKE_DIR/homes.log" 2>/dev/null; then
    printf '%s\n' "$home" >>"$FAKE_DIR/homes.log"
fi
index=$(grep -n -xF -- "$home" "$FAKE_DIR/homes.log" | head -n 1 | cut -d: -f1)
case "$name" in
    kr-voice-check-shows.png) printf 'Unmute microphone\nSession 1b\n$00.1 a second\n'; exit 0 ;;
    kr-voice-check-lacks.png) printf 'Start Voice Sessions\n'; exit 0 ;;
esac
if [ "${FAKE_BAD_FIRST:-0}" -ge "$index" ]; then
    cat -- "${image%.png}.txt" 2>/dev/null | tail -n +2
else
    cat -- "${image%.png}.txt" 2>/dev/null
fi
exit 0
STANDIN
chmod +x "$root/reader-standin.sh"

# ---- One run of the script -----------------------------------------------------------------------

# make_tree <case> [fixture file to leave out ...]: the files the script reads, copied into a folder of
# the case's own. The word ALL leaves out the folder of pictures.
make_tree() {
    local name=$1 file leave
    shift
    c="$root/$name"
    tree="$c/tree"
    mkdir -p "$c/fake" "$c/art" "$c/shots" "$tree/scripts/lib"
    cp "$here/scripts/e2e-voice-device.sh" "$tree/scripts/"
    cp "$here/scripts/lib/artifacts-dir.sh" "$here/scripts/lib/android-avd.sh" "$tree/scripts/lib/"
    [ "${1-}" != ALL ] || return 0
    mkdir -p "$tree/apps/companion/test/voice/reader-fixtures"
    for file in "$fixtures_of_repo"/*; do
        leave=0
        for left_out in "$@"; do
            if [ "${file##*/}" = "$left_out" ]; then leave=1; fi
        done
        [ "$leave" -eq 1 ] || cp "$file" "$tree/apps/companion/test/voice/reader-fixtures/"
    done
}

# run_script <case> [NAME=value ...]: the script in `reader` mode, in the case's tree.
run_script() {
    local name=$1
    shift
    c="$root/$name"
    env PATH="$root/bin:$PATH" KR_TEST_ARTIFACTS_DIR="$c/art" KR_MOBILE_SCREENSHOT_DIR="$c/shots" \
        FAKE_DIR="$c/fake" FAKE_ROOT="$root" READER_STANDIN="$root/reader-standin.sh" "$@" \
        bash "$c/tree/scripts/e2e-voice-device.sh" reader >"$c/out.log" 2>&1
    printf '%s\n' "$?" >"$c/rc"
}

# What a case reads back.
out() { printf '%s/%s/out.log' "$root" "$1"; }
check_log() { printf '%s/%s/art/voice-device/reader-check.log' "$root" "$1"; }
fake() { printf '%s/%s/fake/%s' "$root" "$1" "$2"; }
rc_is() { [ "$(cat "$root/$1/rc")" = "$2" ]; }
says() { grep -qF -- "$2" "$1"; }
never_says() { ! grep -qF -- "$2" "$1" 2>/dev/null; }
reads() { [ -f "$(fake "$1" reads.log)" ] && wc -l <"$(fake "$1" reads.log)" | tr -d ' '; }
no_reads() { [ ! -s "$(fake "$1" reads.log)" ]; }

# ---- The pictures the reader is held to ----------------------------------------------------------

# A deleted pair is a picture less: the check must stop before any read.
make_tree fixture-pair-deleted one-line.png one-line.txt
run_script fixture-pair-deleted
expect "a deleted pair: the reader reads nothing" no_reads fixture-pair-deleted
expect "a deleted pair: the log names the picture" says "$(check_log fixture-pair-deleted)" "one-line.png is missing"
expect "a deleted pair: the run fails with exit 2" rc_is fixture-pair-deleted 2

# A picture without its text file would be held to no words at all.
make_tree fixture-text-missing line-tokens.txt
run_script fixture-text-missing
expect "a missing text file: the reader reads nothing" no_reads fixture-text-missing
expect "a missing text file: the log names the file" says "$(check_log fixture-text-missing)" "line-tokens.txt is missing"

# A text file with no words would require nothing of a reader that gives nothing, but for no-text.
make_tree fixture-text-empty
: >"$root/fixture-text-empty/tree/apps/companion/test/voice/reader-fixtures/line-tokens.txt"
run_script fixture-text-empty
expect "an empty text file: the reader reads nothing" no_reads fixture-text-empty
expect "an empty text file: the log names the file" says "$(check_log fixture-text-empty)" "line-tokens.txt has no words"

# A text file for no-text that has words would require text of a picture without any.
make_tree fixture-no-text-words
printf 'Something\n' >"$root/fixture-no-text-words/tree/apps/companion/test/voice/reader-fixtures/no-text.txt"
run_script fixture-no-text-words
expect "no-text with words: the reader reads nothing" no_reads fixture-no-text-words
expect "no-text with words: the log names the file" says "$(check_log fixture-no-text-words)" "no-text.txt has words"

# A file that is not one of the twelve pairs is not read, and is not allowed to stand there.
make_tree fixture-unlisted
: >"$root/fixture-unlisted/tree/apps/companion/test/voice/reader-fixtures/stale.png"
run_script fixture-unlisted
expect "an unlisted file: the reader reads nothing" no_reads fixture-unlisted
expect "an unlisted file: the log names the file" says "$(check_log fixture-unlisted)" "stale.png is not one of the known pictures"

# No folder at all is a stop of its own, not a read of a path that is not there.
make_tree fixture-folder-missing ALL
run_script fixture-folder-missing
expect "no folder: the reader reads nothing" no_reads fixture-folder-missing
expect "no folder: the log says so" says "$(check_log fixture-folder-missing)" "the folder of known pictures is not there"

# The whole set is read, each picture once, before anything else.
make_tree fixture-complete
run_script fixture-complete
expect "the whole set: twelve reads" test "$(reads fixture-complete)" = 12
expect "the whole set: the script says they read as drawn" says "$(out fixture-complete)" "the text reader read the known pictures as drawn"

if [ "$failures" -ne 0 ]; then
    printf '%s case assertion(s) failed\n' "$failures"
    exit 1
fi
printf 'all cases passed\n'
