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

# Node, which the script starts after the known pictures to draw its own: records the environment it was
# started in, and stops.
cat >"$root/bin/node" <<'STANDIN'
#!/bin/bash
printf 'CFFIXED_USER_HOME=%s\n' "${CFFIXED_USER_HOME-unset}" >>"$FAKE_DIR/node.log"
exit 1
STANDIN
chmod +x "$root/bin/node"

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
# home it was started with. FAKE_READER=fails makes each read fail (exit 2), and FAKE_READER=aborts
# makes each write a line to its error output and exit 134. FAKE_BAD_FIRST=N makes
# the first N folders (by KR_READER_HOME, in the order they are first used) read wrong, leaving out
# the first line of every text, as a wrong build of the system's programs leaves rows out.
# FAKE_DROP_LAST=1 leaves out the last line of every text instead. Like the
# system, it writes a file of compiled programs into the home folder it was started with
# (CFFIXED_USER_HOME) the first time it runs there, unless FAKE_COMPILES=0.
cat >"$root/reader-standin.sh" <<'STANDIN'
#!/bin/bash
image=$1
name=${image##*/}
home=${KR_READER_HOME-unset}
printf '%s home=%s cffixed=%s\n' "$name" "$home" "${CFFIXED_USER_HOME-unset}" >>"$FAKE_DIR/reads.log"
if [ -n "${CFFIXED_USER_HOME-}" ] && [ "${FAKE_COMPILES:-1}" = 1 ]; then
    programs="$CFFIXED_USER_HOME/Library/Caches/read-text-bin/com.apple.e5rt.e5bundlecache"
    if [ ! -d "$programs" ]; then
        mkdir -p "$programs" && printf 'programs for %s\n' "$CFFIXED_USER_HOME" >"$programs/program"
    fi
fi
[ "${FAKE_READER:-good}" != fails ] || exit 2
if [ "${FAKE_READER:-good}" = aborts ]; then
    printf 'fake reader: aborted on purpose\n' >&2
    exit 134
fi
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
elif [ "${FAKE_DROP_LAST:-0}" = 1 ]; then
    awk '{ line[NR] = $0 } END { for (i = 1; i < NR; i++) print line[i] }' "${image%.png}.txt" 2>/dev/null
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
    mkdir -p "$c/fake" "$c/tmp" "$c/shots" "$tree/scripts/lib"
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
    env -i PATH="$root/bin:$PATH" HOME="${HOME:-/}" TMPDIR="$c/tmp" KR_MOBILE_SCREENSHOT_DIR="$c/shots" \
        FAKE_DIR="$c/fake" FAKE_ROOT="$root" READER_STANDIN="$root/reader-standin.sh" "$@" \
        bash "$c/tree/scripts/e2e-voice-device.sh" reader >"$c/out.log" 2>&1
    printf '%s\n' "$?" >"$c/rc"
}

# What a case reads back.
out() { printf '%s/%s/out.log' "$root" "$1"; }
# The script makes its own evidence folder under the case's TMPDIR when none is given to it, and the
# run starts from an empty environment, so nothing the driver's caller set reaches it.
art_of() { local d; for d in "$root/$1"/tmp/*/voice-device; do printf '%s' "$d"; return; done; }
check_log() { printf '%s/reader-check.log' "$(art_of "$1")"; }
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

# An empty picture shows nothing to read, and is not the picture of no-text either.
make_tree fixture-picture-empty
: >"$root/fixture-picture-empty/tree/apps/companion/test/voice/reader-fixtures/one-line.png"
run_script fixture-picture-empty
expect "an empty picture: the reader reads nothing" no_reads fixture-picture-empty
expect "an empty picture: the log names the picture" says "$(check_log fixture-picture-empty)" "one-line.png is missing, empty or cannot be read"

# A text file the reader of the check cannot open is a missing text, not an empty one. A user that can
# read any file cannot show this, and the case is then left out.
make_tree fixture-text-unreadable
chmod 000 "$root/fixture-text-unreadable/tree/apps/companion/test/voice/reader-fixtures/line-tokens.txt"
if [ -r "$root/fixture-text-unreadable/tree/apps/companion/test/voice/reader-fixtures/line-tokens.txt" ]; then
    printf 'skip a text file that cannot be read: this user can read any file\n'
else
    run_script fixture-text-unreadable
    expect "an unreadable text file: the reader reads nothing" no_reads fixture-text-unreadable
    expect "an unreadable text file: the log names the file" says "$(check_log fixture-text-unreadable)" "line-tokens.txt is missing or cannot be read"
fi

# The same for a picture.
make_tree fixture-picture-unreadable
chmod 000 "$root/fixture-picture-unreadable/tree/apps/companion/test/voice/reader-fixtures/line-tokens.png"
if [ -r "$root/fixture-picture-unreadable/tree/apps/companion/test/voice/reader-fixtures/line-tokens.png" ]; then
    printf 'skip a picture that cannot be read: this user can read any file\n'
else
    run_script fixture-picture-unreadable
    expect "an unreadable picture: the reader reads nothing" no_reads fixture-picture-unreadable
    expect "an unreadable picture: the log names the picture" says "$(check_log fixture-picture-unreadable)" "line-tokens.png is missing, empty or cannot be read"
fi

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

# ---- The rows of a text --------------------------------------------------------------------------

# The fixtures of a case, and a text with its final line feed taken away.
fixture_of() { printf '%s/%s/tree/apps/companion/test/voice/reader-fixtures/%s' "$root" "$1" "$2"; }
without_final_line_feed() { printf '%s' "$(cat "$1")" >"$1.new" && mv "$1.new" "$1"; }
ends_without_line_feed() { [ -n "$(tail -c 1 "$1")" ]; }

# A last line with no line feed is a row like any other: the same rows as with it. A reader that gives
# none of a one-line text must be refused for it, and one that leaves out the last line of a page must
# be refused for the page, whether or not the file ends with a line feed.
make_tree last-line-one-good
without_final_line_feed "$(fixture_of last-line-one-good one-line.txt)"
run_script last-line-one-good
expect "a one-line text with no final line feed: the file has none" ends_without_line_feed "$(fixture_of last-line-one-good one-line.txt)"
expect "a one-line text with no final line feed: its line is required and read" says "$(check_log last-line-one-good)" "one-line: every line of its text: passed; it must be passed"
expect "a one-line text with no final line feed: the whole set reads as drawn" says "$(out last-line-one-good)" "the text reader read the known pictures as drawn"

make_tree last-line-one-bad
without_final_line_feed "$(fixture_of last-line-one-bad one-line.txt)"
run_script last-line-one-bad FAKE_BAD_FIRST=9
expect "a one-line text with no final line feed: a reader that gives none is refused" says "$(check_log last-line-one-bad)" "one-line: every line of its text: refused; it must be passed"
expect "a one-line text with no final line feed: no wanted row is dropped to an empty-picture check" never_says "$(check_log last-line-one-bad)" "one-line: no text in a picture without any"

make_tree last-line-page-with
run_script last-line-page-with FAKE_DROP_LAST=1
expect "a whole-page text with its final line feed: a reader that drops the last line is refused" says "$(check_log last-line-page-with)" "whole-page: every line of its text: refused; it must be passed"

make_tree last-line-page-without
without_final_line_feed "$(fixture_of last-line-page-without whole-page.txt)"
run_script last-line-page-without FAKE_DROP_LAST=1
expect "a whole-page text with no final line feed: the file has none" ends_without_line_feed "$(fixture_of last-line-page-without whole-page.txt)"
expect "a whole-page text with no final line feed: a reader that drops the last line is refused" says "$(check_log last-line-page-without)" "whole-page: every line of its text: refused; it must be passed"

# A row of only spacing is no row, for a text that must hold words and for the text of no-text, by the
# rule the check before any reading uses; a text with nothing but spacing, where words are wanted, is
# refused before any reading.
make_tree rows-spaces-between
printf 'Alpha beta\n   \nGamma delta\n' >"$(fixture_of rows-spaces-between line-tokens.txt)"
run_script rows-spaces-between
expect "a row of spaces between two lines: the text is read" says "$(check_log rows-spaces-between)" "line-tokens: every line of its text: passed; it must be passed"
expect "a row of spaces between two lines: the whole set reads as drawn" says "$(out rows-spaces-between)" "the text reader read the known pictures as drawn"

make_tree rows-no-text-spaces
printf '   \n\n  \n' >"$(fixture_of rows-no-text-spaces no-text.txt)"
run_script rows-no-text-spaces
expect "a no-text file of only spaces: the picture is held to read nothing" says "$(check_log rows-no-text-spaces)" "no-text: no text in a picture without any: passed; it must be passed"
expect "a no-text file of only spaces: the whole set reads as drawn" says "$(out rows-no-text-spaces)" "the text reader read the known pictures as drawn"

make_tree rows-text-spaces-only
printf '   \n  \n' >"$(fixture_of rows-text-spaces-only line-tokens.txt)"
run_script rows-text-spaces-only
expect "a text of only spaces where words are wanted: the reader reads nothing" no_reads rows-text-spaces-only
expect "a text of only spaces where words are wanted: the log names the file" says "$(check_log rows-text-spaces-only)" "line-tokens.txt has no words"

# ---- A text that does not match, and a reading that fails ----------------------------------------

checks() { grep -c '^known pictures, read with' "$(check_log "$1")"; }
removals() { [ -f "$(fake "$1" rm.log)" ] && wc -l <"$(fake "$1" rm.log)" | tr -d ' '; }

# A reader that fails is not a reader that read wrong text: the run stops after the first check, with
# its own words, and builds nothing again.
make_tree reader-fails
run_script reader-fails FAKE_READER=fails
expect "a failing reader: one check, of twelve reads" test "$(checks reader-fails)" = 1 -a "$(reads reader-fails)" = 12
expect "a failing reader: its folder is removed once" test "$(removals reader-fails)" = 1
expect "a failing reader: the log shows the failed readings" says "$(check_log reader-fails)" "one-line: every line of its text: a failed reading; it must be passed"
expect "a failing reader: the log shows the reader's own exit status" says "$(check_log reader-fails)" "the reader failed on one-line.png: exit status 2"
expect "a failing reader: the run says it failed" says "$(out reader-fails)" "the text reader failed on a known picture"
expect "a failing reader: the run claims no four checks" never_says "$(out reader-fails)" "four"
expect "a failing reader: the run does not say that a new build changes nothing" never_says "$(out reader-fails)" "no new build"
expect "a failing reader: the words of the code do not say it either" never_says "$here/scripts/e2e-voice-device.sh" "a new build would not change it"
expect "a failing reader: the run fails with exit 2" rc_is reader-fails 2

# A reader that aborts (exit 134) and writes a line to its error output: the log holds its own exit
# status and its own words, not the status of the helper that judged the reading.
make_tree reader-aborts
run_script reader-aborts FAKE_READER=aborts
expect "an aborting reader: one check, of twelve reads" test "$(checks reader-aborts)" = 1 -a "$(reads reader-aborts)" = 12
expect "an aborting reader: the log shows its exit status 134" says "$(check_log reader-aborts)" "the reader failed on one-line.png: exit status 134"
expect "an aborting reader: the log shows its error output" says "$(check_log reader-aborts)" "    fake reader: aborted on purpose"
expect "an aborting reader: the log shows no other status for it" never_says "$(check_log reader-aborts)" "exit status 2"
expect "an aborting reader: the run fails with exit 2" rc_is reader-aborts 2

# Four mismatches, each with a folder of its own: four checks, no cause claimed.
make_tree reader-mismatches
run_script reader-mismatches FAKE_BAD_FIRST=9
expect "four mismatches: four checks" test "$(checks reader-mismatches)" = 4
expect "four mismatches: four folders are removed" test "$(removals reader-mismatches)" = 4
expect "four mismatches: each picture is read once in a check, none a second time" test "$(reads reader-mismatches)" = 48
expect "four mismatches: the run says four checks did not match" says "$(out reader-mismatches)" "did not match a known picture in four checks"
expect "four mismatches: the run clears the page of nothing" never_says "$(out reader-mismatches)" "the page is not at fault"
expect "four mismatches: the run names no builder of the wrong text" never_says "$(out reader-mismatches)" "gave wrong text"
expect "four mismatches: the log names the picture whose text it shows" says "$(check_log reader-mismatches)" "what the reader gave for whole-page"
second_row="$(awk 'NR == 2 { print; exit }' "$fixtures_of_repo/whole-page.txt")"
expect "four mismatches: the log shows the text the reader gave" says "$(check_log reader-mismatches)" "    $second_row"
expect "four mismatches: the run fails with exit 2" rc_is reader-mismatches 2

# Two mismatches and then a good folder: the third check passes. The two rejected folders are removed
# at once and the good one when the run ends.
make_tree reader-recovers
run_script reader-recovers FAKE_BAD_FIRST=2
expect "two mismatches and a pass: three checks" test "$(checks reader-recovers)" = 3
expect "two mismatches and a pass: three folders are removed in all" test "$(removals reader-recovers)" = 3
expect "two mismatches and a pass: the run goes on" says "$(out reader-recovers)" "the text reader read the known pictures as drawn"

# ---- The folder of the system's compiled programs -----------------------------------------------

# Every launch of the reader by the script carries the folder made for it in the environment the
# reader starts with, and the compiler carries none: the setting is the reader's alone.
make_tree launch-environment
run_script launch-environment
reads_file="$(fake launch-environment reads.log)"
expect "launch: the reader was read twelve times" test "$(reads launch-environment)" = 12
expect "launch: each read starts with CFFIXED_USER_HOME set to its folder" awk '
    { home = $2; sub("home=", "", home); started = $3; sub("cffixed=", "", started); if (home != started) bad = 1 }
    END { exit bad }' "$reads_file"
expect "launch: the compiler starts without CFFIXED_USER_HOME" test "$(sort -u "$(fake launch-environment swiftc.log)")" = "CFFIXED_USER_HOME=unset"
expect "launch: node, started after the reader's folder was made, starts without it" test "$(sort -u "$(fake launch-environment node.log)")" = "CFFIXED_USER_HOME=unset"

# The TypeScript reads screenshots with the program it is given, started the way readImage starts it:
# the reader it is given is the wrapper, which gives the home to the reader, and fails without a folder.
wrapper="$(art_of launch-environment)/read-text"
picture="$root/launch-environment/tree/apps/companion/test/voice/reader-fixtures/one-line.png"
typescript_start() {
    node --input-type=module -e '
      import { execFileSync } from "node:child_process"
      execFileSync(process.argv[1], [process.argv[2]], { encoding: "utf8", timeout: 30_000 })
    ' "$wrapper" "$picture"
}
KR_READER_HOME="$root/launch-environment/typescript-home" FAKE_DIR="$root/launch-environment/fake" typescript_start >/dev/null 2>&1
expect "TypeScript launch: the reader starts with CFFIXED_USER_HOME set to the folder" \
    grep -qF -- "home=$root/launch-environment/typescript-home cffixed=$root/launch-environment/typescript-home" "$reads_file"
no_folder_no_reading() { ! FAKE_DIR="$root/launch-environment/fake" typescript_start >/dev/null 2>&1; }
expect "TypeScript launch: no folder, no reading" no_folder_no_reading

# The wrapper is the only name the reader goes by: the compiler writes the reader elsewhere, the
# script passes the wrapper to the TypeScript, and the TypeScript holds no other name.
expect "one name: the compiler writes the reader to read-text-bin" grep -qx -- "$(art_of launch-environment)/read-text-bin" "$(fake launch-environment swiftc-out.log)"
expect "one name: the script gives the TypeScript the wrapper" grep -qF -- '"http://localhost:$port" "$ocr" "$shots"' "$here/scripts/e2e-voice-device.sh"
expect "one name: the TypeScript names no compiled reader" never_says "$here/apps/companion/test/voice/assert-voice-surface.ts" "read-text-bin"

# The files the system compiled are written to the log for each build, each build in a folder of its
# own, with a SHA-1 for each file.
make_tree programs-recorded
run_script programs-recorded FAKE_BAD_FIRST=2
expect "programs: a line for each of three builds" test "$(grep -c '^programs under ' "$(check_log programs-recorded)")" = 3
expect "programs: each build's folder is its own" test "$(grep '^programs under ' "$(check_log programs-recorded)" | sort -u | wc -l | tr -d ' ')" = 3
expect "programs: each build wrote one file" test "$(grep -c ': 1 file(s)$' "$(check_log programs-recorded)")" = 3
expect "programs: each file has a SHA-1" test "$(grep -cE '^    [0-9a-f]{40} Library/Caches/read-text-bin/' "$(check_log programs-recorded)")" = 3

# A reader that wrote no program under its folder cannot be helped by a new folder: the run stops after
# the first mismatch and says so.
make_tree programs-missing
run_script programs-missing FAKE_BAD_FIRST=9 FAKE_COMPILES=0
expect "no programs: one check" test "$(checks programs-missing)" = 1
expect "no programs: the folder is removed once" test "$(removals programs-missing)" = 1
expect "no programs: the run says a new folder cannot build them again" says "$(out programs-missing)" "a new folder cannot build them again"
expect "no programs: the run fails with exit 2" rc_is programs-missing 2

# ---- What the mode reports -----------------------------------------------------------------------

# The mode checks the reader and qualifies nothing, and says so instead of a qualification summary.
make_tree summary
run_script summary
expect "summary: the run says it checked the reader only" says "$(out summary)" "text reader check only: no platform was qualified"
expect "summary: no qualification heading" never_says "$(out summary)" "Voice client qualification"
expect "summary: no list of what was not proved" never_says "$(out summary)" "NOT PROVED"

if [ "$failures" -ne 0 ]; then
    printf '%s case assertion(s) failed\n' "$failures"
    exit 1
fi
printf 'all cases passed\n'
