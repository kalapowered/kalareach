#!/usr/bin/env bash
# Shows the state folder rule of scripts/lib/e2e-state-folder.sh through the two scripts that call
# it, scripts/e2e-desktop.sh and scripts/e2e-permissions.sh:
#
#   bash scripts/e2e-state-folder-cases.sh
#
# It runs only on Linux, and its first act is to say so and end with status 2 anywhere else: on a
# Mac the two scripts go on past the check to real work in the person's own login session. On Linux
# both scripts stop soon after the check, at the missing /bin/launchctl or at their platform test,
# before they start anything. Run it in a container with a private /tmp.
#
# Every run is given a temporary directory of its own (TMPDIR), made below the one this script
# runs in, so that a folder inside it, a folder outside it and the directory itself can all be
# named. A refused run must print the rule's sentence and nothing else, end with status 1, make no
# log directory and nothing else in the temporary directory, and leave the folder as it was (a folder that exists
# keeps its listing and its files, one that is absent stays absent). An accepted run must go on to
# its script's own next stop on Linux, which shows that the check passed and did not end the
# script, and must leave the folder made, marked with the owner word, and marked the same on a
# second run. Each failed case prints a line that starts with `FAILED:`; the script ends with
# status 1 when any case failed. It removes nothing: its folders stay under the directory it names
# at the end.
set -u

if [ "$(uname -s)" != Linux ]; then
  echo "e2e-state-folder-cases: these cases run only on Linux, in a container: on any other system the two scripts go on past the check to real work in a person's session" >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
tmp_real="$(CDPATH='' cd -P -- "${TMPDIR:-/tmp}" && pwd -P)" || exit 2
scratch="$(mktemp -d "$tmp_real/e2e-state-folder-cases.XXXXXX")" || exit 2
# `t` is the temporary directory that each run is given, `o` a folder outside it.
t="$scratch/T"
o="$scratch/O"
mkdir "$t" "$o" || exit 2

failed=0
cases=0
n=0
fail() {
  echo "FAILED: $*"
  failed=1
}
ok() {
  echo "  ok: $*"
}

# The stop each script comes to on Linux once the check has passed.
stop_of() {
  case "$1" in
    e2e-desktop.sh) echo "FAILED: this host has no graphical login session, so there is no desktop to demonstrate" ;;
    e2e-permissions.sh) echo "FAILED: the disclosed checks in this build are macOS operations, and this host is not macOS" ;;
  esac
}

# The sentence of the rule, for the path $1.
sentence() {
  printf 'e2e: refusing KR_E2E_STATE %s: it must be a plain absolute path, not a symbolic link, to a folder inside a subfolder of the temporary directory, KR_E2E_STATE_OWNER must name this run, and the folder must be new, empty, or marked with that name' "$1"
}

# What $1 holds, one level down: each entry's name, kind and mode, and a checksum of each file; or
# `absent`, or where it points when it is a link.
snapshot() {
  if [ -L "$1" ]; then
    echo "link to $(readlink -- "$1")"
  elif [ ! -e "$1" ]; then
    echo absent
  elif [ -d "$1" ]; then
    (
      cd -P -- "$1" || exit 1
      find . -mindepth 1 -maxdepth 1 -printf '%p %y %m\n' | LC_ALL=C sort
      find . -mindepth 1 -maxdepth 1 -type f -exec cksum {} + 2> /dev/null | LC_ALL=C sort
    )
  else
    echo "file $(cksum < "$1")"
  fi
}

# run <script> <state> <owner> <log>: runs one script in an environment of its own that holds only
# the search path, a home, the temporary directory and, where they are not empty, the state folder
# and the owner word; and sets `out` (what it said) and `code` (how it ended).
run() {
  local script="$1" state="$2" owner="$3" log="$4"
  local -a variables=(PATH="$PATH" HOME="$scratch" TMPDIR="$t")
  local -a command=(bash "$root/scripts/$script")
  [ -z "$state" ] || variables+=(KR_E2E_STATE="$state")
  [ -z "$owner" ] || variables+=(KR_E2E_STATE_OWNER="$owner")
  [ -z "$log" ] || command+=("$log")
  out="$(env -i "${variables[@]}" "${command[@]}" 2>&1)"
  code=$?
}

# expect_refused <label> <script> <state> <owner> <watched>...: the run is refused with the rule's
# sentence and nothing else, makes neither the log directory nor anything else in the temporary
# directory (where the evidence directory of a script that goes on would be made), and leaves each
# watched path as it was.
expect_refused() {
  local label="$1" script="$2" state="$3" owner="$4"
  shift 4
  n=$((n + 1))
  cases=$((cases + 1))
  local logs="$t/logs-$n" before="" after="" path
  for path in "$t" "$@"; do
    before="$before$(snapshot "$path")|"
  done
  run "$script" "$state" "$owner" "$logs/run.log"
  for path in "$t" "$@"; do
    after="$after$(snapshot "$path")|"
  done
  local good=1
  if [ "$code" -ne 1 ]; then
    fail "$label ($script): it ended with status $code, not 1"
    good=0
  fi
  if [ "$out" != "$(sentence "$state")" ]; then
    fail "$label ($script): it said '$out', not the rule's sentence"
    good=0
  fi
  if [ -e "$logs" ]; then
    fail "$label ($script): it made the log directory before it refused"
    good=0
  fi
  if [ "$before" != "$after" ]; then
    fail "$label ($script): it changed a folder it refused: $before then $after"
    good=0
  fi
  [ "$good" -eq 0 ] || ok "$label ($script): refused with the sentence, nothing made, nothing changed"
}

# expect_accepted <label> <script> <state> <owner>: the run goes on to its script's own stop, says
# nothing of a refusal, and leaves the folder made and marked with the owner word.
expect_accepted() {
  local label="$1" script="$2" state="$3" owner="$4"
  n=$((n + 1))
  cases=$((cases + 1))
  run "$script" "$state" "$owner" ""
  local good=1
  if [ "$code" -ne 1 ]; then
    fail "$label ($script): it ended with status $code, not 1"
    good=0
  fi
  if ! printf '%s\n' "$out" | grep -Fxq -- "$(stop_of "$script")"; then
    fail "$label ($script): it did not come to its own stop: $out"
    good=0
  fi
  if printf '%s\n' "$out" | grep -Fq 'e2e: refusing'; then
    fail "$label ($script): it refused: $out"
    good=0
  fi
  if [ -n "$state" ]; then
    if [ ! -d "$state" ]; then
      fail "$label ($script): the folder is not there"
      good=0
    elif [ "$(cat -- "$state/.kr-e2e-owner" 2> /dev/null)" != "$owner" ]; then
      fail "$label ($script): the folder is not marked with the owner word"
      good=0
    fi
  fi
  [ "$good" -eq 0 ] || ok "$label ($script): accepted, and the script went on to its own stop"
}

owner="thisrun-12345"

for script in e2e-desktop.sh e2e-permissions.sh; do
  echo "== $script: folders that are refused"
  # The top of the file system is not watched: its listing is not this script's to keep.
  expect_refused "the top of the file system" "$script" / "$owner"

  mkdir -p "$t/dots-$script"
  expect_refused "a component .." "$script" "$t/dots-$script/../dots-$script/state" "$owner" "$t/dots-$script/state"
  expect_refused "a component ." "$script" "$t/dots-$script/./state" "$owner" "$t/dots-$script/state"
  expect_refused "an empty component" "$script" "$t/dots-$script//state" "$owner" "$t/dots-$script/state"
  mkdir -p "$t/slash-$script/state"
  expect_refused "a trailing slash" "$script" "$t/slash-$script/state/" "$owner" "$t/slash-$script/state"

  expect_refused "a relative path" "$script" "relative-state-folder/state" "$owner" "$root/relative-state-folder"

  mkdir -p "$o/outside-$script"
  expect_refused "a folder outside the temporary directory" "$script" "$o/outside-$script/state" "$owner" "$o/outside-$script/state"
  expect_refused "the temporary directory itself" "$script" "$t" "$owner" "$t"
  expect_refused "a folder directly in the temporary directory" "$script" "$t/direct-$script" "$owner" "$t/direct-$script"

  mkdir -p "$o/target-$script" "$t/link-$script"
  ln -s "$o/target-$script" "$t/link-$script/state"
  expect_refused "a symbolic link below it that points outside" "$script" "$t/link-$script/state" "$owner" "$t/link-$script/state" "$o/target-$script"
  ln -s "$o" "$t/parent-link-$script"
  expect_refused "a parent folder that is a link to outside" "$script" "$t/parent-link-$script/state-$script" "$owner" "$o/state-$script"

  mkdir -p "$t/full-$script/state"
  echo data > "$t/full-$script/state/data"
  expect_refused "a folder that holds files and no marker" "$script" "$t/full-$script/state" "$owner" "$t/full-$script/state"

  mkdir -p "$t/other-$script/state"
  echo "someone-else" > "$t/other-$script/state/.kr-e2e-owner"
  expect_refused "a marker with another word" "$script" "$t/other-$script/state" "$owner" "$t/other-$script/state"
  mkdir -p "$t/extra-$script/state"
  printf '%s\nmore\n' "$owner" > "$t/extra-$script/state/.kr-e2e-owner"
  expect_refused "a marker with more than the word" "$script" "$t/extra-$script/state" "$owner" "$t/extra-$script/state"
  mkdir -p "$t/marker-link-$script/state"
  echo "$owner" > "$o/real-marker-$script"
  ln -s "$o/real-marker-$script" "$t/marker-link-$script/state/.kr-e2e-owner"
  expect_refused "a marker that is a link" "$script" "$t/marker-link-$script/state" "$owner" "$t/marker-link-$script/state"
  mkdir -p "$t/marked-$script/state"
  echo "$owner" > "$t/marked-$script/state/.kr-e2e-owner"
  expect_refused "a marked folder and no owner word" "$script" "$t/marked-$script/state" "" "$t/marked-$script/state"

  mkdir -p "$t/file-$script"
  echo data > "$t/file-$script/state"
  expect_refused "a file" "$script" "$t/file-$script/state" "$owner" "$t/file-$script/state"

  mkdir -p "$t/words-$script"
  expect_refused "no owner word" "$script" "$t/words-$script/none" "" "$t/words-$script/none"
  expect_refused "an owner word of 7 characters" "$script" "$t/words-$script/short" "abcd123" "$t/words-$script/short"
  expect_refused "an owner word of 65 characters" "$script" "$t/words-$script/long" "$(printf 'a%.0s' $(seq 1 65))" "$t/words-$script/long"
  expect_refused "an owner word with a space" "$script" "$t/words-$script/space" "has space 123" "$t/words-$script/space"
  expect_refused "an owner word with a slash" "$script" "$t/words-$script/slash" "has/slash/123" "$t/words-$script/slash"

  echo "== $script: folders that are accepted"
  mkdir -p "$t/new-$script"
  expect_accepted "a new folder" "$script" "$t/new-$script/state" "$owner"
  if [ "$(stat -c %a "$t/new-$script/state" 2> /dev/null)" != 700 ]; then
    fail "a new folder ($script): its mode is not 700"
  fi
  expect_accepted "the same folder a second time, with its marker" "$script" "$t/new-$script/state" "$owner"
  mkdir -p "$t/empty-$script/state"
  expect_accepted "an empty folder" "$script" "$t/empty-$script/state" "$owner"
  expect_accepted "no state folder" "$script" "" ""
done

echo "== scripts/e2e-update.sh: both scripts get both variables"
update="$root/scripts/e2e-update.sh"
# Each command, with the lines that a trailing backslash joins made one.
joined="$(awk '{ if (sub(/\\$/, "")) { buffer = buffer $0 } else { print buffer $0; buffer = "" } }' "$update")"
for script in e2e-desktop.sh e2e-permissions.sh; do
  cases=$((cases + 1))
  # The text searched for is the script's own, with its dollar signs: nothing expands here.
  # shellcheck disable=SC2016
  line="$(printf '%s\n' "$joined" | grep -F "scripts/$script" | grep -F 'KR_E2E_STATE="' | grep -F 'KR_E2E_STATE_OWNER="$state_owner"')"
  if [ -n "$line" ]; then
    ok "e2e-update.sh runs $script with KR_E2E_STATE and KR_E2E_STATE_OWNER"
  else
    fail "e2e-update.sh does not run $script with both KR_E2E_STATE and KR_E2E_STATE_OWNER"
  fi
done
cases=$((cases + 1))
# shellcheck disable=SC2016
if grep -Fxq 'state_owner="${work##*/}"' "$update" && grep -Fxq 'work="$(cd -P "$work" && pwd -P)"' "$update"; then
  ok "e2e-update.sh names its run's folder by its physical path and takes the owner word from its name"
else
  fail "e2e-update.sh does not take the owner word from the name of its physical work folder"
fi

echo "e2e-state-folder-cases: $cases cases, scratch folders under $scratch"
exit "$failed"
