#!/usr/bin/env bash
# Shows the state folder rule of scripts/lib/e2e-state-folder.sh through the two scripts that call
# it, scripts/e2e-desktop.sh and scripts/e2e-permissions.sh, and through its two functions that
# those scripts use afterwards:
#
#   bash scripts/e2e-state-folder-cases.sh
#
# It runs only on Linux, and its first act is to say so and end with status 2 anywhere else: on a
# Mac the two scripts go on past the check to real work in the person's own login session. On Linux
# both scripts stop soon after the check, at the missing /bin/launchctl or at their platform test,
# before they start anything. Run it in a container with a private /tmp, or with TMPDIR naming a
# private folder (one that only the caller can write): every folder it makes lies in a scratch
# folder that it makes there with mode 700.
#
# Every run is given a temporary directory of its own (TMPDIR), made below the scratch folder, so
# that a folder inside it, a folder outside it and the directory itself can all be named. A refused
# run must print the rule's sentence (or, where a write failed, that sentence) and nothing else, end
# with status 1, make no log directory and nothing else in the temporary directory, and leave every
# folder it was given as it was: names and kinds at every depth, modes, owners, links and their
# targets, and the checksum of every file, the folder's own mode and owner included. An accepted run
# must go on to its script's own next stop on Linux, which shows that the check passed and did not
# end the script, and must leave the folder made, marked with the owner word, with mode 700, and
# marked the same on a second run. Each failed case prints a line that starts with `FAILED:`; the
# script ends with status 1 when any case failed. It removes nothing: its folders stay under the
# directory it names at the end.
# The library cases below set variables inside subshells on purpose, so that none of them stays.
# shellcheck disable=SC2030,SC2031
set -u
if [ "$(uname -s)" != Linux ]; then
  echo "e2e-state-folder-cases: these cases run only on Linux, in a container: on any other system the two scripts go on past the check to real work in a person's session" >&2
  exit 2
fi

# mk <path>...: makes each folder, and each missing folder above it, with mode 755 whatever mask the
# account runs with, so that a case holds exactly the modes it lists.
mk() {
  local path rest acc
  for path in "$@"; do
    rest="${path#/}"
    acc=""
    while [ -n "$rest" ]; do
      acc="$acc/${rest%%/*}"
      case "$rest" in
        */*) rest="${rest#*/}" ;;
        *) rest="" ;;
      esac
      [ -d "$acc" ] || mkdir -m 755 -- "$acc" || return 1
    done
  done
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
tmp_real="$(CDPATH='' cd -P -- "${TMPDIR:-/tmp}" && pwd -P)" || exit 2
scratch="$(mktemp -d "$tmp_real/e2e-state-folder-cases.XXXXXX")" || exit 2
# `t` is the temporary directory that each run is given, `o` a folder outside it.
t="$scratch/T"
o="$scratch/O"
mk "$t" "$o" || exit 2
# A stand-in for `ls`: where FAKE_LS_LINE is set, the first `ls -ldn -- .` answers with that line, so
# that the rule can be shown for a temporary directory that another account or the administrator
# owns, which a run without those rights cannot make. Every other call is the real `ls`.
real_ls="$(command -v ls)" || exit 2
mk "$scratch/fakebin" || exit 2
cat > "$scratch/fakebin/ls" << 'FAKE'
#!/bin/bash
if [ -n "${FAKE_LS_LINE:-}" ] && [ "$*" = "-ldn -- ." ] && [ ! -e "$FAKE_LS_DONE" ]; then
  : > "$FAKE_LS_DONE"
  printf '%s\n' "$FAKE_LS_LINE"
  exit 0
fi
exec "$REAL_LS" "$@"
FAKE
chmod 755 "$scratch/fakebin/ls"

failed=0
cases=0
n=0
caller="$(id -u)"
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
  printf 'e2e: refusing KR_E2E_STATE %s: it must be a plain absolute path, with no symbolic link in it, to a folder inside a subfolder of the temporary directory; the temporary directory must belong to this account or to root and be closed to writes by others or sticky, and every folder below it, the state folder included, must belong to this account and be closed to writes by its group and others; KR_E2E_STATE_OWNER must name this run; and the folder must be new, empty, or marked with that name' "$1"
}

# The sentence for a folder of the chain that its group or others can write, for the path $1, the
# folder $2 and its mode $3.
mode_sentence() {
  printf 'e2e: refusing KR_E2E_STATE %s: its folder %s has mode %s; every folder from the temporary directory down to the state folder must be closed to writes by its group and others (the temporary directory may instead carry the sticky bit), so remove the write permission of that folder, for example with chmod go-w' "$1" "$2" "$3"
}

# The sentence for a folder or marker that could not be written, for the path $1.
write_sentence() {
  printf 'e2e: could not prepare KR_E2E_STATE %s: its folder, its mode or its owner marker could not be written; nothing that this check made was kept' "$1"
}

# What $1 holds at every depth: each entry's name, kind, mode, owner and link target, the folder's
# own included, and a checksum of each file; or `absent`; or, for a link, where it points and what
# its target holds.
snapshot_tree() {
  (
    cd -P -- "$1" || exit 1
    find . -printf '%p %y %m %u:%g %l\n' | LC_ALL=C sort
    find . -type f -exec cksum {} + 2> /dev/null | LC_ALL=C sort
  )
}
snapshot() {
  if [ -L "$1" ]; then
    echo "link to $(readlink -- "$1")"
    [ ! -d "$1" ] || snapshot_tree "$(readlink -f -- "$1")"
  elif [ ! -e "$1" ]; then
    echo absent
  elif [ -d "$1" ]; then
    snapshot_tree "$1"
  else
    echo "file $(cksum < "$1") $(stat -c '%a %u:%g' -- "$1")"
  fi
}

# run <script> <state> <owner> <log>: runs one script in an environment of its own that holds only
# the search path, a home, the temporary directory and, where they are not empty, the state folder
# and the owner word; and sets `out` (what it said) and `code` (how it ended). Set before the call:
# `run_tmp` (the temporary directory, `$t` if empty), `run_ls` (a line for the stand-in `ls`) and
# `run_limit` (not empty: the run may write no byte to a file, so that a write fails).
run_tmp=""
run_ls=""
run_limit=""
run() {
  local script="$1" state="$2" owner="$3" log="$4"
  local -a variables=(PATH="$PATH" HOME="$scratch" TMPDIR="${run_tmp:-$t}")
  local -a command=(bash "$root/scripts/$script")
  [ -z "$state" ] || variables+=(KR_E2E_STATE="$state")
  [ -z "$owner" ] || variables+=(KR_E2E_STATE_OWNER="$owner")
  if [ -n "$run_ls" ]; then
    variables[0]="PATH=$scratch/fakebin:$PATH"
    variables+=(FAKE_LS_LINE="$run_ls" FAKE_LS_DONE="$scratch/fake-ls-done-$n" REAL_LS="$real_ls")
  fi
  [ -z "$log" ] || command+=("$log")
  if [ -n "$run_limit" ]; then
    # A file may not grow, and the signal that says so is ignored, so that the write fails with an
    # error that the script can read.
    command=(bash -c 'ulimit -f 0; trap "" XFSZ; exec "$@"' bash "${command[@]}")
  fi
  out="$(env -i "${variables[@]}" "${command[@]}" 2>&1)"
  code=$?
}

# expect_refused <label> <script> <state> <owner> <watched>...: the run is refused with the rule's
# sentence and nothing else (the sentence for a failed write when `refusal` says write, the one that
# names a folder and its mode, `refusal_folder` and `refusal_mode`, when it says mode), makes
# neither the log directory nor anything else in the temporary directory (where the evidence
# directory of a script that goes on would be made), and leaves each watched path as it was. The
# temporary directory is watched too, unless `watch_tmp` is set to another path or to `none`.
refusal=rule
refusal_folder=""
refusal_mode=""
watch_tmp=""
expect_refused() {
  local label="$1" script="$2" state="$3" owner="$4"
  shift 4
  n=$((n + 1))
  cases=$((cases + 1))
  local logs="$t/logs-$n" before="" after="" path
  local -a watched=("$@")
  local tmp_watched="${watch_tmp:-${run_tmp:-$t}}"
  [ "$tmp_watched" = none ] || watched=("$tmp_watched" ${watched[@]+"${watched[@]}"})
  for path in "${watched[@]}"; do
    before="$before$(snapshot "$path")|"
  done
  run "$script" "$state" "$owner" "$logs/run.log"
  for path in "${watched[@]}"; do
    after="$after$(snapshot "$path")|"
  done
  local good=1 expected
  if [ "$refusal" = write ]; then
    expected="$(write_sentence "$state")"
  elif [ "$refusal" = mode ]; then
    expected="$(mode_sentence "$state" "$refusal_folder" "$refusal_mode")"
  else
    expected="$(sentence "$state")"
  fi
  if [ "$code" -ne 1 ]; then
    fail "$label ($script): it ended with status $code, not 1"
    good=0
  fi
  if [ "$out" != "$expected" ]; then
    fail "$label ($script): it said '$out', not the expected sentence"
    good=0
  fi
  if [ -e "$logs" ]; then
    fail "$label ($script): it made the log directory before it refused"
    good=0
  fi
  if [ "$before" != "$after" ]; then
    fail "$label ($script): it changed what it refused: $before then $after"
    good=0
  fi
  [ "$good" -eq 0 ] || ok "$label ($script): refused with the sentence, nothing made, nothing changed"
}

# expect_accepted <label> <script> <state> <owner>: the run goes on to its script's own stop, says
# nothing of a refusal, and leaves the folder made, marked with the owner word and with mode 700.
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
  if printf '%s\n' "$out" | grep -Fq 'e2e: '; then
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
    elif [ "$(stat -c %a "$state" 2> /dev/null)" != 700 ]; then
      fail "$label ($script): its mode is not 700"
      good=0
    fi
  fi
  [ "$good" -eq 0 ] || ok "$label ($script): accepted, and the script went on to its own stop"
}

# expect <label> <wanted> <got>: one direct case of a function of the library.
expect() {
  cases=$((cases + 1))
  if [ "$2" = "$3" ]; then
    ok "$1"
  else
    fail "$1: wanted '$2', got '$3'"
  fi
}

owner="thisrun-12345"
other_account=$((caller + 7777))

for script in e2e-desktop.sh e2e-permissions.sh; do
  echo "== $script: folders that are refused"
  # The top of the file system is not watched: its listing is not this script's to keep.
  watch_tmp=none expect_refused "the top of the file system" "$script" / "$owner"

  mk "$t/dots-$script"
  expect_refused "a component .." "$script" "$t/dots-$script/../dots-$script/state" "$owner" "$t/dots-$script/state"
  expect_refused "a component ." "$script" "$t/dots-$script/./state" "$owner" "$t/dots-$script/state"
  expect_refused "an empty component" "$script" "$t/dots-$script//state" "$owner" "$t/dots-$script/state"
  mk "$t/slash-$script/state"
  expect_refused "a trailing slash" "$script" "$t/slash-$script/state/" "$owner" "$t/slash-$script/state"

  mk "$o/outside-$script"
  expect_refused "a folder outside the temporary directory" "$script" "$o/outside-$script/state" "$owner" "$o/outside-$script/state"
  expect_refused "the temporary directory itself" "$script" "$t" "$owner" "$t"
  expect_refused "a folder directly in the temporary directory" "$script" "$t/direct-$script" "$owner" "$t/direct-$script"

  mk "$o/target-$script" "$t/link-$script"
  ln -s "$o/target-$script" "$t/link-$script/state"
  expect_refused "a symbolic link below it that points outside" "$script" "$t/link-$script/state" "$owner" "$t/link-$script/state" "$o/target-$script"
  ln -s "$o" "$t/parent-link-$script"
  expect_refused "a parent folder that is a link to outside" "$script" "$t/parent-link-$script/state-$script" "$owner" "$o/state-$script"
  mk "$t/inside-$script/real"
  ln -s "$t/inside-$script/real" "$t/inside-$script/via"
  expect_refused "a parent folder that is a link to a folder inside" "$script" "$t/inside-$script/via/state" "$owner" "$t/inside-$script/real"

  mk "$t/full-$script/state"
  echo data > "$t/full-$script/state/data"
  expect_refused "a folder that holds files and no marker" "$script" "$t/full-$script/state" "$owner" "$t/full-$script/state"
  mk "$t/lf-$script/state"
  : > "$t/lf-$script/state/"$'\n'
  expect_refused "a folder whose only entry is named by a line end" "$script" "$t/lf-$script/state" "$owner" "$t/lf-$script/state"

  mk "$t/other-$script/state"
  echo "someone-else" > "$t/other-$script/state/.kr-e2e-owner"
  expect_refused "a marker with another word" "$script" "$t/other-$script/state" "$owner" "$t/other-$script/state"
  mk "$t/extra-$script/state"
  printf '%s\nmore\n' "$owner" > "$t/extra-$script/state/.kr-e2e-owner"
  expect_refused "a marker with more than the word" "$script" "$t/extra-$script/state" "$owner" "$t/extra-$script/state"
  mk "$t/marker-link-$script/state"
  echo "$owner" > "$o/real-marker-$script"
  ln -s "$o/real-marker-$script" "$t/marker-link-$script/state/.kr-e2e-owner"
  expect_refused "a marker that is a link" "$script" "$t/marker-link-$script/state" "$owner" "$t/marker-link-$script/state" "$o/real-marker-$script"
  mk "$t/marked-$script/state"
  echo "$owner" > "$t/marked-$script/state/.kr-e2e-owner"
  expect_refused "a marked folder and no owner word" "$script" "$t/marked-$script/state" "" "$t/marked-$script/state"

  mk "$t/file-$script"
  echo data > "$t/file-$script/state"
  expect_refused "a file" "$script" "$t/file-$script/state" "$owner" "$t/file-$script/state"

  mk "$t/words-$script"
  expect_refused "no owner word" "$script" "$t/words-$script/none" "" "$t/words-$script/none"
  expect_refused "an owner word of 7 characters" "$script" "$t/words-$script/short" "abcd123" "$t/words-$script/short"
  expect_refused "an owner word of 65 characters" "$script" "$t/words-$script/long" "$(printf 'a%.0s' $(seq 1 65))" "$t/words-$script/long"
  expect_refused "an owner word with a space" "$script" "$t/words-$script/space" "has space 123" "$t/words-$script/space"
  expect_refused "an owner word with a slash" "$script" "$t/words-$script/slash" "has/slash/123" "$t/words-$script/slash"

  echo "== $script: folders that another account could change"
  # Each parent is made by this account and then opened to writes, so that a process of another
  # account could rename the folder under it, or put a link in its place, between two steps.
  mk "$t/open-$script"
  chmod 777 "$t/open-$script"
  refusal=mode refusal_folder="$t/open-$script" refusal_mode=drwxrwxrwx expect_refused "a parent folder that every account can write" "$script" "$t/open-$script/state" "$owner" "$t/open-$script"
  mk "$t/group-$script"
  chmod 775 "$t/group-$script"
  refusal=mode refusal_folder="$t/group-$script" refusal_mode=drwxrwxr-x expect_refused "a parent folder that its group can write" "$script" "$t/group-$script/state" "$owner" "$t/group-$script"
  # The caller's own `mkdir` under a mask of 002 leaves the folder open to the group: the refusal
  # names the folder and its mode, so that a person knows what to change.
  old_mask="$(umask)"
  umask 002
  mkdir "$t/mask-$script"
  umask "$old_mask"
  refusal=mode refusal_folder="$t/mask-$script" refusal_mode=drwxrwxr-x expect_refused "a folder that the caller made beforehand under a mask of 002" "$script" "$t/mask-$script/state" "$owner" "$t/mask-$script"
  mk "$t/deep-$script/mid"
  chmod 777 "$t/deep-$script/mid"
  refusal=mode refusal_folder="$t/deep-$script/mid" refusal_mode=drwxrwxrwx expect_refused "a folder two levels above it that every account can write" "$script" "$t/deep-$script/mid/state" "$owner" "$t/deep-$script"
  mk "$t/first-$script/mid"
  chmod 777 "$t/first-$script"
  refusal=mode refusal_folder="$t/first-$script" refusal_mode=drwxrwxrwx expect_refused "the first folder below the temporary directory, open to writes" "$script" "$t/first-$script/mid/state" "$owner" "$t/first-$script"
  mk "$t/stateopen-$script/state"
  echo "$owner" > "$t/stateopen-$script/state/.kr-e2e-owner"
  chmod 777 "$t/stateopen-$script/state"
  refusal=mode refusal_folder="$t/stateopen-$script/state" refusal_mode=drwxrwxrwx expect_refused "a marked state folder that every account can write" "$script" "$t/stateopen-$script/state" "$owner" "$t/stateopen-$script"
  mk "$t/stategroup-$script/state"
  echo "$owner" > "$t/stategroup-$script/state/.kr-e2e-owner"
  chmod 770 "$t/stategroup-$script/state"
  refusal=mode refusal_folder="$t/stategroup-$script/state" refusal_mode=drwxrwx--- expect_refused "a marked state folder that its group can write" "$script" "$t/stategroup-$script/state" "$owner" "$t/stategroup-$script"

  # A temporary directory that every account can write is refused unless it is sticky.
  mk "$scratch/R777-$script/mid"
  chmod 777 "$scratch/R777-$script"
  refusal=mode refusal_folder="$scratch/R777-$script" refusal_mode=drwxrwxrwx run_tmp="$scratch/R777-$script" expect_refused "a temporary directory that every account can write, not sticky" "$script" "$scratch/R777-$script/mid/state" "$owner"
  mk "$scratch/R775-$script/mid"
  chmod 775 "$scratch/R775-$script"
  refusal=mode refusal_folder="$scratch/R775-$script" refusal_mode=drwxrwxr-x run_tmp="$scratch/R775-$script" expect_refused "a temporary directory that its group can write, not sticky" "$script" "$scratch/R775-$script/mid/state" "$owner"
  # The same, where the administrator owns it, and where another account owns it even if sticky.
  mk "$t/admin-$script"
  refusal=mode refusal_folder="$t" refusal_mode=drwxrwxrwx run_ls='drwxrwxrwx 5 0 0 4096 Nov 26 20:50 .' expect_refused "a temporary directory that the administrator owns and every account can write, not sticky" "$script" "$t/admin-$script/state" "$owner" "$t/admin-$script"
  run_ls="drwxrwxrwt 5 $other_account $other_account 4096 Nov 26 20:50 ." expect_refused "a sticky temporary directory that another account owns" "$script" "$t/admin-$script/state" "$owner" "$t/admin-$script"
  # A first folder that another account made: the top of the file system is the temporary directory,
  # and the folder below it belongs to the administrator.
  if [ "$caller" -ne 0 ]; then
    run_tmp=/ watch_tmp=none expect_refused "a first folder below the temporary directory that another account made" "$script" "/usr/e2e-state-folder-cases-nothing/state" "$owner" "/usr/e2e-state-folder-cases-nothing"
  fi

  # A temporary directory whose name ends in a line end is compared whole: a run in /T<LF> is not
  # a run in /T.
  tl="$scratch/TL-$script"$'\n'
  mk "$tl" "$scratch/TL-$script/run"
  run_tmp="$tl" expect_refused "a temporary directory whose name ends in a line end, and a folder in the one without it" "$script" "$scratch/TL-$script/run/state" "$owner" "$scratch/TL-$script/run"

  # A relative path to a folder that exists below the temporary directory, from a copy of the checkout
  # that is the script's own working directory.
  copy="$scratch/copy-$script"
  mk "$copy/sub"
  cp -R "$root/scripts" "$copy/scripts"
  n=$((n + 1))
  cases=$((cases + 1))
  before="$(snapshot "$copy/sub")"
  out="$(env -i PATH="$PATH" HOME="$scratch" TMPDIR="$copy" KR_E2E_STATE="sub/state" KR_E2E_STATE_OWNER="$owner" bash "$copy/scripts/$script" 2>&1)"
  code=$?
  if [ "$code" -eq 1 ] && [ "$out" = "$(sentence "sub/state")" ] && [ "$before" = "$(snapshot "$copy/sub")" ]; then
    ok "a relative path to a folder below the temporary directory ($script): refused, nothing made"
  else
    fail "a relative path to a folder below the temporary directory ($script): status $code, said '$out'"
  fi

  echo "== $script: a write that fails"
  # A file may not grow, so the marker cannot be written. The run says so in its own words, the
  # folder it made is gone, and a folder that was there is as it was, its mode too.
  mk "$t/wnew-$script"
  refusal=write run_limit=1 expect_refused "a new folder whose marker cannot be written" "$script" "$t/wnew-$script/state" "$owner" "$t/wnew-$script"
  mk "$t/wempty-$script/state"
  chmod 755 "$t/wempty-$script/state"
  refusal=write run_limit=1 expect_refused "an empty folder whose marker cannot be written" "$script" "$t/wempty-$script/state" "$owner" "$t/wempty-$script"
  # A parent that cannot be written, so the folder cannot be made.
  if [ "$caller" -ne 0 ]; then
    mk "$t/wparent-$script"
    chmod 555 "$t/wparent-$script"
    refusal="write" expect_refused "a folder that cannot be made in its parent" "$script" "$t/wparent-$script/state" "$owner" "$t/wparent-$script"
  fi

  echo "== $script: folders that are accepted"
  # The scripts' own chain: a folder from `mktemp -d` below the temporary directory and the state
  # folder made by the check, under a mask that opens a plain `mkdir` to the group and under one that
  # does not. Both are accepted: every folder they make has an explicit mode.
  for mask in 002 022; do
    old_mask="$(umask)"
    umask "$mask"
    chain="$(mktemp -d "$t/chain-$script-$mask.XXXXXX")"
    expect_accepted "the scripts' own chain, made under a mask of $mask" "$script" "$chain/state" "$owner"
    umask "$old_mask"
  done
  mk "$t/new-$script"
  expect_accepted "a new folder" "$script" "$t/new-$script/state" "$owner"
  expect_accepted "the same folder a second time, with its marker" "$script" "$t/new-$script/state" "$owner"
  mk "$t/empty-$script/state"
  expect_accepted "an empty folder" "$script" "$t/empty-$script/state" "$owner"
  mk "$t/seven-$script/state"
  chmod 755 "$t/seven-$script/state"
  echo "$owner" > "$t/seven-$script/state/.kr-e2e-owner"
  expect_accepted "a marked folder that only its owner can write, set to mode 700" "$script" "$t/seven-$script/state" "$owner"
  mk "$scratch/R1777-$script/mid"
  chmod 1777 "$scratch/R1777-$script"
  run_tmp="$scratch/R1777-$script" expect_accepted "a temporary directory that every account can write and that is sticky" "$script" "$scratch/R1777-$script/mid/state" "$owner"
  mk "$t/admin-ok-$script" "$t/admin-sticky-$script"
  run_ls='drwxr-xr-x 5 0 0 4096 Nov 26 20:50 .' expect_accepted "a temporary directory that the administrator owns and others cannot write" "$script" "$t/admin-ok-$script/state" "$owner"
  run_ls='drwxrwxrwt 5 0 0 4096 Nov 26 20:50 .' expect_accepted "a sticky temporary directory that the administrator owns" "$script" "$t/admin-sticky-$script/state" "$owner"
  mk "$scratch/own-$script"
  run_tmp="$tmp_real" expect_accepted "the temporary directory this run of the cases itself uses" "$script" "$scratch/own-$script/state" "$owner"
  expect_accepted "no state folder" "$script" "" ""
done

echo "== the folder is entered again from inside, and looked at there"
# The scripts use the folder afterwards through e2e_state_folder_enter, from inside it. Each case
# runs the library in a subshell: the check, then a change that another account could make if it
# could write the parent (the folder moved away and a link, or another folder, put in its place), then
# the entry, which must be refused, and must change nothing in what the link points at.
mk "$t/enter"
for variant in same link folder other-marker; do
  cases=$((cases + 1))
  dir="$t/enter/$variant"
  mk "$dir" "$o/enter-target-$variant"
  chmod 755 "$o/enter-target-$variant"
  before="$(snapshot "$o/enter-target-$variant")"
  rc="$(
    # shellcheck source=scripts/lib/e2e-state-folder.sh
. "$root/scripts/lib/e2e-state-folder.sh"
    export TMPDIR="$t"
    export KR_E2E_STATE="$dir/state"
    export KR_E2E_STATE_OWNER="$owner"
    e2e_state_folder_check
    case "$variant" in
      link)
        mv -- "$dir/state" "$dir/aside"
        ln -s "$o/enter-target-$variant" "$dir/state"
        ;;
      folder)
        mv -- "$dir/state" "$dir/aside"
        mkdir -m 700 "$dir/state"
        printf '%s\n' "$owner" > "$dir/state/.kr-e2e-owner"
        ;;
      other-marker)
        printf '%s\n' "someone-else-1" > "$dir/state/.kr-e2e-owner"
        ;;
    esac
    e2e_state_folder_enter > /dev/null 2>&1
    echo "$?"
  )"
  case "$variant" in
    same) wanted=0 ;;
    *) wanted=1 ;;
  esac
  if [ "$rc" != "$wanted" ]; then
    fail "entering the state folder after: $variant: wanted status $wanted, got '$rc'"
  elif [ "$before" != "$(snapshot "$o/enter-target-$variant")" ]; then
    fail "entering the state folder after: $variant: it changed what the link points at"
  else
    ok "entering the state folder after: $variant: status $wanted, nothing changed"
  fi
done
# A run with no folder named by a wrapper enters the folder it is given, and with none given it fails.
mk "$t/enter/own"
rc="$(
  # shellcheck source=scripts/lib/e2e-state-folder.sh
. "$root/scripts/lib/e2e-state-folder.sh"
  export KR_E2E_STATE=""
  e2e_state_folder_check
  e2e_state_folder_enter "$t/enter/own" && [ "$PWD" = "$t/enter/own" ]
  echo "$?"
)"
expect "a run with no folder named by a wrapper enters its own folder" 0 "$rc"
rc="$(
  # shellcheck source=scripts/lib/e2e-state-folder.sh
. "$root/scripts/lib/e2e-state-folder.sh"
  export KR_E2E_STATE=""
  e2e_state_folder_check
  e2e_state_folder_enter > /dev/null 2>&1
  echo "$?"
)"
expect "a run with no folder named by a wrapper and none given enters nothing" 1 "$rc"

echo "== a marker that is already there is not overwritten"
mk "$t/mark/held" "$t/mark/dangling"
printf 'keep-me-4321\n' > "$t/mark/held/.kr-e2e-owner"
ln -s "$o/mark-target" "$t/mark/dangling/.kr-e2e-owner"
before="$(snapshot "$t/mark/held")"
rc="$(
  # shellcheck source=scripts/lib/e2e-state-folder.sh
. "$root/scripts/lib/e2e-state-folder.sh"
  cd "$t/mark/held" && e2e_state_folder_mark "$owner" > /dev/null 2>&1
  echo "$?"
)"
expect "a marker with another word makes the marking fail" 3 "$rc"
expect "a marker with another word is as it was" "$before" "$(snapshot "$t/mark/held")"
rc="$(
  # shellcheck source=scripts/lib/e2e-state-folder.sh
. "$root/scripts/lib/e2e-state-folder.sh"
  cd "$t/mark/dangling" && e2e_state_folder_mark "$owner" > /dev/null 2>&1
  echo "$?"
)"
expect "a marker that is a dangling link makes the marking fail" 3 "$rc"
expect "a dangling link is not followed to make a file" absent "$(snapshot "$o/mark-target")"

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
