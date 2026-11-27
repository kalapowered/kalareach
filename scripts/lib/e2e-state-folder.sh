# shellcheck shell=bash
# The rule for the folder that a demonstration keeps its daemon's state in, where a wrapper names
# one.
#
# `scripts/e2e-desktop.sh` and `scripts/e2e-permissions.sh` keep what their daemon records in
# `KR_E2E_STATE` when it is set, so that a later run finds it. A wrapper that names the folder
# could name the person's own state folder, and the demonstration would then start a daemon in it.
# A script sources this file and calls `e2e_state_folder_check` before it makes or starts
# anything, the log directory included. The check returns at once when KR_E2E_STATE is not set
# (or is empty, which the scripts read as not set), and otherwise ends the script with status 1 and
# says why unless all of these hold:
#
#   * the path has no `.`, `..` or empty component (so no `//` and no trailing `/`) and holds no
#     line feed;
#   * the path is the physical name of the folder: it begins with the temporary directory
#     (${TMPDIR:-/tmp}, read through its links, with every character of its name kept), and the
#     folder lies in a subfolder of that directory, with no symbolic link on the way down;
#   * the temporary directory belongs to the caller or to root and is closed to writes by group and
#     others, or has the sticky bit, so that nobody else can rename or remove an entry that is not
#     theirs;
#   * every folder from the first subfolder down to the state folder belongs to the caller and is
#     closed to writes by group and others, so that no other account can rename, replace or link
#     away anything in the chain;
#   * KR_E2E_STATE_OWNER is set, of 8 to 64 characters from the letters, the digits, `.`, `_`
#     and `-`;
#   * the folder is one of: absent (the check makes it with mode 700 and writes the owner word into
#     `.kr-e2e-owner` in it); a directory that is empty (the same); or a directory that holds
#     `.kr-e2e-owner`, a regular file owned by the caller, with exactly the owner word and a line
#     feed. A folder that exists keeps its listing and its mode until the check has passed; its
#     mode is then set to 700.
#
# A folder that holds anything and no marker is a folder that something else made, and a marker
# with another word is another run's: both are refused. The marker proves that a run with this
# owner word made or took the folder. It lets a later run of the same wrapper reuse the folder, and
# it does not show that no other run uses it. The daemon reads the entries of the state folder by
# name (environment-id, conversation-claims-1, environments) and never lists the folder, so the
# marker is not read by it.
#
# The check walks down from the temporary directory by changing into one folder at a time and
# looking at the folder it is in (`.`), never at a name that something could have changed since it
# was read, and it does this in a subshell of its own, so the script's working directory does not
# move. It leaves the physical name of the state folder in E2E_STATE_FOLDER, and its inode in
# E2E_STATE_FOLDER_ID. Every later use of the state folder in a script runs through
# `e2e_state_folder_enter`, in a subshell: it changes into that physical name once and looks again
# at what it is in (the name, the owner, the mode, the inode, the marker). A script takes the
# folder's name from the working directory it is in, never from KR_E2E_STATE.
#
# A refusal names a folder of the chain that its group or others can write with that folder's mode,
# so that a person knows what to change. Where a folder on the way is not the one that its name
# gives (a link or another folder put in its place after the look, or a name that ends in a line
# feed and was cut there), the refusal adds fixed words after the rule's sentence. A refusal has no
# effect. The check makes the one folder and the one file it names, and when it cannot finish it
# removes the marker and the folder that it made, and nothing else.

# e2e_state_folder_look <root|own>: looks at the working directory. A root is the temporary
# directory: it belongs to the caller or to root, and is closed to writes by group and others or has
# the sticky bit. Any other folder belongs to the caller and is closed to writes by group and others.
# It returns 0 for a folder that passes, 4 for one whose owner is right and whose mode is too open
# (the mode is left in e2e_state_folder_seen), and 1 for anything else.
e2e_state_folder_look() {
  local kind="$1" line perms uid _
  line="$(LC_ALL=C ls -ldn -- . 2> /dev/null)" || return 1
  read -r perms _ uid _ <<< "$line"
  case "${perms:0:1}" in
    d) ;;
    *) return 1 ;;
  esac
  if [ "$kind" = root ]; then
    [ "$uid" = "$(id -u)" ] || [ "$uid" = 0 ] || return 1
    [ "${perms:5:1}${perms:8:1}" = -- ] && return 0
    case "${perms:9:1}" in
      t | T) return 0 ;;
    esac
    e2e_state_folder_seen="${perms:0:10}"
    return 4
  fi
  [ -O . ] || return 1
  [ "${perms:5:1}${perms:8:1}" = -- ] && return 0
  e2e_state_folder_seen="${perms:0:10}"
  return 4
}

# e2e_state_folder_look_failed <status of the look>: ends the walk. Where the look found a folder
# that the caller owns but others can write (status 4), it first prints the mode and the physical
# name of the folder, so that the refusal can name both.
e2e_state_folder_look_failed() {
  if [ "$1" = 4 ]; then
    printf '%s %s' "$e2e_state_folder_seen" "$PWD"
    e2e_state_folder_fail 4
  fi
  e2e_state_folder_fail 1
}

# e2e_state_folder_marker_ok <owner>: the working directory holds the marker of a run with this owner
# word: a regular file of the caller's with the word and one line feed, nothing else.
e2e_state_folder_marker_ok() {
  local owner="$1" said
  [ -f .kr-e2e-owner ] && [ ! -L .kr-e2e-owner ] && [ -O .kr-e2e-owner ] || return 1
  IFS= read -r said < .kr-e2e-owner || return 1
  [ "$said" = "$owner" ] || return 1
  [ "$(wc -c < .kr-e2e-owner | tr -d ' ')" -eq $((${#owner} + 1)) ]
}

# e2e_state_folder_mark <owner>: writes the owner word into the marker of the working directory, which
# the check has found empty. Nothing is overwritten and no link is followed: the marker is made with
# no-clobber, which fails for anything that is already at that name, a dangling link included. A
# marker that cannot be made or written ends it with status 3.
e2e_state_folder_mark() {
  local owner="$1"
  (
    set -C
    : > .kr-e2e-owner
  ) 2> /dev/null || return 3
  e2e_state_folder_marked=1
  { printf '%s\n' "$owner" > .kr-e2e-owner; } 2> /dev/null || return 3
  e2e_state_folder_marker_ok "$owner" || return 3
}

# e2e_state_folder_fail <status>: ends the walk. It first removes what the walk made and nothing
# else: the marker (a file of that one name, in the folder the walk is in) and the folder (an empty
# one, removed from the folder it was made in).
e2e_state_folder_fail() {
  local status="$1"
  if [ "$e2e_state_folder_inside" = 1 ]; then
    if [ "$e2e_state_folder_marked" = 1 ]; then
      rm -f -- .kr-e2e-owner
    fi
    if [ -n "$e2e_state_folder_made" ]; then
      if CDPATH='' cd -P -- .. 2> /dev/null && [ "$PWD" = "$e2e_state_folder_parent" ]; then
        rmdir -- "./$e2e_state_folder_made" 2> /dev/null
      fi
    fi
  elif [ -n "$e2e_state_folder_made" ]; then
    rmdir -- "./$e2e_state_folder_made" 2> /dev/null
  fi
  exit "$status"
}

# e2e_state_folder_walk <path> <owner>: the check proper, run in a subshell. It ends with status 0
# and prints the inode and the physical name of the state folder, with a space between, or with
# status 1 for a refusal by the rule, 3 where a write failed, 4 for a folder of the chain that
# others can write and 5 where a folder on the way is not the one that its name gives. The check
# gives its callers status 1 for every refusal.
e2e_state_folder_walk() {
  local state="$1" owner="$2" tmp base prev rest component name listing line inode _
  e2e_state_folder_made=""
  e2e_state_folder_parent=""
  e2e_state_folder_marked=0
  e2e_state_folder_inside=0
  e2e_state_folder_seen=""

  # The temporary directory, by the name the system gives it. `$PWD` carries every character of it,
  # a line feed at the end included, which a command substitution would drop.
  CDPATH='' cd -P -- "${TMPDIR:-/tmp}" 2> /dev/null || e2e_state_folder_fail 1
  tmp="$PWD"
  e2e_state_folder_look root || e2e_state_folder_look_failed $?
  # The name without its last slash, so that the top of the file system is read like any folder.
  base="${tmp%/}"
  case "$state" in
    "$base"/*/*) ;;
    *) e2e_state_folder_fail 1 ;;
  esac

  # Down through the folders between it and the state folder, each looked at from inside.
  rest="${state#"$base"/}"
  prev="$base"
  while :; do
    case "$rest" in
      */*) ;;
      *) break ;;
    esac
    component="${rest%%/*}"
    rest="${rest#*/}"
    [ ! -L "./$component" ] || e2e_state_folder_fail 1
    CDPATH='' cd -P -- "./$component" 2> /dev/null || e2e_state_folder_fail 1
    [ "$PWD" = "$prev/$component" ] || e2e_state_folder_fail 5
    prev="$PWD"
    e2e_state_folder_look own || e2e_state_folder_look_failed $?
  done

  # The state folder: made if it is absent, and looked at from inside before anything is written.
  name="$rest"
  [ ! -L "./$name" ] || e2e_state_folder_fail 1
  if [ ! -e "./$name" ]; then
    mkdir -m 700 -- "./$name" 2> /dev/null || e2e_state_folder_fail 3
    e2e_state_folder_made="$name"
    e2e_state_folder_parent="$PWD"
  fi
  [ -d "./$name" ] || e2e_state_folder_fail 1
  CDPATH='' cd -P -- "./$name" 2> /dev/null || e2e_state_folder_fail 1
  e2e_state_folder_inside=1
  [ "$PWD" = "$prev/$name" ] || e2e_state_folder_fail 5
  e2e_state_folder_look own || e2e_state_folder_look_failed $?

  # Empty or marked. The listing keeps a line feed at its end: a name that is one line feed is an
  # entry, so the folder is not empty.
  listing="$(ls -A -- . 2> /dev/null && printf x)" || e2e_state_folder_fail 1
  if [ "$listing" = x ]; then
    e2e_state_folder_mark "$owner" || e2e_state_folder_fail $?
  else
    e2e_state_folder_marker_ok "$owner" || e2e_state_folder_fail 1
  fi
  # The folder's mode is set last, so that a refusal leaves a folder that exists as it was.
  chmod 700 -- . 2> /dev/null || e2e_state_folder_fail 3

  line="$(ls -di -- . 2> /dev/null)" || e2e_state_folder_fail 1
  read -r inode _ <<< "$line"
  printf '%s %s' "$inode" "$PWD"
}

# e2e_state_folder_check: see above. It runs in the script's own shell, so that its refusal ends
# the script.
e2e_state_folder_check() {
  E2E_STATE_FOLDER=""
  E2E_STATE_FOLDER_ID=""
  E2E_STATE_FOLDER_OWNER=""
  local state="${KR_E2E_STATE:-}"
  [ -n "$state" ] || return 0
  local owner="${KR_E2E_STATE_OWNER:-}"
  local result code=0

  # The owner word: 8 to 64 characters from a short list. The list is written out, since a range
  # such as `A-Za-z` is read by collation under some locales.
  case "$owner" in
    *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]*) e2e_state_folder_refuse "$state" ;;
  esac
  if [ "${#owner}" -lt 8 ] || [ "${#owner}" -gt 64 ]; then
    e2e_state_folder_refuse "$state"
  fi

  # The path as it was written: no component that names the same or the parent folder, no empty one.
  case "$state" in
    *$'\n'* | *//* | */ | */. | */./* | */.. | */../*) e2e_state_folder_refuse "$state" ;;
  esac

  # The rest runs in a subshell, which changes folders and prints where it ended. The `x` after it
  # keeps a line feed at the end of the name.
  result="$(
    if (e2e_state_folder_walk "$state" "$owner"); then code=0; else code=$?; fi
    printf x
    exit "$code"
  )" || code=$?
  result="${result%x}"
  case "$code" in
    0) ;;
    3) e2e_state_folder_write_failed "$state" ;;
    4) e2e_state_folder_open "$state" "${result%% *}" "${result#* }" ;;
    5) e2e_state_folder_refuse "$state" "the path leads to a folder other than the one it names" ;;
    *) e2e_state_folder_refuse "$state" ;;
  esac
  E2E_STATE_FOLDER_ID="${result%% *}"
  E2E_STATE_FOLDER="${result#* }"
  E2E_STATE_FOLDER_OWNER="$owner"
}

# e2e_state_folder_enter [<own folder>]: changes into the state folder and looks again at what it is
# in: the physical name, the owner and mode, the inode that the check saw, and the marker. It returns
# 1 where any of them differs. The caller runs it in a subshell and does its work in the working
# directory. Where no wrapper named a folder (the check left E2E_STATE_FOLDER empty), it changes into
# the folder given as the argument, which is inside the run's own root.
e2e_state_folder_enter() {
  local line inode _
  if [ -z "${E2E_STATE_FOLDER:-}" ]; then
    [ -n "${1:-}" ] || return 1
    CDPATH='' cd -P -- "$1" 2> /dev/null || return 1
    return 0
  fi
  CDPATH='' cd -P -- "$E2E_STATE_FOLDER" 2> /dev/null || return 1
  [ "$PWD" = "$E2E_STATE_FOLDER" ] || return 1
  e2e_state_folder_look own || return 1
  line="$(ls -di -- . 2> /dev/null)" || return 1
  read -r inode _ <<< "$line"
  [ "$inode" = "${E2E_STATE_FOLDER_ID:-}" ] || return 1
  e2e_state_folder_marker_ok "${E2E_STATE_FOLDER_OWNER:-}"
}

# e2e_state_folder_refuse <path> [<words>]: says that the rule is not met and ends the script. Where
# the check gives words, they follow the sentence after a semicolon; they are fixed words of the
# check, never a name that arrived.
e2e_state_folder_refuse() {
  printf 'e2e: refusing KR_E2E_STATE %s: it must be a plain absolute path, with no symbolic link in it, to a folder inside a subfolder of the temporary directory; the temporary directory must belong to this account or to root and be closed to writes by others or sticky, and every folder below it, the state folder included, must belong to this account and be closed to writes by its group and others; KR_E2E_STATE_OWNER must name this run; and the folder must be new, empty, or marked with that name%s\n' "$1" "${2:+; $2}" >&2
  exit 1
}

# e2e_state_folder_open <path> <mode> <folder>: says which folder of the chain can be written by its
# group or by others, with its mode, and ends the script.
e2e_state_folder_open() {
  printf 'e2e: refusing KR_E2E_STATE %s: its folder %s has mode %s; every folder from the temporary directory down to the state folder must be closed to writes by its group and others (the temporary directory may instead carry the sticky bit), so remove the write permission of that folder, for example with chmod go-w\n' "$1" "$3" "$2" >&2
  exit 1
}

# e2e_state_folder_write_failed <path>: says that the folder or its marker could not be written, and
# ends the script. The walk has removed what it made.
e2e_state_folder_write_failed() {
  printf 'e2e: could not prepare KR_E2E_STATE %s: its folder, its mode or its owner marker could not be written; nothing that this check made was kept\n' "$1" >&2
  exit 1
}
