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
#   * the path is absolute, has no `.`, `..` or empty component (so no `//` and no trailing `/`)
#     and holds no line feed;
#   * its parent folder, read through its links, lies inside a folder that lies in the temporary
#     directory (${TMPDIR:-/tmp}, read through its links): the parent is below that directory and
#     is not that directory;
#   * its last component is not a symbolic link;
#   * KR_E2E_STATE_OWNER is set, of 8 to 64 characters from the letters, the digits, `.`, `_`
#     and `-`;
#   * the folder is one of: absent (the check makes it with mode 700 and writes the owner word into
#     `.kr-e2e-owner` in it); a directory owned by the caller that is empty (the same); or a
#     directory owned by the caller that holds `.kr-e2e-owner`, a regular file owned by the caller,
#     with exactly the owner word and a line feed.
#
# A folder that holds anything and no marker is a folder that something else made, and a marker
# with another word is another run's: both are refused. The marker proves that a run with this
# owner word made or took the folder. It lets a later run of the same wrapper reuse the folder, and
# it does not show that no other run uses it. The daemon reads the entries of the state folder by
# name (environment-id, conversation-claims-1, environments) and never lists the folder, so the
# marker is not read by it.
#
# Nothing is made or removed before every test of the path and of the owner word has held; after
# that the check makes the one folder and the one file it names, and nothing else.

# e2e_state_folder_check: see above. It runs in the script's own shell, so that its refusal ends
# the script.
e2e_state_folder_check() {
  local state="${KR_E2E_STATE:-}"
  [ -n "$state" ] || return 0
  local owner="${KR_E2E_STATE_OWNER:-}"
  local tmp parent marker said listing

  # The owner word: 8 to 64 characters from a short list. The list is written out, since a range
  # such as `A-Za-z` is read by collation under some locales.
  case "$owner" in
    *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]*) e2e_state_folder_refuse "$state" ;;
  esac
  if [ "${#owner}" -lt 8 ] || [ "${#owner}" -gt 64 ]; then
    e2e_state_folder_refuse "$state"
  fi

  # The path itself, as it was written.
  case "$state" in
    /*) ;;
    *) e2e_state_folder_refuse "$state" ;;
  esac
  case "$state" in
    *$'\n'* | *//* | */ | */. | */./* | */.. | */../*) e2e_state_folder_refuse "$state" ;;
  esac

  # Its parent folder is below the temporary directory, both read through their links.
  tmp="$(CDPATH='' cd -P -- "${TMPDIR:-/tmp}" 2> /dev/null && pwd -P)" || e2e_state_folder_refuse "$state"
  parent="${state%/*}"
  [ -n "$parent" ] || parent=/
  parent="$(CDPATH='' cd -P -- "$parent" 2> /dev/null && pwd -P)" || e2e_state_folder_refuse "$state"
  case "$parent" in
    "$tmp"/*) ;;
    *) e2e_state_folder_refuse "$state" ;;
  esac

  # The folder itself: not a link, and one of the three forms.
  [ ! -L "$state" ] || e2e_state_folder_refuse "$state"
  marker="$state/.kr-e2e-owner"
  if [ ! -e "$state" ]; then
    mkdir -m 700 -- "$state" 2> /dev/null || e2e_state_folder_refuse "$state"
    e2e_state_folder_mark "$state" "$marker" "$owner"
    return 0
  fi
  [ -d "$state" ] && [ -O "$state" ] || e2e_state_folder_refuse "$state"
  listing="$(ls -A -- "$state" 2> /dev/null)" || e2e_state_folder_refuse "$state"
  if [ -z "$listing" ]; then
    e2e_state_folder_mark "$state" "$marker" "$owner"
    return 0
  fi
  # The marker: a regular file of the caller's with the owner word and one line feed, nothing else.
  [ -f "$marker" ] && [ ! -L "$marker" ] && [ -O "$marker" ] || e2e_state_folder_refuse "$state"
  IFS= read -r said < "$marker" || e2e_state_folder_refuse "$state"
  [ "$said" = "$owner" ] || e2e_state_folder_refuse "$state"
  [ "$(wc -c < "$marker" | tr -d ' ')" -eq $((${#owner} + 1)) ] || e2e_state_folder_refuse "$state"
  return 0
}

# e2e_state_folder_mark <folder> <marker> <owner>: writes the owner word into the marker of a
# folder that the check has found new or empty, and refuses where it cannot.
e2e_state_folder_mark() {
  printf '%s\n' "$3" > "$2" 2> /dev/null || e2e_state_folder_refuse "$1"
}

# e2e_state_folder_refuse <path>: says that the rule is not met and ends the script.
e2e_state_folder_refuse() {
  printf 'e2e: refusing KR_E2E_STATE %s: it must be a plain absolute path, not a symbolic link, to a folder inside a subfolder of the temporary directory, KR_E2E_STATE_OWNER must name this run, and the folder must be new, empty, or marked with that name\n' "$1" >&2
  exit 1
}
