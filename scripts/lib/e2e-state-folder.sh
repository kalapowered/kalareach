# shellcheck shell=bash
# The rule for the folder that a demonstration keeps its daemon's state in, where a wrapper names
# one.
#
# `scripts/e2e-desktop.sh` and `scripts/e2e-permissions.sh` keep what their daemon records in
# `KR_E2E_STATE` when it is set, so that a later run finds it. A wrapper that names the folder
# could name the person's own state folder, and the demonstration would then start a daemon in it.
# A script sources this file and calls `e2e_state_folder_check` before it makes or starts
# anything, the log directory included. In every run the check holds the temporary directory to
# the rule below for it, and leaves its physical name in E2E_STATE_TMP, which is where the script
# makes the root of its run. When KR_E2E_STATE is not set (or is empty, which the scripts read as not
# set), the run's own state folder, made in that root, gets the same walk through
# `e2e_state_folder_take` once it is made, so that a folder is used the same way whoever named it.
# When KR_E2E_STATE is set, the check ends the script with status 1 and says why unless all of
# these hold:
#
#   * the path has no `.`, `..` or empty component (so no `//` and no trailing `/`) and holds no
#     line feed;
#   * the path is the physical name of the folder: it begins with the temporary directory
#     (${TMPDIR:-/tmp}, read through its links, with every character of its name kept), and the
#     folder lies in a subfolder of that directory, with no symbolic link on the way down;
#   * the temporary directory belongs to the caller or to root and is closed to writes by group and
#     others (with no access list entry on macOS), or has the sticky bit and, on macOS, no access list
#     entry that allows anything and no line that cannot be read as an `allow` or a `deny` entry, so
#     that nobody else can rename or remove an entry that is not theirs, take the sticky bit away or
#     rename the folder itself. A list of the rights that can do this would have to name every one, and
#     a right that it missed would pass; so no right is named. An entry that only denies grants nothing
#     and is accepted. An entry that allows anything refuses the folder whoever it names, this account
#     included: the check does not read whom an entry names;
#   * every folder from the first subfolder down to the state folder belongs to the caller, is
#     closed to writes by group and others and, on macOS, has no access list entry, so that no other
#     account can rename, replace or link away anything in the chain (on Linux the group bits of the
#     mode mask an access list);
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
# The check walks down from the temporary directory one folder at a time, in a subshell of its own,
# so the script's working directory does not move. It reads each folder from inside its parent with
# one listing that does not follow a link (kind, owner, mode and inode; on macOS the listing also
# prints each access list entry on a line of its own, since the `@` mark of an extended attribute
# hides the `+` mark of a list), and only a folder that passes is entered. After the change into it,
# the working directory must have the inode that was listed and the physical name that the system
# gives (`/bin/pwd -P`; the shell's own record of its directory is no evidence: it can keep a name
# that has changed). The check leaves the physical name of the state folder in E2E_STATE_FOLDER,
# and the inode that was listed in E2E_STATE_FOLDER_ID. Every later use of the state folder in a
# script runs through `e2e_state_folder_enter`, in a subshell: it changes into that physical name
# once and looks again at what it is in (the name, the inode, the marker). A script runs a `kr`
# command or the daemon from inside the folder with the folder named `.`, and takes the folder's name
# from the working directory it is in, never from KR_E2E_STATE.
#
# A refusal names a folder of the chain that its group or others can write with that folder's mode,
# or a folder with an access list entry, so that a person knows what to change. Where a folder on the
# way is not the one that its name gives (a link or another folder put in its place after the
# listing, or a name that ends in a line feed and was cut there), the refusal adds fixed words after
# the rule's sentence. A refusal has no effect. The check makes the one folder and the one file it
# names, and when it cannot finish it removes the marker and the folder that it made, and nothing
# else; where it cannot remove one of them, or cannot show by reading the directory that one of them is
# gone, the refusal says what is left or what may be left, and never that nothing was kept.
#
# What the check does not stop. The started program inherits its working directory, and the product
# turns that into a name and opens each file by that name, so the check holds only for as long as
# the folders of the chain are not moved: a process of the caller's OWN account that moves a folder
# of the chain after the walk is not stopped, and such a process can unload service jobs and end
# processes directly, so no check of a name could keep it from them. Holding the root by a handle
# is a change of the product and is not made here. The walk starts at the temporary directory: the
# folders above it belong to the operating system and are not walked (a walk from the top of the
# file system would refuse every run in a container, where the system's folders show as another
# account's, and no supported host lets another account write them), so a temporary directory below
# a folder that others can write is accepted: that protection is an assumption about the host, not
# something this check establishes. Another account is stopped only where it cannot write a folder
# of the chain, by its mode, its owner and, on macOS, its access list; on Linux the group bits of the
# mode mask a list, and a list cannot give another account the right to change a folder's mode or
# owner. The access list rule for a sticky temporary directory names no right, so it does not rest on
# the manual's text for one: it reads the entry lines of the listing and nothing else of its format (a
# listing that leaves them out shows no list), and a real macOS folder with an access list entry is
# not exercised by the cases.

# e2e_state_folder_list <entry>: reads <entry> (a name in the working directory, `.`, or a path) with
# ONE listing that does not follow a link, and leaves what it shows in e2e_state_folder_ino (the
# inode), e2e_state_folder_mode (the kind and the mode, 10 characters), e2e_state_folder_uid (the
# owner), e2e_state_folder_acl (1 where the listing has a line after the entry's own) and
# e2e_state_folder_acl_grants (1 where one of those lines is not a `deny` entry: an entry that allows
# any right, or a line that cannot be read, may grant something; a `deny` entry grants nothing). On macOS the listing is asked for the access list
# entries (`-e`, with `-n`, so that a principal prints as one word), each of which prints on a line of
# its own as ` <number>: <principal> [inherited ]allow|deny <right>,<right>...`: the `@` mark that an
# extended attribute puts after the mode hides the `+` mark of a list, so the mark cannot show a list
# there. Linux has no such flag, so nothing is read there: its group bits mask a list, and no list
# can give another account the right to change a folder's mode or owner. It returns 1 where the entry
# cannot be listed.
e2e_state_folder_list() {
  local flags=-ldin line entries entry word _
  if [ "$(uname -s)" = Darwin ]; then
    flags=-ldine
  fi
  line="$(LC_ALL=C ls "$flags" -- "$1" 2> /dev/null)" || return 1
  read -r e2e_state_folder_ino e2e_state_folder_mode _ e2e_state_folder_uid _ <<< "$line"
  e2e_state_folder_mode="${e2e_state_folder_mode:0:10}"
  e2e_state_folder_acl=0
  e2e_state_folder_acl_grants=0
  case "$line" in
    *$'\n'*)
      e2e_state_folder_acl=1
      entries="${line#*$'\n'}"
      while IFS= read -r entry; do
        read -r _ _ word _ <<< "$entry"
        if [ "$word" = inherited ]; then
          read -r _ _ _ word _ <<< "$entry"
        fi
        case "$word" in
          deny) ;;
          *) e2e_state_folder_acl_grants=1 ;;
        esac
      done <<< "$entries"
      ;;
  esac
}

# e2e_state_folder_look <root|own> <entry>: lists <entry> (see above) and judges it, with the one
# owner and mode test of that folder. A root is the temporary directory: it belongs to the caller or
# to root, and is closed to writes by group and others (with no access list entry) or has the sticky
# bit (with no access list entry that is not a `deny` entry, see `list` above). Any other folder belongs
# to the caller, is closed to writes by group and others and has no access list entry. It returns 0
# for a folder that passes, 4 for one whose owner is right and whose mode is too open (the mode is
# left in e2e_state_folder_seen), 6 for one with an access list entry that the rule refuses, and 1
# for anything else, a link and a file included.
e2e_state_folder_look() {
  e2e_state_folder_list "$2" || return 1
  e2e_state_folder_judge "$1"
}

# e2e_state_folder_judge <root|own>: judges what the last listing showed (see above).
e2e_state_folder_judge() {
  local kind="$1" perms uid
  perms="$e2e_state_folder_mode"
  uid="$e2e_state_folder_uid"
  case "${perms:0:1}" in
    d) ;;
    *) return 1 ;;
  esac
  if [ "$kind" = root ]; then
    [ "$uid" = "$(id -u)" ] || [ "$uid" = 0 ] || return 1
    # A sticky root that anyone can write is accepted only once its access list is read: an entry that
    # allows anything may let another account take the sticky bit away or rename the folder itself, so
    # a sticky root with one is refused, whatever right it names.
    case "${perms:9:1}" in
      t | T)
        [ "$e2e_state_folder_acl_grants" = 0 ] || return 6
        return 0
        ;;
    esac
  else
    [ "$uid" = "$(id -u)" ] || return 1
  fi
  if [ "${perms:5:1}${perms:8:1}" != -- ]; then
    e2e_state_folder_seen="$perms"
    return 4
  fi
  [ "$e2e_state_folder_acl" = 0 ] || return 6
}

# e2e_state_folder_here: leaves the physical name of the working directory in e2e_state_folder_name,
# as the system gives it (`/bin/pwd -P`), with every character of it kept: a command substitution
# would drop a line feed at the end, so the output is read with an `x` after it, and the one line
# feed that `pwd` adds is cut. The shell's own record of its directory ($PWD) is never used for this:
# it can keep a name that has changed.
e2e_state_folder_here() {
  local name
  name="$(/bin/pwd -P 2> /dev/null && printf x)" || return 1
  name="${name%x}"
  e2e_state_folder_name="${name%$'\n'}"
}

# e2e_state_folder_arrived <inode> <name>: ends the walk with status 5 unless the working directory
# is the folder that was listed: it has the inode that the listing gave and the physical name
# that the walk expected.
e2e_state_folder_arrived() {
  local line here _
  line="$(ls -di -- . 2> /dev/null)" || e2e_state_folder_fail 5
  read -r here _ <<< "$line"
  [ "$here" = "$1" ] || e2e_state_folder_fail 5
  e2e_state_folder_here || e2e_state_folder_fail 5
  [ "$e2e_state_folder_name" = "$2" ] || e2e_state_folder_fail 5
}

# e2e_state_folder_look_failed <status of the look> <name>: ends the walk. Where the look found a
# folder that the caller owns but others can write (status 4), it first prints the mode and the
# physical name of the folder, so that the refusal can name both; for a folder with an access list
# entry (status 6) it prints the name.
e2e_state_folder_look_failed() {
  case "$1" in
    4)
      printf '%s %s' "$e2e_state_folder_seen" "$2"
      e2e_state_folder_fail 4
      ;;
    6)
      printf '%s' "$2"
      e2e_state_folder_fail 6
      ;;
  esac
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
# the check has found empty. Nothing is overwritten and no link is followed. A name that exists in any
# form is refused: no-clobber alone stops a regular file and a dangling link, and the existence test
# stops a link to a device or a pipe and any other thing that no-clobber would open. The marker is
# then made and written through ONE open of that name (descriptor 3), so that a name that is
# exchanged for a link after the open cannot redirect the write. The creation is recorded before the
# content is written, so that a cleanup knows a partial marker. A marker that cannot be made,
# written or closed ends it with status 3; one that was refused or not made leaves nothing to remove.
e2e_state_folder_mark() {
  local owner="$1" opened written
  [ ! -e .kr-e2e-owner ] || return 3
  set -C
  { exec 3> .kr-e2e-owner; } 2> /dev/null
  opened=$?
  set +C
  [ "$opened" = 0 ] || return 3
  e2e_state_folder_marked=1
  { printf '%s\n' "$owner" >&3; } 2> /dev/null
  written=$?
  exec 3>&- || return 3
  [ "$written" = 0 ] || return 3
  e2e_state_folder_marker_ok "$owner" || return 3
}

# e2e_state_folder_gone <name>: tells whether <name>, a name in the working directory, is gone. It reads
# the directory and compares each name in it, whole and byte for byte, with <name>: a test of the name
# itself gives the same answer for a name that is not there and for one that cannot be looked at (a
# folder that cannot be searched, an input or output error), so a failed test shows nothing. The
# listing command is run only for its exit status, which says whether the directory can be read; its
# text is never read, since a variable of the environment (a quoting style, forced colour) can change
# how it prints a name. The names come from the shell's own read of the directory, in a subshell that
# sets every option that could change that read: patterns are expanded (not left as they are), no
# pattern hides a name, an unmatched pattern is neither an error nor itself, names that start with a
# dot count, and the bytes of a name are compared as they are. It returns 0 where the directory was read and does not hold the name, 1 where
# it holds it, and 2 where it could not be read, which shows neither.
e2e_state_folder_gone() {
  local found=0
  ls -A -- . > /dev/null 2>&1 || return 2
  (
    unset GLOBIGNORE
    LC_ALL=C
    set +f
    shopt -u failglob
    shopt -s nullglob dotglob
    for entry in ./*; do
      [ "${entry#./}" = "$1" ] && exit 1
    done
    exit 0
  ) || found=$?
  case "$found" in
    0 | 1) return "$found" ;;
  esac
  return 2
}

# e2e_state_folder_fail <status>: ends the walk. It first removes what the walk made and nothing
# else: the marker (a file of that one name, in the folder the walk is in) and the folder (an empty
# one, removed from its parent). A removal counts only where its command succeeded or the directory
# was read and does not hold the name (e2e_state_folder_gone); anything else is left or unresolved. It
# ends with the status plus 16 for what it could not remove or could not show to be gone, so that the
# check can say what is left: 1 for the marker, 2 for the folder, 3 for both, 4 for a folder that could
# not be read and may still be there, 5 for a marker that is there with such a folder, 6 for a marker
# that could not be read, 7 for such a marker with a folder that is there or could not be read. A
# removed folder takes its marker with it. The mode of a folder that was there is changed last of all
# and only when nothing can fail after it, so no status leaves a folder that was there with another
# mode.
e2e_state_folder_fail() {
  local status="$1" left marker=0 folder=0
  if [ "$e2e_state_folder_marked" = 1 ]; then
    if ! rm -f -- .kr-e2e-owner 2> /dev/null; then
      e2e_state_folder_gone .kr-e2e-owner
      marker=$?
    fi
  fi
  if [ -n "$e2e_state_folder_made" ]; then
    e2e_state_folder_unmake
    folder=$?
    [ "$folder" != 0 ] || marker=0
  fi
  case "$marker$folder" in
    00) left=0 ;;
    10) left=1 ;;
    01) left=2 ;;
    11) left=3 ;;
    02) left=4 ;;
    12) left=5 ;;
    20) left=6 ;;
    *) left=7 ;;
  esac
  exit $((status + 16 * left))
}

# e2e_state_folder_unmake: removes the folder that the walk made, from its parent, which it reaches by
# the parent's physical name and checks by that name; the folder is removed only while its name still
# has the inode that the walk listed after it made it. It returns 0 where the folder is gone (removed,
# or the parent was read and does not hold the name), 1 where it is still there (another folder at that
# name is not the walk's to remove), and 2 where that cannot be told: the parent could not be entered
# or is not the folder expected, or the folder could not be listed and the parent could not be read to
# show the name gone. Nothing is removed without the listing's inode.
e2e_state_folder_unmake() {
  CDPATH='' cd -P -- "$e2e_state_folder_parent" 2> /dev/null || return 2
  e2e_state_folder_here && [ "$e2e_state_folder_name" = "$e2e_state_folder_parent" ] || return 2
  if ! e2e_state_folder_list "./$e2e_state_folder_made"; then
    e2e_state_folder_gone "$e2e_state_folder_made" && return 0
    return 2
  fi
  [ "$e2e_state_folder_ino" = "$e2e_state_folder_made_inode" ] || return 1
  if rmdir -- "./$e2e_state_folder_made" 2> /dev/null; then
    return 0
  fi
  e2e_state_folder_gone "$e2e_state_folder_made"
}

# e2e_state_folder_walk <path> <owner>: the check proper, run in a subshell. It ends with status 0
# and prints the inode and the physical name of the state folder, with a space between, or with
# status 1 for a refusal by the rule, 3 where a write failed, 4 for a folder of the chain that
# others can write, 5 where a folder on the way is not the one that its name gives and 6 for a
# folder with an access list entry. The check gives its callers status 1 for every refusal.
e2e_state_folder_walk() {
  local state="$1" owner="$2" tmp base prev rest component name listing inode
  e2e_state_folder_made=""
  e2e_state_folder_parent=""
  e2e_state_folder_made_inode=""
  e2e_state_folder_marked=0
  e2e_state_folder_seen=""

  # The temporary directory, by the name the system gives it, a line feed at the end included.
  CDPATH='' cd -P -- "${TMPDIR:-/tmp}" 2> /dev/null || e2e_state_folder_fail 1
  e2e_state_folder_here || e2e_state_folder_fail 1
  tmp="$e2e_state_folder_name"
  e2e_state_folder_look root . || e2e_state_folder_look_failed $? "$tmp"
  # With no path, the walk ends at the temporary directory and gives its inode and its name.
  if [ -z "$state" ]; then
    printf '%s %s' "$e2e_state_folder_ino" "$tmp" 2> /dev/null || e2e_state_folder_fail 3
    return 0
  fi
  # The name without its last slash, so that the top of the file system is read like any folder.
  base="${tmp%/}"
  case "$state" in
    "$base"/*/*) ;;
    *) e2e_state_folder_fail 1 ;;
  esac

  # Down through the folders between it and the state folder. Each one is listed from inside its
  # parent, where no change of a name can come between the listing and the folder it describes, and is
  # entered only if it passes; the place that was entered must then be the folder that was listed.
  rest="${state#"$base"/}"
  prev="$base"
  while :; do
    case "$rest" in
      */*) ;;
      *) break ;;
    esac
    component="${rest%%/*}"
    rest="${rest#*/}"
    e2e_state_folder_look own "./$component" || e2e_state_folder_look_failed $? "$prev/$component"
    inode="$e2e_state_folder_ino"
    CDPATH='' cd -P -- "./$component" 2> /dev/null || e2e_state_folder_fail 1
    e2e_state_folder_arrived "$inode" "$prev/$component"
    prev="$prev/$component"
  done

  # The state folder: made if it is absent (the listing fails for a name that is not there), listed
  # from inside its parent like the others, and entered only if it passes. The inode of that listing
  # is the one that every later entry into the folder is compared with.
  name="$rest"
  if ! e2e_state_folder_list "./$name"; then
    mkdir -m 700 -- "./$name" 2> /dev/null || e2e_state_folder_fail 3
    e2e_state_folder_made="$name"
    e2e_state_folder_parent="$prev"
    e2e_state_folder_list "./$name" || e2e_state_folder_fail 1
    e2e_state_folder_made_inode="$e2e_state_folder_ino"
  fi
  e2e_state_folder_judge own || e2e_state_folder_look_failed $? "$prev/$name"
  inode="$e2e_state_folder_ino"
  CDPATH='' cd -P -- "./$name" 2> /dev/null || e2e_state_folder_fail 1
  e2e_state_folder_arrived "$inode" "$prev/$name"

  # Empty or marked. The listing keeps a line feed at its end: a name that is one line feed is an
  # entry, so the folder is not empty.
  listing="$(ls -A -- . 2> /dev/null && printf x)" || e2e_state_folder_fail 1
  if [ "$listing" = x ]; then
    e2e_state_folder_mark "$owner" || e2e_state_folder_fail $?
  else
    e2e_state_folder_marker_ok "$owner" || e2e_state_folder_fail 1
  fi
  # The result is handed over first, and the folder's mode is set LAST: nothing after the mode change
  # can fail (the walk only ends), so a refusal or a failure leaves a folder that was there with the
  # mode it had, and a failed mode change leaves it unchanged.
  printf '%s %s' "$inode" "$prev/$name" 2> /dev/null || e2e_state_folder_fail 3
  chmod 700 -- . 2> /dev/null || e2e_state_folder_fail 3
}

# e2e_state_folder_check: see above. It runs in the script's own shell, so that its refusal ends
# the script.
e2e_state_folder_check() {
  E2E_STATE_TMP=""
  E2E_STATE_FOLDER=""
  E2E_STATE_FOLDER_ID=""
  E2E_STATE_FOLDER_OWNER=""
  local state="${KR_E2E_STATE:-}" owner="${KR_E2E_STATE_OWNER:-}"

  if [ -n "$state" ]; then
    e2e_state_folder_subject="KR_E2E_STATE $state"
    e2e_state_folder_wrapped=1
    # The owner word: 8 to 64 characters from a short list. The list is written out, since a range
    # such as `A-Za-z` is read by collation under some locales.
    case "$owner" in
      *[!abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-]*) e2e_state_folder_refuse ;;
    esac
    if [ "${#owner}" -lt 8 ] || [ "${#owner}" -gt 64 ]; then
      e2e_state_folder_refuse
    fi
    # The path as it was written: no component that names the same or the parent folder, no empty one.
    case "$state" in
      *$'\n'* | *//* | */ | */. | */./* | */.. | */../*) e2e_state_folder_refuse ;;
    esac
  else
    e2e_state_folder_subject="the temporary directory ${TMPDIR:-/tmp}"
    e2e_state_folder_wrapped=0
  fi

  # The temporary directory is checked in EVERY run, wrapper or none: the scripts make their own root
  # in it and read job labels from below it. The walk with no path ends at the root and leaves its
  # physical name, which is where the scripts make that root.
  e2e_state_folder_ask "" ""
  # Read by the scripts that source this file.
  # shellcheck disable=SC2034
  E2E_STATE_TMP="${e2e_state_folder_answer#* }"
  [ -z "$state" ] || e2e_state_folder_take "KR_E2E_STATE $state" "$state" "$owner"
}

# e2e_state_folder_ask <path> <owner>: runs the walk in a subshell, which changes folders and prints
# where it ended, and leaves what it printed in e2e_state_folder_answer and its status in
# e2e_state_folder_code. The `x` after the output keeps a line feed at the end of a name.
e2e_state_folder_ask() {
  local code=0
  e2e_state_folder_answer="$(
    if (e2e_state_folder_walk "$1" "$2"); then code=0; else code=$?; fi
    printf x
    exit "$code"
  )" || code=$?
  e2e_state_folder_answer="${e2e_state_folder_answer%x}"
  e2e_state_folder_code="$code"
  e2e_state_folder_report
}

# e2e_state_folder_report: says why the last walk refused and ends the script, or returns for one that
# passed. The walk's status carries what it could not remove in its upper bits (see
# e2e_state_folder_fail).
e2e_state_folder_report() {
  local left=$(((e2e_state_folder_code >> 4) & 7)) code=$((e2e_state_folder_code & 15))
  local result="$e2e_state_folder_answer"
  case "$code" in
    0) ;;
    3) e2e_state_folder_write_failed "$left" ;;
    4) e2e_state_folder_open "${result%% *}" "${result#* }" "$left" ;;
    5) e2e_state_folder_refuse "the path leads to a folder other than the one it names" "$left" ;;
    6) e2e_state_folder_listed "$result" "$left" ;;
    *) e2e_state_folder_refuse "" "$left" ;;
  esac
}

# e2e_state_folder_take <subject> <path> <owner>: walks <path> like a state folder that a wrapper
# named, with the owner word <owner>, and leaves it in E2E_STATE_FOLDER, E2E_STATE_FOLDER_ID and
# E2E_STATE_FOLDER_OWNER. A refusal names <subject> and ends the script. The check calls it for the
# wrapper's folder; a script with no wrapper calls it for the folder of its own run, after it has made
# the run's root in E2E_STATE_TMP, so that every use of the state folder runs the same way.
e2e_state_folder_take() {
  e2e_state_folder_subject="$1"
  case "$1" in
    "KR_E2E_STATE "*) e2e_state_folder_wrapped=1 ;;
    *) e2e_state_folder_wrapped=0 ;;
  esac
  e2e_state_folder_ask "$2" "$3"
  E2E_STATE_FOLDER_ID="${e2e_state_folder_answer%% *}"
  E2E_STATE_FOLDER="${e2e_state_folder_answer#* }"
  E2E_STATE_FOLDER_OWNER="$3"
}

# e2e_state_folder_enter: changes into the state folder and looks again at what it is in: the physical
# name that the system gives (`/bin/pwd -P`), the ORIGINAL inode (the one the walk listed from inside
# the parent, before it entered the folder, which is what E2E_STATE_FOLDER_ID holds), and the marker.
# It returns 1 where any of them differs, and where no state folder was taken: there is ONE way in,
# for a folder that a wrapper named and for the folder of a run's own. It reaches the folder by its
# name and tests nothing of the parent: the inode and the name are what make the folder the one that
# was checked, and only the account that owns a folder can change its mode or its owner, so the folder
# gets no second owner and mode test. The caller runs it in a subshell and does its work in the
# working directory.
e2e_state_folder_enter() {
  local line inode _
  [ -n "${E2E_STATE_FOLDER:-}" ] || return 1
  CDPATH='' cd -P -- "$E2E_STATE_FOLDER" 2> /dev/null || return 1
  e2e_state_folder_here && [ "$e2e_state_folder_name" = "$E2E_STATE_FOLDER" ] || return 1
  line="$(ls -di -- . 2> /dev/null)" || return 1
  read -r inode _ <<< "$line"
  [ "$inode" = "${E2E_STATE_FOLDER_ID:-}" ] || return 1
  e2e_state_folder_marker_ok "${E2E_STATE_FOLDER_OWNER:-}"
}

# e2e_state_folder_run <command> [<argument>...]: in the calling subshell, enters the state folder
# (e2e_state_folder_enter) and replaces the subshell with the command, started inside it. It returns
# 125, and starts nothing, where the folder is no longer the one that was checked.
e2e_state_folder_run() {
  e2e_state_folder_enter || return 125
  exec "$@"
}

# e2e_state_folder_kr <kr> [<argument>...]: runs one `kr` command inside the state folder, in a
# subshell of its own, with the state folder named `.` in KR_STATE_DIR of that command only. The name
# is relative: the command turns it into a name when it starts, in the folder it was started in, which
# is the checked one, so that no name outside the folder is left to be read twice. The caller's own
# environment is not changed. It returns the command's status, or 125 where the folder is no longer
# the one that was checked.
e2e_state_folder_kr() {
  (
    export KR_STATE_DIR=.
    e2e_state_folder_run "$@"
  )
}

# e2e_state_folder_left_words <left>: the fixed words that say what the walk made and could not remove
# (1 the marker, 2 the folder, 3 both, 4 a folder that could not be read and may still be there, 5 the
# marker, which is there, with such a folder, 6 a marker that could not be read and may still be there,
# 7 such a marker with a folder that is there or could not be read); nothing for 0.
e2e_state_folder_left_words() {
  case "$1" in
    1) printf 'the owner marker that the check wrote is still in the folder' ;;
    2) printf 'the empty folder that the check made is still there' ;;
    3) printf 'the folder that the check made, with its owner marker, is still there' ;;
    4) printf 'the folder that the check made may still be there, since it could not be read' ;;
    5) printf 'the owner marker that the check wrote is still in the folder, and the folder that the check made may still be there, since it could not be read' ;;
    6) printf 'the owner marker that the check wrote may still be in the folder, since it could not be read' ;;
    7) printf 'the folder that the check made is still there or could not be read, and the owner marker that the check wrote may still be in it, since the marker could not be read' ;;
  esac
}

# The sentences name the subject of the walk that refused (e2e_state_folder_subject): `KR_E2E_STATE`
# and its path where a wrapper named the folder, `the temporary directory` for the root rule that
# every run is held to, and the run's own folder for a run with no wrapper.

# e2e_state_folder_refuse [<words> [<left>]]: says that the rule is not met and ends the script. Where
# the check gives words, they follow the sentence after a semicolon, and what the walk could not remove
# follows them; all are fixed words of the check, never a name that arrived.
e2e_state_folder_refuse() {
  local words="${1:-}" left
  left="$(e2e_state_folder_left_words "${2:-0}")"
  [ -z "$left" ] || words="${words:+$words; }$left"
  if [ "$e2e_state_folder_wrapped" = 1 ]; then
    printf 'e2e: refusing %s: it must be a plain absolute path, with no symbolic link in it, to a folder inside a subfolder of the temporary directory; the temporary directory must belong to this account or to root and be closed to writes by others or sticky, and every folder below it, the state folder included, must belong to this account and be closed to writes by its group and others; KR_E2E_STATE_OWNER must name this run; and the folder must be new, empty, or marked with that name%s\n' "$e2e_state_folder_subject" "${words:+; $words}" >&2
  else
    printf 'e2e: refusing %s: it must be a folder that belongs to this account (the temporary directory may belong to root), with no symbolic link in its path, closed to writes by its group and others (the temporary directory may instead carry the sticky bit)%s\n' "$e2e_state_folder_subject" "${words:+; $words}" >&2
  fi
  exit 1
}

# e2e_state_folder_open <mode> <folder> [<left>]: says which folder of the chain can be written by its
# group or by others, with its mode, and ends the script.
e2e_state_folder_open() {
  local left
  left="$(e2e_state_folder_left_words "${3:-0}")"
  printf 'e2e: refusing %s: its folder %s has mode %s; every folder from the temporary directory down to the state folder must be closed to writes by its group and others (the temporary directory may instead carry the sticky bit), so remove the write permission of that folder, for example with chmod go-w%s\n' "$e2e_state_folder_subject" "$2" "$1" "${left:+; $left}" >&2
  exit 1
}

# e2e_state_folder_listed <folder> [<left>]: says which folder of the chain has an access list entry
# that the rule does not accept, and what to do about it, and ends the script. Only the macOS branch
# reads an access list (see `list`), so the command that the sentence names is macOS's.
e2e_state_folder_listed() {
  local left
  left="$(e2e_state_folder_left_words "${2:-0}")"
  printf 'e2e: refusing %s: its folder %s has an access list entry that the rule does not accept. The rule refuses any entry that allows something, whoever it names, this account included; any line that is neither an allow nor a deny entry; and a deny entry, unless the folder is a temporary directory with the sticky bit. The owner of the folder can remove the list, for example with chmod -N. If this account does not own the temporary directory, set TMPDIR to a private folder of your own and put KR_E2E_STATE below it%s\n' "$e2e_state_folder_subject" "$1" "${left:+; $left}" >&2
  exit 1
}

# e2e_state_folder_write_failed [<left>]: says that the folder, its mode, its owner marker or the
# hand-over of the result could not be written, and ends the script. It says that nothing was kept
# only where the walk removed everything it made; otherwise it says what is left.
e2e_state_folder_write_failed() {
  local left
  left="$(e2e_state_folder_left_words "${1:-0}")"
  printf 'e2e: could not prepare %s: its folder, its mode or its owner marker could not be written; %s\n' "$e2e_state_folder_subject" "${left:-nothing that this check made was kept}" >&2
  exit 1
}
