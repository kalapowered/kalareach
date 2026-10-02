#!/usr/bin/env bash
# KR-ACC-011: WSL2 acceptance. Several distributions, independent operation, NAT and mirrored
# networking, and environment-specific paths.
#
# This runs on a Windows host with WSL2, in Git Bash or MSYS2. It is an acceptance run, so a
# prerequisite it cannot meet is a failure rather than a skip: a run that cannot establish these
# results has not established them.
#
# What it establishes, in order:
#
#   1. WSL 2 is installed, the default version is 2, and two distributions are registered. A second
#      one is made by exporting and importing the first when only one is there, and is removed
#      again at the end.
#   2. Each distribution runs KalaReach on its own: its own control daemon, its own worker, its own
#      Linux paths and process identifiers, with the native Windows installation taking no part. A
#      distribution this run imported is a copy, so the installation it inherited is removed before
#      anything starts in it and it becomes an installation of its own.
#   3. Argument vectors cross `wsl.exe --exec` unchanged, including values a shell would rewrite.
#   4. Windows reaches each distribution through the process bridge alone, learns that
#      distribution's own environment identity, and gets an answer to a real read across it.
#   5. A listing of stopped distributions comes from the cache and starts nothing. A refresh that
#      was told to start one does. So does creating a session in one from Windows, which also has
#      the distribution's own startup start the control daemon inside it, and so does attaching to
#      a session there, which is told by the distribution that the session has closed.
#   6. The bridge behaves the same in NAT and in mirrored networking mode, which is what decides
#      whether any automatic behaviour is needed.
#
# Every artefact is written under ${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}. The Windows
# daemon this starts keeps its keys in its own run directory (never the Credential Manager).
#
# Knobs, all optional:
#   KR_WSL_HELPER     absolute path of the helper inside a distribution (default /usr/local/bin/kr)
#   KR_WSL_USER       the Linux user the helper runs as (default root)
#   KR_WSL_SECOND     the name of the second distribution this script makes (default kr-acc-011)
#   KR_WSL_ROOT       where that distribution's image is written (default /c/kala/wsl)
#   KR_WSL_KEEP       1 to keep the second distribution and the daemons for inspection
#   KR_WSL_NETWORK_MODES
#                     the networking modes step 6 measures, as `nat`, `mirrored` or `nat mirrored`
#                     (default `nat mirrored`). A host that cannot offer a mode is a failure when
#                     the mode is asked for, so a host that cannot offer mirrored networking, as a
#                     hosted Windows Server cannot, names only `nat` and the run says that mirrored
#                     was not measured on it. The run's result is the modes it measured and no more.
#
# `bash scripts/e2e-wsl.sh --self-test` checks the part of step 3 that removes the installation a
# copied distribution inherited. It runs on a Linux host, with no Windows and no WSL, against trees
# of its own.
set -euo pipefail

# A distribution this run imported is a copy of another one, and a copy of an installation is not a
# second installation: it carries the first one's environment identity, its registry and its
# staging area, and those name a device and an inode that are different here. The daemon in the
# copy is right to refuse them, so the copy is given none of it before anything starts in it.
#
# Two things have to be right, and neither is guessed at here.
#
# **Which directories.** The product derives its runtime and state roots from the directories this
# OS user's environment names. Every one of those inputs is mirrored into a directory of this run's
# own, the installed helper is asked where it then reads an account token (which lies directly in
# the runtime root) and where it publishes the identity it allocates on a first use (which lies
# directly in the state root), and each answer is mapped back through the input it came from. What
# is removed is the exact value that input holds, followed by the plain path the helper named below
# its mirror. Every root the product derives on Linux lies inside one of those inputs, and below a
# home or an XDG directory it lies in a directory named kalareach. So an answer outside every
# mirror, one whose part below its mirror is not a plain path, and one below a home or an XDG
# directory that is not in a directory of that name, each stop the run before anything is removed,
# and so does an input that is set but empty or is not an absolute path. Nothing is read back
# through a step that could change it unseen: the probe is made in a directory whose name is a
# plain path, the helper's answer is taken as it wrote it, a listing of names ends each one with a
# NUL byte, and a name read through a command substitution keeps any newline at its end.
#
# **Which storage.** A directory that is not there was not inherited, and is left alone. A
# directory that is there is removed only when the whole of it -- the directory and everything
# under it -- is on the filesystem the image carries, which is the one the root of this
# distribution is on. Anything else -- a symbolic link out to storage shared between
# distributions, a mount of other storage at its top or at any directory inside it -- is not this
# copy's to remove and not something a copy can be made independent of, so the run stops and says
# which path it was. A root that is the image itself, or holds it, is refused, and so is one that
# is, or holds, the home directory or a base directory the product derives its roots below (the
# XDG directories the environment names, and `.local/state` and `.cache` in the home), however the
# path to it was reached. A root joins the list of what is removed only once every check has passed
# for it, and nothing is removed until both have been measured, so a refusal while measuring leaves
# both alone. A root that is not the directory it was when measured is left, and a root removed
# before it stays removed. The tests are by device and inode, so a bind mount of another directory
# of the same filesystem is not told apart from the directory it covers.
#
# The program runs inside the distribution. Its arguments are the installed helper, the root of the
# image (`/` inside a distribution) and the directory its probe is made in. The self-test below runs
# the same program on this host, with a stand-in for the helper and a tree of its own for the image.
# shellcheck disable=SC2016  # the program is expanded where it runs, not here
inherited_reset='
    set -e
    # Bytes, not characters: every check below is about the exact bytes of a name.
    LC_ALL=C
    export LC_ALL
    # A message is printed as it is, whatever the name in it holds: echo in dash would read a
    # backslash in a name as an escape.
    say() { printf "%s\n" "$*"; }
    refuse() { printf "%s\n" "$*" >&2; exit 1; }
    # Whether the first path is the second one, or lies below it.
    is_within() { case "$1/" in "${2%/}"/*) return 0 ;; esac; return 1; }
    # What the argument leads to, followed by an x. A command substitution drops every newline at
    # the end of what it reads, and a name can end in one, so the caller takes the x off with the
    # one newline readlink adds and keeps the rest.
    leads_to() { readlink -m "$1" && printf x; }
    helper="$1"
    image="$2"
    parent="$3"
    # Every path this program reads back from another program lies under its probe, so the probe
    # is made in a directory whose name is a plain path: nothing in it can split, cut short or
    # escape what is read back.
    case "$parent" in
      /*) ;;
      *) refuse "the probe directory $parent is not an absolute path" ;;
    esac
    case "$parent" in
      *[!A-Za-z0-9._/-]*)
        refuse "the probe directory $parent is not a plain path, so nothing is read back from under it"
        ;;
    esac
    probe="$(mktemp -d "$parent/kr-acc-probe.XXXXXX")"
    trap "rm -rf \"\${probe:?}\"" EXIT
    # Each mirror is owner-only, because a mirror can become a root the product creates its files
    # in directly, and the product refuses a root anyone else can read.
    #
    # The real value of each input is held in a shell variable beside its mirror rather than in a
    # file of pairs. A path may carry a space, a tab or a trailing blank, and a line of text read
    # back as two fields would not return the value the product was given. An input that is set
    # but empty, or is not an absolute path, leads wherever the directory this program runs in
    # leads, which is not a place the product was configured to use, so it stops the run.
    index=0
    for name in HOME XDG_STATE_HOME XDG_RUNTIME_DIR KR_STATE_DIR KR_RUNTIME_DIR; do
      eval "present=\${$name+set}"
      [ -n "$present" ] || continue
      eval "value=\${$name}"
      [ -n "$value" ] || refuse "$name is set but empty, so it leads wherever this program runs"
      case "$value" in
        /*) ;;
        *) refuse "$name holds $value, which is not an absolute path" ;;
      esac
      # A runtime directory inside what WSLg shares between every distribution of the machine is
      # not one the product uses: its runtime root is then below the home directory. So the helper
      # is asked as the product runs, with none, and the root it names is the one it has.
      if [ "$name" = XDG_RUNTIME_DIR ]; then
        case "$(readlink -m "$value")/" in
          /mnt/wslg/*)
            unset XDG_RUNTIME_DIR
            continue
            ;;
        esac
      fi
      index=$((index + 1))
      mkdir -m 0700 "$probe/$index"
      eval "configured_$index=\$value"
      eval "input_$index=\$name"
      eval "export $name=\"\$probe/\$index\""
    done
    # The value is read as the helper wrote it, with nothing taken out of it. A path the document
    # had to escape keeps its backslash, which the plain-path rule below refuses.
    token="$("$helper" --json account token show |
      sed -n "s/.*\"path\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p")"
    [ -n "$token" ] ||
      refuse "the helper did not say where it reads an account token, so its runtime root is not known"
    # This has no daemon to reach and fails once it has allocated the identity, which is the part
    # being read here.
    "$helper" list >/dev/null 2>&1 || true
    # The shallowest file the helper made, read from a listing that ends each record with a NUL
    # byte, and through an x that keeps any newline at the end of its name.
    marker="$(find "$probe" -type f -printf "%d %p\0" | sort -z -n | head -z -n 1 |
      cut -z -d" " -f2- | tr -d "\000"; printf x)"
    marker="${marker%x}"
    [ -n "$marker" ] ||
      refuse "the helper published no identity of its own, so its state root is not known"
    image_device="$(stat -c %d "$image")"
    image_real="$(leads_to "$image")"
    image_real="${image_real%?x}"
    # A root joins the list of what is removed only once every check below has passed for it, and
    # nothing is removed until both have been measured, so a refusal for one leaves both alone.
    count=0
    for named in "${token%/*}" "${marker%/*}"; do
      # What is removed is the exact value an input holds, followed by the plain path the helper
      # named below the mirror of that input. A path outside every mirror, or one whose part below
      # its mirror is not a plain path, is not one this run can map back exactly, so the run stops
      # before it removes anything.
      real=""
      below=""
      input=""
      mapped=0
      while [ "$mapped" -lt "$index" ]; do
        mapped=$((mapped + 1))
        mirror="$probe/$mapped"
        case "$named" in
          "$mirror" | "$mirror"/*)
            eval "value=\$configured_$mapped"
            eval "input=\$input_$mapped"
            below="${named#"$mirror"}"
            real="$value$below"
            ;;
        esac
      done
      [ -n "$real" ] ||
        refuse "the helper named $named, which is outside every directory this run mirrored"
      # The product keeps what it owns below a home or an XDG directory in a directory named
      # kalareach. The directory the input names, and its other children, belong to somebody else.
      case "$input" in
        HOME | XDG_STATE_HOME | XDG_RUNTIME_DIR)
          case "$below" in
            */kalareach | */kalareach/*) ;;
            *)
              refuse "the helper named $real, which is not in a directory named kalareach below $input"
              ;;
          esac
          ;;
      esac
      case "$below" in
        *[!A-Za-z0-9._/-]* | */. | */./* | */.. | */../* | *//*)
          refuse "the helper named $named, and what lies below the directory this run mirrored is not a plain path"
          ;;
      esac
      # What the path leads to, not what it says: a component of it may be a link somewhere else.
      resolved="$(leads_to "$real")"
      resolved="${resolved%?x}"
      if [ ! -e "$resolved" ]; then
        say "  nothing of the product at $real"
        continue
      fi
      # A root that is the image itself, or holds it, would take the image with it. So would one
      # that is, or holds, the home directory or a base directory the product derives its roots
      # below: the ones the environment names, and the two the product falls back to in the home.
      # A link at a root can lead to any of them.
      if is_within "$image_real" "$resolved"; then
        refuse "$real leads to $resolved, which is the image itself or holds it"
      fi
      k=0
      kind=""
      kvalue=""
      while [ "$k" -lt "$index" ]; do
        k=$((k + 1))
        eval "kind=\$input_$k"
        case "$kind" in
          HOME | XDG_STATE_HOME | XDG_RUNTIME_DIR)
            eval "kvalue=\$configured_$k"
            kreal="$(leads_to "$kvalue")"
            kreal="${kreal%?x}"
            if is_within "$kreal" "$resolved"; then
              refuse "$real leads to $resolved, which is or holds $kind"
            fi
            if [ "$kind" = HOME ]; then
              for under in .local/state .cache; do
                base="$(leads_to "$kreal/$under")"
                base="${base%?x}"
                if is_within "$base" "$resolved"; then
                  refuse "$real leads to $resolved, which is or holds $base"
                fi
              done
            fi
            ;;
        esac
      done
      identity="$(stat -c %d:%i "$resolved")"
      device="${identity%%:*}"
      [ "$device" = "$image_device" ] ||
        refuse "$real leads to $resolved, which is on storage this image does not carry and may be shared with the distribution this one was copied from"
      # The whole tree, not only its top: a directory inside it can mount storage of its own, and
      # a removal that walked into one would take something this image does not carry with it.
      #
      # One walk writes two listings in the same order: the device of each entry on a line of its
      # own, which holds only digits, and the name of each entry ended by a NUL byte, which no
      # name can hold. A name can hold a newline, so a listing that ended each name with one would
      # read the rest of such a name as an entry of its own. The devices decide; a name only says
      # which entry it was. grep exits 1 when every entry is on this device, and anything above
      # that is a listing it could not read, which stops the run rather than passing as no
      # crossing.
      find "$resolved" -xdev -fprintf "$probe/devices" "%D\n" -fprintf "$probe/names" "%p\0"
      grep -n -v -x -F -e "$device" "$probe/devices" >"$probe/elsewhere" || [ "$?" -eq 1 ]
      first="$(head -n 1 "$probe/elsewhere" | cut -d: -f1)"
      if [ -n "$first" ]; then
        crossing="$(head -z -n "$first" "$probe/names" | tail -z -n 1 | tr -d "\000"; printf x)"
        crossing="${crossing%x}"
        refuse "$real holds $crossing, which is on storage this image does not carry and may be shared with the distribution this one was copied from"
      fi
      count=$((count + 1))
      eval "real_$count=\$real"
      eval "resolved_$count=\$resolved"
      eval "identity_$count=\$identity"
    done
    # Nothing has been removed until here.
    n=0
    identity=""
    while [ "$n" -lt "$count" ]; do
      n=$((n + 1))
      eval "real=\$real_$n"
      eval "resolved=\$resolved_$n"
      eval "identity=\$identity_$n"
      # A root inside the one before it was taken with it.
      [ -e "$resolved" ] || continue
      # Still the directory that was measured, on the device and at the inode it had then: one put
      # in its place since, or storage mounted on it, was never checked, and the removal below
      # stays on the filesystem it starts on.
      [ "$(stat -c %d:%i "$resolved")" = "$identity" ] ||
        refuse "$real is no longer the directory that was measured, so it is left"
      find "$resolved" -xdev -depth -delete
      say "  removed the inherited $real"
    done
'

# The path of every Unix socket a process holds open, one to a line, with the process identifier as
# its argument: each descriptor that names a socket is looked up by its number in the kernel's table
# of them, which also holds the path the socket was bound to. A socket with no path is not listed.
# shellcheck disable=SC2016  # read by the shell inside the distribution, which is the point
open_socket_paths='for fd in /proc/$1/fd/*; do
    target="$(readlink "$fd")" || continue
    case "$target" in
      "socket:["*"]")
        inode="${target#socket:[}"
        inode="${inode%]}"
        while read -r _ _ _ _ _ _ number path; do
          [ "$number" = "$inode" ] && [ -n "$path" ] && echo "$path"
        done </proc/net/unix
        ;;
    esac
  done'

# One session's row in a compacted `kr --json list --include-closed` document, when that row says
# the session is closed and how, and nothing, with a failure, otherwise. A document is canonical,
# so a row begins with its first key, `attachments`; the row is the one that carries the session's
# identity, which no other row does (its own closure carries it too), and a row that is not closed
# cannot be answered for by another that is.
closed_row_in() {
  local rows="${1#*\"sessions\":\[}" session="$2" row
  [ "$rows" != "$1" ] || return 1
  while [ -n "$rows" ]; do
    row="${rows%%\},\{\"attachments\":*}"
    case "$row" in
      *'"session_id":"'"$session"'"'*)
        case "$row" in *'"state":"closed"'*) : ;; *) return 1 ;; esac
        case "$row" in *'"closure":{'*) : ;; *) return 1 ;; esac
        printf '%s' "$row"
        return 0
        ;;
    esac
    [ "$row" != "$rows" ] || break
    rows="${rows#"$row"}"
    rows="${rows#\},\{\"attachments\":}"
  done
  return 1
}

# The closure record in a compacted document, whole: the object that follows `"closure":`, closed
# where its braces close, with a brace inside a string left alone. Two documents that were given
# the same record carry the same text here.
closure_text() {
  awk '
    {
      start = index($0, "\"closure\":{")
      if (start == 0) { exit 1 }
      start += 10
      depth = 0; quoted = 0; escaped = 0
      for (at = start; at <= length($0); at++) {
        c = substr($0, at, 1)
        if (quoted) {
          if (escaped) { escaped = 0 }
          else if (c == "\\") { escaped = 1 }
          else if (c == "\"") { quoted = 0 }
        } else if (c == "\"") { quoted = 1 }
        else if (c == "{") { depth++ }
        else if (c == "}") {
          depth--
          if (depth == 0) { print substr($0, start, at - start + 1); exit 0 }
        }
      }
      exit 1
    }'
}

# The self-test runs the program above on this host, against trees of its own, and checks what it
# removed and what it left. A stand-in answers for the installed helper: it names the roots the way
# the product names them on Linux and publishes an identity the way a first use does. Every root a
# case configures lies inside that case's own tree, and the program is given no other environment.
# The program removes nothing but a configured root, or a plain path below one, so nothing outside
# the tree can be removed.
self_test_work=""
self_test_passed=0
self_test_failed=0
self_test_not_run=0

self_test_cleanup() {
  if [ -n "$self_test_work" ]; then
    rm -rf "${self_test_work:?}"
  fi
}

# Runs the removal for one case, from the case's own directory, with the image and the probe
# directory it names and the environment it gives. TMPDIR names the probe directory too, so
# whatever the helper or a tool makes in a temporary directory stays in the case's tree, and a path
# that is not absolute can only lead into it.
self_test_reset() {
  local directory="$1" image="$2" parent="$3"
  shift 3
  mkdir -p "$directory" "$parent" &&
    (cd "$directory" && env -i PATH="$PATH" TMPDIR="$parent" "$@" \
      /bin/sh -c "$inherited_reset" sh "$self_test_work/helper" "$image" "$parent") \
      >"$directory/said" 2>&1
}

# An ordinary installation, found through HOME and XDG_RUNTIME_DIR, is removed whole, and what lies
# beside it is left.
self_test_ordinary_tree() {
  local d="$self_test_work/${FUNCNAME[0]}"
  local state="$d/home/.local/state/kalareach"
  mkdir -p "$state/sessions" "$d/home/.local/state/beside" "$d/run/kalareach" || return 1
  printf x >"$state/registry" || return 1
  printf x >"$state/sessions/one" || return 1
  printf x >"$d/home/.local/state/beside/kept" || return 1
  printf x >"$d/run/kalareach/account-token" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" HOME="$d/home" XDG_RUNTIME_DIR="$d/run" ||
    return 1
  [ ! -e "$state" ] && [ ! -e "$d/run/kalareach" ] && [ -f "$d/home/.local/state/beside/kept" ]
}

# Where WSLg puts the runtime directory in what it shares between distributions, the product keeps
# its runtime files below the home directory, and that is what is removed. The shared directory is
# left whatever it holds.
self_test_shared_runtime_directory() {
  local d="$self_test_work/${FUNCNAME[0]}"
  local run="$d/home/.cache/kalareach/run"
  mkdir -p "$run/environment" "$d/home/.cache/beside" || return 1
  printf x >"$run/environment/socket" || return 1
  printf x >"$d/home/.cache/beside/kept" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" HOME="$d/home" \
    XDG_RUNTIME_DIR=/mnt/wslg/runtime-dir || return 1
  [ ! -e "$run" ] && [ -f "$d/home/.cache/beside/kept" ]
}

# A name that holds a newline is one entry of the tree like any other, and the tree is removed.
self_test_newline_name() {
  local d="$self_test_work/${FUNCNAME[0]}"
  local state="$d/home/.local/state/kalareach"
  local inner=$'sessions\nsecond line'
  mkdir -p "$state/$inner" || return 1
  printf x >"$state/$inner/one" || return 1
  printf x >"$state/"$'journal\ncontinued' || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" HOME="$d/home" KR_RUNTIME_DIR="$d/run" ||
    return 1
  [ ! -e "$state" ]
}

# An ordinary configured root is removed, and the directory beside it is left.
self_test_ordinary_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/state/sessions" "$d/state-beside" || return 1
  printf x >"$d/state/sessions/one" || return 1
  printf x >"$d/state-beside/kept" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_STATE_DIR="$d/state" KR_RUNTIME_DIR="$d/run" || return 1
  [ ! -e "$d/state" ] && [ -f "$d/state-beside/kept" ]
}

# A configured root whose own name ends in a newline is removed under that name, and the directory
# whose name is the same without the newline, which is somebody else's, is left.
self_test_newline_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  local root="$d/state"$'\n'
  mkdir -p "$root/sessions" "$d/state" || return 1
  printf x >"$root/sessions/one" || return 1
  printf x >"$d/state/kept" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_STATE_DIR="$root" KR_RUNTIME_DIR="$d/run" || return 1
  [ ! -e "$root" ] && [ -f "$d/state/kept" ]
}

# A probe directory whose name is not a plain path is refused before anything is read back from
# under it, and nothing is removed. This one holds a newline, which a listing that ended each name
# with one would split into a name above the probe.
self_test_unplain_probe() {
  local d="$self_test_work/${FUNCNAME[0]}"
  local parent="$d/parent/name"$'\n'"999"
  local state="$d/home/.local/state/kalareach"
  mkdir -p "$parent" "$state" || return 1
  printf x >"$d/parent/kept" || return 1
  printf x >"$state/registry" || return 1
  if self_test_reset "$d" "$self_test_work" "$parent" HOME="$d/home" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "is not a plain path, so nothing is read back from under it" "$d/said" &&
    [ -f "$d/parent/kept" ] && [ -f "$state/registry" ]
}

# A root the helper names outside every directory the run mirrored is refused, and nothing there is
# removed. Every root the product derives on Linux lies inside one of them, so a root outside them
# is one this run cannot tell belongs to the copy.
self_test_unmirrored_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/outside/run" || return 1
  printf x >"$d/outside/run/kept" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" STAND_IN_RUNTIME_ROOT="$d/outside/run"; then
    return 1
  fi
  grep -q -F -e "which is outside every directory this run mirrored" "$d/said" &&
    [ -f "$d/outside/run/kept" ]
}

# A root that is the whole of HOME is refused, and nothing in HOME is removed. The product keeps its
# roots below a home directory, so removing the home itself would take everything else with it. The
# runtime root beside it is an ordinary one that exists, and it is left alone too: both roots are
# measured before either is removed, so a refusal for one removes nothing for the other.
self_test_whole_home() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home" "$d/run" || return 1
  printf x >"$d/home/kept" || return 1
  printf x >"$d/run/kept" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_RUNTIME_DIR="$d/run" STAND_IN_STATE_IN_HOME=1; then
    return 1
  fi
  grep -q -F -e "which is not in a directory named kalareach below HOME" "$d/said" &&
    [ -f "$d/home/kept" ] && [ -f "$d/run/kept" ]
}

# An input that is not an absolute path is refused, and nothing is removed. Read from where the
# removal runs, the path would lead into a directory the product was never configured to use.
self_test_relative_input() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state/kalareach" || return 1
  printf x >"$d/home/.local/state/kalareach/registry" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" HOME=home KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "HOME holds home, which is not an absolute path" "$d/said" &&
    [ -f "$d/home/.local/state/kalareach/registry" ]
}

# A root that is the image itself is refused, and nothing is removed. This case has an image of its
# own, so that the removal it must not make would take nothing but this case with it.
self_test_image_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/image/sessions" || return 1
  printf x >"$d/image/sessions/one" || return 1
  if self_test_reset "$d" "$d/image" "$d/tmp" KR_STATE_DIR="$d/image" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "which is the image itself or holds it" "$d/said" &&
    [ -f "$d/image/sessions/one" ]
}

# A root below HOME that is not in a directory named kalareach is refused, and what shares the
# directory it names is left alone. The product keeps what it owns in a directory of that name.
self_test_state_outside_kalareach() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state/other" || return 1
  printf x >"$d/home/.local/state/other/kept" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_RUNTIME_DIR="$d/run" STAND_IN_STATE_BELOW=/.local/state; then
    return 1
  fi
  grep -q -F -e "which is not in a directory named kalareach below HOME" "$d/said" &&
    [ -f "$d/home/.local/state/other/kept" ]
}

# A name below a mirror that is not a plain path is refused, and nothing beside it is removed: a
# component of `..` leads out of the directory the helper named, and a backslash or a newline is
# what a document or a listing would split or escape a name with. The first goes through the path
# the helper prints for its token, the other two through the file it makes. Each is a case of its
# own, so that each is shown to depend on the rule.
self_test_unplain_root() {
  local d="$self_test_work/${FUNCNAME[1]}" variant="$1" below kept
  mkdir -p "$d/home/.local/state/kalareach" "$d/home/.cache/kalareach/run" || return 1
  case "$variant" in
    dotdot)
      kept="$d/home/.cache/other/kept"
      mkdir -p "${kept%/*}" || return 1
      printf x >"$kept" || return 1
      self_test_reset "$d" "$self_test_work" "$d/tmp" \
        HOME="$d/home" KR_STATE_DIR="$d/state" \
        STAND_IN_RUNTIME_BELOW=/.cache/kalareach/run/../.. && return 1
      ;;
    backslash | newline)
      if [ "$variant" = backslash ]; then
        below='/.local/state/kalareach/od\d'
      else
        below=$'/.local/state/kalareach/od\nd'
      fi
      kept="$d/home$below/kept"
      mkdir -p "${kept%/*}" || return 1
      printf x >"$kept" || return 1
      self_test_reset "$d" "$self_test_work" "$d/tmp" \
        HOME="$d/home" KR_RUNTIME_DIR="$d/run" STAND_IN_STATE_BELOW="$below" && return 1
      ;;
  esac
  grep -q -F -e "is not a plain path" "$d/said" && [ -f "$kept" ]
}
self_test_unplain_dotdot() { self_test_unplain_root dotdot; }
self_test_unplain_backslash() { self_test_unplain_root backslash; }
self_test_unplain_newline() { self_test_unplain_root newline; }

# A root that is a link to the home directory is refused, because what it leads to is the home,
# which holds much that is not the product's, and nothing in the home is removed.
self_test_link_to_home() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state" || return 1
  printf x >"$d/home/kept" || return 1
  ln -s "$d/home" "$d/home/.local/state/kalareach" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" HOME="$d/home" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "which is or holds HOME" "$d/said" && [ -f "$d/home/kept" ]
}

# An input that is set but empty is refused, and nothing is removed. The product reads it as a
# relative path, which leads wherever the directory the program runs in leads.
self_test_empty_input() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state/kalareach" || return 1
  printf x >"$d/home/.local/state/kalareach/registry" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" XDG_RUNTIME_DIR= KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "XDG_RUNTIME_DIR is set but empty" "$d/said" &&
    [ -f "$d/home/.local/state/kalareach/registry" ]
}

# A root inside the other one is taken with it, and the removal that follows finds nothing left of
# it and goes on. What lies beside them is left.
self_test_nested_roots() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/x/kalareach/state/sessions" "$d/x/beside" || return 1
  printf x >"$d/x/kalareach/state/sessions/one" || return 1
  printf x >"$d/x/kalareach/other" || return 1
  printf x >"$d/x/beside/kept" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" \
    XDG_RUNTIME_DIR="$d/x" KR_STATE_DIR="$d/x/kalareach/state" || return 1
  [ ! -e "$d/x/kalareach" ] && [ -f "$d/x/beside/kept" ]
}

# Puts a wrapper for find first on the path of one case. The first time find is asked to walk the
# state root, which is after the runtime root was measured, the wrapper runs the action it is given,
# and then find goes on as it was asked. The action is what happens to the runtime root meanwhile.
self_test_find_wrapper() {
  local d="$1" action="$2" real_find
  real_find="$(command -v find)" || return 1
  mkdir -p "$d/bin" || return 1
  cat >"$d/bin/find" <<WRAPPER || return 1
#!/bin/sh
if [ "\$1" = "$d/state" ] && [ ! -e "$d/bin/fired" ]; then
  : >"$d/bin/fired"
  $action
fi
exec "$real_find" "\$@"
WRAPPER
  chmod 0755 "$d/bin/find"
}

# A root that was not there when it was measured is not removed if it appears before the removal:
# it never passed the checks a root passes.
self_test_late_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/state/sessions" || return 1
  printf x >"$d/state/sessions/one" || return 1
  self_test_find_wrapper "$d" "mkdir -p \"$d/run\" && printf x >\"$d/run/kept\"" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" \
    PATH="$d/bin:$PATH" HOME="$d/home" KR_STATE_DIR="$d/state" KR_RUNTIME_DIR="$d/run" ||
    return 1
  [ ! -e "$d/state" ] && [ -f "$d/run/kept" ]
}

# A root that is another directory when the removal comes to it than it was when it was measured is
# left, and so is the root measured after it: this one is put in its place while the state root is
# being walked, the way a link put in place of one of its parents would lead somewhere else.
self_test_swapped_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/state/sessions" "$d/run" || return 1
  printf x >"$d/state/sessions/one" || return 1
  printf x >"$d/run/inherited" || return 1
  self_test_find_wrapper "$d" \
    "mv \"$d/run\" \"$d/run.moved\" && mkdir \"$d/run\" && printf x >\"$d/run/kept\"" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    PATH="$d/bin:$PATH" HOME="$d/home" KR_STATE_DIR="$d/state" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "is no longer the directory that was measured" "$d/said" &&
    [ -f "$d/run/kept" ] && [ -f "$d/state/sessions/one" ]
}

# A root that is a link to the directory the product falls back to for its state in the home, or
# that is that directory, is refused: it holds what other programs keep there as well.
self_test_link_to_state_base() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state/other" || return 1
  printf x >"$d/home/.local/state/other/kept" || return 1
  ln -s "$d/home/.local/state" "$d/home/.local/state/kalareach" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" HOME="$d/home" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e ".local/state" "$d/said" && grep -q -F -e "which is or holds" "$d/said" &&
    [ -f "$d/home/.local/state/other/kept" ]
}

self_test_state_base_input() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/home/.local/state/other" || return 1
  printf x >"$d/home/.local/state/other/kept" || return 1
  if self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_STATE_DIR="$d/home/.local/state" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "which is or holds" "$d/said" && [ -f "$d/home/.local/state/other/kept" ]
}

# A root that is a link is resolved: what it leads to is removed, and the link is left.
self_test_link_root() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d/elsewhere/state/sessions" || return 1
  printf x >"$d/elsewhere/state/sessions/one" || return 1
  ln -s "$d/elsewhere/state" "$d/state" || return 1
  self_test_reset "$d" "$self_test_work" "$d/tmp" \
    HOME="$d/home" KR_STATE_DIR="$d/state" KR_RUNTIME_DIR="$d/run" || return 1
  [ ! -e "$d/elsewhere/state" ] && [ -L "$d/state" ]
}

# A root on storage the image does not carry is refused, and nothing is removed. The image handed
# to the removal is a directory on another filesystem than the tree, which is what a root that
# leads out of the image looks like from inside it.
self_test_other_storage() {
  local d="$self_test_work/${FUNCNAME[0]}" other="" candidate
  local state="$d/home/.local/state/kalareach"
  for candidate in /proc /sys /dev /run; do
    if [ -d "$candidate" ] &&
      [ "$(stat -c %d "$candidate")" != "$(stat -c %d "$self_test_work")" ]; then
      other="$candidate"
      break
    fi
  done
  if [ -z "$other" ]; then
    echo "  this host has no directory on another filesystem than $self_test_work"
    return 1
  fi
  mkdir -p "$state" || return 1
  printf x >"$state/registry" || return 1
  if self_test_reset "$d" "$other" "$d/tmp" HOME="$d/home" KR_RUNTIME_DIR="$d/run"; then
    return 1
  fi
  grep -q -F -e "leads to $state, which is on storage this image does not carry" "$d/said" &&
    [ -f "$state/registry" ]
}

# A directory mounted inside a root is refused before anything is removed. Only a mount of the
# case's own shows it, so the case runs where this host lets it make one in a namespace of its own,
# as root or through a user namespace; the mount goes with the namespace. Where it cannot, the case
# says so rather than passing.
self_test_mount_inside() {
  local d="$self_test_work/${FUNCNAME[0]}" status=0
  local state="$d/home/.local/state/kalareach"
  local -a enter=(unshare --mount --propagation private)
  if [ "$(id -u)" != 0 ]; then
    enter=(unshare --user --map-root-user --mount --propagation private)
  fi
  if ! "${enter[@]}" /bin/true >/dev/null 2>&1; then
    echo "  this host refuses a mount namespace of the case's own: ${enter[*]}"
    return 77
  fi
  mkdir -p "$state/mounted" "$d/tmp" || return 1
  printf x >"$state/registry" || return 1
  # shellcheck disable=SC2016  # the script runs in the namespace, with the arguments after it
  "${enter[@]}" /bin/sh -c 'mount -t tmpfs kr-self-test "$1" && : >"$1/on-other-storage" || exit 90
      shift
      exec "$@"' sh "$state/mounted" \
    env -i PATH="$PATH" TMPDIR="$d/tmp" HOME="$d/home" KR_RUNTIME_DIR="$d/run" \
    /bin/sh -c "$inherited_reset" sh "$self_test_work/helper" "$self_test_work" "$d/tmp" \
    >"$d/said" 2>&1 || status=$?
  if [ "$status" = 90 ]; then
    echo "  the mount could not be made: $(cat "$d/said")"
    return 77
  fi
  [ "$status" != 0 ] &&
    grep -q -F -e "holds $state/mounted, which is on storage this image does not carry" "$d/said" &&
    [ -f "$state/registry" ]
}

# The sockets a process holds are listed by their paths: one bound to a path is named, and the
# listing of a process that holds none is empty.
self_test_open_sockets() {
  local d="$self_test_work/${FUNCNAME[0]}" holder listed
  command -v python3 >/dev/null 2>&1 || {
    echo "  this host has no python3 to hold a socket open with"
    return 77
  }
  mkdir -p "$d" || return 1
  python3 -c 'import socket, sys, time
s = socket.socket(socket.AF_UNIX)
s.bind(sys.argv[1])
s.listen()
time.sleep(60)' "$d/held.sock" >"$d/said" 2>&1 &
  holder=$!
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    [ -S "$d/held.sock" ] && break
    sleep 0.25
  done
  listed="$(/bin/sh -c "$open_socket_paths" sh "$holder" 2>>"$d/said")"
  kill "$holder" 2>/dev/null || true
  wait "$holder" 2>/dev/null || true
  [ "$listed" = "$d/held.sock" ] || {
    echo "  the listing was: $listed" >>"$d/said"
    return 1
  }
  # A process that holds no socket lists none.
  sleep 30 &
  holder=$!
  listed="$(/bin/sh -c "$open_socket_paths" sh "$holder" 2>>"$d/said")"
  kill "$holder" 2>/dev/null || true
  wait "$holder" 2>/dev/null || true
  [ -z "$listed" ]
}

# A compacted listing of five sessions: one live, one closed with a closure whose process name holds
# braces, one that is closing and has no closure yet, one marked closed that says nothing of how, and
# one that carries a closure and is not marked closed.
self_test_listing='{"sessions":[{"attachments":0,"closure":null,"created_at_ms":1,"session_id":"live-1","state":"running"},{"attachments":0,"closure":{"closed_at_ms":99,"reason":"close_requested","session_id":"gone-2","terminated":[{"name":"a{brace}\"shell","pid":7}]},"created_at_ms":2,"session_id":"gone-2","state":"closed"},{"attachments":1,"closure":null,"created_at_ms":3,"session_id":"closing-3","state":"closing"},{"attachments":0,"closure":null,"created_at_ms":4,"session_id":"unsaid-4","state":"closed"},{"attachments":0,"closure":{"closed_at_ms":5,"session_id":"odd-5"},"created_at_ms":5,"session_id":"odd-5","state":"running"}]}'

# The row of a session that closed is found, and it is that session's alone.
self_test_closed_row() {
  local row
  row="$(closed_row_in "$self_test_listing" gone-2)" || return 1
  case "$row" in
    *'"session_id":"gone-2","state":"closed"'*) : ;;
    *) return 1 ;;
  esac
  case "$row" in
    *live-1* | *closing-3* | *unsaid-4* | *odd-5*) return 1 ;;
  esac
}

# A session that has not been recorded as closed, and how, has no closed row, whatever else the
# listing holds: a closed row beside it is no answer for it, and neither is a session the listing
# does not name.
self_test_open_row() {
  local d="$self_test_work/${FUNCNAME[0]}"
  mkdir -p "$d" || return 1
  if closed_row_in "$self_test_listing" closing-3 >"$d/said" 2>&1; then return 1; fi
  if closed_row_in "$self_test_listing" live-1 >>"$d/said" 2>&1; then return 1; fi
  if closed_row_in "$self_test_listing" unsaid-4 >>"$d/said" 2>&1; then return 1; fi
  if closed_row_in "$self_test_listing" odd-5 >>"$d/said" 2>&1; then return 1; fi
  if closed_row_in "$self_test_listing" absent-6 >>"$d/said" 2>&1; then return 1; fi
  if closed_row_in '{"sessions":[]}' gone-2 >>"$d/said" 2>&1; then return 1; fi
  if closed_row_in 'not a listing' gone-2 >>"$d/said" 2>&1; then return 1; fi
}

# The closure of a row and the closure in a refusal are the same text when they are the same record,
# a brace inside a string does not end it, and a record made at another time is another text.
self_test_closure_text() {
  local row from_row refusal from_refusal other
  row="$(closed_row_in "$self_test_listing" gone-2)" || return 1
  from_row="$(printf '%s' "$row" | closure_text)" || return 1
  [ "$from_row" = '{"closed_at_ms":99,"reason":"close_requested","session_id":"gone-2","terminated":[{"name":"a{brace}\"shell","pid":7}]}' ] || return 1
  refusal='{"closure":{"closed_at_ms":99,"reason":"close_requested","session_id":"gone-2","terminated":[{"name":"a{brace}\"shell","pid":7}]},"code":"SESSION_CLOSED","ok":false}'
  from_refusal="$(printf '%s' "$refusal" | closure_text)" || return 1
  [ "$from_row" = "$from_refusal" ] || return 1
  other="$(printf '%s' "${refusal/99/100}" | closure_text)" || return 1
  [ "$other" != "$from_row" ] || return 1
  # A document with no closure has none to compare.
  if printf '%s' '{"closure":null,"code":"SESSION_CLOSED"}' | closure_text >/dev/null 2>&1; then
    return 1
  fi
}

# Runs one case and says how it ended. A case that fails shows what the removal said.
self_test_case() {
  local status=0
  "$1" || status=$?
  case "$status" in
    0)
      self_test_passed=$((self_test_passed + 1))
      echo "self-test: ok: $2"
      ;;
    77)
      self_test_not_run=$((self_test_not_run + 1))
      echo "self-test: not run here: $2"
      ;;
    *)
      self_test_failed=$((self_test_failed + 1))
      echo "self-test: FAILED: $2"
      if [ -f "$self_test_work/$1/said" ]; then
        sed 's/^/    /' "$self_test_work/$1/said"
      fi
      ;;
  esac
}

self_test() {
  if [ "$(uname -s)" != Linux ]; then
    echo "self-test: the removal runs inside a Linux distribution, so its self-test runs on Linux" >&2
    return 2
  fi
  self_test_work="$(mktemp -d "${TMPDIR:-/tmp}/kr-wsl-self-test.XXXXXX")" || return 2
  trap self_test_cleanup EXIT
  # Each case makes its probe below this directory, and the removal refuses a probe directory whose
  # name is not a plain path, so every case would fail for that one reason.
  case "$self_test_work" in
    *[!A-Za-z0-9._/-]*)
      echo "self-test: $self_test_work is not a plain path; set TMPDIR to a directory that is" >&2
      return 2
      ;;
  esac
  cat >"$self_test_work/helper" <<'STAND_IN' || return 2
#!/bin/sh
# Stands in for the installed helper. It names the roots the way the product names them on Linux,
# says where it reads an account token, and publishes an identity the way a first use does. A case
# can give it a runtime root of its own, as a product that read one from somewhere else would, name
# a root below the home directory, or have it keep its state in the home directory itself.
if [ -n "${STAND_IN_RUNTIME_ROOT-}" ]; then
  runtime="$STAND_IN_RUNTIME_ROOT"
elif [ -n "${STAND_IN_RUNTIME_BELOW-}" ]; then
  runtime="$HOME$STAND_IN_RUNTIME_BELOW"
elif [ -n "${KR_RUNTIME_DIR-}" ]; then
  runtime="$KR_RUNTIME_DIR"
elif [ -n "${XDG_RUNTIME_DIR-}" ]; then
  runtime="$XDG_RUNTIME_DIR/kalareach"
else
  runtime="$HOME/.cache/kalareach/run"
fi
if [ -n "${STAND_IN_STATE_IN_HOME-}" ]; then
  state="$HOME"
elif [ -n "${STAND_IN_STATE_BELOW-}" ]; then
  state="$HOME$STAND_IN_STATE_BELOW"
elif [ -n "${KR_STATE_DIR-}" ]; then
  state="$KR_STATE_DIR"
elif [ -n "${XDG_STATE_HOME-}" ]; then
  state="$XDG_STATE_HOME/kalareach"
else
  state="$HOME/.local/state/kalareach"
fi
case "$*" in
  "--json account token show")
    printf '{\n  "ok": true,\n  "path": "%s/account-token",\n  "imported": false\n}\n' "$runtime"
    ;;
  list)
    mkdir -p "$state" && printf 'environment\n' >"$state/environment-id"
    echo "no control daemon is running" >&2
    exit 1
    ;;
  *)
    echo "the stand-in helper has no answer for: $*" >&2
    exit 2
    ;;
esac
STAND_IN
  chmod 0755 "$self_test_work/helper" || return 2

  self_test_case self_test_ordinary_tree \
    "an ordinary installation is removed whole, and what lies beside it is left"
  self_test_case self_test_shared_runtime_directory \
    "where the runtime directory is the one WSLg shares, the root below the home directory is removed"
  self_test_case self_test_newline_name \
    "a name that holds a newline is one entry of the tree, and the tree is removed"
  self_test_case self_test_ordinary_root \
    "an ordinary configured root is removed, and the directory beside it is left"
  self_test_case self_test_newline_root \
    "a configured root whose name ends in a newline is removed, and the name without it is left"
  self_test_case self_test_unplain_probe \
    "a probe directory whose name is not a plain path is refused, and nothing is removed"
  self_test_case self_test_unmirrored_root \
    "a root named outside every mirrored directory is refused, and nothing is removed"
  self_test_case self_test_whole_home \
    "a root that is the whole of HOME is refused, and a refusal for one root removes nothing for the other"
  self_test_case self_test_relative_input \
    "an input that is not an absolute path is refused, and nothing is removed"
  self_test_case self_test_image_root \
    "a root that is the image itself is refused, and nothing is removed"
  self_test_case self_test_state_outside_kalareach \
    "a root below HOME outside a directory named kalareach is refused, and what shares it is left"
  self_test_case self_test_unplain_dotdot \
    "a name below a mirror with a parent component is refused, and what lies beside it is left"
  self_test_case self_test_unplain_backslash \
    "a name below a mirror with a backslash is refused, and what lies beside it is left"
  self_test_case self_test_unplain_newline \
    "a name below a mirror with a newline is refused, and what lies beside it is left"
  self_test_case self_test_link_to_home \
    "a root that is a link to the home directory is refused, and nothing in the home is removed"
  self_test_case self_test_empty_input \
    "an input that is set but empty is refused, and nothing is removed"
  self_test_case self_test_nested_roots \
    "a root inside the other is taken with it, and the removal that follows goes on"
  self_test_case self_test_late_root \
    "a root that appears after it was measured is not removed"
  self_test_case self_test_swapped_root \
    "a root that is another directory when the removal comes to it is left, with the other root"
  self_test_case self_test_link_to_state_base \
    "a root that is a link to the home's state directory is refused, and what shares it is left"
  self_test_case self_test_state_base_input \
    "a root that is the home's state directory is refused, and what shares it is left"
  self_test_case self_test_link_root \
    "a root that is a link is resolved, and what it leads to is removed"
  self_test_case self_test_other_storage \
    "a root on storage the image does not carry is refused, and nothing is removed"
  self_test_case self_test_mount_inside \
    "a directory mounted inside a root is refused before anything is removed"
  self_test_case self_test_open_sockets \
    "the sockets a process holds are listed by the paths they were bound to"
  self_test_case self_test_closed_row \
    "a session that closed has its own closed row found in a listing"
  self_test_case self_test_open_row \
    "a session not recorded as closed has no closed row, whatever else the listing holds"
  self_test_case self_test_closure_text \
    "a closure is the same text in a row and in a refusal, and another record is another text"

  echo "self-test: $self_test_passed passed, $self_test_failed failed, $self_test_not_run not run here"
  [ "$self_test_failed" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then
  status=0
  self_test || status=$?
  exit "$status"
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts"
run_stamp="$(date -u '+%Y%m%dT%H%M%SZ')"
run_dir="$artifacts/wsl-$run_stamp"
mkdir -p "$run_dir"
helper_path="${KR_WSL_HELPER:-/usr/local/bin/kr}"
# The bridge suite this acceptance installs beside the helper and runs in step 7, and the manifest
# that binds the whole installed set to the commit it was built from. Both are this acceptance's
# own artefacts rather than programs the product installs, so they live together outside the path.
suite_path=/usr/local/lib/kalareach-acc-bridge-suite
manifest_path=/usr/local/lib/kalareach-acc-commit
# The same set of paths relative to the root, which is the form the manifest carries so that both
# writing it and checking it work from one directory.
helper_relative="${helper_path#/}"
suite_relative="${suite_path#/}"
linux_user="${KR_WSL_USER:-root}"
second_name="${KR_WSL_SECOND:-kr-acc-011}"
wsl_root="${KR_WSL_ROOT:-/c/kala/wsl}"
keep="${KR_WSL_KEEP:-0}"
network_modes="${KR_WSL_NETWORK_MODES:-nat mirrored}"
for mode in $network_modes; do
  case "$mode" in
    nat | mirrored) ;;
    *) echo "FAIL: KR_WSL_NETWORK_MODES names $mode, which is not a mode this run measures: nat or mirrored" >&2; exit 1 ;;
  esac
done

# MSYS2 rewrites an argument that looks like a POSIX path before it hands it to a native program,
# which is wrong for every argument here: `/bin/sh` is a path inside the distribution, not on this
# host, and so is the helper this run enrols. Every path that a native program should read as a
# Windows path is converted below, by name, so nothing is left for a heuristic to guess at.
export MSYS2_ARG_CONV_EXCL='*'
export MSYS_NO_PATHCONV=1

# The Windows form of a path in this shell. Every native program below is handed one of these: this
# shell's own form means nothing to them.
windows_path() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }

passed=0
fail() {
  # Standard error, so that a check inside a command substitution still says what went wrong
  # rather than handing its message to the variable being assigned.
  echo "FAIL: $*" >&2
  exit 1
}
pass() {
  passed=$((passed + 1))
  echo "PASS: $*"
}
step() { echo; echo "==> $*"; }

echo "kalareach wsl2 acceptance (KR-ACC-011)"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  artefacts: $artifacts"

# What this run made, and therefore what it may remove or end. Nothing else is touched: every
# process ended below is one this script started and recorded.
made_distribution=""
made_directory=""
wslconfig_path=""
wslconfig_saved=""
wslconfig_existed=0
daemons=""
windows_daemon=""

cleanup() {
  local status=$?
  if [ -n "$windows_daemon" ]; then
    kill "$windows_daemon" 2>/dev/null || true
  fi
  if [ "$keep" != "1" ]; then
    for distribution in $daemons; do
      # The identifier this script recorded when it started that daemon, and no pattern. The
      # substitution below runs inside the distribution, which is why it stays unexpanded here.
      # shellcheck disable=SC2016
      wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
        'test -f /tmp/kr-acc-controller.pid && kill $(cat /tmp/kr-acc-controller.pid)' \
        >/dev/null 2>&1 || true
    done
    if [ -n "$made_distribution" ]; then
      echo "removing the distribution this run made: $made_distribution"
      wsl.exe --unregister "$made_distribution" >/dev/null 2>&1 || true
    fi
    # The image directory this run made, by the name this run gave it. Nothing else here is
    # this run's to remove.
    if [ -n "$made_directory" ] && [ -d "$made_directory" ]; then
      rm -rf "${made_directory:?}"
    fi
  fi
  # The networking mode is the operator's setting. It goes back exactly as it was.
  if [ -n "$wslconfig_saved" ] && [ -n "$wslconfig_path" ]; then
    if [ "$wslconfig_existed" = "1" ]; then
      cp "$wslconfig_saved" "$wslconfig_path"
    else
      rm -f "${wslconfig_path:?}"
    fi
    wsl.exe --shutdown >/dev/null 2>&1 || true
  fi
  echo "evidence kept under $run_dir"
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------
step "1. WSL 2, and the distributions this acceptance needs"

command -v wsl.exe >/dev/null 2>&1 ||
  fail "this acceptance runs on a Windows host with WSL2; wsl.exe is not on this machine"

# wsl.exe writes UTF-16LE. Dropping the null bytes is enough to read it as text here.
wsl_text() { wsl.exe "$@" 2>&1 | tr -d '\000\r'; }

version_text="$(wsl_text --version)"
echo "$version_text"
echo "$version_text" | grep -qi "WSL version" ||
  fail "wsl.exe --version did not report a WSL version; this needs WSL 2 from the Microsoft installer"

wsl_text --set-default-version 2 >/dev/null ||
  fail "the default WSL version could not be set to 2"

registered() { wsl_text -l -q | sed 's/[[:space:]]*$//' | grep -v '^$'; }
state_of() {
  # The state column of `wsl -l -v` for one distribution, matched on the whole name.
  wsl_text -l -v | sed 's/^[* ]*//' |
    awk -v want="$1" '{
      name = $0
      sub(/[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/, "", name)
      if (name == want) { print $(NF - 1) }
    }'
}
version_of() {
  # The version column of the same listing. Setting the default version converts nothing that is
  # already registered, so a distribution this acceptance selected has to say for itself.
  wsl_text -l -v | sed 's/^[* ]*//' |
    awk -v want="$1" '{
      name = $0
      sub(/[[:space:]]+[^[:space:]]+[[:space:]]+[0-9]+[[:space:]]*$/, "", name)
      if (name == want) { print $NF }
    }'
}

mapfile -t distributions < <(registered)
[ "${#distributions[@]}" -gt 0 ] ||
  fail "no WSL distribution is registered; install one before running this acceptance"
first="${distributions[0]}"
echo "registered: ${distributions[*]}"

if [ "${#distributions[@]}" -lt 2 ]; then
  echo "only one distribution is registered; making a second from it"
  tarball="$run_dir/$first.tar"
  # What wsl.exe said is kept, because a run that could not make its second distribution has to say
  # why rather than only that it could not.
  wsl.exe --export "$first" "$(windows_path "$tarball")" >"$run_dir/export.log" 2>&1 ||
    fail "$first could not be exported to make a second distribution: $(cat "$run_dir/export.log")"
  [ -s "$tarball" ] ||
    fail "exporting $first produced no image: $(cat "$run_dir/export.log")"
  echo "  exported $first: $(wc -c <"$tarball") bytes"
  # The directory this script imports into is this run's own, named after the distribution it
  # makes and the moment it made it. wsl.exe wants an empty directory, and a directory that is
  # already there belongs to something else: this run neither writes into it nor removes it.
  target_dir="$wsl_root/$second_name-$run_stamp"
  mkdir -p "$wsl_root" || fail "$wsl_root could not be made"
  # `mkdir` without `-p` is the ownership: it makes this directory or it fails because something
  # is already there, and only a directory this run made is one this run may remove.
  mkdir "$target_dir" ||
    fail "the image directory $target_dir could not be made by this run, so this run has none of its own to import into"
  made_directory="$target_dir"
  wsl.exe --import "$second_name" "$(windows_path "$target_dir")" \
    "$(windows_path "$tarball")" --version 2 >"$run_dir/import.log" 2>&1 ||
    fail "$second_name could not be imported into $target_dir: $(cat "$run_dir/import.log")"
  made_distribution="$second_name"
  # The one this run made, by the name it gave it. Reading a position out of the listing again
  # would take whichever name the registry happens to put second.
  second="$second_name"
  mapfile -t distributions < <(registered)
else
  second="${distributions[1]}"
fi
[ "${#distributions[@]}" -ge 2 ] || fail "this acceptance needs two distributions"
[ "$first" != "$second" ] || fail "the two distributions this acceptance needs are the same one"
for distribution in "$first" "$second"; do
  version="$(version_of "$distribution")"
  [ "$version" = "2" ] ||
    fail "$distribution is WSL version ${version:-unknown}, and this acceptance is about WSL 2"
done
pass "two WSL 2 distributions are registered: $first and $second"

# ---------------------------------------------------------------------------------------------
step "2. Argument vectors cross --exec unchanged"

# Every one of these would be rewritten by a shell. `--exec` hands the vector to the program named
# next, so each arrives as one element.
# The values below are meant to stay literal: the point is that nothing expands them.
# shellcheck disable=SC2016
awkward_out="$(wsl.exe -d "$first" -u "$linux_user" --exec /bin/sh -c 'printf "%s\n" "$@"' -- \
  "arg 1" "arg'2" 'arg"3' 'space and $HOME and `backtick`' 'semi;colon && ampersand' | tr -d '\r')"
# shellcheck disable=SC2016
awkward_expected="$(printf 'arg 1\narg'"'"'2\narg"3\nspace and $HOME and `backtick`\nsemi;colon && ampersand')"
[ "$awkward_out" = "$awkward_expected" ] ||
  fail "an argument vector was rewritten across the WSL boundary: $awkward_out"
pass "argument vectors cross --exec exactly as they were built"

# ---------------------------------------------------------------------------------------------
step "3. Each distribution runs KalaReach on its own"

# The helper and the daemon are built inside the distribution, from the same commit, into that
# distribution's own filesystem. Nothing here is a Windows binary, and nothing crosses /mnt.
commit="$(git rev-parse HEAD)"

build_inside() {
  local distribution="$1"
  # The whole installed set, from one commit: the helper, the daemon and worker it needs, and the
  # bridge suite step 7 runs. A set from another commit, or a set only half replaced, would prove
  # something about another candidate, so the manifest names the commit and the hash of every
  # installed file, and this reads all of it. A set built elsewhere and installed here carries the
  # manifest its builder wrote, so an incomplete copy fails this rather than passing it.
  if wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -c \
    "cd / && test \"\$(head -n 1 '$manifest_path' 2>/dev/null)\" = '$commit' && tail -n +2 '$manifest_path' | awk '{ print \$2 }' | sort >/tmp/kr-acc-manifest-carries && printf '%s\n' '$helper_relative' '$(dirname "$helper_relative")/kr-controller' '$(dirname "$helper_relative")/kr-worker' '$suite_relative' | sort >/tmp/kr-acc-manifest-wanted && cmp -s /tmp/kr-acc-manifest-carries /tmp/kr-acc-manifest-wanted && tail -n +2 '$manifest_path' | sha256sum -c --quiet" 2>/dev/null; then
    echo "  $distribution: the helper at $helper_path and its bridge suite were built from this commit"
    return 0
  fi
  echo "  $distribution: building the helper inside the distribution (this takes a few minutes)"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    command -v cargo >/dev/null 2>&1 || {
      echo 'cargo is not installed in this distribution, and no helper built from this commit is installed in it' >&2
      exit 1
    }
    rm -rf /tmp/kalareach-src
    cp -a /mnt/c/kala/kalareach /tmp/kalareach-src
    cd /tmp/kalareach-src
    cargo build -p kr-cli --bin kr -p kr-controller --bin kr-controller -p kr-worker --bin kr-worker
    install -m 0755 target/debug/kr '$helper_path'
    install -m 0755 target/debug/kr-controller '$(dirname "$helper_path")/kr-controller'
    install -m 0755 target/debug/kr-worker '$(dirname "$helper_path")/kr-worker'
    # The suite is installed like the rest of the set, so step 7 runs what this distribution
    # carries rather than a source tree that has to survive beside it. cargo names the executable
    # it built for each artefact; the one wanted here is the test target, and the command line
    # above selects exactly one of those.
    suite=\"\$(cargo test -p kr-cli --test bridge --no-run --message-format=json |
      sed -n 's/.*\"kind\":\\[\"test\"\\].*\"executable\":\"\\([^\"]*\\)\".*/\\1/p' | tail -n 1)\"
    test -n \"\$suite\" || {
      echo 'the build produced no bridge suite executable' >&2
      exit 1
    }
    mkdir -p /usr/local/lib
    install -m 0755 \"\$suite\" '$suite_path'
    # The manifest is written last and covers the whole set, so a half-installed set never looks
    # like a set built from this commit.
    cd /
    { echo '$commit'
      sha256sum '$helper_relative' '$(dirname "$helper_relative")/kr-controller' \
        '$(dirname "$helper_relative")/kr-worker' '$suite_relative'
    } >'$manifest_path.partial'
    mv '$manifest_path.partial' '$manifest_path'
  " || fail "$distribution could not build the Linux helper"
}

# Gives a distribution this run imported an installation of its own: the program at the top of this
# script removes the one it inherited. Only a distribution this run imported is ever handed to this.
clear_inherited_installation() {
  local distribution="$1"
  echo "  $distribution: removing the installation it inherited from the distribution it was copied from"
  # The image of a distribution is the whole of it, so the storage it carries is the filesystem its
  # root is on. The probe is made in the distribution's own /tmp.
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "$inherited_reset" \
    sh "$helper_path" / /tmp ||
    fail "$distribution could not be given an installation of its own"
  # The leftovers this acceptance itself put in the distribution that was copied. The file it
  # writes a daemon identifier into would otherwise name a process in that other distribution.
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/rm -f \
    /tmp/kr-acc-controller.pid /tmp/kr-controller.log ||
    fail "$distribution kept what this acceptance left in the distribution it was copied from"
}

start_daemon_inside() {
  local distribution="$1"
  wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "
    set -e
    running=0
    if [ -f /tmp/kr-acc-controller.pid ] && kill -0 \$(cat /tmp/kr-acc-controller.pid) 2>/dev/null; then
      running=1
    fi
    if [ \$running -eq 0 ]; then
      nohup '$(dirname "$helper_path")/kr-controller' \
        --worker '$(dirname "$helper_path")/kr-worker' --secret-store file \
        >/tmp/kr-controller.log 2>&1 &
      echo \$! >/tmp/kr-acc-controller.pid
    fi
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      if '$helper_path' list >/dev/null 2>&1; then
        exit 0
      fi
      sleep 1
    done
    echo 'the daemon inside the distribution did not answer' >&2
    tail -n 40 /tmp/kr-controller.log >&2 || true
    exit 1
  " || fail "$distribution did not start its own control daemon"
  daemons="$daemons $distribution"
}

inside() {
  local distribution="$1"
  shift
  # The distribution's own default paths, which is what the helper the Windows side starts will
  # discover. A directory of this run's own here would leave the two halves talking past each other.
  #
  # What the command answered is held before the carriage returns are taken out of it, because a
  # pipeline would answer for the last program in it: a read that failed inside the distribution
  # has to reach the caller as a failure rather than as an empty string.
  local answer
  answer="$(wsl.exe -d "$distribution" -u "$linux_user" --exec /bin/sh -lc "$*")" || return $?
  printf '%s\n' "$answer" | tr -d '\r'
}

# One line of JSON with the spaces taken out, so an assertion can name a whole key path.
compact() { tr -d ' \n\r'; }

# The first value one named string key carries in a compacted document, or nothing. These are this
# product's own documents and the key is named in full, so the match is exact; and finding nothing
# is not a failure here, because the check that follows says what was missing.
json_string() {
  awk -v key="\"$1\":\"" '
    {
      start = index($0, key)
      if (start == 0) { exit }
      rest = substr($0, start + length(key))
      end = index(rest, "\"")
      if (end == 0) { exit }
      print substr(rest, 1, end - 1)
      exit
    }'
}

# The row of `kr list --include-closed` inside a distribution for one session, once the
# distribution's own daemon says that session is closed and how; a failure while it does not.
# Closing is asynchronous, so a distribution stopped before the record is written would test
# recovery from an interrupted close and not the retention of a completed one.
closed_row_inside() {
  local listing
  listing="$(inside "$1" "'$helper_path' --json list --include-closed" | compact)" || return 1
  closed_row_in "$listing" "$2"
}

build_inside "$first"
start_daemon_inside "$first"
build_inside "$second"
# The set is installed before the inherited installation is removed, because removing it is done by
# asking the installed helper where the product keeps it. A second distribution that was already
# registered belongs to the machine, not to this run, and is started as it is.
if [ "$made_distribution" = "$second" ]; then
  clear_inherited_installation "$second"
fi
start_daemon_inside "$second"
pass "each distribution started its own KalaReach, from its own installed set, with no native Windows installation"

# Linux paths, binaries and process identifiers stay inside the distribution. Each assertion below
# names the process it is about and reads that process's own Linux paths out of /proc.
installed_dir="$(dirname "$helper_path")"
for distribution in "$first" "$second"; do
  # The daemon: the Linux binary this run installed in this distribution, running as the Linux user
  # the enrolment names.
  daemon_pid="$(inside "$distribution" 'cat /tmp/kr-acc-controller.pid')" ||
    fail "$distribution could not be asked for the daemon this run started in it"
  [[ "$daemon_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution did not report a Linux process identifier for its daemon"
  daemon_exe="$(inside "$distribution" "readlink -f /proc/$daemon_pid/exe | head -n 1")" ||
    fail "$distribution could not be asked what its daemon $daemon_pid runs"
  [ "$daemon_exe" = "$installed_dir/kr-controller" ] ||
    fail "$distribution's daemon $daemon_pid runs $daemon_exe, not the $installed_dir/kr-controller installed in it"
  daemon_user="$(inside "$distribution" "stat -c %U /proc/$daemon_pid | head -n 1")" ||
    fail "$distribution could not be asked who its daemon $daemon_pid runs as"
  [ "$daemon_user" = "$linux_user" ] ||
    fail "$distribution's daemon runs as $daemon_user and the enrolment names $linux_user"
  daemon_root="$(inside "$distribution" "readlink /proc/$daemon_pid/root | head -n 1")" ||
    fail "$distribution could not be asked what its daemon $daemon_pid has for a root"
  [ "$daemon_root" = "/" ] ||
    fail "$distribution's daemon has root $daemon_root rather than this distribution's own"
  # The sockets it listens on are the distribution's own: none is in the directory WSLg shares
  # between every distribution of the machine, where another distribution could open it.
  daemon_sockets="$(inside "$distribution" "/bin/sh -c '$open_socket_paths' sh $daemon_pid")" ||
    fail "$distribution could not be asked what its daemon $daemon_pid listens on"
  [ -n "$daemon_sockets" ] ||
    fail "$distribution's daemon $daemon_pid holds no socket with a path, so its runtime root is not known"
  shared_sockets="$(printf '%s\n' "$daemon_sockets" | grep -c '^/mnt/wslg/')" || [ "$shared_sockets" = "0" ]
  if [ "$shared_sockets" != "0" ]; then
    fail "$distribution's daemon holds sockets in the directory WSLg shares between distributions: $(printf '%s' "$daemon_sockets" | tr '\n' ';')"
  fi
  # A session of the distribution's own, named by the identifier the create answered with.
  session="$(inside "$distribution" "'$helper_path' --json new --invisible --shell /bin/sh" | compact)" ||
    fail "$distribution could not be asked to create a session of its own"
  created="$(printf '%s' "$session" | json_string session_id)"
  [ -n "$created" ] ||
    fail "$distribution could not create a session of its own: $session"
  echo "  $distribution created session $created"
  listed="$(inside "$distribution" "'$helper_path' --json list" | compact)" ||
    fail "$distribution could not be asked what sessions it has"
  case "$listed" in
    *"\"session_id\":\"$created\""*) : ;;
    *) fail "$distribution does not list $created, the session it created: $listed" ;;
  esac

  # The worker serving it: this distribution's own Linux process, running the binary installed
  # here, as the same Linux user, with this distribution's filesystem as its root. Nothing on the
  # Windows side takes part in it, and nothing it opens is on the Windows side of /mnt.
  #
  # This run created one session in this distribution and closes it below, so one worker is
  # running here and it is that session's. More than one would leave these checks unable to say
  # which process they are about, so the count is asserted rather than the newest one taken.
  workers="$(inside "$distribution" 'pgrep -x kr-worker')" ||
    fail "$distribution runs no worker for session $created"
  [ "$(printf '%s\n' "$workers" | grep -c .)" = "1" ] ||
    fail "$distribution runs more than one worker, so these checks cannot name the one serving $created: $workers"
  worker_pid="$(printf '%s\n' "$workers" | head -n 1)"
  [[ "$worker_pid" =~ ^[0-9]+$ ]] ||
    fail "$distribution did not report a Linux process identifier for the worker serving $created"
  worker_exe="$(inside "$distribution" "readlink -f /proc/$worker_pid/exe | head -n 1")" ||
    fail "$distribution could not be asked what its worker $worker_pid runs"
  [ "$worker_exe" = "$installed_dir/kr-worker" ] ||
    fail "$distribution's worker $worker_pid runs $worker_exe, not the $installed_dir/kr-worker installed in it"
  worker_user="$(inside "$distribution" "stat -c %U /proc/$worker_pid | head -n 1")" ||
    fail "$distribution could not be asked who its worker $worker_pid runs as"
  [ "$worker_user" = "$linux_user" ] ||
    fail "$distribution's worker runs as $worker_user and the enrolment names $linux_user"
  worker_root="$(inside "$distribution" "readlink /proc/$worker_pid/root | head -n 1")" ||
    fail "$distribution could not be asked what its worker $worker_pid has for a root"
  [ "$worker_root" = "/" ] ||
    fail "$distribution's worker has root $worker_root rather than this distribution's own"
  # What the worker has open that lives on the Windows side: a file under one of the drive mounts
  # (`/mnt/c`, `/mnt/d`), or on a 9p filesystem, which is how WSL2 serves them. The listing is made
  # first and counted afterwards, so a listing that could not be made is a failure here rather than
  # a partial one counted as no crossings. Other files below /mnt are not Windows files: WSLg,
  # where it is installed, keeps what it serves to every distribution in /mnt/wslg, a memory-backed
  # directory of the virtual machine. The product keeps nothing of its own there, which the
  # daemon's sockets above are checked for.
  # shellcheck disable=SC2016  # read by the shell inside the distribution, which is the point
  crossings_script='for fd in /proc/$1/fd/*; do
    target="$(readlink "$fd")" || continue
    case "$target" in
      /mnt/[a-z] | /mnt/[a-z]/*) echo "$target on a drive mount" ;;
      /*) case "$(stat -L -f -c %T "$fd" 2>/dev/null)" in v9fs | 9p) echo "$target on a 9p filesystem" ;; esac ;;
    esac
  done'
  crossing_list="$(inside "$distribution" "/bin/sh -c '$crossings_script' sh $worker_pid")" ||
    fail "$distribution could not be asked what its worker $worker_pid has open"
  crossing="$(printf '%s\n' "$crossing_list" | grep -c .)" || [ "$crossing" = "0" ]
  if [ "$crossing" != "0" ]; then
    fail "$distribution's worker has $crossing open files on the Windows side, so it reaches out of the distribution: $(printf '%s' "$crossing_list" | tr '\n' ';')"
  fi
  inside "$distribution" "'$helper_path' close $created" >/dev/null ||
    fail "$distribution could not close session $created"
done
pass "each distribution's daemon and worker are its own Linux processes, binaries, users and paths"

# ---------------------------------------------------------------------------------------------
step "4. Windows reaches each distribution through the process bridge"

kr_exe=""
for candidate in "C:/kala/target/debug/kr.exe" "target/debug/kr.exe" "C:/kala/target/release/kr.exe"; do
  if [ -f "$candidate" ]; then
    kr_exe="$candidate"
    break
  fi
done
[ -n "$kr_exe" ] || fail "no Windows kr.exe was found; build it with cargo build -p kr-cli --bin kr"
controller_exe="$(dirname "$kr_exe")/kr-controller.exe"
worker_exe="$(dirname "$kr_exe")/kr-worker.exe"
[ -f "$controller_exe" ] || fail "no Windows kr-controller.exe beside $kr_exe"

# The Windows daemon this run owns, with its keys in its own directory rather than the platform
# credential store. Every path handed to one of these native programs is a Windows path, including
# the two in the environment: this shell's own form means nothing to them.
windows_runtime="$run_dir/windows-run"
windows_state="$run_dir/windows-state"
mkdir -p "$windows_runtime" "$windows_state"
"$controller_exe" --runtime-dir "$(windows_path "$windows_runtime")" \
  --state-dir "$(windows_path "$windows_state")" \
  --worker "$(windows_path "$worker_exe")" \
  --secret-store file >"$run_dir/windows-controller.log" 2>&1 &
windows_daemon=$!
KR_RUNTIME_DIR="$(windows_path "$windows_runtime")"
KR_STATE_DIR="$(windows_path "$windows_state")"
export KR_RUNTIME_DIR KR_STATE_DIR
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "$kr_exe" bridge list >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"$kr_exe" bridge list >/dev/null 2>&1 ||
  fail "the Windows daemon did not answer: $(tail -n 20 "$run_dir/windows-controller.log")"
pass "a Windows control daemon is running for this acceptance"

enrol_distribution() {
  local distribution="$1" label="$2" answer identity
  "$kr_exe" --json bridge enrol --access wsl --label "$label" --target "$distribution" \
    --user "$linux_user" --helper "$helper_path" --probe >"$run_dir/enrol-$label.json" 2>&1 ||
    fail "enrolling $distribution failed: $(cat "$run_dir/enrol-$label.json")"
  answer="$(compact <"$run_dir/enrol-$label.json")"
  identity="$(printf '%s' "$answer" | json_string environment_id)"
  [ -n "$identity" ] ||
    fail "enrolling $distribution recorded no environment identity: $answer"
  printf '%s' "$identity"
}

first_id="$(enrol_distribution "$first" "first")"
second_id="$(enrol_distribution "$second" "second")"
echo "  $first is environment $first_id"
echo "  $second is environment $second_id"
[ -n "$first_id" ] && [ -n "$second_id" ] ||
  fail "a distribution did not answer with an environment identity"
[ "$first_id" != "$second_id" ] ||
  fail "two distributions answered with the same environment identity"
pass "each distribution answered the bridge with its own environment identity"

# The identity the enrolment recorded is the one that distribution reports for itself.
for pair in "$first:$first_id" "$second:$second_id"; do
  distribution="${pair%%:*}"
  recorded="${pair##*:}"
  doctor="$(inside "$distribution" "'$helper_path' --json doctor" | compact)" ||
    fail "$distribution could not report on itself"
  reported="$(printf '%s' "$doctor" | json_string environment_id)"
  [ -n "$reported" ] ||
    fail "$distribution named no environment of its own: $doctor"
  [ "$reported" = "$recorded" ] ||
    fail "$distribution reports environment $reported and the enrolment recorded $recorded"
done
pass "the recorded identity is the one each distribution reports for itself"

refresh_and_check() {
  local label="$1" expect_id="$2" flags="${3:-}" text
  # shellcheck disable=SC2086
  "$kr_exe" --json bridge refresh "$label" $flags >"$run_dir/refresh-$label.json" 2>&1 ||
    fail "refreshing $label failed: $(cat "$run_dir/refresh-$label.json")"
  text="$(compact <"$run_dir/refresh-$label.json")"
  # The verification is what the destination answered. Matching the whole document would accept the
  # enrolment's own identity where the verification is absent, so the key path is named here.
  case "$text" in
    *"\"verification\":{\"environment_id\":\"$expect_id\""*) : ;;
    *) fail "the refresh of $label carried no verification from $expect_id: $text" ;;
  esac
  case "$text" in
    *'"role":"controller"'*) : ;;
    *) fail "the refresh of $label was not answered by a control daemon: $text" ;;
  esac
}

refresh_and_check first "$first_id"
refresh_and_check second "$second_id"
pass "a refresh opens a bridge to each distribution and carries a read to its own daemon"

# ---------------------------------------------------------------------------------------------
step "5. A listing reads the cache and starts nothing"

# The distribution's own choice of how its control daemon is started when none is running, which
# is what a create or an attach that starts the distribution then relies on. Setting it starts
# nothing.
inside "$second" "'$helper_path' host startup --set standalone" >"$run_dir/startup-second.log" 2>&1 ||
  fail "the second distribution could not choose how its daemon is started: $(cat "$run_dir/startup-second.log")"

wsl.exe -t "$second" >/dev/null 2>&1 || fail "the second distribution could not be stopped"
sleep 2
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "$second is not stopped, so this check would prove nothing"

# A refresh observes, and observing starts nothing: this one was not told to start the environment.
"$kr_exe" --json bridge refresh second >"$run_dir/refresh-stopped.json" 2>&1 ||
  fail "the refresh of the stopped distribution failed: $(cat "$run_dir/refresh-stopped.json")"
observed="$(compact <"$run_dir/refresh-stopped.json")"
case "$observed" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the refresh did not observe $second as stopped: $observed" ;;
esac
case "$observed" in
  *'"verification":null'*) : ;;
  *) fail "a stopped distribution answered a bridge: $observed" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the refresh started $second although it was not told to"
pass "a refresh observed the stopped distribution and started nothing"

"$kr_exe" --json bridge list >"$run_dir/list-while-stopped.json" 2>&1 ||
  fail "the listing failed: $(cat "$run_dir/list-while-stopped.json")"
listing="$(compact <"$run_dir/list-while-stopped.json")"
# The row for the stopped distribution alone: everything after its identity up to the end of that
# row. Another row's source or status cannot satisfy these.
row="${listing#*\"environment_id\":\""$second_id"\"}"
[ "$row" != "$listing" ] ||
  fail "the stopped distribution is missing from the listing: $listing"
row="${row%%\},\{\"enrolment\"*}"
case "$row" in
  *'"observation":"cache"'*) : ;;
  *) fail "the stopped distribution's row is not from the cache: $row" ;;
esac
case "$row" in
  *'"status":"environment_stopped"'*) : ;;
  *) fail "the listing does not repeat what was observed of $second: $row" ;;
esac
case "$row" in
  *'"last_observed_at_ms":'*) : ;;
  *) fail "the stopped distribution's row carries no observation time: $row" ;;
esac
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "the listing started $second, which a listing must never do"
pass "the listing reported the stopped distribution from the cache and started nothing"

# Creating a session is the other action that starts what it names, and it starts more than a
# refresh does: the distribution, and then the control daemon inside it, which the distribution's
# own startup starts. Nothing here starts a daemon by hand.
"$kr_exe" --json new --invisible --environment second --shell /bin/sh >"$run_dir/new-stopped.json" 2>&1 ||
  fail "creating a session in the stopped distribution failed: $(cat "$run_dir/new-stopped.json")"
created_doc="$(compact <"$run_dir/new-stopped.json")"
[ "$(state_of "$second")" = "Running" ] ||
  fail "creating a session did not start $second"
created_here="$(printf '%s' "$created_doc" | json_string session_id)"
[ -n "$created_here" ] ||
  fail "the create named no session: $created_doc"
case "$created_doc" in
  *"\"environment_id\":\"$second_id\""*) : ;;
  *) fail "the session was not created in $second's environment $second_id: $created_doc" ;;
esac
# The session starts where the user in the distribution starts, which the destination said and
# this host did not: the working directory of the command that asked is a Windows one.
# shellcheck disable=SC2016  # the variable is read inside the distribution, not here
home_inside="$(inside "$second" 'printf %s "$HOME"')" ||
  fail "$second could not say where its user's home is"
case "$created_doc" in
  *"\"cwd\":\"$home_inside\""*) : ;;
  *) fail "the session did not start in $second's home $home_inside: $created_doc" ;;
esac
# Nothing in the daemon started for it is this script's to end except by the identifier recorded
# here: the one control daemon the distribution is running, which its own startup made.
inside "$second" 'pgrep -x kr-controller | head -n 1 >/tmp/kr-acc-controller.pid' ||
  fail "$second could not name the daemon its own startup made"
inside "$second" "'$helper_path' --json list" | compact |
  grep -q "\"session_id\":\"$created_here\"" ||
  fail "$second does not list $created_here, the session created in it through the bridge"
"$kr_exe" --json list | compact | grep -q "\"session_id\":\"$created_here\"" &&
  fail "the Windows daemon lists $created_here, which lives in $second"
pass "creating a session in the stopped distribution started it and its daemon, and the session lives there"

# Attaching is the third action that starts what it names. After the session has closed and the
# distribution has stopped, the bridge asks the distribution what became of it, which takes the
# distribution's daemon, and the answer is that the session closed.
inside "$second" "'$helper_path' close $created_here" >/dev/null ||
  fail "$second could not close $created_here"
# The distribution is stopped once its daemon has recorded the closure, which is what the attach
# below asks about after it starts again.
retained_row=""
for _ in $(seq 1 60); do
  if retained_row="$(closed_row_inside "$second" "$created_here")"; then
    break
  fi
  retained_row=""
  sleep 1
done
[ -n "$retained_row" ] ||
  fail "$second did not record $created_here as closed within a minute of closing it"
retained_closure="$(printf '%s' "$retained_row" | closure_text)" ||
  fail "the closure $second recorded for $created_here could not be read: $retained_row"
wsl.exe -t "$second" >/dev/null 2>&1 || fail "the second distribution could not be stopped again"
sleep 2
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "$second is not stopped, so the attach below would prove nothing"
attach_code=0
"$kr_exe" --json attach "$created_here" --environment second >"$run_dir/attach-closed.json" 2>&1 ||
  attach_code=$?
[ "$attach_code" -ne 0 ] ||
  fail "attaching to the closed session $created_here succeeded: $(cat "$run_dir/attach-closed.json")"
attached="$(compact <"$run_dir/attach-closed.json")"
case "$attached" in
  *'"code":"SESSION_CLOSED"'*) : ;;
  *) fail "attaching to the closed session did not answer SESSION_CLOSED: $attached" ;;
esac
case "$attached" in
  *'"closure":{'*) : ;;
  *) fail "the refusal did not say how the session ended: $attached" ;;
esac
# What the destination retained across the stop is the record it made when the session closed.
answered_closure="$(printf '%s' "$attached" | closure_text)" ||
  fail "the refusal's closure could not be read: $attached"
[ "$answered_closure" = "$retained_closure" ] ||
  fail "the closure the stopped distribution gave back is not the one it recorded: recorded $retained_closure, gave $answered_closure"
[ "$(state_of "$second")" = "Running" ] ||
  fail "attaching did not start $second, which it needs to ask what became of the session"
pass "attaching to a closed session in the stopped distribution said how it ended"
wsl.exe -t "$second" >/dev/null 2>&1 || fail "the second distribution could not be stopped for the refresh below"
sleep 2
[ "$(state_of "$second")" = "Stopped" ] ||
  fail "$second is not stopped, so the refresh below would prove nothing"

# Starting the distribution again is one step; the daemon inside it is another, because stopping a
# distribution ends every process in it. The refresh below starts the distribution, and the bridge
# is checked once that distribution is serving again.
"$kr_exe" --json bridge refresh second --start >"$run_dir/refresh-start.json" 2>&1 ||
  fail "the refresh that was told to start failed: $(cat "$run_dir/refresh-start.json")"
[ "$(state_of "$second")" = "Running" ] ||
  fail "the refresh that was told to start did not start $second"
pass "a refresh that was told to start the distribution started it"

start_daemon_inside "$second"
refresh_and_check second "$second_id"
pass "the bridge reaches the distribution that was started again"

# ---------------------------------------------------------------------------------------------
step "6. NAT and mirrored networking"

# USERPROFILE is a Windows path. The redirection below is this shell's, so it needs the form this
# shell opens files by.
wslconfig_path="$(cygpath -u "${USERPROFILE:?the Windows profile directory}")/.wslconfig"
wslconfig_saved="$run_dir/wslconfig.saved"
if [ -f "$wslconfig_path" ]; then
  wslconfig_existed=1
  cp "$wslconfig_path" "$wslconfig_saved"
else
  : >"$wslconfig_saved"
fi

# What WSL said the first time it brought a distribution up under the mode being asked for. A host
# that cannot offer the mode says so there and falls back to another one.
mode_notice=""

networking_facts() {
  local mode="$1" distribution="$2" effective addresses
  # What WSL is actually doing, not what the file asks for.
  effective="$(inside "$distribution" 'wslinfo --networking-mode 2>/dev/null || true' | tr -d ' ')"
  echo "  $mode: $distribution reports networking mode: ${effective:-unknown}"
  [ -n "$effective" ] ||
    fail "$mode: this WSL build does not report its networking mode, so the mode cannot be established"
  # A mode that is not in effect is not a result about the bridge either way, so the failure names
  # what refused it. On a host that cannot offer the mode, what is missing is the host: the bridge
  # has simply not been measured there, and no automatic behaviour can be settled on one mode.
  [ "$effective" = "$mode" ] ||
    fail "$mode networking was asked for and $effective is in effect, so the bridge has not been \
measured in $mode on this machine. What this host said when it took the setting up: \
${mode_notice:-nothing}"
  addresses="$(inside "$distribution" 'ip -br addr')" ||
    fail "$mode: $distribution could not be asked what addresses it holds"
  echo "  $mode: $distribution addresses:"
  printf '    %s\n' "$addresses"
  inside "$distribution" 'ping -c 1 -W 2 127.0.0.1 >/dev/null 2>&1 && echo loopback-ok' |
    grep -q loopback-ok || fail "$mode: loopback is not reachable inside $distribution"
}

set_mode() {
  local mode="$1"
  printf '[wsl2]\nnetworkingMode=%s\n' "$mode" >"$wslconfig_path"
  wsl.exe --shutdown >/dev/null 2>&1 ||
    fail "the distributions could not be shut down to take up $mode networking"
  sleep 3
  # Bringing one distribution up is what makes WSL configure the network, and what makes it say so
  # when it cannot. The exit status is part of that answer rather than a failure of this run.
  if ! mode_notice="$(wsl.exe -d "$first" -u "$linux_user" --exec /bin/true 2>&1 | tr -d '\000\r')"; then
    mode_notice="${mode_notice:-wsl.exe exited non-zero and said nothing}"
  fi
  [ -z "$mode_notice" ] || echo "  $mode: this host said: $mode_notice"
  daemons=""
  for distribution in "$first" "$second"; do
    start_daemon_inside "$distribution"
  done
}

for mode in $network_modes; do
  set_mode "$mode"
  networking_facts "$mode" "$first"
  # The bridge opens no socket, so it must behave the same in both modes. This is the measurement
  # that decides whether any automatic behaviour is needed, rather than assuming one.
  refresh_and_check first "$first_id"
  pass "$mode: the process bridge opened and carried a read unchanged"
done

# ---------------------------------------------------------------------------------------------
step "7. The helper refuses what may not cross"

# Input that is not a frame at all: the helper ends non-zero and says why.
malformed_code=0
malformed="$(printf 'not a bridge frame' |
  wsl.exe -d "$first" -u "$linux_user" --exec "$helper_path" bridge --stdio 2>&1)" || malformed_code=$?
[ "$malformed_code" -ne 0 ] ||
  fail "the helper served a stream that is not a bridge frame: $malformed"
echo "$malformed" | grep -qi "bridge" ||
  fail "the helper gave no diagnostic for input that is not a frame: $malformed"
pass "input that is not a bridge frame ends the helper non-zero with a diagnostic"

# A properly encoded handshake that declares a network origin has to be refused by protocol, not by
# a parse failure. The suite that builds those frames runs inside the distribution, against the
# Linux helper this run installed: it is told which command to drive, so it tests the installed
# helper rather than whichever build it was compiled beside.
inside "$first" "KR_TEST_COMMAND_BINARY='$helper_path' '$suite_path'" >"$run_dir/wsl-bridge-suite.log" 2>&1 ||
  fail "the bridge suite failed inside $first: $(tail -n 30 "$run_dir/wsl-bridge-suite.log")"
grep -q "test result: ok" "$run_dir/wsl-bridge-suite.log" ||
  fail "the bridge suite reported no result inside $first"
pass "the bridge suite passes inside the distribution, including the refusal of a network origin"

echo
case " $network_modes " in
  *" mirrored "*) : ;;
  *) echo "mirrored networking was not measured: this run asked for $network_modes only." ;;
esac
case " $network_modes " in
  *" nat "*) : ;;
  *) echo "NAT networking was not measured: this run asked for $network_modes only." ;;
esac
echo "KR-ACC-011: $passed checks passed."
