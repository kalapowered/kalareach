# shellcheck shell=bash
# Where a test run keeps its evidence: the one reader of KR_TEST_ARTIFACTS_DIR for shell.
#
# Section 27 puts every screenshot and evidence file of a release test run in one directory,
# KR_TEST_ARTIFACTS_DIR, set under a temporary folder for the build. A script reads the variable only
# through this file, so a value outside this platform's temporary roots is refused where it is used,
# whatever way the value took. Source it, then:
#
#   kr_artifacts_dir          sets kr_artifacts to the evidence directory
#   kr_artifacts_dir_if_set   the same, but kr_artifacts is empty and nothing is made where the
#                             variable is not set (for a report that only looks at the directory)
#
# Both export KR_TEST_ARTIFACTS_DIR with the resolved value, so a program the script starts reads
# the same directory, and both end the script with status 1 and the words below when the value is
# refused. They run in the script's own shell: `x=$(kr_artifacts_dir)` would lose the variable and
# the exit.
#
# The temporary roots are /tmp, the folder TMPDIR names and the folder RUNNER_TEMP names, and on
# Windows (Git Bash) the folder TEMP names, where each is an absolute path to a directory; on
# Windows /tmp is a root only where it is the folder TEMP names, since Git Bash makes it from the
# temporary folder of the first Git Bash process of a session. A root is resolved through its links
# as the platform resolves it (/tmp is /private/tmp on macOS), and so is the part of the value that
# exists, so a link inside a root that leads out of it is refused and a root that is itself behind
# a link is honoured. The top of a file system (/ or //, a drive's top, a share's top) is no root, and
# neither is a folder with a line feed in its name or in its real path. A value is compared with a root by path
# components, never by text: /tmpfoo is not inside /tmp. On Windows the comparison ignores letter
# case. A relative value, an empty value and a value with a `..` in it are refused, and so is a
# root itself.
#
# On Windows a value, and each temporary variable, is read as Windows writes a full path or as Git
# Bash does: C:\folder or C:/folder, \\server\share\folder or //server/share/folder, either of
# those behind \\?\ (with backslashes only), /c/folder and /tmp/folder, with each backslash read as
# a separator (Git Bash settles a path that holds one by its text, so the `..` check and the root
# check read the value with each backslash as a slash). Any other spelling is refused, in words that
# say which are taken: a device path (\\.\), a server with no share, three slashes at the start, a
# path that depends on the current drive (\folder) or on a drive's current directory (C:folder).
# Off Windows a value that holds a backslash is refused, in words that say that a backslash is not
# taken in the folder's path on this platform, before any other read of it, and a temporary
# variable that holds one is passed over as a root: PowerShell's own path commands read a
# backslash as a separator there, so a folder whose name holds one cannot be kept as written by
# every reader and by the scripts that use the path they return, and a value that the four readers
# cannot read as one folder is refused by all four.
#
# Where the variable is not set, the run makes a directory of its own under the temporary folder
# (readable by this account only) and says where it is on standard error. The temporary folder is
# the one TMPDIR names, else /tmp (and /tmp where TMPDIR holds a backslash off Windows), and on
# Windows, where TMPDIR is not set or is /tmp or /tmp/ (a login shell's profile exports it so), the
# one TEMP names. The directory is made under the temporary folder in the form that the reader's
# own classifier returns for it, never in the form as it was written.
#
# The reader guards a test run against a mistake: for any value of the evidence variable, and any
# temporary variable as a platform, a runner, one of our scripts or a developer's shell sets it,
# with folders and links as tools make them, it returns a folder inside the roots or refuses, and
# it refuses nothing that the run set right. It is no boundary against a process of the same
# account, which can write wherever the run can and can change a link or a folder while the reader
# reads. It does not close a case that somebody arranges: a name with a line feed beside a link at
# the shortened name. On Windows the comparison ignores letter case, so a folder made
# case-sensitive, and a letter that the disk and the reader do not fold alike, are not told apart.
#
# On Windows this reader takes the temporary folder from TEMP and the TypeScript reader takes TEMP
# first; the Rust reader and the PowerShell reader take TMP first. Where TMP and TEMP differ, only a
# value under the runner's folder satisfies all four readers.

# Succeeds on Windows (Git Bash), where a name is the same in any letter case.
_kr_artifacts_windows() {
  case "$(uname -s)" in
    MINGW* | MSYS* | CYGWIN*) return 0 ;;
  esac
  return 1
}

# Prints $1 as it is compared with a root: in lower case on Windows, as it is.
_kr_artifacts_fold() {
  if _kr_artifacts_windows; then
    printf '%s\n' "$1" | tr '[:upper:]' '[:lower:]'
  else
    printf '%s\n' "$1"
  fi
}

# Prints the real path of the folder that $1 names, through its links, and fails where $1 is not an
# absolute path to a folder or where a line feed is in the real path. A root is passed from the
# producer below to its consumer one to a line, which a line feed would cut in two, and a command
# substitution drops the line feeds at the end of a name, which would name another folder.
_kr_artifacts_resolve() {
  local _kr_path
  case "$1" in /*) ;; *) return 1 ;; esac
  # The `x` shows the end of the path, so that no line feed of its own is lost.
  _kr_path="$(cd -P -- "$1" 2>/dev/null && pwd -P && printf x)" || return 1
  _kr_path="${_kr_path%x}"
  _kr_path="${_kr_path%$'\n'}"
  case "$_kr_path" in *$'\n'*) return 1 ;; esac
  _kr_artifacts_flat "$_kr_path"
}

# Prints the path $1 with a leading `//` made one `/`, off Windows. bash keeps a leading `//` in a
# real path, so the top of the file system comes back as `//` and /tmp behind a link written `//tmp`
# as `//private/tmp`. Where no network path begins with two slashes they are the one top and the
# one folder; on Windows `//server/share` is a network path and stays as it is.
_kr_artifacts_flat() {
  local _kr_flat="$1"
  if ! _kr_artifacts_windows; then
    while :; do
      case "$_kr_flat" in //*) _kr_flat="${_kr_flat#/}" ;; *) break ;; esac
    done
  fi
  printf '%s\n' "$_kr_flat"
}

# A drive's letter is one of the 52 ASCII letters, listed out in each pattern below: a range such as
# `A-Za-z` is read by collation under some locales (bash 3.2 in a UTF-8 locale takes `é` for a letter
# of it), and a drive has no such letter.

# Succeeds when $1, a folder as Windows writes it, is the top of a file system: a drive (`C:\`) or a
# share (`\\server\share`), with or without the last backslash.
_kr_artifacts_windows_top() {
  local _kr_top
  case "$1" in
    [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]: | [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:[\\/]) return 0 ;;
    \\\\*)
      _kr_top="${1#\\\\}"
      _kr_top="${_kr_top%\\}"
      case "$_kr_top" in
        ?*\\?*) case "${_kr_top#*\\}" in *\\*) ;; *) return 0 ;; esac ;;
      esac
      ;;
  esac
  return 1
}

# Prints the real path of the folder TEMP names (Windows, Git Bash), and fails where it names none.
# The name as it was given is checked first: the conversion to Git Bash's form drops the line feeds
# at the end of a name, and a name that ends with one names no folder.
_kr_artifacts_windows_temp() {
  case "${TEMP:-}" in *$'\n'*) return 1 ;; esac
  _kr_artifacts_resolve "$(_kr_artifacts_posix "${TEMP:-}")"
}

# Prints each temporary root that exists, resolved through its links, one to a line. A root has no
# line feed in it, and is never the top of a file system.
_kr_artifacts_roots() {
  local _kr_candidate _kr_real _kr_windows=0 _kr_seen=$'\n' _kr_temp=""
  local _kr_named=(/tmp "${TMPDIR:-}" "${RUNNER_TEMP:-}")
  if _kr_artifacts_windows; then
    _kr_windows=1
    _kr_named+=("${TEMP:-}")
    # Git Bash makes /tmp from the temporary folder of the process that started the first Git Bash
    # of the session, so it can be a folder that this process's TEMP does not name: /tmp is a root
    # here only where it is the folder TEMP names.
    _kr_temp="$(_kr_artifacts_windows_temp)" || _kr_temp=""
  fi
  for _kr_candidate in "${_kr_named[@]}"; do
    # The name as it was given: the conversion below drops the line feeds at its end.
    case "$_kr_candidate" in *$'\n'*) continue ;; esac
    # Off Windows a temporary variable that holds a backslash names no root.
    if [ "$_kr_windows" != 1 ]; then
      case "$_kr_candidate" in *\\*) continue ;; esac
    fi
    if [ "$_kr_windows" = 1 ]; then
      # A temporary variable in a spelling this reader does not take names no root; the slashes at
      # its end are not part of the folder, so `/tmp/` is `/tmp`.
      _kr_candidate="$(_kr_artifacts_posix "$_kr_candidate")" || continue
      _kr_candidate="$(_kr_artifacts_trim "$_kr_candidate")"
    fi
    _kr_real="$(_kr_artifacts_resolve "$_kr_candidate")" || continue
    if [ -n "$_kr_real" ] && [ "$_kr_real" != / ]; then
      # A drive's top (/c) is a filesystem root on Windows, as / is elsewhere, and so is any folder
      # that Windows writes as the top of a drive (`C:\`) or of a share (`\\server\share`), whatever
      # name Git Bash gives it: with the temporary folder at the top of a drive it writes the whole
      # drive under /tmp.
      if [ "$_kr_windows" = 1 ]; then
        case "$_kr_real" in /?) continue ;; esac
        _kr_artifacts_windows_top "$(cygpath -w -- "$_kr_real" 2>/dev/null)" && continue
        if [ "$_kr_candidate" = /tmp ] && [ "$(_kr_artifacts_fold "$_kr_real")" != "$(_kr_artifacts_fold "$_kr_temp")" ]; then
          continue
        fi
      fi
      # Two names for one folder (/tmp and the folder TMPDIR names) are one root.
      case "$_kr_seen" in *$'\n'"$_kr_real"$'\n'*) continue ;; esac
      _kr_seen="$_kr_seen$_kr_real"$'\n'
      printf '%s\n' "$_kr_real"
    fi
  done
  return 0
}

# Prints $1 as the path Git Bash reads, where $1 is written as Windows writes a full path or as Git
# Bash does, with each backslash read as a separator (Git Bash settles a path that holds one by its
# text, so a `..` behind a backslash climbs out of the folder before any check could see it):
#
#   C:\folder, C:/folder              -> /c/folder
#   \\server\share\x, //server/share/x -> //server/share/x
#   \\?\C:\folder, \\?\UNC\server\share\x (backslashes only: Windows reads a slash behind \\?\ as a
#                                       letter of a name) -> as the two above
#   /c/folder, /tmp/folder            -> as written, backslashes read as slashes (Git Bash's own)
#
# Fails with status 1 for a path that is not absolute (a relative one, \folder, C:folder) and with
# status 2 for any other Windows spelling: a device path (\\.\ or \\?\ with anything but a drive or
# UNC behind it, or with a slash), a server with no share, three slashes at the start. Off Windows a
# path is as it is: a backslash is a letter of a name there.
_kr_artifacts_posix() {
  local _kr_v="$1" _kr_after _kr_server _kr_extended='\\?\'
  if ! _kr_artifacts_windows; then
    printf '%s\n' "$_kr_v"
    return 0
  fi
  case "$_kr_v" in
    "$_kr_extended"*)
      _kr_v="${_kr_v#"$_kr_extended"}"
      case "$_kr_v" in */*) return 2 ;; esac
      case "$_kr_v" in
        [Uu][Nn][Cc]'\'?*) _kr_v='\\'"${_kr_v:4}" ;;
        [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:'\'*) ;;
        *) return 2 ;;
      esac
      ;;
  esac
  case "$_kr_v" in
    [\\/][\\/][.?] | [\\/][\\/][.?][\\/]*) return 2 ;;
    [\\/][\\/][\\/]*) return 2 ;;
    [\\/][\\/]*)
      _kr_after="${_kr_v:2}"
      _kr_after="${_kr_after//\\//}"
      _kr_server="${_kr_after%%/*}"
      case "$_kr_after" in */*) _kr_after="${_kr_after#*/}" ;; *) return 2 ;; esac
      case "$_kr_after" in '' | /*) return 2 ;; esac
      printf '//%s/%s\n' "$_kr_server" "$_kr_after"
      ;;
    [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:[\\/]*) cygpath -u -- "$_kr_v" ;;
    [abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]:* | [\\]*) return 1 ;;
    /*) printf '%s\n' "${_kr_v//\\//}" ;;
    *) return 1 ;;
  esac
}

# Prints $1 without the slashes at its end (the top of a path, `/`, stays).
_kr_artifacts_trim() {
  local _kr_t="$1"
  while [ "${#_kr_t}" -gt 1 ] && [ "${_kr_t%/}" != "$_kr_t" ]; do
    _kr_t="${_kr_t%/}"
  done
  printf '%s\n' "$_kr_t"
}

# Prints the spellings that this reader takes on Windows, for the words of a refusal; nothing off
# Windows.
_kr_artifacts_takes() {
  _kr_artifacts_windows || return 0
  printf '%s' ' (on Windows this reader takes C:\folder or C:/folder, \\server\share\folder or //server/share/folder, and either behind \\?\, as \\?\C:\folder or \\?\UNC\server\share\folder)'
}

# Prints why $1 is refused, with the variable and the roots named, on standard error. With a third
# argument, $1 is a name that was to be made under the temporary folder $3 for the run's own
# directory, and it is the folder that is refused: nothing was set, so the words do not tell the
# caller to leave it unset.
_kr_artifacts_refuse() {
  local _kr_roots _kr_what
  _kr_roots="$(_kr_artifacts_roots | awk 'BEGIN { s = "" } { s = s (NR > 1 ? ", " : "") $0 } END { print s }')"
  [ -n "$_kr_roots" ] || _kr_roots="none: no folder that a temporary variable names exists"
  if [ "$#" -ge 3 ]; then
    _kr_what="$2"
    [ -z "$3" ] || _kr_what="the temporary folder '$3' is refused: $2"
    printf '%s\n' "kr-artifacts: no directory of this run's own can be made for its evidence: ${_kr_what}. It has to be an absolute path to a folder inside one of this platform's temporary roots (${_kr_roots}). Point TMPDIR (on Windows, TEMP: a TMPDIR that is /tmp, or /tmp/, is passed over there) at such a folder, or set KR_TEST_ARTIFACTS_DIR to a folder under one of the roots." >&2
  else
    printf '%s\n' "kr-artifacts: the evidence directory '$1' (KR_TEST_ARTIFACTS_DIR) is refused: $2. It has to be an absolute path inside one of this platform's temporary roots (${_kr_roots}). Set it to a folder under one of them, or leave it unset and the run makes a directory of its own." >&2
  fi
  return 1
}

# Prints the real path of $1 when it is inside a temporary root; else says why not and returns 1.
# With a second argument, $1 is a name under the temporary folder $2 for the run's own directory.
_kr_artifacts_confine() {
  local _kr_value="$1" _kr_written="$1" _kr_prefix="" _kr_probe _kr_rest="" _kr_real _kr_real_folded _kr_root _kr_inside=0 _kr_status=0
  if [ -z "$_kr_value" ]; then
    _kr_artifacts_refuse "$1" "it is empty" ${2+"$2"}
    return 1
  fi
  if ! _kr_artifacts_windows; then
    case "$_kr_value" in
      *\\*)
        _kr_artifacts_refuse "$1" "it holds a backslash, and a backslash is not taken in the folder's path on this platform" ${2+"$2"}
        return 1
        ;;
    esac
  fi
  _kr_value="$(_kr_artifacts_posix "$_kr_value")" || _kr_status=$?
  if [ "$_kr_status" = 2 ]; then
    _kr_artifacts_refuse "$1" "it is a Windows path of a kind this reader does not take$(_kr_artifacts_takes)" ${2+"$2"}
    return 1
  fi
  case "$_kr_status:$_kr_value" in
    0:/*) ;;
    *)
      _kr_artifacts_refuse "$1" "it is not an absolute path$(_kr_artifacts_takes)" ${2+"$2"}
      return 1
      ;;
  esac
  # A step up is looked for in the value as it was written, with each backslash read as a
  # separator on Windows: Git Bash settles a path that holds a backslash by its text, so a `..`
  # behind one climbs out of the folder, and the converted value no longer shows it. The line feeds
  # at its end are dropped as the substitution above dropped them from the converted one, so that a
  # `..` before them is still the last name.
  _kr_written="$(printf '%s' "$_kr_written")"
  if _kr_artifacts_windows; then _kr_written="${_kr_written//\\//}"; fi
  case "/$_kr_written/" in
    */../*)
      _kr_artifacts_refuse "$1" "it steps up a directory with \`..\`" ${2+"$2"}
      return 1
      ;;
  esac
  # Each run of slashes is one slash, except that on Windows a leading `//` before a name stays: it
  # is a network path there. The run is cut at its first `//` and not replaced by a pattern
  # (`${_kr_value//\/\//\/}`), which bash 3.2, the system's own bash on a Mac, reads as a backslash
  # before the slash, and a Mac's own temporary variable ends with a slash.
  if _kr_artifacts_windows; then
    case "$_kr_value" in
      //[!/]*)
        _kr_prefix=/
        _kr_value="${_kr_value#/}"
        ;;
    esac
  fi
  while :; do
    case "$_kr_value" in *//*) _kr_value="${_kr_value%%//*}/${_kr_value#*//}" ;; *) break ;; esac
  done
  _kr_value="$_kr_prefix$_kr_value"
  [ "$_kr_value" = / ] || _kr_value="${_kr_value%/}"
  _kr_probe="$_kr_value"
  while [ -n "$_kr_probe" ] && [ ! -e "$_kr_probe" ]; do
    # Each pass drops one name, so the loop ends at the top of the path.
    [ "$_kr_probe" != "${_kr_probe%/*}" ] || break
    _kr_rest="/${_kr_probe##*/}$_kr_rest"
    _kr_probe="${_kr_probe%/*}"
  done
  [ -n "$_kr_probe" ] || _kr_probe=/
  if [ ! -d "$_kr_probe" ]; then
    _kr_artifacts_refuse "$1" "$_kr_probe is not a directory" ${2+"$2"}
    return 1
  fi
  _kr_real="$(cd -P -- "$_kr_probe" 2>/dev/null && pwd -P)" || {
    _kr_artifacts_refuse "$1" "$_kr_probe cannot be resolved" ${2+"$2"}
    return 1
  }
  _kr_real="$(_kr_artifacts_flat "$_kr_real")"
  [ "$_kr_real" = / ] && _kr_real=""
  _kr_real="$_kr_real$_kr_rest"
  _kr_real_folded="$(_kr_artifacts_fold "$_kr_real")"
  while IFS= read -r _kr_root; do
    # An empty root would make the pattern below `/*`, which every path matches.
    [ -n "$_kr_root" ] || continue
    case "$_kr_real_folded" in
      "$(_kr_artifacts_fold "$_kr_root")"/*) _kr_inside=1 ;;
    esac
  done < <(_kr_artifacts_roots)
  if [ "$_kr_inside" != 1 ]; then
    _kr_artifacts_refuse "$1" "it is not inside a temporary root" ${2+"$2"}
    return 1
  fi
  printf '%s\n' "$_kr_real"
}

# Makes a directory of this run's own under the temporary folder and prints its real path. The
# temporary folder is TMPDIR, else /tmp (and /tmp where TMPDIR holds a backslash, off Windows, which
# passes it over as a root), and on Windows, where TMPDIR is not set or is /tmp or /tmp/ (a login
# shell's profile exports it so), the folder TEMP names: /tmp there is a folder that TEMP may not
# name, and it is no root then. The folder is checked before the directory is made in it, so that a
# temporary folder that is no root is left as it was. The directory is named under the folder in the
# form that the classifier returns for it, and not in the form as it was written: a folder written
# behind \\?\ in backslashes would hold a slash behind the prefix once a name was added to it.
_kr_artifacts_own() {
  local _kr_temporary="${TMPDIR:-/tmp}" _kr_folder _kr_form _kr_made
  if ! _kr_artifacts_windows; then
    case "$_kr_temporary" in *\\*) _kr_temporary=/tmp ;; esac
  fi
  if _kr_artifacts_windows && { [ -z "${TMPDIR:-}" ] || [ "$(_kr_artifacts_trim "$TMPDIR")" = /tmp ]; }; then
    _kr_temporary="$(_kr_artifacts_windows_temp)" || {
      if [ -z "${TEMP:-}" ]; then
        _kr_artifacts_refuse "" "TEMP is not set or is empty, so no temporary folder is named" ""
      else
        _kr_artifacts_refuse "$TEMP" "TEMP names no folder that exists" "$TEMP"
      fi
      return 1
    }
  fi
  # A folder that this reader does not take keeps its written form, which the check below refuses
  # in the words for its spelling; so does a name with a line feed in it, since the conversion drops
  # the line feeds at its end and would name another folder.
  _kr_folder="$_kr_temporary"
  case "$_kr_temporary" in
    *$'\n'*) ;;
    *) _kr_form="$(_kr_artifacts_posix "$_kr_temporary")" && _kr_folder="$(_kr_artifacts_trim "$_kr_form")" ;;
  esac
  _kr_artifacts_confine "$_kr_folder/kr-test-artifacts.XXXXXX" "$_kr_temporary" > /dev/null || return 1
  _kr_made="$(mktemp -d "$_kr_folder/kr-test-artifacts.XXXXXX")" || {
    echo "kr-artifacts: no directory of this run's own can be made in the temporary folder '$_kr_temporary'" >&2
    return 1
  }
  _kr_artifacts_confine "$_kr_made" "$_kr_temporary"
}

# kr_artifacts_dir: sets kr_artifacts to the evidence directory, and exports KR_TEST_ARTIFACTS_DIR.
kr_artifacts_dir() {
  local _kr_dir _kr_caseless=0
  # Every comparison below is by exact letters, whatever the caller set: with nocasematch a `case`
  # would take /TMP for /tmp on a disk that keeps them apart. The option is put back at the end
  # (a refusal ends the script, which has no later use for it).
  if shopt -q nocasematch; then _kr_caseless=1; fi
  shopt -u nocasematch
  if [ "${KR_TEST_ARTIFACTS_DIR+set}" = set ]; then
    _kr_dir="$(_kr_artifacts_confine "$KR_TEST_ARTIFACTS_DIR")" || exit 1
  else
    _kr_dir="$(_kr_artifacts_own)" || exit 1
    echo "KR_TEST_ARTIFACTS_DIR is not set: this run keeps its evidence in $_kr_dir" >&2
  fi
  KR_TEST_ARTIFACTS_DIR="$_kr_dir"
  export KR_TEST_ARTIFACTS_DIR
  # shellcheck disable=SC2034 # The script that sources this file reads it.
  kr_artifacts="$_kr_dir"
  if [ "$_kr_caseless" = 1 ]; then shopt -s nocasematch; fi
}

# kr_artifacts_dir_if_set: as kr_artifacts_dir, but kr_artifacts is empty and nothing is made where
# the variable is not set.
kr_artifacts_dir_if_set() {
  if [ "${KR_TEST_ARTIFACTS_DIR+set}" = set ]; then
    kr_artifacts_dir
  else
    # shellcheck disable=SC2034 # The script that sources this file reads it.
    kr_artifacts=""
  fi
}
