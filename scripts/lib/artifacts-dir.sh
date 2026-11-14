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
# Windows (Git Bash) the folder TEMP names, where each is an absolute path to a directory. A root
# is resolved through its links as the platform resolves it (/tmp is /private/tmp on macOS), and so
# is the part of the value that exists, so a link inside a root that leads out of it is refused and
# a root that is itself behind a link is honoured. A value is compared with a root by path
# components, never by text: /tmpfoo is not inside /tmp. On Windows the comparison ignores letter
# case. A relative value, an empty value and a value with a `..` in it are refused, and so is a
# root itself.
#
# Where the variable is not set, the run makes a directory of its own under the temporary folder
# (readable by this account only) and says where it is on standard error.

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
  printf '%s\n' "$_kr_path"
}

# Succeeds when $1, a folder as Windows writes it, is the top of a file system: a drive (`C:\`) or a
# share (`\\server\share`), with or without the last backslash.
_kr_artifacts_windows_top() {
  local _kr_top
  case "$1" in
    [A-Za-z]: | [A-Za-z]:[\\/]) return 0 ;;
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
    _kr_temp="$(_kr_artifacts_resolve "$(_kr_artifacts_posix "${TEMP:-}")")" || _kr_temp=""
  fi
  for _kr_candidate in "${_kr_named[@]}"; do
    # The name as it was given: the conversion below drops the line feeds at its end.
    case "$_kr_candidate" in *$'\n'*) continue ;; esac
    [ "$_kr_windows" = 1 ] && _kr_candidate="$(_kr_artifacts_posix "$_kr_candidate")"
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

# Prints $1 as a path Git Bash reads, when it is written the way Windows writes it (C:\... or C:/...).
_kr_artifacts_posix() {
  case "$1" in
    [A-Za-z]:[\\/]*) cygpath -u -- "$1" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

# Prints why $1 is refused, with the variable and the roots named, on standard error.
_kr_artifacts_refuse() {
  local _kr_roots
  _kr_roots="$(_kr_artifacts_roots | awk 'BEGIN { s = "" } { s = s (NR > 1 ? ", " : "") $0 } END { print s }')"
  printf '%s\n' "kr-artifacts: the evidence directory '$1' (KR_TEST_ARTIFACTS_DIR) is refused: $2. It has to be an absolute path inside one of this platform's temporary roots (${_kr_roots}). Set it to a folder under one of them, or leave it unset and the run makes a directory of its own." >&2
  return 1
}

# Prints the real path of $1 when it is inside a temporary root; else says why not and returns 1.
_kr_artifacts_confine() {
  local _kr_value="$1" _kr_written="$1" _kr_probe _kr_rest="" _kr_real _kr_real_folded _kr_root _kr_inside=0
  _kr_value="$(_kr_artifacts_posix "$_kr_value")"
  if [ -z "$_kr_value" ]; then
    _kr_artifacts_refuse "$1" "it is empty"
    return 1
  fi
  case "$_kr_value" in
    /*) ;;
    *)
      _kr_artifacts_refuse "$1" "it is not an absolute path"
      return 1
      ;;
  esac
  # A step up is looked for in the value as it was written: the conversion of a Windows path above
  # settles a `..` by its text, so the converted value no longer shows it. The line feeds at its end
  # are dropped as the substitution above dropped them from the converted one, so that a `..` before
  # them is still the last name.
  _kr_written="$(printf '%s' "$_kr_written")"
  case "$_kr_written" in [A-Za-z]:[\\/]*) _kr_written="${_kr_written//\\//}" ;; esac
  case "/$_kr_written/" in
    */../*)
      _kr_artifacts_refuse "$1" "it steps up a directory with \`..\`"
      return 1
      ;;
  esac
  while :; do
    case "$_kr_value" in *//*) _kr_value="${_kr_value//\/\//\/}" ;; *) break ;; esac
  done
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
    _kr_artifacts_refuse "$1" "$_kr_probe is not a directory"
    return 1
  fi
  _kr_real="$(cd -P -- "$_kr_probe" 2>/dev/null && pwd -P)" || {
    _kr_artifacts_refuse "$1" "$_kr_probe cannot be resolved"
    return 1
  }
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
    _kr_artifacts_refuse "$1" "it is not inside a temporary root"
    return 1
  fi
  printf '%s\n' "$_kr_real"
}

# Makes a directory of this run's own under the temporary folder and prints its real path. The
# folder is checked before the directory is made in it, so that a temporary folder that is no root
# is left as it was.
_kr_artifacts_own() {
  local _kr_made
  _kr_artifacts_confine "${TMPDIR:-/tmp}/kr-test-artifacts.XXXXXX" > /dev/null || return 1
  _kr_made="$(mktemp -d "${TMPDIR:-/tmp}/kr-test-artifacts.XXXXXX")" || {
    echo "kr-artifacts: no directory of this run's own can be made for its evidence" >&2
    return 1
  }
  _kr_artifacts_confine "$_kr_made"
}

# kr_artifacts_dir: sets kr_artifacts to the evidence directory, and exports KR_TEST_ARTIFACTS_DIR.
kr_artifacts_dir() {
  local _kr_dir
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
