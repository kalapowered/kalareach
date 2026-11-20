# shellcheck shell=bash
# How a device script starts the host: the test program that runs a real daemon, a worker and a
# session for the phone to pair with.
#
# The program is not given the home folder or the search path of the person who runs the script. It
# runs with a new empty home folder, the system's own search path and, where the script is told one,
# a temporary folder of its own, so that nothing it starts reads or writes the person's files. The
# emulator, the simulator and adb keep the person's home: only the host's command is changed.
#
# Sourced by the device scripts. Three variables, all optional:
#
#   KR_HOST_BIN_DIR    an absolute folder (on the machine's internal disk) that the built program
#                      is copied into and started from, so that it does not run from a build folder
#                      on a removable volume;
#   KR_HOST_TMPDIR     the temporary folder the host program sees; without it the script's own;
#   KR_HOST_HOME_ROOT  the folder the host's new home folder is made in; without it the script's
#                      temporary folder.
#
#   host_install <built executable> <name>   prints where the program is to be started from
#   host_start <program> [<argument>...]     replaces the calling subshell with the program; call
#                                            it with a trailing `&`, so that `$!` is the program

# host_install <built executable> <name>
host_install() {
  local built="$1" name="$2"
  if [ -z "${KR_HOST_BIN_DIR:-}" ]; then
    printf '%s\n' "$built"
    return 0
  fi
  case "$KR_HOST_BIN_DIR" in
    /*) ;;
    *) echo "host_install: KR_HOST_BIN_DIR is not an absolute path" >&2; return 2 ;;
  esac
  mkdir -p "$KR_HOST_BIN_DIR" && cp "$built" "$KR_HOST_BIN_DIR/$name" || return 2
  printf '%s\n' "$KR_HOST_BIN_DIR/$name"
}

# host_start <program> [<argument>...]
host_start() {
  local home
  home="$(mktemp -d "${KR_HOST_HOME_ROOT:-${TMPDIR:-/tmp}}/kr-host-home.XXXXXX")" || exit 2
  exec env HOME="$home" PATH=/usr/bin:/bin:/usr/sbin:/sbin TMPDIR="${KR_HOST_TMPDIR:-${TMPDIR:-/tmp}}" "$@"
}
