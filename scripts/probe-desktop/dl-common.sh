#!/bin/bash
# dl-common.sh: sourced by every script of the desktop probe. Not run on its own.
#
# Needs DL_OUT (the folder that receives the results; created with mode 0700 if absent). Makes DL_TMP, an owner-only
# temporary folder of its own, and removes it, and only it, on every exit (normal, error, INT, TERM, HUP). Every
# background process it starts is remembered by its number and ended by that number on every exit.
#   dl_bg <cmd...>            start a background process; its number is DL_LAST
#   dl_rec <name> <cmd...>    run a command; write its argument vector, words (both streams) and exit code to $DL_OUT/<name>.txt
#   dl_start_xvfb <auth-file> start Xvfb on a free display with a fresh authority file; sets DL_DISPLAY (":N") and DL_XPID
#   dl_find <tool>            print the installed path of a tool: the search path first, then the libexec folders
#   dl_procs_of <exe-path>    print the numbers of this user's processes whose executable is that file
[ -n "${DL_COMMON_LOADED:-}" ] && return 0
DL_COMMON_LOADED=1
umask 077
: "${DL_OUT:?set DL_OUT to the folder that receives the results}"
mkdir -p -- "$DL_OUT" || exit 70
chmod 700 -- "$DL_OUT"
DL_TMP=$(mktemp -d "${TMPDIR:-/tmp}/dc1.XXXXXXXX") || exit 70
chmod 700 -- "$DL_TMP"
DL_PIDS=()
DL_LAST=0
dl_cleanup() {
  local pid
  for pid in "${DL_PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${DL_PIDS[@]}"; do wait "$pid" 2>/dev/null; done
  case "$DL_TMP" in
    "${TMPDIR:-/tmp}"/dc1.*) [ -d "$DL_TMP" ] && rm -rf -- "$DL_TMP" ;;
  esac
}
trap dl_cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT HUP
dl_bg() { "$@" & DL_LAST=$!; DL_PIDS+=("$DL_LAST"); }
dl_rec() {
  local name=$1
  shift
  { printf '$'; printf ' %q' "$@"; printf '\n'; "$@"; printf '== exit %s\n' "$?"; } > "$DL_OUT/$name.txt" 2>&1
}
dl_find() {
  local t=$1 d
  command -v "$t" 2>/dev/null && return 0
  for d in /usr/libexec /usr/lib/at-spi2-core /usr/lib/at-spi2 /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu /usr/lib/xdg-desktop-portal /usr/lib/x86_64-linux-gnu/xdg-desktop-portal; do
    [ -x "$d/$t" ] && { printf '%s\n' "$d/$t"; return 0; }
  done
  return 1
}
dl_procs_of() {
  local exe=$1 p
  for p in /proc/[0-9]*; do
    [ "$(stat -c %u "$p" 2>/dev/null)" = "$(id -u)" ] || continue
    [ "$(readlink "$p/exe" 2>/dev/null)" = "$exe" ] && printf '%s\n' "${p#/proc/}"
  done
}
dl_start_xvfb() {
  local auth=$1 n try
  for n in $(seq 90 189); do
    if [ -e "/tmp/.X11-unix/X$n" ] || [ -e "/tmp/.X$n-lock" ]; then continue; fi
    : > "$auth"
    chmod 600 -- "$auth"
    xauth -f "$auth" add ":$n" . "$(mcookie)" > /dev/null 2>&1 || return 1
    Xvfb ":$n" -screen 0 1280x800x24 -auth "$auth" -nolisten tcp > "$DL_OUT/xvfb-$n.log" 2>&1 &
    DL_XPID=$!
    DL_PIDS+=("$DL_XPID")
    for try in $(seq 1 40); do
      if [ -S "/tmp/.X11-unix/X$n" ]; then DL_DISPLAY=":$n"; return 0; fi
      kill -0 "$DL_XPID" 2>/dev/null || break
      sleep 0.25
    done
    kill "$DL_XPID" 2>/dev/null
    wait "$DL_XPID" 2>/dev/null
  done
  return 1
}
