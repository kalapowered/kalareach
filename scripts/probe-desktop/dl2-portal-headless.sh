#!/bin/bash
# dl2-portal-headless.sh <results-folder>: does the Screenshot portal run on a headless runner at all, and what does it
# report? One dbus-run-session holds the bus, the portal and the reads. It sends no screenshot request. Ends everything it
# started and removes its own folder on every exit. Run by: the desktop-probe job of the conformance workflow, after the packages
# of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-portal-headless.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"
export DL_TMP
dbus-run-session -- bash -c '
  pids=()
  finish() { for p in "${pids[@]}"; do kill "$p" 2> /dev/null; done; for p in "${pids[@]}"; do wait "$p" 2> /dev/null; done; }
  trap finish EXIT
  trap "exit 143" TERM
  trap "exit 130" INT HUP
  portal=""
  for p in /usr/libexec/xdg-desktop-portal /usr/lib/xdg-desktop-portal; do [ -x "$p" ] && { portal=$p; break; }; done
  [ -n "$portal" ] || { echo "xdg-desktop-portal not found" > "$DL_OUT/10-fail.txt"; exit 1; }
  { echo "portal: $portal"; busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListActivatableNames 2>&1 | tr " " "\n" | grep -i portal; } > "$DL_OUT/10-activatable.txt" 2>&1
  "$portal" -r > "$DL_OUT/11-portal.log" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 50); do
    [ "$(busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.freedesktop.portal.Desktop 2> /dev/null)" = "b true" ] && break
    sleep 0.2
  done
  { busctl --user get-property org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Screenshot version 2>&1
    busctl --user introspect org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Screenshot 2>&1; } > "$DL_OUT/12-screenshot-interface.txt"
' > "$DL_OUT/00-inner.log" 2>&1
echo "dl2-portal-headless: inner exit $?, results in $DL_OUT"
