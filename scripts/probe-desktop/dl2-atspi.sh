#!/bin/bash
# dl2-atspi.sh <results-folder>: AT-SPI on a private session bus. Everything (the bus, the launcher, the
# application and every query) runs inside ONE dbus-run-session, through dl2-atspi-inner.sh, so the bus is still there for the
# later queries. Its own Xvfb (fresh authority file, free display) holds the GTK application. Cleanup on every exit.
# Run by: the desktop-probe job of the conformance workflow, after the packages of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-atspi.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"
auth="$DL_TMP/xauthority"
if ! dl_start_xvfb "$auth"; then echo "no display could be started" > "$DL_OUT/00-fail.txt"; exit 1; fi
export DL_TMP DISPLAY="$DL_DISPLAY" XAUTHORITY="$auth"
dbus-run-session -- bash "$here/dl2-atspi-inner.sh" > "$DL_OUT/00-inner.log" 2>&1
echo "dl2-atspi: inner exit $?, results in $DL_OUT"
