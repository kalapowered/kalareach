#!/bin/bash
# dl2-launch.sh <results-folder>: which launch targets hand off to another instance, and what they write at startup.
# For each target that is installed: (a) the D-Bus name has no owner before the start (recorded, so a bystander is visible);
# (b) a first instance starts in its own process group with a disposable home; (c) a second start with the first open (the
# hand-off test), its exit code, and the processes left; (d) the owner of the application's bus name and its process number;
# (e) the files the targets wrote inside the disposable home; (f) both groups are killed by group number, and the processes
# left afterwards are listed. Its own Xvfb and its own private session bus; nothing touches the person's home. Cleanup on every exit.
# Run by: the desktop-probe job of the conformance workflow, after the packages of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-launch.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"
auth="$DL_TMP/xauthority"
if ! dl_start_xvfb "$auth"; then echo "no display could be started" > "$DL_OUT/00-fail.txt"; exit 1; fi
export DL_TMP DISPLAY="$DL_DISPLAY" XAUTHORITY="$auth"
dbus-run-session -- bash "$here/dl2-launch-inner.sh" > "$DL_OUT/00-inner.log" 2>&1
echo "dl2-launch: inner exit $?, results in $DL_OUT"
