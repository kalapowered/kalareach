#!/bin/bash
# dl2-packages.sh <before|after> <results-folder>: the package state of a hosted ubuntu-24.04 job, written to
# <results-folder>/01-packages-<before|after>.txt. It installs nothing: the workflow installs PACKAGES below, between the two calls.
# Run by: the desktop-probe job of the conformance workflow. xcalc, xwd and xdpyinfo come from x11-apps and x11-utils; xauth and
# mcookie are their own packages (xauth, util-linux); weston and the Wayland clients are listed.
PACKAGES="xvfb xauth x11-utils x11-apps maim scrot imagemagick dbus dbus-x11 libglib2.0-bin at-spi2-core gnome-calculator galculator sway grim wayland-utils weston xdg-desktop-portal xdg-desktop-portal-gtk python3-gi gir1.2-glib-2.0 file util-linux"
when=${1:?usage: dl2-packages.sh <before|after> <results-folder>}
DL_OUT=${2:?results folder}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"
case $when in before | after) ;; *) echo "first argument is before or after"; exit 2 ;; esac
{
  echo "packages asked for: $PACKAGES"
  echo "-- dpkg-query (an unknown package prints an error and is not installed):"
  # shellcheck disable=SC2086
  dpkg-query -W -f '${Package}\t${Version}\t${Status}\n' $PACKAGES 2>&1
  echo "-- image: $(. /etc/os-release; echo "$PRETTY_NAME") $(uname -srm)"
} > "$DL_OUT/01-packages-$when.txt" 2>&1
echo "dl2-packages $when: done"
