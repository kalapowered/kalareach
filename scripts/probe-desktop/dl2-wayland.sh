#!/bin/bash
# dl2-wayland.sh <results-folder>: a headless compositor with the screen-copy protocol (sway) and one without
# it (weston), and grim against each. The runtime folder is made with mode 0700 inside the owner-only temporary folder, and
# every client gets that folder and the socket the compositor actually created (read from the folder, not assumed).
# Cleanup on every exit. Run by: the desktop-probe job of the conformance workflow, after the packages of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-wayland.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"
rt="$DL_TMP/run"
mkdir -m 700 -- "$rt"
cfg="$DL_TMP/sway.conf"
: > "$cfg"
sock_of() { # sock_of <before-listing-file> <name-pattern>: the display socket that appeared in the runtime folder (sway also makes an IPC socket there, which is not a display)
  local f
  for _ in $(seq 1 50); do
    for f in "$rt"/$2; do
      [ -S "$f" ] || continue
      grep -qxF "$f" "$1" 2> /dev/null || { basename "$f"; return 0; }
    done
    sleep 0.2
  done
  return 1
}
ls -d "$rt"/* > "$DL_TMP/before-sway" 2> /dev/null
env XDG_RUNTIME_DIR="$rt" WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman sway -c "$cfg" > "$DL_OUT/10-sway.log" 2>&1 &
swaypid=$!
DL_PIDS+=("$swaypid")
swaysock=$(sock_of "$DL_TMP/before-sway" 'wayland-*') || { echo "sway made no socket" > "$DL_OUT/10-fail.txt"; exit 1; }
cl() { env XDG_RUNTIME_DIR="$rt" WAYLAND_DISPLAY="$1" "${@:2}"; }
dl_rec 11-sway-versions bash -c 'sway --version; grim -h 2>&1 | head -n 3; dpkg-query -W sway grim wayland-utils weston'
dl_rec 12-sway-globals cl "$swaysock" wayland-info
{ echo "-- screen-copy globals offered by sway:"; grep -E 'zwlr_screencopy|ext_image_copy|ext_image_capture' "$DL_OUT/12-sway-globals.txt"; } > "$DL_OUT/13-sway-protocols.txt" 2>&1
out="$DL_TMP/grim-sway.png"
dl_rec 14-grim-sway cl "$swaysock" grim "$out"
{ file "$out"; stat -c 'size=%s' "$out"; } >> "$DL_OUT/14-grim-sway.txt" 2>&1

ls -d "$rt"/* > "$DL_TMP/before-weston" 2> /dev/null
env XDG_RUNTIME_DIR="$rt" weston --backend=headless --socket=dc1-weston > "$DL_OUT/20-weston.log" 2>&1 &
DL_PIDS+=("$!")
westonsock=$(sock_of "$DL_TMP/before-weston" 'dc1-weston') || { echo "weston made no socket" > "$DL_OUT/20-fail.txt"; exit 0; }
dl_rec 21-weston-globals cl "$westonsock" wayland-info
{ echo "-- screen-copy globals offered by weston:"; grep -E 'zwlr_screencopy|ext_image_copy|ext_image_capture' "$DL_OUT/21-weston-globals.txt"; } > "$DL_OUT/22-weston-protocols.txt" 2>&1
out2="$DL_TMP/grim-weston.png"
dl_rec 23-grim-weston cl "$westonsock" grim "$out2"
{ ls -l "$out2" 2>&1; } >> "$DL_OUT/23-grim-weston.txt" 2>&1
# A search path with no capture tool: what the facility lookup would see (the tools resolve to none).
dl_rec 24-empty-path env -i PATH="$DL_TMP" /bin/bash -c 'command -v grim maim import scrot xwd || echo "no capture tool on this path"'
echo "dl2-wayland: done, results in $DL_OUT"
