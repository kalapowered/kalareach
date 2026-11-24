#!/bin/bash
# dl2-x11.sh <results-folder>: the real X11 target. Starts its own Xvfb on a free display with a fresh authority
# file inside an owner-only temporary folder (nothing is written under a fixed /tmp name), captures with each tool, then with an
# empty authority file and with a display that does not exist. Every exit ends the Xvfb it started and removes the folder.
# Run by: the desktop-probe job of the conformance workflow, after the packages of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-x11.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"

auth="$DL_TMP/xauthority"
empty="$DL_TMP/xauthority.empty"
: > "$empty"
chmod 600 -- "$empty"
if ! dl_start_xvfb "$auth"; then echo "no display could be started" > "$DL_OUT/00-fail.txt"; exit 1; fi
n=${DL_DISPLAY#:}
free=""
for m in $(seq 190 199); do [ -e "/tmp/.X11-unix/X$m" ] || { free=$m; break; }; done

dl_rec 02-sockets bash -c "ls -l /tmp/.X11-unix/; ss -xl | grep -E 'X$n' || true"
dl_rec 03-versions bash -c 'Xvfb -version 2>&1 | head -n 3; maim --version; import -version | head -n 2; scrot --version; xwd -help 2>&1 | head -n 3; xauth version 2>&1 | head -n 1'
dl_rec 03-geometry env "DISPLAY=$DL_DISPLAY" "XAUTHORITY=$auth" xdpyinfo

# One output file per tool inside the owner-only folder. The tool rows are a closed list.
cap() { # cap <label> <display> <authority-file> <tool> <argument...> (the output path replaces the word OUT)
  local label=$1 disp=$2 xa=$3 out="$DL_TMP/$1.img" a args=()
  shift 3
  for a in "$@"; do if [ "$a" = OUT ]; then args+=("$out"); else args+=("$a"); fi; done
  dl_rec "$label" env "DISPLAY=$disp" "XAUTHORITY=$xa" "${args[@]}"
  if [ -e "$out" ]; then
    { file "$out"; stat -c 'size=%s' "$out"; od -An -tx1 -N40 "$out"; } >> "$DL_OUT/$label.txt" 2>&1
  else
    echo "no output file was written" >> "$DL_OUT/$label.txt"
  fi
}
for row in "maim:maim OUT" "import:import -silent -window root OUT" "scrot:scrot OUT" "xwd:xwd -root -silent -out OUT"; do
  tool=${row%%:*}
  # shellcheck disable=SC2086
  set -- ${row#*:}
  cap "04-$tool-right-authority" "$DL_DISPLAY" "$auth" "$@"
  cap "05-$tool-empty-authority" "$DL_DISPLAY" "$empty" "$@"
  [ -n "$free" ] && cap "06-$tool-no-such-display" ":$free" "$auth" "$@"
done
# Can the worker connect to the socket itself? The two socket names a display has, and one that does not exist.
dl_rec 07-socket-connect python3 -c '
import socket, sys
for p in sys.argv[1:]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect("\0" + p[1:] if p.startswith("@") else p)
        print(p, "connect ok")
    except OSError as e:
        print(p, "connect failed", e)
    finally:
        s.close()
' "/tmp/.X11-unix/X$n" "@/tmp/.X11-unix/X$n" "/tmp/.X11-unix/X${free:-199}"
echo "dl2-x11: done, results in $DL_OUT"
