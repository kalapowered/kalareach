#!/bin/bash
# dl2-x11.sh <results-folder>: the real X11 target. Starts its own Xvfb on a free display with a fresh authority
# file inside an owner-only temporary folder (nothing is written under a fixed /tmp name), captures with each tool, then with an
# empty authority file, with an authority file that holds a wrong key for the same display, and with a display that does not
# exist. Every output file carries the suffix of the format asked for. Every exit ends the Xvfb it started and removes the folder.
# Run by: the desktop-probe job of the conformance workflow, after the packages of dl2-packages.sh are installed.
DL_OUT=${1:?usage: dl2-x11.sh <results-folder>}
export DL_OUT
here=$(cd "$(dirname "$0")" && pwd)
. "$here/dl-common.sh"

auth="$DL_TMP/xauthority"
empty="$DL_TMP/xauthority.empty"
wrong="$DL_TMP/xauthority.wrong"
: > "$empty"
chmod 600 -- "$empty"
if ! dl_start_xvfb "$auth"; then echo "no display could be started" > "$DL_OUT/00-fail.txt"; exit 1; fi
n=${DL_DISPLAY#:}
# The same display name as the right authority file holds, with a different key.
: > "$wrong"
chmod 600 -- "$wrong"
xauth -f "$wrong" add ":$n" . "$(mcookie)" > /dev/null 2>&1
free=""
for m in $(seq 190 199); do [ -e "/tmp/.X11-unix/X$m" ] || { free=$m; break; }; done

dl_rec 01-authority-entries bash -c 'for f in "$@"; do echo "$f"; xauth -f "$f" list | awk "{ print \$1, \$2 }"; done' _ "$auth" "$empty" "$wrong"
dl_rec 02-sockets bash -c "ls -l /tmp/.X11-unix/; ss -xl | grep -E 'X$n' || true"
dl_rec 03-versions bash -c 'Xvfb -version 2>&1 | head -n 3; maim --version; import -version | head -n 2; scrot --version; xwd -help 2>&1 | head -n 3; xauth -V 2>&1 | head -n 1'
dl_rec 03-help bash -c 'maim --help 2>&1 | head -n 40; echo "-- scrot"; scrot --help 2>&1 | head -n 40'
dl_rec 03-geometry env "DISPLAY=$DL_DISPLAY" "XAUTHORITY=$auth" xdpyinfo

# One output file per vector inside the owner-only folder, named with the suffix of its format.
# cap <label> <suffix> <display> <authority-file> <tool> <argument...>: the word OUT inside an argument becomes the output
# path (<label>.<suffix> in the temporary folder), so png:OUT puts a format prefix on it. The tool's two streams go to
# <label>.stdout and <label>.stderr, each in a file of its own. <label>.txt holds the vector, the exit code, the byte count
# of each stream and, when a file was written, what file says about it, its size and its first 100 bytes.
cap() {
  local label=$1 suffix=$2 disp=$3 xa=$4 out a args=() rc
  out="$DL_TMP/$label.$suffix"
  shift 4
  for a in "$@"; do args+=("${a//OUT/$out}"); done
  {
    printf '$'; printf ' %q' env "DISPLAY=$disp" "XAUTHORITY=$xa" "${args[@]}"; printf '\n'
    env "DISPLAY=$disp" "XAUTHORITY=$xa" "${args[@]}" > "$DL_OUT/$label.stdout" 2> "$DL_OUT/$label.stderr"
    rc=$?
    printf '== exit %s\n' "$rc"
    printf 'stdout: %s bytes, stderr: %s bytes\n' "$(stat -c %s "$DL_OUT/$label.stdout")" "$(stat -c %s "$DL_OUT/$label.stderr")"
    if [ -e "$out" ]; then
      file "$out"; stat -c 'size=%s' "$out"; od -An -tx1 -N100 "$out"
    else
      echo "no output file was written"
    fi
  } > "$DL_OUT/$label.txt" 2>&1
}
for row in "maim:png:maim OUT" "import:png:import -silent -window root OUT" "scrot:png:scrot OUT" "xwd:xwd:xwd -root -silent -out OUT"; do
  tool=${row%%:*}
  rest=${row#*:}
  suffix=${rest%%:*}
  # shellcheck disable=SC2086
  set -- ${rest#*:}
  cap "04-$tool-right-authority" "$suffix" "$DL_DISPLAY" "$auth" "$@"
  cap "05-$tool-empty-authority" "$suffix" "$DL_DISPLAY" "$empty" "$@"
  [ -n "$free" ] && cap "06-$tool-no-such-display" "$suffix" ":$free" "$auth" "$@"
  cap "08-$tool-wrong-authority" "$suffix" "$DL_DISPLAY" "$wrong" "$@"
done
# On the right authority: import with the format named by a prefix on a name that has no known suffix, and maim and scrot
# with a suffix that no format has.
cap 09-import-png-prefix-right-authority img "$DL_DISPLAY" "$auth" import -silent -window root png:OUT
cap 10-maim-bad-suffix-right-authority img "$DL_DISPLAY" "$auth" maim OUT
cap 11-scrot-bad-suffix-right-authority img "$DL_DISPLAY" "$auth" scrot OUT
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
