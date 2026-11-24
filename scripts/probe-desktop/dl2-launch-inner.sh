#!/bin/bash
# dl2-launch-inner.sh: runs inside the one dbus-run-session of dl2-launch.sh (DL_OUT, DL_TMP, DISPLAY, XAUTHORITY exported).
# For each installed target: the first instance starts and the script waits up to 15 s for the application's bus name to have
# an owner (a target with no application id waits the full 15 s); then the second instance starts, with a window of 5 s for it to
# end. At 10 s after the first start the files written (with sizes) and the network sockets of the target's processes are listed.
# Every wait is bounded; every exit kills the groups.
: "${DL_OUT:?}" "${DL_TMP:?}"
groups=()
finish() {
  local g
  for g in "${groups[@]}"; do kill -KILL -- "-$g" 2> /dev/null; done
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT HUP
now_ms() { echo $(($(date +%s%N) / 1000000)); }
owner_of() { busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s "$1" 2>&1; }
procs_of() { # procs_of <exe-real-path>
  local p
  for p in /proc/[0-9]*; do
    [ "$(readlink "$p/exe" 2> /dev/null)" = "$1" ] && printf '%s ' "${p#/proc/}"
  done
}
names_of() { # names_of <process numbers>: the lines of the bus's own list (name, process number, program) for those processes
  busctl --user list --no-pager 2>&1 | awk -v pids="$*" 'BEGIN { n = split(pids, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 } NR == 1 || ($2 in want)'
}
sockets_of() { # sockets_of <process numbers>: the TCP and UDP sockets (any state) that those processes hold
  ss -tunap 2>&1 | awk -v pids="$*" 'BEGIN { n = split(pids, a, " "); for (i = 1; i <= n; i++) want["pid=" a[i] ","] = 1 } NR == 1 { print; next } { for (k in want) if (index($0, k)) { print; break } }'
}
snapshot() { # snapshot <start-ms> <home> <reference-file> <exe-real-path>
  local p
  p=$(procs_of "$4")
  echo "-- $(($(now_ms) - $1)) ms after the first start: processes: $p"
  echo "files written outside mesa_shader_cache, size and path:"
  find "$2" -type f -newer "$3" ! -path '*/mesa_shader_cache/*' -printf '%s %P\n' 2>&1
  echo "mesa_shader_cache: $(find "$2" -type f -newer "$3" -path '*/mesa_shader_cache/*' | wc -l) files, $(find "$2" -type f -newer "$3" -path '*/mesa_shader_cache/*' -printf '%s\n' | awk '{ s += $1 } END { print s + 0 }') bytes"
  echo "sockets of those processes (ss -tunap):"
  sockets_of "$p"
}
# target:application-id ("-" when the program is not a D-Bus unique application)
for row in gnome-calculator:org.gnome.Calculator galculator:- xcalc:- mate-calc:org.mate.Calculator kcalc:org.kde.kcalc; do
  t=${row%%:*}; appid=${row#*:}
  exe=$(command -v "$t") || { echo "$t: not installed" >> "$DL_OUT/40-summary.txt"; continue; }
  real=$(readlink -f "$exe")
  out="$DL_OUT/41-$t.txt"
  home="$DL_TMP/home-$t"
  mkdir -p -- "$home"
  ref="$DL_TMP/ref-$t"
  : > "$ref"
  {
    echo "target: $exe -> $real; owner package: $(dpkg-query -S "$real" 2> /dev/null | head -n 1)"
    [ "$appid" != - ] && { echo "before the start, owner of $appid:"; owner_of "$appid"; }
    echo "processes of the target before: $(procs_of "$real")"
  } > "$out" 2>&1
  t0=$(now_ms)
  env HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" XDG_CACHE_HOME="$home/.cache" \
    setsid "$exe" > "$DL_TMP/first-$t.log" 2>&1 &
  first=$!
  groups+=("$first")
  # Wait up to 15 s, every 0.5 s, for the application id to have an owner; take the 10 s snapshot on the way.
  snap_done=0
  name_ms=""
  while ms=$(($(now_ms) - t0)); [ "$ms" -le 15000 ]; do
    if [ "$appid" != - ] && [ "$(owner_of "$appid")" = "b true" ]; then name_ms=$ms; break; fi
    if [ "$snap_done" = 0 ] && [ "$ms" -ge 10000 ]; then snapshot "$t0" "$home" "$ref" "$real" >> "$out" 2>&1; snap_done=1; fi
    sleep 0.5
  done
  {
    if [ -n "$name_ms" ]; then
      echo "the name $appid had an owner $name_ms ms after the first start; the second start follows"
    elif [ "$appid" = - ]; then
      echo "no application id to wait for: waited $ms ms, then the second start follows"
    else
      echo "the name $appid had no owner after $ms ms; the second start follows anyway"
    fi
    echo "processes of the target: $(procs_of "$real")"
    echo "bus names owned by those processes:"
    names_of "$(procs_of "$real")"
    echo "every name on the bus:"
    busctl --user list --no-pager 2>&1
    if [ -n "$name_ms" ]; then echo "owner of $appid:"; busctl --user status "$appid" 2>&1 | grep -E '^(PID|Comm|Exe)='; fi
    echo "first start, first lines of its output:"
    head -n 20 "$DL_TMP/first-$t.log"
  } >> "$out" 2>&1
  start=$(now_ms)
  env HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" XDG_CACHE_HOME="$home/.cache" \
    setsid "$exe" > "$DL_TMP/second-$t.log" 2>&1 &
  second=$!
  groups+=("$second")
  for _ in $(seq 1 50); do kill -0 "$second" 2> /dev/null || break; sleep 0.1; done
  if kill -0 "$second" 2> /dev/null; then
    echo "second start: still running after 5 s (group $second)" >> "$out"
  else
    wait "$second"
    rc=$?
    echo "second start: exited with $rc after $(($(now_ms) - start)) ms" >> "$out"
  fi
  {
    echo "second start, first lines of its output:"
    head -n 20 "$DL_TMP/second-$t.log"
  } >> "$out" 2>&1
  # The snapshot is at 10 s after the first start; wait for that point if the name came early.
  if [ "$snap_done" = 0 ]; then
    while [ $(($(now_ms) - t0)) -lt 10000 ]; do sleep 0.5; done
    snapshot "$t0" "$home" "$ref" "$real" >> "$out" 2>&1
  fi
  sleep 2
  echo "processes of the target after the second start: $(procs_of "$real")" >> "$out"
  if [ -n "$name_ms" ]; then { echo "owner of $appid after the second start:"; busctl --user status "$appid" 2>&1 | grep -E '^(PID|Comm|Exe)='; } >> "$out" 2>&1; fi
  { echo "files written inside the disposable home, size and path:"; find "$home" -type f -newer "$ref" -printf '%s %P\n' 2>&1; } >> "$out" 2>&1
  kill -KILL -- "-$first" 2> /dev/null
  kill -KILL -- "-$second" 2> /dev/null
  sleep 1
  echo "processes of the target after the group kills: $(procs_of "$real")" >> "$out"
  echo "$t: done" >> "$DL_OUT/40-summary.txt"
done
exit 0
