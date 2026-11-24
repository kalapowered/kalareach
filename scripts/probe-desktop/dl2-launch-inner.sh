#!/bin/bash
# dl2-launch-inner.sh: runs inside the one dbus-run-session of dl2-launch.sh (DL_OUT, DL_TMP, DISPLAY, XAUTHORITY exported).
: "${DL_OUT:?}" "${DL_TMP:?}"
groups=()
finish() {
  local g
  for g in "${groups[@]}"; do kill -KILL -- "-$g" 2> /dev/null; done
}
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT HUP
owner_of() { busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s "$1" 2>&1; }
procs_of() { # procs_of <exe-real-path>
  local p
  for p in /proc/[0-9]*; do
    [ "$(readlink "$p/exe" 2> /dev/null)" = "$1" ] && printf '%s ' "${p#/proc/}"
  done
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
  env HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" XDG_CACHE_HOME="$home/.cache" \
    setsid "$exe" > "$DL_TMP/first-$t.log" 2>&1 &
  first=$!
  groups+=("$first")
  sleep 3
  {
    echo "after the first start (3 s): processes: $(procs_of "$real")"
    if [ "$appid" != - ]; then
      echo "owner of $appid:"; owner_of "$appid"
      echo "name owner:"; busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetNameOwner s "$appid" 2>&1
    fi
  } >> "$out" 2>&1
  start=$(date +%s%N)
  env HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" XDG_CACHE_HOME="$home/.cache" \
    setsid "$exe" > "$DL_TMP/second-$t.log" 2>&1 &
  second=$!
  groups+=("$second")
  for _ in $(seq 1 20); do kill -0 "$second" 2> /dev/null || break; sleep 0.1; done
  if kill -0 "$second" 2> /dev/null; then
    echo "second start: still running after 2 s (group $second)" >> "$out"
  else
    wait "$second"
    echo "second start: exited with $? after $((($(date +%s%N) - start) / 1000000)) ms" >> "$out"
  fi
  sleep 2
  echo "processes of the target after the second start: $(procs_of "$real")" >> "$out"
  { echo "files written inside the disposable home:"; find "$home" -type f -newer "$ref" 2>&1; } >> "$out" 2>&1
  kill -KILL -- "-$first" 2> /dev/null
  kill -KILL -- "-$second" 2> /dev/null
  sleep 1
  echo "processes of the target after the group kills: $(procs_of "$real")" >> "$out"
  echo "$t: done" >> "$DL_OUT/40-summary.txt"
done
exit 0
