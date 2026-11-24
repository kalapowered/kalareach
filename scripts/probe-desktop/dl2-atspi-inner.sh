#!/bin/bash
# dl2-atspi-inner.sh: runs inside the one dbus-run-session of dl2-atspi.sh (DL_OUT, DL_TMP, DISPLAY and XAUTHORITY are exported).
# Records the real reply forms of: the accessibility bus address, IsEnabled, the registry's ChildCount, the first application
# (a child of the registry root), the application's own ChildCount (read every 0.5 s for 10 s), its first child (an element) and
# that element's Name, with gdbus (typed) and with dbus-send. dbus-send gets the bus by --bus=, which registers on the bus with
# Hello as a client does; GetChildAtIndex takes a signed 32-bit integer. The application runs twice, one after the other: with
# GTK_A11Y and NO_AT_BRIDGE forced on, then with both unset. Every query is bounded to 5 s. Ends what it started on every exit:
# the launcher (which starts the accessibility bus and the registry) and each application run in a group of their own (setsid)
# and the group is killed.
: "${DL_OUT:?}" "${DL_TMP:?}"
pids=()
finish() { local p; for p in "${pids[@]}"; do kill -KILL -- "-$p" 2> /dev/null || kill -KILL "$p" 2> /dev/null; done; for p in "${pids[@]}"; do wait "$p" 2> /dev/null; done; }
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT HUP
rec() { local name=$1; shift; { printf '$'; printf ' %q' "$@"; printf '\n'; "$@"; printf '== exit %s\n' "$?"; } > "$DL_OUT/$name.txt" 2>&1; }
now_ms() { echo $(($(date +%s%N) / 1000000)); }
q=(timeout 5)

rec 09-dbus-send-help bash -c 'dbus-send --version; dbus-send --help 2>&1'
launcher=""
for p in /usr/libexec/at-spi-bus-launcher /usr/lib/at-spi2-core/at-spi-bus-launcher /usr/lib/at-spi2/at-spi-bus-launcher; do
  [ -x "$p" ] && { launcher=$p; break; }
done
[ -n "$launcher" ] || { echo "at-spi-bus-launcher not found" > "$DL_OUT/10-fail.txt"; exit 1; }
echo "launcher: $launcher" > "$DL_OUT/10-launcher.txt"
rec 11-before-launch busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.a11y.Bus
setsid "$launcher" --launch-immediately > "$DL_OUT/12-launcher.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 25); do
  [ "$(busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.a11y.Bus 2> /dev/null)" = "b true" ] && break
  sleep 0.2
done
rec 13-owner busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus NameHasOwner s org.a11y.Bus
rec 14-getaddress gdbus call --session --dest org.a11y.Bus --object-path /org/a11y/bus --method org.a11y.Bus.GetAddress
addr=$(gdbus call --session --dest org.a11y.Bus --object-path /org/a11y/bus --method org.a11y.Bus.GetAddress 2> /dev/null)
if [[ $addr =~ \(\'([^\']+)\',\) ]]; then addr=${BASH_REMATCH[1]}; else echo "no address: $addr" > "$DL_OUT/15-fail.txt"; exit 1; fi
rec 16-isenabled gdbus call --session --dest org.a11y.Bus --object-path /org/a11y/bus --method org.freedesktop.DBus.Properties.Get org.a11y.Status IsEnabled
rec 17-isenabled-dbussend dbus-send --session --print-reply --dest=org.a11y.Bus /org/a11y/bus org.freedesktop.DBus.Properties.Get string:org.a11y.Status string:IsEnabled
root=/org/a11y/atspi/accessible/root
reg=org.a11y.atspi.Registry
count() { "${q[@]}" gdbus call --address "$addr" --dest "$1" --object-path "$2" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount 2> /dev/null; }
rec 20-count-empty "${q[@]}" gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount
rec 21-count-empty-dbussend "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$reg" "$root" org.freedesktop.DBus.Properties.Get string:org.a11y.atspi.Accessible string:ChildCount

# A GTK application, with a disposable home so that what it writes at startup can be listed.
app=$(command -v gnome-calculator || command -v galculator)
[ -n "$app" ] || { echo "no GTK application installed" > "$DL_OUT/30-fail.txt"; exit 0; }
echo "application: $app" > "$DL_OUT/30-app-path.txt"

# pass <label> <env argument...>: start the application with those env arguments (they come before the home variables, as env
# takes its options first), then query it. <label> starts the name of every file of the pass.
pass() {
  local label=$1 app_pid out i t0 ms first_ms="" child abus apath element ebus epath series
  shift
  local home="$DL_TMP/apphome-$label" ref="$DL_TMP/apphome-$label.ref"
  series="$DL_OUT/$label-36-app-childcount-series.txt"
  mkdir -p -- "$home"
  : > "$ref"
  setsid env "$@" HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_DATA_HOME="$home/.local/share" XDG_CACHE_HOME="$home/.cache" "$app" > "$DL_OUT/$label-31-app.log" 2>&1 &
  app_pid=$!
  pids+=("$app_pid")
  out=""
  for i in $(seq 1 40); do
    out=$(count "$reg" "$root")
    [[ $out =~ \<([0-9]+)\> ]] && [ "${BASH_REMATCH[1]}" -ge 1 ] && break
    sleep 0.25
  done
  echo "env arguments: $*; registry ChildCount after $i reads: ${out:-no reply}" > "$DL_OUT/$label-32-start.txt"
  rec "$label-33-count-with-app" "${q[@]}" gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount
  rec "$label-33b-count-with-app-dbussend" "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$reg" "$root" org.freedesktop.DBus.Properties.Get string:org.a11y.atspi.Accessible string:ChildCount
  rec "$label-34-child0-gdbus" "${q[@]}" gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.a11y.atspi.Accessible.GetChildAtIndex 0
  rec "$label-35-child0-dbussend" "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$reg" "$root" org.a11y.atspi.Accessible.GetChildAtIndex int32:0
  child=$("${q[@]}" gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.a11y.atspi.Accessible.GetChildAtIndex 0 2> /dev/null)
  if [[ $child =~ \(\'([^\']+)\',\ objectpath\ \'([^\']+)\'\) ]] && [ "${BASH_REMATCH[2]}" != /org/a11y/atspi/null ]; then
    abus=${BASH_REMATCH[1]}; apath=${BASH_REMATCH[2]}
    # The application's own child count, read every 0.5 s for 10 s: the series shows when its first child appears, if it does.
    t0=$(now_ms)
    : > "$series"
    while ms=$(($(now_ms) - t0)); [ "$ms" -le 10000 ]; do
      out=$("${q[@]}" gdbus call --address "$addr" --dest "$abus" --object-path "$apath" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount 2>&1)
      printf '%s ms: %s\n' "$ms" "$out" >> "$series"
      if [ -z "$first_ms" ] && [[ $out =~ \<([0-9]+)\> ]] && [ "${BASH_REMATCH[1]}" -ge 1 ]; then first_ms=$ms; fi
      sleep 0.5
    done
    echo "first reading of at least 1: ${first_ms:-none within 10 s}" >> "$series"
    rec "$label-37-app-childcount-dbussend" "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$abus" "$apath" org.freedesktop.DBus.Properties.Get string:org.a11y.atspi.Accessible string:ChildCount
    rec "$label-38-element-gdbus" "${q[@]}" gdbus call --address "$addr" --dest "$abus" --object-path "$apath" --method org.a11y.atspi.Accessible.GetChildAtIndex 0
    rec "$label-38b-element-dbussend" "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$abus" "$apath" org.a11y.atspi.Accessible.GetChildAtIndex int32:0
    element=$("${q[@]}" gdbus call --address "$addr" --dest "$abus" --object-path "$apath" --method org.a11y.atspi.Accessible.GetChildAtIndex 0 2> /dev/null)
    if [[ $element =~ \(\'([^\']+)\',\ objectpath\ \'([^\']+)\'\) ]]; then
      ebus=${BASH_REMATCH[1]}; epath=${BASH_REMATCH[2]}
      echo "element: $ebus $epath" > "$DL_OUT/$label-39-element-path.txt"
      if [ "$epath" = /org/a11y/atspi/null ]; then
        echo "the element is the null reference: no Name read" >> "$DL_OUT/$label-39-element-path.txt"
      else
        rec "$label-39a-element-name-gdbus" "${q[@]}" gdbus call --address "$addr" --dest "$ebus" --object-path "$epath" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible Name
        rec "$label-39b-element-name-dbussend" "${q[@]}" dbus-send --bus="$addr" --print-reply --dest="$ebus" "$epath" org.freedesktop.DBus.Properties.Get string:org.a11y.atspi.Accessible string:Name
      fi
    else
      echo "no element in: $element" > "$DL_OUT/$label-39-fail.txt"
    fi
  else
    echo "no application child (or the null reference) in: $child" > "$DL_OUT/$label-36-fail.txt"
  fi
  # What the application wrote at startup, inside its disposable home.
  { echo "-- files newer than the start, size and path:"; find "$home" -type f -newer "$ref" -printf '%s %P\n' 2>&1; } > "$DL_OUT/$label-41-startup-writes.txt"
  kill -KILL -- "-$app_pid" 2> /dev/null
  wait "$app_pid" 2> /dev/null
}

pass forced NO_AT_BRIDGE=0 GTK_A11Y=atspi
# Wait (at most 5 s) until the registry no longer lists the first application, so the second pass reads its own.
out=""
for _ in $(seq 1 10); do
  out=$(count "$reg" "$root")
  [[ $out =~ \<0\> ]] && break
  sleep 0.5
done
echo "registry ChildCount after the first application ended: ${out:-no reply}" > "$DL_OUT/40-between-passes.txt"
pass default -u GTK_A11Y -u NO_AT_BRIDGE
exit 0
