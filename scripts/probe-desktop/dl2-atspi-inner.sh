#!/bin/bash
# dl2-atspi-inner.sh: runs inside the one dbus-run-session of dl2-atspi.sh (DL_OUT, DL_TMP, DISPLAY and XAUTHORITY are exported).
# Records the real reply forms of: the accessibility bus address, IsEnabled, the registry's ChildCount, the first application
# (a child of the registry root), its first child (an element) and that element's Name, with gdbus (typed) and with dbus-send
# (the form a client would use; GetChildAtIndex takes a signed 32-bit integer). Ends what it started on every exit: the launcher (which starts the accessibility bus and the registry) and the application each run in a group of their own (setsid) and the group is killed.
: "${DL_OUT:?}" "${DL_TMP:?}"
pids=()
finish() { local p; for p in "${pids[@]}"; do kill -KILL -- "-$p" 2> /dev/null || kill -KILL "$p" 2> /dev/null; done; for p in "${pids[@]}"; do wait "$p" 2> /dev/null; done; }
trap finish EXIT
trap 'exit 143' TERM
trap 'exit 130' INT HUP
rec() { local name=$1; shift; { printf '$'; printf ' %q' "$@"; printf '\n'; "$@"; printf '== exit %s\n' "$?"; } > "$DL_OUT/$name.txt" 2>&1; }

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
count() { gdbus call --address "$addr" --dest "$1" --object-path "$2" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount 2> /dev/null; }
rec 20-count-empty gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount
rec 21-count-empty-dbussend dbus-send --address="$addr" --print-reply --dest="$reg" "$root" org.freedesktop.DBus.Properties.Get string:org.a11y.atspi.Accessible string:ChildCount

# A GTK application, with a disposable home so that what it writes at startup can be listed.
app=$(command -v gnome-calculator || command -v galculator)
[ -n "$app" ] || { echo "no GTK application installed" > "$DL_OUT/30-fail.txt"; exit 0; }
mkdir -p -- "$DL_TMP/apphome"
ref="$DL_TMP/apphome.ref"
: > "$ref"
setsid env HOME="$DL_TMP/apphome" XDG_CONFIG_HOME="$DL_TMP/apphome/.config" XDG_DATA_HOME="$DL_TMP/apphome/.local/share" XDG_CACHE_HOME="$DL_TMP/apphome/.cache" \
  NO_AT_BRIDGE=0 GTK_A11Y=atspi "$app" > "$DL_OUT/31-app.log" 2>&1 &
pids+=("$!")
for _ in $(seq 1 40); do
  out=$(count "$reg" "$root")
  [[ $out =~ \<([0-9]+)\> ]] && [ "${BASH_REMATCH[1]}" -ge 1 ] && break
  sleep 0.25
done
echo "application: $app" > "$DL_OUT/32-app-path.txt"
rec 33-count-with-app gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount
rec 34-child0-gdbus gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.a11y.atspi.Accessible.GetChildAtIndex 0
rec 35-child0-dbussend dbus-send --address="$addr" --print-reply --dest="$reg" "$root" org.a11y.atspi.Accessible.GetChildAtIndex int32:0
child=$(gdbus call --address "$addr" --dest "$reg" --object-path "$root" --method org.a11y.atspi.Accessible.GetChildAtIndex 0 2> /dev/null)
if [[ $child =~ \(\'([^\']+)\',\ objectpath\ \'([^\']+)\'\) ]]; then
  abus=${BASH_REMATCH[1]}; apath=${BASH_REMATCH[2]}
  rec 36-app-childcount gdbus call --address "$addr" --dest "$abus" --object-path "$apath" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible ChildCount
  element=$(gdbus call --address "$addr" --dest "$abus" --object-path "$apath" --method org.a11y.atspi.Accessible.GetChildAtIndex 0 2> /dev/null)
  echo "$element" > "$DL_OUT/37-element-reply.txt"
  if [[ $element =~ \(\'([^\']+)\',\ objectpath\ \'([^\']+)\'\) ]]; then
    rec 38-element-name gdbus call --address "$addr" --dest "${BASH_REMATCH[1]}" --object-path "${BASH_REMATCH[2]}" --method org.freedesktop.DBus.Properties.Get org.a11y.atspi.Accessible Name
  else
    echo "no element in: $element" > "$DL_OUT/38-fail.txt"
  fi
else
  echo "no application child in: $child" > "$DL_OUT/36-fail.txt"
fi
# What the application wrote at startup, inside its disposable home.
{ echo "-- files newer than the start:"; find "$DL_TMP/apphome" -type f -newer "$ref" 2>&1; } > "$DL_OUT/39-startup-writes.txt"
exit 0
