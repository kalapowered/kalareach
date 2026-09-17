#!/usr/bin/env bash
# Demonstrates the desktop execution context on the machine this runs on.
#
# A real control daemon, a real worker in the user's own graphical login session, a real shell, a
# real graphical application started from that shell, and the host's real power assertion. Each
# step checks something section 3 requires:
#
#   * a session created in the desktop execution context, and the desktop identity it records
#   * a graphical application started from that session's shell, visible in the login session
#   * the same desktop identity read back through `kr status --json`
#   * the power setting enabled, an assertion taken while a request the host accepted is
#     outstanding, and the operating system's own listing agreeing that it is held
#   * the assertion released when that request finishes
#   * an invisible session that keeps the desktop rather than becoming a headless one
#   * a session whose login session has ended closing with `desktop_lost`
#
# Every path this script uses is on the internal disk, and the binaries it starts are copied there
# first. A process a service manager launches is its own identity to the operating system, and one
# that reaches a removable volume asks the person at the machine for permission.
#
# Nothing the person at this machine owns is touched: the graphical application is a new instance
# started in the background, and this script ends only the processes it started itself.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

echo "kalareach desktop demonstration"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo

uid="$(id -u)"
failed=0

fail() {
  echo "FAILED: $*"
  failed=1
}

require() {
  if [ "$1" != "$2" ]; then
    fail "$3 (expected $2, got $1)"
  else
    echo "  ok: $3"
  fi
}

# A graphical login session is what this demonstration is about. Without one there is nothing to
# show, and saying so is more useful than a failure that means "not applicable".
if ! /bin/launchctl print "gui/$uid" >/dev/null 2>&1; then
  echo "this host has no graphical login session, so there is no desktop to demonstrate"
  exit 0
fi
echo "graphical login session: $(/bin/launchctl print "gui/$uid" | awk '/^\thandle = /{print $3; exit}')"
echo "this shell's login context: $(/bin/launchctl managername)"
echo

echo "building the host"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build -q -p kr-controller -p kr-worker -p kr-cli

# The run's own root, on the internal disk, with the binaries beside it.
run_root="$(mktemp -d "${TMPDIR:-/tmp}/kalareach-desktop.XXXXXX")"
mkdir -p "$run_root/bin" "$run_root/r" "$run_root/s" "$run_root/evidence"
# The host's own roots are owner-only and it checks them rather than assuming: /tmp is
# world-writable by design and a directory this run created with anything looser would be refused.
chmod 700 "$run_root/r" "$run_root/s"
# The build products, wherever this workspace's build cache is. They are copied to the internal
# disk before anything is started, because a process a service manager launches asks the person at
# the machine for permission the first time it reaches a removable volume.
target_dir="${CARGO_TARGET_DIR:-$root/target}"
for binary in kr-controller kr-worker kr; do
  if [ ! -x "$target_dir/debug/$binary" ]; then
    fail "the build did not produce $binary"
    exit 1
  fi
  cp "$target_dir/debug/$binary" "$run_root/bin/$binary"
done
export KR_RUNTIME_DIR="$run_root/r"
export KR_STATE_DIR="$run_root/s"
kr="$run_root/bin/kr"

started_pids=()
gui_pids=()

cleanup() {
  # Only what this script started, by the identifiers it recorded.
  for session in $("$kr" list --json 2>/dev/null | /usr/bin/python3 -c \
    'import json,sys
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in document.get("sessions", []):
    print(entry["display_number"])' 2>/dev/null); do
    "$kr" close "$session" >/dev/null 2>&1 || true
  done
  for pid in "${gui_pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  for pid in "${started_pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  sleep 1
  local survivors
  survivors="$(pgrep -u "$uid" -f "$run_root" 2>/dev/null | grep -v "^$$\$" || true)"
  if [ -n "$survivors" ]; then
    echo "FAILED: these processes outlived the script"
    # shellcheck disable=SC2046,SC2086
    ps -o pid=,command= -p $(printf '%s' "$survivors" | tr '\n' ' ') || true
    failed=1
  else
    echo "no process this run started is still running"
    rm -rf "$run_root"
  fi
}
trap cleanup EXIT

echo "starting the control daemon"
"$run_root/bin/kr-controller" \
  --runtime-dir "$run_root/r" \
  --state-dir "$run_root/s" \
  --worker "$run_root/bin/kr-worker" \
  >"$run_root/evidence/controller.log" 2>&1 &
started_pids+=("$!")
# A minute of asking, because this is a real daemon on a real machine: it opens its registry,
# builds or reads its signing identity through the platform's credential store, and publishes its
# socket, and a machine with something else running takes longer over all three. The wall clock is
# what is reported, not the waiting, so a start that is merely slow reads as slow rather than as
# broken. It is an allowance rather than a deadline: the last question is answered or refused
# however long it takes.
daemon_started_at="$(date +%s)"
daemon_deadline=$((daemon_started_at + 60))
while [ "$(date +%s)" -lt "$daemon_deadline" ]; do
  if "$kr" doctor --json >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
daemon_waited=$(( $(date +%s) - daemon_started_at ))
if ! "$kr" doctor --json >"$run_root/evidence/doctor.json" 2>&1; then
  fail "the control daemon did not start"
  echo "waited $daemon_waited seconds for it"
  echo "--- what the daemon printed ---"
  tail -20 "$run_root/evidence/controller.log" || true
  echo "--- what kr said ---"
  tail -5 "$run_root/evidence/doctor.json" || true
  # A daemon that printed nothing at all has not reached the point of serving. The step before
  # that is opening this platform's credential store for its own signing key, which can wait on
  # the person at the machine, so say so rather than leaving the reason to be guessed at.
  if [ ! -s "$run_root/evidence/controller.log" ]; then
    echo "the daemon printed nothing, so it had not started serving: on a platform whose"
    echo "credential store prompts, it waits there until the prompt is answered"
  fi
  exit 1
fi

echo "the control daemon answered after $daemon_waited seconds"

# One reader for every document this script inspects, so a shape that changed is a failure here
# rather than a silently empty string somewhere later.
read_json() {
  /usr/bin/python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    if document is None:
        break
    document = document.get(key) if isinstance(document, dict) else None
print("" if document is None else document)
' "$1" "$2"
}

echo
echo "1. a session in the desktop execution context"
"$kr" new --invisible --desktop --json >"$run_root/evidence/create-desktop.json"
desktop_display="$(read_json "$run_root/evidence/create-desktop.json" display_number)"
require "$(read_json "$run_root/evidence/create-desktop.json" worker_profile)" \
  "desktop_bound" "the session runs in the desktop execution context"
desktop_id="$(read_json "$run_root/evidence/create-desktop.json" desktop.desktop_session_id)"
if [ -z "$desktop_id" ]; then
  fail "the create receipt records the desktop the session was bound to"
else
  echo "  ok: the create receipt records the desktop: $desktop_id"
fi
for part in "uid=$uid" "session=" "generation=" "boot="; do
  case "$desktop_id" in
    *"$part"*) echo "  ok: the desktop identity binds $part" ;;
    *) fail "the desktop identity binds $part" ;;
  esac
done

echo
echo "2. a graphical application started from that session's shell"
cat >"$run_root/bin/launch-gui.sh" <<'SCRIPT'
#!/bin/sh
# The root shell of a desktop-bound session. It records the login context it is in, starts a new
# instance of a graphical application in the background, and records what the login session then
# has registered. Then it waits, so the session stays live while the evidence is read.
evidence="$1"
/bin/launchctl managername > "$evidence/managername" 2>&1
/usr/bin/pgrep -u "$(id -u)" -f "TextEdit.app/Contents/MacOS/TextEdit" > "$evidence/textedit-before" 2>/dev/null || true
# A new instance, in the background: nothing the person at the machine is using is touched, and
# nothing takes the foreground.
/usr/bin/open -g -n -a TextEdit
sleep 3
/usr/bin/lsappinfo list > "$evidence/lsappinfo" 2>&1 || true
/usr/bin/pgrep -u "$(id -u)" -f "TextEdit.app/Contents/MacOS/TextEdit" > "$evidence/textedit-after" 2>/dev/null || true
exec cat
SCRIPT
chmod +x "$run_root/bin/launch-gui.sh"
cat >"$run_root/bin/session-shell.sh" <<SCRIPT
#!/bin/sh
exec "$run_root/bin/launch-gui.sh" "$run_root/evidence"
SCRIPT
chmod +x "$run_root/bin/session-shell.sh"
"$kr" new --invisible --desktop --shell "$run_root/bin/session-shell.sh" --json \
  >"$run_root/evidence/create-gui.json"
gui_display="$(read_json "$run_root/evidence/create-gui.json" display_number)"
for _ in $(seq 1 100); do
  [ -s "$run_root/evidence/textedit-after" ] && break
  sleep 0.2
done
require "$(cat "$run_root/evidence/managername" 2>/dev/null || true)" "Aqua" \
  "the invisible session's shell is in the graphical login context"
new_gui="$(comm -13 <(sort -u "$run_root/evidence/textedit-before" 2>/dev/null || true) \
  <(sort -u "$run_root/evidence/textedit-after" 2>/dev/null || true) || true)"
if [ -z "$new_gui" ]; then
  fail "a graphical application started from the session's shell"
else
  for pid in $new_gui; do
    gui_pids+=("$pid")
  done
  echo "  ok: a graphical application started from the session's shell: $new_gui"
fi
if grep -q "TextEdit" "$run_root/evidence/lsappinfo" 2>/dev/null; then
  echo "  ok: the login session has it registered as one of its applications"
else
  fail "the login session has the application registered"
fi

echo
echo "3. the desktop identity read back through kr status"
"$kr" status "$desktop_display" --json >"$run_root/evidence/status.json"
require "$(read_json "$run_root/evidence/status.json" desktop.desktop_session_id)" "$desktop_id" \
  "kr status reports the desktop the session was created on"
require "$(read_json "$run_root/evidence/status.json" worker_profile)" "desktop_bound" \
  "kr status reports the execution context"

echo
echo "4. the power setting, and the assertion it takes for work the host has accepted"
"$kr" host power --json >"$run_root/evidence/power-off.json"
require "$(read_json "$run_root/evidence/power-off.json" power.setting)" "off" \
  "the setting is off until the owner chooses it"
require "$(read_json "$run_root/evidence/power-off.json" power.active)" "False" \
  "and nothing is held"
"$kr" host power --set mains_only --json >"$run_root/evidence/power-on.json"
require "$(read_json "$run_root/evidence/power-on.json" power.setting)" "mains_only" \
  "the owner's choice is recorded"
require "$(read_json "$run_root/evidence/power-on.json" power.active)" "False" \
  "enabling the setting alone holds nothing"
power_source="$(read_json "$run_root/evidence/power-on.json" power.power_source)"
echo "  this host is running on $power_source power"

# A closure the host has accepted and not finished is a request outstanding. Closing the session
# that started the graphical application is what produces one here.
"$kr" close "$gui_display" >/dev/null 2>&1 &
close_job=$!
held=""
for _ in $(seq 1 100); do
  "$kr" host power --json >"$run_root/evidence/power-held.json" 2>/dev/null || true
  if [ "$(read_json "$run_root/evidence/power-held.json" power.active)" = "True" ]; then
    held="$(read_json "$run_root/evidence/power-held.json" power.holder)"
    break
  fi
  sleep 0.2
done
# Only the close, not every background job: the control daemon is one of those and it runs until
# this script ends.
wait "$close_job" || true
if [ "$power_source" != "mains" ]; then
  echo "  this host is not on mains power, so a mains-only setting holds nothing here"
  echo "  withheld: $(read_json "$run_root/evidence/power-held.json" power.withheld_reason)"
elif [ -z "$held" ]; then
  fail "an assertion is held while a request the host accepted is outstanding"
else
  echo "  ok: an assertion is held: $held"
  echo "  reason: $(read_json "$run_root/evidence/power-held.json" power.reason)"
  # The operating system's own listing, which is the only thing that settles whether sleep is
  # actually inhibited. The assertion names the process this host holds it on behalf of, and the
  # number after that word is what the listing is searched for.
  holder_pid="$(printf '%s' "$held" | sed -n 's/.*process \([0-9][0-9]*\).*/\1/p')"
  if [ -z "$holder_pid" ]; then
    fail "the assertion names the process it is held on behalf of"
    holder_pid="none"
  fi
  /usr/bin/pmset -g assertions >"$run_root/evidence/pmset-held.txt"
  if grep -q "pid $holder_pid)" "$run_root/evidence/pmset-held.txt"; then
    echo "  ok: the operating system lists the assertion against process $holder_pid"
    grep -n "pid $holder_pid)" "$run_root/evidence/pmset-held.txt" | head -2
  else
    fail "the operating system's own listing shows the assertion"
  fi
fi

# And it goes when the work does.
released=""
for _ in $(seq 1 150); do
  "$kr" host power --json >"$run_root/evidence/power-released.json" 2>/dev/null || true
  if [ "$(read_json "$run_root/evidence/power-released.json" power.active)" = "False" ]; then
    released="yes"
    break
  fi
  sleep 0.2
done
if [ -n "$released" ]; then
  echo "  ok: the assertion is released when the request finishes"
  echo "  withheld: $(read_json "$run_root/evidence/power-released.json" power.withheld_reason)"
else
  fail "the assertion is released when the request finishes"
fi
"$kr" host power --set off --json >"$run_root/evidence/power-restored.json"
require "$(read_json "$run_root/evidence/power-restored.json" power.setting)" "off" \
  "the setting is restored to off"

echo
echo "5. an invisible session takes this host's own execution context"
"$kr" new --invisible --json >"$run_root/evidence/create-default.json"
default_display="$(read_json "$run_root/evidence/create-default.json" display_number)"
require "$(read_json "$run_root/evidence/create-default.json" worker_profile)" "desktop_bound" \
  "an invisible session on a desktop host is not an implicit headless one"
require "$(read_json "$run_root/evidence/create-default.json" desktop.desktop_session_id)" \
  "$desktop_id" "and it kept the same desktop"
require "$(read_json "$run_root/evidence/create-default.json" execution_context_chosen)" "False" \
  "the execution context came from the host rather than the command"

echo
echo "6. a headless session is started outside the graphical login"
cat >"$run_root/bin/headless-shell.sh" <<SCRIPT
#!/bin/sh
# The root shell of a headless session. It records the login context it was started in and any
# desktop handles it was given, then waits.
/bin/launchctl managername > "$run_root/evidence/headless-managername" 2>&1
/usr/bin/printenv \
  | /usr/bin/grep -E '^(DISPLAY|WAYLAND_DISPLAY|XAUTHORITY|DBUS_SESSION_BUS_ADDRESS|XDG_SESSION_ID)=' \
  > "$run_root/evidence/headless-desktop-variables" || :
exec cat
SCRIPT
chmod +x "$run_root/bin/headless-shell.sh"
"$kr" new --invisible --headless --shell "$run_root/bin/headless-shell.sh" --json \
  >"$run_root/evidence/create-headless.json"
headless_display="$(read_json "$run_root/evidence/create-headless.json" display_number)"
for _ in $(seq 1 100); do
  [ -s "$run_root/evidence/headless-managername" ] && break
  sleep 0.2
done
require "$(read_json "$run_root/evidence/create-headless.json" worker_profile)" "headless_user" \
  "the session runs in the headless user context"
require "$(read_json "$run_root/evidence/create-headless.json" desktop.desktop_session_id)" "" \
  "and it is bound to no desktop"
require "$(cat "$run_root/evidence/headless-managername" 2>/dev/null || true)" "Background" \
  "the headless session's shell is outside the graphical login context"
if [ -s "$run_root/evidence/headless-desktop-variables" ]; then
  fail "a headless session inherits no desktop handles"
  cat "$run_root/evidence/headless-desktop-variables"
else
  echo "  ok: a headless session inherits no desktop handles"
fi

echo
echo "7. what this host says about itself"
"$kr" doctor --json >"$run_root/evidence/doctor-final.json" || true
require "$(read_json "$run_root/evidence/doctor-final.json" host.default_worker_profile)" \
  "desktop_bound" "kr doctor reports the execution context new sessions get"
/usr/bin/python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
entries = document["environment"]["persistence"]
for entry in entries:
    print("  logout:", entry["profile"], entry["persistence"], "via", entry["mechanism"])
records = document["environment"]["desktop"]["capabilities"]
for record in records:
    print("  capability:", record["capability"], record["state"], record["evidence_source"])
' "$run_root/evidence/doctor-final.json"
if /usr/bin/python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
records = document["environment"]["desktop"]["capabilities"]
bad = [r["capability"] for r in records
       if r["capability"] in ("desktop.screen_capture", "desktop.input_injection")
       and r["state"] == "qualified_available"]
sys.exit(1 if bad else 0)
' "$run_root/evidence/doctor-final.json"; then
  echo "  ok: selecting a desktop reports neither capture nor injection as available"
else
  fail "selecting a desktop reported capture or injection as available"
fi

echo
echo "8. closing the sessions this run created"
for display in "$desktop_display" "$default_display" "$headless_display"; do
  "$kr" close "$display" --json >"$run_root/evidence/close-$display.json"
  require "$(read_json "$run_root/evidence/close-$display.json" state)" "closing" \
    "session $display was asked to close"
done

echo
echo "9. a session whose login session has ended closes with desktop_lost"
if CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test -q -p kr-worker --test desktop \
  a_desktop_bound_session_closes_with_desktop_lost_when_its_login_ends \
  -- --exact --test-threads=1 >"$run_root/evidence/desktop-lost.log" 2>&1; then
  if grep -qE "^test result: ok\. 1 passed" "$run_root/evidence/desktop-lost.log"; then
    echo "  ok: the closure names the desktop rather than the shell"
  else
    cat "$run_root/evidence/desktop-lost.log"
    fail "the desktop-loss demonstration ran nothing"
  fi
else
  cat "$run_root/evidence/desktop-lost.log"
  fail "a session whose login session has ended closes with desktop_lost"
fi

echo
echo "what a real logout does is documented in docs/host/platforms.md; this script never logs"
echo "anybody out and never changes the machine's own sleep policy beyond the setting it restores."
echo
if [ "$failed" -ne 0 ]; then
  echo "one or more demonstrations failed"
  exit 1
fi
echo "every demonstration passed"
