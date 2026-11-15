#!/bin/bash
# Shared helpers of the probe's group scripts (sourced). Every probe line is
#   PROBE <group>.<n> ok|FAIL <what>
# and never carries the value of a variable, a token or any text that a unit chose.
set -u

PROBE_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SBX_DIR=$(cd "$PROBE_ROOT/../sandbox" && pwd)
TOOLS=/usr/local/lib/sandbox-probe
GUARD=/usr/local/lib/sandbox/guard.sh
: "${SBX_LOGS:?the setup step sets SBX_LOGS}"
PROBE_LINES="$SBX_LOGS/../probe-lines.txt"
PROBE_FAILS=0

emit() {
  local line
  line=$(printf 'PROBE %s %s %s' "$1" "$2" "$3" | tr -c '[:print:]' '?')
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$PROBE_LINES"
}
ok() { emit "$1" ok "$2"; }
fail() {
  emit "$1" FAIL "$2"
  PROBE_FAILS=$((PROBE_FAILS + 1))
}
# check ID WHAT COMMAND...: ok when the command succeeds.
check() {
  local id=$1 what=$2
  shift 2
  if "$@" >/dev/null 2>&1; then ok "$id" "$what"; else fail "$id" "$what"; fi
}
# refuse ID WHAT COMMAND...: ok when the command fails.
refuse() {
  local id=$1 what=$2
  shift 2
  if "$@" >/dev/null 2>&1; then fail "$id" "$what"; else ok "$id" "$what"; fi
}
group() { printf '::group::%s\n' "$1"; }
endgroup() { printf '::endgroup::\n'; }
finish() {
  printf 'PROBE-SUMMARY %s fails=%s\n' "$1" "$PROBE_FAILS"
  [ "$PROBE_FAILS" -eq 0 ]
}

# The raw output of a unit, read by the probe (a file of the runner's own).
rawlog() { cat "$SBX_LOGS/$1.log"; }
has() { grep -q -- "$2" "$SBX_LOGS/$1.log"; }
count() { grep -c -- "$2" "$SBX_LOGS/$1.log"; }

# Units in the legs' namespace as kr-legs, in the service's namespace as kr-svc, on the host's
# network as kr-legs (controls only). Output of the unit is replayed to the job log.
LEGS_BINDS=(--bind /home/kr-legs --bind /opt/kr-legs/cargo --bind /opt/kr-legs/target)
unit_legs() {
  local n=$1
  shift
  bash "$SBX_DIR/run-unit.sh" --name "$n" --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
    --log-dir "$SBX_LOGS" --guard "$GUARD" --netns sbx-legs "${LEGS_BINDS[@]}" \
    --runtime-max "${UNIT_MAX:-120}" "$@"
}
unit_svc() {
  local n=$1
  shift
  bash "$SBX_DIR/run-unit.sh" --name "$n" --user kr-svc --group kr-svc --workdir /home/kr-svc/work \
    --log-dir "$SBX_LOGS" --guard "$GUARD" --netns sbx-svc --bind /home/kr-svc \
    --runtime-max "${UNIT_MAX:-120}" "$@"
}
unit_host() {
  local n=$1
  shift
  bash "$SBX_DIR/run-unit.sh" --name "$n" --user kr-legs --group kr-legs --workdir /home/kr-legs/work \
    --log-dir "$SBX_LOGS" --host-network "${LEGS_BINDS[@]}" \
    --runtime-max "${UNIT_MAX:-120}" "$@"
}

# The runner's canary listeners (TCP, abstract and path sockets), started as root.
LISTENER_PIDFILE="$SBX_LOGS/../listeners.pid"
listeners_start() {
  [ -s "$LISTENER_PIDFILE" ] && return 0
  sudo -n /usr/bin/python3 "$TOOLS/listeners.py" "$LISTENER_PIDFILE" >"$SBX_LOGS/../listeners.out" 2>&1 &
  local i
  for i in $(seq 1 20); do
    [ -s "$LISTENER_PIDFILE" ] && return 0
    sleep 0.5
  done
  cat "$SBX_LOGS/../listeners.out" >&2
  return 1
}
listeners_stop() {
  [ -s "$LISTENER_PIDFILE" ] || return 0
  sudo -n kill "$(cat "$LISTENER_PIDFILE")" 2>/dev/null || true
  rm -f -- "$LISTENER_PIDFILE"
}
