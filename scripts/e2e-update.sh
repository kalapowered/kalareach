#!/usr/bin/env bash
# Runs the desktop and permission demonstrations on one release, updates the host to the next
# release, and runs both again on the same state, with an attach from the command line after each.
#
#   scripts/e2e-update.sh --first ARCHIVE --second ARCHIVE [--screenshots DIR] [--logs DIR] [--identity ad-hoc|developer-id]
#
# `--first` and `--second` are two releases' archives for this Mac's own target, in the order they
# are released. The first is installed into a store of this run's own, its programs run both
# demonstrations (`scripts/e2e-desktop.sh` and `scripts/e2e-permissions.sh`, which keep their state
# in directories that outlive them) and a session is attached to from the command line. Then
# `kr host update` takes the host to the second release, and the same steps run on its programs and
# on the same state. A screenshot of the screen is taken before the first run and after the last, and
# what each demonstration said is copied to `--logs` when it is named.
#
# What it holds after the update:
#   * both demonstrations pass on the second release, as on the first;
#   * the desktop identity a session is bound to is the one it was before the update;
#   * an attach from the command line to a session of the second release shows its screen, with the
#     output of the `git` and `cargo` its shell ran, so the host runs a person's development tools
#     unsandboxed.
# With `--identity developer-id`, it holds as well that both releases' programs are signed by one
# Developer ID team, and that every permission record the second release reports, whole, is the one
# the first reported; the time an answer was taken and the revision an action binds to are the two
# members that may differ. An ad hoc signature gives each build an identity of its own, so a record
# taken against the executable's identity is stale after an update by design, and an ad hoc run says
# that the records were not compared and does not claim them.
#
# The demonstrations need a person's graphical login session, so this runs on a Mac at its console.
# Every path it uses is on the internal disk.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

first=""
second=""
screenshots=""
logs=""
identity="ad-hoc"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --first) first="$2"; shift 2 ;;
    --second) second="$2"; shift 2 ;;
    --screenshots) screenshots="$2"; shift 2 ;;
    --logs) logs="$2"; shift 2 ;;
    --identity) identity="$2"; shift 2 ;;
    *) echo "e2e-update: unknown argument $1" >&2; exit 2 ;;
  esac
done
for need in first second; do
  if [ -z "${!need}" ]; then
    echo "e2e-update: --${need} is needed" >&2
    exit 2
  fi
done
case "$identity" in ad-hoc | developer-id) ;; *) echo "e2e-update: --identity is ad-hoc or developer-id" >&2; exit 2 ;; esac
if [ "$(uname -s)" != Darwin ]; then
  echo "e2e-update: the demonstrations are of a Mac's desktop" >&2
  exit 2
fi

started="$(date '+%Y-%m-%d %H:%M:%S')"
work="$(mktemp -d "${TMPDIR:-/tmp}/kr-e2e-update.XXXXXX")"
# An installed release is read-only, so its directories are opened to removal first.
cleanup() {
  if [ -n "$logs" ]; then
    mkdir -p "$logs"
    cp "$work"/logs/* "$logs"/ 2> /dev/null || true
  fi
  chmod -R u+w "${work:?}" 2> /dev/null || true
  rm -rf "${work:?}"
}
trap cleanup EXIT
mkdir -p "$work/home" "$work/logs" "$work/artifacts" "$work/unpacked"
failed=0
fail() {
  echo "FAILED: $*"
  failed=1
}

shot() {
  [ -n "$screenshots" ] || return 0
  mkdir -p "$screenshots"
  if command -v peekaboo > /dev/null 2>&1; then
    peekaboo see --mode screen --no-elements --path "$screenshots/$1.png" > /dev/null 2>&1 \
      && echo "screenshot: $screenshots/$1.png" || echo "no screenshot: peekaboo could not capture the screen"
  else
    echo "no screenshot: peekaboo is not here"
  fi
}

host_kr() {
  env -i HOME="$work/home" PATH=/usr/bin:/bin "$work/store/current/bin/kr" "$@"
}

echo "installing the first release into a store of this run's own"
tar -xzf "$first" -C "$work/unpacked"
first_tree="$(find "$work/unpacked" -mindepth 1 -maxdepth 1 -type d | head -1)"
env -i HOME="$work/home" PATH=/usr/bin:/bin "$first_tree/bin/kr" host install --store "$work/store" > /dev/null
echo "current: $(host_kr --json host versions | python3 -c 'import json,sys; print([r["release"] for r in json.load(sys.stdin)["releases"] if r["current"]][0])')"

# One demonstration run: both scripts on the programs of the release that is current, on state that
# outlives each of them, with what each said kept for the comparison.
demonstrate() {
  local label="$1"
  local programs="$work/store/current/bin"
  KR_E2E_PROGRAMS="$programs" KR_E2E_STATE="$work/state-desktop" bash "$root/scripts/e2e-desktop.sh" "$work/logs/desktop-$label.log" > /dev/null 2>&1 \
    || fail "the desktop demonstration did not pass on the $label release; see $work/logs/desktop-$label.log"
  KR_E2E_PROGRAMS="$programs" KR_E2E_STATE="$work/state-permissions" KR_TEST_ARTIFACTS_DIR="$work/artifacts" \
    bash "$root/scripts/e2e-permissions.sh" "$work/logs/permissions-$label.log" > /dev/null 2>&1 \
    || fail "the permission demonstration did not pass on the $label release; see $work/logs/permissions-$label.log"
  cp "$work/artifacts/permissions/doctor.json" "$work/logs/doctor-$label.json" 2> /dev/null \
    || fail "the permission demonstration left no capability records on the $label release"
  grep -q 'every demonstration passed' "$work/logs/desktop-$label.log" 2> /dev/null || fail "the desktop demonstration did not end in a pass on the $label release"
  echo "demonstrations on the $label release: done"
}

# An attach from the command line to a session of the current release's own daemon, in a terminal of
# its own: the attach has to put the session's screen on it.
attach() {
  local label="$1"
  python3 "$root/scripts/e2e-update-attach.py" "$work/store/current/bin" \
    || fail "the attach from the command line did not show a session on the $label release"
}

shot "before"
demonstrate first
attach first

echo "updating to the second release"
env -i HOME="$work/home" PATH=/usr/bin:/bin "$work/store/current/bin/kr" host update --archive "$second" > "$work/logs/update.log" 2>&1 \
  || { cat "$work/logs/update.log"; fail "the update did not complete"; }
second_release="$(basename "$second" | sed -E 's/^.*-([0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12})\.tar\.gz$/\1/')"
host_kr --json host versions > "$work/versions.json"
python3 - "$work/versions.json" "$second_release" <<'PY' || failed=1
import json, sys
releases = json.load(open(sys.argv[1]))["releases"]
current = [r["release"] for r in releases if r["current"]]
assert len(releases) == 2 and len(current) == 1, f"the store holds {releases}"
assert current == [sys.argv[2]], f"the current release is {current}, and the update was to {sys.argv[2]}"
print("current after the update:", current[0], "; kept:", sorted(r["release"] for r in releases))
PY

demonstrate second
attach second
shot "after"

desktop_of() { sed -n 's/^  ok: the create receipt records the desktop: //p' "$1" | head -1; }
before="$(desktop_of "$work/logs/desktop-first.log")"
after="$(desktop_of "$work/logs/desktop-second.log")"
if [ -z "$before" ] || [ "$before" != "$after" ]; then
  fail "the desktop identity changed across the update: '$before' then '$after'"
else
  echo "ok: the desktop identity is the same after the update: $before"
fi

# The team a Developer ID signature names; nothing for an ad hoc signature or none.
team_of() {
  local details
  details="$(/usr/bin/codesign -dv --verbose=2 "$1" 2>&1)" || return 0
  case "$details" in
    *"Authority=Developer ID Application:"*) printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | head -1 ;;
  esac
}

# What the host published about each capability, whole: every member of every record but the time
# the answer was taken and the revision an action binds to.
capability_records() {
  /usr/bin/python3 - "$1" <<'PY'
import json, sys

def without_when(value):
    if isinstance(value, dict):
        return {k: without_when(v) for k, v in value.items() if k not in ("observed_at_ms", "revision")}
    if isinstance(value, list):
        return [without_when(v) for v in value]
    return value

records = json.load(open(sys.argv[1]))["environment"]["desktop"]["capabilities"]
assert records, "the host published no capability record"
print(json.dumps(without_when(records), sort_keys=True, indent=1))
PY
}

if [ "$identity" = developer-id ]; then
  first_team="$(team_of "$first_tree/bin/kr")"
  second_team="$(team_of "$work/store/current/bin/kr")"
  if [ -z "$first_team" ] || [ "$first_team" != "${second_team}" ]; then
    fail "--identity developer-id needs both releases signed by one Developer ID team; the first is '${first_team:-not Developer ID}' and the second '${second_team:-not Developer ID}'"
  elif ! capability_records "$work/logs/doctor-first.json" > "$work/logs/records-first.json" \
    || ! capability_records "$work/logs/doctor-second.json" > "$work/logs/records-second.json"; then
    fail "the capability records could not be read"
  elif ! cmp -s "$work/logs/records-first.json" "$work/logs/records-second.json"; then
    fail "the permission records changed across the update; compare $work/logs/records-first.json and records-second.json"
  else
    echo "ok: every permission record is the same after the update, signed by team $first_team"
  fi
else
  echo "not compared: the permission records of an ad hoc release are stale after an update by design, so only a Developer ID run can say they are the same"
fi

# The Dialogs check: a dialog the run raised is a finding, whoever answers it.
if /usr/bin/log show --start "$started" --predicate 'process == "SecurityAgent"' 2> /dev/null | grep -q 'SecurityAgent'; then
  echo "NOTE: SecurityAgent logged since this run began; read it before taking this run as dialog-free"
fi

[ "$failed" -eq 0 ] || exit 1
echo "every check of the update repeat passed"
