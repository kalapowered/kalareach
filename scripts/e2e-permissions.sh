#!/usr/bin/env bash
# Demonstrates the first-start permission checks on the machine this runs on.
#
# A real control daemon, a real worker in the user's own graphical login session, and the four
# disclosed checks section 3 names, performed from inside that session's own shell: the place an
# agent's tools run. Each step checks something the specification requires:
#
#   * the capability records this host publishes, read through `kr doctor --json`, with what
#     produced each answer and what makes it stale
#   * the four disclosed checks run in the session's own execution context, each declaring its
#     effects before it runs, and each recording the subject and identity it was taken against
#   * a check that would change something is withheld, because it needs a test context of its own
#   * a tool-specific permission stays its own record and never becomes a global success
#   * the tools an agent reaches for on this desktop, exercised from the session's own shell
#   * the whole of it with no account of any kind configured
#
# Every path this script uses is on the internal disk, and the binaries it starts are copied there
# first. A process a service manager launches is its own identity to the operating system, and one
# that reaches a removable volume asks the person at the machine for permission.
#
# Nothing the person at this machine owns is touched. No check sends input to an application, none
# changes user data, and the one check that would do either is not run. Every process this script
# ends is one it started, by the identifier it recorded.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/permissions"
mkdir -p "$artefacts"

echo "kalareach first-start permission demonstration"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  artefacts: $artefacts"
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

# A graphical login session is what these permissions are about. Without one there is nothing to
# demonstrate, and a run that demonstrated nothing has not passed: it fails and says why. It runs
# where a person is logged in at the console of a Mac.
if [ "$(uname -s)" != "Darwin" ]; then
  echo "FAILED: the disclosed checks in this build are macOS operations, and this host is not macOS"
  exit 1
fi
if ! /bin/launchctl print "gui/$uid" >/dev/null 2>&1; then
  echo "FAILED: this host has no graphical login session, so there are no desktop permissions to check"
  exit 1
fi
echo "graphical login session: $(/bin/launchctl print "gui/$uid" | awk '/^\thandle = /{print $3; exit}')"
echo "this shell's login context: $(/bin/launchctl managername)"
echo

echo "building the host and the disclosed checks"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build -q -p kr-controller -p kr-worker -p kr-cli
# The checks themselves are built as their own binary, so the session's shell can run them in the
# execution context under test rather than in this script's.
checks_binary="$(CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo test -q -p kr-worker --lib \
  --no-run --message-format=json 2>/dev/null |
  /usr/bin/python3 -c '
import json, sys
for line in sys.stdin:
    try:
        message = json.loads(line)
    except ValueError:
        continue
    target = message.get("target", {})
    # The test binary of the library itself, which is where the checks live.
    if message.get("executable") and target.get("name") == "kr_worker" and "lib" in target.get(
        "kind", []
    ):
        print(message["executable"])
' | tail -1)"
if [ -z "$checks_binary" ] || [ ! -x "$checks_binary" ]; then
  fail "the disclosed checks were not built"
  exit 1
fi

# The run's own root, on the internal disk, with the binaries beside it.
run_root="$(mktemp -d "${TMPDIR:-/tmp}/kalareach-permissions.XXXXXX")"
mkdir -p "$run_root/bin" "$run_root/r" "$run_root/s" "$run_root/evidence" "$run_root/scratch" \
  "$run_root/authorised"
# The host's own roots are owner-only and it checks them rather than assuming.
chmod 700 "$run_root/r" "$run_root/s"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
for binary in kr-controller kr-worker kr; do
  if [ ! -x "$target_dir/debug/$binary" ]; then
    fail "the build did not produce $binary"
    exit 1
  fi
  cp "$target_dir/debug/$binary" "$run_root/bin/$binary"
  # Started once, here, where nothing is timed: the operating system checks a newly written
  # executable the first time it starts, and on a loaded machine that check alone can outlast a
  # create's rendezvous.
  "$run_root/bin/$binary" --version >/dev/null
done
cp "$checks_binary" "$run_root/bin/disclosed-checks"
export KR_RUNTIME_DIR="$run_root/r"
export KR_STATE_DIR="$run_root/s"
kr="$run_root/bin/kr"

# The file the person authorises this context to read. It is this run's own file, in this run's own
# directory: a check that read somebody's documents to prove it could would be the wrong check.
authorised_file="$run_root/authorised/nominated.txt"
printf 'the person nominated this file for the authorised read check\n' >"$authorised_file"

started_pids=()

# The launchd jobs this run's daemon defined, by label. The daemon writes one definition per
# worker's job into its environment's jobs directory and removes it once the job has gone.
defined_jobs() {
  local definition
  for definition in "$run_root"/s/environments/*/jobs/kr-worker-*.plist; do
    [ -e "$definition" ] || continue
    basename "$definition" .plist
  done
}

# Each of those jobs launchd still has loaded, as <domain>/<label>, one to a line. launchd answers
# 113 for a job a domain does not have and 112 for a domain that is not there. A job launchd could
# not answer about otherwise is named with its answer, so a question nobody could read is not
# taken for a job that has gone.
jobs_left() {
  local label domain rc
  for label in $(defined_jobs); do
    for domain in "gui/$uid" "user/$uid"; do
      /bin/launchctl print "$domain/$label" >/dev/null 2>&1 && rc=0 || rc=$?
      case $rc in
        0) echo "$domain/$label" ;;
        112 | 113) ;;
        *) echo "$domain/$label (launchctl print answered $rc)" ;;
      esac
    done
  done
}

cleanup() {
  local status=$?
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
  # A closed session's worker ends, and the daemon then removes the worker's launchd job. The daemon
  # is left running until that has happened, within a bound, because a job it has not removed by
  # the time it stops stays loaded.
  local deadline=$(( $(date +%s) + 90 ))
  while [ -n "$(jobs_left)" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 1
  done
  for pid in "${started_pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  sleep 1
  local survivors keep=0
  survivors="$(pgrep -u "$uid" -f "$run_root" 2>/dev/null | grep -v "^$$\$" || true)"
  if [ -n "$survivors" ]; then
    echo "FAILED: these processes outlived the script"
    # shellcheck disable=SC2046,SC2086
    ps -o pid=,command= -p $(printf '%s' "$survivors" | tr '\n' ' ') || true
    failed=1
    keep=1
  else
    echo "no process this run started is still running"
  fi
  local left target
  left="$(jobs_left)"
  if [ -n "$left" ]; then
    echo "FAILED: these launchd jobs this run's daemon defined were still loaded"
    printf '%s\n' "$left" | sed 's/^/  /'
    failed=1
    # Removed all the same, each by the label this run's own daemon gave it, so the run leaves
    # nothing loaded behind it. launchd ends whatever is still running inside one.
    while IFS= read -r target; do
      /bin/launchctl bootout "${target%% *}" >/dev/null 2>&1 || true
    done <<<"$left"
    left="$(jobs_left)"
    if [ -n "$left" ]; then
      echo "FAILED: these are still loaded after their removal"
      printf '%s\n' "$left" | sed 's/^/  /'
      keep=1
    fi
  else
    echo "no launchd job this run's daemon defined is still loaded"
  fi
  if [ "$keep" -eq 0 ]; then
    rm -rf "${run_root:?}"
  else
    echo "$run_root is kept"
  fi
  # A run that left something behind did not pass, whatever the last command returned.
  if [ "$failed" -ne 0 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

echo "starting the control daemon"
# Started from the run's own root rather than from this checkout. A daemon's working directory is
# what the workers it launches inherit, and a launched process that reaches the workspace volume
# makes the operating system ask the person at the machine for permission. The daemon keeps its
# signing key in a file store under this run's own directory, so nothing here queues behind the
# platform's own credential store.
(cd "$run_root" && exec "$run_root/bin/kr-controller" \
  --runtime-dir "$run_root/r" \
  --state-dir "$run_root/s" \
  --secret-store file \
  --worker "$run_root/bin/kr-worker") \
  >"$run_root/evidence/controller.log" 2>&1 &
started_pids+=("$!")
daemon_started_at="$(date +%s)"
daemon_deadline=$((daemon_started_at + 180))
while [ "$(date +%s)" -lt "$daemon_deadline" ]; do
  if "$kr" doctor --json >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
answered=0
if "$kr" doctor --json >"$run_root/evidence/doctor.json" 2>&1; then
  answered=1
fi
daemon_waited=$(( $(date +%s) - daemon_started_at ))
if [ "$answered" -eq 0 ]; then
  fail "the control daemon did not start"
  echo "waited $daemon_waited seconds for it"
  echo "--- what the daemon printed ---"
  tail -20 "$run_root/evidence/controller.log" || true
  echo "--- what kr said ---"
  tail -5 "$run_root/evidence/doctor.json" || true
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

# One capability record's field, out of a list keyed by capability name. The list is reached by a
# path of keys, and the field may itself be one, because the diagnostic flattens a record and the
# checks write it in the shape the host publishes.
read_capability() {
  /usr/bin/python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
for key in sys.argv[4].split("|"):
    document = document.get(key) if isinstance(document, dict) else document
records = document if isinstance(document, list) else []
for record in records:
    if record.get("capability") == sys.argv[2]:
        value = record
        for key in sys.argv[3].split("."):
            value = value.get(key) if isinstance(value, dict) else None
        print("" if value is None else value)
        break
' "$1" "$2" "$3" "$4"
}

echo
echo "1. the capability records this host publishes"
cp "$run_root/evidence/doctor.json" "$artefacts/doctor.json"
doctor_path="environment|desktop|capabilities"
for capability in desktop.accessibility desktop.application_launch desktop.display_server \
  desktop.input_injection desktop.screen_capture; do
  state="$(read_capability "$run_root/evidence/doctor.json" "$capability" state "$doctor_path")"
  evidence="$(read_capability "$run_root/evidence/doctor.json" "$capability" evidence_source \
    "$doctor_path")"
  if [ -z "$state" ]; then
    fail "$capability has a record"
  else
    echo "  ok: $capability is $state, from $evidence"
  fi
done
require "$(read_json "$run_root/evidence/doctor.json" environment.desktop.desktop.graphic_access)" \
  "True" "this host's own session has the graphical login's access"

echo
echo "2. the four disclosed checks, in a session's own execution context"
cat >"$run_root/bin/run-checks.sh" <<SCRIPT
#!/bin/sh
# The root shell of a desktop-bound session: the execution context an agent's tools run in. It
# records the login context it is in, performs the disclosed checks, and then waits so the session
# stays live while the evidence is read.
/bin/launchctl managername > "$run_root/evidence/managername" 2>&1
KR_PROBE_OUT="$run_root/evidence/checks.json" \\
KR_PROBE_FILE="$authorised_file" \\
KR_PROBE_SCRATCH="$run_root/scratch" \\
KR_PROBE_CONTEXT="\$(/bin/launchctl managername)" \\
  "$run_root/bin/disclosed-checks" --exact --ignored --nocapture \\
  desktop::probe::the_disclosed_checks_on_this_desktop \\
  > "$run_root/evidence/checks.log" 2>&1
echo "\$?" > "$run_root/evidence/checks.status"
exec cat
SCRIPT
chmod +x "$run_root/bin/run-checks.sh"
"$kr" new --invisible --desktop --cwd "$run_root" --shell "$run_root/bin/run-checks.sh" --json \
  >"$run_root/evidence/create-checks.json"
checks_display="$(read_json "$run_root/evidence/create-checks.json" display_number)"
require "$(read_json "$run_root/evidence/create-checks.json" worker_profile)" "desktop_bound" \
  "the checks run in the desktop execution context"
for _ in $(seq 1 600); do
  [ -s "$run_root/evidence/checks.status" ] && break
  sleep 0.2
done
if [ ! -s "$run_root/evidence/checks.status" ]; then
  fail "the disclosed checks answered"
  tail -20 "$run_root/evidence/checks.log" 2>/dev/null || true
else
  require "$(cat "$run_root/evidence/managername" 2>/dev/null || true)" "Aqua" \
    "the session's own shell is in the graphical login context"
  echo "  the checks exited $(cat "$run_root/evidence/checks.status")"
  if [ -s "$run_root/evidence/checks.json" ]; then
    cp "$run_root/evidence/checks.json" "$artefacts/disclosed-checks.json"
    checks_path="records"
    for capability in desktop.accessibility desktop.application_launch \
      desktop.authorised_file_read desktop.input_injection desktop.screen_capture; do
      state="$(read_capability "$run_root/evidence/checks.json" "$capability" state "$checks_path")"
      evidence="$(read_capability "$run_root/evidence/checks.json" "$capability" \
        evidence_source "$checks_path")"
      if [ -z "$state" ]; then
        fail "$capability has a record from the checks"
      else
        echo "  ok: $capability is $state, from $evidence"
      fi
    done
    # The record says what it was taken against and what makes it stale, which is what lets a
    # later reader tell a current answer from a superseded one.
    require "$(read_capability "$run_root/evidence/checks.json" desktop.screen_capture \
      identity.binary "$checks_path")" "/usr/sbin/screencapture" \
      "the screen record names the facility the operation was performed with"
    invalidation="$(/usr/bin/python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
for record in document.get("records", []):
    if record.get("capability") == sys.argv[2]:
        print(",".join(record.get("invalidation", [])))
        break
' "$run_root/evidence/checks.json" desktop.screen_capture)"
    require "$invalidation" "binary_identity,os_permission,desktop_generation,worker_profile" \
      "the record says what re-runs it, and a timer is not among them"
    require "$(read_capability "$run_root/evidence/checks.json" desktop.input_injection state \
      "$checks_path")" "not_tested" \
      "the check that would change something was withheld for want of a context of its own"
    require "$(read_capability "$run_root/evidence/checks.json" desktop.input_injection \
      evidence_source "$checks_path")" "not_probed" \
      "and nothing was run for it"
    # Every check declared what it does before it ran, and only the withheld one touches anything.
    /usr/bin/python3 - "$run_root/evidence/checks.json" <<'PYTHON'
import json, sys

document = json.load(open(sys.argv[1]))
checks = document.get("checks", [])
if len(checks) != 5:
    print(f"FAILED: five checks declare their effects (got {len(checks)})")
    raise SystemExit(1)
for check in checks:
    if not check.get("performs") or not check.get("bound_seconds"):
        print(f"FAILED: {check.get('capability')} declares what it does and its bound")
        raise SystemExit(1)
    changes = check.get("sends_input") or check.get("changes_user_data")
    if changes and not check.get("needs_isolated_context"):
        print(f"FAILED: {check.get('capability')} changes something without its own context")
        raise SystemExit(1)
    if changes and check.get("capability") != "desktop.input_injection":
        print(f"FAILED: {check.get('capability')} sends input or changes user data")
        raise SystemExit(1)
print("  ok: every check declared its effects, and only the withheld one changes anything")
PYTHON
  else
    fail "the checks wrote their records"
  fi
fi

echo
echo "3. a tool-specific permission stays its own record"
/usr/bin/python3 - "$run_root/evidence/checks.json" <<'PYTHON'
import json, sys

records = {
    record["capability"]: record for record in json.load(open(sys.argv[1])).get("records", [])
}
available = {name for name, record in records.items() if record["state"] == "qualified_available"}
unavailable = {name for name, record in records.items() if record["state"] != "qualified_available"}
if not records:
    print("FAILED: there are records to compare")
    raise SystemExit(1)
if available and unavailable:
    print(
        "  ok: "
        + ", ".join(sorted(available))
        + " established, and "
        + ", ".join(sorted(unavailable))
        + " still say so on their own"
    )
elif available:
    print("  ok: every capability was established on this desktop, each on its own record")
else:
    print("  ok: nothing was established here, and each capability says so on its own record")
for name, record in sorted(records.items()):
    if record["state"] != "qualified_available" and not record.get("disabled_reason"):
        print(f"FAILED: {name} is unavailable and says nothing about why")
        raise SystemExit(1)
PYTHON

echo
echo "4. the tools an agent reaches for, from the session's own shell"
# Everything this step runs lives on the internal disk. The browser driver is copied out of the
# workspace first, because a process a service manager launches is a new identity to the operating
# system and one that reaches a removable volume asks the person at the machine for permission.
node_binary="$(command -v node || true)"
driver=""
pnpm_store="$root/node_modules/.pnpm"
if [ -n "$node_binary" ] && [ -d "$pnpm_store" ]; then
  mkdir -p "$run_root/node_modules"
  for package in playwright playwright-core; do
    source_dir="$(find "$pnpm_store" -maxdepth 3 -type d -path "*/$package@*/node_modules/$package" \
      2>/dev/null | head -1)"
    if [ -n "$source_dir" ]; then
      cp -R "$source_dir" "$run_root/node_modules/$package"
    fi
  done
  if [ -d "$run_root/node_modules/playwright" ]; then
    driver="$run_root/node_modules"
    cat >"$run_root/bin/browser-check.mjs" <<'BROWSER'
// Opens a page in a real browser engine and writes one screenshot. The page is this script's own
// bytes rather than anything on the network, and the driver and the browser are both on the
// internal disk.
import { chromium } from 'playwright'

const browser = await chromium.launch()
try {
  const page = await browser.newPage()
  await page.setContent('<title>KalaReach desktop capability check</title><h1>ok</h1>')
  await page.screenshot({ path: '/tmp/kr-permissions-browser-27.07.png' })
  console.log(`ok: ${await page.title()}, screenshot at /tmp`)
} finally {
  await browser.close()
}
BROWSER
  fi
fi

cat >"$run_root/bin/run-tools.sh" <<SCRIPT
#!/bin/sh
# The tools a coding agent reaches for on this desktop, run from a session's own shell: the same
# execution context the disclosed checks ran in. Every one of them is a read. Nothing is focused,
# no input is sent, and no application or machine that was not already running is started.
evidence="$run_root/evidence"
{
  echo "context: \$(/bin/launchctl managername)"
  if command -v peekaboo >/dev/null 2>&1; then
    echo "peekaboo: \$(peekaboo --version 2>&1 | head -1)"
    if peekaboo list apps > "\$evidence/peekaboo-apps.txt" 2>&1; then
      echo "peekaboo-apps: \$(grep -c . "\$evidence/peekaboo-apps.txt") lines"
    else
      echo "peekaboo-apps: refused"
    fi
  else
    echo "peekaboo: absent"
  fi
  if command -v xcrun >/dev/null 2>&1; then
    if xcrun simctl list devices available > "\$evidence/simulators.txt" 2>&1; then
      echo "simulators: \$(grep -c '(' "\$evidence/simulators.txt" || echo 0) listed"
    else
      echo "simulators: refused"
    fi
  else
    echo "simulators: absent"
  fi
  if command -v prlctl >/dev/null 2>&1; then
    if prlctl list --all > "\$evidence/parallels.txt" 2>&1; then
      echo "parallels: \$(grep -c . "\$evidence/parallels.txt") lines"
    else
      echo "parallels: refused"
    fi
  else
    echo "parallels: absent"
  fi
  if [ -n "$driver" ] && [ -n "$node_binary" ]; then
    cd "$run_root"
    if NODE_PATH="$driver" "$node_binary" "$run_root/bin/browser-check.mjs" \
      > "\$evidence/browser.txt" 2>&1; then
      echo "browser: \$(tail -1 "\$evidence/browser.txt")"
    else
      echo "browser: refused, \$(tail -1 "\$evidence/browser.txt")"
    fi
  else
    echo "browser: no driver on the internal disk"
  fi
} > "\$evidence/tools.txt" 2>&1
echo done > "\$evidence/tools.status"
exec cat
SCRIPT
chmod +x "$run_root/bin/run-tools.sh"

"$kr" new --invisible --desktop --cwd "$run_root" --shell "$run_root/bin/run-tools.sh" --json \
  >"$run_root/evidence/create-tools.json"
tools_display="$(read_json "$run_root/evidence/create-tools.json" display_number)"
for _ in $(seq 1 900); do
  [ -s "$run_root/evidence/tools.status" ] && break
  sleep 0.2
done
if [ ! -s "$run_root/evidence/tools.status" ]; then
  fail "the tools step answered"
else
  cp "$run_root/evidence/tools.txt" "$artefacts/tools.txt" 2>/dev/null || true
  for file in peekaboo-apps.txt simulators.txt parallels.txt browser.txt; do
    [ -s "$run_root/evidence/$file" ] && cp "$run_root/evidence/$file" "$artefacts/$file"
  done
  sed 's/^/  /' "$run_root/evidence/tools.txt"
  if grep -q '^context: Aqua' "$run_root/evidence/tools.txt"; then
    echo "  ok: the tools ran in the graphical login context"
  else
    fail "the tools ran in the graphical login context"
  fi
fi
"$kr" close "$tools_display" >/dev/null 2>&1 || true

echo
echo "5. no account of any kind on this path"
# Nothing on this path asks for, stores or reads an account. The run's own state is the whole of
# what setup wrote, so this is checked by looking at it rather than by asserting it.
account_files="$(find "$run_root/s" -type f \( -name '*account*' -o -name '*stripe*' \
  -o -name '*firebase*' -o -name '*cloudflare*' -o -name '*apple*' \) 2>/dev/null || true)"
if [ -n "$account_files" ]; then
  fail "this path wrote something that reads as an account: $account_files"
else
  echo "  ok: nothing on this path wrote an account of any kind"
fi
require "$(read_json "$run_root/evidence/doctor.json" ok)" "True" \
  "the host is healthy with no account configured"
echo "  the environment this ran against: $(read_json "$run_root/evidence/doctor.json" \
  environment.environment_id)"

echo
echo "closing the session the checks ran in"
"$kr" close "$checks_display" >/dev/null 2>&1 || true

echo
if [ "$failed" -eq 0 ]; then
  echo "every check in this demonstration passed"
else
  echo "this demonstration reported at least one failure"
fi
exit "$failed"
