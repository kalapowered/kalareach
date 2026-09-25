#!/usr/bin/env bash
# The recovery bundle and settings sync against real services, leg by leg.
#
# The legs under `tests/integration/backup` hold the recovery module and the settings-sync client to
# the web service itself, and this is the one command that runs them and reports what they found.
# It prints the commit, the host, the time and the origin, then one line per leg, then what the run
# left behind.
#
# Given an HTTPS origin it runs the legs a deployment can answer: the recovery bundle written by one
# fresh installation and found by another that holds only the kit. The legs that need two services
# or a deployment restored from its export are named as local only and are not run.
#
# Given a loopback origin, `http://127.0.0.1:<port>`, it runs every leg on this machine, against
# local deployments of the web service: the first on that port, the others on ports the system
# chooses. `KR_WEB_TREE` names a checkout of the web repository with its dependencies installed and
# its site built (`pnpm install --frozen-lockfile && pnpm build`), whose local restore driver,
# `infra/scripts/testing/local-restore.mjs`, starts, exports, prepares, restores and stops them. The
# restore leg is a source deployment, an export on its schedule, the source stopped, a target
# prepared from that export and restored on its own schedule, and a device's stores meeting each in
# turn. On macOS, keep the tree on the internal disk: the Workers it starts read it.
#
# What it sends, and what it leaves. Every key is made for the run and discarded with it, and every
# locator and identifier is drawn fresh. A local run's deployments, their storage and the device's
# stores live in one directory under TMPDIR, removed when the run ends and kept, and named, when a
# leg failed. Against a deployment a bundle stays where it was written, because no client operation
# removes a bundle: the closing lines say what each leg left there.
#
# Usage: scripts/e2e-backup.sh https://example.invalid
#        KR_WEB_TREE=/path/to/kalareach-web scripts/e2e-backup.sh http://127.0.0.1:8805
#
# It exits 0 when every leg that applies to the origin passed, 1 when any failed or did not run,
# and 2 when it was given no usable origin, or a loopback origin without a usable web tree.
set -euo pipefail

export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

suite=kr-backup-integration

origin="${1:-${KR_BACKUP_ORIGIN:-}}"
if [ -z "$origin" ]; then
  echo "usage: scripts/e2e-backup.sh <https origin | http://127.0.0.1:<port>>" >&2
  echo "       the origin may come from KR_BACKUP_ORIGIN instead" >&2
  exit 2
fi

# The same rules a gateway origin is held to, applied before the value reaches a log, a signed
# request or a directory name. Nothing below repeats a value that failed them.
case "$origin" in
  https://*)
    mode=deployment
    authority="${origin#https://}"
    ;;
  http://127.0.0.1:*)
    mode=local
    authority="${origin#http://}"
    port="${origin#http://127.0.0.1:}"
    if ! [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || [ "$port" -gt 65535 ]; then
      echo "a loopback origin is http://127.0.0.1:<port>, with a port and nothing after it" >&2
      exit 2
    fi
    ;;
  *)
    echo "a deployment is reached over https://, and a local stack at http://127.0.0.1:<port>" >&2
    exit 2
    ;;
esac
case "$authority" in
  '')
    echo "an origin names a host" >&2
    exit 2
    ;;
  *[/?#@]*)
    echo "an origin carries no path, query, fragment or user information" >&2
    exit 2
    ;;
esac
if [ -n "${authority//[]A-Za-z0-9.:[-]/}" ]; then
  echo "an origin is a host and an optional port in printable ASCII, and nothing else" >&2
  exit 2
fi

driver=""
if [ "$mode" = local ]; then
  tree="${KR_WEB_TREE:-}"
  if [ -z "$tree" ] || [ ! -f "$tree/infra/scripts/testing/local-restore.mjs" ]; then
    echo "a loopback run needs KR_WEB_TREE: a web checkout holding infra/scripts/testing/local-restore.mjs" >&2
    exit 2
  fi
  if [ ! -f "$tree/apps/site/dist/index.html" ] || [ ! -x "$tree/node_modules/.bin/wrangler" ]; then
    echo "the web tree is not installed and built: run pnpm install --frozen-lockfile and pnpm build there" >&2
    exit 2
  fi
  if ! command -v node >/dev/null 2>&1; then
    echo "a loopback run needs node, which runs the web tree's local restore driver" >&2
    exit 2
  fi
  driver="$tree/infra/scripts/testing/local-restore.mjs"
fi

# Section 27 puts every test artefact in one directory. This run takes a new directory of its own
# under it and writes one log per leg there, so a leg that failed leaves its whole output behind.
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
case "$artefacts" in
  /*) ;;
  *) artefacts="$PWD/$artefacts" ;;
esac
mkdir -p "$artefacts"
evidence="$(mktemp -d "$artefacts/backup-XXXXXX")"

echo "kalareach backup and recovery checkpoint"
echo "  commit: $(git rev-parse HEAD 2>/dev/null || echo 'not a checkout')"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  origin: $origin"
echo "  evidence: $evidence"
echo

# Built once, before anything is started or sent, so a build failure is not reported as a service
# that answered wrongly.
if ! cargo test --locked --quiet -p "$suite" --no-run >"$evidence/build.log" 2>&1; then
  echo "the legs did not build, so nothing was started or contacted; see $evidence/build.log" >&2
  exit 1
fi

passed=0
failed=0
missed=0
unfinished=()
left=()

# The local deployments and the device's stores, all in one directory this run made.
run=""
state=""
cleanup() {
  local status=$?
  if [ -n "$state" ] && [ -d "$state" ]; then
    node "$driver" stop --state "$state" >>"$evidence/driver.log" 2>&1 || true
  fi
  if [ -n "$run" ] && [ -d "$run" ]; then
    if [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ] && [ "$status" -eq 0 ]; then
      node "$driver" stop --state "$state" --remove >>"$evidence/driver.log" 2>&1 || true
      rm -rf "${run:?}"
    else
      echo "the local run directory was kept for its evidence: $run"
    fi
  fi
}
trap cleanup EXIT

# One step of the web tree's driver. Prints its one line of JSON; fails when the step did.
step() {
  node "$driver" "$@" --state "$state" 2>>"$evidence/driver.log" | tee -a "$evidence/driver.log" | tail -n 1
  return "${PIPESTATUS[0]}"
}

# One member of the JSON line a driver step printed.
member() {
  node -e 'let value; try { value = JSON.parse(process.argv[1])[process.argv[2]]; } catch { value = undefined; } process.stdout.write(value === undefined || value === null ? "" : String(value));' "$1" "$2"
}

# Runs one test of the suite and reports how it ended: 0 passed, 1 failed, 2 did not run.
run_test() {
  local group="$1"
  local test="$2"
  local log="$3"
  shift 3
  local rc=0
  env "$@" KR_REQUIRE_DEPLOYED_ORIGIN=1 \
    cargo test --locked -p "$suite" --test "$group" -- \
    --exact "$test" --nocapture --test-threads=1 >"$log" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then
    return 1
  fi
  if grep -q '^test result: ok\. 1 passed' "$log"; then
    return 0
  fi
  return 2
}

# What a leg said it proved, from the line that names the origin it ran against.
proved() {
  local log="$1"
  local against="$2"
  local line
  while IFS= read -r line; do
    case "$line" in
      *" ($against)") line="${line#*: }"; printf '%s' "${line% (*)}"; return ;;
    esac
  done <"$log"
}

# Why a leg stopped, from its failure: the first line of the panic message.
reason() {
  local why
  why="$(sed -n '/panicked at/{n;p;q;}' "$1")"
  printf '%s' "${why:-it failed; its log says why}"
}

report() {
  local result="$1"
  local leg="$2"
  local what="$3"
  case "$result" in
    ok) passed=$((passed + 1)) ;;
    FAILED) failed=$((failed + 1)); unfinished+=("$leg") ;;
    'NOT RUN') missed=$((missed + 1)); unfinished+=("$leg") ;;
  esac
  printf '  %-7s %-10s %s\n' "$result" "$leg" "$what"
}

# The bundle, at one service: the origin this run was given.
bundle_leg() {
  local against="$1"
  local log="$evidence/bundle.log"
  local rc=0
  run_test bundle a_bundle_is_found_and_authenticated_with_only_the_kit_and_its_origin "$log" \
    KR_DEPLOYED_ORIGIN="$against" || rc=$?
  case "$rc" in
    0) report ok bundle "$(proved "$log" "$against")" ;;
    1) report FAILED bundle "$(reason "$log")" ;;
    *) report 'NOT RUN' bundle "the leg ran nothing" ;;
  esac
  if [ "$mode" = deployment ]; then
    if [ "$rc" -eq 0 ] || grep -q 'the request was sent' "$log"; then
      left+=("bundle: one bundle collection under a locator made for the run, in the namespace of an installation key discarded with the run, with the receipts and spent nonces the service keeps; no client operation removes a bundle")
    else
      left+=("bundle: nothing, because nothing was sent")
    fi
  fi
}

if [ "$mode" = deployment ]; then
  bundle_leg "$origin"
  printf '  %-7s %-10s %s\n' '-' services "local only: needs two services on this machine"
  printf '  %-7s %-10s %s\n' '-' restore "local only: needs a deployment restored from its export on this machine"
else
  run="$(mktemp -d "${TMPDIR:-/tmp}/kr-e2e-backup-XXXXXX")"
  state="$run/web"

  # The bundle, at a local deployment on the given port.
  first=""
  if answer="$(step start --name first --port "$port")"; then
    first="$(member "$answer" origin)"
  fi
  if [ "$first" = "$origin" ]; then
    bundle_leg "$first"
  else
    first=""
    report FAILED bundle "no local deployment served on $origin; see $evidence/driver.log"
  fi

  # The bundle, at two services.
  second=""
  if [ -n "$first" ] && answer="$(step start --name second)"; then
    second="$(member "$answer" origin)"
  fi
  if [ -z "$first" ]; then
    report 'NOT RUN' services "the first local deployment did not serve"
  elif [ -n "$second" ]; then
    log="$evidence/services.log"
    rc=0
    run_test bundle a_kit_naming_two_services_reads_the_bundle_at_either "$log" \
      KR_DEPLOYED_ORIGIN="$first" KR_BACKUP_SECOND_ORIGIN="$second" || rc=$?
    case "$rc" in
      0) report ok services "$(proved "$log" "$first")" ;;
      1) report FAILED services "$(reason "$log")" ;;
      *) report 'NOT RUN' services "the leg ran nothing" ;;
    esac
  else
    report FAILED services "a second local deployment did not serve; see $evidence/driver.log"
  fi
  step stop --name first >/dev/null || true
  step stop --name second >/dev/null || true

  # The client across a restored deployment: a source, its export, a target restored from it.
  device="$run/device"
  restore_failed=""
  source=""
  if answer="$(step start --name source)"; then
    source="$(member "$answer" origin)"
  else
    restore_failed="the source deployment did not serve"
  fi
  if [ -z "$restore_failed" ] && ! run_test restore a_device_makes_its_settings_drafts_and_membership_before_the_export \
    "$evidence/restore-1.log" KR_BACKUP_RUN_DIR="$device" KR_BACKUP_SOURCE_ORIGIN="$source"; then
    restore_failed="phase 1: $(reason "$evidence/restore-1.log")"
  fi
  export_id=""
  if [ -z "$restore_failed" ]; then
    expectations=()
    while IFS= read -r expected; do
      [ -n "$expected" ] && expectations+=(--expect "$expected")
    done <"$device/expected-objects.txt"
    if answer="$(step export --name source "${expectations[@]}")"; then
      export_id="$(member "$answer" export_id)"
    else
      restore_failed="the export: $(member "$answer" error)"
    fi
  fi
  if [ -z "$restore_failed" ] && ! run_test restore after_the_export_the_device_writes_on_and_a_copy_meets_the_source_unchanged \
    "$evidence/restore-2.log" KR_BACKUP_RUN_DIR="$device" KR_BACKUP_SOURCE_ORIGIN="$source"; then
    restore_failed="phase 2: $(reason "$evidence/restore-2.log")"
  fi
  target=""
  recovery=""
  if [ -z "$restore_failed" ]; then
    # The source goes out of service before its export is restored, as a replaced deployment does.
    step stop --name source >/dev/null || true
    if answer="$(step prepare --from source --export "$export_id" --name target)"; then
      target="$(member "$answer" origin)"
    else
      restore_failed="preparing the target: $(member "$answer" error)"
    fi
  fi
  if [ -z "$restore_failed" ]; then
    if answer="$(step restore --name target)"; then
      recovery="$(member "$answer" recovery_id)"
    else
      restore_failed="the restore: $(member "$answer" error)"
    fi
  fi
  if [ -z "$restore_failed" ] && ! run_test restore the_device_meets_the_deployment_restored_from_the_export \
    "$evidence/restore-3.log" KR_BACKUP_RUN_DIR="$device" KR_BACKUP_TARGET_ORIGIN="$target" \
    KR_BACKUP_RECOVERY_ID="$recovery"; then
    restore_failed="phase 3: $(reason "$evidence/restore-3.log")"
  fi
  if [ -z "$restore_failed" ]; then
    report ok restore "$(proved "$evidence/restore-3.log" "$target")"
  else
    report FAILED restore "$restore_failed"
  fi
  step stop --name target >/dev/null || true
fi

echo
total=$((passed + failed + missed))
echo "$total legs against $origin: $passed passed, $failed failed, $missed did not run"

if [ "$mode" = deployment ]; then
  echo
  echo "what these legs left on the deployment:"
  if [ "${#left[@]}" -ne 0 ]; then
    for what in "${left[@]}"; do
      echo "  $what"
    done
  fi
else
  echo "every deployment this run started was stopped; nothing was sent anywhere but this machine"
fi

if [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ]; then
  exit 0
fi
if [ "${#unfinished[@]}" -ne 0 ]; then
  echo
  echo "what to look at, in $evidence:"
  for what in "${unfinished[@]}"; do
    echo "  $what"
  done
fi
exit 1
