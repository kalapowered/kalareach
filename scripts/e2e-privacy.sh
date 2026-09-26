#!/usr/bin/env bash
# Privacy mode enabled while sync, backup and notification work is at the services, leg by leg.
#
# Section 24 asks for privacy mode to be tested while upload, notification and inference work is in
# flight, and for what had already left to be shown and removed only by an action of its own. The
# legs under `tests/integration/privacy` hold the product to that against the web service itself,
# and this is the one command that runs them and reports the whole gate: one line for every leg,
# whether it passed, failed, or has not run yet and what it waits for, then what the run left.
#
# Given an HTTPS origin it runs the leg a deployment can answer: the client's sync, with a settings
# write and a draft publication at the service when privacy mode is enabled. It sends as a fresh
# installation and no account, and gives back what it wrote.
#
# Given a loopback origin, `http://127.0.0.1:<port>`, it starts a local deployment of the web
# service on that port and runs every leg that exists against it. `KR_WEB_TREE` names a checkout of
# the web repository with its dependencies installed and its site built
# (`pnpm install --frozen-lockfile && pnpm build`), kept on this machine's own disk and outside
# TMPDIR, whose files macOS deletes once they are three days old. The deployment is `wrangler dev`
# from that tree with three values of this run: the catalogue's free tier with backup storage in
# it, so an account signed in here can keep a backup collection; a push provider whose token
# endpoint is a loopback stub this script holds, which always answers unavailable, so every provider
# send fails before anything leaves this machine and a delivered notification stays queued at the
# gateway; and a local provider project name. Nothing in the web tree changes.
#
# What it leaves. Every key is made for the run. A local run's deployment, its storage, the stub and
# the devices' stores live in one directory under TMPDIR, removed when the local legs passed and
# kept, and named, when one failed. Against a deployment the sync leg gives back what it wrote; the
# service keeps what it keeps by its own rules, and the closing lines say what that is.
#
# Usage: scripts/e2e-privacy.sh https://example.invalid
#        KR_WEB_TREE=/path/to/kalareach-web scripts/e2e-privacy.sh http://127.0.0.1:8806
#
# It exits 0 only when every leg of the gate ran and passed, 1 when any failed or has not run, and
# 2 when it was given no usable origin, or a loopback origin without a usable web tree.
set -euo pipefail

export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

suite=kr-privacy-integration

origin="${1:-${KR_PRIVACY_ORIGIN:-}}"
if [ -z "$origin" ]; then
  echo "usage: scripts/e2e-privacy.sh <https origin | http://127.0.0.1:<port>>" >&2
  echo "       the origin may come from KR_PRIVACY_ORIGIN instead" >&2
  exit 2
fi

# The same rules a gateway origin is held to, applied before the value reaches a log, a signed
# request or a directory name. Nothing below repeats a value that failed them.
# A port, when an origin names one: a number from 1 to 65535.
valid_port() {
  [[ "$1" =~ ^[1-9][0-9]{0,4}$ ]] && [ "$1" -le 65535 ]
}

# A host name: labels of letters, digits and inner hyphens, joined by dots.
host_label='[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
case "$origin" in
  https://*)
    mode=deployment
    authority="${origin#https://}"
    host="$authority"
    case "$authority" in
      *:*)
        host="${authority%:*}"
        if ! valid_port "${authority##*:}"; then
          echo "a deployment's origin is https://<host>, with at most a port from 1 to 65535 after it" >&2
          exit 2
        fi
        ;;
    esac
    if ! [[ "$host" =~ ^(${host_label}\.)*${host_label}$ ]]; then
      echo "a deployment's origin is https://<host>: a host name and nothing else, no path, query, fragment or user information" >&2
      exit 2
    fi
    ;;
  http://127.0.0.1:*)
    mode=local
    port="${origin#http://127.0.0.1:}"
    if ! valid_port "$port"; then
      echo "a loopback origin is http://127.0.0.1:<port>, with a port from 1 to 65535 and nothing after it" >&2
      exit 2
    fi
    ;;
  *)
    echo "a deployment is reached over https://, and a local stack at http://127.0.0.1:<port>" >&2
    exit 2
    ;;
esac

tree=""
node=""
wrangler=""
if [ "$mode" = local ]; then
  tree="${KR_WEB_TREE:-}"
  if [ -z "$tree" ] || [ ! -f "$tree/infra/wrangler.jsonc" ] || [ ! -f "$tree/infra/scripts/config.mjs" ]; then
    echo "a loopback run needs KR_WEB_TREE: a web checkout holding infra/wrangler.jsonc" >&2
    exit 2
  fi
  tree="$(cd "$tree" && pwd -P)"
  if [ ! -f "$tree/apps/site/dist/index.html" ] || [ ! -x "$tree/node_modules/.bin/wrangler" ]; then
    echo "the web tree is not installed and built: run pnpm install --frozen-lockfile and pnpm build there" >&2
    exit 2
  fi
  temporary="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
  case "$tree/" in
    "$temporary"/*)
      echo "the web tree is under TMPDIR, where macOS deletes files once they are three days old; keep it elsewhere on this disk" >&2
      exit 2
      ;;
  esac
  for tool in node openssl curl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      echo "a loopback run needs $tool" >&2
      exit 2
    fi
  done
  node="$(command -v node)"
  wrangler="$tree/node_modules/.bin/wrangler"
fi

# Section 27 puts every test artefact in one directory. This run takes a new directory of its own
# under it and writes one log per leg there, so a leg that failed leaves its whole output behind.
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
case "$artefacts" in
  /*) ;;
  *) artefacts="$PWD/$artefacts" ;;
esac
mkdir -p "$artefacts"
evidence="$(mktemp -d "$artefacts/privacy-XXXXXX")"

echo "kalareach privacy mode checkpoint"
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

# The product's own rule decides whether the origin is one a service credential travels to, so the
# script accepts exactly what the legs will, and refuses the rest before starting or sending anything.
if ! env KR_PRIVACY_CHECK_ORIGIN="$origin" cargo test --locked --quiet -p "$suite" --lib -- \
  --exact tests::the_origin_a_run_is_about_to_use_is_one_a_credential_travels_to \
  >"$evidence/origin.log" 2>&1; then
  if grep -q 'not an origin a service credential travels to' "$evidence/origin.log"; then
    echo "$origin is not an origin a service credential travels to; see $evidence/origin.log" >&2
    exit 2
  fi
  echo "the origin could not be checked; see $evidence/origin.log" >&2
  exit 1
fi

passed=0
failed=0
missed=0
unfinished=()
left=()

report() {
  local result="$1"
  local leg="$2"
  local what="$3"
  case "$result" in
    ok) passed=$((passed + 1)) ;;
    FAILED) failed=$((failed + 1)); unfinished+=("$leg") ;;
    *) missed=$((missed + 1)) ;;
  esac
  printf '  %-7s %-9s %s\n' "$result" "$leg" "$what"
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
  local line
  while IFS= read -r line; do
    case "$line" in
      *" ($origin)") line="${line#*: }"; printf '%s' "${line% (*)}"; return ;;
    esac
  done <"$log"
}

# Why a leg stopped, from its failure: the first line of the panic message.
reason() {
  local why
  why="$(sed -n '/panicked at/{n;p;q;}' "$1")"
  printf '%s' "${why:-it failed; its log says why}"
}

# Every line a leg printed about something it could not give back.
not_given_back() {
  grep 'give back what it took' "$1" 2>/dev/null | sed 's/^.*give back what it took: //' || true
}

leg() {
  local name="$1"
  local group="$2"
  local test="$3"
  shift 3
  local log="$evidence/$name.log"
  local rc=0
  run_test "$group" "$test" "$log" "$@" || rc=$?
  case "$rc" in
    0) report ok "$name" "$(proved "$log")" ;;
    1) report FAILED "$name" "$(reason "$log")" ;;
    *) report 'NOT RUN' "$name" "the leg ran nothing; see $log" ;;
  esac
  local what
  while IFS= read -r what; do
    [ -n "$what" ] && left+=("$name: $what")
  done < <(not_given_back "$log")
  return 0
}

sync_leg() {
  leg sync sync \
    kr_req_24_28_privacy_enabled_while_a_settings_write_and_a_draft_publication_are_in_flight \
    KR_DEPLOYED_ORIGIN="$origin"
}

# The later legs: what each waits for, in the product's words. Each is named on every run, so the
# gate fails, and says why, until every one of them has run.
later_legs() {
  report 'NOT RUN' host "waits for privacy mode's production entry point: the host enabling it through a registered method, with sync, push and inference work in flight and the history-page fence"
  report 'NOT RUN' backup "waits for the backup uploader to start with the daemon, with its account token source and a transport gate covering deletions"
  report 'NOT RUN' companion "waits for the companion's list of retained artifacts and its deletion action"
  report 'NOT RUN' phone "waits for physical devices, with a notification in flight at a phone"
}

# The local deployment: its run directory, and every process this run started for it.
#
# A process is known by its number and the instant the kernel says it started, and the two are only
# ever read together, in one look at the process table. The deployment's leader is the process this
# shell forked for `wrangler dev`; the group's number is the leader's. A member of the group is
# recorded only from a look in which the leader is still this shell's own child and still started
# when it was recorded: until the leader ends, no other group can have its number, so every member in
# that look is this run's. Nothing is signalled by the group's number, and a recorded process is
# signalled only while a fresh read of its number gives the start it was recorded with.
run=""
state=""
group=""
leader_started=""
# Every process of the deployment, as "<number>|<started>".
deployment=()
stub=""
stub_started=""
stub_port=""
why=""
stopped=1
local_complete=0
removed=0
finished=0

# One look at the process table: "<number>|<parent>|<group>|<started>" for every process, each line
# describing one process.
process_table() {
  LC_ALL=C ps -axo pid=,ppid=,pgid=,lstart= |
    awk '{ started = $4; for (i = 5; i <= NF; i++) started = started " " $i; print $1 "|" $2 "|" $3 "|" started }'
}

# When the kernel says process $1 started, spelt as process_table spells it, or nothing.
started_of() {
  LC_ALL=C ps -o lstart= -p "$1" 2>/dev/null |
    awk '{ started = $1; for (i = 2; i <= NF; i++) started = started " " $i; print started }'
}

# When one of this shell's own children started, from a look in which it is still this shell's
# child, or nothing when it is not.
child_started() {
  local pid parent member started
  while IFS='|' read -r pid parent member started; do
    if [ "$pid" = "$1" ] && [ "$parent" = "$$" ]; then
      printf '%s\n' "$started"
      return 0
    fi
  done < <(process_table)
  return 0
}

# Whether a recorded process is still the one recorded.
still_there() {
  [ -n "$2" ] && [ "$(started_of "$1")" = "$2" ]
}

# Whether the deployment's leader is still the child this shell forked.
leader_alive() {
  [ -n "$group" ] && [ -n "$leader_started" ] && [ "$(child_started "$group")" = "$leader_started" ]
}

# Records every member of the deployment's group, from one look in which its leader is unchanged.
record_members() {
  [ -n "$group" ] && [ -n "$leader_started" ] || return 0
  local table pid parent member started
  table="$(process_table)"
  grep -qxF "$group|$$|$group|$leader_started" <<<"$table" || return 0
  while IFS='|' read -r pid parent member started; do
    [ "$member" = "$group" ] || continue
    case " ${deployment[*]:-} " in
      *" $pid|"*) continue ;;
    esac
    deployment+=("$pid|$started")
  done <<<"$table"
  return 0
}

# How many recorded processes of the deployment are still the ones recorded.
deployment_running() {
  local record pid started count=0
  for record in "${deployment[@]:-}"; do
    [ -n "$record" ] || continue
    IFS='|' read -r pid started <<<"$record"
    if still_there "$pid" "$started"; then
      count=$((count + 1))
    fi
  done
  echo "$count"
}

# The numbers of the processes in the deployment's group now, whoever they are.
group_now() {
  ps -axo pid=,pgid= | awk -v group="$group" '$2 == group { print $1 }'
}

# Asks the deployment to stop, then makes it, and says whether any of it is left.
stop_deployment() {
  [ -n "$group" ] || return 0
  record_members
  local signal record pid started
  for signal in TERM KILL; do
    for record in "${deployment[@]:-}"; do
      [ -n "$record" ] || continue
      IFS='|' read -r pid started <<<"$record"
      if still_there "$pid" "$started"; then
        kill "-$signal" "$pid" 2>/dev/null || true
      fi
    done
    for _ in $(seq 1 80); do
      [ "$(deployment_running)" -eq 0 ] && break
      sleep 0.25
    done
    [ "$(deployment_running)" -eq 0 ] && break
  done
  if [ "$(deployment_running)" -ne 0 ]; then
    stopped=0
  fi
  # Anything still in the group was never recorded, so it is left alone, and reported.
  if [ -n "$(group_now)" ]; then
    stopped=0
  fi
  group=""
}

# Stops the provider stub, and says whether it has gone.
stop_stub() {
  [ -n "$stub" ] || return 0
  local signal
  for signal in TERM KILL; do
    if still_there "$stub" "$stub_started"; then
      kill "-$signal" "$stub" 2>/dev/null || true
    fi
    for _ in $(seq 1 40); do
      still_there "$stub" "$stub_started" || break
      sleep 0.25
    done
    still_there "$stub" "$stub_started" || break
  done
  if still_there "$stub" "$stub_started"; then
    stopped=0
  fi
  stub=""
}

# Removes the run directory when the local legs ran and passed and everything this run started
# stopped. The later legs never run here, so the exit status says nothing about this directory.
finish_local() {
  if [ -n "$run" ] && [ -d "$run" ] && [ "$stopped" -eq 1 ] && [ "$failed" -eq 0 ] &&
    [ "$local_complete" -eq 1 ]; then
    rm -rf "${run:?}"
    removed=1
  fi
}

# Runs on exit, whatever the reason. A run that ended early still stops everything it started and
# names the directory it kept.
# shellcheck disable=SC2329
cleanup() {
  [ "$mode" = local ] || return 0
  [ "$finished" -eq 0 ] || return 0
  stop_deployment
  stop_stub
  if [ -n "$run" ] && [ -d "$run" ]; then
    echo "the run ended early; its directory was kept: $run"
  fi
  if [ "$stopped" -eq 0 ]; then
    echo "something this run started did not stop; see $evidence/deployment.log"
  fi
}
trap cleanup EXIT
# A signal ends the run through `exit`, so the cleanup above runs for it as well.
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# The values a local deployment starts with, and the databases its migrations go to, from the web
# tree's own configuration. A value is written single-quoted, which the values file keeps exactly
# as written, so a JSON document arrives whole; one that could not be written that way is refused.
write_values() {
  cat >"$run/values.mjs" <<'VALUES'
import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const [tree, keyFile, stubPort, valuesFile, bindingsFile] = process.argv.slice(2);
const { readWranglerConfig } = await import(pathToFileURL(join(tree, 'infra', 'scripts', 'config.mjs')).href);
const config = readWranglerConfig();

// The configuration's own catalogue, with backup storage in its free tier.
const catalogue = JSON.parse(config.vars?.BILLING_CATALOGUE ?? '{}');
catalogue.free = {
  ...catalogue.free,
  allowances: { ...catalogue.free?.allowances, storage_bytes: String(64 * 1024 * 1024) },
};

// A service account made for this run, whose token endpoint is the loopback stub.
const account = {
  type: 'service_account',
  project_id: 'kalareach-local',
  client_email: 'provider@kalareach-local.invalid',
  private_key: readFileSync(keyFile, 'utf8'),
  token_uri: `http://127.0.0.1:${stubPort}/token`,
};

const quoted = (value) => {
  if (value.includes("'") || value.includes('\n')) {
    throw new Error('a value that cannot be written single-quoted');
  }
  return `'${value}'`;
};
const lines = [
  `BETTER_AUTH_SECRET=local-${randomUUID()}-${randomUUID()}`,
  // The ledger reads its whole configuration before it admits anything. Test-mode values that no
  // request here sends anywhere.
  'STRIPE_SECRET_KEY=sk_test_local_privacy_not_a_key',
  'STRIPE_WEBHOOK_SECRET=whsec_local_privacy_not_a_secret',
  'FIREBASE_PROJECT_ID=kalareach-local',
  `FCM_SERVICE_ACCOUNT_JSON=${quoted(JSON.stringify(account))}`,
  `BILLING_CATALOGUE=${quoted(JSON.stringify(catalogue))}`,
];
writeFileSync(valuesFile, `${lines.join('\n')}\n`, { mode: 0o600 });
const bindings = (config.d1_databases ?? [])
  .filter((entry) => typeof entry?.migrations_dir === 'string')
  .map((entry) => entry.binding);
writeFileSync(bindingsFile, `${bindings.join('\n')}\n`);
VALUES
  (umask 077 && openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$run/provider-key.pem" 2>>"$evidence/deployment.log") || return 1
  "$node" "$run/values.mjs" "$tree" "$run/provider-key.pem" "$1" "$run/values.env" \
    "$run/bindings.txt" 2>>"$evidence/deployment.log"
}

# A push provider that is never available: every request is answered 503 and written down. It sets
# `stub` and `stub_port`, and runs in this shell so the process is recorded where cleanup reads it.
start_stub() {
  cat >"$run/provider.mjs" <<'STUB'
import { createServer } from 'node:http';
import { appendFileSync, writeFileSync } from 'node:fs';

const [portFile, logFile] = process.argv.slice(2);
const server = createServer((request, response) => {
  let length = 0;
  request.on('data', (chunk) => { length += chunk.length; });
  request.on('end', () => {
    appendFileSync(logFile, `${new Date().toISOString()} ${request.method} ${request.url} ${length} bytes\n`);
    response.writeHead(503, { 'content-type': 'application/json' });
    response.end('{"error":"unavailable"}');
  });
});
server.listen(0, '127.0.0.1', () => writeFileSync(portFile, `${server.address().port}\n`));
STUB
  "$node" "$run/provider.mjs" "$run/provider.port" "$evidence/provider.log" \
    >>"$evidence/deployment.log" 2>&1 &
  stub=$!
  stub_started="$(child_started "$stub")"
  [ -n "$stub_started" ] || return 1
  for _ in $(seq 1 100); do
    [ -s "$run/provider.port" ] && break
    sleep 0.1
  done
  [ -s "$run/provider.port" ] || return 1
  stub_port="$(tr -d '[:space:]' <"$run/provider.port")"
}

# Whether anything accepts a connection on one loopback port.
port_taken() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

# Starts the local deployment on the port this run was given, and waits until it serves. It runs in
# this shell, so what it starts is recorded where cleanup reads it; why it failed is left in `why`.
start_deployment() {
  local binding version health
  start_stub || { why="the provider stub did not start"; return 1; }
  write_values "$stub_port" || { why="the deployment's values could not be written"; return 1; }
  while IFS= read -r binding; do
    [ -n "$binding" ] || continue
    if ! (cd "$tree/infra" && CI=1 CLOUDFLARE_INCLUDE_PROCESS_ENV=false WRANGLER_SEND_METRICS=false \
      "$wrangler" d1 migrations apply "$binding" --local --persist-to "$state" \
      --config "$tree/infra/wrangler.jsonc") >>"$evidence/deployment.log" 2>&1; then
      why="the migrations of $binding did not apply"
      return 1
    fi
  done <"$run/bindings.txt"
  if port_taken "$port"; then
    why="something already listens on $origin, so no deployment was started there"
    return 1
  fi
  version="privacy-$("$node" -e 'process.stdout.write(require("node:crypto").randomUUID())')"
  # A process group of its own, so the Worker runtime it starts is found and stopped with it.
  set -m
  (cd "$tree/infra" && exec env CI=1 CLOUDFLARE_INCLUDE_PROCESS_ENV=false WRANGLER_SEND_METRICS=false \
    "$wrangler" dev --config "$tree/infra/wrangler.jsonc" --ip 127.0.0.1 --port "$port" \
    --inspector-port 0 --persist-to "$state" --env-file "$run/values.env" \
    --var "PUBLIC_SITE_ORIGIN:$origin" --var "PUSH_GATEWAY_ORIGIN:$origin" \
    --var "BUILD_VERSION:$version" --test-scheduled --log-level warn) \
    >>"$evidence/deployment.log" 2>&1 &
  group=$!
  set +m
  leader_started="$(child_started "$group")"
  [ -n "$leader_started" ] || { why="the deployment stopped as it started"; return 1; }
  # Only an answer carrying this start's own version counts: another Worker serving on the port
  # could otherwise be taken for this one.
  for _ in $(seq 1 480); do
    health="$(curl --noproxy '*' -fsS -m 2 "$origin/api/health" 2>/dev/null || true)"
    case "$health" in
      *"\"$version\""*)
        case "$health" in
          *'"environment":"development"'*)
            # Serving this run's version: every member of the group now is this run's.
            record_members
            return 0
            ;;
          *) why="the deployment on $origin is not a development one"; return 1 ;;
        esac
        ;;
    esac
    leader_alive || { why="the deployment stopped before it served"; return 1; }
    sleep 0.25
  done
  why="the deployment did not serve on $origin within two minutes"
  return 1
}

# What ran: the paths and versions of the programs this run started, in the evidence.
record_tools() {
  {
    echo "node: $node $("$node" --version)"
    echo "node sha256: $(shasum -a 256 "$(cd "$(dirname "$node")" && pwd -P)/$(basename "$node")" 2>/dev/null | cut -d' ' -f1)"
    echo "wrangler: $wrangler $("$wrangler" --version 2>/dev/null | tail -n 1)"
    echo "openssl: $(command -v openssl) $(openssl version)"
    echo "web tree: $tree"
  } >"$evidence/tools.txt" 2>&1
}

if [ "$mode" = deployment ]; then
  sync_leg
  report '-' retained "local only: signs accounts in and answers a push challenge through a local deployment"
  local_complete=1
else
  run="$(mktemp -d "${TMPDIR:-/tmp}/kr-e2e-privacy-XXXXXX")"
  state="$run/state"
  record_tools
  if start_deployment; then
    sync_leg
    leg retained retained \
      kr_req_24_29_what_is_at_the_services_stays_until_its_own_authorised_action_removes_it \
      KR_DEPLOYED_ORIGIN="$origin" KR_PRIVACY_STATE="$state"
    local_complete=1
  else
    report FAILED sync "no local deployment served: $why; see $evidence/deployment.log"
    report FAILED retained "no local deployment served"
  fi
  stop_deployment
  stop_stub
  finish_local
fi
finished=1
later_legs

echo
total=$((passed + failed + missed))
echo "$total legs of the gate against $origin: $passed passed, $failed failed, $missed did not run here"

echo
echo "what these legs left:"
if [ "${#left[@]}" -ne 0 ]; then
  for what in "${left[@]}"; do
    echo "  could not give back, $what"
  done
fi
if [ "$mode" = deployment ]; then
  # Said only on the leg's own word: a leg that stopped before it gave anything back never says it.
  if grep -q 'this leg gave back everything it took' "$evidence/sync.log" 2>/dev/null; then
    echo "  sync: every request identity it presented ended and every collection it wrote emptied; the service keeps each identity's receipt for 30 days, a content-free record of each removed object's place, spent nonces and the ledger's record of the run's installation"
  else
    echo "  sync: the leg did not say it gave back what it took, so as far as it got it may have left the collections it wrote besides what the service keeps by its own rules; see $evidence/sync.log"
  fi
else
  if [ "$stopped" -eq 0 ]; then
    failed=$((failed + 1))
    echo "  a process this run started did not stop, and the run directory was kept: $run; see $evidence/deployment.log"
  elif [ "$removed" -eq 1 ]; then
    echo "  nothing: the local deployment and the provider stub stopped, their state was removed, and nothing was sent anywhere but this machine"
  else
    echo "  the local run directory, kept for its evidence: $run"
  fi
  # The gateway reaches its provider only by first asking the stub for a token, which it never gets.
  if [ -f "$evidence/provider.log" ]; then
    asked="$(grep -c ' POST /token ' "$evidence/provider.log" || true)"
    other="$(grep -c -v ' POST /token ' "$evidence/provider.log" || true)"
    echo "  the push provider's token endpoint, this run's stub, refused ${asked:-0} requests and received ${other:-0} others"
  fi
fi

if [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ]; then
  exit 0
fi
if [ "${#unfinished[@]}" -ne 0 ]; then
  echo
  echo "what to look at, in $evidence:"
  for what in "${unfinished[@]}"; do
    echo "  $what.log"
  done
fi
exit 1
