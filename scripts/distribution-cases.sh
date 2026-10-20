#!/usr/bin/env bash
# Runs the pairing suite of kr-controller (crates/kr-controller/tests/distribution_endpoints.rs)
# against two installations on this machine.
#
# The suite's cases are ignored in an ordinary run because each needs a control daemon this run did
# not start, and one that another installation's endpoint is handed to. scripts/e2e-wsl.sh runs
# them inside two WSL distributions, a run that is started by hand. This runs them on a Unix
# machine, with the two installations told apart by their runtime and state directories, so an
# ordinary step runs them too, and holds the two installations to what e2e-wsl.sh holds its two
# distributions to: each paired a viewer with an endpoint of its own, a viewer is let in where it
# was paired and ended by the other, and neither installation holds a record of the other's viewer.
#
#   bash scripts/distribution-cases.sh
#
# The script builds the daemon and its worker, starts one daemon for each installation from copies
# of the programs below the temporary directory, and ends both when it is done. It exits non-zero
# when any case or check fails; each runs even when an earlier one failed, so one run shows every
# one that does not hold. Written for the bash macOS ships.
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2
root_directory="$PWD"
# shellcheck source=scripts/lib/owned-processes.sh
. "$root_directory/scripts/lib/owned-processes.sh"

# A short root for the installations: a socket address is at most 104 bytes on macOS, and the
# installations' directories are below it.
root="$(mktemp -d /tmp/kr-dc.XXXXXX)" || exit 2
# The programs the daemons run are copies, below the temporary directory, so that they stay what
# was built here while the suite builds its own test programs, and so that a run whose root is the
# temporary directory (scripts/end-to-end.sh) finds a daemon left behind by the programs' paths.
programs="$(mktemp -d "${TMPDIR:-/tmp}/kr-dc-bin.XXXXXX")" || exit 2
built="${CARGO_TARGET_DIR:-$root_directory/target}/debug"
failed=0

# The numbers of the processes this script started that are still running as the process it
# started: a number a process that has ended left, and another process now has, is not one.
daemons_running() {
  local record number started program
  for record in "${owned_processes[@]:-}"; do
    [ -n "$record" ] || continue
    IFS='|' read -r number started program <<<"$record"
    if is_same_process "$number" "$started" "$program"; then
      printf '%s\n' "$number"
    fi
  done
}

# shellcheck disable=SC2329  # run by the trap below
cleanup() {
  local status=$? deadline left
  end_owned_processes
  deadline=$(( $(date +%s) + 30 ))
  while [ -n "$(daemons_running)" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 0.5
  done
  left="$(daemons_running)"
  if [ -n "$left" ]; then
    echo "FAILED: these daemons outlived the script, so $root and $programs are kept:"
    # The numbers are one argument each, which is what this call wants.
    # shellcheck disable=SC2046,SC2086
    ps -o pid=,command= -p $(printf '%s' "$left" | tr '\n' ',') || true
    exit 1
  fi
  rm -rf "${root:?}" "${programs:?}"
  exit "$status"
}
trap cleanup EXIT

problem() {
  echo "FAILED: $*" >&2
  failed=1
}

compact() { tr -d ' \n\r'; }

# The first value one named string key carries in a compacted document, or nothing. These are this
# product's own documents and the key is named in full, so the match is exact.
json_string() {
  awk -v key="\"$1\":\"" '
    {
      start = index($0, key)
      if (start == 0) { exit }
      rest = substr($0, start + length(key))
      end = index(rest, "\"")
      if (end == 0) { exit }
      print substr(rest, 1, end - 1)
      exit
    }'
}

CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
  cargo build -p kr-controller --bin kr-controller -p kr-worker --bin kr-worker || exit 2
for program in kr-controller kr-worker; do
  cp "$built/$program" "$programs/$program" || exit 2
  # Started once, here, where nothing is timed: the operating system checks a newly written
  # executable the first time it starts, and on a loaded machine that check alone can outlast a
  # daemon's wait for its worker.
  "$programs/$program" --version >/dev/null || exit 2
done

first="$root/first"
second="$root/second"
for installation in "$first" "$second"; do
  mkdir -p "$installation/run" "$installation/state" "$installation/acc" || exit 2
  chmod 700 "$installation" "$installation/run" "$installation/state" "$installation/acc" || exit 2
done

# The installation in the directory $1 as its own: the runtime and state directories the daemon and
# the suite find it by, and the directory the suite keeps its keys in.
as_installation() {
  local installation="$1"
  shift
  env KR_RUNTIME_DIR="$installation/run" KR_STATE_DIR="$installation/state" \
    KR_ACC_DIR="$installation/acc" "$@"
}

# Whether something accepts connections on the daemon's endpoint of the installation in the
# directory $1. A socket file a daemon that ended left behind refuses them.
answers() {
  local endpoint
  endpoint="$(find "$1/run" -name c.sock -type s 2>/dev/null | head -n 1)"
  [ -n "$endpoint" ] &&
    python3 -c 'import socket, sys; socket.socket(socket.AF_UNIX).connect(sys.argv[1])' "$endpoint" 2>/dev/null
}

# Starts the daemon of the installation in the directory $1 and waits until it answers. The daemon
# is the process the background job becomes, so the number the job has is the daemon's, and it is
# recorded with when it started and the program it runs: it is ended by that record and no other.
start_daemon() {
  local installation="$1" pid started
  (
    export KR_RUNTIME_DIR="$installation/run" KR_STATE_DIR="$installation/state"
    exec "$programs/kr-controller" --worker "$programs/kr-worker" --secret-store file
  ) >"$installation/controller.log" 2>&1 &
  pid=$!
  remember_process "$pid" "$programs/kr-controller"
  started="$(process_started "$pid")"
  echo "$pid|$started|$programs/kr-controller" >"$installation/daemon"
  for _ in $(seq 1 120); do
    if answers "$installation"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.5
  done
  echo "the daemon of $installation did not answer" >&2
  tail -n 40 "$installation/controller.log" >&2
  exit 2
}

# Ends the daemon of the installation in the directory $1 by its record, and waits until it has
# gone, so that the next one finds the environment free.
stop_daemon() {
  local installation="$1" number started program
  IFS='|' read -r number started program <"$installation/daemon"
  end_process "$number" "$started" "$program"
  for _ in $(seq 1 120); do
    is_same_process "$number" "$started" "$program" || return 0
    sleep 0.5
  done
  echo "the daemon of $installation did not end" >&2
  exit 2
}

# One case of the suite inside the installation in the directory $1, with the endpoint of the other
# installation ($2, which only some cases read). What it printed is kept in $1/case.log.
run_case() {
  local installation="$1" other="$2" name="$3" status
  echo "== $name in $installation"
  as_installation "$installation" env KR_ACC_OTHER="$other" \
    cargo test -p kr-controller --test distribution_endpoints -- \
    --ignored --exact --nocapture --test-threads 1 "$name" >"$installation/case.log" 2>&1
  status=$?
  if [ "$status" -ne 0 ] || ! grep -q 'test result: ok. 1 passed' "$installation/case.log"; then
    cat "$installation/case.log"
    problem "$name did not pass in $installation"
    return 1
  fi
}

# The JSON a case printed on a line of one kind, which is the first such line.
printed() {
  sed -n "s/.*acceptance-fact $2 //p" "$1/case.log" | head -n 1
}

start_daemon "$first"
start_daemon "$second"

# The loopback network is a document the daemon reads when it starts, so both are started again.
run_case "$first" "" prepare_the_network
run_case "$second" "" prepare_the_network
stop_daemon "$first"
stop_daemon "$second"
start_daemon "$first"
start_daemon "$second"

# Each installation pairs a viewer with its own endpoint, and the two are two environments, two
# endpoint identities and two viewers.
run_case "$first" "" pair_a_viewer_with_this_distribution
first_endpoint="$(printed "$first" endpoint | compact)"
first_device="$(printed "$first" viewer | compact | json_string device_id)"
first_transport="$(printed "$first" viewer | compact | json_string transport)"
run_case "$second" "" pair_a_viewer_with_this_distribution
second_endpoint="$(printed "$second" endpoint | compact)"
second_device="$(printed "$second" viewer | compact | json_string device_id)"
second_transport="$(printed "$second" viewer | compact | json_string transport)"
if [ -z "$first_endpoint" ] || [ -z "$second_endpoint" ] || [ -z "$first_device" ] ||
  [ -z "$second_device" ] || [ -z "$first_transport" ] || [ -z "$second_transport" ]; then
  echo "an installation paired a viewer and reported no endpoint or device" >&2
  exit 1
fi
first_id="$(compact <"$first/state/environment-id")"
second_id="$(compact <"$second/state/environment-id")"
[ "$(printf '%s' "$first_endpoint" | json_string environment_id)" = "$first_id" ] ||
  problem "the endpoint paired in the first installation is not the environment it holds: $first_endpoint"
[ "$(printf '%s' "$second_endpoint" | json_string environment_id)" = "$second_id" ] ||
  problem "the endpoint paired in the second installation is not the environment it holds: $second_endpoint"
[ "$first_id" != "$second_id" ] ||
  problem "two installations hold one environment identity"
[ "$(printf '%s' "$first_endpoint" | json_string endpoint_id)" != "$(printf '%s' "$second_endpoint" | json_string endpoint_id)" ] ||
  problem "two installations answered with one endpoint identity"

# Each viewer reaches the installation it was paired with and is ended by the other.
run_case "$first" "$second_endpoint" a_viewer_reaches_only_the_distribution_it_was_paired_with
run_case "$second" "$first_endpoint" a_viewer_reaches_only_the_distribution_it_was_paired_with

# What each installation holds of devices and grants: its own viewer, and none of the other's. The
# search can only find a record the report carries, so each report is first shown to carry its own
# viewer's.
run_case "$first" "" report_the_devices_and_grants
first_held="$(printed "$first" held | compact)"
run_case "$second" "" report_the_devices_and_grants
second_held="$(printed "$second" held | compact)"
if [ -z "$first_held" ] || [ -z "$second_held" ]; then
  problem "an installation reported nothing of its devices and grants"
else
  case "$first_held" in
    *"$first_device"*"$first_transport"* | *"$first_transport"*"$first_device"*) : ;;
    *) problem "the first installation's report holds no record of the viewer paired with it" ;;
  esac
  case "$second_held" in
    *"$second_device"*"$second_transport"* | *"$second_transport"*"$second_device"*) : ;;
    *) problem "the second installation's report holds no record of the viewer paired with it" ;;
  esac
  case "$second_held" in
    *"$first_device"* | *"$first_transport"*) problem "the second installation holds a record of the viewer paired with the first" ;;
  esac
  case "$first_held" in
    *"$second_device"* | *"$second_transport"*) problem "the first installation holds a record of the viewer paired with the second" ;;
  esac
fi

exit "$failed"
