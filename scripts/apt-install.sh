#!/usr/bin/env bash
# Installs apt packages on a hosted Linux runner whose Ubuntu mirror is slow or failing.
#
#   bash scripts/apt-install.sh [--deadline SECONDS] [--names-from SCRIPT] [PACKAGE...]
#
# apt has no minimum transfer rate. A mirror that answers slowly keeps one download going for as
# long as bytes arrive, and the image's timeout and its failover to the next mirror act on a silent
# connection only, so a step that needs 70 to 100 MB can run for an hour at 30 kB/s and then fail
# on a mirror that starts to answer 503. This script puts every call that reaches the network under
# a bound and tries again until its deadline, then installs from the archives it fetched, with no
# network:
#
#   1. `apt-get update`, bound 180 s. A non-zero exit fails the attempt. An exit of 0 that printed
#      `W: Failed to fetch` is what a 503 on an index gives, since apt reports a failed index as a
#      warning: the update runs again, twice at most, after 10 and 20 s, and then the attempt goes
#      on with the indexes it has. If the index arrives at less than about 72 kB/s (13 MB in 180 s)
#      this bound stops every update, and the step fails at its deadline.
#   2. With --names-from, the program SCRIPT is run by bash against the indexes just updated and
#      prints one package name per line, which are installed with the PACKAGEs. It runs again in
#      each attempt, after that attempt's last update, so the names match the indexes the download
#      and the install use. A failure of the program ends the script.
#   3. `apt-get install --simulate`, bound 120 s, with no network. When the update printed no
#      warning, a failure is the packages' own (an unknown name, a conflict) and ends the script
#      at once with apt's lines; otherwise the indexes may be the cause and the attempt is retried.
#   4. `apt-get install --download-only`, bound by the time left. Exit 0 ends the attempts.
#   A failed attempt prints its number, its status (124 means that a bound cut it) and the last
#   three lines of its output, waits 10 s times its number (at most 60 s, never past the deadline)
#   and starts again, until the deadline.
#   5. `apt-get install --no-download`, once and not under a bound: a package whose archive is
#      missing fails the install and is not fetched. Its status is the script's.
#
# Every bound is `sudo timeout --kill-after=G T ...`, with `timeout` inside `sudo` so that it can
# signal the root process on every runner image, and G + T equal to the bound, where G is 10 s or,
# for a bound of 10 s or less, the bound less 1 s. A call is never given less than 2 s and never
# given 0, which `timeout` reads as no limit.
set -euo pipefail

usage() {
  echo "usage: apt-install.sh [--deadline SECONDS] [--names-from SCRIPT] [PACKAGE...]" >&2
  exit 2
}

deadline=1800
names_from=
packages=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --deadline)
      [ "$#" -ge 2 ] || usage
      deadline=$2
      shift 2
      ;;
    --names-from)
      [ "$#" -ge 2 ] || usage
      names_from=$2
      shift 2
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        packages+=("$1")
        shift
      done
      ;;
    -*) usage ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done
case "$deadline" in '' | *[!0-9]*) usage ;; esac
[ "$deadline" -ge 2 ] || usage

start=$SECONDS
work=$(mktemp -d)
trap 'sudo rm -rf -- "$work"' EXIT

# The seconds left before the deadline.
remaining() {
  echo $((deadline - (SECONDS - start)))
}

# pause SECONDS: waits, at most 60 s and always leaving a second before the deadline.
pause() {
  local seconds=$1 left
  [ "$seconds" -le 60 ] || seconds=60
  left=$(remaining)
  [ "$seconds" -lt "$left" ] || seconds=$((left - 1))
  if [ "$seconds" -gt 0 ]; then
    echo "apt-install: waiting ${seconds}s"
    sleep "$seconds"
  fi
}

# run_apt BOUND LOG ARGUMENT...: `apt-get ARGUMENT...` as root, ended inside BOUND seconds, its
# output shown and kept in LOG. The status is apt's, or timeout's 124 and 137.
run_apt() {
  local bound=$1 log=$2 grace=10 status=0
  shift 2
  [ "$grace" -lt "$bound" ] || grace=$((bound - 1))
  echo "apt-install: sudo timeout --kill-after=$grace $((bound - grace)) env DEBIAN_FRONTEND=noninteractive apt-get $*"
  sudo timeout --kill-after="$grace" "$((bound - grace))" env DEBIAN_FRONTEND=noninteractive apt-get "$@" 2>&1 | tee "$log" || status=${PIPESTATUS[0]}
  return "$status"
}

# bound_for CAP: the smaller of CAP and the time left, or a failure when under 2 s are left.
bound_for() {
  local cap=$1 left
  left=$(remaining)
  [ "$left" -gt 1 ] || return 1
  if [ "$left" -lt "$cap" ]; then
    echo "$left"
  else
    echo "$cap"
  fi
}

total_warnings=0
last_warnings=0
failed_log=
all=()

# update_indexes: step 1.
update_indexes() {
  local round=0 bound status=0 warnings
  while :; do
    bound=$(bound_for 180) || return 124
    round=$((round + 1))
    if run_apt "$bound" "$work/update.log" update; then
      status=0
    else
      status=$?
    fi
    if [ "$status" -ne 0 ]; then
      failed_log=$work/update.log
      return "$status"
    fi
    warnings=$(grep -c '^W: Failed to fetch' "$work/update.log" || true)
    last_warnings=$warnings
    total_warnings=$((total_warnings + warnings))
    if [ "$warnings" -eq 0 ] || [ "$round" -ge 3 ]; then
      return 0
    fi
    echo "apt-install: the update printed $warnings failed fetches, update $round of at most 3"
    pause $((10 * round))
  done
}

# find_names: step 2. Sets `all` to the named packages and those the program prints.
find_names() {
  local out line
  all=()
  if [ "${#packages[@]}" -gt 0 ]; then
    all=("${packages[@]}")
  fi
  [ -n "$names_from" ] || return 0
  if ! out=$(bash "$names_from" 2> "$work/names.err"); then
    cat "$work/names.err" >&2
    echo "apt-install: $names_from failed" >&2
    exit 1
  fi
  while IFS= read -r line; do
    if [ -n "$line" ]; then
      all+=("$line")
    fi
  done <<< "$out"
}

# resolve: step 3.
resolve() {
  local bound status=0
  bound=$(bound_for 120) || return 124
  if run_apt "$bound" "$work/resolve.log" install --simulate --no-install-recommends "${all[@]}"; then
    return 0
  else
    status=$?
  fi
  if [ "$last_warnings" -eq 0 ]; then
    echo "apt-install: apt cannot plan the install of: ${all[*]}" >&2
    grep '^E:' "$work/resolve.log" >&2 || true
    exit 1
  fi
  failed_log=$work/resolve.log
  return "$status"
}

# attempt: steps 1 to 4, once.
attempt() {
  local bound status=0
  update_indexes || return $?
  find_names
  if [ "${#all[@]}" -eq 0 ]; then
    return 0
  fi
  resolve || return $?
  bound=$(bound_for "$deadline") || return 124
  if run_apt "$bound" "$work/download.log" install --download-only --no-install-recommends --yes "${all[@]}"; then
    return 0
  else
    status=$?
  fi
  failed_log=$work/download.log
  return "$status"
}

echo "apt-install: deadline ${deadline}s, packages: ${packages[*]-}${names_from:+, and the names $names_from prints}"
apt-config dump 2>&1 |
  grep -E '^Acquire::(Retries|http::(Timeout|Dl-Limit|Pipeline-Depth|No-Cache|BrokenProxy)|https::(Timeout|Dl-Limit)) ' || true
for file in /etc/apt/apt-mirrors.txt /etc/apt/sources.list /etc/apt/sources.list.d/*; do
  if [ -f "$file" ]; then
    echo "apt-install: $file"
    cat "$file"
  fi
done

attempts=0
status=1
while [ "$(remaining)" -gt 1 ]; do
  attempts=$((attempts + 1))
  failed_log=
  if attempt; then
    status=0
    break
  else
    status=$?
  fi
  echo "apt-install: attempt $attempts failed, status $status"
  if [ -n "$failed_log" ]; then
    tail -n 3 "$failed_log"
  fi
  pause $((10 * attempts))
done
if [ "$status" -ne 0 ]; then
  echo "apt-install: failed: deadline=${deadline}s attempts=$attempts warnings=$total_warnings last_status=$status" >&2
  exit 1
fi

install_status=0
if [ "${#all[@]}" -gt 0 ]; then
  echo "apt-install: sudo env DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --no-download --yes ${all[*]}"
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --no-download --yes "${all[@]}" || install_status=$?
fi
echo "apt-install: packages=${#all[@]} attempts=$attempts warnings=$total_warnings elapsed=$((SECONDS - start))s"
exit "$install_status"
