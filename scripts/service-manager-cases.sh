#!/usr/bin/env bash
# Runs the cases that need a user service manager for the account that runs them. An ordinary run
# leaves them out, because they are ignored where the account has none (a hosted runner's); this
# script is where a Linux host whose account has one runs each of them:
#
#   bash scripts/service-manager-cases.sh
#
# It runs from anywhere inside the repository. It refuses a host that is not Linux and an account
# whose `systemctl --user` does not answer, with exit 2 and before it runs any case, so that a host
# without a manager fails the step instead of passing it with nothing run. Each command below must
# report that it passed exactly the cases it names after `--exact`: a case that was renamed or
# removed is filtered out, and cargo then exits 0 having run nothing. The script exits non-zero
# when any command fails or runs less than it names; each command runs even when an earlier one
# failed, so one run shows every case that does not hold. It starts no unit of its own and removes
# nothing: the units a case leaves behind when it dies are the caller's to end.
set -u

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

if [ "$(uname -s)" != Linux ]; then
  echo "service-manager-cases: these cases run only on Linux" >&2
  exit 2
fi
if ! systemctl --user show --property=Version --value > /dev/null 2>&1; then
  echo "service-manager-cases: this account has no user service manager (\`systemctl --user\` does not answer)" >&2
  exit 2
fi

failed=0
step() {
  echo "== $*"
  local output status=0 exact=0 named=0 word
  output=$("$@" 2>&1) || status=$?
  printf '%s\n' "$output"
  for word in "$@"; do
    if [ "$exact" = 1 ]; then
      named=$((named + 1))
    elif [ "$word" = --exact ]; then
      exact=1
    fi
  done
  if [ "$status" -ne 0 ]; then
    echo "service-manager-cases: the command exited $status" >&2
    failed=1
  elif [ "$named" -eq 0 ] || ! printf '%s\n' "$output" | grep -q "^test result: ok\. $named passed; 0 failed;"; then
    echo "service-manager-cases: the command did not pass the $named case(s) it names after --exact" >&2
    failed=1
  fi
}

step cargo test --locked -p kr-worker --test host -- --ignored --exact a_crashed_workers_tree_is_stopped_under_the_platforms_service_manager
step cargo test --locked -p kr-worker --test host -- --ignored --exact a_session_in_a_service_rests_on_a_control_group_and_a_close_ends_what_left_its_tree

exit "$failed"
