#!/usr/bin/env bash
# Shows that owned-processes.sh signals a recorded process only while it is still that process.
#
#   bash scripts/lib/owned-processes-check.sh
#
# It starts two processes of its own and asks the helper to end the second under records that no
# longer describe it: the start time of the first, which is what a number handed on to a new
# process looks like, and another program. Each must leave it running. Then the true record must
# end it, and a record of a process that has gone must be passed over in silence. Every process it
# starts it ends by the number it recorded, and it exits non-zero if any of this did not hold.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/lib/owned-processes.sh
. "$here/owned-processes.sh"

failed=0
fail() {
  echo "FAILED: $*"
  failed=1
}

sleep 300 &
first=$!
first_started="$(process_started "$first")"
# The kernel's start time is to the second, so the second process starts in a later one.
sleep 1.2
sleep 300 &
second=$!
second_started="$(process_started "$second")"
sleep_program="$(process_command "$second")"
sleep_program="${sleep_program%% *}"
# Whatever happens below, each is ended on the way out by its own record, so a number that has
# been collected and handed on by then is not signalled.
cleanup() {
  end_process "$first" "$first_started" "$sleep_program" >/dev/null
  end_process "$second" "$second_started" "$sleep_program" >/dev/null
}
trap cleanup EXIT

[ -n "$first_started" ] && [ -n "$second_started" ] || fail "both processes are described"
[ "$first_started" != "$second_started" ] || fail "the two processes started in different seconds"
echo "the second process is $second, $sleep_program, started $second_started"

# A number whose process started at another time is another process.
said="$(end_process "$second" "$first_started" "$sleep_program")"
echo "  under the first process's start time: $said"
if is_same_process "$second" "$second_started" "$sleep_program"; then
  echo "  ok: a number that names a process started at another time is left alone"
else
  fail "a number that names a process started at another time was signalled"
fi

# A number whose process runs another program is another process.
said="$(end_process "$second" "$second_started" "/usr/bin/not-what-was-started")"
echo "  under another program: $said"
if is_same_process "$second" "$second_started" "$sleep_program"; then
  echo "  ok: a number that names a process running another program is left alone"
else
  fail "a number that names a process running another program was signalled"
fi

# The record that describes it ends it.
end_process "$second" "$second_started" "$sleep_program"
wait "$second" 2>/dev/null || true
if is_same_process "$second" "$second_started" "$sleep_program"; then
  fail "the process the record describes was not ended"
else
  echo "  ok: the process the record describes is ended"
fi

# A process that has gone leaves nothing to signal and nothing to say.
end_process "$first" "$first_started" "$sleep_program"
wait "$first" 2>/dev/null || true
said="$(end_process "$first" "$first_started" "$sleep_program")"
if [ -z "$said" ] || [ "$(process_started "$first")" != "$first_started" ]; then
  echo "  ok: a record of a process that has gone signals nothing"
else
  fail "a record of a process that has gone was taken for a live one: $said"
fi

# And a process that has gone before it is recorded is not recorded, without ending a script that
# runs under `set -e` and `pipefail`, as this one does.
remember_process "$first" "$sleep_program"
if [ "${#owned_processes[@]}" -eq 0 ]; then
  echo "  ok: a process that has gone is not recorded, and the script carries on"
else
  fail "a process that has gone was recorded: ${owned_processes[*]}"
fi

if [ "$failed" -ne 0 ]; then
  exit 1
fi
echo "every record was honoured"
