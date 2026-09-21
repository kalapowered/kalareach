#!/usr/bin/env bash
# What a deployment answers, leg by leg, after it has been deployed.
#
# Every other suite in this repository checks a client against something this repository wrote: a
# mock, a loopback server, a service half running inside the test. The legs under
# `tests/integration/sync` check it against a live deployment instead, and this is the one command
# that runs them and reports what they found. It prints the commit, the host, the time and the
# origin, then one line per leg, then what the run left behind.
#
# What it sends, and what it leaves. Every principal is made when a leg starts and discarded when it
# ends: a fresh authorisation key signs, and the identifiers the legs publish are drawn for the run
# alone, so a leg touches nothing that was not made for it. Each leg gives back what it took before
# it reports - a host removes itself from the feed it enrolled in, a mailbox is emptied and
# acknowledged - whether the leg passed or failed. What a leg could not take back is named in the
# closing lines, and it is the deployment's to end: a durable record ends when it is acknowledged,
# refused or removed, and not by a lapse of time.
#
# The origin is checked before anything is printed or built. It must name HTTPS and it must be a
# host and an optional port and nothing else, because this signs requests to whatever it is given
# and because an address may carry a user name and a password in front of the host. A refusal says
# which rule the value broke and never repeats the value, since this report is written to a log.
#
# Usage: scripts/e2e-mailbox.sh https://example.invalid
#        KR_DEPLOYED_ORIGIN=https://example.invalid scripts/e2e-mailbox.sh
#
# It exits 0 when every leg passed, 1 when any leg failed or did not run, and 2 when it was given no
# usable origin.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

suite=kr-sync-integration

# The order the report reads in. Every file under the suite's `tests/` directory must be named here,
# so a group of legs that was added stays out of no report: an unnamed one stops this run rather
# than passing unnoticed.
groups=(mailbox authority)

origin="${1:-${KR_DEPLOYED_ORIGIN:-}}"
if [ -z "$origin" ]; then
  echo "usage: scripts/e2e-mailbox.sh <https origin>" >&2
  echo "       the origin may come from KR_DEPLOYED_ORIGIN instead" >&2
  exit 2
fi

# The same rules a gateway origin is held to, applied here so that a value which is not one is
# refused before it reaches a log, a signed request or a directory name. Nothing below repeats the
# value: whoever typed it has it, and a log that quoted it would publish whatever was in it.
authority="${origin#https://}"
if [ "$authority" = "$origin" ]; then
  echo "this checks a deployment, and a deployment is reached over https://" >&2
  exit 2
fi
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
# What is left once every character a host and a port may hold is taken out. A space, a control
# character, a byte outside ASCII and every punctuation mark an address has no use for all survive
# this, and any of them is a value that is not an origin.
if [ -n "$(printf '%s' "$authority" | tr -d 'A-Za-z0-9.:[]-')" ]; then
  echo "an origin is a host and an optional port in printable ASCII, and nothing else" >&2
  exit 2
fi

for file in tests/integration/sync/tests/*.rs; do
  name="$(basename "$file" .rs)"
  case " ${groups[*]} " in
    *" $name "*) ;;
    *)
      echo "$file holds legs this report does not name, so they would not be run" >&2
      exit 2
      ;;
  esac
done

# Section 27 puts every test artefact in one directory. This run takes a new directory of its own
# under it and writes one log per leg there, so a leg that failed leaves its whole output behind
# rather than the few lines this report prints. It is a directory this run made: nothing here
# removes anything, so a second run beside this one keeps its own evidence and neither loses it.
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
case "$artefacts" in
  /*) ;;
  *) artefacts="$PWD/$artefacts" ;;
esac
mkdir -p "$artefacts"
evidence="$(mktemp -d "$artefacts/deployment-XXXXXX")"

echo "kalareach deployment checkpoint"
echo "  commit: $(git rev-parse HEAD 2>/dev/null || echo 'not a checkout')"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  origin: $origin"
echo "  evidence: $evidence"
echo

# Built once, before anything is sent, so a build failure is not reported as a deployment that
# answered wrongly.
if ! cargo test --locked --quiet -p "$suite" --no-run; then
  echo "the legs did not build, so this deployment was not contacted" >&2
  exit 1
fi

passed=0
failed=0
missed=0
unfinished=()
left_behind=""
newline=$'\n'

# Runs one leg on its own and prints the one line it gets in the report.
#
# On its own, in a process of its own, because the report says what each leg found rather than what
# a whole suite's exit code was: a leg that failed is named beside the ones that passed.
run_leg() {
  local group="$1"
  local leg="$2"
  local log="$evidence/$group-$leg.log"
  local rc=0
  local line
  local proved=""
  KR_DEPLOYED_ORIGIN="$origin" KR_REQUIRE_DEPLOYED_ORIGIN=1 \
    cargo test --locked -p "$suite" --test "$group" -- \
    --exact "$leg" --nocapture --test-threads=1 >"$log" 2>&1 || rc=$?

  while IFS= read -r line; do
    case "$line" in
      # What the leg itself said it proved, in its own words: its closing line names the deployment
      # it ran against. Matched as a whole ending rather than anywhere in the line, so a sentence
      # that mentions the origin is not mistaken for it.
      *" ($origin)")
        proved="${line#*: }"
        proved="${proved% (*)}"
        ;;
      # A leg says so when it published something and the deployment would not take it back,
      # whether it reported that itself or failed on it.
      *"give back what it took"*)
        left_behind="$left_behind$newline  $group/$leg: ${line#*took: }"
        ;;
    esac
  done <"$log"
  [ -n "$proved" ] || proved="$leg"

  if [ "$rc" -ne 0 ]; then
    failed=$((failed + 1))
    unfinished+=("$group-$leg")
    printf '  %-7s %-14s %s\n' FAILED "$group" "$leg"
  elif grep -q '^test result: ok\. 1 passed' "$log"; then
    passed=$((passed + 1))
    printf '  %-7s %-14s %s\n' ok "$group" "$proved"
  else
    # It did not fail and it did not run: a leg that is ignored, or a name nothing matched. A run
    # that named a deployment and then ran nothing against it has proved nothing.
    missed=$((missed + 1))
    unfinished+=("$group-$leg")
    printf '  %-7s %-14s %s\n' 'NOT RUN' "$group" "$leg"
  fi
}

for group in "${groups[@]}"; do
  listed=0
  names=""
  # Asked for and checked before any of it is used. A listing that was cut short would otherwise be
  # run as though it were the whole group, and a report of what ran would be missing legs without
  # saying so.
  names="$(cargo test --locked --quiet -p "$suite" --test "$group" -- --list \
    2>"$evidence/$group-listing.log")" || listed=$?
  if [ "$listed" -ne 0 ]; then
    failed=$((failed + 1))
    unfinished+=("$group-listing")
    printf '  %-7s %-14s %s\n' FAILED "$group" "the legs of this group could not be listed"
    continue
  fi
  names="$(printf '%s\n' "$names" | sed -n 's/: test$//p')"
  if [ -z "$names" ]; then
    failed=$((failed + 1))
    unfinished+=("$group-listing")
    printf '  %-7s %-14s %s\n' FAILED "$group" "this group named no legs at all"
    continue
  fi
  while IFS= read -r leg; do
    [ -n "$leg" ] || continue
    run_leg "$group" "$leg"
  done <<<"$names"
done

echo
total=$((passed + failed + missed))
echo "$total legs against $origin: $passed passed, $failed failed, $missed did not run"

# What is still on the deployment. Each leg gives back what it took before it reports, and says so
# when it could not; this is where a run that left something behind names it.
if [ -n "$left_behind" ]; then
  echo
  echo "what these legs could not give back:"
  printf '%s\n' "${left_behind#"$newline"}"
  echo "  whatever of theirs did reach the deployment is still there: a durable record ends when it"
  echo "  is acknowledged, refused or removed, and not by a lapse of time"
fi

if [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ]; then
  echo "every key this run signed with was made for it, and every leg gave back what it took"
  exit 0
fi

echo "a leg that did not finish may have published what it never took back; its log says what it reached"
if [ "${#unfinished[@]}" -ne 0 ]; then
  echo
  echo "what to look at, in $evidence:"
  for what in "${unfinished[@]}"; do
    echo "  $what.log"
  done
fi
exit 1
