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
# acknowledged - whether the leg passed or failed. Anything a leg could not take back is named in
# the closing section, and the service's own retention is what then ends it.
#
# The origin must be an HTTPS one and must carry no credentials. This sends signed requests to
# whatever it is given, so an address that is not a deployment's, or one with a password in front of
# the host, is refused before anything is built.
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

case "$origin" in
  https://*) ;;
  *)
    echo "this checks a deployment, and a deployment is reached over HTTPS: $origin" >&2
    exit 2
    ;;
esac
case "$origin" in
  *@* | *[[:space:]]*)
    # An address may carry a user name and a password in front of the host, and this report is
    # written to a log. The address itself is the only thing here that could carry a secret.
    echo "an origin this reports on carries no credentials" >&2
    exit 2
    ;;
esac

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

# Section 27 puts every test artefact in one directory. One log per leg lands there, so a leg that
# failed leaves its whole output behind rather than the few lines this report prints.
evidence="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/deployment"
rm -rf "${evidence:?}"
mkdir -p "$evidence"

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

# Runs one leg on its own and prints the one line it gets in the report.
#
# On its own, in a process of its own, because the report says what each leg found rather than what
# a whole suite's exit code was: a leg that failed is named beside the ones that passed.
run_leg() {
  local group="$1"
  local leg="$2"
  local log="$evidence/$group-$leg.log"
  local rc=0
  local proved
  KR_DEPLOYED_ORIGIN="$origin" KR_REQUIRE_DEPLOYED_ORIGIN=1 \
    cargo test --locked -p "$suite" --test "$group" -- \
    --exact "$leg" --nocapture --test-threads=1 >"$log" 2>&1 || rc=$?

  # What the leg itself said it proved, in its own words: one line naming the deployment it ran
  # against. Absent one, the leg's name is what the report has to show.
  proved="$(grep -F " ($origin)" "$log" | tail -n 1 || true)"
  proved="${proved#*: }"
  proved="${proved% ($origin)}"
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
  legs=0
  while IFS= read -r leg; do
    [ -n "$leg" ] || continue
    legs=$((legs + 1))
    run_leg "$group" "$leg"
  done < <(cargo test --locked --quiet -p "$suite" --test "$group" -- --list 2>/dev/null |
    sed -n 's/: test$//p')
  if [ "$legs" -eq 0 ]; then
    failed=$((failed + 1))
    printf '  %-7s %-14s %s\n' FAILED "$group" "this group named no legs at all"
  fi
done

echo
total=$((passed + failed + missed))
echo "$total legs against $origin: $passed passed, $failed failed, $missed did not run"

# What is still on the deployment. Each leg gives back what it took before it reports, and says so
# when it could not; this is where a run that left something behind names it.
left="$(grep -h 'could not give back what it took' "$evidence"/*.log 2>/dev/null || true)"
if [ -n "$left" ]; then
  echo
  echo "left on the deployment until its own retention ends it:"
  echo "$left" | sed 's/^/  /'
elif [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ]; then
  echo "every key this run signed with was made for it, and every leg gave back what it took"
fi

if [ "$failed" -ne 0 ] || [ "$missed" -ne 0 ]; then
  if [ "${#unfinished[@]}" -ne 0 ]; then
    echo
    echo "what to look at, in $evidence:"
    for what in "${unfinished[@]}"; do
      echo "  $what.log"
    done
  fi
  exit 1
fi
