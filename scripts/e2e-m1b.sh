#!/usr/bin/env bash
# The cross-boundary checkpoint: a real host, a paired device and the deployed site, leg by leg.
#
# Every leg under tests/e2e/m1b runs the processes a person runs - the kr-controller daemon, the
# kr-worker it launches for each session and kr on real terminals, all built from this tree and
# copied to the internal disk - with a paired device that is this repository's native client library
# over iroh, against the origin it is given. It prints the commit, the host, the time and the origin,
# then one line per leg, then what the run left on the deployment.
#
#   site       the origin answers and names its build; a host reserves its invitations there, and an
#              origin that serves no rendezvous is a configuration error
#   pairing    a device pairs by short code through the deployed rendezvous and by direct QR over
#              loopback iroh, and both connect with kr-connect/1; a wrong code is counted
#   terminal   the terminal workflow from the paired device, in a managed shell built from this tree
#   catalogue  the published catalogue release, enrolled on the device's confirmation, synchronised
#              and installed, byte for byte the bundled copy
#   plugin     the installed package bound into a running session and invoked through its broker
#
# What it sends, and what it leaves. Every key a leg uses is made for that leg. A pairing through the
# deployment uses one invitation and one rendezvous room, and the host releases the room's locator
# when the invitation ends; each leg says in its last line what it left on the deployment, and this
# report gathers those lines. Nothing here removes anything: each run keeps its own evidence
# directory, with one log per leg.
#
# The origin is checked before anything is printed or built. It must name HTTPS and it must be a host
# and an optional port and nothing else. A refusal says which rule the value broke and never repeats
# the value, since this report is written to a log.
#
# The managed shell the terminal leg runs is the package KR_SHELL_PACKAGES, KR_SHELL_PREFIX or the
# build script's default prefix names; scripts/build-shells.sh --zsh builds it from this tree, and a
# missing package fails that leg with its reason. The catalogue leg enrols the release
# KR_M1B_CATALOGUE_RELEASE names, and fails saying so when it names none.
#
# Usage: scripts/e2e-m1b.sh https://example.invalid
#        KR_M1B_ORIGIN=https://example.invalid scripts/e2e-m1b.sh
#
# It exits 0 when every leg passed, 1 when any leg failed or did not run, and 2 when it was given no
# usable origin.
set -euo pipefail

# This compares an address byte by byte and reads what the legs print. Both are ASCII, and a
# collation order that is not the C one would put accented letters inside a range of plain ones.
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

suite=kr-e2e-m1b
group=checkpoint

# The legs in the order they run, each as the word the report uses and the test that is the leg.
# Every test in the group must be named here, so a leg that was added stays out of no report.
legs=(
  "site:the_site_answers_and_a_host_reserves_its_invitations_there"
  "pairing:a_device_pairs_by_code_through_the_site_and_by_direct_qr_over_loopback"
  "terminal:a_device_uses_an_agent_in_a_managed_shell_and_reattaches_to_the_screen_kr_attach_draws"
  "catalogue:the_host_installs_the_published_catalogue_release_byte_for_byte_the_bundled_copy"
  "plugin:the_installed_package_is_bound_into_the_session_and_acts_through_its_broker"
)

origin="${1:-${KR_M1B_ORIGIN:-}}"
if [ -z "$origin" ]; then
  echo "usage: scripts/e2e-m1b.sh <https origin>" >&2
  echo "       the origin may come from KR_M1B_ORIGIN instead" >&2
  exit 2
fi

# The rules a rendezvous origin is held to, applied here so that a value which is not one is refused
# before it reaches a log, a request or a directory name. Nothing below repeats the value.
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
# What is left once every character a host and a port may hold is taken out. Anything that
# survives is a value that is not an origin.
if [ -n "${authority//[]a-z0-9.:[-]/}" ]; then
  echo "an origin is a lower-case host and an optional port in printable ASCII, and nothing else" >&2
  exit 2
fi

# Section 27 puts every test artefact in one directory. This run takes a new directory of its own
# under it and writes one log per leg there, so a leg that failed leaves its whole output behind.
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
case "$artefacts" in
  /*) ;;
  *) artefacts="$PWD/$artefacts" ;;
esac
mkdir -p "$artefacts"
evidence="$(mktemp -d "$artefacts/m1b-XXXXXX")"

echo "kalareach cross-boundary checkpoint"
echo "  commit: $(git rev-parse HEAD 2>/dev/null || echo 'not a checkout')"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  origin: $origin"
echo "  evidence: $evidence"
echo

# Built once, before anything is sent, so a build failure is not reported as a leg that failed. The
# legs launch these binaries from beside their own test binary.
if ! cargo build --locked --quiet -p kr-cli -p kr-controller -p kr-worker --bins \
  >"$evidence/build.log" 2>&1 ||
  ! cargo test --locked --quiet -p "$suite" --no-run >>"$evidence/build.log" 2>&1; then
  tail -20 "$evidence/build.log" >&2
  echo "the legs did not build, so nothing was contacted" >&2
  exit 1
fi

# Every test in the group is a leg this report names, and every leg it names is a test.
listed=0
names="$(cargo test --locked --quiet -p "$suite" --test "$group" -- --list \
  2>"$evidence/listing.log")" || listed=$?
if [ "$listed" -ne 0 ]; then
  echo "the legs could not be listed, so none was run" >&2
  exit 1
fi
names="$(printf '%s\n' "$names" | sed -n 's/: test$//p')"
while IFS= read -r name; do
  [ -n "$name" ] || continue
  case " ${legs[*]} " in
    *":$name "*) ;;
    *)
      echo "$name is a leg this report does not name, so it would not be run" >&2
      exit 2
      ;;
  esac
done <<<"$names"

passed=0
failed=0
missed=0
unfinished=()
left=()

# Runs one leg on its own and prints the one line it gets in the report: what it proved when it
# passed, and why it stopped when it did not.
run_leg() {
  local word="$1"
  local name="$2"
  local log="$evidence/$word.log"
  local rc=0
  local line
  local proved=""
  local reason=""
  local reported=""
  local after_panic=0
  local suffix=" ($origin)"
  KR_M1B_ORIGIN="$origin" KR_REQUIRE_M1B=1 KR_REQUIRE_SHELL_PACKAGES=1 \
    cargo test --locked -p "$suite" --test "$group" -- \
    --exact "$name" --nocapture --test-threads=1 >"$log" 2>&1 || rc=$?

  while IFS= read -r line; do
    if [ "$after_panic" -eq 1 ]; then
      # The first line of the message is the reason the report gives.
      [ -n "$reason" ] || reason="$line"
      after_panic=0
      continue
    fi
    case "$line" in
      # What the leg said it proved: its closing line names the deployment it ran against. Matched
      # as a whole ending, so a sentence that mentions the origin is not mistaken for it.
      "$word: "*" ($origin)")
        proved="${line#"$word: "}"
        proved="${proved%"$suffix"}"
        ;;
      "left on the deployment by the $word leg: "*)
        reported="${line#"left on the deployment by the $word leg: "}"
        ;;
      "thread '"*" panicked at "*)
        after_panic=1
        ;;
    esac
  done <"$log"

  if [ "$rc" -ne 0 ]; then
    failed=$((failed + 1))
    unfinished+=("$word")
    printf '  %-7s %-10s %s\n' FAILED "$word" "${reason:-see its log}"
  elif grep -q '^test result: ok\. 1 passed' "$log" && [ -n "$proved" ]; then
    passed=$((passed + 1))
    printf '  %-7s %-10s %s\n' ok "$word" "$proved"
  else
    # It did not fail and it proved nothing: a leg that skipped, or a name nothing matched. A run
    # that named a deployment and then ran nothing against it has proved nothing.
    missed=$((missed + 1))
    unfinished+=("$word")
    printf '  %-7s %-10s %s\n' 'NOT RUN' "$word" "it passed without saying what it proved"
  fi
  if [ -n "$reported" ]; then
    left+=("$word: $reported")
  else
    left+=("$word: the leg did not say; its log records every request it sent")
  fi
}

for leg in "${legs[@]}"; do
  run_leg "${leg%%:*}" "${leg#*:}"
done

echo
total=$((passed + failed + missed))
echo "$total legs against $origin: $passed passed, $failed failed, $missed did not run"
echo
echo "what the run left on the deployment:"
printf '  %s\n' "${left[@]}"

if [ "$failed" -eq 0 ] && [ "$missed" -eq 0 ]; then
  exit 0
fi
echo
echo "what to look at, in $evidence:"
for what in "${unfinished[@]}"; do
  echo "  $what.log"
done
exit 1
