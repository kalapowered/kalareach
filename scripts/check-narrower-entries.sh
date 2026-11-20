#!/usr/bin/env bash
# Holds the rules of a worker's input that an entry of the narrower table lists to every release of
# their level.
#
#   scripts/check-narrower-entries.sh
#
# Run it in a checkout with the release tags fetched (`git fetch --tags`), on macOS or Linux. A
# level is one surface, and a rule that refuses more than the retained release's did is held to it
# by the entry that says so: the root and the helpers the entry lists have to be, in every release
# at the level, what the entry names. The script
#
#   1. counts the entries of the table and stops with nothing to hold when there are none, before
#      anything is built;
#   2. lists the releases at the level (`kr-protocol-gen --level-releases`) and stops when no
#      release is at the level yet;
#   3. runs the check over them (the ignored test `narrower_rules_are_in_every_release_of_their_level`
#      of `kr-cli`'s `retained_surface`) and fails unless that one test ran and passed, with the
#      number of entries and of releases it read being the ones counted here.
set -euo pipefail

cd "$(dirname "$0")/.."

case "$(uname -s)" in
  Darwin | Linux) ;;
  *)
    # The test is compiled out elsewhere, and would pass having run nothing.
    echo "REFUSED: this check runs on macOS and Linux" >&2
    exit 1
    ;;
esac

table=crates/kr-cli/tests/retained_surface/narrower_table.rs
if [ ! -f "$table" ]; then
  echo "REFUSED: $table is not here" >&2
  exit 1
fi

# `grep -c` exits 1 when it counts none.
entries=$(grep -c '^    Narrower {' "$table" || true)
if [ "$entries" -eq 0 ]; then
  echo "narrower: 0 entries, nothing to hold"
  exit 0
fi

work=$(mktemp -d)
trap 'rm -rf "${work:?}"' EXIT

cargo run -q --locked -p kr-protocol --bin kr-protocol-gen -- --level-releases > "$work/releases"
releases=$(wc -l < "$work/releases" | tr -d ' ')
if [ "$releases" -eq 0 ]; then
  echo "narrower: no release at the level, nothing to hold"
  exit 0
fi

test=narrower_rules_are_in_every_release_of_their_level
status=0
KR_LEVEL_RELEASES="$work/releases" cargo test --locked -p kr-cli --test retained_surface -- \
  --ignored --exact "$test" --show-output --format pretty --color never > "$work/output" 2>&1 || status=$?
cat "$work/output"
if [ "$status" -ne 0 ]; then
  echo "narrower: the check failed (exit $status)" >&2
  exit 1
fi
if ! grep -q '^test result: ok\. 1 passed; 0 failed;' "$work/output"; then
  echo "narrower: the check did not run and pass exactly one test" >&2
  exit 1
fi
if ! grep -q "^test $test \\.\\.\\. ok\$" "$work/output"; then
  echo "narrower: the check's own line is not on one line, or it did not pass" >&2
  exit 1
fi
if ! grep -q "^narrower: $entries entries, $releases releases read\$" "$work/output"; then
  echo "narrower: the check did not read $entries entries and $releases releases" >&2
  exit 1
fi
echo "narrower: $entries entries held in $releases releases"
