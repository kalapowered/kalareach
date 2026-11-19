#!/usr/bin/env bash
# The programs a release ships, shown to hold none of the refusal that test builds carry.
#
# A test build of the control daemon and of the command line refuses a `launchctl` command that
# changes the manager unless the run asked for the account's own launchd, and writes that ask into
# the service definition it makes. The code that does so compiles in only with the crate's own
# `testing` feature, which no release build enables: each release program is built alone, as
# `cargo build -p <package> --bin <name>` does, and a dependency's feature does not turn on another
# crate's. A later change that lets the feature into one of them (a default feature, or a normal
# dependency on the crate that has it) puts the refusal into a program a person runs, and this is
# the check that says so.
#
# It builds the programs that `scripts/release-programs.py builds` names for the host's target, each
# alone and in a target directory of its own, as a release tree builds them, and the whole workspace
# in the release profile (`cargo build --locked --release --workspace`), since that build puts the
# features of every crate's tests into one graph. It also builds the two test programs that carry
# the refusal (`kr-controller-held` and `kr` with `--features testing`). The case
# `a_shipped_program_holds_none_of_the_launchd_refusal` of `kr-ipc` then reads the files: the test
# programs have to hold the bytes of the refusal sentence and of the variable's name, which proves
# that a search which finds nothing is not a search that cannot find, and no program of either
# release build may hold either. The profile is the release one throughout: it is what a person
# installs.
#
# Usage: scripts/shipped-hold-gate.sh
#
# The builds go in a new directory under TMPDIR, removed when the run ends. KR_SHIPPED_TARGET_DIR
# names a directory to build in instead, and keeps it, for a run that is repeated.
# KR_SHIPPED_WORKSPACE_TARGET names the target directory of a whole-workspace release build that is
# already made, which is then read in place of a build of this script's own; it has to hold every
# program the list names, and a missing one fails the run. The run reads the programs of the host's
# own target only, so a platform's gate is the run on that platform.
#
# It exits 0 when no shipped program holds the refusal, and with the failing step's status
# otherwise.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

profile=release
triple="${KR_SHIPPED_TRIPLE:-$(rustc -vV | sed -n 's/^host: //p')}"

if [ -n "${KR_SHIPPED_TARGET_DIR:-}" ]; then
  target="$KR_SHIPPED_TARGET_DIR"
  mkdir -p "$target"
else
  target="$(mktemp -d "${TMPDIR:-/tmp}/kr-shipped-hold.XXXXXX")"
  trap 'rm -rf "${target:?}"' EXIT
fi

# The test programs that carry the refusal: a different target directory from the shipped programs',
# so that the features of one build are not the other's.
CARGO_TARGET_DIR="$target/held" cargo build --locked --release \
  -p kr-controller --features testing --bin kr-controller-held
CARGO_TARGET_DIR="$target/held" cargo build --locked --release \
  -p kr-cli --features testing --bin kr
held="$target/held/$profile/kr-controller-held
$target/held/$profile/kr"

# The whole workspace in the release profile, unless a finished build of it is named.
if [ -n "${KR_SHIPPED_WORKSPACE_TARGET:-}" ]; then
  workspace="$KR_SHIPPED_WORKSPACE_TARGET"
else
  workspace="$target/workspace"
  CARGO_TARGET_DIR="$workspace" cargo build --locked --release --workspace
fi

# Each program a release ships, alone, as a release tree builds it, and the same program in the
# workspace build. A list that names none is a gate that reads nothing.
shipped=""
while IFS=/ read -r package name; do
  [ -n "$name" ] || continue
  CARGO_TARGET_DIR="$target/shipped" cargo build --locked --target "$triple" --release \
    -p "$package" --bin "$name"
  shipped="$shipped$target/shipped/$triple/$profile/$name
$workspace/$profile/$name
"
done < <(python3 -I scripts/release-programs.py builds --target "$triple")
if [ -z "$shipped" ]; then
  echo "shipped-hold-gate: scripts/release-programs.py names no program to read" >&2
  exit 1
fi

KR_SHIPPED_HELD="$held" KR_SHIPPED_PROGRAMS="$shipped" \
  cargo test --locked -p kr-ipc --test account_launchd -- --ignored --exact a_shipped_program_holds_none_of_the_launchd_refusal --nocapture
