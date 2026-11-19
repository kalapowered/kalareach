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
# alone and in a target directory of its own, as a release tree builds them, and builds the two test
# programs that carry the refusal (`kr-controller-held` and `kr` with `--features testing`). The
# case `a_shipped_program_holds_none_of_the_launchd_refusal` of `kr-ipc` then reads the files: the
# test programs have to hold the bytes of the refusal sentence and of the variable's name, which
# proves that a search which finds nothing is not a search that cannot find, and no shipped program
# may hold either.
#
# Usage: scripts/shipped-hold-gate.sh
#
# The builds go in a new directory under TMPDIR, removed when the run ends. KR_SHIPPED_TARGET_DIR
# names a directory to build in instead, and keeps it, for a run that is repeated.
# KR_SHIPPED_PROFILE=debug builds the debug profile in place of the release one, which holds the
# same features and takes far less time. KR_SHIPPED_WORKSPACE_TARGET names the target directory of
# a whole-workspace release build (`cargo build --locked --release --workspace`) whose programs
# are read as well, since that build puts the features of every crate's tests into one graph.
#
# It exits 0 when no shipped program holds the refusal, and with the failing step's status
# otherwise.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

profile=release
profile_flags=(--release)
if [ "${KR_SHIPPED_PROFILE:-release}" = debug ]; then
  profile=debug
  profile_flags=()
fi
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
CARGO_TARGET_DIR="$target/held" cargo build --locked "${profile_flags[@]}" \
  -p kr-controller --features testing --bin kr-controller-held
CARGO_TARGET_DIR="$target/held" cargo build --locked "${profile_flags[@]}" \
  -p kr-cli --features testing --bin kr
held="$target/held/$profile/kr-controller-held
$target/held/$profile/kr"

# Each program a release ships, alone, as a release tree builds it.
shipped=""
while IFS=/ read -r package name; do
  [ -n "$name" ] || continue
  CARGO_TARGET_DIR="$target/shipped" cargo build --locked --target "$triple" "${profile_flags[@]}" \
    -p "$package" --bin "$name"
  shipped="$shipped$target/shipped/$triple/$profile/$name
"
  if [ -n "${KR_SHIPPED_WORKSPACE_TARGET:-}" ]; then
    shipped="$shipped$KR_SHIPPED_WORKSPACE_TARGET/release/$name
"
  fi
done < <(python3 -I scripts/release-programs.py builds --target "$triple")

KR_SHIPPED_HELD="$held" KR_SHIPPED_PROGRAMS="$shipped" \
  cargo test --locked -p kr-ipc --test account_launchd -- --ignored --exact a_shipped_program_holds_none_of_the_launchd_refusal --nocapture
