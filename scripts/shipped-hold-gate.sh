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
# programs have to hold the bytes of the refusal sentence and of the variable's name and, on macOS,
# the three strings of the stand-in service manager's seam (the variable `KR_MANAGER_STAND_IN`, the
# sentence of its refusal and the marker's file name `kr-manager-stand-in.installation`), which
# proves that a search which finds nothing is not a search that cannot find, and no program of
# either release build may hold any of them. The profile is the release one throughout: it is what
# a person installs.
#
# The three release builds do not stand on the disk together. The case is compiled first, so the
# last step compiles nothing. Each build's programs are copied into a folder of their own, and the
# copy is checked against the original by its SHA-256 digest, before that build's target directory
# is removed and the next build starts. The case reads the copies, which hold the bytes it would
# have read in the builds. The run prints the free space of the disk at each phase.
#
# Usage: scripts/shipped-hold-gate.sh
#
# The builds go in a new directory under TMPDIR, removed when the run ends. KR_SHIPPED_TARGET_DIR
# names a directory to build in instead, and keeps the copies of the programs there, for a run to
# read again; the target directories of the builds are removed as each one ends, in both cases.
# KR_SHIPPED_WORKSPACE_TARGET names the target directory of a whole-workspace release build that is
# already made, which is then read in place of a build of this script's own and is not removed; it
# has to hold every program the list names, and a missing one fails the run. The run reads the
# programs of the host's own target only, so a platform's gate is the run on that platform.
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

# One line with the disk that holds the builds: its size, what is used and what is free.
disk() {
  printf 'shipped-hold-gate: disk %s: %s\n' "$1" "$(df -h "$target" | tail -n 1)"
}

# The SHA-256 digest of the file at $1.
digest() {
  if command -v sha256sum > /dev/null; then
    sha256sum "$1" | cut -d ' ' -f 1
  else
    shasum -a 256 "$1" | cut -d ' ' -f 1
  fi
}

# Copies the program at $1 to $2, and fails unless the copy holds the same bytes.
keep_program() {
  local from="$1" to="$2" before after
  if [ ! -f "$from" ]; then
    echo "shipped-hold-gate: $from is not built" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$to")"
  cp "$from" "$to"
  before="$(digest "$from")"
  after="$(digest "$to")"
  if [ "$before" != "$after" ]; then
    echo "shipped-hold-gate: the copy $to of $from holds other bytes ($after, not $before)" >&2
    exit 1
  fi
  echo "shipped-hold-gate: kept $to sha256 $after"
}

# Removes the target directory of a build that this script made as $target/$1: what the case reads
# is copied out of it by then.
drop_build() {
  local size
  size="$(du -sh "$target/$1" 2> /dev/null | cut -f 1 | tr -d ' ' || true)"
  rm -rf "${target:?}/${1:?}"
  echo "shipped-hold-gate: removed the $1 build, which held $size"
}

disk "at the start"

# The case, compiled before any release build, in the target directory the caller names (the job's
# own, when none): the run at the end then compiles nothing, whatever the release builds left.
cargo test --locked -p kr-ipc --test account_launchd --no-run
disk "after the case is compiled"

# The programs a release ships, as the names `package/name` of the list.
list="$(python3 -I scripts/release-programs.py builds --target "$triple")"
names=""
while IFS=/ read -r _ name; do
  [ -n "$name" ] || continue
  names="$names$name
"
done <<< "$list"
if [ -z "$names" ]; then
  echo "shipped-hold-gate: scripts/release-programs.py names no program to read" >&2
  exit 1
fi

programs="$target/programs"

# The test programs that carry the refusal: a different target directory from the shipped programs',
# so that the features of one build are not the other's.
CARGO_TARGET_DIR="$target/held" cargo build --locked --release \
  -p kr-controller --features testing --bin kr-controller-held
CARGO_TARGET_DIR="$target/held" cargo build --locked --release \
  -p kr-cli --features testing --bin kr
disk "after the held programs are built"
keep_program "$target/held/$profile/kr-controller-held" "$programs/held/kr-controller-held"
keep_program "$target/held/$profile/kr" "$programs/held/kr"
drop_build held
disk "after the held build is removed"
held="$programs/held/kr-controller-held
$programs/held/kr"

# The whole workspace in the release profile, unless a finished build of it is named.
if [ -n "${KR_SHIPPED_WORKSPACE_TARGET:-}" ]; then
  workspace="$KR_SHIPPED_WORKSPACE_TARGET"
  built=""
else
  workspace="$target/workspace"
  built=workspace
  CARGO_TARGET_DIR="$workspace" cargo build --locked --release --workspace
  disk "after the workspace is built"
fi
while IFS= read -r name; do
  [ -n "$name" ] || continue
  keep_program "$workspace/$profile/$name" "$programs/workspace/$name"
done <<< "$names"
if [ -n "$built" ]; then
  drop_build workspace
  disk "after the workspace build is removed"
fi

# Each program a release ships, alone, as a release tree builds it, one after another in one target
# directory. A list that names none is a gate that reads nothing.
shipped=""
while IFS=/ read -r package name; do
  [ -n "$name" ] || continue
  CARGO_TARGET_DIR="$target/shipped" cargo build --locked --target "$triple" --release \
    -p "$package" --bin "$name"
  keep_program "$target/shipped/$triple/$profile/$name" "$programs/shipped/$name"
  shipped="$shipped$programs/shipped/$name
$programs/workspace/$name
"
  disk "after $name is built"
done <<< "$list"
drop_build shipped
disk "after the shipped builds are removed"

KR_SHIPPED_HELD="$held" KR_SHIPPED_PROGRAMS="$shipped" \
  cargo test --locked -p kr-ipc --test account_launchd -- --ignored --exact a_shipped_program_holds_none_of_the_launchd_refusal --nocapture
