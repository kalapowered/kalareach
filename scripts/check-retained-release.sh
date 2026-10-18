#!/usr/bin/env bash
# Keeps the newest retained level the release immediately before the one being cut.
#
#   scripts/check-retained-release.sh
#
# Run it in a clean checkout of the commit a release is cut from, with the release tags fetched
# (`git fetch --tags`): the tags are what say which release came before. It
#
#   1. takes the release before this one, the newest tag `packages/v<version>+<commit>` in the
#      commit's history at a compatibility level below its own, and fails unless that level is the
#      newest this build retains (`kr-protocol-gen --predecessor`);
#   2. holds that release's schema, table of public majors and plugin host protocol to the ones the
#      level kept, and moves the level's record (`retained/<level>/RELEASE` and its row in
#      docs/releases/support-window.md) to the release when it names an earlier one of the level
#      (`kr-protocol-gen --release-commit`);
#   3. checks the rules the level kept against the source tree of that release, which the
#      `retained_surface` test reads when `KR_RELEASE_TREE` names a checkout;
#   4. runs `kr-protocol-gen --check`.
#
# When the record moved, the two files it changed are left in the working tree to be committed.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "REFUSED: the checkout has changes; run this in a clean checkout of the commit to be released" >&2
  exit 1
fi

generator() {
  cargo run -q --locked -p kr-protocol --bin kr-protocol-gen -- "$@"
}

before=$(generator --predecessor)
read -r level commit <<<"$before"
echo "the release before this one is level $level at $commit"

generator --release-commit "$level" "$commit"

tree=$(mktemp -d)
trap 'rm -rf "${tree:?}"' EXIT
git archive "$commit" | tar -x -C "$tree"
KR_RELEASE_TREE="$tree" cargo test --locked -p kr-cli --test retained_surface

generator --check

if [ -n "$(git status --porcelain)" ]; then
  echo "the record of level $level moved to the release before this one; commit these files:"
  git status --short
fi
