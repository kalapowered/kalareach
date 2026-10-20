#!/usr/bin/env bash
# Keeps the newest retained level the level of the release before the one being cut.
#
#   scripts/check-retained-release.sh
#
# Run it in a clean checkout of the commit a release is cut from, on macOS or Linux, with the
# release tags fetched (`git fetch --tags`): the tags are what say which release came before. It
#
#   1. takes the release before this one, the newest tag `packages/v<version>+<commit>` in the
#      commit's history at the highest compatibility level below its own that
#      `crates/kr-protocol/retained/EXCLUDED` does not name, and fails unless that level is the
#      newest this build retains (`kr-protocol-gen --predecessor`);
#   2. holds the schema, the table of public majors and the plugin host protocol of every release
#      tagged at that level that the record does not name, whether or not the commit's history
#      reaches it, to the ones the level kept, and moves the level's record
#      (`retained/<level>/RELEASE` and its row in docs/releases/support-window.md) to the newest
#      when it names an earlier one of the level (`kr-protocol-gen --release-commit`);
#   3. checks the rules and limits the level kept against the source tree of the newest release,
#      which the `retained_surface` test reads when `KR_RELEASE_TREE` names a checkout, and the
#      rules on the table of public majors against the record as it now stands;
#   4. runs `kr-protocol-gen --check`.
#
# When the record moved, the two files it changed are left in the working tree and the script
# fails: the tree to release is the commit that holds them, so commit them and run the script
# again on that commit, which must pass without changing anything.
set -euo pipefail

cd "$(dirname "$0")/.."

case "$(uname -s)" in
  Darwin | Linux) ;;
  *)
    # The test that reads the release's source is compiled out elsewhere, and would pass having
    # run nothing.
    echo "REFUSED: this check runs on macOS and Linux" >&2
    exit 1
    ;;
esac

if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
  echo "REFUSED: the checkout has changes; run this in a clean checkout of the commit to be released" >&2
  exit 1
fi

generator() {
  cargo run -q --locked -p kr-protocol --bin kr-protocol-gen -- "$@"
}

before=$(generator --predecessor)
read -r level commit tag <<<"$before"
echo "the release before this one is $tag, level $level at $commit"

generator --release-commit "$level" "$commit"

tree=$(mktemp -d)
trap 'rm -rf "${tree:?}"' EXIT
git archive "$commit" | tar -x -C "$tree"
KR_RELEASE_TREE="$tree" cargo test --locked -p kr-cli --test retained_surface
cargo test --locked -p kr-protocol --test public_majors

generator --check

changed=$(git status --porcelain --untracked-files=all)
if [ -n "$changed" ]; then
  echo "the record of level $level moved to $tag; these files changed:"
  git status --short
  echo "commit them, run the upgrade suite (cargo test -p kr-cli --features upgrade-suite --test upgrade -- --nocapture), which builds the release the record now names, and run this script again on that commit"
  exit 1
fi
echo "the retained level $level holds against $tag"
