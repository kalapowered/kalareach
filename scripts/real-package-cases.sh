#!/usr/bin/env bash
# Runs the cases that need the managed shell packages a run has built. An ordinary run leaves them
# out, because they are ignored unless the packages exist; this script is where a run that built
# them runs every one.
#
#   KR_SHELL_PACKAGES=<prefix> bash scripts/real-package-cases.sh
#
# <prefix> is the installation the packages were built into (the prefix `build-shells.sh`
# installed to). The script runs from anywhere inside the repository and exits non-zero when any
# command below fails; each command runs even when an earlier one failed, so one run shows every
# case that does not hold.
set -u

: "${KR_SHELL_PACKAGES:?KR_SHELL_PACKAGES names the installation the packages were built into}"
packages="$KR_SHELL_PACKAGES"
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 2

# The shells the `shells` suite starts are found on its PATH: the built packages' own.
shell_path="$packages/zsh/$(cat "$packages/zsh/current")/bin:$packages/fish/$(cat "$packages/fish/current")/bin"

failed=0
step() {
  echo "== $*"
  "$@" || failed=1
}

step cargo test -p kr-controller --test shell -- --ignored
step cargo test -p kr-worker --test fence -- --ignored
step env -u KR_SHELL_PACKAGES PATH="$shell_path:$PATH" cargo test -p kr-worker --test shells -- --ignored

exit "$failed"
