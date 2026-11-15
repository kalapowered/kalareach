#!/bin/bash
# fetch-trap.sh
# Runs as the build account in the fetch unit after fetch-core.sh. A project in the checkout has
# a repository setting (a target directory) that a build reads. Prints where `cargo metadata`
# puts the target directory when run inside the project (the setting is live) and when run in
# the fetch step's form (a folder outside the repository and a manifest path): only the first
# may show the project's setting.
set -u
export HOME=/home/kr-legs CARGO_HOME=/opt/kr-legs/cargo RUSTUP_HOME=/home/kr-legs/rustup CARGO_TERM_COLOR=never
export RUSTUP_TOOLCHAIN
RUSTUP_TOOLCHAIN=$(cat /home/kr-legs/toolchain.txt)
cargo=/opt/kr-legs/cargo/bin/cargo
trap=/home/kr-legs/core/scripts/ci/sandbox-probe/tools/fetch-trap
target_of() { /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'; }

cd "$trap"
inside=$("$cargo" metadata --offline --no-deps --format-version 1 | target_of)
cd /home/kr-legs/work
outside=$("$cargo" metadata --offline --no-deps --format-version 1 --manifest-path "$trap/Cargo.toml" | target_of)
echo "TRAP inside=$inside"
echo "TRAP fetch-form=$outside"
