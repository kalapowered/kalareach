#!/bin/bash
# fetch-core.sh URL SHA MODE
# Runs as the build account inside the fetch unit (the one unit with a network): checks out the
# commit with Git's own trusted entry point and no repository-chosen hook, installs the Rust
# toolchain with a pinned rustup-init, and fetches the crates the lock file names. MODE is core
# (the whole workspace) or client (the probe's own client crate). Nothing here runs a crate's code.
set -eu
url=${1:?}
sha=${2:?}
mode=${3:?}
case $mode in core | client) ;; *) echo "fetch-core: bad mode" >&2; exit 2 ;; esac

export HOME=/home/kr-legs CARGO_HOME=/opt/kr-legs/cargo RUSTUP_HOME=/home/kr-legs/rustup
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 CARGO_TERM_COLOR=never
GIT=/usr/bin/git
pin=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c

cd /home/kr-legs
"$GIT" init --quiet core
cd core
"$GIT" -c protocol.allow=never -c protocol.https.allow=always -c core.hooksPath=/dev/null \
  fetch --quiet --depth 1 --no-tags --no-recurse-submodules -- "$url" "$sha"
[ "$("$GIT" rev-parse FETCH_HEAD)" = "$sha" ] || { echo "fetch-core: FETCH_HEAD is not the commit asked for" >&2; exit 1; }
"$GIT" -c core.hooksPath=/dev/null checkout --quiet --detach FETCH_HEAD
echo "FETCH checked out $(printf '%s' "$sha" | cut -c1-12)"

# rustup-init at a pinned version; its hash is compared before it runs.
mkdir -p /home/kr-legs/tmp
init=/home/kr-legs/tmp/rustup-init
/usr/bin/curl --proto '=https' --tlsv1.2 -fsSL -o "$init" \
  https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init
echo "$pin  $init" | /usr/bin/sha256sum -c --quiet -
chmod 0700 "$init"
"$init" -y --no-modify-path --profile minimal --default-toolchain none --quiet
rm -f -- "$init"

# The toolchain named by the repository's pin file; read as a version number and nothing else.
chan=$(sed -n 's/^channel *= *"\([0-9][0-9.]*\)".*/\1/p' /home/kr-legs/core/rust-toolchain.toml | head -1)
case $chan in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "fetch-core: no plain version in the pin file" >&2; exit 1 ;; esac
cd /home/kr-legs/work
"$CARGO_HOME/bin/rustup" toolchain install "$chan" --profile minimal --no-self-update
printf '%s\n' "$chan" >/home/kr-legs/toolchain.txt
echo "FETCH toolchain $chan"

# The fetch runs from a folder outside the repository, so that no repository setting is read
# (a build reads them; this step must not), and with the toolchain named on the command line.
if [ "$mode" = core ]; then
  manifest=/home/kr-legs/core/Cargo.toml
else
  manifest=/home/kr-legs/core/scripts/ci/sandbox-probe/tools/client/Cargo.toml
fi
RUSTUP_TOOLCHAIN=$chan "$CARGO_HOME/bin/cargo" fetch --locked --target x86_64-unknown-linux-gnu --manifest-path "$manifest"
echo "FETCH crates fetched for $mode"
