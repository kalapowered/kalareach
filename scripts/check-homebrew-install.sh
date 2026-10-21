#!/usr/bin/env bash
# Installs a release with Homebrew, upgrades it to the next release, and removes it, and holds what
# each step does to the host's store of releases.
#
#   scripts/check-homebrew-install.sh --brew BREW --kind cask|formula --first ARCHIVE --second ARCHIVE
#
# `--first` and `--second` are two releases' archives for the target this machine runs, in the
# order they are released: `kalareach-<target>-<release>.tar.gz`. The files `package-managers.py`
# renders from them go into a tap of this run's own (a cask on macOS, a formula on Linux), and
# Homebrew installs from there. `--brew` is the Homebrew to use: a runner's own, or a checkout of
# Homebrew's own repository in a directory of its own, whose prefix is that directory and which
# touches nothing of the machine's.
#
# What it holds:
#   1. after the install, `kr` on the search path is a link into Homebrew's own directory, and its
#      first command admits that release into the store of a home directory made for this run:
#      the store names the release as current and Homebrew as the one who put it there;
#   2. after the upgrade, the new release's first command admits it, and the release before it is
#      still in the store's `versions/`, though Homebrew removed the directory it was unpacked in;
#   3. after the removal, `kr` is gone from the search path and both releases are in the store.
set -euo pipefail

brew=""
kind=""
first=""
second=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --brew) brew="$2"; shift 2 ;;
    --kind) kind="$2"; shift 2 ;;
    --first) first="$2"; shift 2 ;;
    --second) second="$2"; shift 2 ;;
    *) echo "check-homebrew-install: unknown argument $1" >&2; exit 2 ;;
  esac
done
for need in brew kind first second; do
  if [ -z "${!need}" ]; then
    echo "check-homebrew-install: --${need} is needed" >&2
    exit 2
  fi
done
case "$kind" in
  cask) system=apple-darwin; stanza=--cask; tapdir=Casks ;;
  formula) system=unknown-linux-gnu; stanza=--formula; tapdir=Formula ;;
  *) echo "check-homebrew-install: --kind is cask or formula" >&2; exit 2 ;;
esac

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/kr-homebrew-check.XXXXXX")"
# An installed release is read-only, and the run's home directory holds the store of releases: its
# directories are opened to removal first.
cleanup() {
  chmod -R u+w "${work:?}" 2> /dev/null || true
  rm -rf "${work:?}"
}
trap cleanup EXIT

release_of() { basename "$1" | sed -E 's/^kalareach-[a-z0-9_-]+-([0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12})\.tar\.gz$/\1/'; }
target_of() { basename "$1" | sed -E 's/^kalareach-([a-z0-9_-]+)-[0-9]+\.[0-9]+\.[0-9]+\+[0-9a-f]{12}\.tar\.gz$/\1/'; }
first_release="$(release_of "$first")"
second_release="$(release_of "$second")"
target="$(target_of "$first")"
case "$target" in
  *-"$system") ;;
  *) echo "check-homebrew-install: a $kind installs a $system release, and $first is $target" >&2; exit 2 ;;
esac
if [ "$(target_of "$second")" != "$target" ]; then
  echo "check-homebrew-install: the two archives are for different targets" >&2
  exit 2
fi
case "$target" in
  aarch64-*) other="x86_64-${target#aarch64-}" ;;
  x86_64-*) other="aarch64-${target#x86_64-}" ;;
esac

# The archives are served from a directory of this run's. The other architecture's archive is a
# stand-in: Homebrew reads only the digest and address of the architecture it runs on, and the
# renderer writes both architectures or neither.
served="$work/served"
mkdir -p "$served"
for archive in "$first" "$second"; do
  cp "$archive" "$served/"
  release="$(release_of "$archive")"
  echo "stands in for the $other release, which this machine does not install" > "$served/kalareach-$other-$release.tar.gz"
done
prefix_url="file://$served"

# Homebrew's own state stays in this run's directory when the Homebrew is a checkout of its own.
export HOMEBREW_NO_AUTO_UPDATE=1
export HOMEBREW_NO_ANALYTICS=1
export HOMEBREW_NO_ENV_HINTS=1
export HOMEBREW_NO_INSTALL_FROM_API=1
export HOMEBREW_NO_ASK=1
export HOMEBREW_NO_INSTALL_CLEANUP=1
# An upgrade looks for what depends on the package, which would make Homebrew clone its whole core
# repository into the prefix.
export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1
if [ -n "${HOMEBREW_CHECK_STATE:-}" ]; then
  export HOMEBREW_CACHE="$HOMEBREW_CHECK_STATE/cache" HOMEBREW_LOGS="$HOMEBREW_CHECK_STATE/logs" HOMEBREW_TEMP="$HOMEBREW_CHECK_STATE/tmp"
  mkdir -p "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$HOMEBREW_TEMP"
fi

brew_prefix="$("$brew" --prefix)"
tap="check/kalareach"
# What an earlier run of this check left behind, whichever way it ended.
if "$brew" tap | grep -qx "$tap"; then
  "$brew" uninstall "$stanza" "$tap/kalareach" > /dev/null 2>&1 || true
  "$brew" untap "$tap"
fi
"$brew" tap-new --no-git "$tap" > /dev/null
tap_root="$("$brew" --repository "$tap")"
rm -f "$tap_root"/.github/workflows/*.yml
name="$tap/kalareach"

render() {
  python3 "$here/package-managers.py" render --release "$1" --url-prefix "$prefix_url" \
    --archive "$served/kalareach-$target-$1.tar.gz" --archive "$served/kalareach-$other-$1.tar.gz" \
    --out "$work/rendered-$1" > /dev/null
  mkdir -p "$tap_root/$tapdir"
  cp "$work/rendered-$1/$tapdir/kalareach.rb" "$tap_root/$tapdir/kalareach.rb"
}

# `kr`'s first command, in a home directory of this run's: every program runs with that home and a
# search path of Homebrew's bin and the system's directories.
home="$work/home"
mkdir -p "$home"
kr_run() {
  env -i HOME="$home" PATH="$brew_prefix/bin:/usr/bin:/bin" "$brew_prefix/bin/kr" "$@"
}
case "$(uname -s)" in
  Darwin) store="$home/Library/Application Support/KalaReach/host" ;;
  *) store="$home/.local/share/kalareach/host" ;;
esac

# What `host versions` says, read as the check needs it: the current release, the releases kept,
# and who put them there.
inspect() {
  kr_run --json host versions > "$work/versions.json"
  python3 - "$work/versions.json" "$store/installer" "$@" <<'PY'
import json, sys
versions = json.load(open(sys.argv[1]))
installer = open(sys.argv[2]).read().strip()
current, kept = sys.argv[3], sys.argv[4:]
names = [entry["release"] for entry in versions["releases"]]
now = [entry["release"] for entry in versions["releases"] if entry["current"]]
assert now == [current], f"the current release is {now}, and it should be {current}"
assert sorted(names) == sorted(kept), f"the store holds {names}, and it should hold {kept}"
assert installer == "homebrew", f"the store names {installer} as the installer"
PY
}

echo "== install $first_release"
render "$first_release"
"$brew" install "$stanza" "$name"
kr_path="$brew_prefix/bin/kr"
case "$(readlink "$kr_path" 2>/dev/null || true)" in
  *Cellar/*|*Caskroom/*) ;;
  *) echo "check-homebrew-install: $kr_path is not a link into Homebrew's own directory" >&2; exit 1 ;;
esac
inspect "$first_release" "$first_release"
echo "ok   the first command of kr admits $first_release and Homebrew is the installer"

echo "== upgrade to $second_release"
render "$second_release"
"$brew" upgrade "$stanza" "$name"
unpacked_before="$(find "$brew_prefix/Cellar" "$brew_prefix/Caskroom" -maxdepth 3 -name "*$first_release*" 2>/dev/null || true)"
if [ -n "$unpacked_before" ]; then
  echo "check-homebrew-install: Homebrew kept the release it upgraded from: $unpacked_before" >&2
  exit 1
fi
inspect "$second_release" "$first_release" "$second_release"
echo "ok   the upgrade is admitted at its first command, and $first_release stays in the store"

echo "== remove"
"$brew" uninstall "$stanza" "$name"
if [ -e "$kr_path" ] || [ -L "$kr_path" ]; then
  echo "check-homebrew-install: kr is still on the search path after the removal" >&2
  exit 1
fi
for release in "$first_release" "$second_release"; do
  if [ ! -f "$store/versions/$release/bin/kr" ]; then
    echo "check-homebrew-install: the removal took $release out of the store" >&2
    exit 1
  fi
done
echo "ok   the removal leaves both releases in the store"
"$brew" untap "$tap" > /dev/null
