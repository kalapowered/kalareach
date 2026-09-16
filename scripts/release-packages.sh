#!/usr/bin/env bash
# Packs the generated TypeScript packages from this commit and records what they hash to.
#
# `@kalareach/protocol` and `@kalareach/plugin-sdk` come from the Rust types in this repository, and
# the website and the plugin catalogue consume them as immutable releases pinned by URL and
# integrity. A release is therefore exactly one commit's output, and this script is what makes that
# true: it refuses a working tree that is not clean, holds every generated artefact the two packages
# ship to the canonical Rust source before it packs anything, names each archive after the commit it
# came from, and writes the digests a consumer pins and verifies against.
#
# The archives are byte-for-byte reproducible from the same commit with the pinned Node and pnpm, so
# the script packs each one twice and compares the two. The archive format belongs to pnpm, not to
# this script, which is why the toolchain is pinned in package.json and in the release workflow.
#
#   bash scripts/release-packages.sh                                  # writes dist/packages
#   bash scripts/release-packages.sh --output /tmp/kalareach-packages
#   bash scripts/release-packages.sh --tag packages/v0.1.0+0123456789ab
#
# `--tag` is what the release workflow passes. The tag has to name this commit and this version, so
# a tag pushed at the wrong revision fails here rather than publishing a mislabelled archive.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The packages a release carries. One tag names one version, so both of these hold the same one.
packages=(packages/protocol packages/plugin-sdk)

output="$root/dist/packages"
tag=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      [ "$#" -ge 2 ] || { echo "--output needs a directory" >&2; exit 2; }
      output="$2"
      shift 2
      ;;
    --tag)
      [ "$#" -ge 2 ] || { echo "--tag needs a tag" >&2; exit 2; }
      tag="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      echo "usage: release-packages.sh [--output <directory>] [--tag <tag>]" >&2
      exit 2
      ;;
  esac
done

# A release names the commit it was packed from, so it has to be that commit and nothing else. The
# generated files the archives carry are not committed, which is why this asks about tracked files
# and untracked ones but not about ignored ones.
dirty="$(git status --porcelain --untracked-files=all)"
if [ -n "$dirty" ]; then
  echo "This tree is not clean, so a release packed from it would not be this commit:" >&2
  echo "$dirty" >&2
  exit 1
fi

commit="$(git rev-parse HEAD)"
short="${commit:0:12}"

# Prints "<package name> <version> <archive base name>" for one package directory. pnpm names an
# archive after the package, so the name is read from the manifest rather than spelled out here.
manifest() {
  # shellcheck disable=SC2016  # the ${} below are JavaScript template placeholders.
  node -e '
    const { readFileSync } = require("node:fs")
    const directory = process.argv[1]
    const found = JSON.parse(readFileSync(`${directory}/package.json`, "utf8"))
    if (typeof found.name !== "string" || typeof found.version !== "string") {
      process.stderr.write(`${directory}/package.json names no package and version\n`)
      process.exit(1)
    }
    process.stdout.write(
      `${found.name} ${found.version} ${found.name.replace(/^@/, "").replace(/\//g, "-")}\n`
    )
  ' "$1"
}

# Prints "<hex> <base64>" for one file: the same sha512 in the two forms a release publishes.
digest() {
  # shellcheck disable=SC2016  # the ${} below are JavaScript template placeholders.
  node -e '
    const { createHash } = require("node:crypto")
    const { readFileSync } = require("node:fs")
    const sum = createHash("sha512").update(readFileSync(process.argv[1])).digest()
    process.stdout.write(`${sum.toString("hex")} ${sum.toString("base64")}\n`)
  ' "$1"
}

version=""
for package in "${packages[@]}"; do
  read -r _ found _ <<<"$(manifest "$package")"
  if [ -z "$version" ]; then
    version="$found"
  elif [ "$found" != "$version" ]; then
    echo "packages/protocol is $version and $package is $found." >&2
    echo "One tag names one version, so the two packages are released together at the same one." >&2
    exit 1
  fi
done

expected_tag="packages/v${version}+${short}"

if [ -n "$tag" ] && [ "$tag" != "$expected_tag" ]; then
  echo "Tag $tag does not name this release." >&2
  echo "Commit $commit at version $version is $expected_tag." >&2
  exit 1
fi

# Existing files are never removed and never uploaded by accident: an output directory holding two
# commits' archives is the mistake this refuses.
if [ -e "$output" ] && [ -n "$(ls -A "$output")" ]; then
  echo "$output already holds files:" >&2
  ls -A "$output" >&2
  echo "Empty it or choose another directory." >&2
  exit 1
fi

mkdir -p "$output"
output="$(cd "$output" && pwd)"

staging="$(mktemp -d "${TMPDIR:-/tmp}/kalareach-release.XXXXXX")"
trap 'rm -rf "$staging"' EXIT

echo "kalareach package release"
echo "  commit: $commit"
echo "  version: $version"
echo "  tag: $expected_tag"
echo "  output: $output"
echo

echo "installing the pinned dependencies"
pnpm install --frozen-lockfile
echo

# What the archives carry is generated from the Rust types, so each generator is asked whether the
# committed output is still its output. These are the generators behind the schema, the TypeScript
# types, the WIT package and the conformance vectors the two packages publish; the suites that
# exercise them belong to the ordinary build, which this release's commit has already passed.
echo "holding the generated artefacts to their sources"
cargo run --locked -p kr-protocol --bin kr-protocol-gen -- --check
cargo run --locked -p kr-crypto --bin kr-crypto-vectors -- --check
cargo run --locked -p kr-pairing --bin kr-pairing-vectors -- --check
cargo run --locked -p kr-plugin-sdk --bin kr-plugin-sdk-gen -- --check
pnpm -r generate:check
echo

assets=()
integrities=()
sums=()

for package in "${packages[@]}"; do
  read -r name found base <<<"$(manifest "$package")"
  packed="${base}-${found}.tgz"
  asset="${base}-${found}+${short}.tgz"

  echo "packing $name $found"
  mkdir -p "$staging/first" "$staging/second"
  pnpm -C "$package" pack --pack-destination "$staging/first" >/dev/null
  pnpm -C "$package" pack --pack-destination "$staging/second" >/dev/null

  for attempt in first second; do
    if [ ! -f "$staging/$attempt/$packed" ]; then
      echo "pnpm packed something other than $packed:" >&2
      ls -A "$staging/$attempt" >&2
      exit 1
    fi
  done

  read -r hex encoded <<<"$(digest "$staging/first/$packed")"
  read -r again _ <<<"$(digest "$staging/second/$packed")"

  # Two archives packed from one commit are the same archive. When they are not, the release is not
  # reproducible and the digests published here would be a claim about one run only.
  if [ "$hex" != "$again" ]; then
    echo "Packing $name twice produced two different archives ($hex and $again)." >&2
    echo "A release has to be reproducible from its commit, so this is not publishable." >&2
    exit 1
  fi

  mv "$staging/first/$packed" "$output/$asset"
  rm -rf "$staging/first" "$staging/second"

  assets+=("$asset")
  integrities+=("sha512-${encoded}")
  sums+=("$hex  $asset")
done

{
  echo "# The KalaReach generated packages at version $version, packed from commit $commit."
  echo "# Release tag $expected_tag."
  echo "#"
  echo "# Each sha512- line below is the integrity a lockfile records for that archive. The lines"
  echo "# that follow are the same digests in the format \`sha512sum -c\` reads."
  for index in "${!assets[@]}"; do
    echo "# ${assets[index]} ${integrities[index]}"
  done
  printf '%s\n' "${sums[@]}"
} >"$output/SHA512SUMS"

echo
echo "assets in $output:"
for index in "${!assets[@]}"; do
  printf '  %s  %s bytes  %s\n' \
    "${assets[index]}" "$(wc -c <"$output/${assets[index]}" | tr -d ' ')" "${integrities[index]}"
done
printf '  %s  %s bytes\n' SHA512SUMS "$(wc -c <"$output/SHA512SUMS" | tr -d ' ')"
echo
echo "tag: $expected_tag"
