#!/usr/bin/env bash
# Packs the generated TypeScript packages from this commit and records what they hash to.
#
# `@kalareach/protocol` and `@kalareach/plugin-sdk` come from the Rust types in this repository, and
# the website and the plugin catalogue consume them as immutable releases pinned by URL and
# integrity. A release is therefore exactly one commit's output, and this script is what makes that
# true: it refuses a working tree that is not clean, holds every generated artefact the two packages
# ship to the canonical Rust source before it packs anything, asks each archive what it contains,
# names it after the commit it came from, and writes the digests a consumer pins and verifies
# against.
#
# The archive format belongs to pnpm: members in a fixed order under a fixed timestamp, compressed
# at pnpm's own level. The bytes are therefore a function of the commit, the Node and pnpm versions
# and the pack settings, so the script refuses a setting that would change them and packs each
# archive twice to check that nothing else in the environment reached the bytes.
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

# Two pnpm settings decide what a release is, and neither belongs to one machine.
#
# `pack-gzip-level` changes the compressed bytes, so a release packed under a configured level could
# not be reproduced by anyone without that same configuration. `ignore-scripts` makes packing skip
# the step that generates the declarations, the conformance vectors and the provenance file the
# protocol package publishes: the result is a smaller archive that still packs, still equals a
# second pack of itself, and is missing most of what a consumer installs.
level="$(pnpm config get pack-gzip-level)"
if [ "$level" != "undefined" ]; then
  echo "This environment sets pack-gzip-level to $level." >&2
  echo "A release is packed at pnpm's own level, because the archive bytes depend on it." >&2
  exit 1
fi

scripted="$(pnpm config get ignore-scripts)"
if [ "$scripted" != "undefined" ] && [ "$scripted" != "false" ]; then
  echo "This environment sets ignore-scripts to $scripted." >&2
  echo "Packing would then skip the step that generates most of what the protocol package ships." >&2
  exit 1
fi

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

# Prints the paths one package publishes, one per line, from its manifest's `files` list.
published() {
  # shellcheck disable=SC2016  # the ${} below are JavaScript template placeholders.
  node -e '
    const { readFileSync } = require("node:fs")
    const directory = process.argv[1]
    const found = JSON.parse(readFileSync(`${directory}/package.json`, "utf8"))
    if (!Array.isArray(found.files) || found.files.length === 0) {
      process.stderr.write(`${directory}/package.json publishes no files list\n`)
      process.exit(1)
    }
    process.stdout.write(`${found.files.join("\n")}\n`)
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

# Reads one package's name, version and archive base name into `name`, `version` and `base`, and
# refuses anything a tag and an archive name could not carry.
read_manifest() {
  local directory="$1" line found_name found_version found_base
  line="$(manifest "$directory")"
  read -r found_name found_version found_base <<<"$line"

  if [ -z "$found_name" ] || [ -z "$found_base" ]; then
    echo "$directory/package.json names no package: $line" >&2
    exit 1
  fi

  # A tag and an archive name join the version and the commit with a plus, so a version that
  # already carries build metadata of its own could not be read back out of either.
  if ! [[ "$found_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
    echo "$directory/package.json is version $found_version, which a release name cannot carry." >&2
    exit 1
  fi

  name="$found_name"
  version="$found_version"
  base="$found_base"
}

# Reads one file's sha512 into `hex` and `sri`, refusing anything that is not a whole digest. A
# digest that failed to run would otherwise leave an empty string, and an empty string equals the
# next empty string.
read_digest() {
  local line found_hex found_encoded
  line="$(digest "$1")"
  read -r found_hex found_encoded <<<"$line"

  if ! [[ "$found_hex" =~ ^[0-9a-f]{128}$ ]] ||
    ! [[ "$found_encoded" =~ ^[A-Za-z0-9+/]{86}==$ ]]; then
    echo "The digest of $1 came back as $line, which is not a sha512." >&2
    exit 1
  fi

  hex="$found_hex"
  sri="sha512-$found_encoded"
}

# Asks one archive what it contains: every path the manifest publishes has to be in it, the manifest
# inside has to name that package and version, and a provenance file, where the package has one, has
# to name this commit. This is what catches an archive packed without the step that generates most
# of its contents, which is otherwise a well-formed archive of the wrong thing.
verify_archive() {
  local archive="$1" directory="$2" expected_name="$3" expected_version="$4"
  local unpacked entries entry prefix

  unpacked="$staging/unpacked"
  rm -rf "$unpacked"
  mkdir -p "$unpacked"
  tar -xzf "$archive" -C "$unpacked"

  entries="$(published "$directory")"

  while IFS= read -r entry; do
    prefix="${entry%%\**}"
    if [ ! -e "$unpacked/package/$prefix" ]; then
      echo "$(basename "$archive") carries no $entry, which $directory publishes. It carries:" >&2
      (cd "$unpacked/package" && ls -A) >&2
      exit 1
    fi
  done <<<"$entries"

  # shellcheck disable=SC2016  # the ${} below are JavaScript template placeholders.
  node -e '
    const { existsSync, readFileSync } = require("node:fs")
    const [directory, expectedName, expectedVersion, commit] = process.argv.slice(1)
    const read = (file) => JSON.parse(readFileSync(`${directory}/${file}`, "utf8"))
    const problems = []

    const found = read("package.json")
    if (found.name !== expectedName) {
      problems.push(`it contains ${found.name}, not ${expectedName}`)
    }
    if (found.version !== expectedVersion) {
      problems.push(`it contains version ${found.version}, not ${expectedVersion}`)
    }

    if (existsSync(`${directory}/provenance.json`)) {
      const provenance = read("provenance.json")
      if (provenance.core_commit !== commit) {
        problems.push(`it was packed from ${provenance.core_commit}, not from ${commit}`)
      }
      if (provenance.package !== expectedName || provenance.version !== expectedVersion) {
        problems.push(
          `its provenance names ${provenance.package} ${provenance.version}, ` +
            `not ${expectedName} ${expectedVersion}`
        )
      }
    }

    if (problems.length > 0) {
      process.stderr.write(`${problems.join("\n")}\n`)
      process.exit(1)
    }
  ' "$unpacked/package" "$expected_name" "$expected_version" "$commit"

  rm -rf "$unpacked"
}

name=""
version=""
base=""
hex=""
sri=""
release_version=""

for package in "${packages[@]}"; do
  read_manifest "$package"
  if [ -z "$release_version" ]; then
    release_version="$version"
  elif [ "$version" != "$release_version" ]; then
    echo "${packages[0]} is $release_version and $package is $version." >&2
    echo "One tag names one version, so the two packages are released together at the same one." >&2
    exit 1
  fi
done

expected_tag="packages/v${release_version}+${short}"

if [ -n "$tag" ] && [ "$tag" != "$expected_tag" ]; then
  echo "Tag $tag does not name this release." >&2
  echo "Commit $commit at version $release_version is $expected_tag." >&2
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
mkdir -p "$staging/assets"

echo "kalareach package release"
echo "  commit: $commit"
echo "  version: $release_version"
echo "  tag: $expected_tag"
echo "  output: $output"
echo

echo "installing the pinned dependencies"
pnpm install --frozen-lockfile
echo

# What the archives carry is generated from the Rust types, so each generator is asked whether the
# committed output is still its output: the schema, the TypeScript types, the WIT package and the
# conformance vectors the two packages publish. The terminal fixtures have their own generator and
# are in neither package, so they are not part of this.
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
  read_manifest "$package"
  packed="${base}-${version}.tgz"
  asset="${base}-${version}+${short}.tgz"

  echo "packing $name $version"
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

  read_digest "$staging/first/$packed"
  first_hex="$hex"
  first_sri="$sri"
  read_digest "$staging/second/$packed"

  # Two archives packed from one commit in one environment are one archive. When they are not,
  # something outside the commit reached the bytes, and the digests published here would describe
  # one run rather than the release.
  if [ "$hex" != "$first_hex" ]; then
    echo "Packing $name twice produced two different archives ($first_hex and $hex)." >&2
    echo "A release has to be reproducible from its commit, so this is not publishable." >&2
    exit 1
  fi

  verify_archive "$staging/first/$packed" "$package" "$name" "$version"

  mv "$staging/first/$packed" "$staging/assets/$asset"
  rm -rf "$staging/first" "$staging/second"

  assets+=("$asset")
  integrities+=("$first_sri")
  sums+=("$first_hex  $asset")
done

{
  echo "# The KalaReach generated packages at version $release_version, packed from commit $commit."
  echo "# Release tag $expected_tag."
  echo "#"
  echo "# Each sha512- line below is the integrity a lockfile records for that archive. The lines"
  echo "# that follow are the same digests in the format \`sha512sum -c\` reads."
  for index in "${!assets[@]}"; do
    echo "# ${assets[index]} ${integrities[index]}"
  done
  printf '%s\n' "${sums[@]}"
} >"$staging/assets/SHA512SUMS"

# Nothing reaches the output directory until every archive is packed, checked and summed, so a run
# that stopped part way leaves no half a release behind.
mv "$staging/assets/"* "$output/"

echo
echo "assets in $output:"
for index in "${!assets[@]}"; do
  printf '  %s  %s bytes  %s\n' \
    "${assets[index]}" "$(wc -c <"$output/${assets[index]}" | tr -d ' ')" "${integrities[index]}"
done
printf '  %s  %s bytes\n' SHA512SUMS "$(wc -c <"$output/SHA512SUMS" | tr -d ' ')"
echo
echo "tag: $expected_tag"
