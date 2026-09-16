#!/usr/bin/env bash
# Packs the generated TypeScript packages from this commit and records what they hash to.
#
# `@kalareach/protocol` and `@kalareach/plugin-sdk` come from the Rust types in this repository, and
# the website and the plugin catalogue consume them as immutable releases pinned by URL and
# integrity. A release is therefore exactly one commit's output, and this script is what makes that
# true: it holds every generated artefact the two packages ship to the canonical Rust source, packs
# from a fresh checkout of the commit rather than from the working tree, asks each archive what it
# contains, names it after the commit, and writes the digests a consumer pins and verifies against.
#
# The archive format belongs to pnpm: members in a fixed order under a fixed timestamp, with fixed
# permissions and no machine identity. What is left to vary is the environment, so the script takes
# the committed bytes with no conversion, refuses a configured value for each of the pnpm settings
# listed below, and packs each archive twice to catch anything that varies within one run. The Node
# and pnpm versions are the release's own, pinned where the release runs.
#
#   bash scripts/release-packages.sh                                  # writes dist/packages
#   bash scripts/release-packages.sh --output /tmp/kalareach-packages
#   bash scripts/release-packages.sh --tag packages/v0.2.0+0123456789ab
#
# `--tag` is what the release workflow passes. The tag has to name this commit and this version, so
# a tag pushed at the wrong revision fails here rather than publishing a mislabelled archive.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# The packages a release carries. One tag names one version, so both of these hold the same one.
packages=(packages/protocol packages/plugin-sdk)

# The pnpm settings that reach an archive, as "<setting>|<the value a release is packed under>|<what
# another value changes>". `pack-gzip-level` reaches zlib directly. `ignore-scripts` decides whether
# the step that generates the declarations, the conformance vectors and the provenance file of the
# protocol package runs at all, and a pack that skipped it is a smaller archive that still packs and
# still equals a second pack of itself. `skip-manifest-obfuscation` decides which manifest is
# written into the archive, and a configured pnpmfile can rewrite that manifest from outside the
# commit through its packing hook.
settings=(
  "pack-gzip-level|undefined|the compressed bytes"
  "ignore-scripts|false|whether most of what the protocol package publishes is generated at all"
  "skip-manifest-obfuscation|false|the manifest written into the archive"
  "pnpmfile|undefined|the manifest written into the archive"
  "global-pnpmfile|undefined|the manifest written into the archive"
)

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

# A release names the commit it was packed from, so what it carries has to be committed. The
# generated files the archives pick up are not, which is why this asks about tracked files and
# untracked ones but not about ignored ones; the pack itself runs in a fresh checkout further down,
# so a file that exists only here cannot reach an archive either way.
dirty="$(git status --porcelain --untracked-files=all)"
if [ -n "$dirty" ]; then
  echo "This tree is not clean, so a release packed from it would not be this commit:" >&2
  echo "$dirty" >&2
  exit 1
fi

commit="$(git rev-parse HEAD)"
short="${commit:0:12}"

for entry in "${settings[@]}"; do
  IFS='|' read -r key allowed changes <<<"$entry"
  configured="$(pnpm config get "$key")"

  if [ "$configured" != "undefined" ] && [ "$configured" != "$allowed" ]; then
    echo "This environment sets $key to $configured, which changes $changes." >&2
    echo "A release is packed under pnpm's own $key, so this one is not publishable." >&2
    exit 1
  fi
done

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

# Asks one archive what it contains, rather than trusting that packing went well: a file under every
# path the package publishes, the file behind every entry point it declares, those declarations
# unchanged, a manifest naming that package and version, and a provenance file, where the package
# has one, naming this commit. What the package publishes is read from the checkout, because an
# archive measured against its own manifest is an archive asked whether it agrees with itself.
verify_archive() {
  local archive="$1" source="$2" expected_name="$3" expected_version="$4" unpacked

  unpacked="$staging/unpacked"
  rm -rf "$unpacked"
  mkdir -p "$unpacked"
  tar -xzf "$archive" -C "$unpacked"

  # shellcheck disable=SC2016  # the ${} below are JavaScript template placeholders.
  node -e '
    const { readdirSync, readFileSync, statSync } = require("node:fs")
    const [source, archive, label, expectedName, expectedVersion, commit] = process.argv.slice(1)

    const declared = JSON.parse(readFileSync(`${source}/package.json`, "utf8"))
    const packed = JSON.parse(readFileSync(`${archive}/package.json`, "utf8"))

    const carried = readdirSync(archive, { recursive: true })
      .filter((entry) => statSync(`${archive}/${entry}`).isFile())
      .map((entry) => entry.split("\\").join("/"))

    const problems = []
    const bare = (path) => path.replace(/^\.\//, "")

    // A path with a `*` in it is met by anything that matches; a plain path by itself.
    const matches = (pattern, entry) =>
      new RegExp(
        `^${bare(pattern)
          .split("*")
          .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
          .join(".*")}$`
      ).test(entry)

    if (declared.name !== expectedName || declared.version !== expectedVersion) {
      problems.push(
        `${source}/package.json names ${declared.name} ${declared.version}, ` +
          `not ${expectedName} ${expectedVersion}`
      )
    }
    if (packed.name !== expectedName) {
      problems.push(`${label} contains ${packed.name}, not ${expectedName}`)
    }
    if (packed.version !== expectedVersion) {
      problems.push(`${label} contains version ${packed.version}, not ${expectedVersion}`)
    }

    // The declarations a consumer resolves through have to survive packing. pnpm rewrites the
    // manifest it puts in the archive, dropping the lifecycle scripts among other things, so these
    // are compared field by field and not as whole documents. The comparison keeps the order of an
    // exports map: the conditions in it are tried in the order they appear, so two maps with the
    // same entries in another order resolve differently.
    const written = (value) => JSON.stringify(value === undefined ? null : value)

    for (const field of ["main", "types", "exports"]) {
      if (written(declared[field]) !== written(packed[field])) {
        problems.push(
          `${label} declares ${field} ${written(packed[field])}, not ${written(declared[field])}`
        )
      }
    }

    // Each published path is met the way the checkout holds it. A file has to be that file, so a
    // directory of that name is not a `provenance.json`; a directory has to hold something, so an
    // empty `types` is not the declarations. Every entry in `carried` is a regular file.
    for (const published of Array.isArray(declared.files) ? declared.files : []) {
      const path = bare(published).replace(/\/+$/, "")
      const holds = path.includes("*")
        ? carried.some((entry) => matches(path, entry))
        : statSync(`${source}/${path}`, { throwIfNoEntry: false })?.isDirectory()
          ? carried.some((entry) => entry.startsWith(`${path}/`))
          : carried.includes(path)

      if (!holds) {
        problems.push(`${label} carries no ${published}, which the package publishes`)
      }
    }

    // What the package points at is what a consumer resolves: its main, its declarations and every
    // target in its exports map. Each is compared as a path, so a manifest that leaned on Node
    // resolving an extension or a directory index would need this to grow.
    const targets = new Set()
    const collect = (value) => {
      if (typeof value === "string") targets.add(value)
      else if (value !== null && typeof value === "object") Object.values(value).forEach(collect)
    }

    collect(declared.main)
    collect(declared.types)
    collect(declared.exports)

    for (const target of targets) {
      const path = bare(target)
      const present = path.includes("*")
        ? carried.some((entry) => matches(path, entry))
        : carried.includes(path)

      if (!present) {
        problems.push(`${label} carries nothing at ${target}, which the package exports`)
      }
    }

    if (carried.includes("provenance.json")) {
      const provenance = JSON.parse(readFileSync(`${archive}/provenance.json`, "utf8"))

      if (provenance.core_commit !== commit) {
        problems.push(`${label} was packed from ${provenance.core_commit}, not from ${commit}`)
      }
      if (provenance.package !== expectedName || provenance.version !== expectedVersion) {
        problems.push(
          `${label} names ${provenance.package} ${provenance.version} as its provenance, ` +
            `not ${expectedName} ${expectedVersion}`
        )
      }
    }

    if (problems.length > 0) {
      process.stderr.write(`${problems.join("\n")}\n`)
      process.stderr.write(`It carries:\n${carried.sort().join("\n")}\n`)
      process.exit(1)
    }
  ' "$source" "$unpacked/package" "$(basename "$archive")" "$expected_name" "$expected_version" \
    "$commit"

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
# commits' archives is the mistake this refuses. The listing is taken first, so a directory that
# cannot be read ends the run instead of passing for an empty one.
if [ -e "$output" ]; then
  existing="$(ls -A "$output")"

  if [ -n "$existing" ]; then
    echo "$output already holds files:" >&2
    echo "$existing" >&2
    echo "Empty it or choose another directory." >&2
    exit 1
  fi
fi

mkdir -p "$output"
output="$(cd "$output" && pwd)"

staging="$(mktemp -d "${TMPDIR:-/tmp}/kalareach-release.XXXXXX")"
trap 'rm -rf "$staging"' EXIT
mkdir -p "$staging/assets"
checkout="$staging/checkout"

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

# Packing happens in a checkout of nothing but this commit. A working tree also holds files Git
# ignores, and pnpm packs what is inside a published directory whether Git ignores it or not, so a
# stray file here would otherwise travel inside a release. The checkout takes the committed bytes
# exactly: pnpm packs the bytes it finds, and line-ending conversion is configured per machine, both
# as a setting and through attribute files outside the commit.
echo "checking out $short to pack from"
git clone --quiet --shared --no-checkout "$root" "$checkout"
git -C "$checkout" config core.autocrlf false
git -C "$checkout" config core.eol lf
git -C "$checkout" config core.attributesFile /dev/null
GIT_ATTR_NOSYSTEM=1 git -C "$checkout" checkout --quiet --detach "$commit"
pnpm -C "$checkout" install --frozen-lockfile
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
  pnpm -C "$checkout/$package" pack --pack-destination "$staging/first" >/dev/null
  pnpm -C "$checkout/$package" pack --pack-destination "$staging/second" >/dev/null

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

  # Two archives packed from one commit in one run are one archive. When they are not, something
  # that varies from moment to moment reached the bytes, and the digests published here would
  # describe one pack rather than the release.
  if [ "$hex" != "$first_hex" ]; then
    echo "Packing $name twice produced two different archives ($first_hex and $hex)." >&2
    echo "A release has to be reproducible from its commit, so this is not publishable." >&2
    exit 1
  fi

  verify_archive "$staging/first/$packed" "$checkout/$package" "$name" "$version"

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
# that stopped before this point leaves nothing behind at all.
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
