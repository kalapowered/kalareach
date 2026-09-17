#!/usr/bin/env bash
# Builds the test components under fixtures/plugins/components/ for wasm32-wasip2.
#
# The components are a separate Cargo workspace with their own lockfile, because they are compiled
# for a different target and one of them deliberately imports interfaces the runtime refuses.
# Nothing about them belongs in the host workspace's dependency graph.
#
# The built components are not committed. Rust embeds build paths in a component's custom sections,
# so two machines produce different bytes for the same source and a committed artefact could not be
# checked. They are built here, and by the same step in continuous integration, into
#
#   fixtures/plugins/components/build/<name>.wasm
#
# which is where crates/kr-plugin-runtime's tests look for them.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
components="$root/fixtures/plugins/components"
output="$components/build"
target="wasm32-wasip2"
profile="release"

if ! command -v rustup >/dev/null 2>&1; then
    echo "build-plugin-fixtures: rustup is needed to install the $target target" >&2
    exit 1
fi

if ! rustup target list --installed | grep -qx "$target"; then
    echo "build-plugin-fixtures: installing the $target target"
    rustup target add "$target"
fi

# Each component is one package, and the .wasm is named after the package with dashes replaced.
# Listing them here rather than globbing keeps a component that was added without a test, or a test
# that names a component nobody builds, from passing quietly.
#
# Two groups, two invocations. The sandboxed components are no_std and supply their own allocator
# and panic handler; ambient-import is an ordinary standard-library build, which is what gives it
# the wasi imports the runtime refuses. Cargo unifies features across the packages of one
# invocation, so building them together would link the standard library into the no_std components
# and its panic handler would collide with theirs. Separate invocations keep each group's features
# to itself.
sandboxed=(
    infinite-loop
    memory-hog
    oversized-output
    slow-compile
    slow-observe
    well-behaved
)
ambient=(
    ambient-import
)
components_list=("${sandboxed[@]}" "${ambient[@]}")

# The components' own target directory, set explicitly. An inherited CARGO_TARGET_DIR would send
# the build somewhere else and leave the copies below reading whatever an older build had put here.
export CARGO_TARGET_DIR="$components/target"

echo "build-plugin-fixtures: building ${#components_list[@]} components for $target"
(
    cd "$components"
    packages=()
    for name in "${sandboxed[@]}"; do
        packages+=(-p "kr-fixture-$name")
    done
    cargo build --locked --target "$target" --profile "$profile" "${packages[@]}"
    packages=()
    for name in "${ambient[@]}"; do
        packages+=(-p "kr-fixture-$name")
    done
    cargo build --locked --target "$target" --profile "$profile" "${packages[@]}"
)

mkdir -p "$output"
built="$components/target/$target/$profile"
for name in "${components_list[@]}"; do
    source_file="$built/kr_fixture_${name//-/_}.wasm"
    if [ ! -f "$source_file" ]; then
        echo "build-plugin-fixtures: $source_file was not produced" >&2
        exit 1
    fi
    cp "$source_file" "$output/$name.wasm"
    size="$(wc -c <"$output/$name.wasm" | tr -d ' ')"
    printf 'build-plugin-fixtures: %-18s %8s bytes\n' "$name" "$size"
done

echo "build-plugin-fixtures: components are in $output"
