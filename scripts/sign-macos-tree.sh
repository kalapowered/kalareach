#!/usr/bin/env bash
# Signs every Mach-O file of a release tree with one identity.
#
#   scripts/sign-macos-tree.sh <tree> -                  ad hoc, for a run that proves the pipeline
#   scripts/sign-macos-tree.sh <tree> "<Developer ID>"   the release's identity, with the hardened runtime
#
# A tree is signed whole, the host's programs, the shells' programs and the modules a shell loads, by
# the same identity, because a hardened process loads only code of its own team (library
# validation). The release asks for the hardened runtime and for no entitlement: no App Sandbox,
# since the host runs the person's own development tools unsandboxed, and no exception to library
# validation, so a module the person built and signed otherwise is refused by the system, which says
# so when the shell tries to load it.
#
# An ad hoc signature has no team, so a hardened ad hoc process refuses its own modules: an ad hoc
# run signs without the runtime, and says so. Nothing here changes a file that is not Mach-O, and
# the manifest is written after this step, since a signature changes the bytes it covers.

set -euo pipefail

tree="${1:?name the tree}"
identity="${2:?name the identity: - for ad hoc}"

if [ "$(uname -s)" != Darwin ]; then
    echo "sign-macos-tree: codesign is a macOS tool" >&2
    exit 1
fi

options=(--force --sign "$identity")
if [ "$identity" = "-" ]; then
    options+=(--timestamp=none)
    echo "sign-macos-tree: ad hoc, without the hardened runtime: an ad hoc signature has no team for library validation to name"
else
    options+=(--options runtime --timestamp)
fi

count=0
while IFS= read -r -d '' file; do
    if file -b "$file" | grep -q 'Mach-O'; then
        /usr/bin/codesign "${options[@]}" "$file"
        count=$((count + 1))
    fi
done < <(find "$tree" -type f -print0)

if [ "$count" -eq 0 ]; then
    echo "sign-macos-tree: $tree holds no Mach-O file" >&2
    exit 1
fi
echo "sign-macos-tree: signed $count files in $tree"
