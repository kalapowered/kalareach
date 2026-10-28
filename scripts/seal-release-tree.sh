#!/usr/bin/env bash
# Seals a release tree: the manifest is written again over the files as they now are, signed by the
# update channel's release keys, and the tree is packed into the archive a host takes.
#
#   scripts/seal-release-tree.sh --tree <dir> --checkout <dir> --plugins <dir> --kr-release <program> \
#       --root <root.json> --key <targets key>... --out <dir>
#
# A platform signature changes the bytes the manifest's digests cover, so the manifest follows it.
# What the manifest states about the release (its name, sequence, commit, target and floor) is read
# from the `release.json` the tree already has, and the channel's root replaces the one in the tree.
# The steps, each of which stops the script when it fails:
#
#   1. the tree's update root is replaced by <root.json>, so the root the release carries is the
#      one given and nothing else;
#   2. `kr-release manifest`, `check` and `sign`: the manifest is made from the tree, the tree is
#      held to what a release is, and the manifest is signed by each key;
#   3. `kr-release verify` over the signed tree against <root.json>, as a host does;
#   4. the tree is scanned for a private key;
#   5. the tree is packed into <out>/<top directory>.tar.gz with no extended attributes, and
#      <out>/SHA256SUMS names that one archive;
#   6. the archive is checked the way a host stages one, and scanned for a private key.
#
# The release workflows run it with a root and keys that the run made, to prove the path in every
# run, and with the channel's own root and keys when a release is sealed. The script reads no
# network and no environment variable that holds a secret: keys are named by path.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tree=""
checkout=""
plugins=""
kr_release=""
root=""
out=""
keys=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --tree) tree="${2:?--tree needs a directory}"; shift 2 ;;
        --checkout) checkout="${2:?--checkout needs a directory}"; shift 2 ;;
        --plugins) plugins="${2:?--plugins needs a directory}"; shift 2 ;;
        --kr-release) kr_release="${2:?--kr-release needs a program}"; shift 2 ;;
        --root) root="${2:?--root needs a file}"; shift 2 ;;
        --key) keys+=("${2:?--key needs a file}"); shift 2 ;;
        --out) out="${2:?--out needs a directory}"; shift 2 ;;
        *) echo "seal-release-tree: unknown argument $1" >&2; exit 2 ;;
    esac
done
for need in tree checkout plugins kr_release root out; do
    if [ -z "${!need}" ]; then
        echo "seal-release-tree: --${need//_/-} is needed" >&2
        exit 2
    fi
done
if [ "${#keys[@]}" -eq 0 ]; then
    echo "seal-release-tree: at least one --key is needed" >&2
    exit 2
fi
if [ ! -f "$tree/release.json" ]; then
    echo "seal-release-tree: $tree holds no release.json" >&2
    exit 1
fi

# What the release states about itself, as the tree's own manifest says it.
facts="$(python3 -I - "$tree/release.json" << 'PYTHON'
import json
import sys

signed = json.load(open(sys.argv[1], encoding="utf-8"))["signed"]
floor = signed["os_floor"]
for name, value in (
    ("release", signed["release"]),
    ("sequence", signed["sequence"]),
    ("commit", signed["commit"]),
    ("target", signed["target"]),
    ("floor", f"{floor['system']}={floor['version']}"),
):
    print(f"{name}={value}")
PYTHON
)"
fact() { printf '%s\n' "$facts" | sed -n "s/^$1=//p"; }
release="$(fact release)"
sequence="$(fact sequence)"
commit="$(fact commit)"
target="$(fact target)"
floor="$(fact floor)"
top="$(basename "$tree")"
if [ "$top" != "kalareach-$target-$release" ]; then
    echo "seal-release-tree: the directory is named $top, and the manifest names kalareach-$target-$release" >&2
    exit 1
fi

cp "$root" "$tree/share/update-root.json"
"$kr_release" manifest --tree "$tree" --checkout "$checkout" --release "$release" --sequence "$sequence" \
    --commit "$commit" --target "$target" --floor "$floor"
key_options=()
for key in "${keys[@]}"; do key_options+=(--key "$key"); done
"$kr_release" check --tree "$tree" --checkout "$checkout" --plugins "$plugins"
"$kr_release" sign --tree "$tree" --checkout "$checkout" "${key_options[@]}" --plugins "$plugins"
"$kr_release" verify --tree "$tree" --root "$root"
if ! cmp -s "$tree/share/update-root.json" "$root"; then
    echo "seal-release-tree: the root the release carries is not the root given" >&2
    exit 1
fi
python3 -I "$here/check-release-secrets.py" scan "$tree"

mkdir -p "$out"
archive="$out/$top.tar.gz"
# No extended attributes: macOS's tar writes a second entry for each, which a release archive does
# not hold.
COPYFILE_DISABLE=1 tar -C "$(dirname "$tree")" -czf "$archive" "$top"
(cd "$out" && { sha256sum "$top.tar.gz" 2> /dev/null || shasum -a 256 "$top.tar.gz"; } > SHA256SUMS)
python3 -I "$here/check-release-archive.py" check --archive "$archive" --sums "$out/SHA256SUMS"
python3 -I "$here/check-release-secrets.py" scan "$archive"
echo "seal-release-tree: $archive is sealed for $release ($target), $(cut -d' ' -f1 < "$out/SHA256SUMS")"
