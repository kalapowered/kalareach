#!/usr/bin/env bash
# Assembles a release's tree from built programs and built shell packages, and writes its record and
# its unsigned manifest.
#
#   scripts/build-release.sh --target <triple> --release <name> --sequence <n> --commit <sha> \
#       --floor <system>=<version> --programs <dir> --shells <dir> --root <update-root.json> \
#       --out <tree> [--kr-release <program>] [--plugins <dir>] [--web <dir>] [--development] \
#       [--macos-identity <identity>]
#
# The tree is `bin/` with the host's programs, `shells/` with the shell packages, `share/` with the
# update channel's root, the record and the licences, and `release.json`, which `kr-release sign`
# then signs. What the tree holds is checked by `kr-release`, not here: a package built from other
# inputs than this checkout's, a missing module directory and a file a release does not hold stop
# the manifest, so a tree that is wrong is never written down as a release.
#
# Every file of a package is copied as a file of its own, because the build names one binary twice
# and an archive writes the second name as a link. A directory the build left empty is left out,
# since a release holds none. A step that changes a file, such as the platform's signature, runs
# on the tree before the manifest is written: `--macos-identity` signs each Mach-O file, and a
# platform signature made by another step is made before `kr-release manifest` is run again.
#
# No release key is read here: the manifest is signed by `kr-release sign`. The programs are built
# and their floors checked by the workflow that calls this.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

target=""
release=""
sequence=""
commit=""
floor=""
programs=""
shells=""
update_root=""
out=""
macos_identity=""
kr_release="${KR_RELEASE:-$root/target/release/kr-release}"
record_options=()

usage() {
    sed -n '2,22p' "$0" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target) target="${2:?--target needs a value}"; shift 2 ;;
        --release) release="${2:?--release needs a value}"; shift 2 ;;
        --sequence) sequence="${2:?--sequence needs a value}"; shift 2 ;;
        --commit) commit="${2:?--commit needs a value}"; shift 2 ;;
        --floor) floor="${2:?--floor needs a value}"; shift 2 ;;
        --programs) programs="${2:?--programs needs a directory}"; shift 2 ;;
        --shells) shells="${2:?--shells needs a directory}"; shift 2 ;;
        --root) update_root="${2:?--root needs a file}"; shift 2 ;;
        --out) out="${2:?--out needs a directory}"; shift 2 ;;
        --kr-release) kr_release="${2:?--kr-release needs a program}"; shift 2 ;;
        --plugins) record_options+=(--plugins "${2:?--plugins needs a directory}"); shift 2 ;;
        --web) record_options+=(--web "${2:?--web needs a directory}"); shift 2 ;;
        --development) record_options+=(--development); shift ;;
        --macos-identity) macos_identity="${2:?--macos-identity needs an identity}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "build-release: unknown argument $1" >&2; usage ;;
    esac
done

for name in target release sequence commit floor programs shells update_root out; do
    if [ -z "${!name}" ]; then
        echo "build-release: --${name//_/-} is needed" >&2
        usage
    fi
done
if [ ! -x "$kr_release" ]; then
    echo "build-release: $kr_release is not a program; build kr-release first or name it with --kr-release" >&2
    exit 1
fi
if [ -e "$out" ] && [ -n "$(ls -A "$out" 2>/dev/null)" ]; then
    echo "build-release: $out is not empty" >&2
    exit 1
fi

suffix=""
case "$target" in *windows*) suffix=".exe" ;; esac

mkdir -p "$out/bin" "$out/shells" "$out/share"

# The host's programs, by the list that the release, the Windows archive check and the host's own
# check of a release all read.
while IFS= read -r name; do
    source_file="$programs/$name$suffix"
    if [ ! -f "$source_file" ]; then
        echo "build-release: $source_file is not built" >&2
        exit 1
    fi
    cp "$source_file" "$out/bin/$name$suffix"
    chmod 755 "$out/bin/$name$suffix"
done < <(python3 "$root/scripts/release-programs.py" names --target "$target")

# The shell packages this target ships: each one's current build, every file as a file of its own,
# no empty directory, the pointer to the build, the entry an installed host's startup files source
# and the licence of the shell.
python3 - "$shells" "$out/shells" "$root" <<'PYTHON'
import json
import os
import shutil
import sys

built, destination, root = sys.argv[1:4]


def copy_files(source, target):
    """Every regular file of `source` as a file of its own; a directory is made only for a file."""
    for directory, _, names in os.walk(source):
        for name in sorted(names):
            path = os.path.join(directory, name)
            if os.path.islink(path):
                os.stat(path)  # a link a package holds must lead somewhere
            relative = os.path.relpath(path, source)
            made = os.path.join(target, relative)
            os.makedirs(os.path.dirname(made), exist_ok=True)
            shutil.copyfile(path, made)
            shutil.copymode(path, made)


for shell in ("zsh", "bash", "fish"):
    package = os.path.join(built, shell)
    pointer = os.path.join(package, "current")
    if not os.path.isfile(pointer):
        sys.exit(f"build-release: {shell} is not built in {built}")
    identity = open(pointer, encoding="utf-8").read().strip()
    home = os.path.join(package, identity)
    out = os.path.join(destination, shell)
    copy_files(home, os.path.join(out, identity))
    with open(os.path.join(out, "current"), "w", encoding="utf-8") as handle:
        handle.write(identity)
    record = json.load(open(os.path.join(home, "kr-shell-identity.json"), encoding="utf-8"))
    entry = record["startup_entry"]["file"]
    shutil.copyfile(os.path.join(home, entry), os.path.join(out, os.path.basename(entry)))
    shutil.copyfile(os.path.join(root, "shells", shell, "LICENSE"), os.path.join(out, "LICENSE"))
PYTHON

cp "$update_root" "$out/share/update-root.json"
cp "$root/LICENSE" "$out/share/LICENSE"

# Every Mach-O file is signed before anything is digested: a signature changes the bytes the
# manifest covers.
if [ -n "$macos_identity" ]; then
    bash "$root/scripts/sign-macos-tree.sh" "$out" "$macos_identity"
fi

"$kr_release" record --tree "$out" --checkout "$root" --target "$target" ${record_options[@]+"${record_options[@]}"}
"$kr_release" manifest --tree "$out" --checkout "$root" --release "$release" --sequence "$sequence" \
    --commit "$commit" --target "$target" --floor "$floor"
echo "build-release: $out is a release tree for $release"
