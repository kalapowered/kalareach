#!/usr/bin/env bash
# Signs every Mach-O file of a release tree with one identity, using `rcodesign`.
#
#   scripts/sign-macos-tree.sh <tree> -             ad hoc, for a run that proves the pipeline
#   scripts/sign-macos-tree.sh <tree> developer-id  the release's identity, with the hardened runtime
#
# For developer-id the identity is read from files, never from a keychain, so signing changes
# nothing in the person's keychains or their search list:
#
#   KR_SIGN_KEY    the private key, PKCS #8 PEM
#   KR_SIGN_CERT   the Developer ID Application certificate, PEM
#   KR_SIGN_CHAIN  the Developer ID intermediate certificate, DER
#
# A tree is signed whole, the host's programs, the shells' programs and the modules a shell loads, by
# the same identity, because a hardened process loads only code of its own team (library
# validation). The release asks for the hardened runtime and for one entitlement on one program: no
# App Sandbox, since the host runs the person's own development tools unsandboxed, and no exception
# to library validation, so a module the person built and signed otherwise is refused by the system,
# which says so when the shell tries to load it. The one entitlement is
# `com.apple.security.cs.allow-unsigned-executable-memory` on `bin/kr-plugin-host`
# (`scripts/macos-entitlements/kr-plugin-host.plist`): that program runs Wasmtime, which writes machine
# code into memory and then makes it executable, and the hardened runtime ends a process that does
# so without the entitlement. No other program makes code at run time.
#
# An ad hoc signature has no team, so a hardened ad hoc process refuses its own modules: an ad hoc
# run signs without the runtime, and says so, except the plugin host, which loads no module and so
# is signed as a release signs it. Nothing here changes a file that is not Mach-O, and the manifest
# is written after this step, since a signature changes the bytes it covers.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tree="${1:?name the tree}"
identity="${2:?name the identity: - for ad hoc, or developer-id}"
entitlements="$here/macos-entitlements/kr-plugin-host.plist"
entitled="bin/kr-plugin-host"

if [ "$(uname -s)" != Darwin ]; then
    echo "sign-macos-tree: the signature of a Mach-O file is made on macOS" >&2
    exit 1
fi

# The signer is the pinned one. A program named in the environment is taken only for an ad hoc
# signature of a proving run: the Developer ID signature reads the private key, and only the pinned
# program is given it.
if [ -n "${KR_RCODESIGN:-}" ]; then
    # By absolute path, so that the file that is verified is the file that runs.
    case "$KR_RCODESIGN" in /*) ;; *) KR_RCODESIGN="$PWD/$KR_RCODESIGN" ;; esac
fi
if [ -n "${KR_RCODESIGN:-}" ] && [ "$identity" = developer-id ]; then
    bash "$here/install-rcodesign.sh" --verify "$KR_RCODESIGN" || {
        echo "sign-macos-tree: KR_RCODESIGN is not the pinned rcodesign, and the Developer ID key is read only by the pinned one" >&2
        exit 1
    }
fi
rcodesign="${KR_RCODESIGN:-$(bash "$here/install-rcodesign.sh")}"

key_options=()
case "$identity" in
    -)
        echo "sign-macos-tree: ad hoc, without the hardened runtime: an ad hoc signature has no team for library validation to name"
        ;;
    developer-id)
        for need in KR_SIGN_KEY KR_SIGN_CERT KR_SIGN_CHAIN; do
            if [ -z "${!need:-}" ] || [ ! -f "${!need}" ]; then
                echo "sign-macos-tree: $need must name a file" >&2
                exit 1
            fi
        done
        key_options=(--pem-file "$KR_SIGN_KEY" --pem-file "$KR_SIGN_CERT" --certificate-der-file "$KR_SIGN_CHAIN")
        ;;
    *)
        echo "sign-macos-tree: $identity is neither - nor developer-id" >&2
        exit 2
        ;;
esac

count=0
while IFS= read -r -d '' file; do
    file -b "$file" | grep -q 'Mach-O' || continue
    relative="${file#"$tree"/}"
    options=(--binary-identifier "$(basename "$file")")
    if [ "$identity" = developer-id ]; then
        options+=("${key_options[@]}" --code-signature-flags runtime)
    elif [ "$relative" = "$entitled" ]; then
        options+=(--code-signature-flags runtime)
    fi
    if [ "$relative" = "$entitled" ]; then
        options+=(--entitlements-xml-file "$entitlements")
    fi
    mode="$(stat -f %Lp "$file")"
    chmod u+w "$file"
    "$rcodesign" sign "${options[@]}" "$file" > /dev/null 2> "${TMPDIR:-/tmp}/kr-sign-macos-tree.$$.log" || {
        cat "${TMPDIR:-/tmp}/kr-sign-macos-tree.$$.log" >&2
        rm -f "${TMPDIR:-/tmp}/kr-sign-macos-tree.$$.log"
        echo "sign-macos-tree: $relative was not signed" >&2
        exit 1
    }
    chmod "$mode" "$file"
    count=$((count + 1))
done < <(find "$tree" -type f -print0)
rm -f "${TMPDIR:-/tmp}/kr-sign-macos-tree.$$.log"

if [ "$count" -eq 0 ]; then
    echo "sign-macos-tree: $tree holds no Mach-O file" >&2
    exit 1
fi
echo "sign-macos-tree: signed $count files in $tree"
