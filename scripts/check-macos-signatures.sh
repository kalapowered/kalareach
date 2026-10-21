#!/usr/bin/env bash
# Holds every Mach-O file of a release tree to the signature the release says it has.
#
#   scripts/check-macos-signatures.sh <tree> ad-hoc
#   scripts/check-macos-signatures.sh <tree> developer-id
#   scripts/check-macos-signatures.sh <tree> notarized
#
# Every mode: each file passes `codesign --verify --strict`, and none carries the App Sandbox
# entitlement or an exception to library validation, since the host runs the person's development
# tools unsandboxed and a module of another team is refused.
#
# ad-hoc: the system's assessment refuses the file, which is the control that the check does not
# pass everything. developer-id: each file has the hardened runtime, a Developer ID authority, the
# one team that signs the whole tree and a timestamp. notarized: each file also passes `codesign --check-notarization` and the
# system's assessment of it accepts it as a Notarized Developer ID, which needs the network and a
# notarised release.

set -euo pipefail

tree="${1:?name the tree}"
mode="${2:?name the mode: ad-hoc, developer-id or notarized}"
failed=0
count=0
teams=()

fail() {
    echo "check-macos-signatures: $1" >&2
    failed=1
}

while IFS= read -r -d '' file; do
    file -b "$file" | grep -q 'Mach-O' || continue
    count=$((count + 1))
    relative="${file#"$tree"/}"
    /usr/bin/codesign --verify --strict "$file" 2> /dev/null || fail "$relative does not pass codesign --verify --strict"
    entitlements="$(/usr/bin/codesign -d --entitlements - "$file" 2> /dev/null || true)"
    case "$entitlements" in
        *com.apple.security.app-sandbox*) fail "$relative is sandboxed, and the host runs development tools unsandboxed" ;;
        *com.apple.security.cs.disable-library-validation*) fail "$relative excepts itself from library validation" ;;
    esac
    details="$(/usr/bin/codesign -d --verbose=4 "$file" 2>&1 || true)"
    case "$mode" in
        ad-hoc)
            if /usr/sbin/spctl --assess --type open --context context:primary-signature "$file" 2> /dev/null; then
                fail "the system accepts the ad hoc file $relative, so this check could not tell a signed release from an unsigned one"
            fi
            ;;
        developer-id | notarized)
            case "$details" in *"Authority=Developer ID Application"*) ;; *) fail "$relative has no Developer ID authority" ;; esac
            case "$details" in *"flags="*runtime*) ;; *) fail "$relative does not have the hardened runtime" ;; esac
            case "$details" in *"TeamIdentifier=not set"*) fail "$relative has no team" ;; esac
            team="$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | head -1)"
            known=0
            for seen in ${teams[@]+"${teams[@]}"}; do [ "$seen" = "$team" ] && known=1; done
            [ "$known" -eq 1 ] || teams+=("$team")
            case "$details" in *"Timestamp="*) ;; *) fail "$relative has no timestamp" ;; esac
            if [ "$mode" = notarized ]; then
                /usr/bin/codesign --verify --strict --check-notarization "$file" 2> /dev/null \
                    || fail "$relative is not notarised"
                assessed="$(/usr/sbin/spctl --assess --type open --context context:primary-signature -vv "$file" 2>&1 || true)"
                case "$assessed" in *"source=Notarized Developer ID"*) ;; *) fail "the system does not accept $relative as a Notarized Developer ID: $assessed" ;; esac
            fi
            ;;
        *) echo "check-macos-signatures: $mode is not a mode" >&2; exit 2 ;;
    esac
done < <(find "$tree" -type f -print0)

[ "$count" -gt 0 ] || { echo "check-macos-signatures: $tree holds no Mach-O file" >&2; exit 1; }
# One team signs the whole tree: a module another team signed is refused by library validation.
if [ "$mode" != ad-hoc ] && [ "${#teams[@]}" -gt 1 ]; then
    fail "the tree is signed by more than one team: ${teams[*]}"
fi
[ "$failed" -eq 0 ] || exit 1
echo "check-macos-signatures: $count files hold to $mode"
