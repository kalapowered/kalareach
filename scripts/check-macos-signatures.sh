#!/usr/bin/env bash
# Holds every Mach-O file of a release tree to the signature the release says it has.
#
#   scripts/check-macos-signatures.sh <tree> ad-hoc
#   scripts/check-macos-signatures.sh <tree> developer-id
#   scripts/check-macos-signatures.sh <tree> notarized
#   scripts/check-macos-signatures.sh self-test
#
# Every mode: each file passes `codesign --verify --strict`, and the entitlements are an
# allow-list. `bin/kr-plugin-host` has exactly one entitlement, `com.apple.security.cs.allow-unsigned-executable-memory`
# set to true, because it runs Wasmtime, which makes machine code at run time and is ended by the
# hardened runtime without it; every other file has none. So none is sandboxed (the host runs
# development tools unsandboxed) and none excepts itself from library validation (a module of another
# team is refused).
#
# ad-hoc: the plugin host has the hardened runtime and no other file has it (an ad hoc signature has no
# team, which library validation needs to load a shell's modules), and the system's assessment
# refuses the file, which is the control that the check does not pass everything. developer-id: each file has the hardened runtime, a three-certificate chain that
# ends at Apple, the one team that signs this project's releases, and a timestamp; the team is the
# constant below and a designated requirement over the Developer ID leaf and intermediate says so,
# so a Developer ID of another team, the individual team's included, is refused. notarized: each
# file also passes `codesign --check-notarization` and the system's assessment of it accepts it as a
# Notarized Developer ID, which needs the network and a notarised release.
#
# The self-test signs ad hoc, so it shows the entitlement, runtime and signature rules. A tree signed by
# another team's Developer ID, or a requirement that fails, needs a certificate of another team to try and
# has no case here.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
team="L775WGST9V"
entitled="bin/kr-plugin-host"
entitlements_wanted='{"com.apple.security.cs.allow-unsigned-executable-memory": true}'

# The Developer ID leaf and its intermediate (Apple's object identifiers 1.2.840.113635.100.6.1.13
# and 1.2.840.113635.100.6.2.6) and the team in the leaf's subject.
requirement() {
    printf '=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = "%s"' "$1"
}

# The file's entitlements as one JSON object with its keys sorted, or nothing when it has none.
entitlements_of() {
    local plist
    plist="$(/usr/bin/codesign -d --entitlements :- "$1" 2> /dev/null || true)"
    [ -n "$plist" ] || return 0
    printf '%s' "$plist" | /usr/bin/plutil -convert json -o - - | /usr/bin/python3 -I -c 'import json, sys; print(json.dumps(json.load(sys.stdin), sort_keys=True))'
}

check() {
    local tree="$1" mode="$2" failed=0 count=0 file relative keys details assessed
    fail() {
        echo "check-macos-signatures: $1" >&2
        failed=1
    }
    while IFS= read -r -d '' file; do
        file -b "$file" | grep -q 'Mach-O' || continue
        count=$((count + 1))
        relative="${file#"$tree"/}"
        /usr/bin/codesign --verify --strict "$file" 2> /dev/null || fail "$relative does not pass codesign --verify --strict"
        keys="$(entitlements_of "$file")"
        if [ "$relative" = "$entitled" ]; then
            [ "$keys" = "$entitlements_wanted" ] || fail "$relative must have exactly $entitlements_wanted, and has: ${keys:-none}"
        elif [ -n "$keys" ]; then
            fail "$relative has entitlements, and only $entitled has one: $keys"
        fi
        details="$(/usr/bin/codesign -d --verbose=4 "$file" 2>&1 || true)"
        case "$mode" in
            ad-hoc)
                case "$details" in
                    *"flags="*runtime*) [ "$relative" = "$entitled" ] || fail "$relative has the hardened runtime, which an ad hoc file has only when it is the plugin host" ;;
                    *) [ "$relative" != "$entitled" ] || fail "$relative does not have the hardened runtime" ;;
                esac
                if /usr/sbin/spctl --assess --type open --context context:primary-signature "$file" 2> /dev/null; then
                    fail "the system accepts the ad hoc file $relative, so this check could not tell a signed release from an unsigned one"
                fi
                ;;
            developer-id | notarized)
                case "$details" in *"Authority=Developer ID Application"*) ;; *) fail "$relative has no Developer ID authority" ;; esac
                case "$details" in *"flags="*runtime*) ;; *) fail "$relative does not have the hardened runtime" ;; esac
                case "$details" in *"Timestamp="*) ;; *) fail "$relative has no timestamp" ;; esac
                [ "$(printf '%s\n' "$details" | grep -c '^Authority=')" -eq 3 ] || fail "$relative has a chain of other than three certificates"
                [ "$(printf '%s\n' "$details" | sed -n 's/^TeamIdentifier=//p' | head -1)" = "$team" ] || fail "$relative is not signed by the team $team"
                /usr/bin/codesign --verify --strict -R "$(requirement "$team")" "$file" 2> /dev/null \
                    || fail "$relative does not satisfy the Developer ID requirement of the team $team"
                if [ "$mode" = notarized ]; then
                    /usr/bin/codesign --verify --strict --check-notarization "$file" 2> /dev/null \
                        || fail "$relative is not notarised"
                    assessed="$(/usr/sbin/spctl --assess --type open --context context:primary-signature -vv "$file" 2>&1 || true)"
                    case "$assessed" in *"source=Notarized Developer ID"*) ;; *) fail "the system does not accept $relative as a Notarized Developer ID: $assessed" ;; esac
                fi
                ;;
            *) echo "check-macos-signatures: $mode is not a mode" >&2; return 2 ;;
        esac
    done < <(find "$tree" -type f -print0)

    [ "$count" -gt 0 ] || { echo "check-macos-signatures: $tree holds no Mach-O file" >&2; return 1; }
    [ "$failed" -eq 0 ] || return 1
    echo "check-macos-signatures: $count files hold to $mode"
}

# A tree of small programs signed the way the release signs them, and then the same tree with one
# fault planted in it, for each fault the check has to refuse. The control is the tree as the
# release signs it, which has to pass.
self_test() {
    local rcodesign failures=0
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-check-signatures.XXXXXX")"
    trap 'chmod -R u+w "${work:?}" 2> /dev/null; rm -rf "${work:?}"' EXIT
    rcodesign="${KR_RCODESIGN:-$(bash "$here/install-rcodesign.sh")}"
    printf 'int main(void) { return 0; }\n' > "$work/program.c"
    /usr/bin/clang -o "$work/program" "$work/program.c"

    make_tree() {
        local tree="$work/$1"
        mkdir -p "$tree/bin" "$tree/shells"
        for name in kr kr-worker kr-plugin-host; do cp "$work/program" "$tree/bin/$name"; done
        cp "$work/program" "$tree/shells/module"
        KR_RCODESIGN="$rcodesign" bash "$here/sign-macos-tree.sh" "$tree" - > /dev/null
    }
    resign() { # <tree> <file> <entitlements plist or ''> <flags...>: from the program as built, so no entitlement is kept
        local tree="$1" file="$2" entitlements="$3"
        shift 3
        cp "$work/program" "$work/$tree/$file"
        local options=(--binary-identifier "$(basename "$file")" "$@")
        [ -z "$entitlements" ] || options+=(--entitlements-xml-file "$entitlements")
        "$rcodesign" sign "${options[@]}" "$work/$tree/$file" > /dev/null 2>&1
    }
    plist_of() { # <key> <name> [true|false]
        printf '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>%s</key><%s/></dict></plist>\n' "$1" "${3:-true}" > "$work/$2.plist"
        printf '%s' "$work/$2.plist"
    }
    expect() { # <name> <exit wanted: 0 or 1> <tree> <mode>
        local rc=0
        check "$work/$3" "$4" > "$work/out.txt" 2>&1 || rc=$?
        if { [ "$2" = 0 ] && [ "$rc" -ne 0 ]; } || { [ "$2" = 1 ] && [ "$rc" -eq 0 ]; }; then
            echo "self-test FAILED: $1 (exit $rc)"
            sed 's/^/    /' "$work/out.txt"
            failures=$((failures + 1))
        else
            echo "self-test ok: $1"
        fi
    }

    make_tree control
    expect "the tree as the release signs it, ad hoc, passes" 0 control ad-hoc
    expect "an ad hoc tree is refused as a Developer ID tree" 1 control developer-id

    make_tree extra-entitlement
    resign extra-entitlement bin/kr-worker "$(plist_of com.apple.security.cs.allow-jit jit)" --code-signature-flags runtime
    expect "an entitlement on another program is refused" 1 extra-entitlement ad-hoc

    make_tree missing-entitlement
    resign missing-entitlement bin/kr-plugin-host "" --code-signature-flags runtime
    expect "a plugin host without its entitlement is refused" 1 missing-entitlement ad-hoc

    make_tree false-entitlement
    resign false-entitlement bin/kr-plugin-host "$(plist_of com.apple.security.cs.allow-unsigned-executable-memory off false)" --code-signature-flags runtime
    expect "an entitlement set to false is refused" 1 false-entitlement ad-hoc

    make_tree no-runtime
    resign no-runtime bin/kr-plugin-host "$here/macos-entitlements/kr-plugin-host.plist"
    expect "a plugin host without the hardened runtime is refused" 1 no-runtime ad-hoc

    make_tree runtime-elsewhere
    resign runtime-elsewhere shells/module "" --code-signature-flags runtime
    expect "an ad hoc file other than the plugin host with the hardened runtime is refused" 1 runtime-elsewhere ad-hoc

    make_tree two-entitlements
    cat > "$work/two.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/><key>com.apple.security.cs.allow-jit</key><true/></dict></plist>
PLIST
    resign two-entitlements bin/kr-plugin-host "$work/two.plist" --code-signature-flags runtime
    expect "a plugin host with a second entitlement is refused" 1 two-entitlements ad-hoc

    make_tree library-validation
    resign library-validation shells/module "$(plist_of com.apple.security.cs.disable-library-validation lv)" --code-signature-flags runtime
    expect "an exception to library validation is refused" 1 library-validation ad-hoc

    make_tree sandbox
    resign sandbox bin/kr "$(plist_of com.apple.security.app-sandbox sb)" --code-signature-flags runtime
    expect "the App Sandbox is refused" 1 sandbox ad-hoc

    make_tree unsigned
    /usr/bin/codesign --remove-signature "$work/unsigned/bin/kr"
    expect "a file with no signature is refused" 1 unsigned ad-hoc

    if [ "$failures" -ne 0 ]; then
        echo "check-macos-signatures: $failures self-test case(s) failed" >&2
        return 1
    fi
    echo "check-macos-signatures: the self-test passed"
}

if [ "${1:-}" = self-test ]; then
    self_test
    exit $?
fi
check "${1:?name the tree}" "${2:?name the mode: ad-hoc, developer-id or notarized}"
