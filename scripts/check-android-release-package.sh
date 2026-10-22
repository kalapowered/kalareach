#!/usr/bin/env bash
#
# Checks what a packaged Android release build carries that its verified TLS needs.
#
#   scripts/check-android-release-package.sh <package.apk>
#
# A release build allows no cleartext traffic, and Android's revocation check in the platform
# verifier's Kotlin half fetches the revocation lists certificate authorities publish over plain
# HTTP (Let's Encrypt, Google Trust Services and SSL.com have all dropped OCSP, and Cloudflare serves
# certificates from each of them). Where that fetch is refused, the verifier reports the
# certificate as revoked and the application reaches no service whose certificate comes from such
# an authority. The verifier's Kotlin half therefore brings a network security configuration that
# permits cleartext traffic to those authorities' revocation-list hosts and to nothing else. This
# checks that the package names that configuration, that the configuration keeps cleartext off
# elsewhere, and that it lists the hosts of the authorities the deployed service's certificates
# come from.
#
# Exit codes: 0 the package carries it, 2 it does not or cannot be read, 3 there are no build tools.
set -uo pipefail

apk="${1:-}"
[ -f "$apk" ] || { printf 'usage: %s <package.apk>\n' "$0" >&2; exit 2; }
sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
aapt2="$(ls -d "$sdk"/build-tools/*/aapt2 2>/dev/null | sort -V | tail -1)"
[ -n "$aapt2" ] || { echo "no aapt2 under $sdk/build-tools" >&2; exit 3; }

fail=0
say() { printf '== [release-package] %s\n' "$*"; }

manifest="$("$aapt2" dump xmltree "$apk" --file AndroidManifest.xml 2>&1)"
if printf '%s' "$manifest" | grep -q 'networkSecurityConfig'; then
    say "the manifest names a network security configuration"
else
    say "the manifest names no network security configuration"
    fail=1
fi

# The configuration's path inside the package is resource-table-defined; the build tool names it.
# A minified release build renames its resource files, so the file is the one the resource table gives
# the configuration's name.
config="$("$aapt2" dump resources "$apk" 2>/dev/null | grep -A2 -E 'resource 0x[0-9a-f]+ xml/network_security_config' | grep -o 'res/[^ ]*\.xml' | head -1)"
if [ -z "$config" ]; then
    say "the package holds no network security configuration"
    exit 2
fi
tree="$("$aapt2" dump xmltree "$apk" --file "$config" 2>&1)"
if printf '%s\n' "$tree" | awk '/E: base-config/ {found=1; next} found {print; exit}' | grep -q 'cleartextTrafficPermitted=false'; then
    say "cleartext traffic is off by default"
else
    say "the configuration does not turn cleartext traffic off by default"
    fail=1
fi
# Only the authorities' revocation-list hosts are permitted, and none of this project's own.
if printf '%s' "$tree" | grep -q -F 'kala.to'; then
    say "the configuration permits cleartext traffic to a host of this project"
    fail=1
else
    say "the configuration permits cleartext traffic to no host of this project"
fi
for host in c.pki.goog c.lencr.org; do
    if printf '%s' "$tree" | grep -q -F "$host"; then
        say "cleartext is permitted for $host"
    else
        say "cleartext is not permitted for $host"
        fail=1
    fi
done
exit "$fail"
