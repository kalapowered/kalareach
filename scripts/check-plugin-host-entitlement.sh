#!/usr/bin/env bash
# Shows that the entitlement the plugin host is signed with is the one thing standing between it and
# the hardened runtime, on the machine that runs it.
#
#   scripts/check-plugin-host-entitlement.sh <program> [<argument>...]
#
# <program> is a Mach-O program that compiles and runs a WebAssembly component the way the plugin
# host does (Wasmtime writes machine code into memory and then makes it executable), such as the
# test executable of `kr-plugin-runtime`'s `execution` suite with a case's name as its argument. The
# command is run three times, each on a copy of the program signed ad hoc:
#
#   1. without the hardened runtime: it has to succeed, which shows the command itself is sound;
#   2. with the hardened runtime and no entitlement: it has to fail, which shows the hardened
#      runtime ends a process that makes code at run time, so the entitlement is needed;
#   3. with the hardened runtime and the plugin host's one entitlement
#      (`scripts/macos-entitlements/kr-plugin-host.plist`): it has to succeed.
#
# The program's own signature is not touched. An ad hoc signature can carry the hardened runtime
# (`--code-signature-flags runtime`); it has no team, which the plugin host does not need, because it
# loads no module of another program.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
program="${1:?name the program}"
shift

if [ "$(uname -s)" != Darwin ]; then
    echo "check-plugin-host-entitlement: the hardened runtime is macOS's" >&2
    exit 1
fi

rcodesign="${KR_RCODESIGN:-$(bash "$here/install-rcodesign.sh")}"
work="$(mktemp -d "${TMPDIR:-/tmp}/kr-entitlement.XXXXXX")"
trap 'rm -rf "${work:?}"' EXIT

signed_copy() { # <name> <signing options...>
    local name="$1"
    shift
    cp "$program" "$work/$name"
    "$rcodesign" sign --binary-identifier "$name" "$@" "$work/$name" > /dev/null 2>&1
    echo "$work/$name"
}

attempt() { # <label> <program path>
    local label="$1" path="$2" rc=0
    "$path" "${args[@]}" > "$work/$label.log" 2>&1 || rc=$?
    echo "$rc"
}

args=("$@")
failed=0

plain="$(signed_copy plain)"
rc="$(attempt "without the hardened runtime" "$plain")"
if [ "$rc" -eq 0 ]; then
    echo "check-plugin-host-entitlement: ok: without the hardened runtime the command succeeds"
else
    echo "check-plugin-host-entitlement: the command fails (exit $rc) without the hardened runtime, so it shows nothing about the entitlement:" >&2
    tail -n 20 "$work/without the hardened runtime.log" >&2
    exit 1
fi

hardened="$(signed_copy hardened --code-signature-flags runtime)"
rc="$(attempt "with the hardened runtime and no entitlement" "$hardened")"
if [ "$rc" -ne 0 ]; then
    echo "check-plugin-host-entitlement: ok: with the hardened runtime and no entitlement the command is ended (exit $rc)"
else
    echo "check-plugin-host-entitlement: the command succeeds under the hardened runtime without the entitlement, so the entitlement is not what it needs" >&2
    failed=1
fi

entitled="$(signed_copy entitled --code-signature-flags runtime --entitlements-xml-file "$here/macos-entitlements/kr-plugin-host.plist")"
rc="$(attempt "with the hardened runtime and the entitlement" "$entitled")"
if [ "$rc" -eq 0 ]; then
    echo "check-plugin-host-entitlement: ok: with the hardened runtime and the entitlement the command succeeds"
else
    echo "check-plugin-host-entitlement: the command fails (exit $rc) under the hardened runtime with the entitlement:" >&2
    tail -n 20 "$work/with the hardened runtime and the entitlement.log" >&2
    failed=1
fi
exit "$failed"
