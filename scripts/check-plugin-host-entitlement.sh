#!/usr/bin/env bash
# Shows that the entitlement the plugin host is signed with is the one thing standing between it and
# the hardened runtime, on the machine that runs it.
#
#   scripts/check-plugin-host-entitlement.sh [--host <kr-plugin-host>] <program> [<argument>...]
#   scripts/check-plugin-host-entitlement.sh --probe
#
# With --probe only the probe below is run, and the exit status says what it found: 0 when this machine
# enforces the hardened runtime, 10 when it does not. A workflow runs it first so as not to build what
# it cannot use.
#
# <program> is a Mach-O program that compiles and runs a WebAssembly component the way the plugin
# host does (Wasmtime writes machine code into memory and then makes it executable), such as the
# test executable of `kr-plugin-runtime`'s `execution` suite with a case's name as its argument. The
# command is run three times, each on a copy of the program signed ad hoc. With --host, <program>
# is instead a test that starts the plugin host, such as the `service` suite of `kr-plugin-host`, and
# it is the plugin host that is signed: the file --host names is signed in place for each run and the
# file it had is put back at the end.
#
#   1. without the hardened runtime: it has to succeed, which shows the command itself is sound;
#   2. with the hardened runtime and no entitlement: it has to fail, which shows the hardened
#      runtime ends a process that makes code at run time, so the entitlement is needed;
#   3. with the hardened runtime and the plugin host's one entitlement
#      (`scripts/macos-entitlements/kr-plugin-host.plist`): it has to succeed.
#
# First a probe: a small program that writes machine code into memory, makes it executable and runs
# it, signed ad hoc with the hardened runtime and no entitlement. On a Mac that enforces the hardened
# runtime it is ended. A hosted build machine can be a virtual machine that does not enforce it (the
# probe then runs to the end), and nothing is shown there: the script says so and succeeds, rather
# than fail on a machine that cannot tell the two signatures apart.
#
# The program's own signature is not touched. An ad hoc signature can carry the hardened runtime
# (`--code-signature-flags runtime`); it has no team, which the plugin host does not need, because it
# loads no module of another program.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
host=""
probe_only=0
if [ "${1:-}" = --probe ]; then
    probe_only=1
    set -- probe
elif [ "${1:-}" = --host ]; then
    host="${2:?--host needs the plugin host}"
    shift 2
fi
program="${1:?name the program}"
shift

if [ "$(uname -s)" != Darwin ]; then
    echo "check-plugin-host-entitlement: the hardened runtime is macOS's" >&2
    exit 1
fi

rcodesign="${KR_RCODESIGN:-$(bash "$here/install-rcodesign.sh")}"
work="$(mktemp -d "${TMPDIR:-/tmp}/kr-entitlement.XXXXXX")"
trap 'rm -rf "${work:?}"' EXIT

if [ -n "$host" ]; then
    cp -p "$host" "$work/host.original"
    trap 'cp -p "$work/host.original" "$host" && rm -rf "${work:?}"' EXIT
fi

# The program to run, signed ad hoc with the options given; with --host, the plugin host is signed in
# place and the program is run as it is.
# It sets $signed to the file to run, and is called as a command and not in a substitution, which
# would hide a failure of the copy or of the signature.
signed_copy() { # <name> <signing options...>
    local name="$1"
    shift
    if [ -n "$host" ]; then
        cp -p "$work/host.original" "$host"
        "$rcodesign" sign --binary-identifier kr-plugin-host "$@" "$host" > /dev/null 2>&1
        signed="$program"
        return 0
    fi
    cp "$program" "$work/$name"
    "$rcodesign" sign --binary-identifier "$name" "$@" "$work/$name" > /dev/null 2>&1
    signed="$work/$name"
}

attempt() { # <label> <program path>
    local label="$1" path="$2" rc=0
    "$path" "${args[@]}" > "$work/$label.log" 2>&1 || rc=$?
    echo "$rc"
}

args=("$@")
failed=0

# The probe: arm64 `mov w0, #42; ret`, or x86-64 `mov eax, 42; ret`, written into a page that was
# read-write, made read-execute, and called.
cat > "$work/probe.c" << 'PROBE'
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
int main(void) {
#if defined(__aarch64__)
    static const uint8_t code[] = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
#else
    static const uint8_t code[] = {0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
#endif
    void *page = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (page == MAP_FAILED) return 2;
    memcpy(page, code, sizeof code);
    if (mprotect(page, 16384, PROT_READ | PROT_EXEC) != 0) return 3;
    return ((int (*)(void))page)() == 42 ? 0 : 4;
}
PROBE
/usr/bin/clang -o "$work/probe" "$work/probe.c"
"$rcodesign" sign --binary-identifier probe --code-signature-flags runtime "$work/probe" > /dev/null 2>&1
probe_flags="$(/usr/bin/codesign -d --verbose=2 "$work/probe" 2>&1 || true)"
case "$probe_flags" in
    *"flags="*runtime*) ;;
    *) echo "check-plugin-host-entitlement: the probe does not carry the hardened runtime, so it shows nothing" >&2; exit 1 ;;
esac
if { "$work/probe" > /dev/null 2>&1; } 2> /dev/null; then
    message="this machine does not enforce the hardened runtime on code made at run time (a program signed with it and no entitlement runs one), so nothing is shown here; the check is made on a Mac that enforces it"
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::warning::check-plugin-host-entitlement: $message"
    else
        echo "check-plugin-host-entitlement: $message"
    fi
    [ "$probe_only" -eq 0 ] || exit 10
    exit 0
fi
echo "check-plugin-host-entitlement: ok: this machine enforces the hardened runtime on code made at run time"
[ "$probe_only" -eq 0 ] || exit 0

signed_copy plain
plain="$signed"
rc="$(attempt "without the hardened runtime" "$plain")"
if [ "$rc" -eq 0 ]; then
    echo "check-plugin-host-entitlement: ok: without the hardened runtime the command succeeds"
else
    echo "check-plugin-host-entitlement: the command fails (exit $rc) without the hardened runtime, so it shows nothing about the entitlement:" >&2
    tail -n 20 "$work/without the hardened runtime.log" >&2
    exit 1
fi

signed_copy hardened --code-signature-flags runtime
hardened="$signed"
rc="$(attempt "with the hardened runtime and no entitlement" "$hardened")"
if [ "$rc" -ne 0 ]; then
    echo "check-plugin-host-entitlement: ok: with the hardened runtime and no entitlement the command is ended (exit $rc)"
else
    echo "check-plugin-host-entitlement: the command succeeds under the hardened runtime without the entitlement, so the entitlement is not what it needs" >&2
    failed=1
fi

signed_copy entitled --code-signature-flags runtime --entitlements-xml-file "$here/macos-entitlements/kr-plugin-host.plist"
entitled="$signed"
rc="$(attempt "with the hardened runtime and the entitlement" "$entitled")"
if [ "$rc" -eq 0 ]; then
    echo "check-plugin-host-entitlement: ok: with the hardened runtime and the entitlement the command succeeds"
else
    echo "check-plugin-host-entitlement: the command fails (exit $rc) under the hardened runtime with the entitlement:" >&2
    tail -n 20 "$work/with the hardened runtime and the entitlement.log" >&2
    failed=1
fi
exit "$failed"
