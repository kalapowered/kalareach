#!/usr/bin/env bash
# Starts the host of an installed release and has it create and close a session.
#
#   scripts/check-host-start.sh <kr program of the installed release>
#
# `kr host install` copies and admits a release, and `kr --version` reads nothing of the host, so
# neither shows that the control daemon, a worker and a shell of the release start. This does: it
# chooses the standalone start, installs the shells' startup entries, creates a session with no
# terminal attached (`kr new --invisible --headless`), lists it, and closes it. The state and runtime
# directories are made for the run and removed at its end, and on Linux so is the home directory, so a
# person's own host is never read or written. It runs only on a throwaway machine (a CI runner, which
# sets CI, or a guest, with KR_THROWAWAY_HOST=1): a started host keeps its device keys in the machine's
# key store, which on macOS is the login keychain of the account that runs it, and `kr shell install`
# edits that account's shell startup files on macOS.

set -euo pipefail

kr="${1:?name the kr program of the installed release}"
if [ "${CI:-}" != true ] && [ "${KR_THROWAWAY_HOST:-}" != 1 ]; then
    echo "check-host-start: this starts a host and keeps its keys in the machine's key store; run it on a throwaway machine (CI=true or KR_THROWAWAY_HOST=1)" >&2
    exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/kr-host-start.XXXXXX")"
chmod 700 "$work"
mkdir -m 700 "$work/home" "$work/state" "$work/run"
export KR_STATE_DIR="$work/state" KR_RUNTIME_DIR="$work/run"
if [ "$(uname -s)" = Linux ]; then
    export HOME="$work/home"
fi
cleanup() {
    "$kr" close 1 > /dev/null 2>&1 || true
    chmod -R u+w "${work:?}" 2> /dev/null || true
    rm -rf "${work:?}"
}
trap cleanup EXIT

"$kr" host startup --set standalone
"$kr" shell install
"$kr" new --invisible --headless
listed="$("$kr" list)"
printf '%s\n' "$listed"
case "$listed" in
    *"no sessions"* | "") echo "check-host-start: the host lists no session after it created one" >&2; exit 1 ;;
esac
"$kr" close 1
echo "check-host-start: the control daemon, a worker and a shell of $("$kr" --version) started, and the session closed"
