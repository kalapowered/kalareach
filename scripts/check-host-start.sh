#!/usr/bin/env bash
# Starts the host of an installed release and has it create and close a session.
#
#   scripts/check-host-start.sh <kr program of the installed release>
#
# `kr host install` copies and admits a release, and `kr --version` reads nothing of the host, so
# neither shows that the control daemon, a worker and a shell of the release start. This does: it
# chooses the standalone start, installs the shells' startup entries, creates a session with no
# terminal attached (`kr new --invisible --headless`), lists it, and closes it. It then stops the
# control daemon that `kr new` started, removes the startup entries it installed, and removes the
# state and runtime directories made for the run, and on Linux the home directory too, so a person's
# own host is never read or written. It runs only on a throwaway machine (a CI runner, which sets CI,
# or a guest, with KR_THROWAWAY_HOST=1): a started host keeps its device keys in the machine's key
# store, which on macOS is the login keychain of the account that runs it, and on macOS the startup
# entries go into that account's shell startup files.

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
    mkdir -m 700 "$work/home/.config"
    export HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config"
fi
daemon=""
failed=0
cleanup() {
    local status=$?
    "$kr" close 1 > /dev/null 2>&1 || true
    # The daemon is the process `kr new` reported starting; nothing else is ended. A process that
    # is still alive after ten seconds fails the check, and the directories it uses stay where they
    # are, since removing them under a running daemon proves nothing.
    if [ -n "$daemon" ]; then
        kill "$daemon" 2> /dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$daemon" 2> /dev/null || break; sleep 1; done
        if kill -0 "$daemon" 2> /dev/null; then
            echo "check-host-start: the control daemon (process $daemon) is still running ten seconds after it was asked to stop; $work stays" >&2
            exit 1
        fi
    fi
    "$kr" shell remove > /dev/null 2>&1 || true
    chmod -R u+w "${work:?}" 2> /dev/null || true
    rm -rf "${work:?}"
    # A step that ended the script under `set -e` keeps its own status.
    if [ "$failed" -ne 0 ]; then exit 1; fi
    exit "$status"
}
trap cleanup EXIT

"$kr" host startup --set standalone
"$kr" shell install
if ! created="$("$kr" new --invisible --headless 2>&1)"; then
    printf '%s\n' "$created"
    daemon="$(printf '%s\n' "$created" | sed -n 's/.*started the control daemon.*(process \([0-9][0-9]*\)).*/\1/p' | head -1)"
    echo "check-host-start: kr new failed" >&2
    failed=1
    exit 1
fi
printf '%s\n' "$created"
daemon="$(printf '%s\n' "$created" | sed -n 's/.*started the control daemon.*(process \([0-9][0-9]*\)).*/\1/p' | head -1)"
if [ -z "$daemon" ]; then
    echo "check-host-start: kr new did not say which process it started as the control daemon, so its stop cannot be shown" >&2
    failed=1
    exit 1
fi
if ! listed="$("$kr" list)"; then
    echo "check-host-start: kr list failed" >&2
    failed=1
    exit 1
fi
printf '%s\n' "$listed"
case "$listed" in
    *"no sessions"* | "") echo "check-host-start: the host lists no session after it created one" >&2; failed=1; exit 1 ;;
esac
"$kr" close 1
# A close is asked for and takes a moment: the daemon is stopped once no session is left.
closed=no
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if listed="$("$kr" list)" && case "$listed" in *"no sessions"*) true ;; *) false ;; esac; then
        closed=yes
        break
    fi
    sleep 1
done
if [ "$closed" != yes ]; then
    echo "check-host-start: the session was still listed twenty seconds after it was closed" >&2
    failed=1
    exit 1
fi
echo "check-host-start: the control daemon, a worker and a shell of $("$kr" --version) started, and the session closed"
