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

# How long a closed session may stay listed, and how long a daemon may take to stop. The self-test
# shortens both.
close_wait="${KR_START_CLOSE_SECONDS:-20}"
stop_wait="${KR_START_STOP_SECONDS:-10}"

# The process `kr new` names for the control daemon, whether it says it started it or says that the
# one it started did not answer (`crates/kr-cli/src/startup.rs`).
process_of() { sed -n 's/.*the control daemon.*(process \([0-9][0-9]*\)).*/\1/p' | head -1; }

self_test() {
    local work status=0 expected_exit
    work="$(mktemp -d "${TMPDIR:-/tmp}/kr-host-start-test.XXXXXX")"
    trap 'rm -rf "${work:?}"' RETURN
    # A stand-in for `kr` that answers as the real one does, as far as this script reads it. The text
    # it prints when the daemon does not answer is the real one.
    cat > "$work/kr" << 'KR'
#!/usr/bin/env bash
state="$KR_STAND_IN_STATE"
case "$1" in
    host) [ "$SCENARIO" = startup_fails ] && exit 3; exit 0 ;;
    shell) exit 0 ;;
    new)
        case "$SCENARIO" in
            no_pid) echo "session 1 created"; : > "$state/open"; exit 0 ;;
            stuck) bash -c "trap '' TERM; while :; do sleep 1; done" > /dev/null 2>&1 & ;;
            *) sleep 300 > /dev/null 2>&1 & ;;
        esac
        pid=$!
        echo "$pid" > "$state/pid"
        if [ "$SCENARIO" = new_fails ]; then
            echo "the control daemon this command started for environment test (process $pid) did not answer within 30 seconds: no answer; it is still running, and its log holds nothing since it started; what it writes is in $state/log"
            exit 7
        fi
        echo "started the control daemon for environment test (process $pid) under the standalone start"
        echo "session 1 created"; : > "$state/open"; exit 0 ;;
    list)
        [ "$SCENARIO" = list_fails ] && exit 9
        if [ -e "$state/open" ]; then echo "1 running"; else echo "no sessions"; fi ;;
    close) [ "$SCENARIO" = never_closes ] || rm -f "$state/open" ;;
    --version) echo "kr stand-in" ;;
esac
KR
    chmod +x "$work/kr"
    run_case() { # <scenario> <wanted exit: 0 or 1> <text the output must hold> <whether the daemon is gone afterwards: yes or no>
        local out rc=0 gone=yes exit_ok
        mkdir -p "$work/state" "$work/tmp"
        rm -f "$work/state/pid" "$work/state/open"
        out="$(SCENARIO="$1" KR_STAND_IN_STATE="$work/state" CI=true TMPDIR="$work/tmp" KR_START_CLOSE_SECONDS=2 KR_START_STOP_SECONDS=2 bash "${BASH_SOURCE[0]}" "$work/kr" 2>&1)" || rc=$?
        if [ -f "$work/state/pid" ] && kill -0 "$(cat "$work/state/pid")" 2> /dev/null; then
            gone=no
            kill -9 "$(cat "$work/state/pid")" 2> /dev/null || true
        fi
        expected_exit="$2"
        exit_ok=no
        if [ "$expected_exit" = 0 ] && [ "$rc" -eq 0 ]; then exit_ok=yes; fi
        if [ "$expected_exit" = 1 ] && [ "$rc" -ne 0 ]; then exit_ok=yes; fi
        if [ "$exit_ok" = yes ] && grep -q -F -- "$3" <<< "$out" && [ "$gone" = "$4" ]; then
            echo "self-test ok: $5"
        else
            echo "self-test FAILED: $5 (exit $rc, daemon gone: $gone)"
            printf '%s\n' "$out" | sed 's/^/    /'
            status=1
        fi
        rm -rf "${work:?}/tmp" "${work:?}/state"
    }
    run_case ok 0 "and the session closed" yes "a host that starts, lists a session and closes it passes, and its daemon is stopped"
    run_case new_fails 1 "kr new failed" yes "a kr new that fails with the real text names its daemon, fails, and the daemon is stopped"
    run_case no_pid 1 "did not say which process" yes "a kr new that names no process fails"
    run_case list_fails 1 "kr list failed" yes "a kr list that fails is named as that"
    run_case never_closes 1 "still listed" yes "a session that stays listed after it is closed fails"
    run_case startup_fails 1 "" yes "a startup step that fails fails the check"
    run_case stuck 1 "is still running" no "a daemon that ignores the stop is named and its directories stay"
    [ "$status" -eq 0 ] && echo "check-host-start: the self-test passed"
    return "$status"
}

if [ "${1:-}" = self-test ]; then
    self_test
    exit
fi


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
    # is still alive after the wait fails the check, and the directories it uses stay where they
    # are, since removing them under a running daemon proves nothing.
    if [ -n "$daemon" ]; then
        kill "$daemon" 2> /dev/null || true
        for ((waited = 0; waited < stop_wait; waited++)); do kill -0 "$daemon" 2> /dev/null || break; sleep 1; done
        if kill -0 "$daemon" 2> /dev/null; then
            echo "check-host-start: the control daemon (process $daemon) is still running $stop_wait seconds after it was asked to stop; $work stays" >&2
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
    daemon="$(printf '%s\n' "$created" | process_of)"
    echo "check-host-start: kr new failed" >&2
    failed=1
    exit 1
fi
printf '%s\n' "$created"
daemon="$(printf '%s\n' "$created" | process_of)"
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
list_failed=no
for ((waited = 0; waited < close_wait; waited++)); do
    if listed="$("$kr" list)"; then
        list_failed=no
        case "$listed" in *"no sessions"*) closed=yes; break ;; esac
    else
        list_failed=yes
    fi
    sleep 1
done
if [ "$closed" != yes ]; then
    if [ "$list_failed" = yes ]; then
        echo "check-host-start: kr list failed while the session was being closed, so its closing was not seen" >&2
    else
        echo "check-host-start: the session was still listed $close_wait seconds after it was closed" >&2
    fi
    failed=1
    exit 1
fi
echo "check-host-start: the control daemon, a worker and a shell of $("$kr" --version) started, and the session closed"
