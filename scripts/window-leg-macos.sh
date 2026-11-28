#!/usr/bin/env bash
# Opens windows and a tab of Terminal through the KalaReach terminal profile on a GitHub-hosted macOS
# runner, and holds each one to the host's session list.
#
#   scripts/window-leg-macos.sh <host release tag> <archive SHA-256, or empty> <pictures folder>
#
# The profile is written by the real `kr host terminal-profile install` into the real preferences of
# a real Terminal, from a published release that this script downloads, checks and installs in the
# account's own store, so the profile names `<store>/current/bin/kr` as a person's install does. The
# windows are opened through Terminal's Shell menu with System Events, which sends no Apple event to
# Terminal. The decision is the session list: after the first window exactly one live session with
# one attachment, after a tab exactly two with their own identifiers and the first still there, after
# a second window exactly three; a window of another profile adds none; the account's shell startup
# files and Terminal's two default-profile keys are as they were before the install, during the leg
# and after the removal. Every `check=<name> ok=<0|1>` line is one such decision.
#
# The windows run in two passes. The first uses the release's default store, whose path holds a
# space: the profile's command then names a program with a space in its path, Terminal splits it
# there, and the window starts no session. The first pass's decisions about sessions are therefore a
# named known red (`check=known-red-... finding=profile-command-split-at-space`): it does not fail
# the leg, and when it holds the log says that the finding is gone. The second pass uses a store
# whose path has no space and holds every decision. When a release carries the fix, the known red
# goes in the same change as the pinned tag.
#
# It shows one release's writers and its `kr new` on one image and one account. It does not show a
# person's own Mac, own profiles or own default. A last phase writes a broken command into the
# runner's own entry and holds the leg to seeing that no session starts; it does not show that a
# change in the product's source is caught.
#
# It writes the real preferences of the account it runs in, so it refuses to start anywhere but in
# a hosted runner's own account, before it does anything else. Exit status: 0 when every check held,
# 1 when one did not, 2 for a refusal or a usage fault.

# Every function below is called through `check` or `wait_for`, which shellcheck cannot follow.
# shellcheck disable=SC2329
set -uo pipefail

# guard begin
refuse() { printf 'window-leg-macos: %s\n' "$*" >&2; exit 2; }
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] \
    || [ "${RUNNER_OS:-}" != macOS ] || [ "$(uname -s)" != Darwin ] || [ "${KR_WINDOW_LEG:-}" != 1 ] \
    || [ "$(id -un)" != runner ] || [ "${HOME:-}" != /Users/runner ] \
    || ! [ -e /opt/hca/hosted-compute-agent ] || [ -n "${KR_TERMINAL_PREFERENCES_DIR+set}" ]; then
    refuse "this writes a real account's Terminal preferences and runs only in the account of a GitHub-hosted runner (GITHUB_ACTIONS, RUNNER_ENVIRONMENT, RUNNER_OS and KR_WINDOW_LEG set by the workflow, a Darwin system, the account runner, its home, the hosted agent's file, and KR_TERMINAL_PREFERENCES_DIR unset)"
fi
# guard end

tag="${1:-}"
pinned="${2:-}"
pictures="${3:-}"
[ -n "$tag" ] && [ -n "$pictures" ] || refuse "usage: window-leg-macos.sh <host release tag> <archive SHA-256, or empty> <pictures folder>"
case "$(uname -m)" in
    arm64) target=aarch64-apple-darwin ;;
    x86_64) target=x86_64-apple-darwin ;;
    *) refuse "no release archive for $(uname -m)" ;;
esac
command -v jq > /dev/null || refuse "jq is needed to read the session list"
release="${tag#host/v}"
deadline="${KR_WINDOW_DEADLINE:-240}"
failed=0
work="$(mktemp -d "${RUNNER_TEMP:?}/window-leg.XXXXXX")"
mkdir -p "$pictures"
say() { printf 'window-leg-macos: %s\n' "$*"; }

# One decision of the leg, as a line the run's log is read by.
check() {
    local name=$1
    shift
    if "$@"; then echo "check=$name ok=1"; else echo "check=$name ok=0"; failed=1; return 1; fi
}

# A decision that a named, known fault of the release decides. It prints under a name of its own, with
# the finding, and does not fail the leg; it waits only `known_deadline` seconds, since it is expected
# not to hold. When it does hold, the finding is gone and its mark can be removed.
finding=profile-command-split-at-space
known_deadline="${KR_WINDOW_KNOWN_DEADLINE:-30}"
known_reds=0
known_red() {
    local name=$1 saved=$deadline
    shift
    deadline=$known_deadline
    if "$@"; then
        echo "check=known-red-$name ok=1 finding=$finding"
        say "the finding is gone: remove the known-red mark ($finding)"
    else
        echo "check=known-red-$name ok=0 finding=$finding"
        known_reds=$((known_reds + 1))
    fi
    deadline=$saved
}

# Runs `$@` once a second until it succeeds; gives up after the deadline and says what it waited for.
wait_for() {
    local what=$1 started=$SECONDS
    shift
    until "$@"; do
        if [ $((SECONDS - started)) -ge "$deadline" ]; then say "gave up after ${deadline}s waiting for $what"; return 1; fi
        sleep 1
    done
}

# One System Events statement against Terminal; 30 seconds at most, so a hung call is an error line.
ax() { /usr/bin/perl -e 'alarm 30; exec @ARGV' osascript -e "tell application \"System Events\" to tell process \"Terminal\" to $1" 2>&1; }
terminal_pid() { pgrep -x -u "$(id -u)" Terminal | head -1; }
windows() { ax 'count windows'; }
has_window() { [ "$(windows)" -ge 1 ] 2> /dev/null; }
windows_at_least() { [ "$(windows)" -ge "$1" ] 2> /dev/null; }
newest_login_has_a_child() { local p; p=$(pgrep -x -P "$(terminal_pid)" login | sort -n | tail -1); [ -n "$p" ] && pgrep -P "$p" > /dev/null; }
terminal_gone() { ! pgrep -x -u "$(id -u)" Terminal > /dev/null; }
# The application menu's last item keeps the windows for the next start, so every window is closed
# first: a window that came back would run its profile's command again.
quit_terminal() {
    ax 'click menu item "Close All" of menu 1 of menu bar item "Shell" of menu bar 1' > /dev/null
    ax 'click (last menu item of menu 1 of menu bar item 2 of menu bar 1)' > /dev/null
    wait_for "Terminal to end" terminal_gone
}
# Shell, then the submenu `$1` (New Window or New Tab), then the profile `$2`.
choose() {
    local out
    ax 'set frontmost to true' > /dev/null
    out=$(ax "click menu item \"$2\" of menu 1 of menu item \"$1\" of menu 1 of menu bar item \"Shell\" of menu bar 1") \
        || say "Shell, $1, $2 failed: $out"
}
shot() { screencapture -x "$pictures/$1.png" || say "no picture $1"; }

# The window's own temporary folder is the one a window's `kr new` makes its runtime root in.
window_tmp="$(getconf DARWIN_USER_TEMP_DIR)"
store="$HOME/Library/Application Support/KalaReach/host"
krc() { env -u KR_STATE_DIR -u KR_RUNTIME_DIR TMPDIR="$window_tmp" "$store/current/bin/kr" "$@"; }

# The shell startup files, each by presence and digest, and Terminal's two default-profile keys.
snapshot() {
    local f
    for f in .zshrc .zshenv .zprofile .zlogin .bashrc .bash_profile .bash_login .profile \
        .config/fish/conf.d/kalareach.fish .config/powershell/Microsoft.PowerShell_profile.ps1 .config/powershell/profile.ps1; do
        if [ -e "$HOME/$f" ]; then printf '%s %s\n' "$(shasum -a 256 < "$HOME/$f" | cut -d ' ' -f 1)" "$f"; else printf 'absent %s\n' "$f"; fi
    done
    printf 'default=%s\nstartup=%s\n' "$(defaults read com.apple.Terminal 'Default Window Settings' 2>&1)" "$(defaults read com.apple.Terminal 'Startup Window Settings' 2>&1)"
}
unchanged() { [ "$(snapshot)" = "$before" ]; }
entry() { defaults export com.apple.Terminal - | plutil -extract 'Window Settings.KalaReach' xml1 -o - - 2>&1; }

# The session list: how many sessions, how many of them live with one attachment, and their identifiers.
# A host with no daemon answers with an error and no list; that counts as no session, and says so.
listed() { krc list --json 2> /dev/null; }
session_count() { local out; if out=$(listed); then jq -r '.sessions | length' <<< "$out"; else echo 0; fi; }
sessions_are() {
    local out
    out=$(listed) || return 1
    [ "$(jq -r '.sessions | length' <<< "$out")" = "$1" ] \
        && [ "$(jq -r '[.sessions[] | select(.state == "live" and .attachments == 1)] | length' <<< "$out")" = "$1" ]
}
ids() { listed | jq -r '.sessions[].session_id' | sort; }
keeps_and_differs() { [ -z "$(comm -23 <(printf '%s\n' "$1") <(ids))" ] && [ "$(ids | uniq | wc -l | tr -d ' ')" = "$2" ]; }
closed() { [ "$(krc status "$1" --json 2> /dev/null | jq -r '.state')" = closed ]; }

# 1. The release: downloaded as a person downloads it, checked, unpacked and installed.
fetch_and_install() {
    local archive="kalareach-$target-$release.tar.gz" base out
    base="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:?}/releases/download/${tag//+/%2B}"
    curl -fL -o "$work/$archive" "$base/${archive//+/%2B}" && curl -fL -o "$work/SHA256SUMS" "$base/SHA256SUMS" || return 1
    if [ -n "$pinned" ]; then
        [ "$(shasum -a 256 "$work/$archive" | cut -d ' ' -f 1)" = "$pinned" ] || { say "the archive's digest is not the pinned $pinned"; return 1; }
    else
        say "no digest is pinned for $tag: the archive is checked against its release's SHA256SUMS only"
    fi
    out=$(cd "$work" && shasum -a 256 --ignore-missing -c SHA256SUMS) || return 1
    printf '%s\n' "$out"
    printf '%s\n' "$out" | grep -qxF "$archive: OK" || return 1
    tar -xzf "$work/$archive" -C "$work" && "$work/kalareach-$target-$release/bin/kr" host install
}
check release-installed fetch_and_install || { say "no release, nothing more to do"; exit 1; }
say "window's temporary folder: $window_tmp"

# 2. Terminal must have run once, or its preferences hold no profile to copy.
first_start_and_quit() { open -a Terminal && wait_for "a Terminal window" has_window && quit_terminal; }
check terminal-first-start-and-quit first_start_and_quit

# 3. The host: the standalone start, and its daemon started by a first session that is closed again,
# since `kr host shell-mode --set` needs a running daemon. The first session has no window, and a
# closed session is not in `kr list`, so the counts below do not see it. All of this comes before the
# baseline of the shell files.
first_session() {
    local out id
    out=$(krc new --invisible --shell-mode native_compat --json) || return 1
    id=$(jq -r '.session_id // empty' <<< "$out") || return 1
    [ -n "$id" ] || return 1
    krc close "$id" > /dev/null || return 1
    wait_for "the first session to close" closed "$id"
}
check startup-standalone krc host startup --set standalone || exit 1
check daemon-started-by-first-session first_session || { say "no daemon, nothing more to do"; exit 1; }
check no-session-after-first-session test "$(session_count)" = 0
say "the host's paths: $(krc host paths 2>&1 | tr '\n' ' ')"
before="$(snapshot)"
shot terminal-before-install
check shell-mode-native krc host shell-mode --set native_compat

# 4. One pass of the profile through the windows. `$1` names the pass in each check and picture, and
# `$2` is set where the pass's decisions about sessions are the known red. A pass ends with Terminal
# quit and the profile removed, so that the next one starts from the same state. The functions below
# read the pass's name from this function's own variable `p`.
entry_gone() { ! entry > /dev/null 2>&1; }
command_of() { defaults export com.apple.Terminal - | plutil -extract "Window Settings.KalaReach.$1" raw -o - - 2>&1; }
install_ok() { [ "$(krc host terminal-profile install apple-terminal --json | tee "$work/install-$p.json" | jq -r '.ok')" = true ]; }
status_matches() { [ "$(krc host terminal-profile status --json | jq -r '.terminals[] | select(.terminal == "apple-terminal") | .profile')" = matches ]; }
remove_ok() { krc host terminal-profile remove --json | jq -e '.ok == true and .profiles[0].result == "removed"' > /dev/null; }
session_check() { if [ -n "$known" ]; then known_red "$@"; else check "$@"; fi; }

windows_pass() {
    local p=$1 known=${2:-} count windows_before id
    check "$p-no-entry-before-install" entry_gone
    check "$p-profile-install" install_ok
    entry > "$work/entry-after-install-$p.xml"
    say "$p: the entry's command: $(command_of CommandString)"
    say "$p: the entry runs its command inside a shell: $(command_of RunCommandAsShell)"
    check "$p-profile-status-matches" status_matches
    check "$p-shell-files-after-install" unchanged

    # A window of Terminal's own startup profile, opened after the install: no session.
    open -a Terminal
    check "$p-startup-window" wait_for "the startup window" has_window
    check "$p-startup-window-shell" wait_for "the startup window's shell" newest_login_has_a_child
    check "$p-startup-window-zero-sessions" test "$(session_count)" = 0

    # A window, a window of another profile (which counts only its own window and adds no session),
    # a tab and a window of the profile.
    choose "New Window" KalaReach
    session_check "$p-window-one" wait_for "one live session with one attachment" sessions_are 1
    first="$(ids)"
    shot "$p-window-one"
    count="$(session_count)"
    windows_before="$(windows)"
    choose "New Window" Basic
    check "$p-other-profile-window" wait_for "the other profile's own window" windows_at_least $((windows_before + 1))
    check "$p-other-profile-window-shell" wait_for "that window's shell" newest_login_has_a_child
    check "$p-other-profile-adds-no-session" sessions_are "$count"
    choose "New Tab" KalaReach
    session_check "$p-tab-two" wait_for "two live sessions" sessions_are 2
    session_check "$p-tab-keeps-first-and-differs" keeps_and_differs "$first" 2
    second="$(ids)"
    choose "New Window" KalaReach
    session_check "$p-window-three" wait_for "three live sessions" sessions_are 3
    session_check "$p-window-three-keeps-and-differs" keeps_and_differs "$second" 3
    shot "$p-window-three"
    check "$p-shell-files-during-windows" unchanged

    # Close each session, quit Terminal, take the profile out.
    for id in $(ids); do
        krc close "$id" > /dev/null
        check "$p-closed-$id" wait_for "session $id to close" closed "$id"
    done
    check "$p-terminal-quit" quit_terminal
    entry > "$work/entry-after-quit-$p.xml"
    check "$p-entry-kept-through-the-pass" diff "$work/entry-after-install-$p.xml" "$work/entry-after-quit-$p.xml"
    check "$p-profile-remove" remove_ok
    check "$p-shell-files-and-defaults-after-remove" unchanged
}

# The first pass, in the release's default store. A path with a space is what the known red is about;
# without one, every decision of the pass holds as it does in the second.
known_pass=
case "$store" in *" "*) known_pass=1 ;; esac
say "first pass: the default store, $store"
windows_pass default-store "$known_pass"

# The second pass, in a store with no space in its path, installed from the same unpacked release.
plain="$work/store"
install_plain_store() { [ "${plain// }" = "$plain" ] && "$work/kalareach-$target-$release/bin/kr" host install --store "$plain"; }
check plain-store-installed install_plain_store || { say "no second store, nothing more to do"; exit 1; }
store="$plain"
say "second pass: a store with no space in its path, $store"
windows_pass plain-store

# 5. The runner's own entry broken on purpose: a window through it must start no session.
break_the_entry() {
    krc host terminal-profile install apple-terminal --json > /dev/null || return 1
    command_text="$(command_of CommandString)" || return 1
    [ "${command_text/ new / }" != "$command_text" ] || return 1
    defaults export com.apple.Terminal - | plutil -replace 'Window Settings.KalaReach.CommandString' -string "${command_text/ new / }" -o - - | defaults import com.apple.Terminal -
}
check mutant-entry-written break_the_entry
open -a Terminal
check mutant-startup-window wait_for "a Terminal window" has_window
windows_before="$(windows)"
choose "New Window" KalaReach
check mutant-window wait_for "the broken profile's window" windows_at_least $((windows_before + 1))
# A negative has no event to wait for: the window's command ends at once, so a session that was to
# start has had this long to appear.
sleep 20
shot mutant-window
check mutant-command-without-new-detected test "$(session_count)" = 0

say "done, $([ "$failed" -eq 0 ] && echo 'every check held' || echo 'a check failed'); known reds: $known_reds ($finding)"
exit "$failed"
