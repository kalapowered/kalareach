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
# Terminal. Each menu click must succeed. The decisions are the session list: after the first window
# exactly one live session with one attachment, after a tab exactly two with their own identifiers
# and the first still there, after a second window exactly three; a window of another profile, with
# a shell of its own, adds none; and the application's windows, counted after each action: one more
# after a window, none more after a tab. A session list that does not answer fails the check that
# reads it. The account's shell startup files, Terminal's two default-profile keys and every profile
# other than ours are as they were before the install, after each launch, during the leg and after
# the removal. Every `check=<name> ok=<0|1>` line is one such decision, and each line
# `<name>: windows=<n> sessions=<list>` prints what the decisions beside it read.
#
# The windows run in two passes. The first uses the release's default store, whose path holds a
# space: the profile's command then names a program with a space in its path, Terminal splits it
# there, and the window starts no session. For the release in which that was found, the first pass's
# decisions about sessions are therefore a named known red (`check=known-red-...
# finding=profile-command-split-at-space`, also a warning): it does not fail the leg, and when it
# holds the log says that the finding is gone. Menu clicks, window counts, session-list answers and
# the baselines are gates in that pass too, and any other release runs the whole pass as gates. The
# second pass uses a store whose path has no space and holds every decision. When a release carries
# the fix, the known red goes in the same change as the pinned tag.
#
# It shows one release's writers and its `kr new` on one image and one account. It does not show a
# person's own Mac, own profiles or own default. A last phase writes a broken command into the
# runner's own entry and holds the leg to seeing that no session starts; it does not show that a
# change in the product's source is caught.
#
# It writes the real preferences of the account it runs in, so before it does anything else it
# refuses to start unless the environment is that of a hosted runner's own account. Nine conditions
# decide that (below). They are values and files that a caller could reproduce on another machine, so
# they keep out an ordinary local or self-hosted invocation, not a deliberate one. Exit status: 0
# when every check held, 1 when one did not, 2 for a refusal or a usage fault.

# Every function below is called through `check` or `wait_for`, which shellcheck cannot follow.
# shellcheck disable=SC2329
set -uo pipefail

# guard begin
refuse() { printf 'window-leg-macos: %s\n' "$*" >&2; exit 2; }
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] \
    || [ "${RUNNER_OS:-}" != macOS ] || [ "$(uname -s)" != Darwin ] || [ "${KR_WINDOW_LEG:-}" != 1 ] \
    || [ "$(id -un)" != runner ] || [ "${HOME:-}" != /Users/runner ] \
    || ! [ -e /opt/hca/hosted-compute-agent ] || [ -n "${KR_TERMINAL_PREFERENCES_DIR+set}" ]; then
    refuse "this writes a real account's Terminal preferences and runs only where the environment is that of a GitHub-hosted runner's account (GITHUB_ACTIONS, RUNNER_ENVIRONMENT, RUNNER_OS and KR_WINDOW_LEG set by the workflow, a Darwin system, the account runner, its home, the hosted agent's file, and KR_TERMINAL_PREFERENCES_DIR unset)"
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
# helpers begin
# The definitions below run in scripts/window-leg-flow-test.sh in a stand-in world: they only define
# functions and set the variables the checks read, and call nothing until a check runs them.
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
finding_tag=host/v0.1.0+7c68ef8cf3c0
known_deadline="${KR_WINDOW_KNOWN_DEADLINE:-30}"
known_reds=0
# The finding is the one of the release `finding_tag`, and shows only in a store whose path has a
# space. Any other release, or a store without a space, runs every decision as a gate.
finding_holds_for() { [ "${1// }" != "$1" ] && [ "$2" = "$finding_tag" ]; }
known_red() {
    local name=$1 saved=$deadline
    shift
    deadline=$known_deadline
    if "$@"; then
        echo "check=known-red-$name ok=1 finding=$finding"
        echo "::warning::the finding is gone: remove the known-red mark ($finding, $name)"
    else
        echo "check=known-red-$name ok=0 finding=$finding"
        echo "::warning::known red $name ($finding)"
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
# Terminal's window count. An answer that is not a number is a failure, never a count.
windows() { local n; n=$(ax 'count windows') && [[ $n =~ ^[0-9]+$ ]] && printf '%s\n' "$n"; }
has_window() { [ "$(windows)" -ge 1 ] 2> /dev/null; }
windows_are() { [ "$(windows)" = "$1" ]; }
# The process numbers of Terminal's `login` children (one for each window's or tab's shell), as sorted text.
login_pids() { local t; t=$(terminal_pid); [ -n "$t" ] && pgrep -x -P "$t" login | sort; }
# A login that is not in `$1` (an earlier `login_pids`) and has a child: the shell of the window just opened.
new_login_has_a_child() {
    local p
    for p in $(comm -13 <(printf '%s\n' "$1") <(login_pids)); do
        pgrep -P "$p" > /dev/null && return 0
    done
    return 1
}
# A decision that something did NOT happen has no event to wait for: it reads after this many seconds
# of quiet, counted from the moment the window's own shell is there.
quiet="${KR_WINDOW_QUIET:-10}"
quiet_wait() { sleep "$quiet"; }
terminal_gone() { ! pgrep -x -u "$(id -u)" Terminal > /dev/null; }
# Every window is closed first, and Quit is chosen by its name: a window that came back at the next
# start would run its profile's command again.
quit_terminal() {
    ax 'click menu item "Close All" of menu 1 of menu bar item "Shell" of menu bar 1' > /dev/null
    ax 'click menu item "Quit Terminal" of menu 1 of menu bar item 2 of menu bar 1' > /dev/null
    wait_for "Terminal to end" terminal_gone
}
# Shell, then the submenu `$1` (New Window or New Tab), then the profile `$2`. A click that fails is a
# failure of its caller's check, with what System Events said.
choose() {
    local out
    out=$(ax 'set frontmost to true') || { say "Terminal could not be brought to the front: $out"; return 1; }
    out=$(ax "click menu item \"$2\" of menu 1 of menu item \"$1\" of menu 1 of menu bar item \"Shell\" of menu bar 1") \
        || { say "Shell, $1, $2 failed: $out"; return 1; }
}
shot() { screencapture -x "$pictures/$1.png" || say "no picture $1"; }
# helpers end

# The window's own temporary folder is the one a window's `kr new` makes its runtime root in.
window_tmp="$(getconf DARWIN_USER_TEMP_DIR)"
store="$HOME/Library/Application Support/KalaReach/host"
# helpers begin
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
# Terminal's profiles other than ours, by name with their whole values: the `Window Settings` of its
# preferences without the KalaReach entry. A difference from the baseline is printed.
profiles() {
    local f="$work/profiles.plist"
    defaults export com.apple.Terminal "$f" || return 1
    if plutil -extract 'Window Settings.KalaReach' xml1 -o - "$f" > /dev/null 2>&1; then
        plutil -remove 'Window Settings.KalaReach' "$f" || return 1
    fi
    plutil -extract 'Window Settings' xml1 -o - "$f"
}
profiles_unchanged() {
    local now
    now=$(profiles) || return 1
    [ "$now" = "$before_profiles" ] && return 0
    say "the other profiles differ from the baseline:"
    diff <(printf '%s\n' "$before_profiles") <(printf '%s\n' "$now")
    return 1
}

# The session list. Only an answer that succeeds and holds a `sessions` array counts. One that does not
# fails the check that reads it, with what `kr` said: a count of zero is never made up from an error.
listed() {
    local out
    if ! out=$(krc list --json 2> "$work/list-error.txt"); then
        say "kr list failed: $(cat "$work/list-error.txt")" >&2
        return 1
    fi
    jq -e '.sessions | type == "array"' <<< "$out" > /dev/null 2>&1 || { say "kr list gave no session list: $out" >&2; return 1; }
    printf '%s\n' "$out"
}
daemon_answers() { listed > /dev/null; }
session_count() { local out; out=$(listed) || return 1; jq -r '.sessions | length' <<< "$out"; }
sessions_are() {
    local out
    out=$(listed) || return 1
    [ "$(jq -r '.sessions | length' <<< "$out")" = "$1" ] \
        && [ "$(jq -r '[.sessions[] | select(.state == "live" and .attachments == 1)] | length' <<< "$out")" = "$1" ]
}
ids() { local out; out=$(listed) || return 1; jq -r '.sessions[].session_id' <<< "$out" | sort; }
keeps_and_differs() {
    local now
    now=$(ids) || return 1
    [ -z "$(comm -23 <(printf '%s\n' "$1") <(printf '%s\n' "$now"))" ] && [ "$(printf '%s\n' "$now" | uniq | wc -l | tr -d ' ')" = "$2" ]
}
closed() { [ "$(krc status "$1" --json 2> /dev/null | jq -r '.state')" = closed ]; }
# The application's windows and the validated session list, printed beside the decisions they go with.
observe() {
    local w s
    w=$(windows) || w=unreadable
    s=$(listed) && s=$(jq -c '[.sessions[] | {id: .session_id, state: .state, attachments: .attachments}]' <<< "$s") || s=unreadable
    say "$1: windows=$w sessions=$s"
}
# helpers end

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
check no-session-after-first-session sessions_are 0
say "the host's paths: $(krc host paths 2>&1 | tr '\n' ' ')"
before="$(snapshot)"
before_profiles="$(profiles)"
check profiles-baseline-read test -n "$before_profiles"
shot terminal-before-install
check shell-mode-native krc host shell-mode --set native_compat

# 4. One pass of the profile through the windows. `$1` names the pass in each check and picture, and
# `$2` is set where the pass's decisions about sessions are the known red. A pass ends with Terminal
# quit and the profile removed, so that the next one starts from the same state. The functions below
# read the pass's name from this function's own variable `p`.
#
# Only the decisions about sessions can be the known red. Each menu click, each count of Terminal's
# windows, each answer of the session list and each comparison with the baseline is a gate in both passes.
# helpers begin
entry_gone() { ! entry > /dev/null 2>&1; }
command_of() { defaults export com.apple.Terminal - | plutil -extract "Window Settings.KalaReach.$1" raw -o - - 2>&1; }
install_ok() { [ "$(krc host terminal-profile install apple-terminal --json | tee "$work/install-$p.json" | jq -r '.ok')" = true ]; }
status_matches() { [ "$(krc host terminal-profile status --json | jq -r '.terminals[] | select(.terminal == "apple-terminal") | .profile')" = matches ]; }
remove_ok() { krc host terminal-profile remove --json | jq -e '.ok == true and .profiles[0].result == "removed"' > /dev/null; }
session_check() { if [ -n "$known" ]; then known_red "$@"; else check "$@"; fi; }

windows_pass() {
    local p=$1 known=${2:-} count first second final id logins_before windows_before
    check "$p-no-entry-before-install" entry_gone
    check "$p-profile-install" install_ok
    entry > "$work/entry-after-install-$p.xml"
    say "$p: the entry's command: $(command_of CommandString)"
    say "$p: the entry's RunCommandAsShell=$(command_of RunCommandAsShell)"
    check "$p-profile-status-matches" status_matches
    check "$p-shell-files-after-install" unchanged
    check "$p-profiles-after-install" profiles_unchanged

    # A window of Terminal's own startup profile, opened after the install: no session.
    logins_before="$(login_pids)"
    open -a Terminal
    check "$p-startup-window" wait_for "the startup window" has_window
    check "$p-startup-window-shell" wait_for "the startup window's own shell" new_login_has_a_child "$logins_before"
    quiet_wait
    check "$p-startup-window-zero-sessions" sessions_are 0
    observe "$p-startup-window"
    check "$p-shell-files-after-startup-window" unchanged
    check "$p-profiles-after-startup-window" profiles_unchanged

    # A window of the profile: one more window, and one live session with one attachment.
    windows_before="$(windows)"
    check "$p-window-one-menu" choose "New Window" KalaReach
    session_check "$p-window-one" wait_for "one live session with one attachment" sessions_are 1
    check "$p-window-one-adds-a-window" wait_for "one more window" windows_are $((windows_before + 1))
    check "$p-daemon-answers-after-window-one" daemon_answers
    first="$(ids)"
    observe "$p-window-one"
    shot "$p-window-one"

    # A window of another profile has a shell of its own and adds no session.
    count="$(session_count)"
    check "$p-session-list-read-before-other-profile" test -n "$count"
    logins_before="$(login_pids)"
    windows_before="$(windows)"
    check "$p-other-profile-menu" choose "New Window" Basic
    check "$p-other-profile-window" wait_for "the other profile's own window" windows_are $((windows_before + 1))
    check "$p-other-profile-window-shell" wait_for "that window's own shell" new_login_has_a_child "$logins_before"
    quiet_wait
    check "$p-other-profile-adds-no-session" sessions_are "$count"
    observe "$p-other-profile-window"

    # A tab: two sessions, the first kept, and no more windows.
    windows_before="$(windows)"
    check "$p-tab-menu" choose "New Tab" KalaReach
    session_check "$p-tab-two" wait_for "two live sessions" sessions_are 2
    session_check "$p-tab-keeps-first-and-differs" keeps_and_differs "$first" 2
    check "$p-tab-adds-no-window" windows_are "$windows_before"
    second="$(ids)"
    observe "$p-tab"

    # A second window of the profile: three sessions, the first two kept, one more window.
    windows_before="$(windows)"
    check "$p-window-three-menu" choose "New Window" KalaReach
    session_check "$p-window-three" wait_for "three live sessions" sessions_are 3
    session_check "$p-window-three-keeps-and-differs" keeps_and_differs "$second" 3
    check "$p-window-three-adds-a-window" wait_for "one more window" windows_are $((windows_before + 1))
    check "$p-daemon-answers-after-window-three" daemon_answers
    observe "$p-window-three"
    shot "$p-window-three"
    check "$p-shell-files-during-windows" unchanged
    check "$p-profiles-during-windows" profiles_unchanged

    # Close each session, quit Terminal, take the profile out.
    final="$(ids)"
    [ -n "$known" ] || check "$p-three-sessions-to-close" test "$(printf '%s\n' "$final" | grep -c .)" = 3
    for id in $final; do
        krc close "$id" > /dev/null
        check "$p-closed-$id" wait_for "session $id to close" closed "$id"
    done
    check "$p-terminal-quit" quit_terminal
    entry > "$work/entry-after-quit-$p.xml"
    check "$p-entry-kept-through-the-pass" diff "$work/entry-after-install-$p.xml" "$work/entry-after-quit-$p.xml"
    check "$p-profile-remove" remove_ok
    check "$p-shell-files-and-defaults-after-remove" unchanged
    check "$p-profiles-after-remove" profiles_unchanged
}

# The runner's own entry broken on purpose: its command without `new`, written back and read again.
break_the_entry() {
    local broken
    krc host terminal-profile install apple-terminal --json > /dev/null || return 1
    command_text="$(command_of CommandString)" || return 1
    broken="${command_text/ new / }"
    [ "$broken" != "$command_text" ] || return 1
    defaults export com.apple.Terminal - | plutil -replace 'Window Settings.KalaReach.CommandString' -string "$broken" -o - - | defaults import com.apple.Terminal - || return 1
    [ "$(command_of CommandString)" = "$broken" ]
}
# helpers end

# The first pass, in the release's default store. A path with a space, in the release of the finding,
# is what the known red is about; anywhere else every decision of the pass is a gate, as in the second.
known_pass=
finding_holds_for "$store" "$tag" && known_pass=1
if [ -n "$known_pass" ]; then
    say "first pass: the default store, $store, where the known red $finding applies to $tag"
else
    say "first pass: the default store, $store, every decision gates"
fi
windows_pass default-store "$known_pass"

# The second pass, in a store with no space in its path, installed from the same unpacked release.
plain="$work/store"
install_plain_store() { [ "${plain// }" = "$plain" ] && "$work/kalareach-$target-$release/bin/kr" host install --store "$plain"; }
check plain-store-installed install_plain_store || { say "no second store, nothing more to do"; exit 1; }
store="$plain"
say "second pass: a store with no space in its path, $store"
windows_pass plain-store

# 5. The runner's own entry broken on purpose: a window through it must start no session.
check mutant-entry-written break_the_entry
open -a Terminal
check mutant-startup-window wait_for "a Terminal window" has_window
windows_before="$(windows)"
check mutant-menu choose "New Window" KalaReach
check mutant-window wait_for "the broken profile's window" windows_are $((windows_before + 1))
# A negative has no event to wait for: the window's command ends at once, so a session that was to
# start has had this long to appear.
sleep 20
shot mutant-window
check mutant-command-without-new-detected sessions_are 0
observe mutant-window
check mutant-shell-files-unchanged unchanged
check mutant-profiles-unchanged profiles_unchanged

say "done, $([ "$failed" -eq 0 ] && echo 'every check held' || echo 'a check failed'); known reds: $known_reds ($finding)"
exit "$failed"
