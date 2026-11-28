#!/usr/bin/env bash
# Holds the checks of scripts/window-leg-macos.sh to what their names say, in a stand-in world: the
# real leg runs only in a hosted runner's own account, so this runs the leg's own function text (the
# lines between its `helpers begin` and `helpers end` markers) against stand-ins for System Events,
# `kr`, `pgrep` and `open`. A fake Terminal keeps its windows and logins in files, and a fake host
# keeps its session list in a file. Nothing here touches a real Terminal, preference or process.
# Each case names what it holds; a failed case prints `FAIL: <name>: ...`.
#
#   scripts/window-leg-flow-test.sh

# The stand-ins and the leg's variables are used by the definitions that `eval` reads in, which
# the checker cannot follow.
# shellcheck disable=SC2034,SC2329
set -uo pipefail

script="$(dirname "$0")/window-leg-macos.sh"
helpers="$(awk '/^# helpers begin$/{on=1; next} /^# helpers end$/{on=0} on' "$script")"
failed=0
fail() { echo "window-leg-flow-test: FAIL: $*"; failed=1; }
ok() { echo "ok: $*"; }
[ -n "$helpers" ] || { echo "window-leg-flow-test: no helpers in $script"; exit 1; }
command -v jq > /dev/null || { echo "window-leg-flow-test: jq is needed"; exit 1; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/window-leg-flow.XXXXXX")"

# A fresh stand-in world. The leg's definitions are read in first, so that the stand-ins replace the
# programs they stand for; the waits are made short, and a negative's quiet time is set by the case.
world() {
    fw="$(mktemp -d "$tmp/case.XXXXXX")"
    work="$fw"
    pictures="$fw"
    printf '0\n' > "$fw/windows"
    printf '[]\n' > "$fw/sessions"
    printf '1000\n' > "$fw/next"
    : > "$fw/logins"
    : > "$fw/closed"
    eval "$helpers"
    deadline=0
    known_deadline=0
    quiet=${QUIET:-0}
    failed=0
    known_reds=0
    store="/stand-in/store"
    window_tmp=/stand-in/tmp

    add_window() { echo $(($(cat "$fw/windows") + 1)) > "$fw/windows"; }
    add_login() {
        local n
        n=$(cat "$fw/next")
        echo $((n + 1)) > "$fw/next"
        echo "$n" >> "$fw/logins"
        [ "${1:-}" = nochild ] || : > "$fw/child-$n"
    }
    add_session() {
        local n
        n=$(cat "$fw/next")
        echo $((n + 1)) > "$fw/next"
        jq --arg id "s$n" '. + [{session_id: $id, state: "live", attachments: 1}]' "$fw/sessions" > "$fw/s.tmp" && mv "$fw/s.tmp" "$fw/sessions"
    }
    # The fake Terminal's Shell menu: a window or a tab of a profile, or a click that fails or does nothing.
    menu() {
        local rest=${1#click menu item \"} item sub
        item=${rest%%\"*}
        rest=${rest#*menu item \"}
        sub=${rest%%\"*}
        if [ "${FAKE_MENU_FAIL:-}" = "$sub/$item" ]; then echo "execution error: Can't get menu item \"$item\". (-1728)"; return 1; fi
        [ "${FAKE_MENU_NOOP:-}" != "$sub/$item" ] || return 0
        case "$sub/$item" in
            "New Window/KalaReach") add_window; add_login; [ -n "${FAKE_NO_SESSIONS:-}" ] || add_session ;;
            "New Window/Basic")
                add_window
                [ -n "${FAKE_BASIC_NO_LOGIN:-}" ] || add_login
                [ -z "${FAKE_BASIC_SESSION:-}" ] || add_session
                [ -z "${FAKE_BASIC_LATE_SESSION:-}" ] || { (command sleep 0.3; add_session) > /dev/null 2>&1 & }
                ;;
            "New Tab/KalaReach")
                add_login
                [ -z "${FAKE_TAB_WINDOW:-}" ] || add_window
                [ -n "${FAKE_NO_SESSIONS:-}" ] || [ -n "${FAKE_TAB_NO_SESSION:-}" ] || add_session
                ;;
        esac
    }
    ax() {
        case "$1" in
            'count windows')
                [ -z "${FAKE_COUNT_FAIL:-}" ] || { echo "execution error: not allowed"; return 1; }
                [ -z "${FAKE_COUNT_TEXT:-}" ] || { echo "missing value"; return 0; }
                cat "$fw/windows"
                ;;
            'set frontmost to true') [ -z "${FAKE_FRONT_FAIL:-}" ] || { echo "execution error: no front"; return 1; } ;;
            'click menu item "'*) menu "$1" ;;
        esac
    }
    open() {
        [ "$(cat "$fw/windows")" = 0 ] || return 0
        add_window
        add_login
        [ -z "${FAKE_STARTUP_LATE_SESSION:-}" ] || { (command sleep 0.3; add_session) > /dev/null 2>&1 & }
    }
    krc() {
        case "$1" in
            list)
                [ -z "${FAKE_LIST_FAIL:-}" ] || { echo "kr: the daemon does not answer" >&2; return 1; }
                [ -z "${FAKE_LIST_GARBAGE:-}" ] || { echo '{"error":"not a list"}'; return 0; }
                jq -c '{sessions: .}' "$fw/sessions"
                ;;
            close)
                jq --arg id "$2" 'map(select(.session_id != $id))' "$fw/sessions" > "$fw/s.tmp" && mv "$fw/s.tmp" "$fw/sessions"
                echo "$2" >> "$fw/closed"
                ;;
            status) if grep -qx "$2" "$fw/closed"; then echo '{"state":"closed"}'; else echo '{"state":"live"}'; fi ;;
        esac
    }
    sleep() { if [ "$1" = 1 ]; then command sleep 0.05; else command sleep "$1"; fi; }
    screencapture() { :; }
    terminal_pid() { echo 4242; }
    pgrep() { case "$1" in -x) cat "$fw/logins" ;; -P) [ -e "$fw/child-$2" ] ;; esac; }
}

# `pass <pass name> [known]` runs one pass in a fresh world and prints its log and its end state.
pass() {
    world
    # The leaves that read or write the real preferences and the real host are not under test here.
    entry() { echo '<dict/>'; }
    command_of() { echo "'$store/current/bin/kr' new --attach --hold-on-failure"; }
    entry_gone() { true; }
    install_ok() { true; }
    status_matches() { true; }
    remove_ok() { true; }
    unchanged() { true; }
    profiles_unchanged() { true; }
    quit_terminal() { true; }
    windows_pass "$@"
    echo "end: failed=$failed known_reds=$known_reds"
}
# `unit <commands>` runs the commands in a fresh world and prints their output and their last status.
unit() {
    world
    "$@"
    echo "status=$?"
}
has() { printf '%s\n' "$1" | grep -qxF -- "$2"; }
holds() { printf '%s\n' "$1" | grep -qF -- "$2"; }
tail_of() { printf '%s\n' "$1" | tail -n 30; }
# `want <case> <output> <line>`: the output has this exact line; `want_not`: it does not.
want() { if has "$2" "$3"; then ok "$1"; else fail "$1: no line '$3' in: $(tail_of "$2")"; fi; }
want_not() { if has "$2" "$3"; then fail "$1: the line '$3' is there: $(tail_of "$2")"; else ok "$1"; fi; }
want_text() { if holds "$2" "$3"; then ok "$1"; else fail "$1: no '$3' in: $(tail_of "$2")"; fi; }
# A function that the leg is to have.
need() { (world; declare -F "$1" > /dev/null) || { fail "$2: the leg has no function $1"; return 1; }; }
want_not_text() { if holds "$2" "$3"; then fail "$1: '$3' is there: $(tail_of "$2")"; else ok "$1"; fi; }

# A healthy second pass: every decision holds, and the windows and sessions are as the names say.
out=$(pass plain-store)
for name in no-entry-before-install profile-install shell-files-after-install profiles-after-install \
    startup-window startup-window-shell startup-window-zero-sessions shell-files-after-startup-window profiles-after-startup-window \
    window-one-menu window-one window-one-adds-a-window daemon-answers-after-window-one \
    session-list-read-before-other-profile other-profile-menu other-profile-window other-profile-window-shell other-profile-adds-no-session \
    tab-menu tab-two tab-keeps-first-and-differs tab-adds-no-window window-three-menu window-three \
    window-three-keeps-and-differs window-three-adds-a-window daemon-answers-after-window-three shell-files-during-windows profiles-during-windows \
    three-sessions-to-close terminal-quit profile-remove shell-files-and-defaults-after-remove profiles-after-remove; do
    want "healthy pass: $name holds" "$out" "check=plain-store-$name ok=1"
done
want "healthy pass: nothing failed, no known red" "$out" "end: failed=0 known_reds=0"
want "healthy pass: three sessions are closed" "$(printf '%s\n' "$out" | grep -c 'check=plain-store-closed-.* ok=1')" 3
want_text "healthy pass: the startup window is observed with an empty list" "$out" "window-leg-macos: plain-store-startup-window: windows=1 sessions=[]"
want_text "healthy pass: window one is observed with one session" "$out" "window-leg-macos: plain-store-window-one: windows=2 sessions=[{"
want_text "healthy pass: the tab is observed with no new window" "$out" "window-leg-macos: plain-store-tab: windows=3 sessions=[{"
want_text "healthy pass: window three is observed with one more window" "$out" "window-leg-macos: plain-store-window-three: windows=4 sessions=[{"

# A menu click that fails is a failure of its own check, whichever pass it is in and whatever follows.
for pair in "New Window/KalaReach:window-one-menu" "New Window/Basic:other-profile-menu" "New Tab/KalaReach:tab-menu"; do
    out=$(FAKE_MENU_FAIL="${pair%%:*}" pass plain-store)
    want "a failed click ${pair%%:*} fails ${pair##*:}" "$out" "check=plain-store-${pair##*:} ok=0"
    want_text "a failed click ${pair%%:*} says what System Events said" "$out" "Can't get menu item"
    want_text "a failed click ${pair%%:*} fails the pass" "$out" "end: failed=1"
done
for pair in "New Window/KalaReach:window-one-menu" "New Window/Basic:other-profile-menu" "New Tab/KalaReach:tab-menu"; do
    out=$(FAKE_NO_SESSIONS=1 FAKE_MENU_FAIL="${pair%%:*}" pass default-store 1)
    want "a failed click ${pair%%:*} in the known-red pass is not the finding" "$out" "check=default-store-${pair##*:} ok=0"
    want_text "a failed click ${pair%%:*} in the known-red pass fails the pass" "$out" "end: failed=1"
done
out=$(FAKE_NO_SESSIONS=1 FAKE_MENU_FAIL="New Window/KalaReach" pass default-store 1)
want "a failed second window click in the known-red pass is not the finding" "$out" "check=default-store-window-three-menu ok=0"
out=$(unit choose "New Window" Basic)
want "choose: a click that holds returns success" "$out" "status=0"
out=$(FAKE_FRONT_FAIL=1 unit choose "New Window" Basic)
want "choose: Terminal that cannot be brought to the front returns failure" "$out" "status=1"
want_text "choose: Terminal that cannot be brought to the front says so" "$out" "could not be brought to the front"
out=$(FAKE_MENU_FAIL="New Window/Basic" unit choose "New Window" Basic)
want "choose: a click that fails returns failure" "$out" "status=1"
want_text "choose: a click that fails names the menu and the item" "$out" "Shell, New Window, Basic failed"

# A click that does nothing, or a tab that opens a window, shows in the application's window count.
out=$(FAKE_MENU_NOOP="New Window/KalaReach" pass plain-store)
want "a click that opens no window fails window one's window count" "$out" "check=plain-store-window-one-adds-a-window ok=0"
out=$(FAKE_TAB_WINDOW=1 pass plain-store)
want "a tab that opens a window fails the tab's window count" "$out" "check=plain-store-tab-adds-no-window ok=0"
want "a tab that opens a window still gives its session" "$out" "check=plain-store-tab-two ok=1"
out=$(FAKE_COUNT_FAIL=1 pass plain-store)
want "an unreadable window count fails window one's window count" "$out" "check=plain-store-window-one-adds-a-window ok=0"
out=$(FAKE_COUNT_TEXT=1 unit windows)
want "windows: an answer that is not a number fails" "$out" "status=1"
want_not_text "windows: an answer that is not a number is not printed as a count" "$out" "missing value"
out=$(FAKE_COUNT_FAIL=1 unit windows)
want "windows: an unreadable count fails" "$out" "status=1"
want_not_text "windows: an unreadable count is not printed as a count" "$out" "execution error"

# The known red is the five decisions about sessions; nothing else.
out=$(FAKE_NO_SESSIONS=1 pass default-store 1)
for name in window-one tab-two tab-keeps-first-and-differs window-three window-three-keeps-and-differs; do
    want "known red: $name is the finding" "$out" "check=known-red-default-store-$name ok=0 finding=profile-command-split-at-space"
done
want "known red: the menu click is a gate that holds" "$out" "check=default-store-window-one-menu ok=1"
want "known red: window one's window count is a gate that holds" "$out" "check=default-store-window-one-adds-a-window ok=1"
want "known red: the tab's window count is a gate that holds" "$out" "check=default-store-tab-adds-no-window ok=1"
want "known red: the daemon's answer is a gate that holds" "$out" "check=default-store-daemon-answers-after-window-one ok=1"
want "known red: five reds, the pass holds" "$out" "end: failed=0 known_reds=5"
want_not_text "known red: no more than the five are named" "$out" "known-red-default-store-three-sessions-to-close"
want_text "known red: each red is printed as a warning" "$out" "::warning::known red default-store-window-one (profile-command-split-at-space)"
out=$(FAKE_NO_SESSIONS=1 FAKE_LIST_FAIL=1 pass default-store 1)
want "known red: a daemon that does not answer is not the finding" "$out" "check=default-store-daemon-answers-after-window-one ok=0"
want "known red: a daemon that does not answer after window three is not the finding" "$out" "check=default-store-daemon-answers-after-window-three ok=0"
want_text "known red: a daemon that does not answer fails the pass" "$out" "end: failed=1"
out=$(FAKE_NO_SESSIONS=1 FAKE_MENU_NOOP="New Window/KalaReach" pass default-store 1)
want "known red: no window opened is not the finding" "$out" "check=default-store-window-one-adds-a-window ok=0"
want "known red: no second window opened is not the finding" "$out" "check=default-store-window-three-adds-a-window ok=0"
out=$(FAKE_NO_SESSIONS=1 FAKE_TAB_WINDOW=1 pass default-store 1)
want "known red: a tab that opens a window is not the finding" "$out" "check=default-store-tab-adds-no-window ok=0"
out=$(pass default-store 1)
want_text "known red: a pass that holds says the finding is gone" "$out" "::warning::the finding is gone: remove the known-red mark (profile-command-split-at-space, default-store-window-one)"
out=$(FAKE_NO_SESSIONS=1 pass default-store)
want "the mark is only for the pass that is given it: window one gates" "$out" "check=default-store-window-one ok=0"
want_text "the mark is only for the pass that is given it: the pass fails" "$out" "end: failed=1"

# The mark follows the release of the finding and a space in the store's path, and nothing else.
if need finding_holds_for "the mark"; then
    out=$(world; finding_holds_for "/Users/runner/Library/Application Support/KalaReach/host" host/v0.1.0+7c68ef8cf3c0 && echo yes || echo no)
    want "the mark: a space in the path and the release of the finding" "$out" yes
    out=$(world; finding_holds_for "/Users/runner/Library/Application Support/KalaReach/host" host/v0.2.0+aaaaaaaaaaaa && echo yes || echo no)
    want "the mark: another release gates every decision" "$out" no
    out=$(world; finding_holds_for "/Users/runner/store" host/v0.1.0+7c68ef8cf3c0 && echo yes || echo no)
    want "the mark: no space in the path gates every decision" "$out" no
fi

# The session list: only an answer with a sessions array counts, a failure is printed, and no count of
# zero is made up.
out=$(FAKE_LIST_FAIL=1 unit session_count 2>&1)
want "session_count: a list that fails fails" "$out" "status=1"
want_text "session_count: the error of the list is printed" "$out" "kr: the daemon does not answer"
out=$(FAKE_LIST_FAIL=1 unit sessions_are 0 2>&1)
want "sessions_are 0: a list that fails fails" "$out" "status=1"
out=$(FAKE_LIST_GARBAGE=1 unit session_count 2>&1)
want "session_count: an answer with no sessions array fails" "$out" "status=1"
out=$(FAKE_LIST_GARBAGE=1 unit daemon_answers 2>&1)
want "daemon_answers: an answer with no sessions array fails" "$out" "status=1"
out=$(unit daemon_answers 2>&1)
want "daemon_answers: an empty list is an answer" "$out" "status=0"
out=$(FAKE_LIST_GARBAGE=1 unit sessions_are 0 2>&1)
want "sessions_are 0: an answer with no sessions array fails" "$out" "status=1"
want_text "sessions_are 0: an answer with no sessions array is printed" "$out" "kr list gave no session list"
out=$(unit sessions_are 0 2>&1)
want "sessions_are 0: an empty list holds" "$out" "status=0"
out=$(FAKE_LIST_FAIL=1 unit ids 2>&1)
want "ids: a list that fails fails" "$out" "status=1"
out=$(FAKE_LIST_FAIL=1 pass plain-store)
want "a list that fails fails the startup window's zero" "$out" "check=plain-store-startup-window-zero-sessions ok=0"
want "a list that fails fails the other profile's zero" "$out" "check=plain-store-session-list-read-before-other-profile ok=0"
want "a list that fails fails the closing of three" "$out" "check=plain-store-three-sessions-to-close ok=0"
want_text "a list that fails is observed as unreadable" "$out" "window-leg-macos: plain-store-window-one: windows=2 sessions=unreadable"
want "pass 2 closes three sessions" "$(printf '%s\n' "$(pass plain-store)" | grep -c 'check=plain-store-closed-.* ok=1')" 3
out=$(FAKE_TAB_NO_SESSION=1 pass plain-store)
want "a pass that has only two sessions at its end does not close three" "$out" "check=plain-store-three-sessions-to-close ok=0"

# A control window decides its own zero: its own login with a shell, then a quiet time before the read.
out=$(FAKE_BASIC_NO_LOGIN=1 pass plain-store)
want "the other profile's window needs a login of its own" "$out" "check=plain-store-other-profile-window-shell ok=0"
out=$(FAKE_BASIC_SESSION=1 pass plain-store)
want "a session of the other profile's window fails its zero" "$out" "check=plain-store-other-profile-adds-no-session ok=0"
out=$(QUIET=0.8 FAKE_BASIC_LATE_SESSION=1 pass plain-store)
want "a session that comes late from the other profile's window fails its zero" "$out" "check=plain-store-other-profile-adds-no-session ok=0"
out=$(QUIET=0.8 FAKE_STARTUP_LATE_SESSION=1 pass plain-store)
want "a session that comes late from the startup window fails its zero" "$out" "check=plain-store-startup-window-zero-sessions ok=0"
if need new_login_has_a_child "the control window"; then
    out=$(world; add_login; add_login; before=$(login_pids); new_login_has_a_child "$before" && echo yes || echo no)
    want "new_login_has_a_child: logins that were already there do not count" "$out" no
    out=$(world; add_login; before=$(login_pids); add_login nochild; new_login_has_a_child "$before" && echo yes || echo no)
    want "new_login_has_a_child: a new login without a child does not count" "$out" no
    out=$(world; add_login; before=$(login_pids); add_login; new_login_has_a_child "$before" && echo yes || echo no)
    want "new_login_has_a_child: a new login with a child counts" "$out" yes
fi

# Terminal is quit by the name of its Quit item.
out=$(world; terminal_gone() { true; }; ax() { echo "$1" >> "$fw/ax.log"; }; quit_terminal; cat "$fw/ax.log")
want_text "quit_terminal: Quit is chosen by its name" "$out" 'click menu item "Quit Terminal" of menu 1 of menu bar item 2 of menu bar 1'
want_not "quit_terminal: Quit is not the last item" "$out" 'click (last menu item of menu 1 of menu bar item 2 of menu bar 1)'

# The runner's own entry is broken on purpose and read again: a write that did not take is a failure.
broken_entry() {
    world
    echo "'kr' new --attach" > "$fw/cmd"
    command_of() { cat "$fw/cmd"; }
    krc() { return 0; }
    defaults() { case "$1" in export) echo '<plist/>' ;; import) cat > /dev/null; [ -n "${FAKE_IMPORT_NOOP:-}" ] || cp "$fw/cmd.new" "$fw/cmd" ;; esac; }
    plutil() { printf '%s\n' "$4" > "$fw/cmd.new"; echo '<plist/>'; }
    break_the_entry
    echo "status=$? command=$(cat "$fw/cmd")"
}
out=$(broken_entry)
want "break_the_entry: a write that took holds" "$out" "status=0 command='kr' --attach"
out=$(FAKE_IMPORT_NOOP=1 broken_entry)
want_text "break_the_entry: a write that did not take fails" "$out" "status=1 command='kr' new --attach"

# The other profiles are compared whole, by name and value, without our own entry.
if command -v plutil > /dev/null && need profiles "the profiles"; then
    write_prefs() {
        cat > "$1" << PREFS_END
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Default Window Settings</key>
	<string>Basic</string>
	<key>Window Settings</key>
	<dict>
		<key>Basic</key>
		<dict>
			<key>BackgroundColor</key>
			<data>YWJj</data>
			<key>name</key>
			<string>Basic</string>
		</dict>
		<key>Grass</key>
		<dict>
			<key>name</key>
			<string>${2:-Grass}</string>
		</dict>
${3:-}
	</dict>
</dict>
</plist>
PREFS_END
    }
    ours='		<key>KalaReach</key>
		<dict>
			<key>CommandString</key>
			<string>x</string>
		</dict>'
    # The baseline holds the plain profiles; the later read holds the variant named by the arguments.
    profile_case() {
        world
        write_prefs "$fw/base.plist" Grass
        write_prefs "$fw/now.plist" "$@"
        defaults() { cp "$fw/$prefs.plist" "$3"; }
        prefs=base
        before_profiles="$(profiles)"
        prefs=now
        profiles_unchanged
        echo "status=$?"
    }
    out=$(world; write_prefs "$fw/p.plist" Grass "$ours"; defaults() { cp "$fw/p.plist" "$3"; }; profiles)
    want_text "profiles: the other profiles are there with their values" "$out" "YWJj"
    want_not_text "profiles: our own entry is not there" "$out" "KalaReach"
    out=$(profile_case Grass "$ours" 2>&1)
    want_text "profiles_unchanged: our own entry changes nothing" "$out" "status=0"
    out=$(profile_case Moss 2>&1)
    want_text "profiles_unchanged: a changed value fails" "$out" "status=1"
    want_text "profiles_unchanged: a changed value is printed" "$out" "the other profiles differ from the baseline"
else
    echo "skipped: the profile comparison needs plutil and the leg's profiles function"
fi

# A known red that fails is counted and warned of; one that holds says the finding is gone.
out=$(world; known_red a-red false; known_red b-green true; echo "reds=$known_reds")
want_text "known_red: a red is a warning" "$out" "::warning::known red a-red (profile-command-split-at-space)"
want_text "known_red: a green says the finding is gone" "$out" "::warning::the finding is gone: remove the known-red mark (profile-command-split-at-space, b-green)"
want "known_red: one red is counted" "$out" "reds=1"

exit "$failed"
