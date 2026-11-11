#!/usr/bin/env bash
# shellcheck disable=SC2154  # the variables below are the calling script's, as the header says
# The lock-screen leg of `scripts/e2e-voice-call-device.sh android lock-screen`.
#
# Sourced by that script. While the application holds a call, this locks the emulator's screen and
# reads the lock screen the way a person and the system do: the system's own record of the call's
# notification (`dumpsys notification`), the keyguard's state, the notification's controls on the
# lock screen itself (`uiautomator`, which reads the system's screens), and a still of it. It then
# presses the controls there:
#
#   Mute     acts with no unlock;
#   Unmute   asks for the unlock, and the microphone stays closed to the call until the person
#            gives it;
#   Stop     ends the call with no unlock.
#
# The lock screen is the emulator's own at its default notification settings: no notification
# setting of the device is changed. A lock screen needs a lock to show, and a locked phone asks for
# its credential, so the leg gives the virtual device a credential of its own for the run (a PIN
# that protects nothing) and clears it again, and puts the lock setting back as it found it.
#
# The caller defines `say`, and sets `emulator_adb`, `emulator_serial`, `harness`, `artefacts` and
# `app_id`. The leg's checks are written to `$harness/script-checks.txt` in the lines the
# application's own checks have, and the caller adds them to the result.

# The credential the virtual device holds while the leg runs.
lock_pin=2468
# The call's notification: its identifier in the application (VoiceCallService.NOTIFICATION_ID).
lock_notification_id=19286
# The channel it belongs to (VoiceCallService.CHANNEL_ID).
lock_channel_id=kr-voice-call-running

lock_device() { "$emulator_adb" -s "$emulator_serial" "$@"; }

lock_check() { # <name> <0|1> <detail>
    printf 'check=%s ok=%s detail=%s\n' "$1" "$2" "$3" >>"$harness/script-checks.txt"
    say "check=$1 ok=$2 detail=$3"
}

# Waits up to `$1` seconds for the rest of the arguments, a command, to succeed.
lock_wait() { # <seconds> <command...>
    local seconds=$1 waited=0
    shift
    while ! "$@"; do
        [ "$waited" -lt "$seconds" ] || return 1
        sleep 1
        waited=$((waited + 1))
    done
}

lock_asleep() { lock_device shell dumpsys power 2>/dev/null | grep -q 'mWakefulness=Asleep'; }
lock_awake() { lock_device shell dumpsys power 2>/dev/null | grep -q 'mWakefulness=Awake'; }

# The keyguard's own state, from the activity manager's record of it.
lock_showing() {
    lock_device shell dumpsys activity activities 2>/dev/null | grep -q 'mKeyguardShowing=true'
}

# The system's record of the call's notification, from the notification manager.
lock_record() {
    lock_device shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' \
        | awk -v id="$lock_notification_id" -v app="$app_id" '
            /NotificationRecord\(/ { on = (index($0, "pkg=" app " ") > 0 && index($0, " id=" id " ") > 0); if (on) print; next }
            on && /^      / { print; next }
            { on = 0 }'
}

# The system's record of the call's channel: its importance, sound and vibration.
lock_channel() {
    lock_device shell dumpsys notification --noredact 2>/dev/null | tr -d '\r' \
        | grep -F "NotificationChannel{mId='$lock_channel_id'" | head -1
}

lock_record_has() { # <text>
    lock_record | grep -q -F -- "$1"
}

# The screen's accessibility tree, saved as `$1`.
lock_dump() { # <file>
    local remote="/data/local/tmp/kr-ui-$run.xml"
    lock_device shell uiautomator dump "$remote" >/dev/null 2>&1
    lock_device exec-out cat "$remote" >"$1" 2>/dev/null
    lock_device shell rm -f "$remote" >/dev/null 2>&1
}

# Presses the control labelled `$2` in the screen read into `$1`, where a person would.
lock_press() { # <dump> <label>
    local point
    point="$(python3 -I "$here/scripts/lib/ui-node.py" center "$1" "$2")" || return 1
    [ -n "$point" ] || return 1
    # shellcheck disable=SC2086
    lock_device shell input tap $point
}

lock_still() { # <name>
    lock_device exec-out screencap -p >"$artefacts/lock-screen/$1.png" 2>/dev/null
}

# Locks the screen: the power key, and then the screen woken to the lock screen.
lock_the_screen() {
    lock_device shell input keyevent KEYCODE_POWER
    lock_wait 15 lock_asleep || return 1
    lock_device shell input keyevent KEYCODE_WAKEUP
    lock_wait 15 lock_awake || return 1
    lock_wait 15 lock_showing
}

lock_screen_restore() {
    [ -e "$harness/credential-set" ] || return 0
    lock_device shell locksettings clear --old "$lock_pin" >/dev/null 2>&1
    if [ -s "$harness/lock-disabled-before" ]; then
        lock_device shell locksettings set-disabled "$(cat "$harness/lock-disabled-before")" >/dev/null 2>&1
    fi
    /bin/rm -f "${harness:?}/credential-set"
    say "the emulator's lock credential and lock setting are put back"
}

# Ends the call through the unlocked shade, so that a run which found no Stop on the lock screen does
# not wait out the application's patience.
lock_stop_through_the_shade() {
    local dump="$artefacts/lock-screen/shade.xml"
    lock_device shell input keyevent KEYCODE_WAKEUP
    lock_device shell input swipe 540 1800 540 600 200
    lock_device shell input text "$lock_pin"
    lock_device shell input keyevent KEYCODE_ENTER
    sleep 2
    lock_device shell cmd statusbar expand-notifications
    sleep 2
    lock_dump "$dump"
    lock_press "$dump" Stop
}

# The leg. Returns 0 whatever it finds: what it finds is in its checks.
lock_screen_leg() {
    mkdir -p "$artefacts/lock-screen"
    : >"$harness/script-checks.txt"
    local before
    before="$(lock_device shell locksettings get-disabled 2>/dev/null | tr -d '\r')"
    printf '%s\n' "${before:-true}" >"$harness/lock-disabled-before"
    lock_device shell locksettings set-disabled false >/dev/null 2>&1
    if lock_device shell locksettings set-pin "$lock_pin" 2>&1 | grep -q -i 'password set\|pin set\|set to'; then
        touch "$harness/credential-set"
    else
        lock_check "the leg holds a lock credential of its own" 0 "the emulator already had a credential, or set-pin was refused"
        lock_screen_restore
        return 0
    fi

    if lock_the_screen; then
        lock_check "the screen is locked" 1 "keyguard showing"
    else
        lock_check "the screen is locked" 0 "the keyguard did not show"
    fi
    lock_still 1-locked

    # The system's record of the call's notification, and what the lock screen itself shows of it.
    lock_record >"$artefacts/lock-screen/record-1-locked.txt"
    lock_device shell dumpsys activity activities 2>/dev/null | grep -i 'keyguard' | head -20 >"$artefacts/lock-screen/keyguard-1-locked.txt"
    local dump="$artefacts/lock-screen/locked-1.xml" shown=0 tries=0
    while [ "$tries" -lt 15 ]; do
        lock_dump "$dump"
        if python3 -I "$here/scripts/lib/ui-node.py" has "$dump" "Voice call running"; then shown=1; break; fi
        sleep 1
        tries=$((tries + 1))
    done
    lock_still 2-locked-after-read
    # What the platform holds of the notification's channel: of default importance (what puts a
    # notification on the lock screen of a phone at its default settings), with no sound and no
    # vibration, and the notification itself carrying none.
    lock_channel >"$artefacts/lock-screen/channel.txt"
    if grep -q 'mImportance=3' "$artefacts/lock-screen/channel.txt" \
        && grep -q 'mSound=null' "$artefacts/lock-screen/channel.txt" \
        && ! grep -q 'mVibrationEnabled=true' "$artefacts/lock-screen/channel.txt" \
        && lock_record_has 'sound=null' && lock_record_has 'vibrate=null'; then
        lock_check "the call's notification makes no sound and no vibration" 1 "$(sed 's/mDescription=[^,]*, //' "$artefacts/lock-screen/channel.txt" | cut -c1-300)"
    else
        lock_check "the call's notification makes no sound and no vibration" 0 "channel: $(cut -c1-300 "$artefacts/lock-screen/channel.txt")"
    fi
    if [ "$shown" = 1 ] && lock_record_has "Mute" && lock_record_has "Stop"; then
        lock_check "the call's notification is on the lock screen with Mute and Stop" 1 "the notification manager holds it and the lock screen shows it"
    else
        lock_check "the call's notification is on the lock screen with Mute and Stop" 0 "on the lock screen: $shown; record: $(grep -c . "$artefacts/lock-screen/record-1-locked.txt") lines"
        lock_stop_through_the_shade
        lock_screen_restore
        return 0
    fi

    # Mute, from the locked screen.
    if lock_press "$dump" Mute && lock_wait 10 lock_record_has '"Unmute"'; then
        lock_check "Mute from the lock screen mutes the call with no unlock" 1 "the notification now offers Unmute; the screen stayed locked: $(lock_showing && echo yes || echo no)"
    else
        lock_check "Mute from the lock screen mutes the call with no unlock" 0 "the notification did not change to Unmute"
    fi

    # Unmute, from the locked screen: the system asks for the credential and the call stays muted.
    lock_dump "$dump"
    local asked=0
    if lock_press "$dump" Unmute; then
        sleep 3
        lock_dump "$artefacts/lock-screen/locked-2-unmute.xml"
        lock_still 3-unmute-asks
        if lock_showing && lock_record_has '"Unmute"' \
            && python3 -I "$here/scripts/lib/ui-node.py" ids "$artefacts/lock-screen/locked-2-unmute.xml" "" | grep -q -i 'pin'; then
            asked=1
        fi
    fi
    lock_check "Unmute from the lock screen asks for the unlock and leaves the call muted" "$asked" "the credential prompt shows, the screen is still locked and the notification still offers Unmute"
    lock_device shell date +%s%N >"$harness/unlock-at.txt"
    # The person unlocks: the unmute then goes through.
    lock_device shell input text "$lock_pin"
    lock_device shell input keyevent KEYCODE_ENTER
    if lock_wait 15 lock_record_has '"Mute"'; then
        lock_check "Unmute goes through once the screen is unlocked" 1 "the notification offers Mute again"
    else
        lock_check "Unmute goes through once the screen is unlocked" 0 "the notification still offers Unmute"
    fi

    # Stop, from the locked screen.
    lock_the_screen
    lock_dump "$dump"
    lock_still 4-locked-again
    lock_press "$dump" Stop
    local gone=0 waited=0
    while [ "$waited" -lt 15 ]; do
        if [ -z "$(lock_record)" ]; then gone=1; break; fi
        sleep 1
        waited=$((waited + 1))
    done
    if [ "$gone" = 1 ] && lock_showing; then
        lock_check "Stop from the lock screen ends the call with no unlock" 1 "the notification is gone and the screen is still locked"
    else
        lock_check "Stop from the lock screen ends the call with no unlock" 0 "notification gone: $gone"
        lock_stop_through_the_shade
    fi
    lock_screen_restore
    return 0
}

# Reads the application's record of the microphone against the time the person gave the credential:
# the call was open, was muted from the lock screen, and was opened again only after the unlock.
lock_judge_trail() { # <result file>
    local line at verdict
    line="$(grep '^check=the microphone followed the taps on the lock screen ok=' "$1" | head -1)"
    at=""
    [ ! -s "$harness/unlock-at.txt" ] || at="$(tr -d '\r\n' <"$harness/unlock-at.txt")"
    verdict="$(python3 -I - "$line" "$at" <<'PY'
import re
import sys

line, unlock_ns = sys.argv[1], sys.argv[2]
steps = re.findall(r"(open|muted)@(\d+)", line.split("detail=", 1)[-1])
order = [word for word, _ in steps]
if order != ["open", "muted", "open"] or not unlock_ns.isdigit():
    print("0 %s" % (" ".join("%s@%s" % each for each in steps) or "no record"))
else:
    reopened, unlocked = int(steps[2][1]), int(unlock_ns) // 1_000_000
    print("%d the microphone reopened %d ms after the credential prompt was answered" % (reopened >= unlocked, reopened - unlocked))
PY
)"
    lock_check "the microphone stayed muted until the unlock" "${verdict%% *}" "${verdict#* }"
}
