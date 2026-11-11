#!/usr/bin/env bash
# shellcheck disable=SC2154  # the variables below are the calling script's, as the header says
# The lock-screen leg of `scripts/e2e-voice-call-device.sh android lock-screen`.
#
# Sourced by that script. While the application holds a call, this first presses the microphone
# control on the call's own screen and reads what the screen says, swipes the call's notification
# away in the unlocked shade and reads that it is posted again, then locks the emulator's screen and
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

# Presses the control labelled `$1`. The lock screen draws the notification folded, with its controls
# under "Expand", so this expands it first when the control is not there; the screen is read into `$2`.
lock_control() { # <label> <dump>
    local tries=0
    while [ "$tries" -lt 8 ]; do
        lock_dump "$2"
        lock_press "$2" "$1" && return 0
        lock_press "$2" Expand
        sleep 1
        tries=$((tries + 1))
    done
    return 1
}

# Whether the lock screen, read afresh into `$2`, shows the words `$1`.
lock_says() { # <words> <dump>
    lock_dump "$2"
    python3 -I "$here/scripts/lib/ui-node.py" has "$2" "$1"
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

# Puts the virtual device's lock back as the leg found it. The leg's marker is made before its first
# change, and is kept until the credential is cleared and the lock setting reads as it did, so that
# the run's end tries again after a failure here. Returns 1 when something could not be put back.
lock_screen_restore() {
    [ -e "$harness/lock-changed" ] || return 0
    local before output ok=1
    before="$(cat "$harness/lock-disabled-before" 2>/dev/null)"
    if [ -e "$harness/credential-set" ]; then
        if output="$(lock_device shell locksettings clear --old "$lock_pin" 2>&1)" && ! printf '%s' "$output" | grep -q -i 'fail\|error\|incorrect'; then
            /bin/rm -f "${harness:?}/credential-set"
        else
            ok=0
        fi
    fi
    if [ "$ok" = 1 ] && [ -n "$before" ]; then
        lock_device shell locksettings set-disabled "$before" >/dev/null 2>&1
        [ "$(lock_device shell locksettings get-disabled 2>/dev/null | tr -d '\r')" = "$before" ] || ok=0
    fi
    if [ "$ok" = 1 ]; then
        /bin/rm -f "${harness:?}/lock-changed"
        say "the emulator's lock credential and lock setting are put back"
        return 0
    fi
    say "the emulator's lock could not be put back as it was"
    return 1
}

# Puts the lock back and says whether it is back, as a check of the leg.
lock_screen_restore_check() {
    if lock_screen_restore; then
        lock_check "the emulator's lock is put back as the leg found it" 1 "the credential is cleared and the lock setting reads as it did"
    else
        lock_check "the emulator's lock is put back as the leg found it" 0 "the credential or the lock setting could not be put back; the run's end tries again"
    fi
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

# Waits up to `$1` seconds for the call's own screen, read afresh into `$3`, to say all of `$2`:
# words separated by a bar, each of which must be on the screen.
screen_says() { # <seconds> <words, separated by |> <dump>
    local words=$2 dump=$3 word ok until=$((SECONDS + $1))
    while :; do
        lock_dump "$dump"
        ok=1
        while IFS= read -r word; do
            python3 -I "$here/scripts/lib/ui-node.py" has "$dump" "$word" || ok=0
        done < <(printf '%s\n' "$words" | tr '|' '\n')
        [ "$ok" = 1 ] && return 0
        [ "$SECONDS" -lt "$until" ] || return 1
        sleep 1
    done
}

# The call's own screen, before anything locks: the page the person sees while the call runs. It
# says the microphone is on and offers to mute it; pressing that mutes the call, and the screen then
# says the microphone is muted (not that none is available) and offers to unmute it; pressing that
# opens the microphone again. Each press is a tap where the control is, read from the screen.
screen_leg() {
    local dump="$artefacts/lock-screen/screen.xml" found="" ok
    lock_still 0-screen-before
    # The call's own screen is under Sessions, behind "Talk to your host"; a screen that is opened
    # while a call runs finds the call.
    if screen_says 30 "Sessions" "$dump"; then lock_press "$dump" Sessions; fi
    if screen_says 30 "Talk to your host" "$dump"; then lock_press "$dump" "Talk to your host"; fi
    if screen_says 40 "Microphone on|Mute microphone" "$dump"; then ok=1; found="the screen says the microphone is on and offers to mute it"; else ok=0; found="the screen did not say so"; fi
    lock_still 0-screen-on
    lock_check "the call's own screen says the microphone is on and offers to mute it" "$ok" "$found"
    [ "$ok" = 1 ] || return 0

    if lock_press "$dump" "Mute microphone"; then
        if screen_says 20 "Microphone muted|Unmute microphone" "$dump" && ! python3 -I "$here/scripts/lib/ui-node.py" has "$dump" "No microphone available"; then
            ok=1; found="after Mute microphone the screen says the microphone is muted and offers to unmute it"
        else
            ok=0; found="after Mute microphone the screen does not say the microphone is muted, or says no microphone is available"
        fi
    else
        ok=0; found="the Mute microphone control could not be pressed"
    fi
    lock_still 0-screen-muted
    lock_check "the call's own screen says the microphone is muted and offers to unmute it" "$ok" "$found"
    [ "$ok" = 1 ] || return 0

    if lock_press "$dump" "Unmute microphone"; then
        if screen_says 20 "Microphone on|Mute microphone" "$dump"; then
            ok=1; found="after Unmute microphone the screen says the microphone is on and offers to mute it"
        else
            ok=0; found="after Unmute microphone the screen does not say the microphone is on"
        fi
    else
        ok=0; found="the Unmute microphone control could not be pressed"
    fi
    lock_still 0-screen-unmuted
    lock_check "the call's own screen unmutes the microphone" "$ok" "$found"
}

# When the notification of the call was last posted, from the system's record of it.
screen_posted() {
    lock_record | sed -n 's/.*[[:space:]]when=\([0-9][0-9]*\)\/.*/\1/p' | head -1
}

# Waits until the notification has read as posted at one time for three looks in a row, and prints
# that time: a capture change that lands during the swipe below must not pass for its republication.
screen_posted_still() {
    local last="" same=0 now until=$((SECONDS + 30))
    while [ "$SECONDS" -lt "$until" ]; do
        now="$(screen_posted)"
        if [ -n "$now" ] && [ "$now" = "$last" ]; then same=$((same + 1)); else same=0; fi
        if [ "$same" -ge 3 ]; then printf '%s\n' "$now"; return 0; fi
        last="$now"
        sleep 1
    done
    return 1
}

# The notification of a running call on an unlocked phone: the person swipes it away in the shade,
# and it is back while the call runs (Android 14 and later let the person dismiss it, and a locked
# phone would then show no controls for the call). The swipe is made across the screen where the
# notification's own title is drawn, after the notification has stopped changing; the system's
# record must then hold a notification, carrying the foreground-service flag, posted after the swipe.
screen_dismiss_leg() {
    local dump="$artefacts/lock-screen/shade.xml" before after point px py width ok=0 found="" until
    lock_device shell cmd statusbar expand-notifications
    sleep 2
    lock_dump "$dump"
    lock_still 0-shade-before
    point="$(python3 -I "$here/scripts/lib/ui-node.py" at "$dump" "Voice call running")"
    before="$(screen_posted_still)"
    width="$(lock_device shell wm size 2>/dev/null | tr -d '\r' | sed -n 's/.*[^0-9]\([0-9][0-9]*\)x[0-9][0-9]*.*/\1/p' | tail -1)"
    if [ -z "$before" ] || [ -z "$point" ] || [ -z "$width" ]; then
        found="the notification was not in the shade, or did not settle (posted: ${before:-none})"
    else
        read -r px py <<<"$point"
        lock_device shell input swipe "$px" "$py" "$((width - 20))" "$py" 250
        found="the notification was swiped away in the shade and was not posted again (posted $before)"
        until=$((SECONDS + 20))
        while [ "$SECONDS" -lt "$until" ]; do
            after="$(screen_posted)"
            if [ -n "$after" ] && [ "$after" -gt "$before" ] 2>/dev/null && lock_record_has "FOREGROUND_SERVICE"; then
                ok=1
                found="the notification was swiped away in the shade and was posted again (posted $before, then $after)"
                break
            fi
            sleep 1
        done
    fi
    lock_device shell cmd statusbar collapse
    lock_still 0-shade-after
    lock_check "a notification dismissed in the shade while the call runs is posted again" "$ok" "$found"
}

# The leg. Returns 0 whatever it finds: what it finds is in its checks.
lock_screen_leg() {
    mkdir -p "$artefacts/lock-screen"
    : >"$harness/script-checks.txt"
    screen_leg
    screen_dismiss_leg
    local before
    before="$(lock_device shell locksettings get-disabled 2>/dev/null | tr -d '\r')"
    printf '%s\n' "${before:-true}" >"$harness/lock-disabled-before"
    touch "$harness/lock-changed"
    lock_device shell locksettings set-disabled false >/dev/null 2>&1
    if lock_device shell locksettings set-pin "$lock_pin" 2>&1 | grep -q -i 'password set\|pin set\|set to'; then
        touch "$harness/credential-set"
    else
        lock_check "the leg holds a lock credential of its own" 0 "the emulator already had a credential, or set-pin was refused"
        lock_screen_restore_check
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
    local muted_ok=0 found_mute=""
    if lock_control Mute "$dump"; then
        found_mute="Mute was pressed on the lock screen;"
        lock_wait 10 lock_record_has '"Unmute"' && found_mute="$found_mute the notification offers Unmute;" || found_mute="$found_mute the notification does not offer Unmute;"
        lock_showing && found_mute="$found_mute the screen stayed locked;" || found_mute="$found_mute the screen is not locked;"
        lock_wait 10 lock_says "Microphone muted" "$dump" && found_mute="$found_mute the lock screen says the microphone is muted;" || found_mute="$found_mute the lock screen does not say so;"
        case "$found_mute" in
            *"does not"* | *"not locked"*) muted_ok=0 ;;
            *) muted_ok=1 ;;
        esac
    else
        found_mute="the Mute control was not on the lock screen"
    fi
    lock_check "Mute from the lock screen mutes the call with no unlock" "$muted_ok" "${found_mute# }"

    # Unmute, from the locked screen: the system asks for the credential and the call stays muted.
    local asked=0 found=""
    if lock_control Unmute "$dump"; then
        sleep 3
        lock_dump "$artefacts/lock-screen/locked-2-unmute.xml"
        lock_still 3-unmute-asks
        lock_showing && found="$found the screen is still locked;" || found="$found the screen is not locked;"
        lock_record_has '"Unmute"' && found="$found the notification still offers Unmute;" || found="$found the notification no longer offers Unmute;"
        if python3 -I "$here/scripts/lib/ui-node.py" ids "$artefacts/lock-screen/locked-2-unmute.xml" "" | grep -q -i 'pin'; then
            found="$found the credential prompt shows;"
        else
            found="$found no credential prompt shows;"
        fi
        case "$found" in
            *"not locked"* | *"no longer"* | *"no credential"*) asked=0 ;;
            *) asked=1 ;;
        esac
    else
        found="the Unmute control was not on the lock screen"
    fi
    lock_check "Unmute from the lock screen asks for the unlock and leaves the call muted" "$asked" "${found# }"
    # The person unlocks: the unmute then goes through. The device's own clock, as the application's
    # record of the microphone is, is read between typing the credential and submitting it: the
    # earliest instant the unlock can happen.
    lock_device shell input text "$lock_pin"
    lock_device shell date +%s%N >"$harness/unlock-at.txt"
    lock_device shell input keyevent KEYCODE_ENTER
    if lock_wait 15 lock_record_has '"Mute"'; then
        lock_check "Unmute goes through once the screen is unlocked" 1 "the notification offers Mute again"
    else
        lock_check "Unmute goes through once the screen is unlocked" 0 "the notification still offers Unmute"
    fi

    # Stop, from the locked screen.
    local armed=0 tapped=0 gone=0 waited=0
    if lock_the_screen && [ -n "$(lock_record)" ]; then armed=1; fi
    lock_still 4-locked-again
    if [ "$armed" = 1 ] && lock_control Stop "$dump"; then tapped=1; fi
    while [ "$tapped" = 1 ] && [ "$waited" -lt 15 ]; do
        if [ -z "$(lock_record)" ]; then gone=1; break; fi
        sleep 1
        waited=$((waited + 1))
    done
    if [ "$gone" = 1 ] && lock_showing; then
        lock_check "Stop from the lock screen ends the call with no unlock" 1 "the screen was locked with the notification on it, Stop was pressed there, the notification is gone and the screen is still locked"
    else
        lock_check "Stop from the lock screen ends the call with no unlock" 0 "locked with the notification on it: $armed; Stop pressed: $tapped; notification gone: $gone"
        lock_stop_through_the_shade
    fi
    lock_screen_restore_check
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
detail = line.split("detail=", 1)[-1]
# Each change is `<state>@<first look at the new state>/<last look at the earlier one>`.
steps = re.findall(r"(open|muted)@(\d+)/(\d+)", detail)
order = [word for word, _, _ in steps]
# The call's own screen muted and unmuted it first, and then the lock screen did.
if order != ["open", "muted", "open", "muted", "open"] or not unlock_ns.isdigit():
    print("0 %s" % (detail or "no record"))
else:
    # The microphone reopened after the last look that still saw it muted. If that look was made at or
    # after the credential was submitted, the reopen came after it: no look, however late, can place it
    # earlier.
    unlocked = int(unlock_ns) // 1_000_000
    last_muted_look = int(steps[4][2])
    ok = last_muted_look >= unlocked
    print("%d the microphone was still muted %d ms after the leg submitted the credential and was seen open %d ms after it" % (ok, last_muted_look - unlocked, int(steps[4][1]) - unlocked))
PY
)"
    lock_check "the microphone stayed muted until the unlock" "${verdict%% *}" "${verdict#* }"
}
