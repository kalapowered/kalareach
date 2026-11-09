#!/usr/bin/env bash
# The Android virtual device that KalaReach's device scripts start.
#
# Source this file and call `kr_android_avd <the emulator program>`. The device is KalaReach's own,
# KalaReach_API_36_Play: API 36 with Google Play, 16 KB pages and a 16 GB data partition, and it is
# the only one. KR_ANDROID_AVD may repeat its name; naming another is refused. Every other virtual
# device on a machine belongs to other work, so no script takes the first one listed, a default that
# is someone else's or a name from the environment, and none starts, installs into, wipes or changes
# one.
#
# On success the function prints the device's name and returns 0. When KR_ANDROID_AVD names another
# device, when the emulator does not list the device, or there is no emulator, it prints the reason,
# which names the device, and returns 3, the scripts' status for "nothing to run on". A caller takes
# either text with `avd="$(kr_android_avd "$emulator")"` and tells them apart by the status.
#
# A script that starts the device on a serial of its own then reads `kr_android_device_name <adb>
# <serial>`, the name the device that answers on the serial reports, and goes on only when it is the
# one it started, before it installs into the device, changes a setting of it or stops it: a device
# that took the serial between the script's check that it was free and the boot is someone else's.

kr_android_avd() {
    local emulator=$1 avd=KalaReach_API_36_Play listed line
    if [ -n "${KR_ANDROID_AVD:-}" ] && [ "$KR_ANDROID_AVD" != "$avd" ]; then
        printf 'KR_ANDROID_AVD names %s, which is not KalaReach'\''s virtual device: only %s is started, and no other virtual device is started, installed into or changed\n' "$KR_ANDROID_AVD" "$avd"
        return 3
    fi
    if [ ! -x "$emulator" ]; then
        printf 'there is no Android emulator at %s\n' "$emulator"
        return 3
    fi
    # Read whole and then searched: a pipe into a search that stops at the first match would end
    # the emulator's output early, which a script that sets pipefail takes for a failure.
    listed="$("$emulator" -list-avds 2>/dev/null)" || true
    while IFS= read -r line; do
        if [ "${line%$'\r'}" = "$avd" ]; then
            printf '%s\n' "$avd"
            return 0
        fi
    done <<<"$listed"
    printf 'the Android virtual device %s is not available here (the emulator lists the ones under ANDROID_AVD_HOME): create it with avdmanager (API 36 with Google Play, 16 KB pages, a 16 GB data partition); no other virtual device is started\n' "$avd"
    return 3
}

# Prints the name of the virtual device that answers on `serial`, or nothing when it says none.
kr_android_device_name() { # <adb> <serial>
    "$1" -s "$2" emu avd name 2>/dev/null | tr -d '\r' | sed -n 1p || true
}
