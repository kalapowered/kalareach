#!/usr/bin/env bash
# The Android virtual device that KalaReach's device scripts start.
#
# Source this file and call `kr_android_avd <the emulator program>`. The device is KalaReach's own,
# KalaReach_API_36_Play: API 36 with Google Play, 16 KB pages and a 16 GB data partition.
# KR_ANDROID_AVD names another virtual device made for KalaReach. Every other virtual device on a
# machine belongs to other work, so no script takes the first one listed or a default that is
# someone else's, and none starts, installs into, wipes or changes one.
#
# On success the function prints the device's name and returns 0. When the emulator does not list
# the device, or there is no emulator, it prints the reason, which names the device, and returns 3,
# the scripts' status for "nothing to run on". A caller takes either text with
# `avd="$(kr_android_avd "$emulator")"` and tells them apart by the status.

kr_android_avd() {
    local emulator=$1 avd="${KR_ANDROID_AVD:-KalaReach_API_36_Play}" listed line
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
    printf 'the Android virtual device %s is not available here (the emulator lists the ones under ANDROID_AVD_HOME): create it with avdmanager (API 36 with Google Play, 16 KB pages, a 16 GB data partition) or name another made for KalaReach in KR_ANDROID_AVD; no other virtual device is started\n' "$avd"
    return 3
}
