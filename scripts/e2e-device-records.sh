#!/usr/bin/env bash
#
# Runs the companion's device records on the iOS Simulator, with the real application: the
# pairing records open, the secure store keeps an item across a relaunch, the device's own attempt
# budget keeps its count and its boot identity across a relaunch and spends a code once the boot
# record is gone, and the directories of the pairing records are kept out of the device's backup.
#
# A debug build of the application reads a request from its data directory when it starts and
# writes one line per check beside it (companion-tauri's `device_probe`). This script builds that
# application, starts one simulator, and launches the application three times in the same boot of
# the simulator, after a first start of the fresh installation (below):
#
#   1. writes an item to the secure store and charges one try against a code
#   2. reads the item back and deletes it; the same code has one try fewer and the boot identity
#      is the first launch's
#   3. after the script has deleted the boot record from the application's caches: the item is
#      gone, the boot identity is another, and the same code is refused as spent
#
# The first start has no request and no data directory: a new installation has none, and the
# application makes it. It shows that the application makes the data directory and the two record
# directories there and marks both of them as excluded from the backup, as the host's `xattr`
# reads them. It does not show the records open: the probe's request needs the data directory, so
# the launches below are the ones that report the records open. The three launches run within four
# minutes of one another, so that a refusal in the last cannot be the five-minute window ending.
#
# It claims what the lines say and nothing more: a check the application did not report is a check
# that did not run, and any line that is not `ok=1`, a launch that never says `done=1`, or an
# identity that does not behave as above fails the run. A simulator shares the Mac's clocks, so
# this shows a relaunch and a record that is gone; it cannot show a reboot of the phone.
#
# A simulator only inside the Mac's device lease, and a build inside a build slot:
#
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-device-records.sh
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
app_id=to.kala.reach
device="${KR_IOS_DEVICE:-iPhone 17 Pro}"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/device-records-ios"
mkdir -p "${artefacts:?}"
run="$(uuidgen)"
item="$(uuidgen)"
log="$artefacts/run.log"
: >"${log:?}"

say() { printf '== [device-records] %s\n' "$*" | tee -a "$log"; }

udid="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" udid "$device")"
[ -n "$udid" ] || { say "no iOS simulator named $device"; exit 3; }

say "building the debug application for the simulator"
# No push: the build names no Firebase configuration.
printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$companion/src-tauri/gen/apple/Local.xcconfig"
rm -rf "${companion:?}/src-tauri/gen/apple/build"
( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
    || { say "the build failed; see $artefacts/build.log"; exit 2; }
app="$companion/src-tauri/gen/apple/build/arm64-sim/KalaReach.app"
[ -d "$app" ] || { say "the build left no application"; exit 2; }

# The application declares the system boot time it reads, with the reason that matches the use.
manifest="$app/PrivacyInfo.xcprivacy"
if [ -f "$manifest" ] && plutil -p "$manifest" | grep -q 'NSPrivacyAccessedAPICategorySystemBootTime' \
    && plutil -p "$manifest" | grep -q '"35F9.1"'; then
    say "the application's bundle carries its privacy manifest, with the system boot time reason"
else
    say "the application's bundle carries no privacy manifest that declares the system boot time"
    exit 2
fi

say "starting the simulator $device"
xcrun simctl boot "$udid" >/dev/null 2>&1
xcrun simctl bootstatus "$udid" -b >/dev/null 2>&1
xcrun simctl uninstall "$udid" "$app_id" >/dev/null 2>&1
xcrun simctl install "$udid" "$app" || { say "the application did not install"; exit 2; }

data="$(xcrun simctl get_app_container "$udid" "$app_id" data)"
support="$data/Library/Application Support/$app_id"
caches="$data/Library/Caches/$app_id"
directory="$support/kr-probe"
failed=0

# A fresh installation: nothing of the application's has been made in its container.
[ ! -e "$support" ] || { say "the fresh installation already has $support"; exit 2; }
say "first start, in a container with no data directory"
xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; exit 2; }
excluded() { xattr -l "$1" 2>/dev/null | grep -q 'com_apple_backup_excludeItem'; }
# Until both directories exist and read as excluded: the application makes each before it marks it.
waited=0
while ! { [ -d "$support/pairing" ] && excluded "$support/pairing" \
    && [ -d "$support/pairing-budget" ] && excluded "$support/pairing-budget"; }; do
    sleep 2
    waited=$((waited + 2))
    [ "$waited" -lt 60 ] || break
done
for name in pairing pairing-budget; do
    if [ -d "$support/$name" ] && excluded "$support/$name"; then
        say "after the first start of a new installation, $name exists and is excluded from the backup"
    else
        say "after the first start of a new installation, $name is missing or not excluded from the backup"
        failed=1
    fi
done
xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
mkdir -p "$directory"
started=$SECONDS

# Launches the application once and reads what it wrote.
launch() { # <n> <secret> <tries left or "null">
    local n=$1 secret=$2 tries=$3 result="$directory/device-result-$run-$1.txt" waited=0
    printf '{"run":"%s","launch":%s,"item":"%s","secret":"%s","tries_left":%s}\n' \
        "$run" "$n" "$item" "$secret" "$tries" >"$directory/device-request.json"
    say "launch $n"
    xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; failed=1; return; }
    while ! grep -qs '^done=1$' "$result"; do
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -lt 120 ] || break
    done
    cp "$result" "$artefacts/launch-$n.txt" 2>/dev/null
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    if ! grep -qs '^done=1$' "$result"; then
        say "launch $n never said it was done"
        xcrun simctl spawn "$udid" log show --last 5m --style compact \
            --predicate 'process == "KalaReach"' 2>/dev/null | tail -100 >"$artefacts/application-$n.log"
        failed=1
        return
    fi
    local line name
    while IFS= read -r line; do
        say "launch $n: $line"
        case "$line" in
            check=*" ok=1 "*) ;;
            check=*) failed=1 ;;
        esac
    done <"$result"
    # Each check the launch is claimed to make was made, once: a check that is missing proves nothing.
    for name in "the pairing records open" "secret store" "the boot identity" "budget" \
        "the paired hosts are out of the backup" "the budget is out of the backup"; do
        [ "$(grep -c "^check=$name ok=" "$result")" = 1 ] || { say "launch $n did not report \"$name\" once"; failed=1; }
    done
}

digest() { sed -n 's/^check=the boot identity ok=1 detail=digest \(.*\)$/\1/p' "$artefacts/launch-$1.txt"; }

launch 1 write 4
say "the boot record after launch 1: $(ls "$caches" 2>&1 | tr '\n' ' ')"
[ -f "$caches/pairing-boot" ] || { say "launch 1 left no boot record in the caches"; failed=1; }
launch 2 read_and_delete 3
rm -f "$caches/pairing-boot"
launch 3 absent null

elapsed=$((SECONDS - started))
say "the three launches took $elapsed s"
[ "$elapsed" -lt 240 ] || { say "the launches took four minutes or more, so a refusal at the end may be the window's"; failed=1; }
first="$(digest 1)"
second="$(digest 2)"
third="$(digest 3)"
say "boot identity digests: $first $second $third"
[ -n "$first" ] && [ "$first" = "$second" ] || { say "a relaunch in the same boot changed the boot identity"; failed=1; }
[ -n "$third" ] && [ "$third" != "$first" ] || { say "a deleted boot record did not give another boot identity"; failed=1; }
[ -f "$caches/pairing-boot" ] || { say "launch 3 left no boot record in the caches"; failed=1; }
for name in pairing pairing-budget; do
    say "backup attributes of $name: $(xattr -l "$support/$name" 2>&1 | tr '\n' ' ')"
done

xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
if [ "$failed" = 0 ]; then
    say "every check passed"
    exit 0
fi
say "a check did not pass"
exit 2
