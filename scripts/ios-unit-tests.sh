#!/usr/bin/env bash
# Runs the iOS application's native unit tests in an iOS Simulator: the `KalaReachNativeTests`
# scheme of the generated Xcode project, which builds the native decisions without the application.
#
#   scripts/ios-unit-tests.sh [--results=<file>] [-- <xcodebuild arguments>]
#
#   --results=<file>   Where the tests' result tree is written, as `xcrun xcresulttool get
#                      test-results tests` prints it, whatever xcodebuild's exit status. The result
#                      bundle itself is kept beside it, with `.xcresult` for `.json`. The
#                      conformance report reads the file.
#   --                 What follows goes to xcodebuild after the scheme, for example
#                      `-only-testing:KalaReachNativeTests/<Class>/<method>`. A `-destination` among
#                      them replaces the simulator this script chooses.
#
# The exit status is xcodebuild's. It needs Xcode with an iOS Simulator runtime, and a network to
# fetch the Swift packages the project pins. Those are fetched at the versions the project's
# `Package.resolved` records and never resolved again, so the run leaves the file as it found it.
#
# The simulator is the newest iPhone the scheme can use with the selected Xcode (DEVELOPER_DIR names
# another). One that this script boots is shut down when it ends, and the build's files are removed.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project_directory="$root/apps/companion/src-tauri/gen/apple"
project="companion-tauri.xcodeproj"
scheme="KalaReachNativeTests"

results=""
xcode_arguments=()
while [ $# -gt 0 ]; do
    case "$1" in
        --results=*) results="${1#--results=}" ;;
        --)
            shift
            xcode_arguments=("$@")
            break
            ;;
        -h|--help)
            sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 2
            ;;
        *)
            echo "ios-unit-tests: unknown argument $1" >&2
            exit 2
            ;;
    esac
    shift
done

for tool in xcodebuild xcrun python3; do
    command -v "$tool" > /dev/null 2>&1 || { echo "ios-unit-tests: $tool is needed and is not on the path" >&2; exit 2; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/kr-ios-tests.XXXXXX")"
booted_here=""
# shellcheck disable=SC2329 # run by the trap below
cleanup() {
    if [ -n "$booted_here" ]; then
        xcrun simctl shutdown "$booted_here" > /dev/null 2>&1 || true
    fi
    rm -rf "${work:?}"
}
trap cleanup EXIT

echo "kr-tool: xcode: $(xcodebuild -version | paste -sd' ' -)"

destination=()
chosen_udid=""
chosen_name=""
if ! printf '%s\n' ${xcode_arguments[@]+"${xcode_arguments[@]}"} | grep -qx -- '-destination'; then
    destinations="$(cd "$project_directory" && xcodebuild -project "$project" -scheme "$scheme" -showdestinations 2> /dev/null)"
    chosen="$(printf '%s\n' "$destinations" | python3 -I -c '
import re
import sys

# Only the simulators the scheme can run on: a physical device or a placeholder has no OS field.
best = None
for line in sys.stdin:
    found = re.search(r"platform:iOS Simulator, arch:\S+, id:([0-9A-F-]{36}), OS:([0-9.]+), name:(iPhone[^}]*?) \}", line)
    if not found:
        continue
    udid, os_version, name = found.groups()
    key = (tuple(int(part) for part in os_version.split(".")), name)
    if best is None or key[0] > best[0][0] or (key[0] == best[0][0] and key[1] < best[0][1]):
        best = (key, udid, os_version, name)
if best:
    print(f"{best[1]}\t{best[2]}\t{best[3]}")
')"
    if [ -z "$chosen" ]; then
        echo "ios-unit-tests: the $scheme scheme has no iPhone simulator to run on with this Xcode" >&2
        exit 2
    fi
    IFS=$'\t' read -r chosen_udid chosen_os chosen_name <<< "$chosen"
    destination=(-destination "platform=iOS Simulator,id=$chosen_udid")
    echo "kr-tool: simulator: $chosen_name, iOS $chosen_os"
    if ! xcrun simctl list devices booted | grep -q "$chosen_udid"; then
        booted_here="$chosen_udid"
    fi
fi

[ -z "$results" ] || rm -rf "${results:?}" "${results%.json}.xcresult"

cd "$project_directory"
derived=(-derivedDataPath "$work/DerivedData")

# The packages at the versions the project records, fetched into this run's own directory.
xcodebuild -resolvePackageDependencies -onlyUsePackageVersionsFromResolvedFile \
    -project "$project" -scheme "$scheme" "${derived[@]}"

status=0
xcodebuild test -project "$project" -scheme "$scheme" \
    ${destination[@]+"${destination[@]}"} "${derived[@]}" \
    -resultBundlePath "$work/ios.xcresult" -disableAutomaticPackageResolution \
    ${xcode_arguments[@]+"${xcode_arguments[@]}"} || status=$?

if [ -n "$results" ] && [ -d "$work/ios.xcresult" ]; then
    mkdir -p "$(dirname "$results")"
    xcrun xcresulttool get test-results tests --path "$work/ios.xcresult" --compact > "$results" || rm -f "$results"
    cp -R "$work/ios.xcresult" "${results%.json}.xcresult"
fi
exit "$status"
