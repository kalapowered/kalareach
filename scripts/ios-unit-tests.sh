#!/usr/bin/env bash
# Runs the iOS application's native unit tests in an iOS Simulator: the `KalaReachNativeTests`
# scheme of the generated Xcode project, which builds the native decisions without the application.
#
#   scripts/ios-unit-tests.sh [--results=<file>] [-- <xcodebuild arguments>]
#
#   --results=<file>   Where the tests' result tree is written, as `xcrun xcresulttool get
#                      test-results tests` prints it, whatever xcodebuild's exit status. The result
#                      bundle itself is kept beside it, with `.xcresult` for `.json`. The
#                      conformance report reads the file. An earlier file and bundle of those names
#                      are replaced; a path that is not a file is refused.
#   --                 What follows goes to xcodebuild after the scheme, for example
#                      `-only-testing:KalaReachNativeTests/<Class>/<method>`. The simulator is this
#                      script's choice, so a `-destination` among them is refused.
#
# The exit status is xcodebuild's. It needs Xcode with an iOS Simulator runtime, and a network to
# fetch the Swift packages the project pins. Those are fetched at the versions the project's
# `Package.resolved` records and never resolved again, so the run leaves the file as it found it.
#
# The tests are built with the newest Xcode that is installed under a versioned name
# (`/Applications/Xcode_<version>.app`, as a hosted runner has them) or is the one selected, by its
# own version and build number, because the default Xcode of such a runner is older than the Swift
# the tests need. DEVELOPER_DIR names another. The simulator is the newest iPhone the scheme can
# use with that Xcode. One that this script boots is shut down when it ends, and the build's files
# are removed.

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
            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 2
            ;;
        *)
            echo "ios-unit-tests: unknown argument $1" >&2
            exit 2
            ;;
    esac
    shift
done

for argument in ${xcode_arguments[@]+"${xcode_arguments[@]}"}; do
    if [ "$argument" = "-destination" ]; then
        echo "ios-unit-tests: the simulator is this script's choice, so -destination is refused" >&2
        exit 2
    fi
done

# The path stays the same when the script changes directory.
case "$results" in
    "" | /*) ;;
    *) results="$PWD/$results" ;;
esac

for tool in xcodebuild xcrun python3; do
    command -v "$tool" > /dev/null 2>&1 || { echo "ios-unit-tests: $tool is needed and is not on the path" >&2; exit 2; }
done

if [ -z "${DEVELOPER_DIR:-}" ]; then
    newest="$(python3 -I - <<'PYTHON'
import glob
import os
import re
import subprocess

best = None
candidates = []
for application in glob.glob("/Applications/Xcode_*.app"):
    # A hosted runner names each Xcode by version and links other names to the same one.
    if os.path.islink(application) or not re.fullmatch(r"/Applications/Xcode_[0-9.]+\.app", application):
        continue
    candidates.append(application + "/Contents/Developer")
# The Xcode the machine has selected competes too, so that a Mac with its own Xcode beside a
# versioned one is not made to use the older.
selected = subprocess.run(["xcode-select", "-p"], capture_output=True, text=True).stdout.strip()
if selected:
    candidates.append(selected)
for developer in candidates:
    try:
        said = subprocess.run([developer + "/usr/bin/xcodebuild", "-version"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        continue
    found = re.match(r"Xcode ([0-9.]+)\s+Build version (\S+)", " ".join(said.split()))
    if not found:
        continue
    key = (tuple(int(part) for part in found.group(1).split(".")), found.group(2))
    if best is None or key > best[0]:
        best = (key, developer)
if best:
    print(best[1])
PYTHON
)"
    if [ -n "$newest" ]; then
        export DEVELOPER_DIR="$newest"
    fi
fi

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

if [ -n "$results" ]; then
    if [ -e "$results" ] && [ ! -f "$results" ]; then
        echo "ios-unit-tests: $results is not a file, and this script replaces what it writes there" >&2
        exit 2
    fi
    bundle_kept="${results%.json}.xcresult"
    rm -f "${results:?}"
    rm -rf "${bundle_kept:?}"
fi

cd "$project_directory"
derived=(-derivedDataPath "$work/DerivedData")

# The packages at the versions the project records, fetched into this run's own directory. The
# destinations are asked for after this, with the same directory and no further resolving, so that
# nothing resolves the packages to other versions and rewrites the file that pins them.
xcodebuild -resolvePackageDependencies -onlyUsePackageVersionsFromResolvedFile \
    -project "$project" -scheme "$scheme" "${derived[@]}"

destinations="$(xcodebuild -project "$project" -scheme "$scheme" "${derived[@]}" \
    -disableAutomaticPackageResolution -showdestinations)"
chosen="$(printf '%s\n' "$destinations" | python3 -I -c '
import re
import sys

# Only the simulators the scheme can run on: a physical device, a placeholder and an ineligible
# destination are not.
best = None
for line in sys.stdin:
    if "Ineligible destinations" in line:
        break
    found = re.search(r"platform:iOS Simulator, arch:\S+, id:([0-9A-F-]{36}), OS:([0-9.]+), name:(iPhone[^}]*?) \}", line)
    if not found or "error:" in line:
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
echo "kr-tool: simulator: $chosen_name, iOS $chosen_os"
if ! xcrun simctl list devices booted | grep -q "$chosen_udid"; then
    booted_here="$chosen_udid"
fi

status=0
xcodebuild test -project "$project" -scheme "$scheme" \
    -destination "platform=iOS Simulator,id=$chosen_udid" "${derived[@]}" \
    -resultBundlePath "$work/ios.xcresult" -disableAutomaticPackageResolution \
    ${xcode_arguments[@]+"${xcode_arguments[@]}"} || status=$?

if [ -n "$results" ] && [ -d "$work/ios.xcresult" ]; then
    mkdir -p "$(dirname "$results")"
    xcrun xcresulttool get test-results tests --path "$work/ios.xcresult" --compact > "$results" || rm -f "$results"
    cp -R "$work/ios.xcresult" "$bundle_kept"
    # The runtime's own build, which the result tree records for the device it ran on.
    if [ -f "$results" ]; then
        echo "kr-tool: simulator-runtime: $(python3 -I -c '
import json
import sys

devices = json.load(open(sys.argv[1])).get("devices") or [{}]
print(devices[0].get("osBuildNumber", "unknown"))
' "$results")"
    fi
fi
exit "$status"
