#!/usr/bin/env bash
# Runs the Android application's native unit tests: the `:krnative` Gradle module, which is plain
# Kotlin on the Java virtual machine and needs no device, no emulator and no Android SDK.
#
#   scripts/android-unit-tests.sh [--results=<directory>] [-- <Gradle arguments>]
#
#   --results=<directory>   A directory the JUnit files Gradle wrote are copied into, whatever
#                           Gradle's exit status; the `TEST-*.xml` files it already holds are
#                           replaced. The conformance report reads them there.
#   --                      What follows goes to Gradle after the task, for example
#                           `--tests to.kala.reach.companion.mobile.VoiceCaptureGateTest.<method>`.
#
# The exit status is Gradle's. It needs a JDK (17 or newer), `cargo` with the pinned toolchain,
# which the build asks for the Android TLS verifier's repository, and a network.
#
# Gradle reads two files Tauri's build writes when it packages the application, and a checkout that
# has not packaged it has neither. The module under test needs neither, so a missing one is written
# here as a comment and taken away again when the script ends; a developer's own are never touched.
# Gradle and Kotlin run in this script's processes and leave none behind.

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="$root/apps/companion/src-tauri/gen/android"

results=""
gradle_arguments=()
while [ $# -gt 0 ]; do
    case "$1" in
        --results=*) results="${1#--results=}" ;;
        --)
            shift
            gradle_arguments=("$@")
            break
            ;;
        -h|--help)
            sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 2
            ;;
        *)
            echo "android-unit-tests: unknown argument $1" >&2
            exit 2
            ;;
    esac
    shift
done

if ! command -v cargo > /dev/null 2>&1; then
    echo "android-unit-tests: cargo is needed and is not on the path" >&2
    exit 2
fi

written=()
# shellcheck disable=SC2329 # run by the trap below
cleanup() {
    local file
    for file in ${written[@]+"${written[@]}"}; do
        rm -f "${file:?}"
    done
}
trap cleanup EXIT

for file in tauri.settings.gradle app/tauri.build.gradle.kts; do
    if [ ! -e "$project/$file" ] && [ ! -L "$project/$file" ]; then
        printf '%s\n' '// Written by scripts/android-unit-tests.sh for a build that has not packaged the application.' > "$project/$file"
        written+=("$project/$file")
    fi
done

# What the tests run with, as Gradle itself reports it.
version="$(cd "$project" && ./gradlew --no-daemon --console=plain --version)"
echo "kr-tool: gradle: $(printf '%s\n' "$version" | awk '/^Gradle /{ print $2; exit }')"
echo "kr-tool: java: $(printf '%s\n' "$version" | sed -n 's/^Launcher JVM: *//p' | head -n 1)"

# Nothing an earlier run left can be read as this run's.
rm -rf "${project:?}/build/krnative/test-results"

status=0
(
    cd "$project"
    ./gradlew --no-daemon --console=plain -Pkotlin.compiler.execution.strategy=in-process \
        :krnative:test --rerun ${gradle_arguments[@]+"${gradle_arguments[@]}"}
) || status=$?

if [ -n "$results" ]; then
    mkdir -p "$results"
    rm -f "${results:?}"/TEST-*.xml
    cp "$project"/build/krnative/test-results/test/*.xml "$results"/ 2> /dev/null || true
fi
exit "$status"
