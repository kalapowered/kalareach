#!/usr/bin/env bash
# Removes the Xcode simulator runtimes from a GitHub-hosted macOS runner, so that the job's builds
# and test runs have the disk to themselves.
#
#   scripts/free-simulator-runtimes.sh [--keep-ios]
#
# The runner image carries a simulator runtime for each Xcode platform and release it ships with:
# five for iOS, three for tvOS, three for watchOS and five for visionOS, 113 GB of disk images in
# all, which is more than a third of the data volume. What is left of the volume is what the
# workspace's test build, which takes more than 40 GB at its peak, has to fit in.
#
# A job that builds and tests Rust on the host, and drives no simulator, uses none of them. A job
# that drives iOS simulators keeps every iOS runtime with --keep-ios, so that Xcode chooses among
# the same simulators as on an image left as it was, and loses only the platforms it never uses.
# Removing a runtime also removes the dyld shared cache made from it.
#
# This changes the machine it runs on, so it refuses to run anywhere but a GitHub-hosted runner,
# whose disk is the job's own and is gone when the job ends. Freeing the disk is best effort: a
# runtime that cannot be removed, or a listing that cannot be read, is named in a warning and the
# job goes on, and the free space is printed before and after.

set -euo pipefail

keep_ios=0
case "${1:-}" in
    "") ;;
    --keep-ios) keep_ios=1 ;;
    *)
        echo "usage: free-simulator-runtimes.sh [--keep-ios]" >&2
        exit 2
        ;;
esac

if [ "$(uname -s)" != Darwin ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo "free-simulator-runtimes: this removes software from the machine it runs on, and runs only on a GitHub-hosted macOS runner" >&2
    exit 2
fi

volume=/System/Volumes/Data
started_all=$SECONDS
free() {
    df -h "$volume" | awk 'NR == 2 { print $4 " free of " $2 }'
}
echo "== before: $(free)"

# The identifiers of the runtimes to remove, one to a line.
if ! listing="$(xcrun simctl runtime list -j)"; then
    echo "::warning::the simulator runtimes could not be listed, so none was removed"
    exit 0
fi
if ! doomed="$(python3 -I -c '
import json
import sys

keep_ios = sys.argv[1] == "1"
for runtime in json.load(sys.stdin).values():
    if keep_ios and runtime["platformIdentifier"] == "com.apple.platform.iphonesimulator":
        continue
    print(runtime["identifier"])
' "$keep_ios" <<< "$listing")"; then
    echo "::warning::the simulator runtimes could not be read, so none was removed"
    exit 0
fi
xcrun simctl runtime list || true

removed=0
asked=""
for identifier in $doomed; do
    if xcrun simctl runtime delete "$identifier"; then
        removed=$((removed + 1))
        asked="$asked $identifier"
    else
        echo "::warning::the simulator runtime $identifier could not be removed"
    fi
done
echo "asked for $removed simulator runtimes to be removed"

# Removal goes on after the command returns, and the room comes back as the images go. The build
# waits until a listing that was read no longer holds any runtime that was asked for, so that it
# does not compete with the removal for the disk and so that the figures printed after this step
# are the last ones. A listing that cannot be read is tried again until the deadline.
deadline=$((SECONDS + 300))
while :; do
    if now="$(xcrun simctl runtime list -j 2> /dev/null)"; then
        pending=0
        for identifier in $asked; do
            case "$now" in
                *"\"$identifier\""*) pending=$((pending + 1)) ;;
            esac
        done
        [ "$pending" -eq 0 ] && break
    else
        pending="an unknown number of"
    fi
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "::warning::$pending simulator runtimes were still listed five minutes after they were asked to be removed"
        break
    fi
    sleep 5
done

echo "== after, $((SECONDS - started_all)) s later: $(free)"
xcrun simctl runtime list || true
