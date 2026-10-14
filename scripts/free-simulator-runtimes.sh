#!/usr/bin/env bash
# Removes the Xcode simulator runtimes from a GitHub-hosted macOS runner, with their dyld shared
# caches, so that the job's builds and test runs have the disk to themselves.
#
#   scripts/free-simulator-runtimes.sh [--keep-newest-ios]
#
# The runner image carries a simulator runtime for each Xcode platform and release it ships with:
# five for iOS, three for tvOS, three for watchOS and five for visionOS, about 113 GB of disk
# images, and about 54 GB of dyld shared caches made from them. That is more than half of the data
# volume, and what is left of it is what the workspace's test build, about 35 GB, has to fit in.
#
# A job that builds and tests Rust on the host, and drives no simulator, uses none of them. A job
# that does, such as the conformance report's iOS unit tests, keeps the newest iOS runtime with
# --keep-newest-ios: the tests pick the newest iPhone simulator that the newest installed Xcode can
# run, which is a simulator of that runtime, so removing every older one and every other platform's
# changes nothing about the choice. The cache of a runtime that stays is left alone.
#
# This changes the machine it runs on, so it refuses to run anywhere but a GitHub-hosted runner,
# whose disk is the job's own and is gone when the job ends. A runtime that cannot be removed is
# named in a warning and left; the free space is printed before and after.

set -euo pipefail

keep_newest_ios=0
case "${1:-}" in
    "") ;;
    --keep-newest-ios) keep_newest_ios=1 ;;
    *)
        echo "usage: free-simulator-runtimes.sh [--keep-newest-ios]" >&2
        exit 2
        ;;
esac

if [ "$(uname -s)" != Darwin ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
    echo "free-simulator-runtimes: this removes software from the machine it runs on, and runs only on a GitHub-hosted macOS runner" >&2
    exit 2
fi

volume=/System/Volumes/Data
echo "== before: $(df -h "$volume" | awk 'NR == 2 { print $4 " free of " $2 }')"
xcrun simctl runtime list || true

# The identifiers of the runtimes to remove, one to a line.
doomed="$(xcrun simctl runtime list -j | python3 -I -c '
import json
import sys

keep_newest_ios = sys.argv[1] == "1"
runtimes = json.load(sys.stdin).values()

def version(runtime):
    return tuple(int(part) for part in runtime["version"].split("."))

kept = set()
if keep_newest_ios:
    phones = [r for r in runtimes if r["platformIdentifier"] == "com.apple.platform.iphonesimulator"]
    if phones:
        newest = max(version(r) for r in phones)
        kept = {r["identifier"] for r in phones if version(r) == newest}
for runtime in runtimes:
    if runtime["identifier"] not in kept:
        print(runtime["identifier"])
' "$keep_newest_ios")"

removed=0
for identifier in $doomed; do
    started=$SECONDS
    # The cache goes with the runtime that made it, and a runtime that stays keeps its own.
    xcrun simctl runtime dyld_shared_cache remove "$identifier" || echo "no cache removed for $identifier"
    if xcrun simctl runtime delete "$identifier"; then
        removed=$((removed + 1))
        echo "removed $identifier in $((SECONDS - started)) s"
    else
        echo "::warning::the simulator runtime $identifier could not be removed"
    fi
done
echo "removed $removed of $(printf '%s\n' "$doomed" | grep -c .) simulator runtimes"

echo "== after: $(df -h "$volume" | awk 'NR == 2 { print $4 " free of " $2 }')"
xcrun simctl runtime list || true
du -skx /Library/Developer/CoreSimulator/Caches 2> /dev/null | awk '{ printf "the simulators'"'"' caches that remain: %.1f GiB\n", $1 / 1048576 }' || true
