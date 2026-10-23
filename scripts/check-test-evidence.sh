#!/usr/bin/env bash
# Holds that the screenshots of a test run were kept in the run's evidence directory.
#
#   scripts/check-test-evidence.sh <evidence directory> <subdirectory> [<directory to search for strays>]
#
# Section 21 collects the screenshots of the tests into one directory, `KR_TEST_ARTIFACTS_DIR`,
# which the landing workflow uploads as the run's evidence. A test that writes its picture
# somewhere else loses it with the runner, and a run that kept no picture at all would still upload
# an empty directory without complaint. This fails when
#
#   * there is no PNG image under `<evidence directory>/<subdirectory>`, or
#   * a file named `kr-*.png` lies directly in the directory searched for strays, which is the
#     system's temporary directory (`/tmp/`) unless one is given: the name the browser tests give
#     their pictures, written where the run would lose them.
#
# Exit status: 0 when both hold, 1 when one does not, 2 for a usage fault.

set -euo pipefail

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
    echo "usage: check-test-evidence.sh <evidence directory> <subdirectory> [<directory to search for strays>]" >&2
    exit 2
fi
evidence="$1/$2"
strays_in="${3:-/tmp/}"

count=0
if [ -d "$evidence" ]; then
    count="$(find "$evidence" -name '*.png' | wc -l | tr -d ' ')"
fi
echo "$count screenshots under $evidence"
if [ "$count" -eq 0 ]; then
    echo "::error::the tests kept no screenshot under $evidence"
    exit 1
fi

stray="$(find "$strays_in" -maxdepth 1 -name 'kr-*.png')"
if [ -n "$stray" ]; then
    echo "::error::screenshots were written outside the evidence directory:"
    echo "$stray"
    exit 1
fi
echo "none outside it, in $strays_in"
