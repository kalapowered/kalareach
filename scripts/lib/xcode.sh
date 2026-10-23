#!/usr/bin/env bash
# The Xcode the iOS scripts build with.
#
# Source this file and call `kr_select_xcode`. Unless DEVELOPER_DIR already names one, it exports
# DEVELOPER_DIR for the newest Xcode that is installed under a versioned name
# (`/Applications/Xcode_<version>.app`, as a hosted runner has them) or is the one selected, by its
# own version and build number. The default Xcode of a hosted runner is older than the Swift the
# application's tests need, so the newest one builds them.

kr_select_xcode() {
    local newest
    if [ -n "${DEVELOPER_DIR:-}" ]; then
        return 0
    fi
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
}
