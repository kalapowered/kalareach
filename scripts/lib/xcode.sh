#!/usr/bin/env bash
# The Xcode the iOS scripts build with.
#
# Source this file and call `kr_select_xcode`. Unless DEVELOPER_DIR already names one, it exports
# DEVELOPER_DIR for the newest Xcode that is installed under a versioned name
# (`/Applications/Xcode_<version>.app`, as a hosted runner has them) or is the one selected, by its
# own version and build number. The default Xcode of a hosted runner is older than the Swift the
# application's tests need, so the newest one builds them.
#
# `kr_shared_packages` sets the array `kr_package_options` to the xcodebuild options that put the
# Swift packages in one folder that every build shares, when KR_IOS_PACKAGES names one, and to
# nothing otherwise. A build fetches 1.3 GB of packages into a tree of its own unless it is given
# a folder. The folder has to be an absolute path, and the options name its resolved path. A build
# that is given it uses the package versions the project's `Package.resolved` records, so the shared
# folder never moves a pin. Only the build and the tools it starts, which are children of the
# terminal, read the folder, as long as the scheme's test run loads no package product: the UI-test
# scheme the device scripts build links none. A scheme whose tests load a package (the native unit
# tests link WebRTC) keeps its own folder, since the simulator's test agent then reads the package
# from it, and from an external volume that is an access the person would be asked about.
#
# `kr_with_packages_lock <command...>` runs the command, and while KR_IOS_PACKAGES names a folder it
# holds that folder's lock, named from its resolved path, for the whole command, and waits for it
# for at most half an hour. Two builds that fetch into one empty folder at the same time break each
# other (SwiftPM takes no lock of its own there), so a command that may fetch runs under it. The
# lock is released when the command ends, however it ends.

kr_shared_packages() {
    kr_package_options=()
    if [ -z "${KR_IOS_PACKAGES:-}" ]; then
        return 0
    fi
    case "$KR_IOS_PACKAGES" in
        /*) ;;
        *)
            echo "KR_IOS_PACKAGES has to name an absolute path, and holds $KR_IOS_PACKAGES" >&2
            return 2
            ;;
    esac
    mkdir -p "$KR_IOS_PACKAGES" || return 2
    local folder
    folder="$(cd "$KR_IOS_PACKAGES" && pwd -P)" || return 2
    # shellcheck disable=SC2034 # read by the scripts that source this file
    kr_package_options=(-clonedSourcePackagesDirPath "$folder" -onlyUsePackageVersionsFromResolvedFile)
}

kr_with_packages_lock() {
    if [ -z "${KR_IOS_PACKAGES:-}" ]; then
        "$@"
        return
    fi
    local folder
    folder="$(cd "$KR_IOS_PACKAGES" && pwd -P)" || { echo "the folder KR_IOS_PACKAGES names is not there" >&2; return 2; }
    /usr/bin/lockf -k -t 1800 "$folder.lock" "$@"
}

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
