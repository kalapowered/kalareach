#!/usr/bin/env bash
#
# Builds the companion's release application for the iOS Simulator and holds its privacy manifests
# to the built bundle (apps/companion/scripts/privacy-manifest.mjs): every category of required
# reason API that a binary in the bundle uses is declared by the manifest of the bundle it belongs
# to, and the application's manifest declares nothing its executable does not use.
#
# The release build is the one that is held to the manifest, because it is what ships: a debug
# build links more code, and a category it uses alone is not one the application declares.
#
# A release build needs a Firebase configuration, which belongs to the account that owns the
# Firebase project and is not kept in this repository. The build here is given a throwaway one
# made for the run, with placeholder values, which the check does not read and nothing sends
# anywhere: no simulator starts and nothing is signed or uploaded. Because the build runs
# `xcodebuild` and compiles the Rust archive, run it inside a build slot on this Mac:
#
#   bash lead-scripts/with-slot.sh <label> scripts/ios-privacy-manifest.sh
#
# Exit codes: 0 the manifests hold, 1 a manifest does not hold, 2 the build failed or the check
# could not run.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
apple="$companion/src-tauri/gen/apple"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/privacy-manifest-ios"
mkdir -p "${artefacts:?}"

say() { printf '== [privacy-manifest] %s\n' "$*"; }

# The build rewrites the version in a tracked property list. Put it back when it was clean.
version_list="apps/companion/src-tauri/gen/apple/companion-tauri_iOS/Info.plist"
was_clean=0
git -C "$here" diff --quiet -- "$version_list" 2>/dev/null && was_clean=1
wrote_local=0
kept="$artefacts/Local.xcconfig.kept"
restore() {
    [ "$was_clean" = 1 ] && git -C "$here" checkout -- "$version_list" 2>/dev/null
    [ "$wrote_local" = 1 ] || return 0
    if [ -f "$kept" ]; then cp "$kept" "$apple/Local.xcconfig"; else rm -f "${apple:?}/Local.xcconfig"; fi
}
trap restore EXIT

cat >"$artefacts/GoogleService-Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>API_KEY</key><string>placeholder-for-a-build-that-sends-nothing</string>
	<key>GCM_SENDER_ID</key><string>000000000000</string>
	<key>PROJECT_ID</key><string>placeholder</string>
	<key>BUNDLE_ID</key><string>to.kala.reach</string>
	<key>GOOGLE_APP_ID</key><string>1:000000000000:ios:0000000000000000000000</string>
</dict>
</plist>
PLIST

say "building the release application for the simulator"
rm -rf "${apple:?}/build"
# The build reads the configuration's path from Local.xcconfig, which a developer may keep for a real
# Firebase configuration or signing choices. This run writes its own and puts the developer's back.
local_config="$apple/Local.xcconfig"
rm -f "${kept:?}"
[ ! -f "$local_config" ] || cp "$local_config" "$kept"
wrote_local=1
printf 'KR_GOOGLE_SERVICE_INFO = %s\n' "$artefacts/GoogleService-Info.plist" >"$local_config"
( cd "$companion" && pnpm tauri ios build --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
    || { say "the build failed; see $artefacts/build.log"; exit 2; }
app="$apple/build/arm64-sim/KalaReach.app"
[ -d "$app" ] || { say "the build left no application"; exit 2; }

say "holding the manifests to the built bundle"
node "$companion/scripts/privacy-manifest.mjs" "$app"
code=$?
case "$code" in
    0) say "the manifests hold" ;;
    1) say "a manifest does not hold" ;;
    *) say "the check could not run" ;;
esac
exit "$code"
