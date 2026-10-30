#!/usr/bin/env bash
# Archives the iOS application and its notification extension, and exports the build the App Store
# takes for TestFlight and the store.
#
#   scripts/store-ios.sh [--build-number <n>] [--unsigned-archive]
#
# Three steps, and the first two need no Apple account:
#
#   1. `tauri ios build --no-sign --archive-only`: the archive, with the build number as the bundle
#      version (a single integer: `agvtool` writes it into the application and the extension, and a
#      store refuses more than three numbers, which `--build-number` would make of it).
#   2. The archive is signed ad hoc with the entitlements of the two bundles, the team's prefix in
#      place of the placeholder and the production push environment (`store-ios-sign.mjs` says
#      why), and `store-bundle.mjs` holds it to what a store build needs.
#   3. `xcodebuild -exportArchive` signs it for the App Store with the App Store Connect API key:
#      Xcode makes or finds the cloud-managed distribution certificate and the App Store profiles
#      of both identifiers. `store-bundle.mjs` then reads the exported `.ipa`.
#
# `--unsigned-archive` stops after step 2. Tauri is run with no `APPLE_*` or `IOS_*` variable in its
# environment, on purpose. With the API key in it the CLI switches signing off and leaves an archive
# with no entitlements; with a certificate in it the CLI imports that certificate into a keychain it
# makes and writes its identity into the project. Neither belongs in an archive that is signed in
# step 3.
#
# The API key is the file `apple/asc-api-key.json` under `~/.config/kalareach-secrets` (its key
# identifier and issuer, which are identifiers and not secrets, and the path of the `.p8`). The
# `.p8` is passed to Xcode by path and is never copied or printed. The Firebase configuration is
# `firebase-apps/GoogleService-Info.plist` in the same directory (`KR_GOOGLE_SERVICE_INFO` names
# another); it goes into the application as its configuration, and the build directories keep a
# copy of it as they do of every resource.
#
# The build rewrites tracked files under `gen/apple`, so the script refuses to start when the
# directory has an uncommitted change or a new file, and puts it back when it ends (an edit made
# there while the build runs is lost with it). If it cannot, the script fails, writes no receipt
# and names what it kept. The export must leave the login
# keychain and the keychain search list as they were: a signing identity Xcode made locally instead
# of in the cloud would change `find-identity`, and the script fails when either differs. The
# export also saves two profiles of its own under `~/Library/Developer/Xcode/UserData/Provisioning
# Profiles`, and leaves logs that hold request tokens made from the key: the script removes
# `export/Packaging.log` and the log in the temporary directory, and every run ends by searching
# its output directory for the key's text and for signed tokens, a signal during the export
# included. The application's `Info.plist`
# says it needs no export documentation (`ITSAppUsesNonExemptEncryption` false), which the checker
# requires.
#
# The build number is recorded only for a build that passed every check. A failed one leaves its
# files, and a failed check leaves a `store-build.json` whose `holds` is false: none of it is to be
# uploaded. The receipt holds the highest number whose build passed every step of this script.
# Nothing is uploaded by this script. A build is a heavy step:
#
#   bash lead-scripts/with-slot.sh <label> scripts/store-ios.sh
#
# Exit codes: 0 every check passed, 2 bad usage, a missing input or a failed check.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
apple="$companion/src-tauri/gen/apple"
kr_store_tag=store-ios
# shellcheck source=scripts/lib/store-build.sh
. "$here/scripts/lib/store-build.sh"

firebase="${KR_GOOGLE_SERVICE_INFO:-$KR_SECRETS_DIR/firebase-apps/GoogleService-Info.plist}"
api_record="$KR_SECRETS_DIR/apple/asc-api-key.json"

number_given=""
archive_only=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-number) number_given="${2:-}"; shift 2 || { echo "usage: --build-number <n>" >&2; exit 2; } ;;
        --unsigned-archive) archive_only=1; shift ;;
        *) echo "usage: $0 [--build-number <n>] [--unsigned-archive]" >&2; exit 2 ;;
    esac
done

kr_store_clean_tree "$here" || exit 2
[ -f "$firebase" ] || { kr_store_say "no Firebase configuration at $firebase"; exit 2; }
team="$(sed -n 's/^ *DEVELOPMENT_TEAM: *\([A-Z0-9]*\) *$/\1/p' "$apple/project.yml" | head -1)"
[ -n "$team" ] || { kr_store_say "project.yml names no Apple team"; exit 2; }

key_id="" issuer="" key_file=""
if [ "$archive_only" = 0 ]; then
    kr_store_require_file "$api_record" "the App Store Connect API key's record" || exit 2
    key_id="$(kr_store_json_field "$api_record" key_id)" || { kr_store_say "$api_record has no key_id"; exit 2; }
    issuer="$(kr_store_json_field "$api_record" issuer_id)" || { kr_store_say "$api_record has no issuer_id"; exit 2; }
    key_file="$(kr_store_json_field "$api_record" key_file)" || { kr_store_say "$api_record has no key_file"; exit 2; }
    kr_store_require_file "$key_file" "the API key" || exit 2
    kr_store_refuse_secret_in "$key_file" "$KR_STORE_ROOT" ${number_given:+"$number_given"} || exit 2
fi

version="$(kr_store_version "$here")" || exit 2
number="$(kr_store_number ios "$number_given")" || exit 2
out="$KR_STORE_ROOT/$version-$number-ios"
kr_store_claim_number ios "$number" || exit 2
kr_store_claim "$out" || exit 2
kr_store_guard_begin "$here" "$apple" || exit 2

# What a run owes however it ends: Xcode's credential logs are removed, the output directory is
# searched for the key's text and for signed tokens, and the Apple project is put back. A normal
# end and a signal take this one path; it fails when any part of it does.
finish() {
    local result=0
    kr_store_remove_token_logs "$out" || result=2
    if [ -n "$key_file" ]; then
        node "$companion/scripts/store-bundle.mjs" --scan-dir "$out" --secret-file "$key_file" 2>&1 | tee -a "$out/scan.log"
        [ "${PIPESTATUS[0]}" = 0 ] || result=2
    fi
    kr_store_guard_end || result=2
    return "$result"
}
interrupted() {
    trap '' INT TERM HUP
    finish
    exit 130
}
trap interrupted INT TERM HUP
kr_store_say "version $version, build number $number, team $team, into $out"

# What the build is of, taken before it rewrites tracked project files.
commit="$(git -C "$here" rev-parse HEAD)"
dirty=false
[ -z "$(git -C "$here" status --porcelain --untracked-files=no)" ] || dirty=true

ipa=""
build() {
    # The Firebase file for the build phase, the team's prefix, which a build with signing off cannot
    # take from a provisioning profile, and the mark that this build is the official one, which
    # registers with the official push gateway (Build.xcconfig says why they are written here).
    kr_store_guard_write_local "$(printf 'KR_GOOGLE_SERVICE_INFO = %s\nAppIdentifierPrefix = %s.\nKR_OFFICIAL_BUILD = 1' "$firebase" "$team")" \
        || { kr_store_say "could not write $apple/Local.xcconfig"; return 2; }

    # ---- 1. The archive ------------------------------------------------------------------------

    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(kr_store_cargo_target "$here")}"
    rm -rf -- "${apple:?}/build"
    kr_store_say "archiving (no signing, no Apple credential in the environment)"
    # Every APPLE_* and IOS_* variable is taken out, whatever its name: the CLI reads several of
    # them before it looks at `--no-sign`.
    local unset_arguments=() name
    while IFS= read -r name; do
        unset_arguments+=(-u "$name")
    done < <(compgen -e | grep -E '^(APPLE_|IOS_)' || true)
    ( cd "$companion" && kr_store_official_run env ${unset_arguments[@]+"${unset_arguments[@]}"} \
        pnpm tauri ios build --ci --target aarch64 --archive-only --no-sign \
        --config "{\"bundle\":{\"iOS\":{\"bundleVersion\":\"$number\"}}}" ) \
        || { kr_store_say "the archive failed"; return 2; }
    local archive="$apple/build/companion-tauri_iOS.xcarchive"
    local app="$archive/Products/Applications/KalaReach.app"
    [ -d "$app" ] || { kr_store_say "the archive holds no application at $app"; return 2; }

    # ---- 2. The entitlements -------------------------------------------------------------------

    kr_store_say "signing the archive ad hoc with the entitlements of the application and its extension"
    node "$companion/scripts/store-ios-sign.mjs" "$app" "$team" >"$out/archive-entitlements.json" \
        || { kr_store_say "the archive could not be signed"; return 2; }
    local common=(--version-code "$number" --version-name "$version")
    [ -z "$key_file" ] || common+=(--secret-file "$key_file" --scan-dir "$out")
    local notes=(--note "commit=$commit" --note "uncommittedChanges=$dirty" --note "xcode=$(xcodebuild -version | tr '\n' ' ')"
        --note "builtAt=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        --note "tauriCli=$(node -e 'process.stdout.write(require(process.argv[1]).version)' "$companion/node_modules/@tauri-apps/cli/package.json")")
    kr_store_say "checking the archive"
    node "$companion/scripts/store-bundle.mjs" --ios "$app" --stage archive --skip-app-checks "${common[@]}" "${notes[@]}" \
        --record "$out/archive-build.json" 2>&1 | tee "$out/archive-check.log"
    [ "${PIPESTATUS[0]}" = 0 ] || { kr_store_say "the archive does not hold"; return 2; }
    # The privacy manifest and the debug code are read from this application too, so that a finding
    # is known before an export is made; they are held against the exported build, which is the one
    # that is uploaded, and the same binaries are in both.
    local each
    for each in privacy-manifest debug-code; do
        if node "$companion/scripts/$each.mjs" "$app" >"$out/archive-$each.log" 2>&1; then
            kr_store_say "the archive's $each check holds"
        else
            kr_store_say "the archive's $each check FAILS (the exported build is held to it; see $out/archive-$each.log)"
        fi
    done
    if [ "$archive_only" = 1 ]; then
        kr_store_say "archived (no export asked for): $archive"
        return 0
    fi

    # ---- 3. The export -------------------------------------------------------------------------

    cat >"$out/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key><string>app-store-connect</string>
    <key>teamID</key><string>$team</string>
    <key>signingStyle</key><string>automatic</string>
    <key>destination</key><string>export</string>
    <key>uploadSymbols</key><true/>
    <key>manageAppVersionAndBuildNumber</key><false/>
</dict>
</plist>
PLIST

    # What must not change: the identities the login keychain offers and the search list.
    snapshot() {
        {
            security list-keychains -d user
            security find-identity -v -p codesigning
        } 2>&1
    }
    snapshot >"$out/keychain-before.txt"
    kr_store_say "exporting for the App Store with the API key (Xcode may make the cloud-managed certificate and profiles)"
    xcodebuild -exportArchive -archivePath "$archive" -exportPath "$out/export" -exportOptionsPlist "$out/ExportOptions.plist" \
        -allowProvisioningUpdates -authenticationKeyPath "$key_file" -authenticationKeyID "$key_id" \
        -authenticationKeyIssuerID "$issuer" >"$out/export.log" 2>&1
    local exported=$?
    snapshot >"$out/keychain-after.txt"
    local cleaned=0
    kr_store_remove_token_logs "$out" || cleaned=2
    if ! cmp -s "$out/keychain-before.txt" "$out/keychain-after.txt"; then
        kr_store_say "the login keychain's identities or the search list changed during the export (see $out/keychain-*.txt); stopping"
        return 2
    fi
    [ "$exported" = 0 ] || { kr_store_say "the export failed (see $out/export.log)"; kr_store_show_tail "$out/export.log" "$key_file"; return 2; }
    [ "$cleaned" = 0 ] || return 2
    ipa="$(find "$out/export" -maxdepth 1 -name '*.ipa' | head -1)"
    [ -f "$ipa" ] || { kr_store_say "the export left no .ipa in $out/export"; return 2; }

    kr_store_say "checking the exported build"
    node "$companion/scripts/store-bundle.mjs" --ios "$ipa" --stage export "${common[@]}" "${notes[@]}" \
        --record "$out/store-build.json" 2>&1 | tee "$out/check.log"
    [ "${PIPESTATUS[0]}" = 0 ] || { kr_store_say "the exported build does not hold; $out/store-build.json is not to be uploaded"; return 2; }
}

build
status=$?

# However the build ended, the run's debts are paid; a failure of any of them fails the script.
trap '' INT TERM HUP
finish || status=2
trap - INT TERM HUP
if [ "$status" != 0 ]; then
    kr_store_say "failed; no build number was recorded as built, and what is in $out is not to be uploaded"
    exit 2
fi
if [ "$archive_only" = 1 ]; then
    exit 0
fi
kr_store_receipt ios "$number" || { kr_store_say "the build number could not be recorded"; exit 2; }
kr_store_say "built and checked: $ipa"
kr_store_say "sha256 $(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).sha256)' "$out/store-build.json")"
