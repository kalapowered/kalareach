#!/bin/bash
# The iPhone checks of the application: builds, one session at a time, and the clean-up after one.
#
#   device-ios.sh build-app [--harness] [--no-firebase]   the signed application and its extension
#   device-ios.sh build-tests                             the signed test runner and its test plan
#   device-ios.sh session <name>                          install, run and remove, for one session
#   device-ios.sh cleanup                                 what a session that was killed left behind
#
# Sessions (the tests each runs are listed in `session_tests` below):
#   s0   the proofs, the keychain boundary and the application's lifecycle with push started, 20 minutes
#   s1   push to this phone through Firebase, with the person not touching notifications, 30 minutes
#   s2a  recovery, the keyboard and rotation, the file pickers and the camera: person at the phone, 30 minutes
#   s2b  the accessibility audit, target sizes and text size: person at the phone, 15 minutes
#   s3a  the microphone refused: person at the phone, 10 minutes
#   s3b  the microphone allowed and a change of route: person at the phone, 15 minutes
#   s4   the screen locked and unlocked under the audio check: person at the phone, 10 minutes
#
# It uses the phone only under the lease the caller holds, and only to install, drive and remove the
# application under test and its runner. It reads nothing else on the phone, and keeps of a session
# only the lines the tests say, the names and outcomes of the tests, and the application's own
# pictures, under KR_SHOTS.
#
# What it needs from the environment, none of it kept in the repository:
#   KR_DEVICE                  the phone's UDID, which devicectl and xcodebuild both take (or the simulator's name)
#   KR_DEVICE_LEASE            the lease that is held while this runs
#   KR_SIGN_IDENTITY           the SHA-1 of the signing certificate, in capitals: never its name, since a
#                              name can match another identity in another keychain
#   KR_APP_PROFILE, KR_EXTENSION_PROFILE, KR_RUNNER_PROFILE
#                              the UUIDs of the three provisioning profiles, found in KR_PROFILE_DIR
#                              (default ~/Library/MobileDevice/Provisioning Profiles)
#   KR_GOOGLE_SERVICE_INFO     the Firebase configuration, for a build that has push
#   KR_KEYCHAIN, KR_KEYCHAIN_PASSWORD_FILE
#                              the keychain that holds the signing identity, and the file holding its
#                              password, for a device build
#   KR_PUSH_TOOL               the script that sends the one test notification (session s1 only)
# And, optional: KR_TARGET=simulator to run everything on a simulator instead of the phone,
# KR_WORK (products and the record of a session, on the internal disk), KR_RAW (the raw output of a
# run, which is deleted when the session ends) and KR_SHOTS (the application's pictures).
set -u

here=$(cd "$(dirname "$0")" && pwd)
companion=$(cd "$here/.." && pwd)
apple="$companion/src-tauri/gen/apple"
target=${KR_TARGET:-device}
work=${KR_WORK:-$HOME/Library/Caches/kalareach-device-ios}
shots=${KR_SHOTS:-/tmp/kalareach-device-ios}
raw=${KR_RAW:-/tmp/kalareach-device-ios-raw}
record="$work/session-record"
devicectl_limit=90
app_id=to.kala.reach
runner_id=to.kala.reach.uitests.xctrunner
tests_scheme=KalaReachUITests

die() { echo "device-ios: $*" >&2; exit 2; }
say() { echo "device-ios: $*"; }

# MARK: The lease, and the target

# The lease is held when its owner is this script or something that started it.
require_lease() {
  [ -n "${KR_DEVICE_LEASE:-}" ] || die "KR_DEVICE_LEASE is not set: a session runs under the device lease"
  [ -f "$KR_DEVICE_LEASE/owner" ] || die "nothing holds the lease at $KR_DEVICE_LEASE"
  local owner pid
  owner=$(awk '{print $1}' "$KR_DEVICE_LEASE/owner")
  pid=$$
  while [ -n "$pid" ] && [ "$pid" -gt 1 ]; do
    [ "$pid" = "$owner" ] && return 0
    pid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
  done
  die "this was not started under the lease held at $KR_DEVICE_LEASE"
}

require_target() {
  [ -n "${KR_DEVICE:-}" ] || die "KR_DEVICE names no phone"
  case $target in
    device | simulator) ;;
    *) die "KR_TARGET is device or simulator" ;;
  esac
}

# What a build is for: the phone's own platform, or the simulator's.
sdk() { [ "$target" = device ] && echo iphoneos || echo iphonesimulator; }
destination() {
  if [ "$target" = device ]; then echo "platform=iOS,id=$KR_DEVICE"; else echo "platform=iOS Simulator,name=$KR_DEVICE"; fi
}

# MARK: One thing at a time on the target

boot_simulator() {
  [ "$target" = simulator ] || return 0
  xcrun simctl boot "$KR_DEVICE" >/dev/null 2>&1
  xcrun simctl bootstatus "$KR_DEVICE" -b >/dev/null 2>&1
}

# Whether a bundle is installed: yes, no, or unknown when the target did not answer.
installed_state() { # <bundle id>
  if [ "$target" = device ]; then
    mkdir -p "$raw"; rm -f "$raw/apps.json"
    xcrun devicectl --timeout "$devicectl_limit" device info apps --device "$KR_DEVICE" --bundle-id "$1" --quiet --json-output "$raw/apps.json" >/dev/null 2>&1 \
      && [ -s "$raw/apps.json" ] || { echo unknown; return; }
    # The JSON's exact nesting is not promised, so every object in it is asked.
    python3 - "$raw/apps.json" "$1" <<'PY'
import json, sys

def holds(node, wanted):
    if isinstance(node, dict):
        return node.get("bundleIdentifier") == wanted or any(holds(value, wanted) for value in node.values())
    if isinstance(node, list):
        return any(holds(value, wanted) for value in node)
    return False

print("yes" if holds(json.load(open(sys.argv[1])), sys.argv[2]) else "no")
PY
  elif xcrun simctl get_app_container "$KR_DEVICE" "$1" >/dev/null 2>&1; then
    echo yes
  else
    echo no
  fi
}

target_install() { # <path>
  if [ "$target" = device ]; then xcrun devicectl --timeout "$devicectl_limit" device install app --device "$KR_DEVICE" "$1" >/dev/null; else xcrun simctl install "$KR_DEVICE" "$1"; fi
}

target_uninstall() { # <bundle id>
  if [ "$target" = device ]; then xcrun devicectl --timeout "$devicectl_limit" device uninstall app --device "$KR_DEVICE" "$1" >/dev/null 2>&1; else xcrun simctl uninstall "$KR_DEVICE" "$1" >/dev/null 2>&1; fi
}

target_launch() { # <args...>: starts the application afresh with these arguments
  if [ "$target" = device ]; then
    # The arguments go after `--`: without it devicectl takes `-KRDeviceProbe` for an option of its own.
    xcrun devicectl --timeout "$devicectl_limit" device process launch --device "$KR_DEVICE" --terminate-existing "$app_id" -- "$@" >/dev/null
  else
    xcrun simctl terminate "$KR_DEVICE" "$app_id" >/dev/null 2>&1
    xcrun simctl launch "$KR_DEVICE" "$app_id" "$@" >/dev/null
  fi
}

# Copies one file out of the application's own container.
target_copy() { # <path inside the container> <local file>
  mkdir -p "$(dirname "$2")"
  if [ "$target" = device ]; then
    xcrun devicectl --timeout "$devicectl_limit" device copy from --device "$KR_DEVICE" --domain-type appDataContainer --domain-identifier "$app_id" \
      --source "$1" --destination "$2" >/dev/null 2>&1
  else
    cp "$(xcrun simctl get_app_container "$KR_DEVICE" "$app_id" data)/$1" "$2" 2>/dev/null
  fi
}

# MARK: What a device check leaves

# Starts a device check in the application, waits for its file and prints it. Each check is given a
# run of its own and only a file that names that run is taken: a file an earlier check left is never
# read as this one's.
run_check() { # <mode> <file stem>
  local file="$work/checks/probe-$2.txt" run
  run=$(uuidgen)
  rm -f "$file"
  target_launch -KRDeviceProbe "$1" -KRProbeRun "$run" || return 1
  local waited=0
  while [ "$waited" -lt 60 ]; do
    sleep 2; waited=$((waited + 2))
    if target_copy "Documents/probe-$2.txt" "$file" && [ -s "$file" ] && grep -q "^run=$run\$" "$file"; then
      cat "$file"
      return 0
    fi
  done
  return 1
}

fact() { # <file> <key>: the value of one key=value line
  sed -n "s/^$2=//p" "$1" | head -1
}

# The two keychain groups hold nothing before a session starts and after it ends. The count is of
# attributes alone, and a query that was refused is not an empty group.
baseline() {
  say "counting what the two keychain groups hold"
  run_check count count > "$work/checks/count.out" || die "the count did not report"
  [ "$(fact "$work/checks/probe-count.txt" ok)" = 1 ] || die "a keychain query was refused, so the baseline is unknown"
  [ "$(fact "$work/checks/probe-count.txt" total)" = 0 ] || die "the groups are not empty: stop here and ask"
  echo "baseline=empty" >> "$record"
}

sweep_once() {
  run_check sweep sweep > "$work/checks/sweep.out" || { say "the sweep did not report"; return 1; }
  [ "$(fact "$work/checks/probe-sweep.txt" ok)" = 1 ] && [ "$(fact "$work/checks/probe-sweep.txt" remaining)" = 0 ] \
    || { say "the sweep left something, or was refused: $(grep -E '^(remaining|ok|failed)=' "$work/checks/probe-sweep.txt" | tr '\n' ' ')"; return 1; }
}

# Removes what the application and its libraries filed in the two groups, and checks that nothing is
# left; once more if the first did not leave them empty.
sweep() {
  say "removing what the application and its libraries filed in the two groups"
  sweep_once || { say "trying the sweep once more"; sweep_once; }
}

# MARK: Builds

# The team that owns the application, as the project names it.
team() { sed -n 's/^ *DEVELOPMENT_TEAM: *//p' "$apple/project.yml" | head -1; }

# The push choice goes to Local.xcconfig, which Build.xcconfig reads and the repository ignores. A
# device build is made with signing off, so the team's prefix, which the build takes from a profile
# when it signs, is given here for the keychain groups and the bundle's own names to carry.
write_local_xcconfig() { # <with push: yes|no>
  {
    [ "$target" = device ] && echo "AppIdentifierPrefix = $(team)."
    if [ "$1" = yes ]; then
      [ -f "${KR_GOOGLE_SERVICE_INFO:-}" ] || die "KR_GOOGLE_SERVICE_INFO names no file"
      echo "KR_GOOGLE_SERVICE_INFO = $KR_GOOGLE_SERVICE_INFO"
    else
      # A build without push names no configuration, whatever the environment holds.
      echo "KR_GOOGLE_SERVICE_INFO ="
    fi
  } > "$apple/Local.xcconfig"
}

# MARK: Signing

profiles=${KR_PROFILE_DIR:-$HOME/Library/MobileDevice/Provisioning Profiles}
profile_file() { # <uuid>
  [ -f "$profiles/$1.mobileprovision" ] || die "there is no profile $1 in $profiles"
  echo "$profiles/$1.mobileprovision"
}

# The user's keychain search list, one path a line, in $listing. A list that could not be read, or is
# empty, is an error: it would be put back as nothing.
read_search_list() {
  local raw
  raw=$(security list-keychains -d user) || return 1
  listing=$(printf '%s\n' "$raw" | sed -e 's/^[[:space:]]*"//' -e 's/"[[:space:]]*$//' | sed '/^$/d')
  [ -n "$listing" ]
}

signing_lock=""
signing_child=""
signing_paths=()
signing_before=""
signing_ended=1

# Puts the search list back as it was recorded and locks the signing keychain, once, whichever way the
# signing ended. The lock is released only when the list is known to be what it was: a list that could
# not be put back keeps the lock, so that no other build signs on top of it.
end_signing() {
  [ "$signing_ended" = 1 ] && return 0
  signing_ended=1
  local restored=1
  security list-keychains -d user -s "${signing_paths[@]}" || restored=0
  security lock-keychain "$KR_KEYCHAIN" || say "THE SIGNING KEYCHAIN COULD NOT BE LOCKED: lock it by hand"
  read_search_list || restored=0
  say "keychain search list after signing: $(printf '%s' "$listing" | tr '\n' ' ')"
  if [ "$restored" = 1 ] && [ "$listing" = "$signing_before" ]; then
    rmdir "$signing_lock" 2>/dev/null
    return 0
  fi
  say "THE KEYCHAIN SEARCH LIST IS NOT WHAT IT WAS BEFORE SIGNING: put it back by hand, then remove $signing_lock"
  return 1
}

# A TERM, INT or HUP while signing: the command is stopped, then the list is put back and the keychain
# locked, before this shell goes.
signing_interrupted() { # <exit status>
  [ -n "$signing_child" ] && kill "$signing_child" 2>/dev/null
  wait "$signing_child" 2>/dev/null
  end_signing
  exit "$1"
}

# Runs a command with the signing keychain at the end of the user's keychain search list, where
# codesign has to find the identity, and puts the list back as it was however the command ends. The
# keychain is unlocked from its password file just before, which is never printed, and locked again
# after. Nothing else changes: the login keychain stays first and the default keychain is not touched.
# One signing runs at a time on this checkout, and a list that already holds the signing keychain, or
# cannot be read, is not signed on top of.
with_signing_keychain() { # <command...>
  [ "$target" = device ] || die "only a device build is signed"
  [ -n "${KR_KEYCHAIN:-}" ] && [ -f "${KR_KEYCHAIN_PASSWORD_FILE:-}" ] || die "KR_KEYCHAIN and KR_KEYCHAIN_PASSWORD_FILE are needed to sign"
  mkdir -p "$work"
  signing_lock="$work/signing.lock"
  mkdir "$signing_lock" 2>/dev/null || die "another build is signing, or one ended without restoring the list: see $signing_lock"
  if ! read_search_list; then rmdir "$signing_lock"; die "the keychain search list could not be read, or it is empty"; fi
  signing_before=$listing
  if printf '%s\n' "$signing_before" | grep -Fxq "$KR_KEYCHAIN"; then
    rmdir "$signing_lock"
    die "the signing keychain is already on the search list: an earlier signing did not put it back, so put it back by hand"
  fi
  say "keychain search list before signing: $(printf '%s' "$signing_before" | tr '\n' ' ')"
  signing_paths=()
  local each
  while IFS= read -r each; do signing_paths+=("$each"); done <<< "$signing_before"
  signing_ended=0
  trap 'signing_interrupted 130' INT
  trap 'signing_interrupted 143' TERM
  trap 'signing_interrupted 129' HUP
  local status
  if security unlock-keychain -p "$(cat "$KR_KEYCHAIN_PASSWORD_FILE")" "$KR_KEYCHAIN" \
    && security list-keychains -d user -s "${signing_paths[@]}" "$KR_KEYCHAIN"; then
    "$@" &
    signing_child=$!
    wait "$signing_child"
    status=$?
    signing_child=""
  else
    status=2
  fi
  trap - INT TERM HUP
  end_signing || die "the signing left the keychain search list changed"
  return "$status"
}

signer() { echo "$companion/scripts/sign-ios.mjs"; }

# Signs the application, its extension and what they hold, then checks every signature, the
# certificate it was made with and the entitlements it is sealed with, with no keychain on the list.
sign_application() { # <KalaReach.app>
  [ -n "${KR_SIGN_IDENTITY:-}" ] && [ -n "${KR_APP_PROFILE:-}" ] && [ -n "${KR_EXTENSION_PROFILE:-}" ] \
    || die "a device build needs KR_SIGN_IDENTITY, KR_APP_PROFILE and KR_EXTENSION_PROFILE"
  local arguments=(
    "$1" --identity "$KR_SIGN_IDENTITY"
    --app-profile "$(profile_file "$KR_APP_PROFILE")" --extension-profile "$(profile_file "$KR_EXTENSION_PROFILE")"
    --app-entitlements "$apple/companion-tauri_iOS/companion-tauri_iOS.entitlements"
    --extension-entitlements "$apple/KalaReachNotificationService/KalaReachNotificationService.entitlements"
    --device "$KR_DEVICE"
  )
  with_signing_keychain node "$(signer)" sign-app "${arguments[@]}" --keychain "$KR_KEYCHAIN" || return 1
  node "$(signer)" verify-app "${arguments[@]}"
}

sign_runner() { # <Runner.app>
  [ -n "${KR_SIGN_IDENTITY:-}" ] && [ -n "${KR_RUNNER_PROFILE:-}" ] || die "a device build needs KR_SIGN_IDENTITY and KR_RUNNER_PROFILE"
  local arguments=("$1" --identity "$KR_SIGN_IDENTITY" --profile "$(profile_file "$KR_RUNNER_PROFILE")" --device "$KR_DEVICE")
  with_signing_keychain node "$(signer)" sign-runner "${arguments[@]}" --keychain "$KR_KEYCHAIN" || return 1
  node "$(signer)" verify-runner "${arguments[@]}"
}

build_app() {
  local harness=no push=yes
  for each in "$@"; do
    case $each in
      --harness) harness=yes ;;
      --no-firebase) push=no ;;
      *) die "build-app: unknown option $each" ;;
    esac
  done
  mkdir -p "$work"
  write_local_xcconfig "$push"
  local flavour=app
  [ "$harness" = yes ] && flavour=harness
  [ "$push" = no ] && flavour=$flavour-nofirebase
  local arguments=(--debug --ci)
  if [ "$target" = device ]; then arguments+=(--target aarch64 --archive-only --no-sign); else arguments+=(--target aarch64-sim); fi
  if [ "$harness" = yes ]; then
    arguments+=(--config '{"build":{"frontendDist":"../dist-harness","beforeBuildCommand":"pnpm build:harness"},"app":{"windows":[{"label":"main","create":false,"title":"KalaReach","width":1180,"height":800,"minWidth":480,"minHeight":480,"dragDropEnabled":true,"titleBarStyle":"Transparent","hiddenTitle":true,"url":"harness.html"}]}}')
  fi
  rm -rf "${apple:?}/build"
  ( cd "$companion" && pnpm tauri ios build "${arguments[@]}" ) || die "the build failed"
  local built
  if [ "$target" = device ]; then
    built=$(ls -d "$apple"/build/*.xcarchive/Products/Applications/*.app 2>/dev/null | head -1)
  else
    built="$apple/build/arm64-sim/KalaReach.app"
  fi
  [ -d "$built" ] || die "the build left no application"
  rm -rf "${work:?}/$flavour.app"
  cp -R "$built" "$work/$flavour.app"
  [ "$target" = device ] && { sign_application "$work/$flavour.app" || die "the application did not sign"; }
  say "built $work/$flavour.app"
}

build_tests() {
  mkdir -p "$work"
  write_local_xcconfig no
  local derived="$work/tests-$target" unsigned=()
  # A device build is made with signing off and signed by hand afterwards.
  [ "$target" = device ] && unsigned=(CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO)
  ( cd "$apple" && xcodebuild build-for-testing -project companion-tauri.xcodeproj -scheme "$tests_scheme" -sdk "$(sdk)" \
      -destination "generic/platform=$([ "$target" = device ] && echo iOS || echo 'iOS Simulator')" -derivedDataPath "$derived" \
      ${unsigned[@]+"${unsigned[@]}"} ) \
    > "$work/build-tests-$target.log" 2>&1 || { tail -20 "$work/build-tests-$target.log"; die "the test build failed"; }
  local plan products="$derived/Build/Products"
  plan=$(ls "$products"/*.xctestrun 2>/dev/null | head -1)
  [ -f "$plan" ] || die "the test build left no test plan"
  # The plan stays where Xcode left it, since its paths are relative to its own directory.
  local session_plan="$products/session.xctestrun"
  cp "$plan" "$session_plan"
  # Nothing the runner can keep is kept: no recording, no picture, no attachment, no diagnostics.
  local key=":$tests_scheme" plist=/usr/libexec/PlistBuddy
  $plist -c "Set $key:SystemAttachmentLifetime keepNever" "$session_plan" || die "the test plan has no SystemAttachmentLifetime to set"
  $plist -c "Set $key:UserAttachmentLifetime keepNever" "$session_plan" || die "the test plan has no UserAttachmentLifetime to set"
  $plist -c "Set $key:DiagnosticCollectionPolicy 0" "$session_plan" || die "the test plan has no DiagnosticCollectionPolicy to set"
  $plist -c "Delete $key:CommandLineArguments" "$session_plan" >/dev/null 2>&1
  $plist -c "Add $key:CommandLineArguments array" "$session_plan" || die "the test plan took no command line arguments"
  local at=0
  for each in -DisableDiagnosticScreenRecordings YES -DisableDiagnosticScreenshots YES; do
    $plist -c "Add $key:CommandLineArguments:$at string $each" "$session_plan" || die "the test plan took no argument $each"
    at=$((at + 1))
  done
  # A simulator run can be asked to leave the application's tree and picture of a failure under /tmp.
  if [ "$target" = simulator ] && [ "${KR_FAILURE_DUMP:-}" = 1 ]; then
    $plist -c "Add $key:TestingEnvironmentVariables:KR_FAILURE_DUMP string 1" "$session_plan" || die "the test plan took no failure dump setting"
  fi
  # Every value is read back: a plan that did not take them is not one to run on a phone.
  [ "$($plist -c "Print $key:SystemAttachmentLifetime" "$session_plan")" = keepNever ] || die "the plan does not keep no system attachments"
  [ "$($plist -c "Print $key:UserAttachmentLifetime" "$session_plan")" = keepNever ] || die "the plan does not keep no user attachments"
  [ "$($plist -c "Print $key:DiagnosticCollectionPolicy" "$session_plan")" = 0 ] || die "the plan collects diagnostics"
  [ "$($plist -c "Print $key:CommandLineArguments:3" "$session_plan")" = YES ] || die "the plan lacks the runner arguments"
  echo "$session_plan" > "$work/tests-$target.path"
  say "built the test runner, plan at $session_plan"
  runner_app=$(ls -d "$derived"/Build/Products/*/"$tests_scheme-Runner.app" | head -1)
  [ -d "$runner_app" ] || die "the test build left no runner"
  # The debug symbols of the test bundle are not a plug-in and have no place in an installed bundle.
  rm -rf "${runner_app:?}"/PlugIns/*.dSYM
  [ "$target" = device ] && { sign_runner "$runner_app" || die "the runner did not sign"; }
  echo "$runner_app" > "$work/runner-$target.path"
}

# MARK: Sessions

# Each session: the application's build, the tests it runs, how long it may take in minutes, and
# whether the person is at the phone.
session_tests() { # <name>
  case $1 in
    s0) echo "ProofTests/testWhatATestSaysReachesTheScriptWhileItRuns ProofTests/testHomePressesKeepThePhoneAwake ProofTests/testTheApplicationDrawsItsOwnWindowsForTheScriptToCopy KeychainTests LifecycleTests" ;;
    s1) echo "PushTests/testALegWithTheApplicationTerminated PushTests/testALegWithTheApplicationInTheBackground" ;;
    s2a) echo "RecoveryTests LayoutTests PickerTests" ;;
    s2b) echo "AccessibilityTests" ;;
    s3a) echo "AudioTests/testARefusedMicrophoneIsSaidAndNothingOpens" ;;
    s3b) echo "AudioTests/testAnAllowedMicrophoneOpensTheSessionAndAChangeOfRouteIsCounted" ;;
    s4) echo "AudioTests/testAudioCarriesOnThroughALockedScreen" ;;
    *) return 1 ;;
  esac
}
session_minutes() { case $1 in s0) echo 20 ;; s1) echo 30 ;; s2a) echo 30 ;; s2b) echo 15 ;; s3a) echo 10 ;; s3b) echo 15 ;; s4) echo 10 ;; esac; }
# Which build of the application a session installs: s0 and s1 hold Firebase's configuration, s2a and s2b run the harness page.
session_app() { case $1 in s0 | s1) echo app ;; s2a | s2b) echo harness-nofirebase ;; *) echo app-nofirebase ;; esac; }

ending=0
runner_pid=""
# How many lines of the runner's output have been looked through for what the tests say.
forwarded=0
# Whether the phone is clean afterwards, and whether the session's proofs held. A session that
# leaves something behind keeps its record; one whose proof was not met ends with its own status.
unclean=0
unproven=0

# Stops what is driving the phone, and waits until it has stopped, before anything is cleaned up.
stop_runner() {
  if [ -n "$runner_pid" ] && kill -0 "$runner_pid" 2>/dev/null; then
    kill "$runner_pid" 2>/dev/null
    local waited=0
    while kill -0 "$runner_pid" 2>/dev/null && [ "$waited" -lt 30 ]; do sleep 1; waited=$((waited + 1)); done
    kill -9 "$runner_pid" 2>/dev/null
  fi
  wait "$runner_pid" 2>/dev/null
  runner_pid=""
}

# What the tests say goes to the person as it is said, with the time it arrived: an instruction to
# lock the phone is useless afterwards, and the times show the output is live. It reads the lines the
# runner has finished since the last call, nothing is left running between calls, and the lines are
# kept in a file for the proofs.
forward_what_the_tests_say() { # <the runner's output> <where the lines are kept>
  local total
  total=$(wc -l < "$1" 2>/dev/null || echo 0)
  [ "$total" -gt "$forwarded" ] || return 0
  # Only the lines counted: the runner may have written more since, and they are read next time.
  tail -n +"$((forwarded + 1))" "$1" | head -n "$((total - forwarded))" | grep -E 'KR-' | while IFS= read -r line; do
    printf 'device-ios: [%s] %s\n' "$(date +%s)" "${line#*KR-}"
  done | tee -a "$2"
  forwarded=$total
}

# Copies the application's own pictures out of its container, before the uninstall takes them.
copy_shots() { # <session>
  local into="$shots/$1"
  mkdir -p "$into"
  if [ "$target" = device ]; then
    xcrun devicectl --timeout "$devicectl_limit" device copy from --device "$KR_DEVICE" --domain-type appDataContainer \
      --domain-identifier "$app_id" --source Documents/shots --destination "$into" >/dev/null 2>&1 || say "no pictures to copy"
  else
    cp -R "$(xcrun simctl get_app_container "$KR_DEVICE" "$app_id" data)/Documents/shots/." "$into" 2>/dev/null || say "no pictures to copy"
  fi
}

# What every session ends with, however it ends: the runner stopped, the pictures copied, the sweep,
# then the application and the runner removed and checked gone. A session that cannot show all of that
# keeps its record, so that `cleanup` knows what is left, and ends with a failure.
finish_session() {
  [ "$ending" = 1 ] && return
  ending=1
  stop_runner
  say "ending the session"
  local keep_app=0
  if grep -q '^baseline=empty$' "$record" 2>/dev/null; then
    copy_shots "${session_name:-session}"
    [ "${session_name:-}" = s0 ] && check_shot_proof "$shots/s0"
    echo "sweep=pending" >> "$record"
    if sweep; then
      echo "sweep=done" >> "$record"
    else
      # The sweep runs through the application, so the application stays until a sweep has worked:
      # removing it now would leave the items with nothing to remove them.
      say "THE KEYCHAIN GROUPS ARE NOT KNOWN TO BE EMPTY: the application stays installed, and cleanup runs the sweep again"
      keep_app=1
      unclean=1
    fi
  else
    say "no empty baseline is on record, so nothing is swept"
  fi
  [ "$keep_app" = 1 ] || target_uninstall "$app_id"
  target_uninstall "$runner_id"
  for id in "$app_id" "$runner_id"; do
    if [ "$id" = "$app_id" ] && [ "$keep_app" = 1 ]; then continue; fi
    if [ "$(installed_state "$id")" = no ]; then say "$id is gone"; else say "$id is STILL INSTALLED or not known to be gone"; unclean=1; fi
  done
  if [ "$unclean" = 0 ]; then rm -f "$record"; fi
  rm -rf "${work:?}/push" "${work:?}/checks" "${raw:?}" "$(dirname "$(cat "$work/tests-$target.path" 2>/dev/null)")/attachment-proof.xctestrun"
  [ "$unclean" = 0 ] || exit 3
  [ "$unproven" = 0 ] || exit 4
}

session() {
  [ "$ending" = 1 ] && return
  ending=1
  stop_runner
  say "ending the session"
  local swept=1
  if grep -q '^baseline=empty$' "$record" 2>/dev/null; then
    copy_shots "${session_name:-session}"
    [ "${session_name:-}" = s0 ] && check_shot_proof "$shots/s0"
    sweep || { say "THE KEYCHAIN GROUPS ARE NOT KNOWN TO BE EMPTY: run cleanup before anything else"; swept=0; unclean=1; }
  else
    say "no empty baseline is on record, so nothing is swept"
  fi
  target_uninstall "$app_id"
  target_uninstall "$runner_id"
  for id in "$app_id" "$runner_id"; do
    if [ "$(installed_state "$id")" = no ]; then say "$id is gone"; else say "$id is STILL INSTALLED or not known to be gone"; unclean=1; fi
  done
  if [ "$unclean" = 0 ]; then rm -f "$record"; fi
  rm -rf "${work:?}/push" "${work:?}/checks" "${raw:?}"
  [ "$unclean" = 0 ] || exit 3
  [ "$unproven" = 0 ] || exit 4
}

session() {
  local name=${1:-}
  local tests minutes
  tests=$(session_tests "$name") || die "unknown session $name"
  minutes=$(session_minutes "$name")
  session_name=$name
  local started
  started=$(date +%s)
  require_lease
  require_target
  # Pictures an earlier run of this session left are not this run's, and the proof reads this run's.
  rm -rf "${shots:?}/$name"
  mkdir -p "$work/checks" "$work/push" "$shots" "$raw"
  [ -f "$work/$(session_app "$name").app/Info.plist" ] || die "build the application first: build-app (the $(session_app "$name") build)"
  [ -f "$work/tests-$target.path" ] && [ -f "$(cat "$work/tests-$target.path")" ] || die "build the test runner first: build-tests"
  [ ! -f "$record" ] || die "a session left its record at $record: run cleanup first"
  boot_simulator
  # The application and the runner are not on the phone to begin with; if either is, it is not this session's.
  for id in "$app_id" "$runner_id"; do
    case $(installed_state "$id") in
      no) ;;
      yes) die "$id is already installed: it is not this session's, so nothing is touched" ;;
      *) die "the phone did not say whether $id is installed" ;;
    esac
  done
  # The record says whose installation this is: the target, the phone, and when it began. Cleanup
  # touches nothing that this record does not name.
  printf 'target=%s\ndevice=%s\nsession=%s\nstarted=%s\n' "$target" "$KR_DEVICE" "$name" "$started" > "$record"
  trap 'stop_runner; finish_session; exit 130' INT
  trap 'stop_runner; finish_session; exit 143' TERM
  trap finish_session EXIT
  say "installing"
  target_install "$work/$(session_app "$name").app" || die "the application did not install"
  target_install "$(cat "$work/runner-$target.path")" || die "the test runner did not install"
  baseline
  if [ "$name" = s0 ]; then
    attachment_proof
    [ "$unproven" = 0 ] || { say "the attachment check did not hold, so the session ends here"; exit 4; }
  fi

  say "session $name: $tests (at most $((minutes + 10)) minutes in all)"
  local result="$raw/result-$name.xcresult" out="$raw/session-$name.out"
  rm -rf "$result" "$out"
  : > "$out"
  local only=()
  for each in $tests; do only+=("-only-testing:$tests_scheme/$each"); done
  xcodebuild test-without-building -xctestrun "$(cat "$work/tests-$target.path")" -destination "$(destination)" \
    -resultBundlePath "$result" -collect-test-diagnostics never "${only[@]}" > "$out" 2>&1 &
  runner_pid=$!
  # The record names the driver, so that cleanup can end it if this script is killed.
  echo "runner=$runner_pid" >> "$record"
  local sent=0
  forwarded=0
  while kill -0 "$runner_pid" 2>/dev/null; do
    sleep 2
    forward_what_the_tests_say "$out" "$raw/live.out"
    # A push leg says it is waiting once the application has its token and has been put away: the
    # one test notification goes then, to the token the application filed, and never twice for a step.
    local waiting
    waiting=$(grep -c 'KR-STEP wait' "$out" 2>/dev/null || true)
    if [ "$name" = s1 ] && [ "$waiting" -gt "$sent" ]; then
      sent=$waiting
      send_push || say "the push was not sent"
    fi
    if [ $(( $(date +%s) - started )) -gt $(( (minutes + 10) * 60 )) ]; then
      say "the session ran past its limit: stopping it"
      stop_runner
      break
    fi
  done
  sleep 1
  forward_what_the_tests_say "$out" "$raw/live.out"
  wait "$runner_pid" 2>/dev/null
  local status=$?
  runner_pid=""
  report "$out"
  [ "$name" = s0 ] && proofs "$raw/live.out"
  say "session $name finished, xcodebuild status $status"
  # The cleanup runs from the trap on this exit; a clean-up that fails ends with its own status.
  exit "$status"
}

# The first proof of session s0: what a test says reaches this script while the test is running. The
# two lines are said fifteen seconds apart and their arrival times must show about that.
proofs() { # <live output>
  local first second
  first=$(sed -n 's/^device-ios: \[\([0-9]*\)\] PROOF first.*/\1/p' "$1" | head -1)
  second=$(sed -n 's/^device-ios: \[\([0-9]*\)\] PROOF second.*/\1/p' "$1" | head -1)
  if [ -n "$first" ] && [ -n "$second" ] && [ $((second - first)) -ge 10 ]; then
    say "PROOF live: the two lines arrived $((second - first)) seconds apart"
  else
    say "PROOF NOT MET: what a test says does not reach this script while it runs, so a push leg cannot be sent at the right time"
    unproven=1
  fi
}

# The second proof of session s0: the application's own picture of itself reached this Mac, and it
# is a picture of a window with something in it. The size is the window's, and a picture that is one
# colour compresses to almost nothing, so its file is small.
check_shot_proof() { # <folder>
  local picture size width height
  # Wherever the copy put it: devicectl may keep the folder's own name.
  picture=$(find "$1" -name 'shot-*.png' 2>/dev/null | head -1)
  if [ -z "$picture" ]; then say "PROOF NOT MET: the application's picture of itself did not come out of its container"; unproven=1; return; fi
  width=$(sips -g pixelWidth "$picture" 2>/dev/null | awk '/pixelWidth/ {print $2}')
  height=$(sips -g pixelHeight "$picture" 2>/dev/null | awk '/pixelHeight/ {print $2}')
  size=$(stat -f %z "$picture")
  if [ -n "$width" ] && [ -n "$height" ] && [ "$width" -ge 300 ] && [ "$height" -ge 600 ] && [ "$size" -ge 50000 ]; then
    say "PROOF the application's picture of itself came out: ${width} by ${height} points scaled, ${size} bytes"
  else
    say "PROOF NOT MET: the application's picture is ${width:-?} by ${height:-?} and ${size} bytes, which is not a picture of a page"
    unproven=1
  fi
}

# The third proof of session s0: a test that fails on purpose is run with every attachment asked to
# be kept and the runner's arguments that suppress pictures and recordings, and what its result
# holds is listed by kind alone. A picture or a recording among them means the arguments do not
# hold, and nothing else is run on this phone until they do. What was exported is deleted without
# being opened.
attachment_proof() {
  local plan proof_plan out bundle exported plist=/usr/libexec/PlistBuddy key=":$tests_scheme"
  plan=$(cat "$work/tests-$target.path")
  proof_plan="$(dirname "$plan")/attachment-proof.xctestrun"
  out="$raw/attachment-proof.out"; bundle="$raw/attachment-proof.xcresult"; exported="$raw/attachment-proof-files"
  rm -rf "$bundle" "$exported"
  cp "$plan" "$proof_plan" || { say "PROOF NOT MET: no plan to run the attachment check with"; unproven=1; return; }
  $plist -c "Set $key:SystemAttachmentLifetime keepAlways" "$proof_plan" \
    && $plist -c "Set $key:UserAttachmentLifetime keepAlways" "$proof_plan" \
    && $plist -c "Add $key:TestingEnvironmentVariables:KR_ATTACHMENT_PROOF string 1" "$proof_plan" \
    || { say "PROOF NOT MET: the plan for the attachment check could not be written"; unproven=1; return; }
  say "running a test that fails on purpose, with every attachment kept"
  xcodebuild test-without-building -xctestrun "$proof_plan" -destination "$(destination)" -resultBundlePath "$bundle" \
    -collect-test-diagnostics never "-only-testing:$tests_scheme/ProofTests/testAFailureLeavesNothingBehind" > "$out" 2>&1 &
  runner_pid=$!
  echo "runner=$runner_pid" >> "$record"
  # Five minutes is far more than a test of a few seconds needs; a phone that does not answer is not waited for.
  local waited=0
  while kill -0 "$runner_pid" 2>/dev/null && [ "$waited" -lt 300 ]; do sleep 2; waited=$((waited + 2)); done
  if kill -0 "$runner_pid" 2>/dev/null; then
    say "the attachment check did not end in five minutes: stopping it"
    stop_runner
    unproven=1; rm -rf "$bundle" "$exported" "$proof_plan"; return
  fi
  wait "$runner_pid" 2>/dev/null
  runner_pid=""
  if ! grep -q "Test Case '.*testAFailureLeavesNothingBehind.*' failed" "$out"; then
    say "PROOF NOT MET: the test that fails on purpose did not run and fail, so what a failure leaves is not known"
    unproven=1; rm -rf "$bundle" "$exported" "$proof_plan"; return
  fi
  if ! xcrun xcresulttool export attachments --path "$bundle" --output-path "$exported" >/dev/null 2>&1; then
    say "PROOF NOT MET: the result of the test that fails on purpose could not be read"
    unproven=1; rm -rf "$bundle" "$exported" "$proof_plan"; return
  fi
  # By kind alone: the file name's extension, counted. Nothing is opened. Only kinds that are text may
  # be left; a picture, a recording or any kind this does not know is a failure.
  local kinds others
  kinds=$(find "$exported" -type f ! -name manifest.json | sed 's/.*\.//' | sort | uniq -c | awk '{printf "%s %s, ", $2, $1}')
  others=$(find "$exported" -type f ! -name manifest.json ! \( -iname '*.txt' -o -iname '*.log' -o -iname '*.json' -o -iname '*.plist' -o -iname '*.xml' \) | wc -l | tr -d ' ')
  rm -rf "$bundle" "$exported" "$proof_plan"
  if [ "$others" = 0 ]; then
    say "PROOF the failure left no picture or recording (kinds left: ${kinds:-none})"
  else
    say "PROOF NOT MET: the failure left $others files that are not text (kinds: $kinds), which were deleted unopened: stop and report before anything else runs"
    unproven=1
  fi
}

send_push() {
  [ -n "${KR_PUSH_TOOL:-}" ] && [ -f "$KR_PUSH_TOOL" ] || { say "KR_PUSH_TOOL names no script"; return 1; }
  local file="$work/push/probe-push.json"
  rm -f "$file"
  target_copy "Documents/probe-push.json" "$file" && [ -s "$file" ] || { say "the application left no token file"; return 1; }
  node "$KR_PUSH_TOOL" --token-file "$file" --validate-only || return 1
  node "$KR_PUSH_TOOL" --token-file "$file" || return 1
  rm -f "$file"
}

# The names and outcomes of the tests, and the lines the tests said; skipped tests are named too, so
# a session that skipped what it was for does not read as a pass.
report() { # <output>
  grep -E "Test Case '.*' (started|passed|failed|skipped)|Executed [0-9]+ test|\*\* TEST|Restarting after unexpected exit, crash, or test timeout" "$1" \
    | sed -E "s/Test Case '-\[KalaReachUITests\./Test Case '[/" || true
}

# Ends the driver the record names, if it is still running: a session killed with no chance to stop it
# leaves its xcodebuild behind, and nothing is uninstalled or deleted while that is still driving the
# phone. Only a process the record names whose command is the test run.
stop_recorded_driver() {
  local pid waited=0
  for pid in $(sed -n 's/^runner=//p' "$record" | sort -u); do
    kill -0 "$pid" 2>/dev/null || continue
    ps -o command= -p "$pid" 2>/dev/null | grep -q 'xcodebuild test-without-building' || continue
    say "stopping the test run $pid that the record names"
    kill "$pid" 2>/dev/null
    while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 30 ]; do sleep 1; waited=$((waited + 1)); done
    kill -9 "$pid" 2>/dev/null
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then say "THE TEST RUN $pid WOULD NOT STOP: nothing is cleaned up"; exit 3; fi
  done
}

cleanup() {
  require_lease
  require_target
  mkdir -p "$work/checks" "$raw"
  [ -f "$record" ] || { say "no session left a record, so there is nothing of ours to clean up"; return 0; }
  # Only what the record names: the same kind of target and the same phone.
  [ "$(sed -n 's/^target=//p' "$record")" = "$target" ] && [ "$(sed -n 's/^device=//p' "$record")" = "$KR_DEVICE" ] \
    || die "the record at $record is of another target or phone: nothing is touched"
  boot_simulator
  say "cleaning up the session the record names"
  stop_recorded_driver
  local keep_app=0
  if [ "$(installed_state "$app_id")" = yes ]; then
    if grep -q '^baseline=empty$' "$record"; then
      copy_shots "cleanup"
      echo "sweep=pending" >> "$record"
      if sweep; then
        echo "sweep=done" >> "$record"
      else
        say "THE KEYCHAIN GROUPS ARE NOT KNOWN TO BE EMPTY: the application stays installed"
        keep_app=1
        unclean=1
      fi
    else
      say "that session did not begin with an empty baseline, so nothing is swept: report what is there"
    fi
  elif grep -q '^baseline=empty$' "$record" && [ "$(sed -n 's/^sweep=//p' "$record" | tail -1)" != done ]; then
    # The application is gone and no sweep of this session is known to have finished: what it filed in the
    # two groups cannot be counted from here.
    say "THE KEYCHAIN GROUPS ARE NOT KNOWN TO BE EMPTY: the application is gone and the session's sweep did not finish"
    unclean=1
  fi
  [ "$keep_app" = 1 ] || target_uninstall "$app_id"
  target_uninstall "$runner_id"
  for id in "$app_id" "$runner_id"; do
    if [ "$id" = "$app_id" ] && [ "$keep_app" = 1 ]; then continue; fi
    if [ "$(installed_state "$id")" = no ]; then say "$id is gone"; else say "$id is STILL INSTALLED or not known to be gone"; unclean=1; fi
  done
  [ "$unclean" = 0 ] && rm -f "$record"
  rm -rf "${work:?}/push" "${work:?}/checks" "${raw:?}" "$(dirname "$(cat "$work/tests-$target.path" 2>/dev/null)")/attachment-proof.xctestrun"
  [ "$unclean" = 0 ] || exit 3
}

command=${1:-}
shift || true
case $command in
  build-app) require_target; build_app "$@" ;;
  build-tests) require_target; build_tests ;;
  session) session "$@" ;;
  cleanup) cleanup ;;
  *) sed -n '2,38p' "$0"; exit 2 ;;
esac
