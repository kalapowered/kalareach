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
#   s1   push to this phone through Firebase, with the person not touching notifications, 45 minutes
#   s2   the keyboard, rotation, accessibility, file pickers, recovery: person at the phone, 90 minutes
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
#   KR_DEVICE                  the phone's identifier for devicectl (or the simulator's name)
#   KR_DEVICE_LEASE            the lease that is held while this runs
#   KR_SIGN_IDENTITY, KR_SIGN_FLAGS, KR_APP_PROFILE, KR_EXTENSION_PROFILE, KR_RUNNER_PROFILE
#                              the signing choices of a device build (see Build.xcconfig)
#   KR_GOOGLE_SERVICE_INFO     the Firebase configuration, for a build that has push
#   KR_KEYCHAIN, KR_KEYCHAIN_PASSWORD_FILE
#                              the keychain that holds the signing identity, unlocked before a device build
#   KR_PUSH_TOOL               the script that sends the one test notification (session s1 only)
# And, optional: KR_TARGET=simulator to run everything on a simulator instead of the phone,
# KR_WORK (products and results, on the internal disk) and KR_SHOTS (the application's pictures).
set -u

here=$(cd "$(dirname "$0")" && pwd)
companion=$(cd "$here/.." && pwd)
apple="$companion/src-tauri/gen/apple"
target=${KR_TARGET:-device}
work=${KR_WORK:-$HOME/Library/Caches/kalareach-device-ios}
shots=${KR_SHOTS:-/tmp/kalareach-device-ios}
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
    rm -f "$work/apps.json"
    xcrun devicectl device info apps --device "$KR_DEVICE" --bundle-id "$1" --quiet --json-output "$work/apps.json" >/dev/null 2>&1 \
      && [ -s "$work/apps.json" ] || { echo unknown; return; }
    # The JSON's exact nesting is not promised, so every object in it is asked.
    python3 - "$work/apps.json" "$1" <<'PY'
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
  if [ "$target" = device ]; then xcrun devicectl device install app --device "$KR_DEVICE" "$1" >/dev/null; else xcrun simctl install "$KR_DEVICE" "$1"; fi
}

target_uninstall() { # <bundle id>
  if [ "$target" = device ]; then xcrun devicectl device uninstall app --device "$KR_DEVICE" "$1" >/dev/null 2>&1; else xcrun simctl uninstall "$KR_DEVICE" "$1" >/dev/null 2>&1; fi
}

target_launch() { # <args...>: starts the application afresh with these arguments
  if [ "$target" = device ]; then
    xcrun devicectl device process launch --device "$KR_DEVICE" --terminate-existing "$app_id" "$@" >/dev/null
  else
    xcrun simctl terminate "$KR_DEVICE" "$app_id" >/dev/null 2>&1
    xcrun simctl launch "$KR_DEVICE" "$app_id" "$@" >/dev/null
  fi
}

# Copies one file out of the application's own container.
target_copy() { # <path inside the container> <local file>
  mkdir -p "$(dirname "$2")"
  if [ "$target" = device ]; then
    xcrun devicectl device copy from --device "$KR_DEVICE" --domain-type appDataContainer --domain-identifier "$app_id" \
      --source "$1" --destination "$2" >/dev/null 2>&1
  else
    cp "$(xcrun simctl get_app_container "$KR_DEVICE" "$app_id" data)/$1" "$2" 2>/dev/null
  fi
}

# MARK: What a device check leaves

# Starts a device check in the application, waits for its file and prints it.
run_check() { # <mode> <file stem>
  local file="$work/checks/probe-$2.txt"
  rm -f "$file"
  target_launch -KRDeviceProbe "$1"
  local waited=0
  while [ "$waited" -lt 60 ]; do
    sleep 2; waited=$((waited + 2))
    if target_copy "Documents/probe-$2.txt" "$file" && [ -s "$file" ]; then cat "$file"; return 0; fi
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
  echo "empty" > "$work/last-baseline"
}

sweep() {
  say "removing what the application and its libraries filed in the two groups"
  run_check sweep sweep > "$work/checks/sweep.out" || { say "the sweep did not report"; return 1; }
  [ "$(fact "$work/checks/probe-sweep.txt" ok)" = 1 ] && [ "$(fact "$work/checks/probe-sweep.txt" remaining)" = 0 ] \
    || { say "the sweep left something, or was refused: $(grep -E '^(remaining|ok|failed)=' "$work/checks/probe-sweep.txt" | tr '\n' ' ')"; return 1; }
}

# MARK: Builds

# The signing and push choices go to Local.xcconfig, which Build.xcconfig reads and the repository ignores.
write_local_xcconfig() { # <with push: yes|no>
  {
    if [ "$target" = device ]; then
      [ -n "${KR_SIGN_IDENTITY:-}" ] && [ -n "${KR_APP_PROFILE:-}" ] && [ -n "${KR_EXTENSION_PROFILE:-}" ] && [ -n "${KR_RUNNER_PROFILE:-}" ] \
        || die "a device build needs KR_SIGN_IDENTITY, KR_APP_PROFILE, KR_EXTENSION_PROFILE and KR_RUNNER_PROFILE"
      echo "KR_SIGN_STYLE = Manual"
      echo "KR_SIGN_IDENTITY = $KR_SIGN_IDENTITY"
      echo "KR_SIGN_FLAGS = ${KR_SIGN_FLAGS:-}"
      echo "KR_APP_PROFILE = $KR_APP_PROFILE"
      echo "KR_EXTENSION_PROFILE = $KR_EXTENSION_PROFILE"
      echo "KR_RUNNER_PROFILE = $KR_RUNNER_PROFILE"
    fi
    if [ "$1" = yes ]; then
      [ -f "${KR_GOOGLE_SERVICE_INFO:-}" ] || die "KR_GOOGLE_SERVICE_INFO names no file"
      echo "KR_GOOGLE_SERVICE_INFO = $KR_GOOGLE_SERVICE_INFO"
    fi
  } > "$apple/Local.xcconfig"
}

unlock_keychain() {
  [ "$target" = device ] || return 0
  [ -n "${KR_KEYCHAIN:-}" ] && [ -f "${KR_KEYCHAIN_PASSWORD_FILE:-}" ] || die "KR_KEYCHAIN and KR_KEYCHAIN_PASSWORD_FILE are needed to sign"
  security unlock-keychain -p "$(cat "$KR_KEYCHAIN_PASSWORD_FILE")" "$KR_KEYCHAIN" || die "the signing keychain would not unlock"
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
  unlock_keychain
  local flavour=app
  [ "$harness" = yes ] && flavour=harness
  [ "$push" = no ] && flavour=$flavour-nofirebase
  local arguments=(--debug --ci)
  if [ "$target" = device ]; then arguments+=(--target aarch64 --archive-only); else arguments+=(--target aarch64-sim); fi
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
  say "built $work/$flavour.app"
}

build_tests() {
  mkdir -p "$work"
  write_local_xcconfig no
  unlock_keychain
  local derived="$work/tests-$target"
  ( cd "$apple" && xcodebuild build-for-testing -project companion-tauri.xcodeproj -scheme "$tests_scheme" -sdk "$(sdk)" \
      -destination "generic/platform=$([ "$target" = device ] && echo iOS || echo 'iOS Simulator')" -derivedDataPath "$derived" ) \
    > "$work/build-tests-$target.log" 2>&1 || { tail -20 "$work/build-tests-$target.log"; die "the test build failed"; }
  local plan
  plan=$(ls "$derived"/Build/Products/*.xctestrun 2>/dev/null | head -1)
  [ -f "$plan" ] || die "the test build left no test plan"
  cp "$plan" "$work/tests-$target.xctestrun"
  # Nothing the runner can keep is kept: no recording, no picture, no attachment, no diagnostics.
  local key=":$tests_scheme"
  /usr/libexec/PlistBuddy -c "Set $key:SystemAttachmentLifetime keepNever" "$work/tests-$target.xctestrun" 2>/dev/null
  /usr/libexec/PlistBuddy -c "Set $key:UserAttachmentLifetime keepNever" "$work/tests-$target.xctestrun" 2>/dev/null
  /usr/libexec/PlistBuddy -c "Set $key:DiagnosticCollectionPolicy 0" "$work/tests-$target.xctestrun" 2>/dev/null
  /usr/libexec/PlistBuddy -c "Delete $key:CommandLineArguments" "$work/tests-$target.xctestrun" 2>/dev/null
  /usr/libexec/PlistBuddy -c "Add $key:CommandLineArguments array" "$work/tests-$target.xctestrun"
  local at=0
  for each in -DisableDiagnosticScreenRecordings YES -DisableDiagnosticScreenshots YES; do
    /usr/libexec/PlistBuddy -c "Add $key:CommandLineArguments:$at string $each" "$work/tests-$target.xctestrun"; at=$((at + 1))
  done
  say "built the test runner, plan at $work/tests-$target.xctestrun"
  runner_app=$(ls -d "$derived"/Build/Products/*/"$tests_scheme-Runner.app" | head -1)
  echo "$runner_app" > "$work/runner-$target.path"
}

# MARK: Sessions

# Each session: the application's build, the tests it runs, how long it may take in minutes, and
# whether the person is at the phone.
session_tests() { # <name>
  case $1 in
    s0) echo "ProofTests KeychainTests LifecycleTests" ;;
    s1) echo "PushTests/testALegWithTheApplicationTerminated PushTests/testALegWithTheApplicationInTheBackground" ;;
    s2) echo "RecoveryTests LayoutTests AccessibilityTests PickerTests" ;;
    s3a) echo "AudioTests/testARefusedMicrophoneIsSaidAndNothingOpens" ;;
    s3b) echo "AudioTests/testAnAllowedMicrophoneOpensTheSessionAndAChangeOfRouteIsCounted" ;;
    s4) echo "AudioTests/testAudioCarriesOnThroughALockedScreen" ;;
    *) return 1 ;;
  esac
}
session_minutes() { case $1 in s0) echo 20 ;; s1) echo 45 ;; s2) echo 90 ;; s3a) echo 10 ;; s3b) echo 15 ;; s4) echo 10 ;; esac; }
# Which build of the application a session installs: s0 and s1 hold Firebase's configuration, s2 runs the harness page.
session_app() { case $1 in s0 | s1) echo app ;; s2) echo harness-nofirebase ;; *) echo app-nofirebase ;; esac; }

ending=0
# What every session ends with, however it ends: the sweep, then the application and the runner removed.
finish_session() {
  [ "$ending" = 1 ] && return
  ending=1
  say "ending the session"
  if [ "${baseline_was_empty:-0}" = 1 ]; then sweep; fi
  target_uninstall "$app_id"
  target_uninstall "$runner_id"
  local left=0
  for id in "$app_id" "$runner_id"; do
    if [ "$(installed_state "$id")" = no ]; then say "$id is gone"; else say "$id is STILL INSTALLED or not known to be gone"; left=1; fi
  done
  [ "$left" = 0 ] && rm -f "$work/last-baseline"
  rm -rf "${work:?}/push" "${work:?}/checks"
}

session() {
  local name=${1:-}
  local tests minutes
  tests=$(session_tests "$name") || die "unknown session $name"
  minutes=$(session_minutes "$name")
  require_lease
  require_target
  mkdir -p "$work/checks" "$work/push" "$shots"
  [ -f "$work/$(session_app "$name").app/Info.plist" ] || die "build the application first: build-app (the $(session_app "$name") build)"
  [ -f "$work/tests-$target.xctestrun" ] || die "build the test runner first: build-tests"
  boot_simulator
  # The application and the runner are not on the phone to begin with; if either is, it is not this session's.
  for id in "$app_id" "$runner_id"; do
    case $(installed_state "$id") in
      no) ;;
      yes) die "$id is already installed: it is not this session's, so nothing is touched" ;;
      *) die "the phone did not say whether $id is installed" ;;
    esac
  done
  baseline_was_empty=0
  trap finish_session EXIT INT TERM
  say "installing"
  target_install "$work/$(session_app "$name").app" || die "the application did not install"
  target_install "$(cat "$work/runner-$target.path")" || die "the test runner did not install"
  rm -f "$work/last-baseline"
  baseline
  baseline_was_empty=1

  say "session $name: $tests (at most $((minutes + 10)) minutes)"
  local result="$work/result-$name.xcresult" out="$work/session-$name.out"
  rm -rf "$result" "$out"
  local only=()
  for each in $tests; do only+=("-only-testing:$tests_scheme/$each"); done
  xcodebuild test-without-building -xctestrun "$work/tests-$target.xctestrun" -destination "$(destination)" \
    -resultBundlePath "$result" -collect-test-diagnostics never "${only[@]}" > "$out" 2>&1 &
  local runner=$! started waits=0 sent=0
  started=$(date +%s)
  while kill -0 "$runner" 2>/dev/null; do
    sleep 2
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
      kill "$runner" 2>/dev/null
      break
    fi
  done
  wait "$runner" 2>/dev/null
  local status=$?
  report "$out"
  say "session $name finished, xcodebuild status $status"
  exit "$status"
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

# The names and outcomes of the tests and the lines the tests said, and nothing else of the run.
report() { # <output>
  grep -E "KR-|Test Case '.*' (started|passed|failed)|Executed [0-9]+ test|\*\* TEST" "$1" \
    | sed -E "s/Test Case '-\[KalaReachUITests\./Test Case '[/" || true
}

cleanup() {
  require_lease
  require_target
  mkdir -p "$work/checks"
  boot_simulator
  say "looking for what a session left"
  if [ "$(installed_state "$app_id")" = yes ]; then
    # Only a session that began with empty groups may sweep them: otherwise what is there is not ours.
    if [ -f "$work/last-baseline" ]; then sweep; else say "no empty baseline is on record, so no sweep: report what is there"; fi
  fi
  target_uninstall "$app_id"
  target_uninstall "$runner_id"
  local left=0
  for id in "$app_id" "$runner_id"; do
    if [ "$(installed_state "$id")" = no ]; then say "$id is gone"; else say "$id is STILL INSTALLED or not known to be gone"; left=1; fi
  done
  [ "$left" = 0 ] && rm -f "$work/last-baseline"
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
