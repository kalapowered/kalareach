#!/usr/bin/env bash
#
# Drives the voice surface on the iOS Simulator, the Android emulator and the desktop window, and
# writes a qualification log made only of what this run actually checked.
#
# Two rules govern this script. It asserts rather than photographs: the screenshots are evidence
# beside the assertions, never instead of them. And it claims nothing it did not establish: every
# PROVED line in the log comes from an assertion that passed on this run, every clause the run could
# not reach is printed as NOT PROVED with the reason, and no figure is printed that nothing measured.
# A screenshot's PROVED line is built from the very words the platform reported on that screenshot,
# and from the words it reported absent, so it cannot say more than the check that allowed it.
#
# What a person can see is read from the screen: every claim that something is on screen, in the
# browser engines, the desktop window and the phones alike, is held to what the system's text
# recognition reads in an image of it, taken as the page draws itself, every word whole and in
# order. A page's structure only says where to look; what must be absent is counted in it with
# hidden elements included. Without text recognition (macOS's Vision framework, compiled here with
# swiftc) nothing a person sees can be checked, and the run says so.
#
# The page is the harness: the real screen against the scripted host. Its starting state comes from
# the address (voice_terms, voice_capture, voice_broker), later changes from the host's controls,
# and a call screen is reached by pressing the start control, never by an address alone.
#
# Rows this run can speak to:
#   KR-REQ-15.09  managed content access disclosed in the provider choice
#   KR-REQ-15.19  the provider, the sessions, the context scope and the rate shown before voice starts
#   KR-REQ-15.17  local mute, playback stop and closure survive an unreachable voice service
#   KR-REQ-15.22  stopping the voice is not cancelling a turn
#   KR-REQ-15.35  the interruption states the surface draws
#   KR-REQ-15.36  muted or unavailable capture displayed, with the refusal beside it
#
# Rows a simulator and an emulator cannot close, and which this script therefore does not claim:
#   KR-REQ-15.34  audio after a hardware screen lock
#   KR-ACC-014    a screen-lock call on a handset
#   KR-PERF-010   first-audio and delegation latency, which need a connected media path
#
# Usage:
#   scripts/e2e-voice-device.sh           # every platform that is available here
#   scripts/e2e-voice-device.sh ios
#   scripts/e2e-voice-device.sh android
#   scripts/e2e-voice-device.sh desktop
#
# Exit codes: 0 every requested platform ran, 2 bad usage or a failed assertion, 3 a requested
# platform is not available on this machine.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/voice-device"
shots="${KR_MOBILE_SCREENSHOT_DIR:-/tmp}"
port="${KR_VOICE_TEST_PORT:-4188}"
want="${1:-all}"

case "$want" in
    ios | android | desktop | all) ;;
    *) printf 'unknown target: %s\n' "$want" >&2; exit 2 ;;
esac

mkdir -p "${artefacts:?}"
log="$artefacts/e2e-voice-device.log"
: >"${log:?}"

say() { printf '== [e2e-voice-device] %s\n' "$*" | tee -a "${log:?}"; }

# What this run established, and what it could not. Both are printed at the end, and neither is a
# fixed list: they are appended as the run reaches each check.
proved_lines=()
unproved_lines=()
missing_platforms=()
failures=0

proved() { proved_lines+=("$*"); }
unproved() { unproved_lines+=("$*"); }
fail() { failures=$((failures + 1)); say "FAILED: $*"; }

# ---- The harness the surfaces are driven in ----------------------------------------------------

server=0
ios_booted_here=0
ios_udid=""
android_started_here=0
android_serial=""
android_pid=""
adb_path=""

# Ends a process this run started and every process it started in turn, by process id, the
# children first so none is left without a parent this run can still name.
end_tree() {
    local pid=$1 child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        end_tree "$child"
    done
    kill "$pid" 2>/dev/null || true
}

cleanup() {
    # Only what this run started, and only by the identity this run recorded. The harness server is
    # a shell, a launcher and the server itself; all three go.
    if [ "${server:-0}" -ne 0 ]; then
        end_tree "${server:?}"
        wait "${server:?}" 2>/dev/null || true
    fi
    if [ "$ios_booted_here" = 1 ] && [ -n "$ios_udid" ]; then
        say "shutting down the simulator this run booted"
        xcrun simctl shutdown "$ios_udid" 2>/dev/null || true
    fi
    # The emulator this run launched, by the process this run launched, and nothing else. A serial
    # names whatever is listening on a port; the process is this run's own.
    if [ "$android_started_here" = 1 ] && [ -n "$android_pid" ]; then
        say "stopping the emulator this run started"
        kill "$android_pid" 2>/dev/null || true
        wait "$android_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT

say "building the harness bundle"
if ! ( cd "$companion" && pnpm build:harness ) >"$artefacts/build.log" 2>&1; then
    say "the harness bundle did not build; see $artefacts/build.log"
    exit 2
fi

# The section page: the harness in a frame the size of the screen, with the section named by `show`
# brought to the top of the frame's own scrolling. A phone test that can only take pictures asks for
# each section it photographs this way, because the simulator's browser cannot be scrolled from
# outside without taking focus. Written into the built bundle, which nothing tracks, on every run.
cat >"$companion/dist-harness/voice-section.html" <<'HTML'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Voice section</title>
<style>html, body { margin: 0; height: 100%; overflow: hidden } iframe { position: fixed; inset: 0; width: 100%; height: 100%; border: 0 }</style>
</head>
<body>
<iframe id="page" title="Voice"></iframe>
<script>
  const params = new URLSearchParams(location.search)
  const show = params.get('show')
  params.delete('show')
  const frame = document.getElementById('page')
  frame.src = 'harness.html?' + params.toString()
  const began = Date.now()
  // Kept at the top while the host's answers arrive and move it, for a few seconds.
  const keep = setInterval(() => {
    const inner = frame.contentDocument
    const heading = inner && [...inner.querySelectorAll('h1, h2, h3')].find((element) => element.textContent.trim() === show)
    if (heading) heading.scrollIntoView({ block: 'start' })
    if (Date.now() - began > 8000) clearInterval(keep)
  }, 200)
</script>
</body>
</html>
HTML

# An empty page, which each phone shot opens first so the page before cannot pass for the next one.
printf '<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><title>Blank</title></head><body></body></html>\n' \
    >"$companion/dist-harness/blank.html"

# Something already answering on the port is not this run's server, and the pages it serves could be
# another build's, so the run stops rather than take them for this one.
if curl -s -o /dev/null "http://localhost:$port/"; then
    say "something this run did not start is already serving on port $port, so this run stops"
    exit 2
fi
say "serving the harness on port $port"
( cd "$companion" && PORT="$port" node scripts/preview-harness.mjs ) >"$artefacts/serve.log" 2>&1 &
server=$!

ready=0
for _ in $(seq 1 60); do
    # Ready only while the server this run started is still running.
    kill -0 "$server" 2>/dev/null || break
    if curl -fsS "http://localhost:$port/harness.html" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
done
if [ "$ready" != 1 ]; then
    say "the harness did not start; see $artefacts/serve.log"
    exit 2
fi

# ---- What a screenshot shows --------------------------------------------------------------------
#
# A screenshot is evidence of what it shows, and a file that exists shows nothing by being there: a
# browser still starting draws an empty page and the capture of it is a valid, non-empty image. So
# no screenshot is claimed here until the image itself, read with the system's text recognition,
# shows the words the claim is about.

ocr=""
ocr_ready() {
    [ -n "$ocr" ] && return 0
    command -v swiftc >/dev/null 2>&1 || return 1
    local source="$artefacts/read-text.swift"
    cat >"${source:?}" <<'SWIFT'
import AppKit
import Vision

// Prints the text the system recognises in one image: a line of the image per line, from the top
// down and, along a line, from the left.
guard CommandLine.arguments.count == 2,
      let image = NSImage(contentsOfFile: CommandLine.arguments[1]),
      let picture = image.cgImage(forProposedRect: nil, context: nil, hints: nil) else { exit(2) }

// Text that runs to the edges of an image, as it does in a picture of one element, is not found, so
// the picture is first set on a margin of its own background, the colour of its corner.
let margin = 32
let space = CGColorSpaceCreateDeviceRGB()
let layout = CGImageAlphaInfo.premultipliedLast.rawValue
var corner = [UInt8](repeating: 255, count: 4)
if let pixel = picture.cropping(to: CGRect(x: 0, y: 0, width: 1, height: 1)) {
    corner.withUnsafeMutableBytes { bytes in
        CGContext(data: bytes.baseAddress, width: 1, height: 1, bitsPerComponent: 8, bytesPerRow: 4,
                  space: space, bitmapInfo: layout)?
            .draw(pixel, in: CGRect(x: 0, y: 0, width: 1, height: 1))
    }
}
guard let framed = CGContext(data: nil, width: picture.width + 2 * margin, height: picture.height + 2 * margin,
                             bitsPerComponent: 8, bytesPerRow: 0, space: space, bitmapInfo: layout) else { exit(2) }
framed.setFillColor(CGColor(red: CGFloat(corner[0]) / 255, green: CGFloat(corner[1]) / 255,
                            blue: CGFloat(corner[2]) / 255, alpha: 1))
framed.fill(CGRect(x: 0, y: 0, width: framed.width, height: framed.height))
framed.draw(picture, in: CGRect(x: margin, y: margin, width: picture.width, height: picture.height))
guard let page = framed.makeImage() else { exit(2) }

let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
try VNImageRequestHandler(cgImage: page, options: [:]).perform([request])

// Vision's own order is not the reading order, so the pieces it finds are put back into rows by
// where they sit.
struct Piece { let box: CGRect; let text: String }
let pieces = (request.results ?? [])
    .compactMap { line in line.topCandidates(1).first.map { Piece(box: line.boundingBox, text: $0.string) } }
    .sorted { $0.box.midY > $1.box.midY }
var rows: [[Piece]] = []
for piece in pieces {
    if let last = rows.last?.last, abs(last.box.midY - piece.box.midY) < min(last.box.height, piece.box.height) / 2 {
        rows[rows.count - 1].append(piece)
    } else {
        rows.append([piece])
    }
}
for row in rows {
    print(row.sorted { $0.box.minX < $1.box.minX }.map(\.text).joined(separator: " "))
}
SWIFT
    swiftc -O -o "$artefacts/read-text" "$source" >"$artefacts/read-text-build.log" 2>&1 || return 1
    ocr="$artefacts/read-text"
}

# The words of a text, in lower case, one space between them and one at each end. Spacing, line
# breaks and punctuation only separate words, so a phrase the screen wrapped or a comma the
# recogniser missed reads the same, while every word is compared whole: "Unmute" is not "Mute", and
# "0.01" (the words 0 and 01) is not "00.1".
words_of() {
    printf ' %s ' "$(printf '%s' "$1" | LC_ALL=C tr '[:upper:]' '[:lower:]' |
        LC_ALL=C sed -E 's/[^[:alnum:]]+/ /g; s/^ +//; s/ +$//' | tr '\n' ' ' | sed -E 's/ +/ /g; s/ $//')"
}

# True when each of the phrases after the image path is read in it, every word whole and in order.
# Every variable here is local: a caller's own word lists must come back exactly as they went in.
image_shows() {
    local image=$1 text phrase
    shift
    text="$("$ocr" "$image" 2>/dev/null)" || return 1
    text="$(words_of "$text")"
    for phrase in "$@"; do
        [[ "$text" == *"$(words_of "$phrase")"* ]] || return 1
    done
}

# True when none of the phrases after the image path is read in it.
image_lacks() {
    local image=$1 text phrase
    shift
    text="$("$ocr" "$image" 2>/dev/null)" || return 1
    text="$(words_of "$text")"
    for phrase in "$@"; do
        [[ "$text" == *"$(words_of "$phrase")"* ]] && return 1
    done
    return 0
}

# The clause of a screenshot claim: the words the platform reported on it and, after `--without`,
# the words it reported absent, quoted as they were checked.
words_clause() {
    local seen="" missing="" into=seen word
    for word in "$@"; do
        if [ "$word" = "--without" ]; then
            into=missing
        elif [ "$into" = seen ]; then
            seen="${seen:+$seen, }\"$word\""
        else
            missing="${missing:+$missing, }\"$word\""
        fi
    done
    printf 'showed %s' "$seen"
    if [ -n "$missing" ]; then printf ', and no %s' "$missing"; fi
}

# The words before `--without`, and the words after it, one per line.
words_wanted() {
    local word
    for word in "$@"; do
        [ "$word" = "--without" ] && return 0
        printf '%s\n' "$word"
    done
}
words_unwanted() {
    local word after=0
    for word in "$@"; do
        if [ "$after" = 1 ]; then printf '%s\n' "$word"; fi
        [ "$word" = "--without" ] && after=1
    done
    return 0
}

urlencoded() { python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "$1"; }

# The address of the voice screen on a surface, with a starting state, and when a heading is named,
# the section page that brings that section to the top.
voice_address() {
    local surface=$1 state=$2 heading=${3:-}
    if [ -n "$heading" ]; then
        printf 'http://localhost:%s/voice-section.html?surface=%s&tab=voice%s&show=%s' \
            "$port" "$surface" "$state" "$(urlencoded "$heading")"
    else
        printf 'http://localhost:%s/harness.html?surface=%s&tab=voice%s' "$port" "$surface" "$state"
    fi
}

# ---- The assertions, in the engine each platform draws the surface with -------------------------

run_assertions() {
    say "asserting the surface in WebKit and Chromium"
    ocr_ready || {
        fail "no text recognition on this machine, so nothing a person sees can be asserted"
        return 0
    }
    if node --experimental-strip-types "$companion/test/voice/assert-voice-surface.ts" \
        "http://localhost:$port" "$ocr" "$shots" >"$artefacts/assertions.log" 2>&1; then
        while IFS= read -r line; do
            case "$line" in
                proved\ *) proved "${line#proved }" ;;
                unproved\ *) unproved "${line#unproved }" ;;
            esac
        done <"$artefacts/assertions.log"
        say "$(grep -c '^proved ' "$artefacts/assertions.log" || true) clauses asserted"
    else
        fail "the surface assertions did not pass; see $artefacts/assertions.log"
        sed -n '$p' "$artefacts/assertions.log" | tee -a "${log:?}"
    fi
}

# ---- iOS ---------------------------------------------------------------------------------------

ios_leg() {
    say "driving the iOS voice surface"
    if ! command -v xcrun >/dev/null 2>&1; then
        say "no Xcode command line tools on this machine"
        missing_platforms+=("ios: no xcrun")
        return 3
    fi
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}"
    ios_udid="$(xcrun simctl list devices available -j 2>/dev/null |
        python3 "$here/scripts/simulator-identity.py" udid "$device" 2>/dev/null)"
    if [ -z "$ios_udid" ]; then
        say "no iOS simulator named $device is available"
        missing_platforms+=("ios: no simulator named $device")
        return 3
    fi

    local state
    state="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" state "$ios_udid")"
    # One device at a time, and only a device this run started: a simulator that is already booted
    # is somebody else's, and driving it would change what they are looking at.
    if [ "$state" = "Booted" ]; then
        say "$device ($ios_udid) is already booted by something else, so this run leaves it alone"
        missing_platforms+=("ios: $device is already in use")
        return 3
    fi
    if [ "$state" != "Booted" ]; then
        say "booting $device ($ios_udid)"
        xcrun simctl boot "$ios_udid" || { missing_platforms+=("ios: $device would not boot"); return 3; }
        ios_booted_here=1
        local booted=0
        for _ in $(seq 1 60); do
            if xcrun simctl list devices available -j |
                python3 "$here/scripts/simulator-identity.py" state "$ios_udid" | grep -q Booted; then
                booted=1
                break
            fi
            sleep 1
        done
        [ "$booted" = 1 ] || { say "$device did not finish booting"; missing_platforms+=("ios: boot timed out"); return 3; }
    fi

    local desc
    desc="$(xcrun simctl list devices available -j |
        python3 "$here/scripts/simulator-identity.py" describe "$ios_udid")"
    printf 'iOS device: %s\n' "$desc" | tee "$artefacts/ios-device.txt" | tee -a "${log:?}"

    # Opens an address and keeps a screenshot only once the image shows every one of the words and
    # none of the words after `--without`. Only then is the claim made, of exactly those words.
    shoot_ios() {
        local row=$1 address=$2 name=$3
        shift 3
        local wanted=() unwanted=() word
        while IFS= read -r word; do wanted+=("$word"); done < <(words_wanted "$@")
        while IFS= read -r word; do unwanted+=("$word"); done < <(words_unwanted "$@")
        ocr_ready || { say "no text recognition on this machine, so no iOS screenshot can be checked"; return 1; }
        # A simulator reports itself booted before it can open an address, so a refusal just after
        # boot is waited out, bounded.
        open_ios() {
            for _ in $(seq 1 20); do
                xcrun simctl openurl "$ios_udid" "$1" >/dev/null 2>&1 && return 0
                sleep 3
            done
            say "the simulator never opened $1"
            return 1
        }
        # Away first, to an empty page, until none of the words is on the screen: the page before
        # could otherwise pass for this one.
        open_ios "http://localhost:$port/blank.html" || return 1
        local cleared=0
        for _ in 1 2 3 4 5 6 7 8; do
            sleep 2
            xcrun simctl io "$ios_udid" screenshot --type=png "$shots/$name" >/dev/null 2>&1 || continue
            if image_lacks "$shots/$name" "${wanted[@]}"; then
                cleared=1
                break
            fi
        done
        [ "$cleared" = 1 ] || { say "the iOS screen never left the previous page"; return 1; }
        open_ios "$address" || return 1
        for _ in 1 2 3 4 5 6; do
            sleep "${KR_MOBILE_SETTLE:-4}"
            xcrun simctl io "$ios_udid" screenshot --type=png "$shots/$name" >/dev/null 2>&1 || continue
            if image_shows "$shots/$name" "${wanted[@]}" &&
                image_lacks "$shots/$name" ${unwanted[@]+"${unwanted[@]}"}; then
                say "iOS screenshot $shots/$name $(words_clause "$@")"
                proved "$row | the iOS Simulator screenshot $name $(words_clause "$@") | $desc"
                return 0
            fi
        done
        say "the iOS screen never $(words_clause "$@")"
        return 1
    }

    shoot_ios "KR-REQ-15.09, KR-REQ-15.19" "$(voice_address ios "")" "kr-voice-ios-15.09-disclosure.png" \
        "Start a voice session" "Voice model" "gpt-live-1" "What this gives access to" "Audio travels directly" ||
        fail "iOS provider choice screenshot"
    shoot_ios "KR-REQ-15.19" "$(voice_address ios "" "Sessions this call can reach")" \
        "kr-voice-ios-15.19-sessions.png" "Sessions this call can reach" "Session 1" ||
        fail "iOS sessions screenshot"
    shoot_ios "KR-REQ-15.19" "$(voice_address ios "" "What will be sent")" \
        "kr-voice-ios-15.19-context-scope.png" "What will be sent" "8,000 tokens" "Not sent" ||
        fail "iOS context scope screenshot"
    shoot_ios "KR-REQ-15.19" "$(voice_address ios "" "What it costs")" \
        "kr-voice-ios-15.19-rate.png" "What it costs" "a second" "Start voice session" ||
        fail "iOS rate screenshot"
    shoot_ios "KR-REQ-15.19" "$(voice_address ios "&voice_terms=unread")" \
        "kr-voice-ios-15.19-no-terms.png" "Start a voice session" "could not read the managed" ||
        fail "iOS no-terms screenshot"
    shoot_ios "KR-REQ-15.19" \
        "$(voice_address ios "&voice_terms=unread" "What speaking will be allowed to do")" \
        "kr-voice-ios-15.19-no-terms-end.png" "What speaking will be allowed to do" \
        --without "Start voice session" ||
        fail "iOS no-terms end-of-page screenshot"

    unproved "KR-REQ-15.36 | the call screen's capture states on the iOS Simulator | a call screen is reached by pressing start, and the simulator's browser cannot be pressed without taking focus; the states are asserted in WebKit above"
    unproved "KR-REQ-15.34 | duplex audio after a screen lock | the iOS Simulator has no microphone input and no lock screen"
    unproved "KR-ACC-014 | a screen-lock call | the same; the device leg is the operator gate"

    return 0
}

# Shuts down the simulator this run booted and waits, bounded, until it reports itself shut down.
# The run keeps it as its own until then, so the final cleanup still owns one that did not stop.
shut_down_ios() {
    [ "$ios_booted_here" = 1 ] || return 0
    say "shutting down the simulator this run booted"
    xcrun simctl shutdown "$ios_udid" >/dev/null 2>&1 || true
    local state
    for _ in $(seq 1 60); do
        state="$(xcrun simctl list devices available -j |
            python3 "$here/scripts/simulator-identity.py" state "$ios_udid" 2>/dev/null)"
        if [ "$state" = "Shutdown" ]; then
            ios_booted_here=0
            return 0
        fi
        sleep 1
    done
    say "the simulator this run booted still reports $state"
    return 1
}

run_ios() {
    local rc=0
    ios_leg || rc=$?
    # One device at a time on this machine: the simulator this run booted is shut down before any
    # other device is started, however the leg ended, and not left for the final cleanup.
    shut_down_ios || fail "the simulator this run booted did not shut down"
    return "$rc"
}

# ---- Android -----------------------------------------------------------------------------------

run_android() {
    say "driving the Android voice surface"
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}"
    adb_path="$sdk/platform-tools/adb"
    local emulator="$sdk/emulator/emulator"
    if [ ! -x "$adb_path" ]; then
        say "no Android platform tools"
        missing_platforms+=("android: no adb")
        adb_path=""
        return 3
    fi

    local running
    running="$("$adb_path" devices | awk '/^emulator-[0-9]+/ {print $1}' | tr '\n' ' ')"
    # One device at a time, and only a device this run started: an emulator that is already running
    # is somebody else's, and attaching to it would drive, and later stop, their device.
    if [ -n "$running" ]; then
        say "an emulator this run did not start is running ($running), so this run leaves it alone"
        missing_platforms+=("android: another emulator is running")
        return 3
    fi
    if [ -z "$android_serial" ]; then
        local avd="${KR_ANDROID_AVD:-Nines_API_36_Play}"
        if [ ! -x "$emulator" ]; then
            say "no Android emulator binary"
            missing_platforms+=("android: no emulator")
            return 3
        fi
        # A console port of this run's own choosing, so the emulator this run started is named
        # rather than guessed. Taking the first device `adb` lists would attach to, and later kill,
        # an emulator somebody else started.
        local console=""
        for candidate in 5554 5556 5558 5560 5562 5564 5566 5568 5570 5572; do
            if ! nc -z 127.0.0.1 "$candidate" >/dev/null 2>&1; then
                console="$candidate"
                break
            fi
        done
        if [ -z "$console" ]; then
            say "no free emulator console port"
            missing_platforms+=("android: no free console port")
            return 3
        fi

        say "starting the emulator $avd on console port $console"
        "$emulator" -avd "$avd" -port "$console" -crash-report-mode disabled -no-snapshot-save \
            -no-boot-anim -netdelay none -netspeed full >"$artefacts/emulator.log" 2>&1 &
        local emulator_pid=$!
        android_pid=$emulator_pid
        android_started_here=1
        # Bounded: `adb wait-for-device` on a virtual device that never appears waits for ever.
        local up=0 expected="emulator-$console"
        for _ in $(seq 1 180); do
            if ! kill -0 "$emulator_pid" 2>/dev/null; then
                say "the emulator process ended before it booted"
                break
            fi
            if "$adb_path" devices | grep -q "^$expected	device$" &&
                [ "$("$adb_path" -s "$expected" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; then
                android_serial="$expected"
                up=1
                break
            fi
            sleep 2
        done
        if [ "$up" != 1 ]; then
            say "the emulator did not come up within six minutes; see $artefacts/emulator.log"
            # Its own process, by the identity this run recorded, and nothing else.
            kill "$emulator_pid" 2>/dev/null || true
            android_started_here=0
            android_pid=""
            android_serial=""
            missing_platforms+=("android: emulator did not boot")
            return 3
        fi
    fi

    local model release sdkver
    model="$("$adb_path" -s "$android_serial" shell getprop ro.product.model | tr -d '\r')"
    release="$("$adb_path" -s "$android_serial" shell getprop ro.build.version.release | tr -d '\r')"
    sdkver="$("$adb_path" -s "$android_serial" shell getprop ro.build.version.sdk | tr -d '\r')"
    local desc="$android_serial, $model, Android $release, API $sdkver"
    printf 'Android device: %s\n' "$desc" | tee "$artefacts/android-device.txt" | tee -a "${log:?}"

    "$adb_path" -s "$android_serial" reverse "tcp:$port" "tcp:$port" >/dev/null 2>&1 || true

    # Opens an address in the browser. Just after a cold boot the system can report the boot
    # complete before it can resolve a browser for an address, so a refusal is waited out, bounded.
    open_android() {
        local answer
        for _ in $(seq 1 20); do
            answer="$("$adb_path" -s "$android_serial" shell \
                "am start -a android.intent.action.VIEW --es com.android.browser.application_id com.android.chrome -d '$1'" 2>&1)"
            case "$answer" in
                *Error*) sleep 3 ;;
                *) return 0 ;;
            esac
        done
        say "the browser never opened the address: $answer"
        return 1
    }
    # Presses a control by its text, the way a finger would: UI Automator reports where the browser
    # drew it, and a tap lands on its centre. The dump file is this run's own and is removed after.
    local dump="/sdcard/kr-voice-ui.xml"
    screen_has() {
        "$adb_path" -s "$android_serial" shell uiautomator dump "$dump" >/dev/null 2>&1 || return 2
        "$adb_path" -s "$android_serial" shell cat "$dump" 2>/dev/null |
            python3 -c 'import sys; page = sys.stdin.read(); sys.exit(0 if all(w in page for w in sys.argv[1:]) else 1)' "$@"
    }
    # Waits, bounded, until the screen shows every one of the words. A browser starting on a cold
    # emulator can take most of a minute to draw its first page.
    wait_for_android() {
        for _ in $(seq 1 30); do
            screen_has "$@" && return 0
            sleep 2
        done
        return 1
    }
    screen_lacks() {
        "$adb_path" -s "$android_serial" shell uiautomator dump "$dump" >/dev/null 2>&1 || return 2
        "$adb_path" -s "$android_serial" shell cat "$dump" 2>/dev/null |
            python3 -c 'import sys; page = sys.stdin.read(); sys.exit(0 if not any(w in page for w in sys.argv[1:]) else 1)' "$@"
    }
    wait_for_android_without() {
        for _ in $(seq 1 30); do
            screen_lacks "$@" && return 0
            sleep 2
        done
        return 1
    }
    # Keeps a screenshot of the screen as it is, once the image itself shows every one of the words
    # and none of the words after `--without` is anywhere on the page, and only then claims exactly
    # those words. The image is read with the same text recognition as the iOS screenshots, because
    # UI Automator's positions for a page scrolled inside a frame do not follow the scroll, so they
    # cannot say what a screenshot shows. It does say what a page holds, so it answers for what is
    # absent. `how` says what brought the screen there.
    capture_android() {
        local row=$1 name=$2 how=$3
        shift 3
        local wanted=() unwanted=() word
        while IFS= read -r word; do wanted+=("$word"); done < <(words_wanted "$@")
        while IFS= read -r word; do unwanted+=("$word"); done < <(words_unwanted "$@")
        ocr_ready || { say "no text recognition on this machine, so no Android screenshot can be checked"; return 1; }
        local seen=0
        for _ in $(seq 1 20); do
            sleep 3
            "$adb_path" -s "$android_serial" exec-out screencap -p >"$shots/$name" 2>/dev/null || continue
            if [ -s "$shots/$name" ] && image_shows "$shots/$name" "${wanted[@]}"; then
                seen=1
                break
            fi
        done
        if [ "$seen" != 1 ]; then
            # Kept to show what was on the screen instead, and named so it is never taken for
            # evidence of the page.
            mv "$shots/$name" "$shots/kr-voice-android-not-evidence-$name" 2>/dev/null || true
            say "the Android screen never $(words_clause "${wanted[@]}") (what it showed: $shots/kr-voice-android-not-evidence-$name)"
            return 1
        fi
        if [ "${#unwanted[@]}" -gt 0 ] && ! screen_lacks "${unwanted[@]}"; then
            mv "$shots/$name" "$shots/kr-voice-android-not-evidence-$name" 2>/dev/null || true
            say "the Android page carried one of: ${unwanted[*]}"
            return 1
        fi
        say "Android screenshot $shots/$name $(words_clause "$@")"
        proved "$row | the Android emulator screenshot $name, $how, $(words_clause "$@") | $desc"
    }
    # Opens an address and captures it. The browser is first moved to an empty page and held there
    # until none of the words is on it, because the words of the page before, or of a tab an earlier
    # run left open, would otherwise pass for this page's.
    shoot_android() {
        local row=$1 address=$2 name=$3
        shift 3
        local wanted=() word
        while IFS= read -r word; do wanted+=("$word"); done < <(words_wanted "$@")
        open_android "http://localhost:$port/blank.html" || return 1
        wait_for_android_without "${wanted[@]}" || { say "the Android screen never left the previous page"; return 1; }
        open_android "$address" || return 1
        capture_android "$row" "$name" "of the page it opened" "$@"
    }
    press_android() {
        local label=$1 centre=""
        for _ in 1 2 3 4 5 6 7 8; do
            # A dump taken while the page is still moving is refused; the next one is taken after
            # the page has settled, so a refusal here is a reason to look again, not to give up.
            if ! "$adb_path" -s "$android_serial" shell uiautomator dump "$dump" >/dev/null 2>&1; then
                sleep 2
                continue
            fi
            centre="$(find_android "$label")"
            if [ -n "$centre" ]; then
                # Read again once the page has rested, and press where the control rests.
                sleep 2
                "$adb_path" -s "$android_serial" shell uiautomator dump "$dump" >/dev/null 2>&1 &&
                    centre="$(find_android "$label")"
                [ -n "$centre" ] && break
            fi
            # Below the fold: scroll the page up by most of a screen, slowly enough that it stops
            # where the thumb lifts, so the next report's positions are where the control rests.
            "$adb_path" -s "$android_serial" shell input swipe 540 1800 540 900 900 >/dev/null 2>&1 || return 1
            sleep 3
        done
        [ -n "$centre" ] || { say "the $label control never came on screen"; return 1; }
        say "pressing $label at $centre"
        # shellcheck disable=SC2086
        "$adb_path" -s "$android_serial" shell input tap $centre >/dev/null 2>&1 || return 1
        sleep 2
    }
    find_android() {
        "$adb_path" -s "$android_serial" shell cat "$dump" 2>/dev/null | python3 -c '
import re, sys
label = sys.argv[1]
for node in re.finditer(r"<node [^>]*>", sys.stdin.read()):
    text = node.group(0)
    if f"text=\"{label}\"" in text or f"content-desc=\"{label}\"" in text:
        x1, y1, x2, y2 = map(int, re.search(r"bounds=\"\[(\d+),(\d+)\]\[(\d+),(\d+)\]\"", text).groups())
        # The browser reports a control that is off screen with no size at all; only one it has
        # drawn somewhere a finger can reach counts.
        if x2 > x1 and y2 > y1:
            print((x1 + x2) // 2, (y1 + y2) // 2)
            break
' "$1"
    }

    # A browser's first page on a cold emulator can take minutes on a busy machine. The page is
    # opened once and waited for before any evidence is taken, so the checks below measure the
    # page and not the browser starting.
    say "warming the browser"
    open_android "$(voice_address android "")" || true
    wait_for_android "Start a voice session" || wait_for_android "Start a voice session" ||
        wait_for_android "Start a voice session" || true

    shoot_android "KR-REQ-15.09, KR-REQ-15.19" "$(voice_address android "")" \
        "kr-voice-android-15.09-disclosure.png" \
        "Start a voice session" "Voice model" "gpt-live-1" "What this gives access to" "Audio travels directly" ||
        fail "Android provider choice screenshot"
    shoot_android "KR-REQ-15.19" "$(voice_address android "" "Sessions this call can reach")" \
        "kr-voice-android-15.19-sessions.png" "Sessions this call can reach" "Session 1" ||
        fail "Android sessions screenshot"
    shoot_android "KR-REQ-15.19" "$(voice_address android "" "What will be sent")" \
        "kr-voice-android-15.19-context-scope.png" "What will be sent" "8,000 tokens" "Not sent" ||
        fail "Android context scope screenshot"
    shoot_android "KR-REQ-15.19" "$(voice_address android "" "What it costs")" \
        "kr-voice-android-15.19-rate.png" "What it costs" "a second" "Start voice session" ||
        fail "Android rate screenshot"
    shoot_android "KR-REQ-15.19" "$(voice_address android "&voice_terms=unread")" \
        "kr-voice-android-15.19-no-terms.png" "Start a voice session" "could not read the managed" \
        --without "Start voice session" ||
        fail "Android no-terms screenshot"

    # The call screen, reached by pressing start on a host whose call reports no microphone.
    # A press the browser did not take leaves the start control where it was, and only then is it
    # pressed again; a press that was taken opens the call screen, which has no start control.
    pressed_into_call() {
        for _ in 1 2 3; do
            press_android "Start voice session" || return 1
            for _ in 1 2 3 4 5 6; do
                screen_has "No microphone available" && return 0
                sleep 2
            done
            screen_has "Start voice session" || return 1
        done
        return 1
    }
    local on_call=0
    if open_android "http://localhost:$port/blank.html" &&
        wait_for_android_without "Start a voice session" &&
        open_android "$(voice_address android "&voice_capture=unavailable")" &&
        wait_for_android "Start a voice session" && pressed_into_call; then
        capture_android "KR-REQ-15.36" "kr-voice-android-15.36-capture-unavailable.png" \
            "taken after the start control was pressed" \
            "No microphone available" "Nothing spoken while the microphone was not carrying" \
            --without "Start voice session" && on_call=1
    fi
    if [ "$on_call" != 1 ]; then
        unproved "KR-REQ-15.36 | the call screen on the Android emulator | UI Automator did not report the start control or the call screen, so no press could be checked"
    fi

    # The emulator's simulated call is a telephony state change, not a call on a handset. It is
    # recorded as what it is, and it is raised with the call screen open where a press reached it.
    say "raising the emulator's simulated incoming call"
    if "$adb_path" -s "$android_serial" emu gsm call 15555215554 >/dev/null 2>&1; then
        sleep 3
        "$adb_path" -s "$android_serial" exec-out screencap -p \
            >"$shots/kr-voice-android-15.35-incoming-call.png" || fail "Android incoming call screenshot"
        if "$adb_path" -s "$android_serial" emu gsm cancel 15555215554 >/dev/null 2>&1; then
            sleep 2
            proved "KR-REQ-15.35 | the emulator's simulated incoming call was raised and cancelled with the surface open | $desc"
        else
            fail "the simulated call would not cancel, and this emulator is left with it raised"
        fi
        unproved "KR-REQ-15.35 | audio focus loss to a real call | the emulator's telephony state change is not a call on a handset, and no call is connected to lose focus from"
    else
        unproved "KR-REQ-15.35 | the simulated incoming call | this emulator refused the telephony command"
    fi

    "$adb_path" -s "$android_serial" shell rm -f /sdcard/kr-voice-ui.xml >/dev/null 2>&1 || true

    unproved "KR-REQ-15.34 | audio from the foreground service after a screen lock | an emulator does not qualify a foreground microphone service; the device leg is the operator gate"
    return 0
}

# ---- Desktop -----------------------------------------------------------------------------------

run_desktop() {
    say "capturing the desktop voice screens"
    ocr_ready || {
        fail "no text recognition on this machine, so no desktop screenshot can be checked"
        return 0
    }
    # Each screenshot is taken once the page carries every one of its words and none of the words
    # after `--without`, hidden elements included, and is then read with the same text recognition
    # as the phones' screenshots: its PROVED line is made only of the words read in the image, and
    # of the words neither the page nor the image carried. The screenshots are of the whole page.
    local where='desktop window, headless Chromium, 1280x800'
    ( cd "$companion" && node --input-type=module -e "
      import { chromium } from '@playwright/test';
      const browser = await chromium.launch({ headless: true });
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
      const open = async (query) => {
        await page.goto('http://localhost:$port/harness.html?surface=desktop&tab=voice' + query);
        await page.waitForSelector('.kr-voice');
      };
      // The page is photographed as it draws itself, with nothing paused or changed: an animation
      // that ends is waited for, a little, and one that never ends is shown as it is.
      const settled = () => page.waitForFunction(() => document.getAnimations().every((animation) =>
        animation.playState !== 'running' || animation.effect?.getComputedTiming().endTime === Infinity),
        undefined, { timeout: 2000 }).catch(() => undefined);
      const shoot = async (row, name, how, words, without = []) => {
        for (const word of words) await page.getByText(word, { exact: false }).first().waitFor({ timeout: 5000 });
        for (const word of without) {
          if ((await page.getByText(word, { exact: false }).count()) !== 0) throw new Error(name + ' carried ' + word);
        }
        await settled();
        await page.screenshot({ path: '$shots/' + name, fullPage: true });
        console.log(['shot', row, name, how, words.join('|'), without.join('|')].join('\t'));
      };
      const start = async () => {
        await page.getByRole('button', { name: 'Start voice session' }).click();
        await page.getByRole('heading', { name: 'Voice session', exact: true }).waitFor({ timeout: 5000 });
      };
      await open('');
      await shoot('KR-REQ-15.09, KR-REQ-15.19', 'kr-voice-desktop-15.09-disclosure.png', 'of the provider choice',
        ['Voice model', 'gpt-live-1', 'What this gives access to', 'Audio travels directly', 'Sessions this call can reach',
         'Session 1', 'What will be sent', '8,000 tokens', 'Not sent', 'What it costs', 'a second', 'Start voice session']);
      await open('&voice_terms=unread');
      await shoot('KR-REQ-15.19', 'kr-voice-desktop-15.19-no-terms.png', 'of the provider choice without the service terms',
        ['could not read the managed', 'What will be sent'], ['Start voice session']);
      await open('&voice_capture=unavailable');
      await start();
      await shoot('KR-REQ-15.36', 'kr-voice-desktop-15.36-capture-unavailable.png', 'after the start control was pressed',
        ['No microphone available', 'Nothing spoken while the microphone was not carrying']);
      await page.evaluate(() => window.krTestHost.setVoiceCapture('muted_by_person'));
      await shoot('KR-REQ-15.36', 'kr-voice-desktop-15.36-muted.png', 'after the call reported the microphone muted',
        ['Microphone muted', 'Nothing spoken while the microphone was not carrying']);
      await open('');
      await start();
      await shoot('KR-REQ-15.22', 'kr-voice-desktop-15.22-call-screen.png', 'of a running call',
        ['Stop the voice', 'Cancel what the agent is doing', 'End session']);
      await browser.close();
    " ) >"$artefacts/desktop.log" 2>&1 || { fail "desktop screenshots; see $artefacts/desktop.log"; return 0; }
    local kind row name how seen unseen wanted unwanted words
    while IFS=$'\t' read -r kind row name how seen unseen; do
        [ "$kind" = shot ] || continue
        wanted=()
        unwanted=()
        IFS='|' read -r -a wanted <<<"$seen"
        if [ -n "$unseen" ]; then IFS='|' read -r -a unwanted <<<"$unseen"; fi
        words=("${wanted[@]}")
        if [ "${#unwanted[@]}" -gt 0 ]; then words+=(--without "${unwanted[@]}"); fi
        if image_shows "$shots/$name" "${wanted[@]}" &&
            image_lacks "$shots/$name" ${unwanted[@]+"${unwanted[@]}"}; then
            proved "$row | the $name screenshot, $how, $(words_clause "${words[@]}") | $where"
        else
            fail "the desktop screenshot $shots/$name never $(words_clause "${words[@]}")"
        fi
    done <"$artefacts/desktop.log"
    say "desktop screenshots under $shots"
    return 0
}

# ---- Execution ---------------------------------------------------------------------------------

run_assertions

platform_missing=0
case "$want" in
    ios) run_ios || platform_missing=1 ;;
    android) run_android || platform_missing=1 ;;
    desktop) run_desktop || platform_missing=1 ;;
    all)
        run_desktop || platform_missing=1
        run_ios || platform_missing=1
        # Never a second device while the first is still up.
        if [ "$ios_booted_here" = 1 ]; then
            say "the simulator is still running, so no emulator is started"
            missing_platforms+=("android: not started while this run's simulator was still running")
            platform_missing=1
        else
            run_android || platform_missing=1
        fi
        ;;
esac

{
    printf '\n'
    printf '================================================================================\n'
    printf 'Voice client qualification, %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf '================================================================================\n'
    printf '\nPROVED by this run (row | clause | where):\n'
    if [ "${#proved_lines[@]}" -eq 0 ]; then
        printf '  nothing\n'
    else
        printf '  %s\n' "${proved_lines[@]}"
    fi
    printf '\nNOT PROVED by this run (row | clause | why):\n'
    if [ "${#unproved_lines[@]}" -eq 0 ]; then
        printf '  nothing outstanding\n'
    else
        printf '  %s\n' "${unproved_lines[@]}"
    fi
    if [ "${#missing_platforms[@]}" -ne 0 ]; then
        printf '\nPlatforms not available here:\n'
        printf '  %s\n' "${missing_platforms[@]}"
    fi
    printf '\nScreenshots: %s\nArtefacts:   %s\n' "$shots" "$artefacts"
    printf '================================================================================\n'
} | tee -a "${log:?}"

if [ "$failures" -ne 0 ]; then
    say "$failures check(s) failed"
    exit 2
fi
if [ "$platform_missing" -ne 0 ]; then
    say "a requested platform was not available"
    exit 3
fi
say "run complete"
