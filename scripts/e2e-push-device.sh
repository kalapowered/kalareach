#!/usr/bin/env bash
#
# Runs a phone's notifications on the iOS Simulator or the Android emulator, with the real
# application, the real gateway and a real host, and nothing real of the provider.
#
# The gateway is the web repository's Worker under `wrangler dev`, started on this machine by the
# local deployment driver with a recording stand-in for Firebase in place of Google's servers
# (`local-restore.mjs start --fcm-stand-in`). The host is `kr-controller`'s ignored `push_device`
# suite: the real daemon on the loopback interface, a worker with a session, and that stand-in. The
# daemon takes a credential from the gateway and delivers through it, and refuses any origin that
# is not loopback. This script builds the debug application and that suite, starts one device and
# the gateway, and has the host issue a direct invitation. The application pairs with the host and
# turns notifications on through the commands the page uses (companion-tauri's
# `probe::notifications`), and the gateway sends the phone's challenge to the stand-in. Neither
# platform has a provider here, so this script puts each message the stand-in recorded on the phone
# the way the provider would hand it over: on Android as a broadcast to the application's own
# Firebase receiver, from inside the application's own user; on the simulator as `xcrun simctl
# push`. The host then asks a question, which is delivered through the gateway the same way.
#
# What the run shows, and what it does not:
#   shows       the phone answers the gateway's challenge from its receiver and no other message,
#               becomes a destination at the host under the authorisation the gateway issued, files
#               the host's preview key in the limited store, and shows the host's generic alert
#               for a question; the host's text reaches neither the provider's message nor the
#               screen. A message it was not waiting for is not answered.
#   does not    a real Firebase or APNs delivery, a real registration token, background limits of a
#               phone, the notification service extension on a device, or a force-quit
#               application. A staging run with the staging sender credentials, or the person's
#               own phone, adds those.
#
# A simulator or an emulator only inside the Mac's device lease, and the builds inside a build slot:
#
#   KR_WEB_TREE=<a built checkout of the web repository> \
#   bash lead-scripts/with-slot.sh <label> bash lead-scripts/with-device.sh <label> \
#     scripts/e2e-push-device.sh android
#
# Usage:
#   scripts/e2e-push-device.sh ios
#   scripts/e2e-push-device.sh android
#
# KR_PUSH_ANDROID_APK and KR_PUSH_IOS_APP name a build to install instead of making one.
# KR_PUSH_SHOTS is where the screenshots go (default /tmp/kr-push-phone).
#
# Exit codes: 0 every check passed, 2 bad usage or a failed check, 3 the device is not available.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
companion="$here/apps/companion"
platform="${1:-}"
case "$platform" in
    ios | android) ;;
    *) printf 'usage: %s ios|android\n' "$0" >&2; exit 2 ;;
esac
web="${KR_WEB_TREE:-}"
[ -f "$web/infra/scripts/testing/local-restore.mjs" ] \
    || { printf 'KR_WEB_TREE names a built checkout of the web repository\n' >&2; exit 2; }

# shellcheck source=scripts/lib/android-avd.sh
. "$here/scripts/lib/android-avd.sh"

artefacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}/push-device-$platform"
shots="${KR_PUSH_SHOTS:-/tmp/kr-push-phone}"
cache="${HOME}/Library/Caches/kalareach-tests/push-device"
mkdir -p "${artefacts:?}" "${shots:?}" "${cache:?}"
app_id=to.kala.reach
log="$artefacts/run.log"
: >"${log:?}"
# The messages' outcomes are this run's alone: the judge keeps the last line of each message, and a
# message this run never sent must not be judged on an earlier run's.
: >"${artefacts:?}/challenge-outcomes.txt"
: >"${artefacts:?}/delivery-outcomes.txt"
# What the harness and the gateway hold lives on the internal disk, for this run.
harness="$(mktemp -d "${TMPDIR:-/tmp}/kr-push-device.XXXXXX")"
gateway_state="$harness/gateway"
run="r$(uuidgen | tr -d - | tr 'A-F' 'a-f' | cut -c1-10)"
token="kr-device-run-$(uuidgen | tr 'A-F' 'a-f')"
harness_pid=""
pump_pid=""
steps_pid=""
log_pid=""
gateway_started=""
emulator_pid=""
emulator_serial=""
emulator_adb=""
simulator_made=""
xcconfig="$companion/src-tauri/gen/apple/Local.xcconfig"
xcconfig_saved=""
xcconfig_made=""
plist="$companion/src-tauri/gen/apple/companion-tauri_iOS/Info.plist"
plist_saved=""

say() { printf '== [push-device] %s\n' "$*" | tee -a "$log"; }

# A free loopback port.
free_port() {
    python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

gateway_port="$(free_port)"
fcm_port="$(free_port)"
gateway_origin="http://127.0.0.1:$gateway_port"

# Ends what this script started and removes what it made: the host is asked to finish and ended by
# its pid only when it does not, the gateway by its own `stop`, the emulator through its serial and
# by its pid when it does not stop, the simulator this script made is shut down and deleted, and
# the two files of the iOS build are put back as they were.
finish() {
    touch "$harness/finish" 2>/dev/null
    for pid in "$pump_pid" "$steps_pid" "$harness_pid"; do
        [ -n "$pid" ] || continue
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 20 ]; do
            sleep 1
            waited=$((waited + 1))
        done
        kill -0 "$pid" 2>/dev/null && kill "$pid" 2>/dev/null
    done
    [ -z "$log_pid" ] || kill "$log_pid" 2>/dev/null
    if [ -n "$gateway_started" ]; then
        cp "$gateway_state/push.log" "$artefacts/gateway.log" 2>/dev/null
        node "$web/infra/scripts/testing/local-restore.mjs" stop --state "$gateway_state" >/dev/null 2>&1
    fi
    if [ -n "$emulator_pid" ] && kill -0 "$emulator_pid" 2>/dev/null; then
        "$emulator_adb" -s "$emulator_serial" reverse --remove-all >/dev/null 2>&1
        "$emulator_adb" -s "$emulator_serial" uninstall "$app_id" >/dev/null 2>&1
        "$emulator_adb" -s "$emulator_serial" emu kill >/dev/null 2>&1
        local stopped=0
        while kill -0 "$emulator_pid" 2>/dev/null && [ "$stopped" -lt 30 ]; do
            sleep 1
            stopped=$((stopped + 1))
        done
        kill -0 "$emulator_pid" 2>/dev/null && kill "$emulator_pid" 2>/dev/null
    fi
    if [ -n "$simulator_made" ]; then
        xcrun simctl shutdown "$simulator_made" >/dev/null 2>&1
        xcrun simctl delete "$simulator_made" >/dev/null 2>&1
    fi
    if [ -n "$xcconfig_saved" ]; then
        cp "$xcconfig_saved" "$xcconfig" 2>/dev/null
    elif [ -n "$xcconfig_made" ]; then
        /bin/rm -f "${xcconfig:?}"
    fi
    [ -z "$plist_saved" ] || cp "$plist_saved" "$plist" 2>/dev/null
    # The messages the provider stand-in recorded, as the phone was handed them, are kept with the
    # run: they are the real examples the receivers' decode cases are recorded from.
    mkdir -p "${artefacts:?}/recorded"
    cp "$harness"/inject-*.json "$artefacts/recorded/" 2>/dev/null
    /bin/rm -rf "${harness:?}"
}
trap finish EXIT

# ---- The gateway and the host ----------------------------------------------------------------

start_gateway() {
    say "starting the gateway at $gateway_origin, with the provider stand-in on port $fcm_port"
    node "$web/infra/scripts/testing/local-restore.mjs" start --state "$gateway_state" --name push \
        --port "$gateway_port" --fcm-stand-in "http://127.0.0.1:$fcm_port" >"$artefacts/gateway-start.json" 2>&1 \
        || { say "the gateway did not start: $(head -c 300 "$artefacts/gateway-start.json")"; return 2; }
    gateway_started=1
}

# Builds the host once, copies its executable to the internal disk, and says where it is.
build_harness() {
    say "building the host and the provider stand-in"
    cargo test --manifest-path "$here/Cargo.toml" -p kr-controller --test push_device --no-run \
        --message-format=json >"$artefacts/harness-build.json" 2>"$artefacts/harness-build.log" \
        || { say "the harness did not build; see $artefacts/harness-build.log"; return 2; }
    local built
    built="$(python3 - "$artefacts/harness-build.json" <<'PY'
import json
import sys

found = ""
for line in open(sys.argv[1], encoding="utf-8"):
    try:
        message = json.loads(line)
    except ValueError:
        continue
    if (
        message.get("reason") == "compiler-artifact"
        and message.get("executable")
        and message["target"]["name"] == "push_device"
    ):
        found = message["executable"]
print(found)
PY
)"
    [ -n "$built" ] && [ -x "$built" ] || { say "the harness left no executable"; return 2; }
    harness_exe="$cache/push_device"
    cp "$built" "$harness_exe" || return 2
}

# Starts the host for a phone that reaches this machine as `peer`, and waits until it is up.
start_harness() { # <peer>
    KR_HARNESS_DIR="$harness" KR_HARNESS_PEER="$1" KR_HARNESS_SECONDS=1500 \
        KR_PUSH_GATEWAY="$gateway_origin" KR_PUSH_FCM_PORT="$fcm_port" KR_PUSH_TOKEN="$token" \
        "$harness_exe" --ignored --exact a_phone_registers_with_a_gateway_and_is_delivered_to_through_it --nocapture \
        >"$artefacts/harness.log" 2>&1 &
    harness_pid=$!
    local waited=0
    while [ ! -s "$harness/ready.json" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the host ended before it was ready; see $artefacts/harness.log"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 180 ] || { say "the host was not ready in time"; return 2; }
    done
    say "the host is up, reached as $1"
}

# The request the application reads when it starts.
write_request() { # <file> <run> <json fields after the run, with a leading comma, or nothing>
    python3 - "$1" "$2" "$gateway_origin" "$token" "${3:-}" <<'PY'
import json
import sys

path, run, origin, token, extra = sys.argv[1:6]
request = {"run": run, "origin": origin, "token": token}
if extra:
    request.update(json.loads(extra))
with open(path, "w", encoding="utf-8") as out:
    json.dump(request, out)
PY
}

# Waits for the host to say it is done, by its report.
wait_for_report() {
    local waited=0
    while [ ! -s "$harness/report.json" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the host ended before it reported; see $artefacts/harness.log"; return 2; }
        sleep 2
        waited=$((waited + 2))
        [ "$waited" -lt 900 ] || { say "the host did not report in time"; return 2; }
    done
}

# ---- What the run must have shown ------------------------------------------------------------

# Decides the run from the lines the phone reported and the host's report, and says each check.
# Needs the files `$artefacts/phone-register.txt`, `phone-pending.json`, `phone-push.json` and
# `phone-limited.txt` which the platform's run leaves.
judge() {
    python3 - "$harness/report.json" "$artefacts" "$platform" <<'PY'
import json
import os
import re
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
art = sys.argv[2]
platform = sys.argv[3]
bad = 0


def say(name, ok, detail=""):
    global bad
    print(f"check={name} ok={int(bool(ok))}" + (f" detail={detail}" if detail else ""))
    if not ok:
        bad = 1


def read(name):
    try:
        return open(os.path.join(art, name), encoding="utf-8").read()
    except OSError:
        return ""


phone = read("phone-register.txt")
lines = [line for line in phone.splitlines() if line.startswith("check=")]
say("the phone's own checks ran and reported done", "done=1" in phone and lines, f"{len(lines)} lines")
for line in lines:
    say("phone " + line.split(" ok=")[0][len("check="):], " ok=1 " in line + " ", line.split(" detail=", 1)[-1] if " detail=" in line else "")

pending = read("phone-pending.json")
try:
    state = json.loads(pending)["state"]
except Exception:
    state = "none"
say("the phone's registration record is answered", state == "answered", f"state {state}")
outcomes = {}
for line in read("challenge-outcomes.txt").splitlines():
    number, _, text = line.partition("|")
    if number.isdigit():
        outcomes[int(number)] = text
expected = {1: "registration", 2: "token", 3: "origin", 4: "expired", 5: "malformed"}
for number, reason in expected.items():
    text = outcomes.get(number, "")
    say(f"message {number} was a challenge the phone left unanswered for its reason: {reason} (16.06)",
        "ignored" in text and reason in text, text)
say("the real challenge was answered (16.06)", "answered" in outcomes.get(6, "") and "ignored" not in outcomes.get(6, ""), outcomes.get(6, ""))
say("the same challenge again was not answered a second time (16.06)", "ignored" in outcomes.get(7, "") and "not_pending" in outcomes.get(7, ""), outcomes.get(7, ""))
say("the host had no destination before the answer",
    report.get("destinations_before_the_challenge") == 0, f"destinations {report.get('destinations_before_the_challenge')}")
say("the host holds the phone as a destination (16.08)", report.get("destination_present") is True)
say("the destination is in service", report.get("destination_enabled") is True)
try:
    kept = json.loads(read("phone-push.json"))
    ids = {entry.get("sender_record_id") for entry in kept.get("hosts", {}).values()}
except Exception:
    ids = set()
say("the host's destination is under the authorisation the phone issued",
    report.get("sender_record_id") in ids and report.get("sender_record_id") is not None,
    f"host {report.get('sender_record_id')} phone {sorted(ids)}")
own = ""
for line in phone.splitlines():
    if line.startswith("check=this phone's preview key identifier"):
        own = line.split(" detail=", 1)[-1].strip()
say("the key the host seals to is the key this phone holds (16.11)", own != "" and own == report.get("preview_key_id"),
    f"phone {own} host {report.get('preview_key_id')}")
if platform == "android":
    # The store names a file by the digest of the item's name, and holds one sealed item: the set of
    # preview keys the application handed over, whole. What is in it is sealed under the keystore.
    import hashlib
    expected = hashlib.sha256(b"preview-keys").hexdigest()
    limited = read("phone-limited.txt").split()
    say("the limited store holds the one item that is the set of preview keys, and nothing else (16.11, 10.48)",
        limited == [expected], f"store {limited} expected {expected}")
else:
    print("note=the iOS keychain cannot be listed from outside: the key's filing is shown by the write that preceded 'on' and by the Swift cases (10.48)")
say("the key's revision is 1", report.get("preview_key_revision") == 1, f"revision {report.get('preview_key_revision')}")
say("the delivery reached the provider", report.get("delivery_reached_the_provider") is True)
say("the provider's message is under 3,500 bytes (16.12)",
    isinstance(report.get("provider_message_bytes"), int) and report["provider_message_bytes"] < 3500,
    f"{report.get('provider_message_bytes')} bytes")
say("the provider's message carries none of the question's text (16.13)",
    report.get("provider_message_carries_the_marker") is False)
say("the host recorded the event before the provider received the send (16.12)",
    report.get("event_recorded_before_the_provider_received_it") is True)
shape = report.get("provider_message_shape", {})
if platform == "android":
    say("the gateway sent an Android delivery as a data message of high priority, with the alert in its data",
        shape.get("android_data_only") is True and shape.get("android_priority") == "high", f"{shape}")
else:
    say("the gateway's iOS delivery carries an alert, mutable content, an expiry and a collapse identifier (16.02)",
        shape.get("apns_alert") is True and shape.get("apns_mutable_content") == 1
        and shape.get("apns_expiration") is True and shape.get("apns_collapse_id") is True, f"{shape}")
if platform == "android":
    # The receiver logs why the alert it showed stands, never what the preview held. The question the
    # worker asks carries no sentence of the host's own, so the host seals nothing to show: the real
    # receiver opened the real host's seal, found it authentic and addressed to this phone, and had
    # nothing to put in the alert's place.
    deliveries = [line.partition("|")[2] for line in read("delivery-outcomes.txt").splitlines() if "|" in line]
    say("the receiver opened each sealed preview the host sent and found nothing to show (16.11, 16.13)",
        len(deliveries) > 0 and all(outcome.strip() == "delivery: shown (empty_preview)" for outcome in deliveries),
        f"{deliveries}")
    cold = read("cold-start.txt")
    before_pid = cold.split("pid before the message: '")[1].split("'")[0] if "pid before the message: '" in cold else "?"
    after_pid = cold.split("pid after the message: '")[1].split("'")[0] if "pid after the message: '" in cold else ""
    say("the application had no process when the delivery came, and the system started one for it alone (13.24, 16.15)",
        before_pid == "" and after_pid != "", f"before '{before_pid}' after '{after_pid}'")
say("the message went under the access token the stand-in issued", report.get("provider_message_authorised") is True)
paths = set(report.get("provider_paths", []))
say("the provider was asked only for a token and for sends",
    all(path == "/token" or path.endswith("/messages:send") for path in paths), f"{sorted(paths)}")
say("the delivery was shown on the phone, with the host's generic alert and none of the question's text (16.13)",
    report.get("delivery_shown") is True)

tapped = report.get("tap_step") or ""
if platform == "android":
    left_on_hosts = "PUSH-ON-HOSTS" in tapped
else:
    notes = read("test-notes.txt")
    left_on_hosts = "left the page on Hosts: true" in notes and "left the page on Hosts: false" not in notes
say("the application was on its Hosts screen when the notification was tapped, and the tap opened it on its Attention screen (09.21)",
    left_on_hosts and "PUSH-TAPPED" in tapped and "Attention" in tapped, tapped[:200].replace("\n", " "))
say("the person answered Yes from there, and the worker's ledger holds that answer as this paired device's (09.21)",
    report.get("question_answered_from_the_notification") is True and report.get("answer_is_the_paired_devices") is True
    and report.get("answer_is_yes") is True)
late_seen = report.get("late_observe_step") or ""
late_chosen = report.get("late_step") or ""
say("a second question answered at the host while the person had chosen Yes and not sent it: the phone says it was answered by someone else and what the person had chosen, and offers nothing to send (09.21)",
    report.get("second_resolved_at_the_host") is True and "PUSH-ENDED" in late_seen
    and "answered by someone else" in late_seen and re.search(r"You had chosen( \| | )Yes", late_seen) and "Send answer" not in late_seen
    and "still offered" not in late_seen
    and ("PUSH-CHOSEN" in late_chosen or "chosen" in late_chosen),
    late_seen[:300].replace("\n", " "))
say("and the host's answer is the one the worker keeps (09.21)", report.get("host_answer_kept") is True)

if report.get("later_phases_ran") is not True:
    say("the phases after the registration ran", False, "the host had no destination to go on with")
else:
    reissue = read("phone-reissue.txt")
    say("the phone's installation had the gateway issue its authorisation again (16.09)",
        "the gateway issued the authorisation again ok=1" in reissue, reissue.strip().splitlines()[-2] if reissue.strip() else "no result")
    say("the application was ended when the host renewed (16.09)", report.get("reissue_step") == "ended", f"{report.get('reissue_step')}")
    say("the host renewed through the gateway and the delivery arrived (16.09)", report.get("renewal_delivered") is True)
    before, after = report.get("revision_before_the_reissue"), report.get("revision_after_the_renewal")
    say("the credential the host holds is the revision after the reissue's own: the host renewed over it (16.09)",
        isinstance(before, int) and isinstance(after, int) and after == before + 2, f"before {before} after {after}")
    say("the renewal left the destination as it was and in service (16.09)", report.get("renewal_left_the_destination_as_it_was") is True)
    say("the renewal kept the authorisation the destination delivers under (16.09)", report.get("renewal_kept_the_authorisation") is True)
    say("the provider answered a send as it answers an unknown token (16.16)", report.get("provider_answered_unregistered") is True)
    say("the host took the destination out of service (16.16)", report.get("destination_out_of_service") is True)
    say("nothing was sent while it was out of service (16.16)", report.get("nothing_sent_while_out_of_service") is True)
    say("a replacement token was sent a challenge and the phone answered it (16.16)",
        report.get("replacement_challenged") is True and report.get("replacement_challenge_put_on_the_phone") is True)
    say("the phone's second registration ended in the host holding it again (16.16)",
        report.get("destination_back_in_service") is True)
    say("delivery resumed on the new token (16.16)", report.get("delivery_resumed_on_the_new_token") is True)
    asked = report.get("burst_asked")
    allowance = report.get("burst_policy_burst")
    say("the host's journal retained every one of the burst's events (16.17)",
        report.get("burst_settled") is True and report.get("burst_events_retained") == asked, f"events {report.get('burst_events_retained')} of {asked}")
    say("each event is one delivery record, and the host accepted as many as its allowance gives and collapsed the rest (16.17)",
        report.get("burst_deliveries_written") == asked and isinstance(allowance, int) and isinstance(asked, int)
        and report.get("burst_accepted") == min(asked, allowance)
        and report.get("burst_collapsed") == asked - min(asked, allowance) and report.get("burst_other") == 0,
        f"states {report.get('burst_states')} allowance {allowance}")
    say("what reached the provider is exactly what the host's journal says the gateway accepted (16.17)",
        report.get("burst_provider_caught_up") is True and report.get("burst_at_the_provider") == report.get("burst_accepted"),
        f"provider {report.get('burst_at_the_provider')} accepted {report.get('burst_accepted')}")
    say("unpairing succeeded (16.10)", report.get("unpaired") is True)
    say("the destination ended (16.10)", report.get("destination_ended") is True)
    say("the daemon forgot the credential and its secret store gave the bearer up (16.10)",
        report.get("credential_forgotten") is True and report.get("secret_store_gave_the_bearer_up") is True
        and report.get("bearer_was_in_the_secret_store") is True, "the control: the store held it before")
    say("the gateway took the revocation (16.10)", report.get("revocation_no_longer_owed") is True)
    say("nothing was sent after unpairing (16.10)", report.get("nothing_sent_after_unpairing") is True)
sys.exit(bad)
PY
}

# ---- The Android emulator --------------------------------------------------------------------

# Puts each message the host writes on the phone, in order, and says when the phone has had it.
# On Android a message is a broadcast to the application's own Firebase receiver, sent from the
# application's own user: the receiver is not exported to anyone else, and the application has no
# Firebase project here, so the provider's delivery is the one thing this stands in for. The
# application logs what became of each message (by kind, never by content), which is what this
# waits for.
pump_android() { # <adb> <serial>
    local adb="$1" serial="$2" n=1 file outcome
    while [ ! -e "$harness/finish" ]; do
        file="$harness/inject-$n.json"
        if [ ! -s "$file" ]; then
            sleep 1
            continue
        fi
        local before after waited=0
        before="$("$adb" -s "$serial" logcat -d -s KalaReachPush:I 2>/dev/null | grep -c 'KalaReachPush')"
        python3 "$here/scripts/lib/push-inject.py" android "$file" >"$harness/inject-$n.sh" \
            || { say "message $n could not be turned into a broadcast"; return 1; }
        if python3 "$here/scripts/lib/push-inject.py" kind "$file" | grep -q '^delivery$' && [ ! -e "$harness/cold-done" ]; then
            # The first delivery meets an application with no process: the system starts one for the
            # message alone, with no activity and no WebView. The registration run has ended by now.
            : >"$harness/cold-done"
            local ended=0
            until "$adb" -s "$serial" shell run-as "$app_id" cat kr-probe/push-result-register.txt 2>/dev/null | grep -q 'done=1'; do
                ended=$((ended + 1))
                [ "$ended" -lt 30 ] || break
                sleep 1
            done
            "$adb" -s "$serial" shell input keyevent KEYCODE_HOME >/dev/null 2>&1
            "$adb" -s "$serial" shell am force-stop "$app_id" >/dev/null 2>&1
            echo "pid before the message: '$("$adb" -s "$serial" shell pidof "$app_id" | tr -d '\r')'" >"$artefacts/cold-start.txt"
        fi
        "$adb" -s "$serial" shell "run-as $app_id sh" <"$harness/inject-$n.sh" >"$harness/inject-$n.out" 2>&1
        while :; do
            after="$("$adb" -s "$serial" logcat -d -s KalaReachPush:I 2>/dev/null | grep -c 'KalaReachPush')"
            [ "$after" -gt "$before" ] && break
            waited=$((waited + 1))
            [ "$waited" -lt 40 ] || break
            sleep 1
        done
        python3 "$here/scripts/lib/push-inject.py" note "$file" >>"$artefacts/injected.txt"
        [ ! -e "$artefacts/cold-start.txt" ] || grep -q 'after' "$artefacts/cold-start.txt" || echo "pid after the message: '$("$adb" -s "$serial" shell pidof "$app_id" | tr -d '\r')'" >>"$artefacts/cold-start.txt"
        outcome="$("$adb" -s "$serial" logcat -d -s KalaReachPush:I 2>/dev/null | tail -n 1 | sed 's/^.*KalaReachPush: //')"
        say "message $n: $(python3 "$here/scripts/lib/push-inject.py" note "$file") -> $outcome"
        if python3 "$here/scripts/lib/push-inject.py" kind "$file" | grep -q '^delivery$'; then
            printf '%s|%s\n' "$n" "$outcome" >>"$artefacts/delivery-outcomes.txt"
            check_android_notification "$adb" "$serial" "$n"
        else
            printf '%s|%s\n' "$n" "$outcome" >>"$artefacts/challenge-outcomes.txt"
        fi
        : >"$harness/injected-$n"
        n=$((n + 1))
    done
}

# Reads the notification the phone is showing for a delivery, and says so when it is the generic
# alert and holds none of the question's text.
check_android_notification() { # <adb> <serial> <n>
    local adb="$1" serial="$2" n="$3" dump
    dump="$("$adb" -s "$serial" shell dumpsys notification --noredact 2>/dev/null)"
    printf '%s\n' "$dump" >"$artefacts/notifications-$n.txt"
    # Read from the file: a search that stops at its first match would end a pipe early, which a
    # script that sets pipefail takes for a failure.
    local alert
    alert="$(python3 "$here/scripts/lib/push-inject.py" alert "$harness/inject-$n.json")"
    if grep -q "pkg=$app_id" "$artefacts/notifications-$n.txt" && grep -q -F "$alert" "$artefacts/notifications-$n.txt" \
        && ! grep -q 'kr-marker-4f1c9a' "$artefacts/notifications-$n.txt"; then
        : >"$harness/shown-$n"
    fi
}

# Writes the request for one launch into the application's data directory and starts the
# application, then waits for the result the application writes for it, which it keeps in
# `phone-<name>.txt`.
android_launch() { # <adb> <serial> <name> <json fields>
    local adb="$1" serial="$2" name="$3" extra="$4"
    local request="$harness/request-$name.json" remote="/data/local/tmp/kr-push-$name.json"
    write_request "$request" "$name" "$extra"
    "$adb" -s "$serial" shell run-as "$app_id" mkdir -p kr-probe
    "$adb" -s "$serial" push "$request" "$remote" >/dev/null
    "$adb" -s "$serial" shell run-as "$app_id" cp "$remote" kr-probe/push-request.json
    "$adb" -s "$serial" shell rm -f "$remote"
    say "starting the application, run $name"
    # A request is read when the process starts, so a process that is running is ended first.
    "$adb" -s "$serial" shell am force-stop "$app_id"
    "$adb" -s "$serial" shell am start -n "$app_id/.MainActivity" >/dev/null
    local text="" until=$((SECONDS + 600))
    while :; do
        text="$("$adb" -s "$serial" shell run-as "$app_id" cat "kr-probe/push-result-$name.txt" 2>/dev/null | tr -d '\r')"
        case "$text" in *done=1*) break ;; esac
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/phone-$name.txt"
}

# Taps the notification the host's generic alert is on, opens the question on the Attention screen
# and chooses an answer; for `send` it then sends it. What the phone showed is written to the step's
# done file.
action_android() { # <adb> <serial> <step> <words of the question> <choice> <send|stop>
    local adb="$1" serial="$2" step="$3" words="$4" choice="$5" ending="$6" alert out="$harness/done-$3.tmp" blind=blind
    alert="$(python3 "$here/scripts/lib/push-inject.py" alert "$(ls -t "$harness"/inject-*.json | head -1)")"
    # The sheet a notification's tap opens is not always in the tree the web view hands over, so the
    # person who answers from it presses where the form draws its choices. Every question's form is
    # laid out from the foot of the sheet, so a question with more or fewer lines above its choices
    # leaves them where they were.
    : >"$out"
    if python3 "$here/scripts/lib/push-android.py" tap "$adb" "$serial" "$shots" "$alert" >>"$out" 2>&1 \
        && python3 "$here/scripts/lib/push-android.py" choose "$adb" "$serial" "$shots" "$words" "$choice" $blind >>"$out" 2>&1 \
        && [ "$ending" = send ]; then
        python3 "$here/scripts/lib/push-android.py" send "$adb" "$serial" "$shots" $blind >>"$out" 2>&1
    fi
    mv "$out" "$harness/done-$step"
}

# Does what the host asks of the phone besides what messages do: the gateway issues the phone's
# authorisation again and the application ends, and the application registers again with a new
# token. Each is done once, when its file appears.
steps_android() { # <adb> <serial>
    local adb="$1" serial="$2" ended
    while [ ! -e "$harness/finish" ]; do
        if [ -e "$harness/step-reissue.json" ] && [ ! -e "$harness/started-reissue" ]; then
            : >"$harness/started-reissue"
            android_launch "$adb" "$serial" reissue '{"reissue": true}'
            "$adb" -s "$serial" shell am force-stop "$app_id"
            ended="$("$adb" -s "$serial" shell pidof "$app_id" 2>/dev/null | tr -d '\r')"
            [ -z "$ended" ] && echo "ended" >"$harness/done-reissue" || echo "running $ended" >"$harness/done-reissue"
        fi
        if [ -e "$harness/step-tap.json" ] && [ ! -e "$harness/started-tap" ]; then
            : >"$harness/started-tap"
            action_android "$adb" "$serial" tap "A question is waiting for an answer" "Yes" send
        fi
        if [ -e "$harness/step-late.json" ] && [ ! -e "$harness/started-late" ]; then
            : >"$harness/started-late"
            action_android "$adb" "$serial" late "A question is waiting for an answer" "Yes" stop
        fi
        if [ -e "$harness/step-late-observe.json" ] && [ ! -e "$harness/started-late-observe" ]; then
            : >"$harness/started-late-observe"
            python3 "$here/scripts/lib/push-android.py" observe "$adb" "$serial" "$shots" >"$harness/done-late-observe.tmp" 2>&1
            mv "$harness/done-late-observe.tmp" "$harness/done-late-observe"
        fi
        if [ -e "$harness/step-newtoken.json" ] && [ ! -e "$harness/started-newtoken" ]; then
            : >"$harness/started-newtoken"
            android_launch "$adb" "$serial" newtoken "{\"token\": \"$token-replaced\", \"enable\": true}"
            grep -c 'ok=1' "$artefacts/phone-newtoken.txt" >"$harness/done-newtoken" 2>/dev/null
        fi
        sleep 1
    done
}

run_android() {
    local sdk="${ANDROID_HOME:-$HOME/Library/Android/sdk}" avd apk="${KR_PUSH_ANDROID_APK:-}"
    local adb="${KR_ADB:-$sdk/platform-tools/adb}" serial_port=5596
    local serial="emulator-$serial_port"
    [ -x "$adb" ] || { say "no adb at $adb"; return 3; }
    if ! avd="$(kr_android_avd "$sdk/emulator/emulator")"; then
        say "$avd"
        return 3
    fi

    if [ -z "$apk" ]; then
        say "building the application for the emulator"
        ( cd "$companion" && pnpm android --debug --target aarch64 ) >"$artefacts/build.log" 2>&1 \
            || { say "the build failed; see $artefacts/build.log"; return 2; }
        apk="$companion/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk"
    fi
    [ -f "$apk" ] || { say "there is no package at $apk"; return 2; }
    build_harness || return 2

    if "$adb" devices 2>/dev/null | awk '{print $1}' | grep -qx "$serial"; then
        say "a device is already on $serial, which is left alone"
        return 3
    fi
    say "starting the emulator $avd"
    "$sdk/emulator/emulator" -avd "$avd" -port "$serial_port" -no-snapshot-save -no-boot-anim \
        -no-window -no-audio -no-metrics -gpu swiftshader_indirect >"$artefacts/emulator.log" 2>&1 &
    emulator_pid=$!
    emulator_serial=$serial
    emulator_adb=$adb
    local booted=0
    for _ in $(seq 1 180); do
        kill -0 "$emulator_pid" 2>/dev/null || break
        if [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then booted=1; break; fi
        sleep 2
    done
    { [ "$booted" = 1 ] && kill -0 "$emulator_pid" 2>/dev/null; } || { say "the emulator did not come up"; return 3; }

    "$adb" -s "$serial" uninstall "$app_id" >/dev/null 2>&1
    "$adb" -s "$serial" install -r "$apk" >/dev/null || { say "the package did not install"; return 2; }
    # The person's answer to the system's question is given up front: this run is about what
    # follows it, and the permission dialog is the system's own.
    "$adb" -s "$serial" shell pm grant "$app_id" android.permission.POST_NOTIFICATIONS 2>/dev/null

    start_gateway || return 2
    # The gateway is the phone's loopback address on the emulator too, so that the origin the phone
    # signs for is the origin the gateway signs for.
    "$adb" -s "$serial" reverse "tcp:$gateway_port" "tcp:$gateway_port" >/dev/null \
        || { say "the emulator's loopback interface could not be tied to the gateway"; return 2; }
    start_harness 10.0.2.2 || return 2
    pump_android "$adb" "$serial" &
    pump_pid=$!

    : >"$harness/go"
    local waited=0
    while [ ! -s "$harness/invitation.txt" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the host ended before it issued an invitation"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 90 ] || { say "the host issued no invitation"; return 2; }
    done
    steps_android "$adb" "$serial" &
    steps_pid=$!
    "$adb" -s "$serial" logcat -c
    android_launch "$adb" "$serial" register "$(python3 -c 'import json,sys; print(json.dumps({"invitation": open(sys.argv[1]).read().strip(), "enable": True}))' "$harness/invitation.txt")"
    wait_for_report || return 2
    "$adb" -s "$serial" shell run-as "$app_id" cat no_backup/push-pending.json >"$artefacts/phone-pending.json" 2>/dev/null
    "$adb" -s "$serial" shell run-as "$app_id" cat push/push.json >"$artefacts/phone-push.json" 2>/dev/null
    "$adb" -s "$serial" shell run-as "$app_id" ls no_backup/limited-keys 2>/dev/null | tr -d '\r' >"$artefacts/phone-limited.txt"
    "$adb" -s "$serial" logcat -d -b all 2>/dev/null | grep -v -E 'CompositionEngine|AccessibilityNodeInfoDumper' | tail -3000 >"$artefacts/logcat.log"
    "$adb" -s "$serial" logcat -d -b crash >"$artefacts/crash.log" 2>&1
    touch "$harness/finish"
    cat "$harness/report.json" >"$artefacts/report.json"
    local status=0 line
    while IFS= read -r line; do
        say "$line"
        case "$line" in *" ok=0"*) status=2 ;; esac
    done < <(judge)
    [ "$status" = 0 ] || return 2
}


# ---- The iOS Simulator -----------------------------------------------------------------------

# Puts each message the host writes on the phone, in order, with `xcrun simctl push`, and says when
# the phone has had it. A challenge is a background push: the application's own delegate method
# receives it and logs what became of it, which is what this waits for. A delivery is an alert: the
# system shows its banner, which the test that drives the phone reads and, where it is asked to,
# taps. The application is sent to the background before the first delivery, so that the banner is
# the system's and the process is suspended.
# Says where the application is to be, and waits until the test that drives it has put it there.
want_ios() { # foreground|background
    # The place is written before `is` is taken away, since the test serves a place when it finds `is`
    # gone, and must then read this one and not the last.
    printf '%s\n' "$1" >"$harness/want"
    /bin/rm -f "$harness/is"
    local waited=0
    until [ "$(cat "$harness/is" 2>/dev/null)" = "$1" ]; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 90 ] || { say "the application did not go to the $1"; return 1; }
    done
}

pump_ios() { # <udid>
    local udid="$1" n=1 file kind before after waited place=foreground deliveries=0 outcome
    while [ ! -e "$harness/finish" ]; do
        file="$harness/inject-$n.json"
        if [ ! -s "$file" ]; then
            sleep 1
            continue
        fi
        kind="$(python3 "$here/scripts/lib/push-inject.py" kind "$file")"
        python3 "$here/scripts/lib/push-inject.py" ios "$file" >"$harness/payload-$n.json" \
            || { say "message $n could not be turned into a payload"; return 1; }
        waited=0
        if [ "$kind" = challenge ]; then
            # The application is in front while a challenge is answered: the simulator hands a
            # background push to no delegate, so a push that wakes a suspended application is one
            # only a real device shows.
            [ "$place" = foreground ] || { want_ios foreground; place=foreground; }
            before="$(grep -c 'a registration challenge' "$harness/ios.log" 2>/dev/null)"
            if [ "$n" = 1 ]; then
                # What the simulator does with a push that only wakes the application is found out
                # once, here: the message as the gateway sent it goes through `simctl push`, and the
                # delegate is not called. The system's own log of it is kept for whoever reads this.
                xcrun simctl push "$udid" "$app_id" "$harness/payload-$n.json" >"$harness/push-$n.out" 2>&1
                waited=0
                while [ "$waited" -lt 12 ]; do
                    after="$(grep -c 'handed the delegate a push' "$harness/ios.log" 2>/dev/null)"
                    [ "$after" -gt 0 ] && break
                    waited=$((waited + 1))
                    sleep 1
                done
                echo "simctl push of the challenge: the delegate was called $(grep -c 'handed the delegate a push' "$harness/ios.log" 2>/dev/null) time(s)" >>"$artefacts/ios-push-variants.txt"
                xcrun simctl spawn "$udid" log show --last 5m --style compact \
                    --predicate 'process == "usernoted" OR process == "SpringBoard" OR process == "apsd" OR process == "KalaReach"' 2>/dev/null \
                    | grep -i -E 'to\.kala\.reach|kalareach' | grep -v -i 'sandbox extension' | tail -120 >"$artefacts/ios-push-system-log.txt"
            fi
            # The message reaches the application's delegate method the way the system would call it:
            # the simulator will not make the call, so a debug build is handed the data and makes it.
            python3 "$here/scripts/lib/push-inject.py" data "$file" >"$harness/push-message.json"
            support="$(xcrun simctl get_app_container "$udid" "$app_id" data)/Library/Application Support/$app_id/kr-probe"
            cp "$harness/push-message.json" "$support/push-message.json"
            xcrun simctl spawn "$udid" notifyutil -p to.kala.reach.probe.push-message >/dev/null 2>&1
            waited=0
            while :; do
                after="$(grep -c 'a registration challenge' "$harness/ios.log" 2>/dev/null)"
                [ "$after" -gt "$before" ] && break
                waited=$((waited + 1))
                [ "$waited" -lt 40 ] || break
                sleep 1
            done
            outcome="$(grep 'a registration challenge' "$harness/ios.log" 2>/dev/null | tail -n 1 | sed 's/^.*KalaReach: //')"
            say "message $n: $(python3 "$here/scripts/lib/push-inject.py" note "$file") -> $outcome"
            printf '%s|%s\n' "$n" "$outcome" >>"$artefacts/challenge-outcomes.txt"
        else
            # A delivery is shown by the system while the application is in the background: the
            # person's acts bring it to the front, so it is asked to go every time.
            want_ios background
            deliveries=$((deliveries + 1))
            python3 "$here/scripts/lib/push-inject.py" banner "$file" >"$harness/banner-expect-$n.txt"
            xcrun simctl push "$udid" "$app_id" "$harness/payload-$n.json" >"$harness/push-$n.out" 2>&1
            : >"$harness/banner-wanted-$n"
            # The person taps the banner of the first two questions, which the host's acts on the
            # phone start from; the banners after those are only read.
            if [ "$deliveries" -le 2 ]; then
                echo "$n" >>"$harness/tap-order"
                : >"$harness/tap-$n"
            else
                : >"$harness/no-tap-$n"
            fi
            until [ -s "$harness/banner-$n.txt" ]; do
                sleep 1
                waited=$((waited + 1))
                [ "$waited" -lt 90 ] || break
            done
            cp "$harness/banner-$n.txt" "$artefacts/banner-$n.txt" 2>/dev/null
            if [ -e "$harness/tap-$n" ]; then
                # The tap brought the application to the front, where the person's acts are.
                until [ -s "$harness/tapped-$n" ]; do
                    sleep 1
                    waited=$((waited + 1))
                    [ "$waited" -lt 150 ] || break
                done
                cp "$harness/tapped-$n" "$artefacts/tapped-$n.txt" 2>/dev/null
                want_ios foreground && place=foreground
            fi
            say "message $n: $(python3 "$here/scripts/lib/push-inject.py" note "$file") -> banner: $(head -c 200 "$harness/banner-$n.txt" 2>/dev/null)"
            if [ -s "$harness/banner-$n.txt" ] && ! grep -q 'kr-marker-4f1c9a' "$harness/banner-$n.txt" \
                && grep -q -F -f "$harness/banner-expect-$n.txt" "$harness/banner-$n.txt"; then
                : >"$harness/shown-$n"
            fi
        fi
        python3 "$here/scripts/lib/push-inject.py" note "$file" >>"$artefacts/injected.txt"
        : >"$harness/injected-$n"
        n=$((n + 1))
    done
}

# Asks the test that drives the phone to do one thing a person does, and waits for what the screen
# showed after it. The acts are numbered, in the order they are asked.
act_ios() { # <verb>
    local k waited=0
    k=$(( $(cat "$harness/act-count" 2>/dev/null || echo 0) + 1 ))
    echo "$k" >"$harness/act-count"
    printf '%s\n' "$1" >"$harness/act-$k"
    until [ -s "$harness/acted-$k" ]; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 120 ] || { echo "no answer to act $k"; return 1; }
    done
    cat "$harness/acted-$k"
}

# What the screen showed after the person tapped the banner of the <k>th question: the test that
# drives the phone writes it when it has tapped the banner.
tapped_ios() { # <k>
    local k="$1" n waited=0
    while :; do
        n="$(sed -n "${k}p" "$harness/tap-order" 2>/dev/null)"
        [ -n "$n" ] && [ -s "$harness/tapped-$n" ] && break
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 150 ] || { echo "no banner $k was tapped"; return 1; }
    done
    cat "$harness/tapped-$n"
}

# Does what the host asks of the phone besides what messages do, on the simulator: the person taps
# the notification, chooses an answer and sends it; the gateway issues the authorisation again and
# the application ends; and the application registers again with a new token.
steps_ios() { # <udid>
    local udid="$1" out
    while [ ! -e "$harness/finish" ]; do
        if [ -e "$harness/step-tap.json" ] && [ ! -e "$harness/started-tap" ]; then
            : >"$harness/started-tap"
            out="$(tapped_ios 1; act_ios choose; act_ios send)"
            printf 'PUSH-TAPPED %s\n' "$out" >"$harness/done-tap.tmp" && mv "$harness/done-tap.tmp" "$harness/done-tap"
        fi
        if [ -e "$harness/step-late.json" ] && [ ! -e "$harness/started-late" ]; then
            : >"$harness/started-late"
            out="$(tapped_ios 2; act_ios choose)"
            printf '%s\n' "$out" >"$harness/done-late.tmp" && mv "$harness/done-late.tmp" "$harness/done-late"
        fi
        if [ -e "$harness/step-late-observe.json" ] && [ ! -e "$harness/started-late-observe" ]; then
            : >"$harness/started-late-observe"
            out="$(act_ios observe)"
            printf 'PUSH-ENDED %s\n' "$out" >"$harness/done-late-observe.tmp" && mv "$harness/done-late-observe.tmp" "$harness/done-late-observe"
        fi
        if [ -e "$harness/step-reissue.json" ] && [ ! -e "$harness/started-reissue" ]; then
            : >"$harness/started-reissue"
            ios_launch "$udid" reissue '{"reissue": true}'
            xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
            echo "ended" >"$harness/done-reissue"
        fi
        if [ -e "$harness/step-newtoken.json" ] && [ ! -e "$harness/started-newtoken" ]; then
            : >"$harness/started-newtoken"
            ios_launch "$udid" newtoken "{\"token\": \"$token-replaced\", \"enable\": true}"
            grep -c 'ok=1' "$artefacts/phone-newtoken.txt" >"$harness/done-newtoken" 2>/dev/null
        fi
        sleep 1
    done
}

# Writes the request for one launch into the application's data directory and starts the
# application, then waits for the result the application writes for it, which it keeps in
# `phone-<name>.txt`.
ios_launch() { # <udid> <name> <json fields>
    local udid="$1" name="$2" extra="$3" support text="" until=$((SECONDS + 600))
    support="$(xcrun simctl get_app_container "$udid" "$app_id" data)/Library/Application Support/$app_id/kr-probe"
    write_request "$support/push-request.json" "$name" "$extra"
    say "starting the application, run $name"
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    xcrun simctl launch "$udid" "$app_id" >/dev/null
    while :; do
        text="$(cat "$support/push-result-$name.txt" 2>/dev/null)"
        case "$text" in *done=1*) break ;; esac
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/phone-$name.txt"
}

run_ios() {
    local device="${KR_IOS_DEVICE:-iPhone 17 Pro}" udid app="${KR_PUSH_IOS_APP:-}"
    local template
    template="$(xcrun simctl list devices available -j | python3 "$here/scripts/simulator-identity.py" template "$device")"
    [ -n "$template" ] || { say "no iOS simulator named $device"; return 3; }

    if [ -z "$app" ]; then
        say "building the application for the simulator"
        # No push configuration: the build names no Firebase project, so no Google host is reached.
        # The file is a developer's own when it exists, and is put back as it was; the build also
        # rewrites the end of one tracked file.
        if [ -f "$xcconfig" ]; then
            xcconfig_saved="$(mktemp "${TMPDIR:-/tmp}/kr-xcconfig.XXXXXX")"
            cp "$xcconfig" "$xcconfig_saved"
        else
            xcconfig_made=1
        fi
        plist_saved="$(mktemp "${TMPDIR:-/tmp}/kr-info-plist.XXXXXX")"
        cp "$plist" "$plist_saved"
        printf 'KR_GOOGLE_SERVICE_INFO =\n' >"$xcconfig"
        /bin/rm -rf "${companion:?}/src-tauri/gen/apple/build"
        ( cd "$companion" && pnpm tauri ios build --debug --ci --target aarch64-sim ) >"$artefacts/build.log" 2>&1 \
            || { say "the build failed; see $artefacts/build.log"; return 2; }
        cp "$plist_saved" "$plist"
        app="$companion/src-tauri/gen/apple/build/arm64-sim/KalaReach.app"
    fi
    [ -d "$app" ] || { say "there is no application at $app"; return 2; }

    say "building the tests that drive it"
    local derived="$cache/ios-tests"
    ( cd "$companion/src-tauri/gen/apple" && xcodebuild build-for-testing -project companion-tauri.xcodeproj \
        -scheme KalaReachUITests -sdk iphonesimulator -destination 'generic/platform=iOS Simulator' \
        -derivedDataPath "$derived" ) >"$artefacts/build-tests.log" 2>&1 \
        || { tail -20 "$artefacts/build-tests.log"; say "the tests did not build"; return 2; }
    local plan
    plan="$(ls "$derived"/Build/Products/*.xctestrun 2>/dev/null | head -1)"
    [ -f "$plan" ] || { say "the test build left no plan"; return 2; }
    build_harness || return 2

    say "making and starting a simulator like $device"
    # shellcheck disable=SC2086
    udid="$(xcrun simctl create "kr-push-device-$$" $template)" \
        || { say "the simulator could not be made"; return 3; }
    simulator_made="$udid"
    xcrun simctl boot "$udid" >/dev/null 2>&1
    xcrun simctl bootstatus "$udid" -b >/dev/null 2>&1
    xcrun simctl install "$udid" "$app" || { say "the application did not install"; return 2; }

    start_gateway || return 2
    # A simulator shares this machine's network: the gateway and the host are where they say.
    start_harness 127.0.0.1 || return 2
    xcrun simctl spawn "$udid" log stream --style compact \
        --predicate 'process == "KalaReach" AND eventMessage CONTAINS "KalaReach"' >"$harness/ios.log" 2>&1 &
    log_pid=$!
    pump_ios "$udid" &
    pump_pid=$!
    steps_ios "$udid" &
    steps_pid=$!

    : >"$harness/go"
    local waited=0
    while [ ! -s "$harness/invitation.txt" ]; do
        kill -0 "$harness_pid" 2>/dev/null || { say "the host ended before it issued an invitation"; return 2; }
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 90 ] || { say "the host issued no invitation"; return 2; }
    done

    # The application's data directory exists after its first start, which is made and ended here
    # so that the request can be put where the application reads it.
    xcrun simctl launch "$udid" "$app_id" >/dev/null || { say "the application did not start"; return 2; }
    local data support
    data="$(xcrun simctl get_app_container "$udid" "$app_id" data)"
    support="$data/Library/Application Support/$app_id"
    waited=0
    while [ ! -d "$support" ]; do
        sleep 1
        waited=$((waited + 1))
        [ "$waited" -lt 60 ] || { say "the application made no data directory"; return 2; }
    done
    xcrun simctl terminate "$udid" "$app_id" >/dev/null 2>&1
    mkdir -p "$support/kr-probe"
    write_request "$support/kr-probe/push-request.json" "$run" \
        "$(python3 -c 'import json,sys; print(json.dumps({"invitation": open(sys.argv[1]).read().strip(), "enable": True}))' "$harness/invitation.txt")"
    say "driving the application, run $run"
    local out="$artefacts/xcodebuild.log" test_status=0
    ( TEST_RUNNER_KR_PUSH_DIR="$harness" xcodebuild test-without-building -xctestrun "$plan" \
        -destination "platform=iOS Simulator,id=$udid" -only-testing:KalaReachUITests/PushDeviceTests \
        >"$out" 2>&1; echo $? >"$harness/test-status" ) &
    : >"$harness/go-app"

    local text="" until=$((SECONDS + 600))
    while :; do
        text="$(cat "$support/kr-probe/push-result-$run.txt" 2>/dev/null)"
        case "$text" in *done=1*) break ;; esac
        sleep 2
        [ "$SECONDS" -lt "$until" ] || break
    done
    printf '%s\n' "$text" >"$artefacts/phone-register.txt"
    wait_for_report || return 2
    cp "$support/../push-pending.json" "$artefacts/phone-pending.json" 2>/dev/null
    cp "$support/push/push.json" "$artefacts/phone-push.json" 2>/dev/null
    : >"$artefacts/phone-limited.txt"
    cp "$harness/test-notes.txt" "$artefacts/test-notes.txt" 2>/dev/null
    touch "$harness/finish"
    cp "$harness/report.json" "$artefacts/report.json"
    # The test ends when the script says finish; its own verdict is part of the run.
    waited=0
    while [ ! -e "$harness/test-status" ] && [ "$waited" -lt 60 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    grep -E "Test Case .* (passed|failed)|error:|XCTAssert|KR-" "$out" | sed 's/^/    /' | tee -a "$log"
    [ "$(cat "$harness/test-status" 2>/dev/null)" = 0 ] || { say "check=the driving test passed ok=0"; test_status=2; }
    cp "$harness/ios.log" "$artefacts/application.log" 2>/dev/null
    search_ios_log "$udid" || test_status=2
    local status=$test_status line
    while IFS= read -r line; do
        say "$line"
        case "$line" in *" ok=0"*) status=2 ;; esac
    done < <(judge)
    [ "$status" = 0 ] || return 2
}

# What the simulator's log says of the run. No part of it reaches a Google host: the application's
# log, read whole, names none. And the notification service extension ran for a delivery.
search_ios_log() { # <udid>
    local bad=0
    xcrun simctl spawn "$1" log show --last 40m --style compact --predicate 'process == "KalaReach"' \
        >"$artefacts/application-log-whole.txt" 2>/dev/null
    if [ ! -s "$artefacts/application-log-whole.txt" ]; then
        say "check=no Google host is named in the application's log ok=0 detail=the log could not be read"
        bad=2
    elif grep -q -i -E 'googleapis|firebaseinstallations|firebase\.google' "$artefacts/application-log-whole.txt"; then
        say "check=no Google host is named in the application's log ok=0"
        bad=2
    else
        say "check=no Google host is named in the application's log ok=1"
    fi
    # The notification service extension is its own process: a debug build says that it ran, and
    # why it showed what it showed, and nothing of the notification. The simulator's own way of
    # delivering a push has not run it on the system versions this was tried on (the extension is
    # installed and registered, and the system never starts it), so its running is a check when it
    # did and a note when it did not, and a device is what shows it. What the system says of the
    # extension is kept for whoever reads the run.
    xcrun simctl spawn "$1" log show --last 40m --style compact \
        --predicate 'process == "KalaReachNotificationService"' \
        >"$artefacts/extension-log.txt" 2>/dev/null
    if grep -v 'log run noninteractively' "$artefacts/extension-log.txt" | grep -q 'KalaReachExtension: ran'; then
        say "check=the notification service extension ran for a delivery (16.02) ok=1 detail=$(grep -o 'KalaReachExtension: ran, .*' "$artefacts/extension-log.txt" | sort -u | head -3 | tr '\n' ';')"
    else
        say "note=the simulator did not start the notification service extension for a delivery: only a device shows that it runs (16.02)"
    fi
    return $bad
}

case "$platform" in
    ios) run_ios ;;
    android) run_android ;;
esac
