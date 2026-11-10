#!/usr/bin/env python3
"""Decides a voice call device run from the report the machine side wrote.

    voice-call-host-judge.py <report.json> <mode> <platform> [<leg>] [--send-unmeasured]

`mode` is `native-failure` (the answer leads nowhere and native code ends the call), `outage` (the
answer is the phone's own peer, the call carries audio and then the voice service goes away) or
`delegating` (the call hands spoken requests to the host; `leg` says which of the legs the run
played, and what the voice service carried to the model and what the host's sessions were sent is
read against what that leg expects). `platform` is `ios` or `android`. `--send-unmeasured` says the
phone's own result could not measure the audio it sent, as a simulator with no microphone cannot, so
a peer that heard nothing is no evidence against the call.

It prints one line per check, `== [voice-call-device] host check=<name> ok=<0, 1 or 2> detail=<text>`,
and exits 0 when every check passed, 4 when every check that measured passed and some could not
measure, and 2 when one failed.
"""
import json
import sys

# The audio packets a direction must have carried: the same floor the phone's checks hold.
AUDIO_FLOOR = 50


def counter(series, key):
    """The largest value of a counter over the samples, or None where no sample held it."""
    values = [
        sample["figures"][key]
        for sample in series
        if isinstance(sample.get("figures"), dict) and isinstance(sample["figures"].get(key), int)
    ]
    return max(values) if values else None


def lock_screen(series):
    """The lock-screen readings over the samples, in order."""
    return [
        sample["figures"]["lockScreen"]
        for sample in series
        if isinstance(sample.get("figures"), dict) and isinstance(sample["figures"].get("lockScreen"), dict)
    ]


SHOWN_TITLE = "Kala Reach voice call"


def as_designed(each):
    """One reading of the system's lock-screen state while the call is held: stop is offered, play and
    toggle are not, the fixed title is shown, and the rate follows the microphone (pause offered, rate
    1; muted, rate 0)."""
    return (
        each.get("title") == SHOWN_TITLE
        and each.get("stopOffered") is True
        and not each.get("playOffered")
        and not each.get("toggleOffered")
        and each.get("rate") == (1 if each.get("pauseOffered") else 0)
    )


def checks_for(report, mode, platform, send_unmeasured):
    expected = "Bearer " + report["token"]
    checks = [
        ("the service created one call", int(report["creations"] == 1), report["creations"]),
        # The service opens a control for the phone's token only, so a control that attached used it.
        (
            "the control attached with the phone's token",
            int(bool(report["control_tokens"]) and all(each == expected for each in report["control_tokens"])),
            len(report["control_tokens"]),
        ),
    ]
    if mode == "native-failure":
        checks += [
            ("the host told the service the call is over", int(report["host_closes"] >= 1), report["host_closes"]),
            (
                "the control asked the service to close the call",
                int("close" in report["control_commands"]),
                ",".join(report["control_commands"]),
            ),
        ]
        return checks

    peer = report.get("peer") or {}
    series = peer.get("figures") or []
    received = counter(series, "packetsReceived")
    sent = counter(series, "packetsSent")
    checks += [
        ("the voice service went away", int(bool(report.get("went_down"))), report.get("went_down")),
        (
            "the peer answered the call's offer",
            int(peer.get("answered", 0) >= 1 and not peer.get("errors")),
            "answered %s of %s%s" % (peer.get("answered"), peer.get("relayed"), "; " + "; ".join(peer["errors"]) if peer.get("errors") else ""),
        ),
    ]
    if received is not None and received >= AUDIO_FLOOR:
        heard = 1
    elif send_unmeasured:
        heard = 2
    else:
        heard = 0
    checks.append((
        "the peer received audio from the call",
        heard,
        "packets received %s, floor %d%s" % (received, AUDIO_FLOOR, "; the phone could not measure what it sent" if heard == 2 else ""),
    ))
    checks.append((
        "the peer sent audio to the call",
        int(sent is not None and sent >= AUDIO_FLOOR),
        "packets sent %s, floor %d" % (sent, AUDIO_FLOOR),
    ))
    errors = sorted({error for sample in series if isinstance(sample.get("figures"), dict) for error in sample["figures"].get("errors", [])})
    checks.append(("the peer's audio device reported no error", int(not errors), "; ".join(errors)))
    if platform == "ios":
        readings = lock_screen(series)
        shown = [each for each in readings if each.get("title")]
        offered = [each for each in shown if each.get("pauseOffered")]
        wrong = [each for each in shown if not as_designed(each)]
        # The audio unit starts only when the call is permitted, so a peer that heard the call is proof
        # that it was: controls never read then are a failure, not a call that was not permitted.
        if offered and not wrong:
            verdict, said = 1, "%d of %d readings" % (len(offered), len(readings))
        elif wrong:
            verdict, said = 0, "a reading of the held call was not as designed: " + json.dumps(wrong[0], sort_keys=True)
        elif heard == 1:
            verdict, said = 0, "no reading offered pause, though the peer heard the call, which was therefore permitted"
        else:
            verdict, said = 2, "no reading showed the controls; the peer heard nothing, so the call may not have been permitted"
        checks.append(("the lock screen offered pause while the call was held", verdict, said))
        if readings:
            last = readings[-1]
            clear = not (last.get("pauseOffered") or last.get("stopOffered") or last.get("playOffered") or last.get("toggleOffered") or last.get("title"))
            checks.append(("the lock screen holds nothing after the end", int(clear), json.dumps(last, sort_keys=True)))
        else:
            checks.append(("the lock screen holds nothing after the end", 2, "no reading"))
    return checks


# What the model is told, by the kind of words, read from the front of each sentence.
def told_kind(text):
    if text.startswith("The person's computer read it."):
        return "performed"
    if text.startswith("This call can no longer act on what the person says"):
        return "tainted"
    if text.startswith("Nothing was done on the person's computer: what was said could not be used as a request"):
        return "refused"
    if text.startswith("Nothing was done on the person's computer: this version does not act on spoken requests"):
        return "not_done"
    return "other"


# For each leg: whether the attach words say the phone can ask the host, what each delegation the
# call answered was told (by identifier, in the order told), whether the call is tainted for good
# (the model is told so once, as instructions), and how many requests the host was sent.
LEGS = {
    "production": dict(attach="cannot", told={"d-9": ["not_done"]}, tainted=False, at_host=0),
    "positive": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"]}, tainted=False, at_host=1),
    "first_utterance": dict(attach="can", told={"d-1": ["refused"], "d-2": ["performed"]}, tainted=False, at_host=1),
    "mute": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"], "d-2": ["tainted"], "d-3": ["tainted"]}, tainted=True, at_host=1),
    "gap": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"], "d-2": ["tainted"]}, tainted=True, at_host=1),
    "dtx": dict(attach="can", told={"d-1": ["tainted"]}, tainted=True, at_host=0),
    "malformed": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"], "d-2": ["tainted"]}, tainted=True, at_host=1),
    "late_fragment": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"], "d-2": ["tainted"]}, tainted=True, at_host=1),
    "broker_disagrees": dict(attach="can", told={"d-0": ["refused"], "d-1": ["performed"], "d-2": ["refused"], "d-3": ["performed"]}, tainted=False, at_host=2),
}


def delegating_checks(report, leg, platform):
    expected = "Bearer " + report["token"]
    want = LEGS[leg]
    sent = report.get("control_sent") or []
    instructions = [each["content"] for each in sent if each.get("command") == "instructions" and each.get("delegation") is None and each.get("content")]
    checks = [
        ("the service created one call", int(report["creations"] == 1), report["creations"]),
        (
            "the control attached with the phone's token",
            int(bool(report["control_tokens"]) and all(each == expected for each in report["control_tokens"])),
            len(report["control_tokens"]),
        ),
    ]
    peer = report.get("peer") or {}
    checks.append((
        "the peer answered the call's offer",
        int(peer.get("answered", 0) >= 1 and not peer.get("errors")),
        "answered %s of %s%s" % (peer.get("answered"), peer.get("relayed"), "; " + "; ".join(peer["errors"]) if peer.get("errors") else ""),
    ))
    can = [words for words in instructions if "can ask the person's computer" in words]
    cannot = [words for words in instructions if "cannot act on the person's computer" in words]
    if want["attach"] == "can":
        attach_ok = bool(can) and not cannot
    else:
        attach_ok = bool(cannot) and not can
    checks.append((
        "the model was told on attaching what the phone can do" if want["attach"] == "can" else "the model was told on attaching that the phone cannot act",
        int(attach_ok),
        "can-ask words %d, cannot-act words %d" % (len(can), len(cannot)),
    ))
    tainted_told = [words for words in instructions if told_kind(words) == "tainted"]
    checks.append((
        "the model was told once that the call can no longer act" if want["tainted"] else "the model was never told the call can no longer act",
        int(len(tainted_told) == 1 if want["tainted"] else not tainted_told),
        "%d times" % len(tainted_told),
    ))
    for delegation, kinds in want["told"].items():
        got = [told_kind(each["content"]) for each in sent if each.get("delegation") == delegation and each.get("content")]
        checks.append((
            "the model was told what became of %s" % delegation,
            int(got == kinds),
            "told %s, expected %s" % (",".join(got) or "nothing", ",".join(kinds)),
        ))
    stray = sorted({each["delegation"] for each in sent if each.get("delegation") and each["delegation"] not in want["told"]})
    checks.append(("the model was told of no delegation the leg did not make", int(not stray), ",".join(stray)))
    return checks


def main():
    arguments = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    flags = [argument for argument in sys.argv[1:] if argument.startswith("--")]
    if len(arguments) not in (3, 4) or any(flag != "--send-unmeasured" for flag in flags):
        print(__doc__, file=sys.stderr)
        return 2
    path, mode, platform = arguments[:3]
    leg = arguments[3] if len(arguments) == 4 else None
    if mode not in ("native-failure", "outage", "delegating") or platform not in ("ios", "android"):
        print(__doc__, file=sys.stderr)
        return 2
    if (mode == "delegating") != (leg is not None) or (leg is not None and leg not in LEGS):
        print(__doc__, file=sys.stderr)
        return 2
    report = json.load(open(path, encoding="utf-8"))
    status = 0
    if mode == "delegating":
        found = delegating_checks(report, leg, platform)
    else:
        found = checks_for(report, mode, platform, "--send-unmeasured" in flags)
    for name, verdict, detail in found:
        print("== [voice-call-device] host check=%s ok=%d detail=%s" % (name, verdict, detail))
        if verdict == 0:
            status = 2
        elif verdict == 2 and status == 0:
            status = 4
    return status


if __name__ == "__main__":
    sys.exit(main())
