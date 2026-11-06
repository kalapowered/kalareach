#!/usr/bin/env python3
"""Decides a voice call device run from the report the machine side wrote.

    voice-call-host-judge.py <report.json> <mode> <platform> [--send-unmeasured]

`mode` is `native-failure` (the answer leads nowhere and native code ends the call) or `outage` (the
answer is the phone's own peer, the call carries audio and then the voice service goes away).
`platform` is `ios` or `android`. `--send-unmeasured` says the phone's own result could not measure
the audio it sent, as a simulator with no microphone cannot, so a peer that heard nothing is no
evidence against the call.

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
        offered = [each for each in readings if each.get("pauseOffered") and each.get("title")]
        checks.append((
            "the lock screen offered pause while the call was held",
            1 if offered else 2,
            "%d of %d readings" % (len(offered), len(readings)) if offered else "no reading showed the controls; the call was not permitted, so the audio unit did not start",
        ))
        if readings:
            last = readings[-1]
            clear = not (last.get("pauseOffered") or last.get("stopOffered") or last.get("playOffered") or last.get("toggleOffered") or last.get("title"))
            checks.append(("the lock screen holds nothing after the end", int(clear), json.dumps(last, sort_keys=True)))
        else:
            checks.append(("the lock screen holds nothing after the end", 2, "no reading"))
    return checks


def main():
    arguments = [argument for argument in sys.argv[1:] if not argument.startswith("--")]
    flags = [argument for argument in sys.argv[1:] if argument.startswith("--")]
    if len(arguments) != 3 or any(flag != "--send-unmeasured" for flag in flags):
        print(__doc__, file=sys.stderr)
        return 2
    path, mode, platform = arguments
    if mode not in ("native-failure", "outage") or platform not in ("ios", "android"):
        print(__doc__, file=sys.stderr)
        return 2
    report = json.load(open(path, encoding="utf-8"))
    status = 0
    for name, verdict, detail in checks_for(report, mode, platform, "--send-unmeasured" in flags):
        print("== [voice-call-device] host check=%s ok=%d detail=%s" % (name, verdict, detail))
        if verdict == 0:
            status = 2
        elif verdict == 2 and status == 0:
            status = 4
    return status


if __name__ == "__main__":
    sys.exit(main())
