#!/usr/bin/env python3
"""Turns a message the provider stand-in recorded into what a platform's receiver is handed.

The host's `push_device` suite writes `inject-<n>.json`: {"n", "kind", "note", "message"}, where
`message` is the whole body the gateway sent the provider. A provider hands a phone that message's
data; this puts it on the phone the way the provider would:

  android <file>   the shell commands that broadcast the data to the application's own Firebase
                   receiver (run them as the application's own user)
  ios <file>       the payload `xcrun simctl push` takes: the message's APNs payload, with its data at
                   the top level beside `aps`, as the provider delivers a data message to iOS
  alert <file>     the generic alert in the message's data, which the Android notification shows
  data <file>      the message's data as a flat object of strings, which a debug build is handed in
                   place of a push the simulator will not deliver to the application's delegate
  banner <file>    the words the system's banner for a delivery carries (the alert's body)
  kind <file>      `challenge` or `delivery`
  note <file>      what the message is, in words

Nothing here keeps or prints a secret: a message holds none.
"""
import json
import shlex
import sys


def load(path):
    with open(path, encoding="utf-8") as source:
        return json.load(source)


def main():
    mode, path = sys.argv[1], sys.argv[2]
    inject = load(path)
    message = inject["message"]["message"]
    if mode == "kind":
        print(inject["kind"])
    elif mode == "alert":
        print(message.get("data", {}).get("alert", ""))
    elif mode == "data":
        print(json.dumps({key: str(value) for key, value in message.get("data", {}).items()}))
    elif mode == "banner":
        alert = message.get("apns", {}).get("payload", {}).get("aps", {}).get("alert", "")
        print(alert if isinstance(alert, str) else alert.get("body", ""))
    elif mode == "note":
        print(inject["note"])
    elif mode == "android":
        parts = [
            "am broadcast --user 0 -a com.google.android.c2dm.intent.RECEIVE "
            "-n to.kala.reach/com.google.firebase.iid.FirebaseInstanceIdReceiver"
        ]
        for key, value in message.get("data", {}).items():
            parts.append("--es %s %s" % (shlex.quote(key), shlex.quote(str(value))))
        print(" ".join(parts))
    elif mode.startswith("ios"):
        payload = dict(message.get("apns", {}).get("payload", {}))
        for key, value in message.get("data", {}).items():
            payload[key] = str(value)
        # `ios` is the payload as the gateway sent it. The others are what a device run tries when
        # the simulator does not hand that one to the application: the same data in a push the
        # simulator treats as one to deliver.
        variant = mode[len("ios-"):] if mode.startswith("ios-") else "plain"
        aps = dict(payload.get("aps", {}))
        if variant == "alert":
            aps["alert"] = {"body": "KalaReach"}
        elif variant == "mutable":
            aps["mutable-content"] = 1
        elif variant == "target":
            payload["Simulator Target Bundle"] = "to.kala.reach"
        payload["aps"] = aps
        print(json.dumps(payload))
    else:
        sys.exit("push-inject.py: unknown mode " + mode)


main()
