#!/usr/bin/env python3
"""Finds an iOS simulator, and says which one a run actually used.

`xcrun simctl list -j` answers with the devices grouped by runtime, which is where the runtime
version lives. A run has to record the device model and the runtime version beside every result,
so this reads both out of that listing rather than a caller guessing from a name.

Reads the listing on standard input.

    simulator-identity.py udid "iPhone 17 Pro"     # a booted one first, else any available one
    simulator-identity.py state <udid>             # Booted, Shutdown, ...
    simulator-identity.py describe <udid>          # "iPhone 17 Pro (iOS 26.5) <udid>"
"""

import json
import sys


def runtime_name(identifier: str) -> str:
    """The runtime's version, from the identifier the listing groups by."""
    tail = identifier.rsplit(".", 1)[-1]
    parts = tail.split("-")
    if len(parts) >= 2:
        return f"{parts[0]} {'.'.join(parts[1:])}"
    return tail


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    action, argument = sys.argv[1], sys.argv[2]
    devices = json.load(sys.stdin).get("devices", {})

    if action == "udid":
        booted = [
            device["udid"]
            for runtime, listed in devices.items()
            for device in listed
            if device.get("name") == argument and device.get("state") == "Booted"
        ]
        if booted:
            print(booted[0])
            return 0
        any_named = [
            device["udid"]
            for runtime, listed in devices.items()
            for device in listed
            if device.get("name") == argument
        ]
        print(any_named[0] if any_named else "")
        return 0

    if action == "state":
        for listed in devices.values():
            for device in listed:
                if device.get("udid") == argument:
                    print(device.get("state", "Unknown"))
                    return 0
        print("Unknown")
        return 0

    if action == "describe":
        for runtime, listed in devices.items():
            for device in listed:
                if device.get("udid") == argument:
                    print(f"{device['name']} ({runtime_name(runtime)}) {argument}")
                    return 0
        print(f"unknown simulator {argument}")
        return 0

    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
