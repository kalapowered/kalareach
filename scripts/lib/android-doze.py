#!/usr/bin/env python3
"""Puts the Android emulator in deep Doze and takes it out again, and says what the phone reports.

An emulator has no motion, no battery and no idle timer of its own to run down, so the device-idle
controller is told what a phone that has lain still, unplugged and dark would have told it, and is
then asked to go straight to idle. Every command takes the adb program and the emulator's serial:

  enter <adb> <serial>   unplug the virtual battery, turn the screen off, and force deep idle. Prints
                         `DOZE-ENTERED` with the readback, and ends with status 1, printing
                         `DOZE-FAILED`, when the phone does not report deep idle, the screen off, no
                         power source and the application outside the allowlist.
  read  <adb> <serial>   prints `DOZE-READ` with the readback and changes nothing.
  wake  <adb> <serial>   turns the screen on and prints `DOZE-AWAKE` with the readback. Forced idle
                         outlasts the screen: it ends with status 1 when the phone left deep idle.
  leave <adb> <serial>   ends the forced idle, restores the virtual battery and wakes the screen.
                         Prints `DOZE-LEFT` with the readback, and ends with status 1 when the phone
                         still reports deep idle.

The readback is one line of `key=value` pairs: `deep` and `light` (`dumpsys deviceidle get`),
`idle_mode` (`mDeviceIdleMode` in `dumpsys power`, what the application's `isDeviceIdleMode()` gives
it), `wakefulness`, `forced`, `powered` (any power source on), `allowlisted` (the application is on
the device-idle allowlist) and `clock_ms` (the emulator's own clock, in milliseconds).

It uses the Python standard library alone and nothing but the emulator it is given.
"""

import re
import subprocess
import sys
import time

APPLICATION = "to.kala.reach"


class Phone:
    def __init__(self, adb: str, serial: str) -> None:
        self.adb = adb
        self.serial = serial

    def shell(self, *command: str) -> str:
        done = subprocess.run(
            [self.adb, "-s", self.serial, "shell", *command],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return (done.stdout + done.stderr).replace("\r", "")

    def readback(self) -> dict[str, str]:
        power = self.shell("dumpsys", "power")
        idle = self.shell("dumpsys", "deviceidle")
        battery = self.shell("dumpsys", "battery")
        allowlist = self.shell("dumpsys", "deviceidle", "whitelist")

        def field(text: str, name: str) -> str:
            found = re.search(rf"^\s*{re.escape(name)}=(\S+)", text, re.MULTILINE)
            return found.group(1) if found else "unknown"

        powered = any(
            re.search(rf"^\s*{source} powered: true", battery, re.MULTILINE)
            for source in ("AC", "USB", "Wireless", "Dock")
        )
        clock = self.shell("date", "+%s%3N").strip()
        return {
            "deep": self.shell("dumpsys", "deviceidle", "get", "deep").strip(),
            "light": self.shell("dumpsys", "deviceidle", "get", "light").strip(),
            "idle_mode": field(power, "mDeviceIdleMode"),
            "wakefulness": field(power, "mWakefulness"),
            "forced": field(idle, "mForceIdle"),
            "powered": "true" if powered else "false",
            "allowlisted": "true" if f",{APPLICATION}," in allowlist else "false",
            "clock_ms": clock,
        }

    def until(self, wanted, seconds: float) -> dict[str, str]:
        """The readback as soon as `wanted` accepts it, or the last one after `seconds`."""
        end = time.monotonic() + seconds
        while True:
            seen = self.readback()
            if wanted(seen) or time.monotonic() >= end:
                return seen
            time.sleep(0.5)


def line(seen: dict[str, str]) -> str:
    return " ".join(f"{key}={value}" for key, value in seen.items())


def in_doze(seen: dict[str, str]) -> bool:
    return seen["deep"] == "IDLE" and seen["idle_mode"] == "true"


def enter(phone: Phone) -> int:
    phone.shell("dumpsys", "battery", "unplug")
    phone.shell("dumpsys", "deviceidle", "enable", "deep")
    phone.shell("input", "keyevent", "KEYCODE_SLEEP")
    phone.until(lambda seen: seen["wakefulness"] == "Asleep", 15)
    phone.shell("dumpsys", "deviceidle", "force-idle", "deep")
    seen = phone.until(in_doze, 15)
    held = (
        in_doze(seen)
        and seen["wakefulness"] == "Asleep"
        and seen["powered"] == "false"
        and seen["allowlisted"] == "false"
    )
    print(("DOZE-ENTERED " if held else "DOZE-FAILED ") + line(seen), flush=True)
    return 0 if held else 1


def wake(phone: Phone) -> int:
    phone.shell("input", "keyevent", "KEYCODE_WAKEUP")
    seen = phone.until(lambda each: each["wakefulness"] == "Awake", 15)
    held = in_doze(seen) and seen["wakefulness"] == "Awake"
    print(("DOZE-AWAKE " if held else "DOZE-FAILED ") + line(seen), flush=True)
    return 0 if held else 1


def leave(phone: Phone) -> int:
    phone.shell("dumpsys", "deviceidle", "unforce")
    phone.shell("dumpsys", "battery", "reset")
    phone.shell("input", "keyevent", "KEYCODE_WAKEUP")
    seen = phone.until(lambda each: each["deep"] == "ACTIVE" and each["idle_mode"] == "false", 15)
    left = seen["deep"] != "IDLE" and seen["idle_mode"] == "false"
    print(("DOZE-LEFT " if left else "DOZE-FAILED ") + line(seen), flush=True)
    return 0 if left else 1


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) == 3 and arguments[0] in {"enter", "read", "wake", "leave"}:
        phone = Phone(arguments[1], arguments[2])
        if arguments[0] == "read":
            print("DOZE-READ " + line(phone.readback()), flush=True)
            return 0
        return {"enter": enter, "wake": wake, "leave": leave}[arguments[0]](phone)
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
