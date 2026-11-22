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

A command that fails, or output that does not hold what a field needs, ends the command with
`DOZE-FAILED unreadable=...` and status 1: a field that could not be read is never read as false.

It uses the Python standard library alone and nothing but the emulator it is given.
"""

import re
import subprocess
import sys
import time

APPLICATION = "to.kala.reach"


class Unreadable(Exception):
    """A command of the phone failed, or its output is not what a field needs."""


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
        if done.returncode != 0:
            raise Unreadable(f"`{' '.join(command)}` exited {done.returncode}")
        return (done.stdout + done.stderr).replace("\r", "")

    def readback(self) -> dict[str, str]:
        power = self.shell("dumpsys", "power")
        idle = self.shell("dumpsys", "deviceidle")
        battery = self.shell("dumpsys", "battery")
        allowlist = self.shell("dumpsys", "deviceidle", "whitelist")

        def field(text: str, name: str, allowed: set[str]) -> str:
            found = re.search(rf"^\s*{re.escape(name)}=(\S+)", text, re.MULTILINE)
            if found is None or found.group(1) not in allowed:
                raise Unreadable(f"no valid `{name}` in the phone's report")
            return found.group(1)

        sources = [
            re.search(rf"^\s*{source} powered: (true|false)", battery, re.MULTILINE)
            for source in ("AC", "USB", "Wireless", "Dock")
        ]
        if any(each is None for each in sources):
            raise Unreadable("the battery's report names no power source")
        listed = re.findall(r"^(?:system|system-excidle|user),[^,\s]+,\d+$", allowlist, re.MULTILINE)
        if not listed:
            raise Unreadable("the allowlist's report lists no application")
        clock = self.shell("date", "+%s%3N").strip()
        if not clock.isdigit():
            raise Unreadable("the phone's clock is not a number")
        states = {}
        for which in ("deep", "light"):
            states[which] = self.shell("dumpsys", "deviceidle", "get", which).strip()
            if not re.fullmatch(r"[A-Z_]+", states[which]):
                raise Unreadable(f"no valid `get {which}` state")
        flag = {"true", "false"}
        return {
            "deep": states["deep"],
            "light": states["light"],
            "idle_mode": field(power, "mDeviceIdleMode", flag),
            "wakefulness": field(power, "mWakefulness", {"Awake", "Asleep", "Dreaming", "Dozing"}),
            "forced": field(idle, "mForceIdle", flag),
            "powered": "true" if any(each.group(1) == "true" for each in sources if each) else "false",
            "allowlisted": "true" if any(f",{APPLICATION}," in each for each in listed) else "false",
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
        try:
            if arguments[0] == "read":
                print("DOZE-READ " + line(phone.readback()), flush=True)
                return 0
            return {"enter": enter, "wake": wake, "leave": leave}[arguments[0]](phone)
        except (Unreadable, subprocess.SubprocessError, OSError) as failure:
            print(f"DOZE-FAILED unreadable={failure}", flush=True)
            return 1
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
