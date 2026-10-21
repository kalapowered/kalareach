#!/usr/bin/env python3
"""Drives the installed companion application on the Android emulator through its own screens, for
`scripts/e2e-pairing-device.sh android`.

Two commands:

  pose <grpc port> position|rotation <x> <y> <z>
      Moves the emulator's virtual camera. The emulator's controller is a gRPC service, and its one
      call this needs is `setPhysicalModel`, whose message is small enough to write by hand, so the
      call is made with `curl` and no library.

  drive <adb> <serial> <harness directory> <screenshot directory>
      Runs the cases against the host the harness directory belongs to. The application is read
      through `uiautomator`, which names the page's own buttons and texts, and driven by taps at
      the centre of what it names. Every prompt of the system is answered by the button a person
      would press. A line `PAIRING <what held>` is printed for each thing the run showed.

It uses the Python standard library alone.
"""

import re
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

APP = "to.kala.reach"


# ---- The emulator's camera ---------------------------------------------------------------------


def pose(port: str, kind: str, values: list[float]) -> None:
    """Sets the virtual camera's position (metres) or rotation (degrees)."""
    packed = struct.pack("<" + "f" * len(values), *values)
    parameter = b"\x0a" + bytes([len(packed)]) + packed  # ParameterValue.data, packed
    message = b""
    if kind == "rotation":
        message += b"\x08\x01"  # PhysicalModelValue.target = ROTATION; POSITION is the default, 0
    message += b"\x1a" + bytes([len(parameter)]) + parameter  # PhysicalModelValue.value
    frame = b"\x00" + struct.pack(">I", len(message)) + message
    answer = subprocess.run(
        [
            "curl", "-sS", "--http2-prior-knowledge", "-D", "-", "-o", "/dev/null",
            "-H", "content-type: application/grpc", "-H", "te: trailers", "--data-binary", "@-",
            f"http://127.0.0.1:{port}/android.emulation.control.EmulatorController/setPhysicalModel",
        ],
        input=frame, capture_output=True, check=False, timeout=30,
    )
    headers = answer.stdout.decode("latin-1")
    if answer.returncode != 0 or "grpc-status: 0" not in headers.lower():
        raise SystemExit(f"the camera could not be moved: {headers.strip()} {answer.stderr.decode().strip()}")


# ---- The application's screen ------------------------------------------------------------------


class Phone:
    def __init__(self, adb: str, serial: str, shots: Path):
        self.adb, self.serial, self.shots = adb, serial, shots

    def run(self, *arguments: str, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.adb, "-s", self.serial, *arguments], capture_output=True, timeout=timeout, check=False
        )

    def screen(self) -> list[dict]:
        """What `uiautomator` names on the screen: each node's label, bounds and class."""
        answer = self.run("exec-out", "uiautomator", "dump", "/dev/tty")
        text = answer.stdout.decode("utf-8", "replace")
        end = text.find("</hierarchy>")
        if end < 0:
            return []
        nodes = []
        for node in ElementTree.fromstring(text[: end + len("</hierarchy>")]).iter("node"):
            label = node.get("text") or node.get("content-desc") or ""
            bounds = [int(each) for each in re.findall(r"\d+", node.get("bounds", ""))]
            if len(bounds) == 4:
                nodes.append(
                    {
                        "label": label,
                        "id": node.get("resource-id", ""),
                        "class": node.get("class", ""),
                        "box": bounds,
                    }
                )
        return nodes

    def find(self, wanted) -> dict | None:
        """The first node on the screen whose label `wanted` accepts."""
        for node in self.screen():
            if node["label"] and wanted(node["label"]):
                return node
        return None

    def wait(self, wanted, what: str, timeout: float = 60) -> dict:
        """Waits until a node on the screen is labelled as `wanted` says, never by a fixed delay."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            node = self.find(wanted)
            if node is not None:
                return node
            time.sleep(0.4)
        raise SystemExit(f"timed out waiting for {what}")

    def tap(self, node: dict) -> None:
        left, top, right, bottom = node["box"]
        self.run("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))

    def press(self, label: str, timeout: float = 30) -> None:
        self.tap(self.wait(lambda each: each == label, f"the {label} button", timeout))

    def shot(self, name: str) -> None:
        picture = self.run("exec-out", "screencap", "-p", timeout=60).stdout
        (self.shots / f"android-{name}.png").write_bytes(picture)

    def answer_the_camera_prompt(self) -> bool:
        """Presses the button a person presses to let the application use the camera, when it asks."""
        node = self.find(lambda each: each in ("While using the app", "Only this time", "Allow"))
        if node is None:
            return False
        self.tap(node)
        return True


def touch(directory: Path, name: str) -> None:
    (directory / name).write_text("1\n")


def read(directory: Path, name: str) -> str:
    try:
        return (directory / name).read_text().strip()
    except FileNotFoundError:
        return ""


def wait_for_file(directory: Path, name: str, timeout: float = 180) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if (directory / name).exists():
            return
        time.sleep(0.25)
    raise SystemExit(f"timed out waiting for the host to write {name}")


def say(text: str) -> None:
    print(f"PAIRING {text}", flush=True)


def scan(phone: Phone, directory: Path, picture: str) -> None:
    """Has the camera see `picture`, and presses Scan code, answering the camera's question once."""
    wait_for_file(directory, f"{picture}.png.added")
    phone.press("Scan code")
    # The first scan asks to use the camera; later ones do not, so the question is looked for briefly.
    asked = time.monotonic() + 8
    while time.monotonic() < asked:
        if phone.answer_the_camera_prompt():
            break
        if phone.find(lambda each: each.startswith("Invitation from a host") or each.startswith("Code for a host")):
            break
        time.sleep(0.4)


def drive(adb: str, serial: str, directory: Path, shots: Path) -> None:
    phone = Phone(adb, serial, shots)
    shots.mkdir(parents=True, exist_ok=True)
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each == "Hosts", "the shell's Hosts tab", 90)
    phone.press("Hosts")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")

    # A QR code whose secret has one bit changed opens nothing.
    touch(directory, "go-control")
    scan(phone, directory, "control")
    phone.wait(lambda each: each.startswith("Invitation from a host"), "the scanned invitation")
    phone.press("Pair")
    phone.wait(lambda each: each.startswith("The invitation did not work"), "the refusal")
    touch(directory, "control-done")
    wait_for_file(directory, "done-control")
    if read(directory, "control-result.txt") != "candidate_locked=0":
        raise SystemExit("the host locked a candidate on a changed secret")
    say("a changed secret locked nothing")
    # Scan again opens the scanner, and Cancel closes it: the person is back at the start.
    phone.press("Scan again")
    phone.wait(lambda each: each == "Point the camera at the code on your host", "the scanner")
    phone.shot("scanner")
    phone.press("Cancel")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen after the scanner closed")
    say("the scanner closes on Cancel")

    # The host's invitation: the phone shows the value the host shows, and is paired once approved.
    touch(directory, "go-direct")
    scan(phone, directory, "direct")
    phone.wait(lambda each: each.startswith("Invitation from a host"), "the scanned invitation")
    phone.shot("scanned-summary")
    phone.press("Pair")
    phone.wait(lambda each: each == "Check this value on the host", "the value", 90)
    wait_for_file(directory, "host-value.txt")
    host = read(directory, "host-value.txt").replace(" ", "")
    spelled = ", ".join(" ".join(group) for group in (host[:4], host[4:]))
    phone.wait(lambda each: each == spelled, f"the host's value {host} on the phone", 15)
    say(f"the phone shows the host's value {host}")
    phone.shot("value")
    touch(directory, "approve")
    phone.wait(lambda each: each.startswith("Paired with"), "the paired screen", 120)
    wait_for_file(directory, "done-direct")
    say("the phone is paired")
    phone.shot("paired")

    # A code that names another service asks before anything is contacted.
    touch(directory, "go-code")
    wait_for_file(directory, "code.png.added")
    phone.press("Hosts")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")
    phone.press("Scan code")
    alert = phone.wait(lambda each: each == "Use another pairing service?", "the alert naming the other service", 60)
    named = phone.find(lambda each: each.startswith("This code belongs to https://"))
    if named is None:
        raise SystemExit("the alert does not name the service")
    phone.shot("origin-alert")
    phone.press("Cancel")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen after Cancel")
    if read(directory, "connections.txt") != "0":
        raise SystemExit("a service was contacted before the person agreed")
    say("cancelled: no connection")
    phone.press("Scan code")
    phone.wait(lambda each: each == "Use another pairing service?", "the alert the second time", 60)
    phone.tap(phone.wait(lambda each: each.startswith("Use "), "the button that accepts the service"))
    phone.wait(lambda each: each.startswith("Code for a host that uses"), "the held code")
    phone.press("Pair")
    end = time.monotonic() + 60
    while read(directory, "connections.txt") != "1":
        if time.monotonic() > end:
            raise SystemExit("the other service was not contacted once the person agreed")
        time.sleep(0.25)
    say("accepted: one connection")
    touch(directory, "code-done")
    wait_for_file(directory, "done-code")


def main() -> None:
    arguments = sys.argv[1:]
    if len(arguments) == 6 and arguments[0] == "pose":
        pose(arguments[1], arguments[2], [float(each) for each in arguments[3:6]])
    elif len(arguments) == 5 and arguments[0] == "drive":
        drive(arguments[1], arguments[2], Path(arguments[3]), Path(arguments[4]))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
