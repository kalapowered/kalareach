#!/usr/bin/env python3
"""Drives the installed companion application on the Android emulator through its own screens, for
`scripts/e2e-pairing-device.sh android`.

Three commands:

  aim <grpc port>
      Moves the emulator's virtual camera to its first view of the wall's picture. The emulator's
      controller is a gRPC service, and its one call this needs is `setPhysicalModel`, whose message
      is small enough to write by hand, so the call is made with `curl` and no library.

  drive <adb> <serial> <harness directory> <screenshot directory> <grpc port>
      Runs the cases against the host the harness directory belongs to. The application is read
      through `uiautomator`, which names the page's own buttons and texts, and driven by taps at
      the centre of what it names. Every prompt of the system is answered by the button a person
      would press. A line `PAIRING <what held>` is printed for each thing the run showed.

  release <adb> <serial> <harness directory> <screenshot directory> <port> <attempts file>
      Drives the minified release build through its pairing screen, for
      `scripts/e2e-android-release.sh`: one attempt at the deployed service, then an attempt at the
      local server whose certificate the system does not trust.

It uses the Python standard library alone.
"""

import json
import os
import re
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

APP = "to.kala.reach"


# ---- The emulator's camera ---------------------------------------------------------------------


# Where the camera stands (metres) and which way it looks (degrees) at each view of the wall's
# picture, square on to it and with the picture whole. A person who cannot get a code to read moves
# the phone, and so does this run: the emulator's camera is a frame of 1280 by 960 pixels, a host's
# direct invitation is a code 109 modules wide, and whether one view reads it depends on the code,
# which is new every run. The views keep the window frame, which stands before the picture's corner
# from other places, off the code.
VIEWS = [
    ([-1.807, 0.32, 3.584], [0.0, 210.0, 0.0]),
    ([-1.807, 0.32, 3.2], [0.0, 210.0, 0.0]),
    ([-1.807, 0.32, 2.8], [0.0, 210.0, 0.0]),
    ([-1.807, 0.8, 2.4], [0.0, 210.0, 0.0]),
    ([-1.807, 0.6, 2.0], [0.0, 210.0, 0.0]),
]

# A view of the room with no picture in it.
AWAY = ([-1.807, 0.32, 3.584], [0.0, 30.0, 0.0])

# How long the scanner is given at a view before the phone is moved to the next one. The scanner
# looks at a frame about eight times a second, so this is many frames.
VIEW_SECONDS = 6


def look(port: str, view) -> None:
    """Puts the virtual camera at `view`."""
    position, rotation = view
    pose(port, "position", position)
    pose(port, "rotation", rotation)


def aim(port: str) -> None:
    """Puts the virtual camera at its first view."""
    look(port, VIEWS[0])


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
                        "enabled": node.get("enabled") == "true",
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
        self.give_up(f"timed out waiting for {what}")

    def give_up(self, message: str) -> None:
        """Ends the run, saying what the screen showed, for whoever reads the failure."""
        labels = " | ".join(each["label"] for each in self.screen() if each["label"])
        self.shot("timeout")
        raise SystemExit(f"{message}; the screen shows: {labels}")

    def tap(self, node: dict) -> None:
        left, top, right, bottom = node["box"]
        self.run("shell", "input", "tap", str((left + right) // 2), str((top + bottom) // 2))

    def press(self, label: str, timeout: float = 30) -> None:
        """Presses the button named `label`, however the system writes its capitals."""
        self.tap(self.wait(lambda each: each.lower() == label.lower(), f"the {label} button", timeout))

    def shot(self, name: str) -> None:
        picture = self.run("exec-out", "screencap", "-p", timeout=60).stdout
        (self.shots / f"android-{name}.png").write_bytes(picture)

    def colours_in_the_middle(self) -> int:
        """How many different colours the middle of the screen shows in a screenshot of it.

        The system blanks a window that is marked secure, so the middle of a screenshot of the
        scanner is one colour, and the middle of any other screen of this application is many. The
        frame is the raw one `screencap` writes (a header, then four bytes to a pixel), so a
        screenshot that could not be taken is a failure of the run and never a blank screen.
        """
        answer = self.run("exec-out", "screencap", timeout=60)
        raw = answer.stdout
        if answer.returncode != 0 or len(raw) < 12:
            self.give_up("the screen could not be captured")
        width, height = struct.unpack("<II", raw[:8])
        size = width * height * 4
        if width == 0 or height == 0 or len(raw) < size:
            self.give_up("the screenshot is not a frame of the size its header names")
        pixels = raw[len(raw) - size :]
        colours = set()
        for row in range(height // 4, height * 3 // 4, 8):
            for column in range(0, width, 4):
                at = (row * width + column) * 4
                colours.add(pixels[at : at + 3])
        return len(colours)


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


def scan(
    phone: Phone,
    directory: Path,
    picture: str,
    port: str,
    wanted,
    what: str,
    stale=lambda each: False,
    opener: str = "Scan code",
) -> None:
    """Has the camera see `picture`, presses `opener`, and waits for what a scan of it opens.

    The first scan asks to use the camera, and the answer a person gives is given. When a view of the
    picture is not read in its time, the phone is moved to the next one. The emulator's wall takes a
    moment to show a new picture, so the scanner may read the one before it: a person who sees the
    wrong code put it away and scans again, and so does this, for what `stale` says is the wrong one.
    """
    wait_for_file(directory, f"{picture}.png.added")
    phone.press(opener)
    for view in VIEWS:
        look(port, view)
        end = time.monotonic() + VIEW_SECONDS
        while time.monotonic() < end:
            nodes = phone.screen()
            asking = [node for node in nodes if node["label"] in ("While using the app", "Only this time", "Allow")]
            if asking:
                phone.tap(asking[0])
                continue
            labels = [node["label"] for node in nodes if node["label"]]
            if any(wanted(each) for each in labels):
                return
            if any(stale(each) for each in labels):
                phone.press("Cancel")
                phone.wait(lambda each: each == "Pair with a host", "the pairing screen after the wrong code was put away")
                phone.press("Scan code")
                end = time.monotonic() + VIEW_SECONDS
                continue
            time.sleep(0.3)
    phone.give_up(f"timed out waiting for {what}: the scanner read the picture at none of {len(VIEWS)} views")


# What the card for the host's own invitation says: it grants the phone an owner's rights, which the
# fixture's invitation, the picture the emulator's wall starts with, does not.
def owner_card(each: str) -> bool:
    return each.startswith("Invitation from a host") and "manage the host as an owner" in each


def another_card(each: str) -> bool:
    return each.startswith("Invitation from a host") and "manage the host as an owner" not in each


def any_card(each: str) -> bool:
    return each.startswith("Invitation from a host")


def overlap(one: list[int], other: list[int]) -> bool:
    """Whether two boxes (left, top, right, bottom) share any area."""
    return one[0] < other[2] and other[0] < one[2] and one[1] < other[3] and other[1] < one[3]


def scanner_fits_the_largest_text(phone: Phone, port: str) -> None:
    """At the largest text size the scanner's hint and controls lie inside the screen, and the hint
    does not run under Cancel.

    The scanner's window is secure, so a screenshot shows none of it, but `uiautomator` still names
    what the window holds and where. The application is started again with the larger text, and with
    the normal size again afterwards, because a change of size while the application is open
    recreates it.
    """
    hint_words = "Point the camera at the code on your host"

    def start() -> None:
        phone.run("shell", "am", "force-stop", APP)
        phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
        phone.wait(lambda each: each == "Hosts", "the shell's Hosts tab", 90)
        phone.press("Hosts")
        phone.wait(lambda each: each == "Pair with a host", "the pairing screen")

    phone.run("shell", "settings", "put", "system", "font_scale", "2.0")
    try:
        start()
        look(port, AWAY)
        phone.press("Scan code")
        end = time.monotonic() + 60
        while time.monotonic() < end:
            nodes = phone.screen()
            asking = [node for node in nodes if node["label"] in ("While using the app", "Only this time", "Allow")]
            if asking:
                phone.tap(asking[0])
                continue
            if any(node["label"] == hint_words for node in nodes):
                break
            time.sleep(0.3)
        else:
            phone.give_up("the scanner did not open at the largest text size")
        width = max(node["box"][2] for node in nodes)
        height = max(node["box"][3] for node in nodes)
        found = {node["label"]: node["box"] for node in nodes if node["label"] in (hint_words, "Cancel")}
        for name, box in found.items():
            if box[0] < 0 or box[1] < 0 or box[2] > width or box[3] > height:
                phone.give_up(f"{name} runs past the screen at the largest text size")
        if overlap(found["Cancel"], found[hint_words]):
            phone.give_up("the hint runs under Cancel at the largest text size")
        phone.press("Cancel")
        phone.wait(lambda each: each == "Pair with a host", "the pairing screen after the scanner closed")
    finally:
        phone.run("shell", "settings", "put", "system", "font_scale", "1.0")
    say("the scanner fits the largest text size")


# The PIN the emulator's screen lock is given while the confirmations are answered. The emulator is
# one of this run's own, and the lock is taken off again as soon as the case ends.
SCREEN_LOCK_PIN = "1234"


def enter_screen_lock(phone: Phone) -> None:
    """Answers the system's prompt for the screen lock as its owner would: types the PIN.

    The prompt is the system's own, drawn over the application, and its title names the application's
    request. The PIN is typed into the keypad it shows, and the key that ends it is pressed; when the
    keypad takes no typed text, the digits it shows are touched one by one.
    """
    phone.wait(lambda each: each == "Confirm on this phone", "the system's prompt for the screen lock", 30)
    phone.run("shell", "input", "text", SCREEN_LOCK_PIN)
    phone.run("shell", "input", "keyevent", "KEYCODE_ENTER")
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if phone.find(lambda each: each == "Confirm on this phone") is None:
            return
        time.sleep(0.3)
    for digit in SCREEN_LOCK_PIN:
        key = phone.find(lambda each, digit=digit: each == digit)
        if key is not None:
            phone.tap(key)
    phone.run("shell", "input", "keyevent", "KEYCODE_ENTER")


def owner_confirmations(phone: Phone, directory: Path) -> None:
    """The paired phone is an owner device: the host's own request and a second device the host would
    add are confirmed with the phone's screen lock, and a prompt that is cancelled confirms nothing.

    The emulator has no screen lock at first, so the phone offers no ceremony. Once it is given a PIN
    the ceremony is its screen lock, and the prompt is the system's. The request is listed on the
    Attention tab; the first prompt is cancelled (the request is still listed and the invitation
    behind it is refused); the same request is then confirmed, and the host spends that confirmation
    on the invitation. A second device the host is asked to add shows a
    value, which the request on the phone shows too.
    """
    confirm = "Confirm with your screen lock"
    try:
        phone.run("shell", "am", "force-stop", APP)
        phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
        phone.wait(lambda each: each.startswith("Attention"), "the shell's Attention tab", 90)
        phone.tap(phone.wait(lambda each: each.startswith("Attention"), "the shell's Attention tab"))
        touch(directory, "go-confirm")
        wait_for_file(directory, "challenge.txt")
        # The emulator has no screen lock yet, so the phone can check nothing: the request is on the
        # Attention tab (the tab's badge counts it), and no button named for a ceremony is offered.
        # The row's words, that this phone cannot check that it is you, are in the screenshot and in
        # the page's own case: the accessibility tree gives the row to `uiautomator` only once it
        # has a button to press. The lock is then set while the request is listed, and the button
        # appears named for it without the request coming or going.
        phone.wait(lambda each: "1 waiting for you" in each, "the host's request counted on the Attention tab", 120)
        time.sleep(3)
        if phone.find(lambda each: each.startswith("Confirm with")) is not None:
            phone.give_up("a phone with no screen lock offers a way to confirm")
        phone.shot("confirm-no-lock")
        say("a phone with no screen lock cannot confirm")
        phone.run("shell", "locksettings", "set-pin", SCREEN_LOCK_PIN)
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the host's request", 120))
        phone.wait(lambda each: each == "Confirm on this phone", "the system's prompt", 30)
        phone.shot("confirm-prompt")
        phone.run("shell", "input", "keyevent", "KEYCODE_BACK")
        phone.wait(lambda each: each == "Not confirmed. Nothing changed.", "the words for a prompt that was cancelled", 30)
        say("the host's request is cancelled at the prompt")
        touch(directory, "confirm-cancelled")
        wait_for_file(directory, "challenge-open.txt")
        if not read(directory, "challenge-open.txt").startswith("unanswered=1"):
            raise SystemExit(f"the cancelled request was answered: {read(directory, 'challenge-open.txt')}")
        touch(directory, "confirm-go")
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the host's request", 30))
        enter_screen_lock(phone)
        phone.wait(lambda each: each.startswith("Confirmed."), "the words for a confirmed request", 60)
        wait_for_file(directory, "confirm-result.txt", 60)
        phone.shot("confirmed")
        say("the host's request is confirmed with the screen lock")

        touch(directory, "go-device")
        wait_for_file(directory, "device-value.txt", 90)
        value = read(directory, "device-value.txt").replace(" ", "")
        spelled = ", ".join(" ".join(group) for group in (value[:4], value[4:]))
        phone.wait(lambda each: spelled in each, f"the value {value} the second device shows", 60)
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the second device", 30))
        enter_screen_lock(phone)
        phone.wait(lambda each: each.startswith("Confirmed."), "the words for a confirmed request", 60)
        wait_for_file(directory, "device-result.txt", 90)
        say("a new device is confirmed against its value")
    finally:
        phone.run("shell", "locksettings", "clear", "--old", SCREEN_LOCK_PIN)


def picker_on_a_paired_phone(phone: Phone) -> None:
    """The attachment picker on a phone paired with a host, with the camera refused for good.

    A host this phone is paired with takes no file from it, so the picker is drawn and offers
    nothing: every source is disabled, and the screen says nothing about the camera, which nothing
    can use. The camera's permission is taken away the way "Don't allow" with "Don't ask again"
    leaves it, and the application is started again (the system ends a process that loses a
    permission), so the session screen reads the permission through the platform plugin and decides
    from it. The decision from the permission to what the picker offers and says is the page's own
    case, over every state of it, with the picker offering files; this shows what the real phone does
    with the same permission and a host that takes none.
    """
    camera = "android.permission.CAMERA"
    phone.run("shell", "pm", "revoke", APP, camera)
    phone.run("shell", "pm", "set-permission-flags", APP, camera, "user-fixed", "user-set")
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each.startswith("Sessions"), "the shell's Sessions tab", 90)
    phone.press("Sessions")
    tabs = ("Attention", "Sessions", "Hosts", "Account")
    row = phone.wait(
        lambda each: not each.startswith(tabs) and each != "Sessions" and "session" in each.lower(),
        "the host's session in the list",
        90,
    )
    phone.tap(row)
    phone.wait(lambda each: each == "Photo library", "the attachment picker", 60)
    for name in ("Take a photo", "Photo library", "Files"):
        source = phone.find(lambda each, name=name: each == name)
        if source is None or source["enabled"]:
            phone.give_up(f"the picker offers {name} on a phone paired with a host")
    if phone.find(lambda each: each.startswith("KalaReach cannot use the camera")) is not None:
        phone.give_up("the picker tells the camera's refusal where it offers no file")
    phone.shot("picker-paired")
    say("the attachment picker offers no file on a paired phone, and says nothing of the camera")


def drive(adb: str, serial: str, directory: Path, shots: Path, port: str) -> None:
    phone = Phone(adb, serial, shots)
    shots.mkdir(parents=True, exist_ok=True)
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each == "Hosts", "the shell's Hosts tab", 90)
    phone.press("Hosts")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")
    scanner_fits_the_largest_text(phone, port)
    # The application was started again with the normal size, so the screen is looked for again.
    phone.run("shell", "am", "force-stop", APP)
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each == "Hosts", "the shell's Hosts tab", 90)
    phone.press("Hosts")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")

    # A QR code whose secret has one bit changed opens nothing.
    touch(directory, "go-control")
    scan(phone, directory, "control", port, owner_card, "the scanned invitation", stale=another_card)
    phone.press("Pair")
    phone.wait(lambda each: each.startswith("The invitation did not work"), "the refusal")
    touch(directory, "control-done")
    wait_for_file(directory, "done-control")
    if read(directory, "control-result.txt") != "candidate_locked=0":
        raise SystemExit("the host locked a candidate on a changed secret")
    say("a changed secret locked nothing")
    # Scan again opens the scanner, and Cancel closes it: the person is back at the start. The phone
    # is turned away from the picture first, since the scanner reads a code the moment it sees one.
    look(port, AWAY)
    shown_before = phone.colours_in_the_middle()
    phone.press("Scan again")
    phone.wait(lambda each: each == "Point the camera at the code on your host", "the scanner")
    # The scanner's window is secure: what the camera sees is kept out of screenshots. The control is
    # the screen before it, which a screenshot does show.
    if shown_before < 8:
        phone.give_up("a screenshot of the pairing screen shows nothing, so a blank one proves nothing")
    if phone.colours_in_the_middle() != 1:
        phone.give_up("a screenshot shows what the scanner's camera sees")
    say("the scanner is kept out of screenshots")
    phone.press("Cancel")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen after the scanner closed")
    say("the scanner closes on Cancel")

    # The host's invitation: the phone shows the value the host shows, and is paired once approved.
    touch(directory, "go-direct")
    opener = "Scan code"
    for _ in range(3):
        scan(phone, directory, "direct", port, owner_card, "the scanned invitation", opener=opener)
        phone.shot("scanned-summary")
        phone.press("Pair")
        outcome = phone.wait(
            lambda each: each == "Check this value on the host" or each.startswith("The invitation did not work"),
            "the value or a refusal",
            90,
        )
        if outcome["label"] == "Check this value on the host":
            break
        # The scanner read the picture of the changed secret that was on the wall before this one,
        # which the host refuses: a person scans again.
        opener = "Scan again"
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
    phone.press("Done")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")
    asks = lambda each: each == "Use another pairing service?"
    scan(phone, directory, "code", port, asks, "the alert naming the other service", stale=any_card)
    # The alert names the service the code names: the host's other service, on the port the host says.
    service = f"https://127.0.0.1:{json.loads(read(directory, 'ready.json'))['service_port']}"
    named = phone.find(lambda each: each.startswith(f"This code belongs to {service}."))
    if named is None:
        phone.give_up(f"the alert does not name {service}")
    phone.shot("origin-alert")
    phone.press("Cancel")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen after Cancel")
    if read(directory, "connections.txt") != "0":
        raise SystemExit("a service was contacted before the person agreed")
    say("cancelled: no connection")
    scan(phone, directory, "code", port, asks, "the alert the second time", stale=any_card)
    # The button that accepts is "Use <the service>", and the alert's title is a question that starts
    # with the same word.
    accepts = lambda each: each.lower().startswith("use ") and not each.endswith("?")
    phone.tap(phone.wait(accepts, "the button that accepts the service"))
    phone.wait(lambda each: each.startswith("Code for a host that uses"), "the held code")
    phone.press("Pair")
    end = time.monotonic() + 60
    while read(directory, "connections.txt") != "1":
        if time.monotonic() > end:
            phone.give_up("the other service was not contacted once the person agreed")
        time.sleep(0.25)
    say("accepted: one connection")
    touch(directory, "code-done")
    wait_for_file(directory, "done-code")
    picker_on_a_paired_phone(phone)
    owner_confirmations(phone, directory)


# ---- The release build's verified TLS ----------------------------------------------------------


def a_code_no_host_holds() -> str:
    """Ten characters of the pairing alphabet that no host was given: a locator nobody reserved."""
    import secrets

    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return "".join(secrets.choice(alphabet) for _ in range(10))


def start_pairing_screen(phone: Phone) -> None:
    """Starts the application afresh and opens the pairing screen."""
    phone.run("shell", "am", "force-stop", APP)
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each == "Hosts", "the shell's Hosts tab", 90)
    phone.press("Hosts")
    phone.wait(lambda each: each == "Pair with a host", "the pairing screen")


def type_into_field(phone: Phone, text: str, replacing: int = 0, holding: str = "") -> None:
    """Types `text` into the text field on the screen whose text starts with `holding` (the code
    field, empty or showing its placeholder, when it is blank), after taking out `replacing`
    characters."""
    fields = [node for node in phone.screen() if node["class"] == "android.widget.EditText"]
    field = next(
        (
            node
            for node in fields
            if node["label"].startswith(holding) and (holding or not node["label"].startswith("https://"))
        ),
        None,
    )
    if field is None:
        phone.give_up("the screen shows no such text field")
    phone.tap(field)
    if replacing:
        phone.run("shell", "input", "keyevent", "KEYCODE_MOVE_END")
        phone.run("shell", "input", "keyevent", *(["KEYCODE_DEL"] * replacing))
    phone.run("shell", "input", "text", text)
    # What the field holds is read back, and an input method's stray character taken out: the field's
    # text is what the application is told, and a run never depends on what it was meant to hold.
    for _ in range(3):
        time.sleep(0.8)
        held = next(
            (
                node["label"]
                for node in phone.screen()
                if node["class"] == "android.widget.EditText" and node["label"].startswith(text[:4])
            ),
            None,
        )
        if held == text:
            return
        if held is not None and held.startswith(text):
            phone.run("shell", "input", "keyevent", "KEYCODE_MOVE_END")
            phone.run("shell", "input", "keyevent", *(["KEYCODE_DEL"] * (len(held) - len(text))))
    phone.give_up(f"the field does not hold what was typed ({text})")


def point_codes_at(phone: Phone, origin: str, host: str) -> None:
    """Changes the service codes go through, and goes on only once the screen names `host` as it.

    The keyboard covers the button, so the form is sent with the keyboard's own key: a tap at the
    button's place would land on a key of the keyboard. A code is never sent to another service by
    a run that is about this one, so the attempt that follows is made only once the screen says where
    it goes.
    """
    start_pairing_screen(phone)
    phone.press("Change")
    phone.wait(lambda each: each == "Use this service", "the field for the pairing service", 30)
    type_into_field(phone, origin, replacing=40, holding="https://")
    phone.run("shell", "input", "keyevent", "KEYCODE_ENTER")
    phone.wait(lambda each: each == host, f"{host} as the service codes go through", 30)


def one_attempt(phone: Phone, shot: str) -> str:
    """Sends one random code through the service the screen names, and says how it ended:
    `admitted` (no host answered for it), `not_pairing` (the origin does not offer pairing), or
    `unreachable` (the service could not be reached), or `none` when nothing came in time."""
    type_into_field(phone, a_code_no_host_holds())
    phone.run("shell", "input", "keyevent", "KEYCODE_ENTER")
    end = time.monotonic() + 180
    outcome = "none"
    while time.monotonic() < end:
        words = " | ".join(node["label"] for node in phone.screen() if node["label"])
        if "No host answered for this code" in words:
            outcome = "admitted"
            break
        if "does not offer pairing" in words:
            outcome = "not_pairing"
            break
        if "could not be reached" in words:
            outcome = "unreachable"
            break
        time.sleep(1)
    phone.shot(shot)
    return outcome


def release(adb: str, serial: str, directory: Path, shots: Path, port: str, attempts: Path) -> None:
    """Drives the minified release build through its pairing screen.

    The deployed room first: one attempt with a code no host holds. The room admits a socket for any
    locator and gives an unknown one the shape of a known one, so the attempt ends the way an
    admitted attempt does, with the words for a code no host answered. A build that lost the
    platform verifier cannot get as far, and says the service could not be reached. The two
    sentences differ, so the screen decides it.

    Then the local server whose certificate the system does not trust: the phone says it could not
    reach the service, and the server's own record (judged by the script) says what the phone did.
    """
    phone = Phone(adb, serial, shots)
    shots.mkdir(parents=True, exist_ok=True)
    failed = False

    deployed = os.environ.get("KR_RELEASE_NO_DEPLOYED") != "1"
    if deployed:
        start_pairing_screen(phone)
        phone.wait(lambda each: each == "Pair", "the button that starts an attempt", 30)
        attempts.parent.mkdir(parents=True, exist_ok=True)
        with attempts.open("a", encoding="utf-8") as record:
            record.write(f"attempt at the deployed service at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} local time\n")
        say_plain(f"one attempt at the deployed service at {time.strftime('%H:%M:%S')} local time")
        outcome = one_attempt(phone, "release-deployed")
        with attempts.open("a", encoding="utf-8") as record:
            record.write(f"  outcome: {outcome}\n")
        if outcome == "admitted":
            print("RELEASE-TLS the application admitted the attempt at the deployed service", flush=True)
        else:
            failed = True
            print(f"RELEASE-TLS-FAILED the deployed service was not reached as an admitted attempt: {outcome}", flush=True)

    # A public origin the system trusts, as a positive control for the verifier, when one is named:
    # the product's own lookup with a random code, and no credential.
    public = os.environ.get("KR_RELEASE_PUBLIC_ORIGIN", "")
    if public:
        host = public.removeprefix("https://")
        point_codes_at(phone, public, host)
        with attempts.open("a", encoding="utf-8") as record:
            record.write(f"attempt at {public} at {time.strftime('%Y-%m-%d %H:%M:%S %Z')} local time\n")
        say_plain(f"one attempt at {public} at {time.strftime('%H:%M:%S')} local time")
        outcome = one_attempt(phone, "release-public")
        record_outcome = f"RELEASE-TLS public control {public}: {outcome}"
        print(record_outcome, flush=True)
        with attempts.open("a", encoding="utf-8") as record:
            record.write(f"  outcome: {outcome}\n")
        if outcome != "not_pairing":
            failed = True
            print(f"RELEASE-TLS-FAILED the public origin's certificate was not accepted: {outcome}", flush=True)

    point_codes_at(phone, f"https://127.0.0.1:{port}", "127.0.0.1")
    type_into_field(phone, a_code_no_host_holds())
    phone.run("shell", "input", "keyevent", "KEYCODE_ENTER")
    phone.wait(
        lambda each: "could not be reached" in each or "does not offer pairing" in each,
        "the words for a service that could not be used",
        120,
    )
    phone.shot("release-local")
    print("RELEASE-TLS the application could not reach the local server", flush=True)
    if failed:
        raise SystemExit(1)


def say_plain(text: str) -> None:
    print(f"RELEASE-TLS-NOTE {text}", flush=True)


def main() -> None:
    arguments = sys.argv[1:]
    if len(arguments) == 2 and arguments[0] == "aim":
        aim(arguments[1])
    elif len(arguments) == 6 and arguments[0] == "drive":
        drive(arguments[1], arguments[2], Path(arguments[3]), Path(arguments[4]), arguments[5])
    elif len(arguments) == 7 and arguments[0] == "release":
        release(arguments[1], arguments[2], Path(arguments[3]), Path(arguments[4]), arguments[5], Path(arguments[6]))
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
