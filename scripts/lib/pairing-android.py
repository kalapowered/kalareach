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

# The service a fresh installation sends codes through, as the pairing screen names it.
DEPLOYED_HOST = "reach.kala.to"


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

    def wait(self, wanted, what: str, timeout: float = 60, nudging: bool = False) -> dict:
        """Waits until a node on the screen is labelled as `wanted` says, never by a fixed delay.

        A wait that is for content the page draws after the screen was first read passes `nudging`:
        see `draw_again`."""
        found: list[dict] = []

        def seen(nodes: list[dict]) -> bool:
            node = next((each for each in nodes if each["label"] and wanted(each["label"])), None)
            if node is not None:
                found.append(node)
            return node is not None

        self.wait_screen(seen, what, timeout, nudging)
        return found[-1]

    def wait_gone(self, unwanted, what: str, timeout: float = 60) -> None:
        """Waits until no node on the screen is labelled as `unwanted` says, never by a fixed delay."""
        self.wait_screen(
            lambda nodes: not any(each["label"] and unwanted(each["label"]) for each in nodes), f"{what} to go", timeout
        )

    def wait_screen(self, holds, what: str, timeout: float = 60, nudging: bool = False) -> None:
        """Waits until `holds` says the screen's nodes are as wanted, never by a fixed delay.

        The web view hands its accessibility tree over a piece at a time: content the page draws
        after the tree was first read can be missing from it while it is on the screen, and a screen
        that shows nothing of what a condition needs is never taken for one where that is gone, so a
        wait for an absence names what must be there beside it. A wait for such content (`nudging`)
        has the screen drawn afresh now and then, and says when it needed to."""
        end = time.monotonic() + timeout
        started = time.monotonic()
        nudges = 0
        while time.monotonic() < end:
            if holds(self.screen()):
                if nudges:
                    print(f"PAIRING-NOTE {what} appeared after {nudges} round trips to another tab", flush=True)
                return
            if nudging and (time.monotonic() - started) > 8 * (nudges + 1):
                self.draw_again()
                nudges += 1
            time.sleep(0.4)
        self.give_up(f"timed out waiting for {what}")

    def draw_again(self) -> None:
        """Goes to another tab and back, which draws the Attention screen afresh and has the web view
        send all of it."""
        away = self.find(lambda each: each == "Sessions")
        back = self.find(lambda each: each.startswith("Attention"))
        if away is not None and back is not None:
            # Each tap is its own call to the device, which is longer than the screen takes to
            # change tab.
            self.tap(away)
            self.tap(back)

    def give_up(self, message: str) -> None:
        """Ends the run, saying what the screen showed, for whoever reads the failure."""
        nodes = self.screen()
        labels = " | ".join(each["label"] for each in nodes if each["label"])
        self.shot("timeout")
        # Every node `uiautomator` reported, with its class and box, for whoever reads the failure.
        (self.shots / "android-timeout-nodes.txt").write_text(
            "\n".join(f"{each['class']} {each['box']} {each['label']!r}" for each in nodes) + "\n", encoding="utf-8"
        )
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
        # The display's own size, not the widest node's: a node that runs past the screen is
        # measured against the screen. `uiautomator` clips what it reports to the window, so a
        # control wider than the screen shows as one that ends at its edge and this half cannot
        # see it; the overlap below, and the page's own checks of the same layout, are what can.
        size = re.findall(r"(\d+)x(\d+)", phone.run("shell", "wm", "size").stdout.decode("utf-8", "replace"))
        if not size:
            phone.give_up("the display's size could not be read")
        width, height = (int(each) for each in size[-1])
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

    The emulator has no screen lock at first, so the phone offers no ceremony; it is given a PIN
    before the first request is answered, and the ceremony is then its screen lock, and the prompt is
    the system's. The request is listed on the Attention tab; the first prompt is cancelled (the
    request is still listed and the invitation behind it is refused); the same request is then
    confirmed, and the host spends that confirmation on the invitation. A second device the host is
    asked to add shows a value, which the request on the phone shows too. While that request is
    listed the PIN is taken away: the button that confirms goes, the request and its value stay
    listed, and the button returns when the PIN is set again.
    """
    confirm = "Confirm with your screen lock"
    try:
        phone.run("shell", "am", "force-stop", APP)
        phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
        phone.wait(lambda each: each.startswith("Attention"), "the shell's Attention tab", 90)
        phone.tap(phone.wait(lambda each: each.startswith("Attention"), "the shell's Attention tab"))
        touch(directory, "go-confirm")
        wait_for_file(directory, "challenge.txt")
        # The request is on the Attention tab, which counts it. The lock is set while it is listed,
        # and the button appears named for it without the request coming or going.
        phone.wait(lambda each: "1 waiting for you" in each, "the host's request counted on the Attention tab", 120)
        phone.run("shell", "locksettings", "set-pin", SCREEN_LOCK_PIN)
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the host's request", 45, nudging=True))
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
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the host's request", 30, nudging=True))
        enter_screen_lock(phone)
        phone.wait(lambda each: each.startswith("Confirmed."), "the words for a confirmed request", 60)
        wait_for_file(directory, "confirm-result.txt", 60)
        phone.shot("confirmed")
        say("the host's request is confirmed with the screen lock")

        touch(directory, "go-device")
        wait_for_file(directory, "device-value.txt", 90)
        value = read(directory, "device-value.txt").replace(" ", "")
        spelled = ", ".join(" ".join(group) for group in (value[:4], value[4:]))
        phone.wait(lambda each: spelled in each, f"the value {value} the second device shows", 60, nudging=True)
        phone.wait(lambda each: each == confirm, "the button that confirms the second device", 30, nudging=True)
        # The page is shown the request with a ceremony; the lock goes while it is listed, and the
        # page is told: the button goes, and the request and its value stay. The screen must show the
        # request's value without the button: a screen that shows neither is a tree not yet drawn.
        phone.run("shell", "locksettings", "clear", "--old", SCREEN_LOCK_PIN)

        def listed_without_the_button(nodes: list[dict]) -> bool:
            labels = [each["label"] for each in nodes if each["label"]]
            return any(spelled in each for each in labels) and not any(each.startswith("Confirm with") for each in labels)

        phone.wait_screen(
            listed_without_the_button,
            "the request listed with no button, once the phone has no screen lock",
            120,
            nudging=True,
        )
        phone.shot("confirm-no-lock")
        say("a phone with no screen lock offers no way to confirm, and still lists the request")
        phone.run("shell", "locksettings", "set-pin", SCREEN_LOCK_PIN)
        phone.tap(phone.wait(lambda each: each == confirm, "the button, once the screen lock is back", 120, nudging=True))
        enter_screen_lock(phone)
        phone.wait(lambda each: each.startswith("Confirmed."), "the words for a confirmed request", 60)
        wait_for_file(directory, "device-result.txt", 90)
        say("a new device is confirmed against its value")
    finally:
        phone.run("shell", "locksettings", "clear", "--old", SCREEN_LOCK_PIN)


# The text the person writes as a draft in the session, which the host's agent is later sent.
DRAFT = "Check the release notes before tagging"


def start_on(phone: Phone, tab: str) -> None:
    """Starts the application afresh on the shell and opens the tab named `tab`."""
    phone.run("shell", "am", "force-stop", APP)
    phone.run("shell", "am", "start", "-n", f"{APP}/.MainActivity")
    phone.wait(lambda each: each.startswith(tab), f"the shell's {tab} tab", 90)
    open_tab(phone, tab)


def open_tab(phone: Phone, tab: str) -> None:
    """Opens the tab named `tab`; the bar over it names it too. A tap that lands while the shell
    settles is made again."""
    for _ in range(3):
        phone.tap(phone.wait(lambda each: each.startswith(tab) and len(each) < 60, f"the {tab} tab"))
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if phone.find(lambda each: each == tab) is not None:
                return
            time.sleep(0.4)
    phone.give_up(f"the {tab} tab never opened")


def composer_of(phone: Phone) -> dict | None:
    """The field a message is written in."""
    return next((node for node in phone.screen() if node["class"] == "android.widget.EditText"), None)


def composer_text(phone: Phone) -> str:
    field = composer_of(phone)
    return "" if field is None or field["label"] == "Message this session" else field["label"]


def hide_keyboard(phone: Phone) -> None:
    """Puts the software keyboard away, when it is up: a Back with no keyboard would leave the
    session."""
    for _ in range(3):
        shown = phone.run("shell", "dumpsys", "input_method").stdout.decode("utf-8", "replace")
        if "mInputShown=true" not in shown:
            return
        phone.run("shell", "input", "keyevent", "KEYCODE_BACK")
        time.sleep(0.8)


def open_the_session(phone: Phone) -> None:
    """Opens the host's first session from the Sessions tab, as a person does."""
    open_tab(phone, "Sessions")
    phone.tap(phone.wait(lambda each: "Session 1" in each and not each.startswith(("Sessions", "Attention")), "the host's session in the list", 90))
    phone.wait(lambda each: each == "Message this session" or each == DRAFT, "the composer", 60)


def switch_view(phone: Phone, name: str) -> None:
    """Chooses the Conversation or the Terminal view and waits until the pane shows it: the
    conversation of a session with no entries says so, and the terminal's pane does not."""
    phone.press(name)
    empty = "Nothing in this conversation yet."

    def shows(nodes: list[dict]) -> bool:
        said = any(each["label"] == empty for each in nodes)
        return said if name == "Conversation" else not said and any(each["label"] == name for each in nodes)

    phone.wait_screen(shows, f"the {name} view", 30)


def wait_after_touch(phone: Phone, wanted, what: str, timeout: float = 60, at: tuple[float, float] = (0.2, 0.3)) -> None:
    """Waits for text the page drew over the screen the tree was last read for: a sheet opened over
    the inbox, or a row that appeared in it.

    The web view hands its accessibility tree over a piece at a time, and what the page draws after
    the screen was first read can be missing from it while it is on the screen, as content drawn
    after the first read is (`Phone.wait_screen`). A touch on text that does nothing, at `at` (a
    fraction of the width and of the height), has the web view send what it holds; the tab switch
    `nudging` makes would close a sheet and remount the inbox."""
    size = re.findall(r"(\d+)x(\d+)", phone.run("shell", "wm", "size").stdout.decode("utf-8", "replace"))
    if not size:
        phone.give_up("the display's size could not be read")
    width, height = (int(each) for each in size[-1])
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if phone.find(wanted) is not None:
            return
        phone.run("shell", "input", "tap", str(int(width * at[0])), str(int(height * at[1])))
        time.sleep(1.5)
    phone.give_up(f"timed out waiting for {what}")


def ask_host(directory: Path, phase: str, timeout: float) -> None:
    """Asks the host to be switched off or on and waits until it says it has been. The host takes the
    request away when it is done, so a later request is a new one."""
    (directory / f"done-{phase}").unlink(missing_ok=True)
    touch(directory, f"go-{phase}")
    wait_for_file(directory, f"done-{phase}", timeout)


def paired_host_used(phone: Phone, directory: Path) -> None:
    """The paired host as a person uses it: the inbox tells four kinds apart and a question names
    who asked (13.01, 11.61); the tabs and the settings over a session are walked (13.09); a draft
    is carried across the views and across the host being out of contact (13.03, 13.13, 13.01); and
    the host asks the phone to confirm a hand-over of a session (18.15)."""
    start_on(phone, "Attention")
    touch(directory, "go-seed")
    wait_for_file(directory, "seed-result.txt", 120)
    # A paired device is given the host's own words for each item and none of a session's text.
    for kind, text in (
        ("Waiting for you", "An approval is waiting for you"),
        ("Did not finish", "A command ended with a failure"),
        ("Ready to review", "Finished work is ready to review"),
        ("Waiting for you", "A question is waiting for an answer"),
    ):
        phone.wait(
            lambda each, kind=kind, text=text: each.startswith(f"{kind}. ") and text in each,
            f'a "{kind}" row holding "{text}"',
            120,
            nudging=True,
        )
    phone.shot("attention-four-kinds")
    say("the inbox tells an approval, a failure, finished work and a question apart")
    phone.tap(phone.wait(lambda each: each.startswith("Waiting for you. ") and "A question is waiting for an answer" in each, "the question's row"))
    wait_after_touch(phone, lambda each: each.startswith("Asked by"), "the asker of the question")
    # The identity is the program the host verified, and the name it gave itself comes after it, said
    # not to be verified. The page draws them as parts of one line, which the screen reader's tree
    # may give as one text or as several, so the texts are read in order as one line.
    line = " ".join(node["label"] for node in phone.screen() if node["label"])
    asked = re.search(
        r"Asked by\s+claude\s+\(\s*process \d+\s*\)\s*\u00b7\s*calls itself\s*\u201c\s*claude \(verified by KalaReach\)\s*\u201d\s*\(not verified\)",
        line,
    )
    if asked is None:
        phone.give_up("the question does not name the verified program as the asker and its own name as unverified")
    if phone.find(lambda each: each == "/usr/local/bin/claude") is None:
        phone.give_up("the verified path is not shown")
    phone.shot("question-identity")
    say("the question names the verified program and shows the name it gave itself as unverified")
    wait_after_touch(phone, lambda each: each == "Close item", "the control that closes the question's sheet")
    phone.press("Close item")

    # The host is switched off: the inbox says so in so many words, keeps what it last read from
    # the host beneath, said to be from then, and shows no failure.
    ask_host(directory, "down", 120)
    # Touched at the bar's title, which does nothing: a round trip to another tab would remount the
    # inbox, which reads again from nothing, and a touch on the list could open a row.
    wait_after_touch(
        phone, lambda each: "is out of contact" in each, "the inbox to say the host is out of contact", 120, at=(0.5, 0.07)
    )
    # The row is one node whose text is its parts one after another.
    if phone.find(lambda each: "No contact for" in each or "No contact." in each) is None:
        phone.give_up("the inbox does not say how long")
    if phone.find(lambda each: "may still be running" in each) is None:
        phone.give_up("the inbox does not say the sessions may still be running")
    if phone.find(lambda each: "What is listed here from it was read" in each) is None:
        phone.give_up("the rows it last read are not said to be from that read")
    if phone.find(lambda each: each.startswith("Waiting for you. An approval is waiting for you")) is None:
        phone.give_up("the rows last read were dropped")
    if phone.find(lambda each: each == "The inbox could not be read") is not None:
        phone.give_up("the inbox says it failed")
    # The question's sheet is closed by now. A touch on the page behind a sheet that is still up
    # closes it, as the title bar does, so the photograph is of the inbox and nothing over it.
    for _ in range(4):
        if phone.find(lambda each: each == "Close item") is None:
            break
        phone.press("Close item")
        time.sleep(1.5)
    else:
        phone.give_up("the question's sheet did not close")
    phone.shot("inbox-host-out-of-contact")
    say("the inbox shows the host as out of contact above what it last read from it")
    ask_host(directory, "up", 180)
    phone.wait_gone(lambda each: "is out of contact" in each, "the host out of contact", 180)

    start_on(phone, "Hosts")
    phone.wait(lambda each: each == "In use", "the host in use", 60)
    phone.shot("tab-hosts")
    open_the_session(phone)
    phone.shot("tab-sessions-open-session")
    # The bar's control is an icon the tree can lack until the web view is touched on the bar's title.
    wait_after_touch(phone, lambda each: each == "Settings", "the Settings control", at=(0.5, 0.07))
    phone.press("Settings")
    wait_after_touch(phone, lambda each: each == "The session behind this keeps running.", "the settings over the session")
    phone.shot("settings-over-the-session")
    wait_after_touch(phone, lambda each: each == "Close settings", "the control that closes the settings")
    phone.press("Close settings")
    # What is drawn afresh reaches the tree late, and what is gone can stay in it: a touch on the
    # bar's title has the web view send what it holds, and the control is pressed again if the sheet
    # is still there then.
    for attempt in range(4):
        end = time.monotonic() + 8
        while time.monotonic() < end:
            phone.run("shell", "input", "tap", "540", "168")
            time.sleep(1.5)
            if phone.find(lambda each: each == "The session behind this keeps running.") is None:
                break
        else:
            phone.press("Close settings")
            continue
        break
    else:
        phone.give_up("the settings did not close")
    if composer_of(phone) is None:
        phone.give_up("the session is not where it was once the settings closed")
    phone.shot("settings-closed")
    say("the tabs list the host and its session, and the settings open over a session and close to it")

    # A draft is the same text in both views of the session.
    for _ in range(3):
        # The settings sheet closes with an animation and the tree can still hold it: it is looked
        # at again, and closed again if it is still up, before the field is touched.
        if phone.find(lambda each: each == "Close settings") is not None:
            phone.press("Close settings")
            time.sleep(2)
            continue
        phone.tap(composer_of(phone))
        phone.run("shell", "input", "text", DRAFT.replace(" ", "%s"))
        end = time.monotonic() + 10
        while time.monotonic() < end and phone.find(lambda each: each == DRAFT) is None:
            time.sleep(0.5)
        if phone.find(lambda each: each == DRAFT) is not None:
            break
    phone.wait_screen(lambda nodes: any(each["label"] == DRAFT for each in nodes), "the composer to hold the draft", 30)
    hide_keyboard(phone)
    switch_view(phone, "Terminal")
    phone.wait_screen(lambda nodes: any(each["label"] == DRAFT for each in nodes), "the draft in the terminal view", 30)
    phone.shot("draft-terminal-view")
    switch_view(phone, "Conversation")
    phone.wait_screen(lambda nodes: any(each["label"] == DRAFT for each in nodes), "the draft in the conversation view", 30)
    phone.shot("draft-conversation-view")
    say("the draft is the same text in both views")

    # The host stops answering: the draft stays, and the session says so.
    ask_host(directory, "down", 120)
    lost = "Not in contact with this host. The draft is kept here."
    phone.wait(lambda each: each == lost, "the words for a draft that lost its host", 90)
    if composer_text(phone) != DRAFT:
        phone.give_up("the draft was changed when the host stopped answering")
    send = phone.find(lambda each: each == "Send")
    if send is None or send["enabled"]:
        phone.give_up("a draft that lost its host can be sent")
    phone.shot("draft-host-out-of-contact")

    # The person leaves the session, the host is switched on again at the same address while they
    # are elsewhere, and the draft is bound to its conversation again and is sent there.
    # The system's back leaves the session as the bar's control does; the control is an icon the
    # tree can lack.
    phone.run("shell", "input", "keyevent", "KEYCODE_BACK")
    wait_after_touch(
        phone, lambda each: each == "No host is being reached.", "the sessions list, which says no host is reached", 30, at=(0.5, 0.07)
    )
    ask_host(directory, "up", 180)
    open_the_session(phone)
    phone.wait_screen(
        lambda nodes: not any(each["label"] == lost for each in nodes)
        and any(each["label"] == "Send" and each["enabled"] for each in nodes),
        "the draft to be bound again",
        180,
    )
    if composer_text(phone) != DRAFT:
        phone.give_up("the draft was changed while the host was out of contact")
    phone.shot("draft-host-back")
    phone.press("Send")
    touch(directory, "go-sent")
    wait_for_file(directory, "sent-result.txt", 90)
    if read(directory, "sent-result.txt") != f"prompts=1 text={DRAFT}":
        raise SystemExit(f"the agent was not sent the draft once: {read(directory, 'sent-result.txt')}")
    say("the draft was kept across the views and the host being out of contact, and sent once")

    # The host asks the owner to confirm a hand-over of the session to another device.
    confirm = "Confirm with your screen lock"
    try:
        start_on(phone, "Attention")
        touch(directory, "go-handover")
        wait_for_file(directory, "handover-asked.txt", 120)
        phone.wait(lambda each: each == "Hand control of a session to another device", "the hand-over", 120, nudging=True)
        phone.wait(lambda each: "who may act as the session's owner for" in each, "the role the receiving device is given", 30)
        phone.wait(lambda each: each == "Allows", "what the hand-over allows", 30)
        phone.wait(lambda each: "share sessions with others" in each, "the kinds of action listed", 30)
        # The phone is given its screen lock while the request is listed, and the button appears
        # named for it; the photograph shows the request with the button a person would press.
        phone.run("shell", "locksettings", "set-pin", SCREEN_LOCK_PIN)
        phone.wait(lambda each: each == confirm, "the button that confirms the hand-over", 60, nudging=True)
        phone.shot("handover-sheet")
        say("the hand-over is shown with the role and each kind of action it allows")
        phone.tap(phone.wait(lambda each: each == confirm, "the button that confirms the hand-over", 60, nudging=True))
        enter_screen_lock(phone)
        phone.wait(lambda each: each.startswith("Confirmed."), "the words for a confirmed request", 60)
        wait_for_file(directory, "handover-result.txt", 120)
        if not read(directory, "handover-result.txt").endswith("receiver_holds=1 giver_holds=0"):
            raise SystemExit(f"the hand-over did not move the session: {read(directory, 'handover-result.txt')}")
        phone.shot("handover-confirmed")
        say("the hand-over is confirmed with the screen lock and the session changes hands")
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
    paired_host_used(phone, directory)


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
        # A code is sent only to the service the screen names: a package whose default were another
        # origin would otherwise be tried against it, and still pass.
        phone.wait(lambda each: each == DEPLOYED_HOST, f"{DEPLOYED_HOST} as the service codes go through", 30)
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
