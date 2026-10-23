#!/usr/bin/env python3
"""Drives the Android emulator's notification shade and the application's Attention screen, for
`scripts/e2e-push-device.sh android`.

Commands, each given the adb program, the emulator's serial and a screenshot directory:

  tap <words>
      Leaves the application on its Hosts screen in the background (`PUSH-ON-HOSTS`), opens the
      notification shade, taps the notification that shows those words and waits for the page's own
      heading to say Attention: the tap moved it there. The words are the host's generic alert, so a
      notification that carried any of the question's text would not be found. Prints
      `PUSH-TAPPED <what the screen shows>`.

  choose <words of the question> <Yes|No> [blind]
      On the Attention screen, opens the item that shows those words and chooses the answer, without
      sending it. Prints `PUSH-CHOSEN <what the screen shows>`.

  send [blind]
      Presses the button that sends the chosen answer and prints `PUSH-SENT <what the screen shows
      once the host has answered>`.

  observe
      Waits until the page says that the question was answered by someone else, with what the person
      had chosen, and offers nothing to send. Prints `PUSH-ENDED <what the screen shows>`.

`blind` is for the first sheet the application opens over the Attention screen, which the web view
does not always hand over to `uiautomator`: when the choice or the button is not on the screen, it
is pressed where the form draws it (`SHEET_CHOICES`, `SHEET_SEND`) and the run's own checks, the
worker's ledger and the page's words afterwards, say whether the answer was made.

It reads the application through `uiautomator`, which names the page's own buttons and texts, and
drives it with taps at the centre of what it names, as `pairing-android.py` does, whose `Phone` it
uses. It uses the Python standard library alone.
"""

import importlib.util
import sys
import time
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pairing_android", _here / "pairing-android.py")
_pairing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pairing)
Phone = _pairing.Phone


def texts(phone: Phone) -> str:
    """The labels the screen names, in one line."""
    return " | ".join(each["label"] for each in phone.screen() if each["label"])[:3000]


def seen_within(phone: Phone, wanted, seconds: float) -> dict | None:
    """The first node `wanted` accepts that the screen shows within `seconds`, or None."""
    end = time.monotonic() + seconds
    while True:
        node = phone.find(wanted)
        if node is not None or time.monotonic() >= end:
            return node
        time.sleep(0.4)


APPLICATION = "to.kala.reach"


def on_screen(nodes: list[dict], heading: str) -> bool:
    """Whether the screen's heading, the page's own title and not a tab's label, says `heading`."""
    return any(each["class"].endswith("TextView") and each["label"] == heading for each in nodes)


def leave_on_hosts(phone: Phone) -> None:
    """Brings the application to the front, shows its Hosts screen and leaves it there, in the
    background, as a person who has gone to another screen and then away is. A tap on the
    notification is then shown to move the page to Attention, and not to open on it by default."""
    phone.run("shell", "am", "start", "-n", f"{APPLICATION}/.MainActivity")
    tab = seen_within(phone, lambda each: each == "Hosts", 10)
    if tab is None:
        # A sheet from an earlier question is over the screen: the system's back key closes it.
        phone.run("shell", "input", "keyevent", "KEYCODE_BACK")
        tab = phone.wait(lambda each: each == "Hosts", "the Hosts tab", 60)
    phone.tap(tab)
    phone.wait_screen(lambda nodes: on_screen(nodes, "Hosts"), "the Hosts screen", 45)
    phone.run("shell", "input", "keyevent", "KEYCODE_HOME")
    print("PUSH-ON-HOSTS the application was left on its Hosts screen", flush=True)


def tap_notification(phone: Phone, words: str) -> None:
    leave_on_hosts(phone)
    phone.run("shell", "cmd", "statusbar", "expand-notifications")
    node = phone.wait(lambda each: words in each, f"the notification that shows {words!r}", 45)
    phone.shot("notification")
    phone.tap(node)
    # The page is on the Attention screen because the tap moved it there: the heading is the page's.
    phone.wait_screen(lambda nodes: on_screen(nodes, "Attention"), "the Attention screen the tap opens", 45)
    phone.shot("tapped")
    print(f"PUSH-TAPPED {texts(phone)}", flush=True)


# Where the first question's form puts its choices and its button when the sheet over the Attention
# screen has just opened, on the emulator this script is run on (1080 by 2400 pixels at its normal
# font size). The web view does not always hand over the tree of a sheet that has just opened, and
# a sheet it has not handed over cannot be read, so the first press is made at the place the form is
# drawn; the screen is read again afterwards, since the press changes the page.
SHEET_CHOICES = {"yes": (180, 1514), "no": (180, 1646)}
SHEET_SEND = (280, 1940)


def tap_at(phone: Phone, place: tuple[int, int]) -> None:
    phone.run("shell", "input", "tap", str(place[0]), str(place[1]))


def choose(phone: Phone, words: str, choice: str, blind: bool) -> None:
    item = phone.wait(lambda each: words in each, f"the Attention item that shows {words!r}", 60, nudging=True)
    phone.tap(item)
    wanted = lambda each: each.lower() == choice.lower()  # noqa: E731
    node = seen_within(phone, wanted, 8)
    if node is None and not blind:
        node = phone.wait(wanted, f"the {choice} choice", 60, nudging=True)
    if node is not None:
        phone.tap(node)
    else:
        print(f"PUSH-NOTE the sheet was not in the tree; {choice} was pressed where the form draws it", flush=True)
        tap_at(phone, SHEET_CHOICES[choice.lower()])
    phone.shot("chosen")
    print(f"PUSH-CHOSEN {texts(phone)}", flush=True)


def send(phone: Phone, blind: bool) -> None:
    node = seen_within(phone, lambda each: each == "Send answer", 8)
    if node is None and not blind:
        node = phone.wait(lambda each: each == "Send answer", "the button that sends the answer", 60, nudging=True)
    if node is not None:
        phone.tap(node)
    else:
        print("PUSH-NOTE the sheet was not in the tree; Send answer was pressed where the form draws it", flush=True)
        tap_at(phone, SHEET_SEND)
    # The page decides on a completed press: a tap is a press and a release.
    # The answer is decided when the host has answered: the button goes, or the question is said to
    # be no longer waiting.
    phone.wait_screen(
        lambda nodes: not any(each["label"] == "Send answer" for each in nodes)
        or any(each["label"].startswith("No longer waiting") for each in nodes),
        "the page to say what became of the answer",
        45,
    )
    phone.shot("sent")
    print(f"PUSH-SENT {texts(phone)}", flush=True)


def observe(phone: Phone) -> None:
    """Waits for the page to say that a question the person had chosen an answer to, and had not
    sent, was answered by someone else, and to offer nothing to send."""
    def said(nodes: list[dict]) -> bool:
        labels = [each["label"] for each in nodes]
        return (
            not any(label == "Send answer" for label in labels)
            and any(label.lower() == "no longer waiting" for label in labels)
            and any("answered by someone else" in label for label in labels)
            and any(label.startswith("You had chosen") for label in labels)
        )

    phone.wait_screen(said, "the page to say the question was answered by someone else", 60, nudging=True)
    phone.shot("ended")
    print(f"PUSH-ENDED {texts(phone)}", flush=True)


def main() -> None:
    arguments = sys.argv[1:]
    if len(arguments) >= 4 and arguments[0] in {"tap", "choose", "send", "observe"}:
        phone = Phone(arguments[1], arguments[2], Path(arguments[3]))
        if arguments[0] == "tap" and len(arguments) == 5:
            tap_notification(phone, arguments[4])
            return
        if arguments[0] == "observe" and len(arguments) == 4:
            observe(phone)
            return
        blind = arguments[-1] == "blind"
        if blind:
            arguments = arguments[:-1]
        if arguments[0] == "choose" and len(arguments) == 6:
            choose(phone, arguments[4], arguments[5], blind)
            return
        if arguments[0] == "send" and len(arguments) == 4:
            send(phone, blind)
            return
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
