#!/usr/bin/env python3
"""Drives the Android emulator's notification shade and the application's Attention screen, for
`scripts/e2e-push-device.sh android`.

Commands, each given the adb program, the emulator's serial and a screenshot directory:

  tap <words>
      Opens the notification shade, taps the notification that shows those words and waits for the
      application to come to the front on its Attention tab. The words are the host's generic alert,
      so a notification that carried any of the question's text would not be found. Prints
      `PUSH-TAPPED <what the screen shows>`.

  choose <words of the question> <Yes|No>
      On the Attention screen, opens the item that shows those words and chooses the answer, without
      sending it. Prints `PUSH-CHOSEN <what the screen shows>`.

  send
      Presses the button that sends the chosen answer and prints `PUSH-SENT <what the screen shows
      once the host has answered>`.

It reads the application through `uiautomator`, which names the page's own buttons and texts, and
drives it with taps at the centre of what it names, as `pairing-android.py` does, whose `Phone` it
uses. It uses the Python standard library alone.
"""

import importlib.util
import sys
from pathlib import Path

_here = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pairing_android", _here / "pairing-android.py")
_pairing = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_pairing)
Phone = _pairing.Phone


def texts(phone: Phone) -> str:
    """The labels the screen names, in one line."""
    return " | ".join(each["label"] for each in phone.screen() if each["label"])[:3000]


def tap_notification(phone: Phone, words: str) -> None:
    phone.run("shell", "cmd", "statusbar", "expand-notifications")
    node = phone.wait(lambda each: words in each, f"the notification that shows {words!r}", 45)
    phone.shot("notification")
    phone.tap(node)
    phone.wait(lambda each: each.startswith("Attention"), "the application's Attention tab", 45)
    phone.shot("tapped")
    print(f"PUSH-TAPPED {texts(phone)}", flush=True)


def choose(phone: Phone, words: str, choice: str) -> None:
    item = phone.wait(lambda each: words in each, f"the Attention item that shows {words!r}", 60, nudging=True)
    phone.tap(item)
    phone.tap(phone.wait(lambda each: each.lower() == choice.lower(), f"the {choice} choice", 45))
    phone.shot("chosen")
    print(f"PUSH-CHOSEN {texts(phone)}", flush=True)


def send(phone: Phone) -> None:
    phone.tap(phone.wait(lambda each: each == "Send answer", "the button that sends the answer", 30))
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


def main() -> None:
    arguments = sys.argv[1:]
    if len(arguments) >= 4 and arguments[0] in {"tap", "choose", "send"}:
        phone = Phone(arguments[1], arguments[2], Path(arguments[3]))
        if arguments[0] == "tap" and len(arguments) == 5:
            tap_notification(phone, arguments[4])
            return
        if arguments[0] == "choose" and len(arguments) == 6:
            choose(phone, arguments[4], arguments[5])
            return
        if arguments[0] == "send" and len(arguments) == 4:
            send(phone)
            return
    raise SystemExit(__doc__)


if __name__ == "__main__":
    main()
