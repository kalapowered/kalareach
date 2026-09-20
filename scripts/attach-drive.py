"""Drives a terminal attached to a managed session, the way a person at one does.

Two things happen here that nothing else in this qualification can reach: the key the person bound
is pressed, and the end-of-file gesture is made at an empty primary prompt. Both go over the
daemon's own attachment to the packaged shell the worker started, so what answers is that shell's
reader rather than a harness standing in for one.

The attachment establishes what this terminal can do before it lets anything be typed, so this
answers those questions as a qualified terminal does: silence for a mode report is allowed, but
the device-attributes reply is the terminator and the attachment fails without it.

The gesture ends the attachment. The session stays, which is the point of it: a person who makes
that gesture at a KalaReach prompt leaves the terminal without ending their session.
"""

import fcntl
import os
import pty
import re
import select
import struct
import sys
import termios
import time

BINDING = b"\x1bq"
ENTER = b"\r"
GESTURE = b"\x04"
COMMAND = "kr-user-binding-ran"
# The session's own prompt, from the customisation its startup file runs. An attachment paints a
# screen rather than replaying what was written, so the trailing space of that prompt is an erased
# cell rather than a character, and only what is drawn is matched here.
PROMPT = "KR>"

DEVICE_ATTRIBUTES = b"\x1b[c"
DEVICE_ATTRIBUTES_REPLY = b"\x1b[?62;1;6;22c"
MODE_REPORT = re.compile(rb"\x1b\[\?(\d+)\$p")
# The control sequences a painted screen is made of, so that what is matched above is the text a
# person would see: CSI with its parameter and intermediate bytes, OSC and DCS to their
# terminators, and the two-byte escapes.
ESCAPES = re.compile(
    r"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    r"|\x1b][^\x07\x1b]*(?:\x07|\x1b\\)"
    r"|\x1bP[^\x1b]*\x1b\\"
    r"|\x1b[()][0-9A-B]"
    r"|\x1b[=>78MDEHc]"
)

WHOLE_RUN = 90.0
SETTLE = 1.0


def answer_probe(master: int, chunk: bytes) -> None:
    """Answers the questions the attachment asks this terminal about itself."""
    for mode in MODE_REPORT.findall(chunk):
        # Reset, which is what a terminal that has had none of these turned on reports.
        os.write(master, b"\x1b[?" + mode + b";2$y")
    if DEVICE_ATTRIBUTES in chunk:
        os.write(master, DEVICE_ATTRIBUTES_REPLY)


def drive() -> int:
    command = [os.environ["KR_ATTACH_KR"], "attach", os.environ["KR_ATTACH_DISPLAY"]]
    environment = dict(os.environ)
    environment["HOME"] = os.environ["KR_ATTACH_HOME"]
    environment["TERM"] = "xterm-256color"

    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execve(command[0], command, environment)
        finally:
            os._exit(127)
    # A terminal has a size, and an attachment that is offered one without it is refused.
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

    screen = ""
    stage = "prompt"
    prompts = 0
    ended = False
    at = 0.0
    deadline = time.monotonic() + WHOLE_RUN
    while time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.2)
        if ready:
            try:
                chunk = os.read(master, 8192)
            except OSError:
                chunk = b""
            if not chunk:
                ended = True
                break
            answer_probe(master, chunk)
            screen += chunk.decode("utf-8", "replace")
            at = time.monotonic()
            continue
        # Nothing has arrived for a moment, so what is on the screen is what the session is
        # showing rather than the middle of a redraw.
        if at == 0.0 or time.monotonic() - at < SETTLE:
            continue
        visible = ESCAPES.sub("", screen)
        if stage == "prompt" and visible.count(PROMPT) > prompts:
            prompts = visible.count(PROMPT)
            os.write(master, BINDING)
            stage = "binding"
        elif stage == "binding":
            if COMMAND not in visible:
                print("the key the person bound put nothing on the line")
                break
            print("the binding the person's own startup made put %r on the line" % COMMAND)
            os.write(master, ENTER)
            # Counted again here: pressing the key repaints the line, and the gesture belongs at
            # the prompt that comes back after the command has run rather than at that repaint.
            prompts = visible.count(PROMPT)
            stage = "ran"
        elif stage == "ran" and visible.count(PROMPT) > prompts:
            # The command the binding wrote has run and the shell is back at an empty primary
            # prompt, which is the only place the gesture means what it means.
            os.write(master, GESTURE)
            stage = "gesture"
        at = time.monotonic()

    os.close(master)
    _, status = os.waitpid(pid, 0)

    if stage != "gesture":
        print("the attached terminal stopped at %r" % stage)
        print(ESCAPES.sub("", screen)[-800:])
        return 1
    if not ended:
        print("the gesture left the attachment running")
        return 1
    if status != 0:
        print("the attachment ended with wait status %d" % status)
        return 1
    print("the gesture at that prompt ended the attachment")
    return 0


if __name__ == "__main__":
    sys.exit(drive())
