#!/usr/bin/env python3
"""Runs the real `kr pair` commands as the issuing side of a pairing, on a pseudo-terminal, for
`scripts/e2e-pairing-issuer-device.sh`.

Each command starts `kr` below a pseudo-terminal of its own, which is its controlling terminal, as a
person's terminal is; answers the questions the command asks, the way a person at the host would; and
keeps what the terminal showed, whole. Three files are kept for a command named `<name>`, in the
output folder: `<name>.raw` holds every byte the command printed, `<name>.txt` holds what the screen
showed (the colour codes taken out, each line ended as a terminal ends it) and `<name>.timed.txt`
holds the same lines, each with the seconds since the command began and the moments the helper typed.
`<name>.exit` holds the command's exit code. Every command also prints one summary line, `ISSUER <what>`.

Commands, each with the options `--kr`, `--runtime-dir`, `--state-dir`, `--home` and `--out`:

  invite --name <name>
      `kr pair invite --direct --owner`. The host has no owner yet, so the command asks to be told
      the word `pair`, which is typed. Keeps the invitation's identifier in `invitation-id.txt` and
      the QR code the command drew, as a picture of that drawing, in `<name>-qr.png`.

  status --name <name> --invitation <id> [--json]
      `kr pair status <id>`, in its JSON form (which also names the permissions proposed) with `--json`.

  confirm --name <name> --invitation <id> --value-file <file> [--change-one]
      `kr pair confirm <id>`. The command asks for the verification value the new device shows; the
      text in `--value-file` (what the phone's screen showed) is typed, with its last character
      changed when `--change-one` is given.

It uses the Python standard library alone.
"""

import argparse
import codecs
import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import time
import zlib
from datetime import datetime, timezone
from pathlib import Path

# How long one command may take. A command waits for the person at its questions, and none of these
# waits for anything else.
COMMAND_SECONDS = 300

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def tidy(raw: bytes) -> str:
    """What the screen showed: the colour codes taken out, and every line ended by a line feed."""
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    return ANSI.sub("", text)


def run_on_pty(argv: list[str], environment: dict[str, str], steps: list) -> tuple[bytes, list, int, bool]:
    """Runs `argv` on a pseudo-terminal of its own and answers its questions.

    Each step is `(marker, answer)`: once the marker has been printed (after the last step's), the
    answer, a text or a function that gives one, is typed and ended with Enter. Returns what the
    command printed, the events with their times, its exit code, and whether it was ended for taking
    longer than its time.
    """
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.chdir("/")
            os.execve(argv[0], argv, environment)
        finally:
            os._exit(127)
    # A line that does not wrap, as the terminal of a person with a wide window.
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 80, 240, 0, 0))
    raw = bytearray()
    events: list[tuple[float, str, bytes]] = []
    began = time.monotonic()
    cursor = 0
    step = 0
    timed_out = False
    while True:
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try:
                data = os.read(master, 65536)
            except OSError:
                data = b""
            if not data:
                break
            raw += data
            events.append((time.monotonic() - began, "out", data))
        if step < len(steps):
            marker, answer = steps[step]
            found = raw.find(marker.encode(), cursor)
            if found >= 0:
                cursor = found + len(marker)
                typed = answer() if callable(answer) else answer
                # The prompt is up and the terminal settled before a person types.
                time.sleep(0.3)
                os.write(master, typed.encode() + b"\r")
                events.append((time.monotonic() - began, "typed", typed.encode()))
                step += 1
        if time.monotonic() - began > COMMAND_SECONDS:
            timed_out = True
            os.kill(pid, signal.SIGTERM)
            break
    _, wait_status = os.waitpid(pid, 0)
    os.close(master)
    return bytes(raw), events, os.waitstatus_to_exitcode(wait_status), timed_out


def keep(out: Path, name: str, raw: bytes, events: list, code: int, started: datetime) -> str:
    """Writes the three files of one command and returns what the screen showed."""
    (out / f"{name}.raw").write_bytes(raw)
    text = tidy(raw)
    (out / f"{name}.txt").write_text(text, encoding="utf-8")
    (out / f"{name}.exit").write_text(f"{code}\n")
    lines = [f"# {name}: started {started.strftime('%Y-%m-%d %H:%M:%S')} UTC; each line: seconds since the start"]
    pending = ""
    last = 0.0
    # A character of the QR drawing is several bytes, and a read may end inside one.
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    for at, kind, data in events:
        if kind == "typed":
            lines.append(f"[{at:8.3f}s] (typed at the terminal: {data.decode('utf-8', 'replace')!r})")
            continue
        pending += decoder.decode(data)
        while "\n" in pending:
            line, pending = pending.split("\n", 1)
            lines.append(f"[{at:8.3f}s] {ANSI.sub('', line.replace(chr(13), ''))}")
        last = at
    if pending.strip():
        lines.append(f"[{last:8.3f}s] {ANSI.sub('', pending.replace(chr(13), ''))}")
    (out / f"{name}.timed.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return text


def png(matrix: list[list[bool]], scale: int) -> bytes:
    """A black and white picture of a matrix of modules, `scale` pixels to a module."""
    width = len(matrix[0]) * scale
    rows = bytearray()
    for row in matrix:
        line = b"\x00" + bytes(0 if cell else 255 for cell in row for _ in range(scale))
        rows += line * scale

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, len(matrix) * scale, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(bytes(rows), 9))
        + chunk(b"IEND", b"")
    )


def drawn_code(text: str) -> list[list[bool]]:
    """The modules of the QR code a command drew in cells: a cell's width is a module and its two
    halves are two modules (`▀` the upper, `▄` the lower, `█` both), quiet zone included."""
    lines = text.split("\n")
    first = next((i for i, line in enumerate(lines) if "Scan this QR code" in line), None)
    last = next((i for i, line in enumerate(lines) if "shows its verification value" in line), None)
    if first is None or last is None or last <= first:
        raise SystemExit("the command's output holds no drawn QR code")
    cells = [line for line in lines[first + 1 : last] if line and set(line) <= set(" ▀▄█")]
    if not cells:
        raise SystemExit("the command drew no QR code")
    width = max(len(line) for line in cells)
    matrix: list[list[bool]] = []
    for line in cells:
        line = line.ljust(width)
        matrix.append([character in "▀█" for character in line])
        matrix.append([character in "▄█" for character in line])
    return matrix


def settings(options: argparse.Namespace) -> tuple[list[str], dict[str, str], Path]:
    out = Path(options.out)
    out.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": options.home,
        "KR_RUNTIME_DIR": options.runtime_dir,
        "KR_STATE_DIR": options.state_dir,
        "TERM": "xterm-256color",
    }
    return [options.kr], environment, out


def command(options: argparse.Namespace, arguments: list[str], steps: list) -> tuple[str, int, bool]:
    argv, environment, out = settings(options)
    started = datetime.now(timezone.utc)
    raw, events, code, timed_out = run_on_pty(argv + arguments, environment, steps)
    return keep(out, options.name, raw, events, code, started), code, timed_out


def invite(options: argparse.Namespace) -> int:
    text, code, timed_out = command(
        options,
        ["pair", "invite", "--direct", "--owner"],
        [("to issue the invitation:", "pair")],
    )
    out = Path(options.out)
    found = re.search(r"Invitation (\S+?),", text)
    if code != 0 or timed_out or not found:
        print(f"ISSUER invite failed: exit {code}{', timed out' if timed_out else ''}, invitation {'named' if found else 'not named'}")
        return 2
    (out / "invitation-id.txt").write_text(found.group(1) + "\n")
    (out / f"{options.name}-qr.png").write_bytes(png(drawn_code(text), 8))
    print(f"ISSUER invite ok: invitation {found.group(1)}")
    return 0


def status(options: argparse.Namespace) -> int:
    _, code, timed_out = command(
        options, ["pair", "status", options.invitation] + (["--json"] if options.json else []), []
    )
    print(f"ISSUER status {options.name}: exit {code}{', timed out' if timed_out else ''}")
    return 0 if code == 0 and not timed_out else 2


def confirm(options: argparse.Namespace) -> int:
    def typed() -> str:
        value = Path(options.value_file).read_text().strip()
        if options.change_one:
            last = value[-1]
            value = value[:-1] + format((int(last, 16) + 1) % 16, "x")
        return value

    _, code, timed_out = command(
        options,
        ["pair", "confirm", options.invitation],
        [("the new device shows:", typed)],
    )
    print(f"ISSUER confirm {options.name}: exit {code}{', timed out' if timed_out else ''}")
    return 0 if not timed_out else 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb in ("invite", "status", "confirm"):
        each = sub.add_parser(verb)
        for flag in ("--kr", "--runtime-dir", "--state-dir", "--home", "--out", "--name"):
            each.add_argument(flag, required=True)
        if verb != "invite":
            each.add_argument("--invitation", required=True)
        if verb == "status":
            each.add_argument("--json", action="store_true")
        if verb == "confirm":
            each.add_argument("--value-file", required=True)
            each.add_argument("--change-one", action="store_true")
    options = parser.parse_args()
    return {"invite": invite, "status": status, "confirm": confirm}[options.verb](options)


if __name__ == "__main__":
    sys.exit(main())
