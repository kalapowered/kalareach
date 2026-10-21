#!/usr/bin/env python3
"""Attaches to a session of one release's daemon from the command line, and shows its screen.

    e2e-update-attach.py PROGRAMS

PROGRAMS holds the release's `kr-controller`, `kr-worker` and `kr`, as an installed release does.
A daemon of an installed release starts the release's own worker, so it is given none. It starts
with a runtime and a state directory of its own under a directory of this script's making, a session is made whose shell
prints a marker and then waits, and `kr attach` runs in a terminal of this script's making. The
marker has to reach that terminal, which is the session's screen put on it by the attach. Every
process this starts it ends by its own number, and that directory is removed.
"""

import fcntl
import json
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time

MARKER = "KR-ATTACH-MARKER"


def main(programs):
    # A short path under /tmp: the daemon's socket lives in the runtime directory, and a socket's path
    # is held to about a hundred characters.
    run = os.path.realpath(tempfile.mkdtemp(prefix="kr-at-", dir="/tmp"))
    runtime = os.path.join(run, "r")
    state = os.path.join(run, "s")
    for path in (runtime, state):
        os.makedirs(path, mode=0o700, exist_ok=True)
    shell = os.path.join(run, "marker-shell.sh")
    # The tools a person's development work starts with, run by the session's own shell, so that
    # what the attach shows is also what an unsandboxed host lets them do.
    tools = {"git": "git version", "cargo": "cargo "}
    found = {name: shutil.which(name) for name in tools}
    lines = [f"printf '{MARKER}\\n'"] + [f"'{path}' --version" for path in found.values() if path]
    with open(shell, "w", encoding="utf-8") as handle:
        handle.write("#!/bin/sh\n" + "\n".join(lines) + "\nexec cat\n")
    os.chmod(shell, 0o755)

    environment = dict(os.environ, KR_RUNTIME_DIR=runtime, KR_STATE_DIR=state)
    kr = os.path.join(programs, "kr")
    controller = subprocess.Popen(
        [
            os.path.join(programs, "kr-controller"),
            "--runtime-dir", runtime,
            "--state-dir", state,
            "--secret-store", "file",
        ],
        cwd=run,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    attached = None
    try:
        # An allowance and not a deadline: the daemon opens its registry and builds its signing
        # identity before it answers, and the last question is answered whatever it takes.
        waited = time.monotonic()
        while time.monotonic() - waited < 180:
            if controller.poll() is not None:
                raise SystemExit(f"the daemon of this release ended with status {controller.returncode}")
            answer = subprocess.run([kr, "doctor", "--json"], env=environment, capture_output=True)
            if answer.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise SystemExit("the daemon of this release did not answer")
        created = subprocess.run(
            [kr, "new", "--invisible", "--headless", "--cwd", run, "--shell", shell, "--json"],
            env=environment, capture_output=True, text=True, check=True,
        )
        display = str(json.loads(created.stdout)["display_number"])

        child, terminal = pty.fork()
        if child == 0:
            os.execve(kr, [kr, "attach", "--no-probe", display], environment)
        attached = child
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        seen = b""
        end = time.monotonic() + 60
        wanted = [MARKER] + [tools[name] for name, path in found.items() if path]
        while not all(text.encode() in seen for text in wanted) and time.monotonic() < end:
            ready, _, _ = select.select([terminal], [], [], 1.0)
            if ready:
                try:
                    block = os.read(terminal, 65536)
                except OSError:
                    break
                if not block:
                    break
                seen += block
        missing = [text for text in wanted if text.encode() not in seen]
        if missing:
            raise SystemExit(f"the attach did not show {missing}; it showed {len(seen)} bytes")
        print(f"ok: kr attach showed the session's screen and the tools it ran: {', '.join(name for name, path in found.items() if path)}")
        for name, path in found.items():
            if not path:
                print(f"not run: {name} is not on this machine's search path")
        subprocess.run([kr, "close", display], env=environment, capture_output=True)
    finally:
        if attached is not None:
            try:
                os.kill(attached, signal.SIGTERM)
                os.waitpid(attached, 0)
            except (ProcessLookupError, ChildProcessError):
                pass
        controller.terminate()
        try:
            controller.wait(timeout=60)
        except subprocess.TimeoutExpired:
            controller.kill()
            controller.wait()
        shutil.rmtree(run, ignore_errors=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    main(sys.argv[1])
