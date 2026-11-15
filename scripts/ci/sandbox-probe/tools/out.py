#!/usr/bin/python3
"""Output canaries: every line a unit could print to act on the runner.

None of them may become a workflow command or an annotation once the launcher replays them.
The masked words are unique so that a later mask would show in the log.
"""
import os
import sys
import time


def main():
    out = sys.stdout
    lines = [
        "::notice::CANARY-COLON-NOTICE",
        "##[notice]CANARY-LEGACY-NOTICE",
        "::warning::CANARY-COLON-WARNING",
        "##[warning]CANARY-LEGACY-WARNING",
        "::error::CANARY-COLON-ERROR",
        "##[error]CANARY-LEGACY-ERROR",
        "x ##[notice]CANARY-LEGACY-MIDLINE",
        "  ::notice::CANARY-COLON-LEADING-BLANK",
        "x ##[add-mask]sbxmasklegacy",
        "::add-mask::sbxmaskcolon",
        "::set-output name=sbxout::canary",
        "::set-env name=SBX_SETENV::canary",
        "::stop-commands::sbxcanarytoken",
        "::notice::CANARY-AFTER-STOP-COMMANDS",
        "::sbxcanarytoken::",
    ]
    for line in lines:
        out.write(line + "\n")
    out.write("before-cr\r::notice::CANARY-CR\n")
    out.write("\x1b[31m::notice::CANARY-ESC\x1b[0m\n")
    sys.stderr.write("::notice::CANARY-STDERR\n")
    sys.stderr.flush()
    out.flush()
    pid = os.fork()
    if pid == 0:
        time.sleep(0.3)
        os.write(1, b"::notice::CANARY-LATE-CHILD\n")
        os._exit(0)
    time.sleep(0.1)
    out.write("::notice::CANARY-NO-FINAL-NEWLINE")
    out.flush()


if __name__ == "__main__":
    main()
