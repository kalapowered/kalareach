#!/usr/bin/python3
"""What a unit inherited, printed as names and numbers (never the value of a variable).

inherit.py [PID...]   PIDs of the runner's processes whose /proc entries must be closed to the unit
"""
import errno
import os
import re
import sys


def main():
    print("RESULT cwd %s" % os.getcwd())
    names = sorted(os.environ)
    print("RESULT envnames %s" % " ".join(names))
    bad = [n for n in names if re.match(r"(GITHUB_|ACTIONS_|RUNNER_|SBX_|CI$|ImageOS|ImageVersion)", n)]
    print("RESULT envbad %s" % (" ".join(bad) if bad else "none"))
    fds = []
    for name in os.listdir("/proc/self/fd"):
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except OSError:
            continue
        if target.startswith("/proc/"):
            continue  # the directory listing's own descriptor
        fds.append(int(name))
    print("RESULT fds %s" % " ".join(str(f) for f in sorted(fds)))
    with open("/proc/self/status") as f:
        status = f.read()
    for key in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp"):
        match = re.search(r"^%s:\s*(\S+)" % key, status, re.M)
        print("RESULT %s %s" % (key, match.group(1) if match else "missing"))
    print("RESULT ids uid=%d gid=%d groups=%s ppid=%d" % (os.getuid(), os.getgid(), ",".join(str(g) for g in os.getgroups()), os.getppid()))
    # The runner's processes: nothing of theirs may be readable.
    for pid in sys.argv[1:]:
        for entry in ("environ", "mem", "fd", "root", "cmdline", "maps"):
            path = "/proc/%s/%s" % (pid, entry)
            try:
                if entry == "fd":
                    os.listdir(path)
                else:
                    open(path, "rb").read(1)
                verdict = "READABLE"
            except OSError as exc:
                verdict = errno.errorcode.get(exc.errno, str(exc.errno))
            print("RESULT proc %s %s" % (entry, verdict))
    print("RESULT done")


if __name__ == "__main__":
    main()
