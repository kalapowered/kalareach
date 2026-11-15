#!/usr/bin/python3
"""Process-lifetime fixtures run inside units.

life.py spawn DIR       a double-forked, detached child and a child that ignores SIGTERM; the
                        main process writes their pids to DIR/grand.pid and DIR/ignore.pid and exits
life.py ignore          the main process ignores SIGTERM and sleeps
life.py helper DIR      like a starter that leaves a detached server and exits: one detached
                        child sleeping, its pid in DIR/helper.pid, the main process exits 0
life.py crash           ends itself with SIGSEGV
"""
import os
import signal
import sys
import time


def write_pid(path, pid):
    with open(path, "w") as f:
        f.write("%d\n" % pid)


def detach_and_sleep(pidfile, ignore_term=False):
    """Fork; the child becomes a session leader, forks again, the grandchild sleeps."""
    child = os.fork()
    if child:
        os.waitpid(child, 0)
        return
    os.setsid()
    if os.fork():
        os._exit(0)
    if ignore_term:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    devnull = os.open("/dev/null", os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(devnull, fd)
    write_pid(pidfile, os.getpid())
    time.sleep(600)
    os._exit(0)


def spawn(directory):
    detach_and_sleep(os.path.join(directory, "grand.pid"))
    pid = os.fork()
    if pid == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        write_pid(os.path.join(directory, "ignore.pid"), os.getpid())
        time.sleep(600)
        os._exit(0)
    for _ in range(100):
        if all(os.path.exists(os.path.join(directory, n)) for n in ("grand.pid", "ignore.pid")):
            break
        time.sleep(0.1)
    print("RESULT spawn done", flush=True)


def helper(directory):
    detach_and_sleep(os.path.join(directory, "helper.pid"))
    for _ in range(100):
        if os.path.exists(os.path.join(directory, "helper.pid")):
            break
        time.sleep(0.1)
    print("RESULT helper started", flush=True)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "spawn":
        spawn(sys.argv[2])
    elif mode == "ignore":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print("RESULT ignore sleeping", flush=True)
        time.sleep(600)
    elif mode == "helper":
        helper(sys.argv[2])
    elif mode == "crash":
        os.kill(os.getpid(), signal.SIGSEGV)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
