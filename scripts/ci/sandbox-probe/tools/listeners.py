#!/usr/bin/python3
"""Canary listeners of the runner's host, for the "unreachable from a unit" probes.

listeners.py PIDFILE   run as root: listen, answer "pong" to everything, until it is stopped

TCP 127.0.0.1:18443, 127.0.0.2:18444 and 0.0.0.0:18445; the abstract Unix name @sbx-abstract;
Unix path sockets in /run, /tmp, /var, /opt, /srv and /var/tmp (mode 0777, so that visibility,
not a permission, is what a unit would need). A unit that is meant to be cut off must reach
none of them; the runner's own connection to each one is the control.
"""
import os
import socket
import sys
import threading

TCP = [("127.0.0.1", 18443), ("127.0.0.2", 18444), ("0.0.0.0", 18445)]
PATHS = [
    "/run/sbx-canary.sock",
    "/tmp/sbx-canary.sock",
    "/var/sbx-canary.sock",
    "/opt/sbx-canary.sock",
    "/srv/sbx-canary.sock",
    "/var/tmp/sbx-canary.sock",
]


def answer(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            conn.settimeout(1)
            try:
                conn.recv(64)
            except OSError:
                pass
            conn.sendall(b"pong\n")
        except OSError:
            pass
        finally:
            conn.close()


def start(sock):
    sock.listen(8)
    threading.Thread(target=answer, args=(sock,), daemon=True).start()


def main():
    pidfile = sys.argv[1]
    for host, port in TCP:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        start(s)
        print("listening tcp:%s:%d" % (host, port), flush=True)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind("\0sbx-abstract")
    start(s)
    print("listening unix:@sbx-abstract", flush=True)
    for path in PATHS:
        if os.path.exists(path):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        os.chmod(path, 0o777)
        start(s)
        print("listening unix:%s" % path, flush=True)
    with open(pidfile, "w") as f:
        f.write("%d\n" % os.getpid())
    print("ready", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
