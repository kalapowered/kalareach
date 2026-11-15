#!/usr/bin/python3
"""Network probes run inside units (and by the runner as controls).

net.py check TARGET...   one line per target: RESULT <target> reached|blocked <detail>
net.py ifaces            interfaces and addresses of the caller's own namespace
net.py dns NAME          RESULT dns:<name> reached|blocked <detail>

TARGET is tcp:HOST:PORT, udp:HOST:PORT or unix:PATH (a leading @ is an abstract name). A TCP
target counts as reached when the connection is made; a UDP target when an answer comes back
(a DNS query when the port is 53). The timeout is 2 seconds a target.
"""
import errno
import os
import socket
import sys
import time

TIMEOUT = 2.0
DNS_QUERY = bytes.fromhex("1234010000010000000000000667697468756203636f6d0000010001")


def name_of(exc):
    if isinstance(exc, socket.timeout) or getattr(exc, "errno", None) is None:
        return type(exc).__name__
    return errno.errorcode.get(exc.errno, str(exc.errno))


def split(target):
    kind, rest = target.split(":", 1)
    if kind == "unix":
        return kind, rest, None
    host, port = rest.rsplit(":", 1)
    return kind, host.strip("[]"), int(port)


def check_tcp(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        s.connect((host, port))
    return "connected"


def check_udp(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(TIMEOUT)
        s.connect((host, port))
        s.send(DNS_QUERY if port == 53 else b"ping\n")
        data = s.recv(512)
    return "answer=%d" % len(data)


def check_unix(path):
    if path.startswith("@"):
        path = "\0" + path[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(TIMEOUT)
        s.connect(path)
        s.sendall(b"ping\n")
        data = s.recv(16)
    return "answer=%d" % len(data)


def run_check(target):
    kind, host, port = split(target)
    try:
        if kind == "tcp":
            detail = check_tcp(host, port)
        elif kind == "udp":
            detail = check_udp(host, port)
        elif kind == "unix":
            detail = check_unix(host)
        else:
            raise ValueError("kind " + kind)
        print("RESULT %s reached %s" % (target, detail), flush=True)
        return True
    except (OSError, ValueError) as exc:
        print("RESULT %s blocked %s" % (target, name_of(exc)), flush=True)
        return False


def ifaces():
    with open("/proc/self/net/dev") as f:
        names = [line.split(":")[0].strip() for line in f.readlines()[2:]]
    print("RESULT ifaces %s" % " ".join(names))
    with open("/proc/self/net/if_inet6") as f:
        for line in f:
            parts = line.split()
            print("RESULT inet6 %s %s" % (parts[-1], parts[0]))
    print("RESULT netns %s" % os.readlink("/proc/self/ns/net"))


def dns(name):
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo(name, 443)
        print("RESULT dns:%s reached resolved" % name)
    except OSError as exc:
        print("RESULT dns:%s blocked %s" % (name, name_of(exc)))


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "check":
        for target in sys.argv[2:]:
            run_check(target)
    elif len(sys.argv) == 2 and sys.argv[1] == "ifaces":
        ifaces()
    elif len(sys.argv) == 3 and sys.argv[1] == "dns":
        dns(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
