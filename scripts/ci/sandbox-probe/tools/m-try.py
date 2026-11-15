#!/usr/bin/python3
"""Group M's probe. usage: m-try.py PORT PAYLOAD ADDRESS...

For each address, at once: one TCP connection (opened and closed) and one datagram of PAYLOAD. Prints
`M-RESULT <address> tcp reached|timeout|<errno name>` and `M-RESULT <address> udp sent|<errno name>`.
"""
import errno
import socket
import sys
import threading

BOUND = 3.0


def word(exc):
    if isinstance(exc, socket.timeout):
        return "timeout"
    return errno.errorcode.get(getattr(exc, "errno", None), type(exc).__name__)


def try_tcp(address, port, lines):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(BOUND)
    try:
        sock.connect((address, port))
        lines[(address, "tcp")] = "reached"
    except OSError as exc:
        lines[(address, "tcp")] = word(exc)
    finally:
        sock.close()


def try_udp(address, port, payload, lines):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, (address, port))
        lines[(address, "udp")] = "sent"
    except OSError as exc:
        lines[(address, "udp")] = word(exc)
    finally:
        sock.close()


def main():
    port, payload, addresses = int(sys.argv[1]), sys.argv[2].encode(), sys.argv[3:]
    lines = {}
    threads = []
    for address in addresses:
        threads.append(threading.Thread(target=try_tcp, args=(address, port, lines)))
        threads.append(threading.Thread(target=try_udp, args=(address, port, payload, lines)))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for address in addresses:
        for kind in ("tcp", "udp"):
            print("M-RESULT %s %s %s" % (address, kind, lines.get((address, kind), "none")), flush=True)


main()
