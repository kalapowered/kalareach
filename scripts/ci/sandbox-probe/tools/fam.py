#!/usr/bin/python3
"""Socket families and io_uring, run inside units and by the runner as a control.

fam.py families   one line per family: RESULT fam NAME allowed|refused ERRNO
fam.py uring      RESULT uring ok|<errno name>   (io_uring_setup, syscall 425 on x86-64 and arm64)
"""
import ctypes
import errno
import socket
import sys

# (name, number, socket types to try). Numbers are written out: the library lacks some names.
FAMILIES = [
    ("AF_UNIX", 1, [socket.SOCK_STREAM]),
    ("AF_INET", 2, [socket.SOCK_STREAM]),
    ("AF_INET6", 10, [socket.SOCK_STREAM]),
    ("AF_NETLINK", 16, [socket.SOCK_RAW]),
    ("AF_PACKET", 17, [socket.SOCK_RAW, socket.SOCK_DGRAM]),
    ("AF_RDS", 21, [socket.SOCK_SEQPACKET]),
    ("AF_TIPC", 30, [socket.SOCK_STREAM, socket.SOCK_RDM, socket.SOCK_DGRAM]),
    ("AF_RXRPC", 33, [socket.SOCK_DGRAM]),
    ("AF_ALG", 38, [socket.SOCK_SEQPACKET]),
    ("AF_VSOCK", 40, [socket.SOCK_STREAM, socket.SOCK_DGRAM]),
    ("AF_KCM", 41, [socket.SOCK_DGRAM, socket.SOCK_SEQPACKET]),
    ("AF_SMC", 43, [socket.SOCK_STREAM]),
]


def families():
    for name, number, types in FAMILIES:
        seen = []
        verdict = "refused"
        for kind in types:
            try:
                proto = 0
                if name == "AF_NETLINK":
                    proto = 0  # NETLINK_ROUTE
                s = socket.socket(number, kind, proto)
                s.close()
                verdict = "allowed"
                seen.append("ok")
                break
            except OSError as exc:
                seen.append(errno.errorcode.get(exc.errno, str(exc.errno)))
        print("RESULT fam %s %s %s" % (name, verdict, ",".join(seen)), flush=True)


def uring():
    libc = ctypes.CDLL(None, use_errno=True)
    params = ctypes.create_string_buffer(120)
    fd = libc.syscall(425, 4, params)
    if fd >= 0:
        print("RESULT uring ok fd")
    else:
        print("RESULT uring %s" % errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno())))


if __name__ == "__main__":
    if sys.argv[1:] == ["families"]:
        families()
    elif sys.argv[1:] == ["uring"]:
        uring()
    else:
        print(__doc__)
        sys.exit(2)
