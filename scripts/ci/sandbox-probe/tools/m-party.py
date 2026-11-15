#!/usr/bin/python3
"""Group M's party. usage: m-party.py PORT LOG ADDRESS...

Answers on PORT at each address, TCP and UDP, and writes one line to LOG for each connection
(`TCP <address>`) and each datagram (`UDP <address> <first 12 bytes>`), then `READY` once every socket
is bound. Ends on SIGTERM.
"""
import signal
import socket
import sys
import threading

lock = threading.Lock()


def serve_tcp(sock, address, log):
    while True:
        conn, _ = sock.accept()
        conn.close()
        with lock:
            log.write("TCP %s\n" % address)
            log.flush()


def serve_udp(sock, address, log):
    while True:
        data, _ = sock.recvfrom(64)
        text = "".join(chr(b) if 33 <= b < 127 else "?" for b in data[:12])
        with lock:
            log.write("UDP %s %s\n" % (address, text))
            log.flush()


def main():
    port, path, addresses = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
    log = open(path, "w")
    for address in addresses:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind((address, port))
        tcp.listen(8)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind((address, port))
        threading.Thread(target=serve_tcp, args=(tcp, address, log), daemon=True).start()
        threading.Thread(target=serve_udp, args=(udp, address, log), daemon=True).start()
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    with lock:
        log.write("READY\n")
        log.flush()
    signal.pause()


main()
