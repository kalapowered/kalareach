#!/usr/bin/python3
"""A small TCP service for the reach probes, and its client.

echo.py serve PORT...        listen on 127.0.0.1:PORT for each PORT; runs until it is stopped
echo.py line PORT NONCE [IDLE]   connect, wait IDLE seconds, send "line NONCE", print the reply
echo.py eof PORT NONCE       connect, send "eof NONCE", half-close, print the reply and the end

A "line" request is answered at once ("svc-PORT NONCE-reversed") and the connection stays open;
an "eof" request is read to the end of the stream (the client's half-close) and then answered
("svc-PORT eof NONCE bytes=N") and closed.
"""
import socket
import sys
import threading
import time


def handle(conn, port):
    with conn:
        data = b""
        while b"\n" not in data and not data.startswith(b"eof "):
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk
        if data.startswith(b"line "):
            nonce = data.split(b"\n", 1)[0][5:].decode("ascii", "replace")
            conn.sendall(("svc-%d %s\n" % (port, nonce[::-1])).encode())
        elif data.startswith(b"eof "):
            total = len(data)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
            nonce = data.split(b"\n", 1)[0][4:].decode("ascii", "replace")
            conn.sendall(("svc-%d eof %s bytes=%d\n" % (port, nonce, total)).encode())


def serve(ports):
    listeners = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(16)
        listeners.append((s, port))

    def accept_loop(s, port):
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle, args=(conn, port), daemon=True).start()

    for s, port in listeners:
        threading.Thread(target=accept_loop, args=(s, port), daemon=True).start()
    print("RESULT serve listening %s" % " ".join(str(p) for p in ports), flush=True)
    while True:
        time.sleep(3600)


def client(mode, port, nonce, idle):
    with socket.create_connection(("127.0.0.1", port), timeout=20) as s:
        s.settimeout(90)
        if idle:
            time.sleep(idle)
        if mode == "line":
            s.sendall(("line %s\n" % nonce).encode())
        else:
            s.sendall(("eof %s\n" % nonce).encode())
            s.shutdown(socket.SHUT_WR)
        reply = b""
        while not reply.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
        print("RESULT reply %s" % reply.decode("ascii", "replace").strip(), flush=True)
        if mode == "eof":
            end = s.recv(4096)
            print("RESULT end %s" % ("closed" if end == b"" else "more-data"), flush=True)


def main():
    argv = sys.argv[1:]
    if len(argv) >= 2 and argv[0] == "serve":
        serve([int(p) for p in argv[1:]])
    elif len(argv) >= 3 and argv[0] in ("line", "eof"):
        client(argv[0], int(argv[1]), argv[2], float(argv[3]) if len(argv) > 3 else 0)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    try:
        main()
    except OSError as exc:
        print("RESULT error %s" % exc.__class__.__name__)
        sys.exit(1)
