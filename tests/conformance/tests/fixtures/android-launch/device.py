#!/usr/bin/env python3
"""An Android device for scripts/android-app-launch.sh to run on, made of two programs in one file.

As `adb` it answers the calls the script makes the way a booted device with the application
installed answers them. As `device.py serve` it is the web view's debugging endpoint: the page
list, and a WebSocket that answers the script's question about the page's root.

The device's state is a directory, named by the environment variable KR_FAKE_DEVICE_DIR for both:

  pid        the application's process number (a file that is absent once the process has ended)
  log        what the device's log holds; an end appends `ending.log` to it
  ending.log the log lines the system wrote as the process ended
  ends       when the process ends: `socket` (right after its debugging socket was found),
             `screen` (right after the screen was read), `log` (right after the log was read for
             a crash) or `never`
  port       the port the debugging endpoint listens on
  format     when present, the screen is in pixel format RGB_565
  unreadable-screens
             a number: that many of the first reads of the screen fail, and `screencap` writes
             the text of its error where the frame would be

The screen is a small raw frame in the shape `screencap` writes it: a header of width, height,
format and colour space, then four bytes a pixel. A frame the picture of which was asked for
through `screencap -p` is a PNG of another size, so a script that takes its picture from a second
look at the screen does not keep the frame it checked.
"""

import base64
import hashlib
import json
import os
import socketserver
import struct
import sys
import time

PACKAGE = "to.kala.reach"
WIDTH, HEIGHT = 64, 128


def state_file(name):
    return os.path.join(os.environ["KR_FAKE_DEVICE_DIR"], name)


def read(name, default=""):
    try:
        with open(state_file(name)) as handle:
            return handle.read()
    except OSError:
        return default


def end_the_process():
    """The process is gone, and the system has logged how."""
    try:
        os.remove(state_file("pid"))
    except OSError:
        pass
    with open(state_file("log"), "a") as log:
        log.write(read("ending.log"))


def nth_call(name):
    """The number of this call among the calls the device counts under `name`, from one."""
    number = int(read("calls-" + name, "0").strip() or 0) + 1
    with open(state_file("calls-" + name), "w") as handle:
        handle.write(str(number))
    return number


def count(name):
    """The number a state file of that name holds, or nought."""
    return int(read(name, "0").strip() or 0)


def ends_at(stage):
    if read("ends").strip() == stage and os.path.exists(state_file("pid")):
        end_the_process()


def frame():
    if os.path.exists(state_file("format")):
        # RGB_565: two bytes a pixel, which a reader of four bytes a pixel cannot take for a picture.
        return struct.pack("<IIII", WIDTH, HEIGHT, 4, 0) + bytes(WIDTH * HEIGHT * 2)
    background = bytes([240, 240, 240, 255])
    block = bytes([20, 20, 20, 255])
    rows = []
    for row in range(HEIGHT):
        line = bytearray(background * WIDTH)
        if HEIGHT // 4 < row < HEIGHT // 2:
            line[4 * (WIDTH // 4) : 4 * (3 * WIDTH // 4)] = block * (WIDTH // 2)
        rows.append(bytes(line))
    return struct.pack("<IIII", WIDTH, HEIGHT, 1, 0) + b"".join(rows)


def a_png_of_another_size():
    return (
        b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89"
        b"\0\0\0\rIDATx\x9cc\xf8\xff\xff?\0\x05\xfe\x02\xfe\xa7\x35\x81\x84\0\0\0\0IEND\xaeB`\x82"
    )


def adb(arguments):
    if arguments[:1] == ["-s"]:
        arguments = arguments[2:]
    command, rest = arguments[0], arguments[1:]
    out = sys.stdout.buffer
    pid = read("pid").strip()
    if command == "devices":
        out.write(b"List of devices attached\nemulator-5554\tdevice\n\n")
    elif command in ("uninstall", "install"):
        out.write(b"Success\n")
    elif command == "logcat" and "-c" in rest:
        open(state_file("log"), "w").close()
    elif command == "logcat":
        out.write(read("log").encode())
        out.flush()
        ends_at("log")
    elif command == "forward" and rest[:1] == ["--remove"]:
        pass
    elif command == "forward":
        deadline = time.monotonic() + 10
        while not read("port").strip() and time.monotonic() < deadline:
            time.sleep(0.1)
        out.write((read("port").strip() + "\n").encode())
    elif command == "exec-out" and rest == ["screencap"]:
        if nth_call("screen") <= count("unreadable-screens"):
            out.write(b"screencap: unable to capture the display (error -22)\n")
            out.flush()
            return
        out.write(frame())
        out.flush()
        ends_at("screen")
    elif command == "exec-out" and rest == ["screencap", "-p"]:
        out.write(a_png_of_another_size())
    elif command == "shell":
        words = " ".join(rest)
        if "sys.boot_completed" in words:
            out.write(b"1\n")
        elif words.startswith("getprop"):
            out.write(b"36\n" if "sdk" in words else b"x86_64,arm64-v8a\n")
        elif words.startswith("am start"):
            out.write(b"Status: ok\nActivity: to.kala.reach/.MainActivity\n")
        elif words.startswith("pidof"):
            if not pid:
                sys.exit(1)
            out.write((pid + "\n").encode())
        elif words.startswith("run-as"):
            out.write(
                f"7000000000-7000200000 r-xp 00000000 fe:00 1 /data/app/{PACKAGE}-1/base.apk\n".encode()
            )
        elif words == "cat /proc/net/unix":
            out.write(f"0: 00000002 0 0 10000 1 0 @webview_devtools_remote_{pid}\n".encode())
            out.flush()
            ends_at("socket")
        elif words == "cat /proc/meminfo":
            out.write(b"MemTotal:        2564080 kB\nMemAvailable:     933648 kB\n")
        else:
            sys.exit(f"adb stand-in: no answer for shell {words}")
    else:
        sys.exit(f"adb stand-in: no answer for {command}")


class Debugging(socketserver.StreamRequestHandler):
    """The page list over HTTP, and the one page's WebSocket."""

    def handle(self):
        request = self.rfile.readline().decode()
        headers = {}
        while True:
            line = self.rfile.readline().decode().strip()
            if not line:
                break
            name, _, value = line.partition(":")
            headers[name.lower()] = value.strip()
        if not os.path.exists(state_file("pid")):
            return
        path = request.split()[1]
        port = self.server.server_address[1]
        if path == "/json":
            page = {
                "type": "page",
                "title": "KalaReach",
                "url": "https://tauri.localhost/",
                "webSocketDebuggerUrl": f"ws://127.0.0.1:{port}/devtools/page/1",
            }
            body = json.dumps([page]).encode()
            self.wfile.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
            return
        accept = base64.b64encode(
            hashlib.sha1((headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        )
        self.wfile.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        )
        while True:
            first, second = self.rfile.read(2)
            length = second & 0x7F
            if length == 126:
                length = struct.unpack(">H", self.rfile.read(2))[0]
            mask = self.rfile.read(4)
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(self.rfile.read(length)))
            if first & 0x0F == 8:
                return
            message = json.loads(payload)
            value = json.dumps({"children": 1, "text": 12})
            answer = json.dumps({"id": message["id"], "result": {"result": {"type": "string", "value": value}}}).encode()
            header = bytes([0x81, len(answer)]) if len(answer) < 126 else bytes([0x81, 126]) + struct.pack(">H", len(answer))
            self.wfile.write(header + answer)
            self.wfile.flush()


def serve():
    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    with Server(("127.0.0.1", 0), Debugging) as server:
        with open(state_file("port"), "w") as handle:
            handle.write(str(server.server_address[1]))
        server.serve_forever()


if __name__ == "__main__":
    if sys.argv[1:2] == ["serve"]:
        serve()
    else:
        adb(sys.argv[1:])
