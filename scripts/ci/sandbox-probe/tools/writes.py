#!/usr/bin/python3
"""Write probes run inside units.

writes.py try PATH...        for each PATH: write a file (a directory: make a file in it)
writes.py absent PATH...     for each PATH: RESULT absent PATH yes|no (the path exists in the unit)
writes.py setuid DIR         copy /usr/bin/id into DIR and try to make it setuid
writes.py hardlink A_DIR B_DIR   hard link a file of A_DIR into B_DIR (two binds)
writes.py fixtures DIR       a symbolic link, a FIFO, a socket and a newline name, one folder each
writes.py list               every writable file or folder, by the mount it is on
writes.py mark PATH          make PATH with the text "unit-wrote-this"
writes.py see PATH...        RESULT see PATH present|absent for each PATH
"""
import errno
import os
import socket
import subprocess
import sys


def name_of(exc):
    return errno.errorcode.get(exc.errno, "ERR%s" % exc.errno)


def write_one(path):
    target = path
    if os.path.isdir(path):
        target = os.path.join(path, "sbx-write-test")
    try:
        with open(target, "w") as f:
            f.write("x")
        os.unlink(target)
        return "ok"
    except OSError as exc:
        return name_of(exc)


def mounts():
    out = []
    with open("/proc/self/mountinfo") as f:
        for line in f:
            left, _, right = line.partition(" - ")
            fields = left.split()
            point = fields[4].replace("\\040", " ")
            options = fields[5].split(",")
            fstype = right.split()[0]
            out.append((point, fstype, "ro" in options))
    return out


def which_mount(path, table):
    best = ("/", "?", False)
    for point, fstype, ro in table:
        if path == point or path.startswith(point.rstrip("/") + "/"):
            if len(point) >= len(best[0]):
                best = (point, fstype, ro)
    return best


def list_writable():
    table = mounts()
    found = subprocess.run(
        ["/usr/bin/find", "/", "-path", "/proc", "-prune", "-o", "-path", "/sys", "-prune", "-o",
         "(", "-type", "d", "-o", "-type", "f", ")", "-writable", "-print"],
        capture_output=True, text=True, errors="replace",
    ).stdout.splitlines()
    summary = {}
    for path in found:
        point, fstype, _ = which_mount(path, table)
        summary.setdefault((point, fstype), 0)
        summary[(point, fstype)] += 1
    for (point, fstype), count in sorted(summary.items()):
        print("RESULT writable mount=%s fstype=%s count=%d" % (point, fstype, count))
    print("RESULT writable-total %d" % len(found))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    args = sys.argv[2:]
    if mode == "try":
        for path in args:
            print("RESULT write %s %s" % (path, write_one(path)), flush=True)
    elif mode == "absent":
        for path in args:
            print("RESULT absent %s %s" % (path, "no" if os.path.lexists(path) else "yes"), flush=True)
    elif mode == "setuid":
        dest = os.path.join(args[0], "id-copy")
        with open("/usr/bin/id", "rb") as src, open(dest, "wb") as out:
            out.write(src.read())
        os.chmod(dest, 0o755)
        try:
            os.chmod(dest, 0o4755)
            mode_now = oct(os.stat(dest).st_mode & 0o7777)
            print("RESULT setuid chmod-accepted mode=%s" % mode_now)
        except OSError as exc:
            print("RESULT setuid chmod-refused %s" % name_of(exc))
    elif mode == "hardlink":
        src = os.path.join(args[0], "link-source")
        with open(src, "w") as f:
            f.write("x")
        try:
            os.link(src, os.path.join(args[1], "link-dest"))
            print("RESULT hardlink linked")
        except OSError as exc:
            print("RESULT hardlink %s" % name_of(exc))
    elif mode == "fixtures":
        base = args[0]
        for sub in ("link", "fifo", "sock", "newline", "clean"):
            os.makedirs(os.path.join(base, sub), exist_ok=True)
        os.symlink("/etc/passwd", os.path.join(base, "link", "a-link"))
        os.mkfifo(os.path.join(base, "fifo", "a-fifo"))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(base, "sock", "a-sock"))
        s.close()
        with open(os.path.join(base, "newline", "a\nb"), "w") as f:
            f.write("x")
        with open(os.path.join(base, "clean", "file"), "w") as f:
            f.write("x")
        print("RESULT fixtures made")
    elif mode == "list":
        list_writable()
    elif mode == "mark":
        with open(args[0], "w") as f:
            f.write("unit-wrote-this")
        print("RESULT mark %s" % args[0])
    elif mode == "see":
        for path in args:
            print("RESULT see %s %s" % (path, "present" if os.path.lexists(path) else "absent"))
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
