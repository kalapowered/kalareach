#!/usr/bin/python3
"""Compares the properties that run-unit.sh --dry-run lists with what `systemctl show` echoes.

propcheck.py EXPECTED SHOWN

EXPECTED has lines "PROPERTY Name=Value"; SHOWN is the output of `systemctl show UNIT`.
Prints one tab-separated line per property: ok|FAIL, the name, the detail. A list property
matches when its words are the same set (after the manager's own spelling, such as the time
properties' names and the address filter's prefix lengths).
"""
import re
import sys

TIME_ALIAS = {"RuntimeMaxSec": "RuntimeMaxUSec", "TimeoutStopSec": "TimeoutStopUSec"}
LIST = {
    "SystemCallFilter", "RestrictAddressFamilies", "TemporaryFileSystem", "InaccessiblePaths",
    "BindPaths", "BindReadOnlyPaths", "IPAddressDeny", "IPAddressAllow", "Environment",
}
UNITS = {"us": 1, "ms": 1000, "s": 10**6, "min": 60 * 10**6, "h": 3600 * 10**6, "d": 86400 * 10**6}


def micros(text):
    total = 0
    for number, unit in re.findall(r"([0-9.]+)\s*(us|ms|min|s|h|d)", text):
        total += int(float(number) * UNITS[unit])
    return total


def words(name, value):
    value = value.replace("any", "0.0.0.0/0 ::/0") if name == "IPAddressDeny" else value
    out = set()
    for w in value.split():
        w = w.lstrip("~")
        if name.startswith("IPAddress"):
            w = re.sub(r"/(32|128)$", "", w)
        if name.startswith("Bind"):
            w = w.split(":")[0]
        if w:
            out.add(w)
    return out


def main():
    expected = {}
    order = []
    for line in open(sys.argv[1]):
        if not line.startswith("PROPERTY "):
            continue
        name, _, value = line[9:].rstrip("\n").partition("=")
        if name not in expected:
            order.append(name)
            expected[name] = []
        expected[name].append(value)
    shown = {}
    for line in open(sys.argv[2]):
        name, _, value = line.rstrip("\n").partition("=")
        shown.setdefault(name, value)
    for name in order:
        want = expected[name]
        key = TIME_ALIAS.get(name, name)
        if key not in shown:
            print("FAIL\t%s\tnot echoed by systemctl show" % name)
            continue
        got = shown[key]
        if name in TIME_ALIAS:
            good = micros(got) == int(want[0]) * 10**6
        elif name in LIST:
            wanted = set()
            for v in want:
                wanted |= words(name, v)
            good = wanted == words(name, got)
        else:
            good = got == want[0]
        print("%s\t%s\twanted=%s shown=%s" % ("ok" if good else "FAIL", name, " | ".join(want)[:200], got[:200]))


if __name__ == "__main__":
    main()
