#!/usr/bin/env python3
"""Reads a `uiautomator dump` of the screen.

    ui-node.py center <dump.xml> <label>   prints "<x> <y>" for the centre of the clickable node whose
                                          text or description is exactly <label>, or nothing
    ui-node.py at <dump.xml> <label>      prints "<x> <y>" for the centre of the node, clickable or not,
                                          whose text or description is exactly <label>, or nothing
    ui-node.py has <dump.xml> <text>      exits 0 when a node's text or description holds <text>
    ui-node.py ids <dump.xml> <text>      prints the resource id of each node whose text or description
                                          holds <text>

The system's own screens (the lock screen, its notifications and the unlock prompt) are in the dump,
so the device script reads what the person would see and taps where the person would tap.
"""
import re
import sys
import xml.etree.ElementTree as ET


def nodes(path):
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return []
    return list(tree.iter("node"))


def words(node):
    return [node.get("text") or "", node.get("content-desc") or ""]


def centre(node):
    found = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", node.get("bounds") or "")
    if not found:
        return None
    left, top, right, bottom = (int(each) for each in found.groups())
    return (left + right) // 2, (top + bottom) // 2


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("center", "at", "has", "ids"):
        print(__doc__, file=sys.stderr)
        return 2
    verb, path, wanted = sys.argv[1:4]
    every = nodes(path)
    if verb == "has":
        return 0 if any(wanted in each for node in every for each in words(node)) else 1
    if verb == "ids":
        for node in every:
            if any(wanted in each for each in words(node)):
                print(node.get("resource-id") or "")
        return 0
    for node in every:
        if (verb == "at" or node.get("clickable") == "true") and wanted in words(node):
            point = centre(node)
            if point:
                print("%d %d" % point)
                return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
