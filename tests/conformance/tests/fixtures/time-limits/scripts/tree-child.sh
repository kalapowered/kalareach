#!/bin/bash
# tree-child.sh <file>: ignores the signal that asks a process to end, records its pid and its
# child's in the file, and waits with `sleep`.
trap '' TERM
printf '%s\n' "$$" >> "$1"
sleep 300 &
printf '%s\n' "$!" >> "$1"
wait
