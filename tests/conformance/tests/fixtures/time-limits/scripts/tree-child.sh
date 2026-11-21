#!/bin/bash
# tree-child.sh <file>: ignores the signal that asks a process to end, records its pid and its
# child's in the file, and waits with `sleep`: 61 s, so that it ends by itself.
trap '' TERM
printf '%s\n' "$$" >> "$1"
sleep 61 &
printf '%s\n' "$!" >> "$1"
wait
