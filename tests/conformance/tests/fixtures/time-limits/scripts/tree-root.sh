#!/bin/bash
# tree-root.sh <file>: ignores the signal that asks a process to end, records its pid in the file,
# and starts tree-child.sh, which ignores it too.
trap '' TERM
printf '%s\n' "$$" >> "$1"
bash "$(dirname "$0")/tree-child.sh" "$1" &
wait
