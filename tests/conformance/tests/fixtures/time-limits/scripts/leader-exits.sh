#!/bin/bash
# leader-exits.sh <file>: records its pid in the file, starts tree-child.sh, which ignores the
# signal that asks a process to end, and ends when it is asked to.
printf '%s\n' "$$" >> "$1"
bash "$(dirname "$0")/tree-child.sh" "$1" &
wait
