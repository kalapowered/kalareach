#!/bin/bash
# set-up.sh <file> [status]: makes the file that a test reads, and ends with the status.
set -eu
printf 'made by the set-up step\n' > "$1"
exit "${2:-0}"
