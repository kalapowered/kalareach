#!/bin/bash
# scratch.sh <directory> <file>: writes into the directory and records its path in the file.
set -eu
test -d "$1"
printf 'x\n' > "$1/file"
printf '%s\n' "$1" > "$2"
