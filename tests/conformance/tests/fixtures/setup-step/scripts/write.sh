#!/bin/bash
# write.sh <file>: writes the file it is given.
set -eu
printf 'written\n' > "$1"
