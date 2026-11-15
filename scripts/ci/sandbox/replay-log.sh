#!/bin/bash
# replay-log.sh FILE PREFIX
#
# Prints the output that a transient unit wrote to FILE, after the unit has ended. Nothing in
# the file can act as a workflow command: every line gets a fixed, non-blank prefix, every
# byte outside printable ASCII (carriage return, escape, tab, anything above 126) becomes "?",
# and the whole text sits inside a stop-commands bracket whose token is made here, after the
# writers have stopped, so no writer could have known it. Both command forms ("::name::" and
# "##[name]") are stopped by the bracket and made inert by the prefix.
set -u

[ "$#" -eq 2 ] || { echo "usage: replay-log.sh FILE PREFIX" >&2; exit 2; }
file=$1
prefix=$2
case $prefix in
  '' | *[!A-Za-z0-9._-]*) echo "replay-log: the prefix must match [A-Za-z0-9._-]+" >&2; exit 2 ;;
esac
if [ ! -f "$file" ] || [ -L "$file" ]; then
  echo "replay-log: $prefix: no regular file to replay" >&2
  exit 1
fi

# The token is made after the unit ended. 24 random bytes, hexadecimal.
token=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
[ "${#token}" -eq 48 ] || { echo "replay-log: no token" >&2; exit 1; }

printf '::stop-commands::%s\n' "$token"
# At most 4 MiB. "sed '$a\'" ends a last line that has no newline, so the closing token always
# starts a line of its own.
LC_ALL=C head -c 4194304 -- "$file" |
  LC_ALL=C tr -c '\12\40-\176' '?' |
  LC_ALL=C sed -e '$a\' -e "s/^/${prefix} | /"
printf '::%s::\n' "$token"
