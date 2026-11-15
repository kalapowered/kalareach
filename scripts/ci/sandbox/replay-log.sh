#!/bin/bash
# replay-log.sh FILE PREFIX [FILE PREFIX]...
#
# Prints the output that a transient unit wrote to each FILE, after the unit has ended, all
# inside one bracket. Nothing in a file can act as a workflow command: every line gets a fixed, non-blank prefix, every
# byte outside printable ASCII (carriage return, escape, tab, anything above 126) becomes "?",
# and the whole text sits inside a stop-commands bracket whose token is made here, after the
# writers have stopped, so no writer could have known it. Both command forms ("::name::" and
# "##[name]") are stopped by the bracket and made inert by the prefix.
set -u

[ "$#" -ge 2 ] && [ $(($# % 2)) -eq 0 ] || { echo "usage: replay-log.sh FILE PREFIX [FILE PREFIX]..." >&2; exit 2; }
args=("$@")
for ((i = 0; i < ${#args[@]}; i += 2)); do
  case ${args[i + 1]} in
    '' | *[!A-Za-z0-9._-]*) echo "replay-log: the prefix must match [A-Za-z0-9._-]+" >&2; exit 2 ;;
  esac
done

# The token is made after the unit ended. 24 random bytes, hexadecimal, read by one command.
hex=$(od -An -N24 -tx1 /dev/urandom) || { echo "replay-log: no token" >&2; exit 1; }
token=${hex//[[:space:]]/}
[ "${#token}" -eq 48 ] || { echo "replay-log: no token" >&2; exit 1; }

printf '::stop-commands::%s\n' "$token"
for ((i = 0; i < ${#args[@]}; i += 2)); do
  file=${args[i]}
  prefix=${args[i + 1]}
  if [ ! -f "$file" ] || [ -L "$file" ]; then
    echo "${prefix} | (no regular file to replay)"
    continue
  fi
  # At most 4 MiB a file. The last sed command ("$a\" with no text) ends a last line that has
  # no newline, so the next line, and the closing token, always start a line of their own. It
  # must come last: GNU sed reads the next -e as the text to append.
  LC_ALL=C head -c 4194304 -- "$file" |
    LC_ALL=C tr -c '\12\40-\176' '?' |
    LC_ALL=C sed -e "s/^/${prefix} | /" -e '$a\'
done
printf '::%s::\n' "$token"
