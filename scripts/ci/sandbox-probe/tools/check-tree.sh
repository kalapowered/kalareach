#!/bin/bash
# check-tree.sh DIR OWNER
#
# The check that a tree an account wrote is safe to hand back: nothing but regular files and
# folders, no name with a newline, every entry owned by OWNER, and the scan itself must succeed.
# Prints what it refuses and exits 1 on any of it. Names are read NUL-separated and never
# printed as they are.
set -u
dir=${1:?directory}
owner=${2:?owner}

bad=$(mktemp)
trap 'rm -f -- "$bad"' EXIT
# -P: never follow a link. The first test lists everything that is neither a file nor a folder
# (links, FIFOs, sockets, devices); the second lists entries of another owner.
if ! find -P "$dir" \( ! -type f ! -type d \) -print0 >"$bad.special" 2>"$bad.err"; then
  echo "check-tree: the scan failed" >&2
  exit 1
fi
find -P "$dir" ! -user "$owner" -print0 >"$bad.owner" 2>>"$bad.err" || { echo "check-tree: the owner scan failed" >&2; exit 1; }
find -P "$dir" -name '*
*' -print0 >"$bad.newline" 2>>"$bad.err" || { echo "check-tree: the newline scan failed" >&2; exit 1; }
status=0
for kind in special owner newline; do
  n=$(tr -cd '\0' <"$bad.$kind" | wc -c)
  if [ "$n" -gt 0 ]; then
    echo "check-tree: refused: $n entries ($kind)"
    status=1
  fi
done
rm -f -- "$bad.special" "$bad.owner" "$bad.newline" "$bad.err"
exit "$status"
