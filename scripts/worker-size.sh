#!/usr/bin/env bash
# Prints the size of the session worker program by its largest parts, so that its growth is seen at
# each run of scripts/performance.sh and not when the idle memory figure crosses its bound.
#
# Every idle session runs one worker, all of them mapping the same program, so a megabyte more
# resident code in it is twenty megabytes more in the sum of the processes' resident sizes. This
# reads the program's section table and its symbol table with the binutils a Linux host has, and
# prints the sections that hold the most and, for the code, the read-only data, the writable data and
# the weak symbols (which `nm` does not say are code or data), the crates that the largest parts come
# from (the first path segment of a symbol's name; a symbol written in C is named by its prefix).
#
# usage: scripts/worker-size.sh [program] [crates]
#   program  the worker program (default: the release build's, in CARGO_TARGET_DIR or target)
#   crates   how many crates to name for each kind of content (default 8)
#
# It reads a program and writes to standard output, and a host without the tools prints that it
# recorded nothing: a size record that stopped a measurement would be worse than none.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
program="${1:-${CARGO_TARGET_DIR:-$root/target}/release/kr-worker}"
count="${2:-8}"

if [ "$(uname -s)" != Linux ] || ! command -v nm >/dev/null 2>&1 || ! command -v size >/dev/null 2>&1; then
  echo "  worker size       not recorded on this host: it reads the program with GNU binutils"
  exit 0
fi
if [ ! -f "$program" ]; then
  echo "  worker size       not recorded: there is no program at $program"
  exit 0
fi

kib() { awk -v bytes="$1" 'BEGIN { printf "%d", bytes / 1024 }'; }

file_bytes="$(wc -c < "$program" | tr -d ' ')"
sections="$(size -A "$program" | awk '$1 ~ /^\./ && $2 + 0 >= 262144 { print $2, $1 }' | sort -nr |
  awk '{ printf "%s %d KiB, ", $2, $1 / 1024 }' | sed 's/, $//')"
echo "  worker size       $(kib "$file_bytes") KiB on disk; sections of 256 KiB or more, largest first: ${sections:-none}"

# One line for each kind of content: the crates with the most bytes, from the symbol table. The
# demangled name's first path segment names the crate; a name with no path is a C symbol or an
# unnamed one.
nm --demangle --print-size --radix=d "$program" 2>/dev/null | awk -v count="$count" '
  function crate(name,    first) {
    sub(/^[<&]+/, "", name)
    sub(/^(dyn|mut|const|unsafe|extern) +/, "", name)
    if (name ~ /^\[/ || name ~ /^\(/) return "(slices and tuples of the standard library)"
    if (name ~ /::/) {
      first = name
      sub(/::.*/, "", first)
      sub(/ .*/, "", first)
      sub(/<.*/, "", first)
      return first
    }
    if (name ~ /^sqlite3/) return "sqlite (C)"
    if (name ~ /^(_|anon)/) return "(unnamed)"
    return "(other)"
  }
  NF >= 4 {
    size = $2 + 0
    kind = $3
    if (kind == "t" || kind == "T") group = "code"
    else if (kind == "r" || kind == "R") group = "read-only data"
    else if (kind == "d" || kind == "D") group = "writable data"
    else if (kind == "v" || kind == "V" || kind == "w" || kind == "W") group = "weak symbols"
    else next
    name = $0
    sub(/^[0-9]+ [0-9]+ [A-Za-z] /, "", name)
    by[group SUBSEP crate(name)] += size
    total[group] += size
    seen = 1
  }
  END {
    if (seen == 0) {
      print "  worker size       not recorded: the program has no symbol table to read"
      exit
    }
    n = split("code|read-only data|writable data|weak symbols", groups, "|")
    for (g = 1; g <= n; g++) {
      group = groups[g]
      if (total[group] + 0 < 1024) continue
      m = 0
      for (key in by) {
        split(key, parts, SUBSEP)
        if (parts[1] == group) { names[++m] = parts[2]; sizes[parts[2]] = by[key] }
      }
      # Selection of the largest, since awk has no sort that keeps the pairs together.
      line = sprintf("  worker %-14s %d KiB by symbols; largest crates:", group, total[group] / 1024)
      for (shown = 0; shown < count && m > 0; shown++) {
        best = 1
        for (i = 2; i <= m; i++) if (sizes[names[i]] > sizes[names[best]]) best = i
        line = line sprintf("%s %s %d KiB", shown ? "," : "", names[best], sizes[names[best]] / 1024)
        names[best] = names[m]; m--
      }
      print line
      delete names; delete sizes
    }
  }'
exit 0
