#!/usr/bin/env bash
# Installs apt packages on a hosted Linux runner whose Ubuntu mirror is slow or failing.
#
#   bash scripts/apt-install.sh [--deadline SECONDS] [--archive DIR] [--names-from SCRIPT] [PACKAGE...]
#
# apt has no minimum transfer rate. A mirror that answers slowly keeps one download going for as
# long as bytes arrive, and the image's timeout and its failover to the next mirror act on a silent
# connection only, so a step that needs 70 to 100 MB can run for an hour at 30 kB/s and then fail
# on a mirror that starts to answer 503. This script puts every call that reaches the network under
# a bound and tries again until its deadline, then installs from the archives it fetched, with no
# network:
#
#   1. `apt-get update`, bound 180 s. A non-zero exit fails the attempt. An exit of 0 that printed
#      `W: Failed to fetch` is what a 503 on an index gives, since apt reports a failed index as a
#      warning: the update runs again, twice at most, after 10 and 20 s, and then the attempt goes
#      on with the indexes it has. The first update of a runner fetches the indexes in full, 37.8 MB
#      from the archive hosts (scripts/ubuntu-archive-hosts.sh): if they arrive at less than about
#      210 kB/s (37.8 MB in 180 s) this bound stops every update, and the step fails at its deadline.
#      No other host is tried: the image's mirror list is not read once the archive hosts are in place.
#   2. With --names-from, the program SCRIPT is run by bash against the indexes just updated and
#      prints one package name per line, which are installed with the PACKAGEs. It runs again in
#      each attempt, after that attempt's last update, so the names match the indexes the download
#      and the install use. A failure of the program ends the script.
#   3. `apt-get install --simulate`, bound 120 s, with no network. A call that the bound cut (status
#      124 or 137) fails the attempt, like a cut update. When the update printed no warning, any
#      other failure is the packages' own (an unknown name, a conflict) and ends the script at
#      once with apt's lines; otherwise the indexes may be the cause and the attempt is retried.
#      With --archive the call is `apt-get install --print-uris` instead, against an empty archive
#      directory, so that it lists every archive the install needs as `FILE SIZE SHA256`; the
#      archives of DIR (a directory a cache step restored) that match the list in name, size and
#      SHA-256 are copied to apt's archive directory, and the others are printed as dropped and
#      fetched again. apt itself accepts a cached archive by its size alone, so a copy that an
#      earlier attempt made and this attempt's list no longer matches is removed first.
#   4. `apt-get install --download-only`, bound by the time left. Exit 0 ends the attempts.
#   A failed attempt prints its number, its status (124 means that a bound cut it) and the last
#   three lines of its output, waits 10 s times its number (at most 60 s, never past the deadline)
#   and starts again, until the deadline.
#   5. `apt-get install --no-download`, once and not under a bound: a package whose archive is
#      missing fails the install and is not fetched. Its status is the script's.
#   6. With --archive, after an install that succeeded, DIR is replaced by a new directory made of
#      the listed archives that apt now holds, each checked again against its SHA-256, and a
#      MANIFEST of their sorted names, sizes and hashes. The new directory is built from the list
#      and never from the old one, so a file that is no longer listed does not stay. When the
#      workflow's cache step is to save it, the script writes `save=true` to $GITHUB_OUTPUT: the
#      manifest's digest is not that of the manifest DIR had when the script began, or a restored
#      archive was dropped, which is a repair. The cache entry's name is the `entry` output, the
#      digest, with a suffix from the run when the entry repairs one, since a cache entry cannot be
#      replaced under its own name.
#
# Every bound is `sudo timeout --kill-after=G T ...`, with `timeout` inside `sudo` so that it can
# signal the root process on every runner image, and G + T equal to the bound, where G is 10 s or,
# for a bound of 10 s or less, the bound less 1 s. A call is never given less than 2 s and never
# given 0, which `timeout` reads as no limit. The last line of the output is the summary.
set -euo pipefail

usage() {
  echo "usage: apt-install.sh [--deadline SECONDS] [--archive DIR] [--names-from SCRIPT] [PACKAGE...]" >&2
  exit 2
}

deadline=1800
archive=
names_from=
packages=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --deadline)
      [ "$#" -ge 2 ] || usage
      deadline=$2
      shift 2
      ;;
    --archive)
      [ "$#" -ge 2 ] && [ -n "$2" ] || usage
      archive=$2
      shift 2
      ;;
    --names-from)
      [ "$#" -ge 2 ] || usage
      names_from=$2
      shift 2
      ;;
    --)
      shift
      while [ "$#" -gt 0 ]; do
        packages+=("$1")
        shift
      done
      ;;
    -*) usage ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done
case "$deadline" in '' | *[!0-9]*) usage ;; esac
[ "$deadline" -ge 2 ] || usage
# The directory is replaced as a whole, so it is a path of its own and never the root.
case "$archive" in '' | /?*) ;; *) usage ;; esac

start=$SECONDS
work=$(mktemp -d)
trap 'sudo rm -rf -- "$work"' EXIT

# The seconds left before the deadline.
remaining() {
  echo $((deadline - (SECONDS - start)))
}

# pause SECONDS: waits, at most 60 s and always leaving a second before the deadline.
pause() {
  local seconds=$1 left
  [ "$seconds" -le 60 ] || seconds=60
  left=$(remaining)
  [ "$seconds" -lt "$left" ] || seconds=$((left - 1))
  if [ "$seconds" -gt 0 ]; then
    echo "apt-install: waiting ${seconds}s"
    sleep "$seconds"
  fi
}

# run_apt BOUND LOG ARGUMENT...: `apt-get ARGUMENT...` as root, ended inside BOUND seconds, its
# output shown and kept in LOG. The status is apt's, or timeout's 124 and 137.
run_apt() {
  local bound=$1 log=$2 grace=10 status=0
  shift 2
  [ "$grace" -lt "$bound" ] || grace=$((bound - 1))
  echo "apt-install: sudo timeout --kill-after=$grace $((bound - grace)) env DEBIAN_FRONTEND=noninteractive apt-get $*"
  sudo timeout --kill-after="$grace" "$((bound - grace))" env DEBIAN_FRONTEND=noninteractive apt-get "$@" 2>&1 | tee "$log" || status=${PIPESTATUS[0]}
  return "$status"
}

# bound_for CAP: the smaller of CAP and the time left, or a failure when under 2 s are left.
bound_for() {
  local cap=$1 left
  left=$(remaining)
  [ "$left" -gt 1 ] || return 1
  if [ "$left" -lt "$cap" ]; then
    echo "$left"
  else
    echo "$cap"
  fi
}

total_warnings=0
last_warnings=0
failed_log=
all=()
listed=$work/listed.txt
: > "$listed"
: > "$work/seeded.txt"
: > "$work/dropped.txt"
cache_dir=
restored_digest=none
fetch_count=0

sha256_of() {
  sha256sum "$1" | cut -d' ' -f1
}

size_of() {
  wc -c < "$1" | tr -d ' '
}

# valid_file SIZE SHA256 PATH: PATH is a regular file of that size with that hash.
valid_file() {
  [ -f "$3" ] && [ ! -L "$3" ] && [ "$(size_of "$3")" = "$1" ] && [ "$(sha256_of "$3")" = "$2" ]
}

# update_indexes: step 1.
update_indexes() {
  local round=0 bound status=0 warnings
  while :; do
    bound=$(bound_for 180) || return 124
    round=$((round + 1))
    if run_apt "$bound" "$work/update.log" update; then
      status=0
    else
      status=$?
    fi
    if [ "$status" -ne 0 ]; then
      failed_log=$work/update.log
      return "$status"
    fi
    warnings=$(grep -c '^W: Failed to fetch' "$work/update.log" || true)
    last_warnings=$warnings
    total_warnings=$((total_warnings + warnings))
    if [ "$warnings" -eq 0 ] || [ "$round" -ge 3 ]; then
      return 0
    fi
    echo "apt-install: the update printed $warnings failed fetches, update $round of at most 3"
    pause $((10 * round))
  done
}

# find_names: step 2. Sets `all` to the named packages and those the program prints.
find_names() {
  local out line
  all=()
  if [ "${#packages[@]}" -gt 0 ]; then
    all=("${packages[@]}")
  fi
  [ -n "$names_from" ] || return 0
  if ! out=$(bash "$names_from" 2> "$work/names.err"); then
    cat "$work/names.err" >&2
    echo "apt-install: $names_from failed" >&2
    exit 1
  fi
  while IFS= read -r line; do
    if [ -n "$line" ]; then
      all+=("$line")
    fi
  done <<< "$out"
}

# resolve: step 3.
resolve() {
  local bound status=0
  bound=$(bound_for 120) || return 124
  if [ -n "$archive" ]; then
    mkdir -p "$work/empty"
    run_apt "$bound" "$work/resolve.log" install --print-uris -qq --no-install-recommends \
      -o Acquire::ForceHash=SHA256 -o "Dir::Cache::Archives=$work/empty" "${all[@]}" || status=$?
  else
    run_apt "$bound" "$work/resolve.log" install --simulate --no-install-recommends "${all[@]}" || status=$?
  fi
  if [ "$status" -eq 0 ]; then
    return 0
  fi
  # A call that the bound cut says nothing about the packages: the attempt is retried.
  if [ "$last_warnings" -eq 0 ] && [ "$status" -ne 124 ] && [ "$status" -ne 137 ]; then
    echo "apt-install: apt cannot plan the install of: ${all[*]}" >&2
    grep '^E:' "$work/resolve.log" >&2 || true
    exit 1
  fi
  failed_log=$work/resolve.log
  return "$status"
}

# list_archives: the archives of the plan as `FILE SIZE SHA256` lines. A line with no hash is left
# out: nothing can be checked against it, so it is neither seeded nor saved.
list_archives() {
  awk -v quote="'" 'substr($1, 1, 1) == quote && NF == 4 && $4 ~ /^SHA256:[0-9a-f]+$/ { print $2, $3, substr($4, 8) }' \
    "$work/resolve.log" > "$listed"
}

# seed_archives: copies each listed archive that DIR holds, and that matches its name, size and
# hash, to apt's archive directory. An archive that an earlier attempt copied stays only while it
# still matches this attempt's list, since a later index can list the same name with other bytes of
# the same size, which apt accepts as it is: the copy is removed, by the name the list gives, and
# DIR's archive is checked against this list like any other.
seed_archives() {
  local file size hash
  [ -d "$archive" ] || return 0
  while read -r file size hash; do
    case "$file" in */* | '') continue ;; esac
    if grep -qxF -- "$file" "$work/seeded.txt"; then
      if valid_file "$size" "$hash" "$cache_dir/$file"; then
        continue
      fi
      echo "apt-install: removed $file, the list names other bytes"
      sudo rm -f -- "$cache_dir/$file"
      grep -vxF -- "$file" "$work/seeded.txt" > "$work/seeded.next" || true
      mv -- "$work/seeded.next" "$work/seeded.txt"
    fi
    if grep -qxF -- "$file" "$work/dropped.txt"; then
      continue
    fi
    [ -e "$archive/$file" ] || [ -L "$archive/$file" ] || continue
    if valid_file "$size" "$hash" "$archive/$file"; then
      sudo cp -- "$archive/$file" "$cache_dir/$file"
      echo "$file" >> "$work/seeded.txt"
      echo "apt-install: seeded $file"
    else
      echo "$file" >> "$work/dropped.txt"
      echo "apt-install: dropped $file"
    fi
  done < "$listed"
}

# count_fetches: the listed archives that apt's archive directory does not hold at their size, which
# the download will fetch.
count_fetches() {
  local file size hash
  fetch_count=0
  while read -r file size hash; do
    if ! [ -f "$cache_dir/$file" ] || [ "$(size_of "$cache_dir/$file")" != "$size" ]; then
      fetch_count=$((fetch_count + 1))
    fi
  done < "$listed"
}

# count_lines FILE: the number of distinct lines.
count_lines() {
  sort -u "$1" | awk 'END { print NR }'
}

# write_outputs save=... [digest=... entry=...]: the step outputs, shown and written to the file the
# workflow reads them from.
write_outputs() {
  local line
  for line in "$@"; do
    echo "apt-install: $line"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "$line" >> "$GITHUB_OUTPUT"
    fi
  done
}

# save_archives: step 6.
save_archives() {
  local file size hash new digest save=false entry kept dropped
  if [ ! -s "$listed" ]; then
    write_outputs save=false
    return 0
  fi
  new=$archive.new
  rm -rf -- "$new"
  mkdir -p "$new"
  : > "$work/manifest.txt"
  while read -r file size hash; do
    if valid_file "$size" "$hash" "$cache_dir/$file"; then
      cp -- "$cache_dir/$file" "$new/$file"
      echo "$file $size $hash" >> "$work/manifest.txt"
    else
      echo "apt-install: not saved $file"
    fi
  done < "$listed"
  kept=$(count_lines "$work/manifest.txt")
  if [ "$kept" -eq 0 ]; then
    rm -rf -- "$new"
    write_outputs save=false
    return 0
  fi
  LC_ALL=C sort "$work/manifest.txt" > "$new/MANIFEST"
  digest=$(sha256_of "$new/MANIFEST")
  rm -rf -- "$archive"
  mv -- "$new" "$archive"
  dropped=$(count_lines "$work/dropped.txt")
  entry=$digest
  if [ "$dropped" -gt 0 ]; then
    entry=$digest-repair-${GITHUB_RUN_ID:-0}-${GITHUB_RUN_ATTEMPT:-0}
  fi
  if [ "$digest" != "$restored_digest" ] || [ "$dropped" -gt 0 ]; then
    save=true
  fi
  write_outputs "digest=$digest" "save=$save" "entry=$entry"
}

# attempt: steps 1 to 4, once.
attempt() {
  local bound status=0
  update_indexes || return $?
  find_names
  if [ "${#all[@]}" -eq 0 ]; then
    return 0
  fi
  resolve || return $?
  if [ -n "$archive" ]; then
    list_archives
    seed_archives
    count_fetches
  fi
  bound=$(bound_for "$deadline") || return 124
  if run_apt "$bound" "$work/download.log" install --download-only --no-install-recommends --yes "${all[@]}"; then
    return 0
  else
    status=$?
  fi
  failed_log=$work/download.log
  return "$status"
}

echo "apt-install: deadline ${deadline}s, packages: ${packages[*]-}${names_from:+, and the names $names_from prints}"
apt-config dump 2>&1 |
  grep -E '^Acquire::(Retries|http::(Timeout|Dl-Limit|Pipeline-Depth|No-Cache|BrokenProxy)|https::(Timeout|Dl-Limit)) ' || true
for file in /etc/apt/apt-mirrors.txt /etc/apt/sources.list /etc/apt/sources.list.d/*; do
  if [ -f "$file" ]; then
    echo "apt-install: $file"
    cat "$file"
  fi
done

if [ -n "$archive" ]; then
  cache_dir=$(apt-config shell dir Dir::Cache::Archives/ | sed -n "s/^dir='\(.*\)'\$/\1/p")
  cache_dir=${cache_dir%/}
  [ -n "$cache_dir" ] || cache_dir=/var/cache/apt/archives
  if [ -f "$archive/MANIFEST" ]; then
    restored_digest=$(sha256_of "$archive/MANIFEST")
  fi
  echo "apt-install: archive directory $archive, restored manifest ${restored_digest}"
fi

attempts=0
status=1
while [ "$(remaining)" -gt 1 ]; do
  attempts=$((attempts + 1))
  failed_log=
  if attempt; then
    status=0
    break
  else
    status=$?
  fi
  echo "apt-install: attempt $attempts failed, status $status"
  if [ -n "$failed_log" ]; then
    tail -n 3 "$failed_log"
  fi
  pause $((10 * attempts))
done
if [ "$status" -ne 0 ]; then
  echo "apt-install: failed: deadline=${deadline}s attempts=$attempts warnings=$total_warnings last_status=$status" >&2
  exit 1
fi

install_status=0
if [ "${#all[@]}" -gt 0 ]; then
  echo "apt-install: sudo env DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --no-download --yes ${all[*]}"
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends --no-download --yes "${all[@]}" || install_status=$?
fi
if [ -n "$archive" ]; then
  if [ "$install_status" -eq 0 ]; then
    save_archives
  else
    write_outputs save=false
  fi
  echo "apt-install: packages=${#all[@]} archives=$(awk 'END { print NR }' "$listed") seeded=$(count_lines "$work/seeded.txt") fetched=$fetch_count dropped=$(count_lines "$work/dropped.txt") attempts=$attempts warnings=$total_warnings elapsed=$((SECONDS - start))s"
else
  echo "apt-install: packages=${#all[@]} attempts=$attempts warnings=$total_warnings elapsed=$((SECONDS - start))s"
fi
exit "$install_status"
