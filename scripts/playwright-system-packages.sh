#!/usr/bin/env bash
# Prints the system packages the end-to-end run's browsers need on this Linux runner, one name per
# line, from Playwright's own dry run: the packages that `playwright install-deps chromium webkit`
# would install or upgrade, which is what `playwright install --with-deps` runs apt for.
#
#   bash scripts/playwright-system-packages.sh
#
# It is the name program of scripts/apt-install.sh for the companion job, which runs it against the
# indexes it has just updated. It prints nothing when Playwright says that every package is there.
# Where Playwright's output has any other shape (a release that words it differently, or a dry run
# that failed), it prints what Playwright printed and fails, so that the step stops by its name and
# does not install an empty list.
set -euo pipefail

status=0
output=$(pnpm --silent -C apps/companion exec playwright install-deps --dry-run chromium webkit) || status=$?

if [ "$status" -eq 0 ] && [ "$output" = "All system dependencies are installed." ]; then
  exit 0
fi

# `Missing system dependencies (N):` and then N lines of two spaces and a package name, with exit 1.
count=$(printf '%s\n' "$output" | sed -n '1s/^Missing system dependencies (\([1-9][0-9]*\)):$/\1/p')
names=$(printf '%s\n' "$output" | sed -n 's/^  \([A-Za-z0-9][A-Za-z0-9.+:-]*\)$/\1/p')
lines=$(printf '%s\n' "$output" | grep -c . || true)
found=$(printf '%s\n' "$names" | grep -c . || true)

if [ "$status" -ne 1 ] || [ -z "$count" ] || [ "$found" -ne "$count" ] || [ "$lines" -ne $((count + 1)) ]; then
  echo "playwright-system-packages: the dry run of install-deps printed an unexpected result (status $status):" >&2
  printf '%s\n' "$output" >&2
  exit 1
fi
printf '%s\n' "$names"
