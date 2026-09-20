#!/usr/bin/env bash
# Measures KR-PERF-009: local session descriptions against the real weights.
#
# The division of labour is deliberate. This script knows how to fetch a file and how to pin a run
# to four processors; the product knows what a correct file is and what the budgets are. So the
# script downloads the selected profile's assets once and `kr-describe-bench` verifies every size
# and digest before anything is loaded. A file that does not match stops the run rather than
# producing a figure about weights nobody qualified.
#
# Everything the run touches lives on local storage: the assets, the store the benchmark writes and
# the binary itself. The workspace may be on a removable volume, and a measurement that waited on a
# volume is not a measurement of this product.
#
# Usage:
#   scripts/bench-descriptions.sh [log-file]
#
# Environment:
#   KR_DESCRIBE_PROFILE   the profile to measure (default: the catalogue's default)
#   KR_DESCRIBE_CACHE     where the assets live (default: this platform's cache directory)
#   KR_DESCRIBE_THREADS   how many processors to pin to (default: 4, section 22's own figure)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

profile="${KR_DESCRIBE_PROFILE:-}"
threads="${KR_DESCRIBE_THREADS:-4}"

# The cache is on local storage on every platform, and never inside the workspace.
if [ -n "${KR_DESCRIBE_CACHE:-}" ]; then
  cache="$KR_DESCRIBE_CACHE"
elif [ "$(uname -s)" = "Darwin" ]; then
  cache="$HOME/Library/Caches/kalareach-describe"
else
  cache="$HOME/.cache/kalareach-describe"
fi
case "$cache" in
  /Volumes/*)
    echo "refusing to cache model assets under $cache: the cache belongs on local storage" >&2
    exit 2
    ;;
esac
mkdir -p "$cache"

echo "=== host ==="
uname -a
if [ "$(uname -s)" = "Darwin" ]; then
  sysctl -n machdep.cpu.brand_string || true
  echo "logical processors: $(sysctl -n hw.logicalcpu)"
  echo "memory bytes: $(sysctl -n hw.memsize)"
  pmset -g ps | head -2 || true
else
  sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -1 || true
  echo "logical processors: $(nproc)"
  echo "memory kB: $(sed -n 's/^MemTotal:[[:space:]]*//p' /proc/meminfo)"
fi
echo "load: $(uptime)"
echo "threads pinned to: $threads"

echo "=== build ==="
profile_args=()
[ -n "$profile" ] && profile_args=(--profile "$profile")
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build --release -p kr-describe --bin kr-describe-bench

# The built binary is copied to local storage and run from there, with its working directory there
# too. A process started from a removable volume is a separate privacy identity on macOS, and the
# first path it opened would block on a dialog nobody is watching for.
run_dir="$cache/run"
mkdir -p "$run_dir"
binary="$run_dir/kr-describe-bench"
cp "${CARGO_TARGET_DIR:-$root/target}/release/kr-describe-bench" "$binary"
chmod +x "$binary"

echo "=== assets ==="
manifest="$run_dir/manifest.tsv"
"$binary" --manifest "${profile_args[@]}" > "$manifest"
while IFS=$'\t' read -r name url bytes digest; do
  [ -z "$name" ] && continue
  target="$cache/$name"
  if [ -f "$target" ] && [ "$(wc -c < "$target" | tr -d ' ')" = "$bytes" ]; then
    # The size matches, so the digest decides. A cached file that fails it is removed rather than
    # skipped for ever: a run that refused the same corrupt file every time would be a cache with
    # no way out of it.
    if shasum -a 256 "$target" 2>/dev/null | grep -qi "^$digest" ||
      sha256sum "$target" 2>/dev/null | grep -qi "^$digest"; then
      echo "$name: already held and verified ($bytes bytes)"
      continue
    fi
    echo "$name: cached copy does not match $digest, fetching again"
    rm -f "${target:?}"
  fi
  echo "$name: fetching $bytes bytes from $url"
  rm -f "${target:?}.partial"
  curl --fail --location --show-error --silent --retry 3 --output "$target.partial" "$url"
  mv "$target.partial" "$target"
done < "$manifest"
echo "recorded digests (verified by the product before it loads anything):"
cut -f1,4 "$manifest"

echo "=== KR-PERF-009 ==="
# Four processors, which is section 22's default, enforced by the operating system as well as by
# the profile. A run that used every core would measure a machine this product never promises.
pin=()
if command -v taskset >/dev/null 2>&1; then
  pin=(taskset -c "0-$((threads - 1))")
  echo "pinned with: ${pin[*]}"
else
  echo "no taskset on this platform: the four-thread bound is the profile's own"
fi

cd "$run_dir"
set +e
"${pin[@]}" "$binary" --run "${profile_args[@]}" --cache "$cache"
status=$?
set -e
cd "$root"

if [ "$status" -ne 0 ]; then
  echo "bench-descriptions: failed with status $status"
  exit "$status"
fi
echo "bench-descriptions: measured on $(uname -s) $(uname -m)"
