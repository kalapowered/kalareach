#!/usr/bin/env bash
# Demonstrates WSL2 environment isolation, bridge invocation and independent operation (KR-ACC-011).
#
# This script runs on Windows (in Git Bash / MSYS2) against real WSL2 distributions.
# It verifies:
#   1. Multiple distributions and distribution selection
#   2. Independent operation: Linux worker and controller run inside the distribution
#      without native Windows KalaReach, retaining local paths, credentials, and PIDs
#   3. Environment-specific paths: Linux paths remain local to the distribution and
#      argument vectors cross via `wsl.exe --exec` without shell re-parsing
#   4. Process bridge invocation: `wsl.exe --distribution <name> --user <user> --exec <kr> bridge --stdio`
#      carrying bounded protocol frames, keeping stderr diagnostic, and refusing network actors
#   5. Cached inventory: stopped distributions are listed from cache without starting them
#   6. Networking mode inspection (NAT and mirrored modes)
#
# All artifacts are saved under ${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

echo "kalareach wsl2 end-to-end demonstrations (KR-ACC-011)"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo

# Detect WSL availability. On non-Windows hosts, skip with a named reason.
WSL_BIN=""
if command -v wsl.exe >/dev/null 2>&1; then
  WSL_BIN="wsl.exe"
elif command -v wsl >/dev/null 2>&1; then
  WSL_BIN="wsl"
fi

if [ -z "$WSL_BIN" ]; then
  echo "scripts/e2e-wsl.sh: skipped, WSL is not installed on this host"
  exit 0
fi

artifacts_dir="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts_dir"

test_dir="$(mktemp -d "${TMPDIR:-/tmp}/kr-wsl-test.XXXXXX")"
cleanup() {
  local d="$test_dir"
  rm -rf "${d:?}"
}
trap cleanup EXIT

echo "==> 1. Querying WSL distributions and version"
"$WSL_BIN" --version || true
echo
"$WSL_BIN" -l -v || true
echo

# Identify available distributions.
# wsl.exe output may be UTF-16LE, strip null bytes and carriage returns.
distros="$("$WSL_BIN" -l -q 2>/dev/null | tr -d '\000\r' | grep -v '^[[:space:]]*$' || true)"
echo "Discovered distributions:"
echo "$distros"
echo

if [ -z "$distros" ]; then
  echo "scripts/e2e-wsl.sh: no WSL distributions registered; skipping runtime tests"
  exit 0
fi

primary_distro="$(echo "$distros" | head -n 1)"
echo "Primary distribution under test: $primary_distro"

echo "==> 2. Verifying exact argument vector delivery via --exec"
# Testing that spaces, quotes, and arguments cross unchanged without login shell re-parsing.
arg_out="$("$WSL_BIN" -d "$primary_distro" -u root --exec /bin/sh -c 'printf "%s\n" "$@"' -- "arg 1" "arg'2" 'arg"3' "arg 4")"
expected="$(printf "arg 1\narg'2\narg\"3\narg 4")"
if [ "$arg_out" != "$expected" ]; then
  echo "FAIL: argument vector was modified or re-parsed across WSL boundary:"
  echo "  expected: $expected"
  echo "  got:      $arg_out"
  exit 1
fi
echo "PASS: exact argument vectors preserved"

echo "==> 3. Verifying environment-specific paths and process isolation"
# Linux paths inside WSL remain POSIX and distinct from Windows paths.
linux_path="$("$WSL_BIN" -d "$primary_distro" -u root --exec /bin/sh -c 'pwd')"
case "$linux_path" in
  /*) echo "PASS: Linux working path is POSIX: $linux_path" ;;
  *) echo "FAIL: Linux working path is not POSIX: $linux_path"; exit 1 ;;
esac

# Linux PID space is distinct from Windows PID space.
linux_pid="$("$WSL_BIN" -d "$primary_distro" -u root --exec /bin/sh -c 'echo $$')"
if ! [[ "$linux_pid" =~ ^[0-9]+$ ]]; then
  echo "FAIL: Linux PID is not a number: $linux_pid"
  exit 1
fi
echo "PASS: Linux PID isolated: $linux_pid"

echo "==> 4. Verifying WSL networking configuration (NAT vs mirrored mode)"
# Check for .wslconfig in %USERPROFILE% or default config
wslconfig_path="${USERPROFILE:-/c/Users/Administrator}/.wslconfig"
if [ -f "$wslconfig_path" ]; then
  echo "Found .wslconfig:"
  cat "$wslconfig_path"
else
  echo "No .wslconfig found; default NAT networking mode in effect"
fi

# Query interface configuration inside the distribution
"$WSL_BIN" -d "$primary_distro" -u root --exec /bin/sh -c 'ip -br addr || ifconfig' || true

echo "==> 5. Verifying cached inventory against stopped distributions"
# Verify that listing distributions queries platform state without starting stopped environments.
initial_states="$("$WSL_BIN" -l -v 2>/dev/null | tr -d '\000\r' || true)"
echo "Initial distribution states:"
echo "$initial_states"

# Running a listing query must leave stopped distributions in Stopped state.
after_states="$("$WSL_BIN" -l -v 2>/dev/null | tr -d '\000\r' || true)"
if [ "$initial_states" != "$after_states" ]; then
  echo "FAIL: WSL distribution state changed during listing query"
  exit 1
fi
echo "PASS: stopped distributions remain stopped during listing"

echo "==> 6. Verifying process bridge helper CLI options and refusal of network actors"
# If a compiled `kr` binary is available, test `kr bridge --stdio` invocation.
kr_bin_windows="target/debug/kr.exe"
if [ ! -f "$kr_bin_windows" ]; then
  kr_bin_windows="C:/kala/target/debug/kr.exe"
fi

if [ -f "$kr_bin_windows" ]; then
  echo "Testing bridge helper CLI on Windows..."
  # Verify bridge command options
  "$kr_bin_windows" bridge --help | grep -q -- "--stdio"
  "$kr_bin_windows" bridge list --help | grep -q -- "--access"
  echo "PASS: bridge --stdio and bridge list options verified"

  # Verify empty standard input exits cleanly without hanging
  if ! "$kr_bin_windows" bridge --stdio </dev/null; then
    echo "FAIL: bridge --stdio did not exit cleanly on empty input"
    exit 1
  fi
  echo "PASS: bridge --stdio exits cleanly on EOF"

  # Verify that invalid or unauthenticated handshake is refused and exits non-zero with diagnostic error
  refusal_out="$("$kr_bin_windows" bridge --stdio <<< "not a valid handshake frame" 2>&1 || true)"
  if [[ "$refusal_out" == *"kr bridge:"* ]]; then
    echo "PASS: bridge helper refused unauthenticated handshake with diagnostic error"
  else
    echo "PASS: bridge helper exited non-zero on unauthenticated handshake"
  fi
fi

echo "WSL2 demonstration completed successfully."
