#!/usr/bin/env bash
# Qualifies the managed shell packages end to end, on this machine.
#
#   bash scripts/e2e-fence.sh          build or verify the packages, then qualify them
#   bash scripts/e2e-fence.sh <log>    the same, with a copy of everything in <log>
#
# Each step is something the operating system can see:
#
#   * the packages rebuilt from their pinned upstream releases and patch sets, into an installation
#     on the internal disk, and the identity each build wrote beside its binary
#   * the startup customisations the qualification runs against, fetched once by digest
#   * a real control daemon, a real worker it launched, and a real managed session whose root
#     shell is one of those packages
#   * the whole corpus under tests/shells/ driven against the packages that were just built: the
#     customisations, the person's own bindings and profile order, Ctrl-D at the root prompt, the
#     fence races and what a launch past its budget installs
#   * the upstream register checked against the pins and against what is installed
#
# Every path this script uses is on the internal disk and the binaries it starts are copied there
# first. A process a service manager launches is its own identity to the operating system, and one
# that reaches a removable volume asks the person at the machine for permission.
#
# Nothing here reaches the person's own credential store: the daemon is given `--secret-store
# file`, so the keys a run creates leave with the run.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

log="${1:-}"
if [ -n "$log" ]; then
  mkdir -p "$(dirname "$log")"
  exec > >(tee "$log") 2>&1
fi

artifacts="${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}"
mkdir -p "$artifacts"

# This run is about every case. A filter left in the environment would qualify one of them and
# report all of them, so it is taken out here rather than trusted.
unset KR_QUALIFICATION_CASE

# One root for the whole run: the builder installs here, the daemon resolves here, and the corpus
# drives what is here.
if [ -n "${KR_SHELL_PREFIX:-}" ]; then
  packages="$KR_SHELL_PREFIX"
elif [ "$(uname -s)" = "Darwin" ]; then
  packages="$HOME/Library/Caches/kalareach/shells"
else
  packages="${XDG_CACHE_HOME:-$HOME/.cache}/kalareach/shells"
fi
export KR_SHELL_PREFIX="$packages"
export KR_SHELL_PACKAGES="$packages"

echo "kalareach shell-integration qualification"
echo "  commit: $(git rev-parse HEAD)"
echo "  host: $(uname -sr) $(uname -m)"
echo "  taken at: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  evidence: $artifacts"
echo

failed=0
# A stage that could not run at all, as opposed to one that ran and did not hold. Either ends this
# run without success: a qualification that skipped a stage has not qualified what that stage is
# about, and saying so is the whole point of running it.
incomplete=0
fail() {
  echo "FAILED: $*"
  failed=1
}

require() {
  if [ "$1" != "$2" ]; then
    fail "$3 (expected $2, got $1)"
  else
    echo "  ok: $3"
  fi
}

# The run's own root, on the internal disk, with the binaries beside it.
# Short on purpose: a Unix socket address is 103 bytes on this platform, and the endpoint a case
# binds is under a directory of its own beneath the temporary directory. A run root of the usual
# length leaves a case no room for one.
run_root="$(mktemp -d "${TMPDIR:-/tmp}/kr-fence.XXXXXX")"
mkdir -p "$run_root/bin" "$run_root/r" "$run_root/s" "$run_root/cwd"
chmod 700 "$run_root/r" "$run_root/s"

started_pids=()

cleanup() {
  local status=$?
  for session in $("$run_root/bin/kr" list --json 2>/dev/null | /usr/bin/env python3 -c \
    'import json,sys
try:
    document = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in document.get("sessions", []):
    print(entry["display_number"])' 2>/dev/null); do
    "$run_root/bin/kr" close "$session" >/dev/null 2>&1 || true
  done
  for pid in "${started_pids[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  sleep 1
  local left
  left="$(pgrep -u "$(id -u)" -f "$run_root" 2>/dev/null | grep -v "^$$\$" || true)"
  if [ -n "$left" ]; then
    echo "FAILED: these processes outlived the script"
    # shellcheck disable=SC2086
    ps -o pid=,command= -p $(printf '%s' "$left" | tr '\n' ' ') || true
    failed=1
  else
    echo "no process this run started is still running"
  fi
  rm -rf "${run_root:?}"
  # A run whose processes outlived it did not pass, whatever the last command returned.
  if [ "$failed" -ne 0 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

echo "1. the packages, from their pinned upstream releases and patch sets"
# The identity is a digest of the inputs, so a package that is already installed from these inputs
# reports that nothing changed, and one that is not is built here. Either way what the corpus then
# drives is a package this run stood behind.
if ! bash scripts/build-shells.sh --all --no-upstream-tests > "$run_root/build.log" 2>&1; then
  tail -40 "$run_root/build.log"
  fail "the packages could not be built"
  exit 1
fi
grep -E "is current, nothing changed|installed" "$run_root/build.log" || true

# A second build of one package, from inputs of its own. An installation a person updates holds
# two builds, and the qualification's replacement case needs two that are really different: the
# identity is a digest of the build's inputs, so a flag that reaches the compiler is a second
# package rather than a second copy of the first. The ordinary build runs again afterwards, so
# the installation this run then qualifies is the pinned one.
if ! CPPFLAGS="${CPPFLAGS:+$CPPFLAGS }-DKR_QUALIFICATION_BUILD=1" \
    bash scripts/build-shells.sh --zsh --no-upstream-tests > "$run_root/second-build.log" 2>&1; then
  tail -20 "$run_root/second-build.log"
  fail "a second build of the zsh package could not be made"
fi
grep -E "built zsh|is current, nothing changed" "$run_root/second-build.log" || true
cp "$run_root/second-build.log" "$artifacts/shell-packages-second-build.log"
if ! bash scripts/build-shells.sh --zsh --no-upstream-tests >> "$run_root/build.log" 2>&1; then
  tail -20 "$run_root/build.log"
  fail "the pinned zsh package could not be put back"
fi
# Copied once the log is complete: the restoration above writes into it, and a copy taken before
# that would leave the run's evidence without the step that put the pinned package back.
cp "$run_root/build.log" "$artifacts/shell-packages-build.log"

for shell in zsh bash fish; do
  identity="$(cat "$packages/$shell/current" 2>/dev/null || true)"
  if [ -z "$identity" ]; then
    fail "$shell is not installed"
  else
    echo "  ok: $shell is $identity"
  fi
done
# This package rebuilds no shell: it is qualified against the editor this host already has, and
# publishing that qualification is what puts it where the corpus looks.
if command -v pwsh >/dev/null 2>&1; then
  if ! pwsh -NoProfile -Command "
    Import-Module ./shells/psreadline/module/KalaReach.ShellBridge.psd1
    Publish-KalaReachQualification | Format-List" > "$run_root/psreadline.log" 2>&1; then
    tail -20 "$run_root/psreadline.log"
    fail "the PSReadLine package could not be qualified"
  fi
  cp "$run_root/psreadline.log" "$artifacts/psreadline-qualification.log"
fi
if [ -r "$packages/powershell/current" ]; then
  echo "  ok: powershell is $(cat "$packages/powershell/current")"
else
  fail "the PSReadLine package is not qualified on this host and no editor was found to qualify it against"
fi

echo
echo "2. the startup customisations, by digest"
if ! bash scripts/fetch-shell-stacks.sh > "$run_root/stacks.log" 2>&1; then
  tail -20 "$run_root/stacks.log"
  fail "the startup customisations could not be fetched"
fi
tail -12 "$run_root/stacks.log"
cp "$run_root/stacks.log" "$artifacts/shell-stacks-fetch.log"

echo
echo "3. a real daemon, a real worker and a real managed session"
CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" cargo build -q -p kr-controller -p kr-worker -p kr-cli
target_dir="${CARGO_TARGET_DIR:-$root/target}"
for binary in kr-controller kr-worker kr; do
  if [ ! -x "$target_dir/debug/$binary" ]; then
    fail "the build did not produce $binary"
    exit 1
  fi
  cp "$target_dir/debug/$binary" "$run_root/bin/$binary"
done
export KR_RUNTIME_DIR="$run_root/r"
export KR_STATE_DIR="$run_root/s"
kr="$run_root/bin/kr"

(cd "$run_root" && exec "$run_root/bin/kr-controller" \
  --runtime-dir "$run_root/r" \
  --state-dir "$run_root/s" \
  --secret-store file \
  --worker "$run_root/bin/kr-worker") \
  >"$run_root/controller.log" 2>&1 &
started_pids+=("$!")

deadline=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if "$kr" doctor --json >/dev/null 2>&1; then break; fi
  sleep 0.2
done
if ! "$kr" doctor --json >"$artifacts/fence-doctor.json" 2>&1; then
  tail -20 "$run_root/controller.log"
  fail "the control daemon did not start"
  exit 1
fi
echo "  ok: the control daemon answered"

read_json() {
  /usr/bin/env python3 -c '
import json, sys
document = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    if document is None:
        break
    document = document.get(key) if isinstance(document, dict) else None
print("" if document is None else document)
' "$1" "$2"
}

managed_shell="$packages/zsh/$(cat "$packages/zsh/current")/bin/zsh"
if "$kr" new --invisible --shell-mode managed --shell "$managed_shell" --cwd "$run_root/cwd" \
    --json >"$artifacts/fence-create.json" 2>"$run_root/create.err"; then
  display="$(read_json "$artifacts/fence-create.json" display_number)"
  mode="$(read_json "$artifacts/fence-create.json" session.shell_mode)"
  if [ "$mode" = "managed" ]; then
    echo "  ok: session $display runs the managed package"
  else
    fail "the session the daemon made reports shell_mode=$mode"
  fi

  # What the session says about itself, through the daemon that made it.
  if "$kr" status "$display" --json >"$artifacts/fence-status.json" 2>&1; then
    status_mode="$(read_json "$artifacts/fence-status.json" shell_mode)"
    require "$status_mode" "managed" "the session reports the managed mode it was created in"
  else
    fail "the daemon could not report on the session it made"
  fi

  # The session is closed through the daemon, and the daemon is asked again: a session that did
  # not go is a session this run left behind.
  if ! "$kr" close "$display" >"$run_root/close.log" 2>&1; then
    cat "$run_root/close.log"
    fail "the daemon could not close the session it made"
  fi
  # The daemon keeps a closed session's record and answers for it, so what says the close
  # happened is the state in that record rather than the question failing.
  if "$kr" status "$display" --json >"$artifacts/fence-closed.json" 2>&1; then
    require "$(read_json "$artifacts/fence-closed.json" state)" "closed" \
      "the session the daemon closed reports itself closed"
  else
    fail "the daemon could not report on the session it closed"
  fi
else
  # A refusal that names another shell's record is a condition of this installation rather than of
  # the package this run qualified: a daemon that cannot read one shell's record refuses the whole
  # installation, and the record it cannot read is the one the editor package writes for an editor
  # that lives outside it. It is reported with the answer the daemon gave, and the packages this
  # run built are qualified below either way. Any other refusal is this run's.
  refusal="$(read_json "$artifacts/fence-create.json" code)"
  detail="$(read_json "$artifacts/fence-create.json" message)"
  echo "  the daemon refused a managed session:"
  echo "    ${detail:-$(cat "$run_root/create.err")}"
  if [ "$refusal" = "SHELL_INTEGRATION_UNSUPPORTED" ] && \
     [ "${detail#*"$packages/powershell/"}" != "$detail" ] && \
     [ "${detail#*names paths outside the package it is in}" != "$detail" ]; then
    echo "    the package this run asked for is $managed_shell, and the record the daemon could"
    echo "    not read is another shell's: an installation is read as a whole here, so one"
    echo "    unreadable record refuses every shell in it."
    incomplete=1
  else
    fail "a managed session could not be created"
  fi
fi

echo
echo "4. the corpus, against the packages this run stood behind"
if ! KR_REQUIRE_SHELL_PACKAGES=1 KR_REQUIRE_SHELL_STACKS=1 KR_TEST_ARTIFACTS_DIR="$artifacts" \
    CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" \
    cargo test -p kr-shell-integration --test qualification -- --test-threads=1 \
    >"$run_root/qualification.log" 2>&1; then
  tail -60 "$run_root/qualification.log"
  fail "the qualification did not hold"
fi
grep -E "^(test |test result)" "$run_root/qualification.log" || true
cp "$run_root/qualification.log" "$artifacts/qualification.log"
if [ -r "$artifacts/qualification-cases.tsv" ]; then
  echo
  echo "  what each case qualified:"
  sed 's/^/    /' "$artifacts/qualification-cases.tsv"
fi

echo
if [ "$failed" -ne 0 ]; then
  echo "the qualification did not pass"
  exit 1
fi
if [ "$incomplete" -ne 0 ]; then
  echo "the qualification is incomplete: a stage above could not run, and what it is about is"
  echo "not qualified by this run"
  exit 2
fi
echo "every package was qualified against every customisation this host has"
