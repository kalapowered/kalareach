#!/usr/bin/env bash
# Checks one commit from a clean checkout: that its tree and its history carry nothing that belongs
# outside the repository, and that everything README.md lists under "Build and test" runs.
#
#   scripts/check-clean-checkout.sh                         check this repository's HEAD
#   scripts/check-clean-checkout.sh --commit <rev>          check another commit
#   scripts/check-clean-checkout.sh --repo <path or URL>    clone from another repository
#   scripts/check-clean-checkout.sh --only setup,check      run only these step groups
#   scripts/check-clean-checkout.sh --skip demonstrations   run every group but these
#   scripts/check-clean-checkout.sh --no-steps              make the refusals and run nothing
#   scripts/check-clean-checkout.sh --list                  print the steps a run would take
#   scripts/check-clean-checkout.sh --commits <range>       check these commits' messages
#   scripts/check-clean-checkout.sh --self-test             prove each refusal on a planted defect
#
# What is checked is the commit, never a working tree: uncommitted changes play no part.
#
# The commit is cloned into an empty directory under the temporary directory. Every git command
# and every step then runs with a home directory, a Cargo home, a pnpm store and a temporary
# directory of its own, in an environment reduced to the variables `environment` lists below, so
# no cache, build output, installed package or setting this machine has collected can stand in for
# what the repository provides. The toolchains are the exception: rustup's own directory is used as
# it is, and rust-toolchain.toml picks the toolchain from it.
#
# Before anything runs, the clone is refused when:
#
#   - a tracked file names a working record that is kept outside the repository: a task or a
#     decision identifier, the file name of a task's notes, of a numbered review or of a dispatch,
#     the specification, the ledger, the goal or the records directory by name, or a path on a
#     named volume. A word the product uses in its own sense is not a record, so each pattern
#     matches a record's own form and nothing wider;
#   - a commit in the range, which is the commit's whole history unless --commits names one, has a
#     body or a trailer. A commit message here is one subject line;
#   - a relative Markdown link in a tracked file names a path the tree does not have.
#
# Each pattern in `record_patterns` is written so that its own text does not match it, which is
# what lets this file pass its own check.
#
# Then the steps run. README.md gives them as fenced blocks, each after a line
# `<!-- clean-checkout: <group> -->`; every line of a block is one step, and a line ending in a
# backslash continues on the next. A step runs with bash in the clone's root, groups and steps in
# README.md's order, and the run stops at the first step that fails unless --keep-going is given.
# KR_CLEAN_CHECKOUT_ROOT names the run's directory to every step.
#
# The clone and everything the run wrote are removed at the end, unless --keep is given.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: check-clean-checkout.sh [--commit <rev>] [--repo <path or URL>] [--commits <range>]
                               [--only <groups>] [--skip <groups>] [--no-steps] [--list]
                               [--keep-going] [--keep]
       check-clean-checkout.sh --self-test

  --commit <rev>       the commit to check (default: HEAD of the repository holding this script)
  --repo <path|URL>    the repository to clone it from (default: the one holding this script)
  --commits <range>    the commits whose messages are checked (default: the commit's history)
  --only <groups>      run only these step groups, comma-separated
  --skip <groups>      run every step group except these, comma-separated
  --no-steps           make the refusals and run no step
  --list               make the refusals and print the selected steps instead of running them
  --keep-going         run every selected step even after one fails
  --keep               keep the clone and the directories the run used
  --self-test          check each refusal against a fixture repository planted with its defect
EOF
}

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
script_path="$script_directory/$(basename "${BASH_SOURCE[0]}")"

repo=""
commit="HEAD"
commits=""
only=""
skip=""
run_steps=1
list_steps=0
keep_going=0
keep=0
self_test=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --commit) commit="${2:?--commit needs a revision}"; shift 2 ;;
    --repo) repo="${2:?--repo needs a path or URL}"; shift 2 ;;
    --commits) commits="${2:?--commits needs a range}"; shift 2 ;;
    --only) only="${2:?--only needs a group list}"; shift 2 ;;
    --skip) skip="${2:?--skip needs a group list}"; shift 2 ;;
    --no-steps) run_steps=0; shift ;;
    --list) list_steps=1; shift ;;
    --keep-going) keep_going=1; shift ;;
    --keep) keep=1; shift ;;
    --self-test) self_test=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "check-clean-checkout: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

# The working records a tracked file must not name. Each is an extended regular expression that
# git grep applies to every line of every tracked text file.
record_patterns=(
  '(^|[^[:alnum:]])T-[0-9]{3}'
  '(^|[^[:alnum:]])D-[0-9]{3}'
  '-hand[o]ff(-archive)?\.md'
  '-review-[0-9]+\.md'
  '-dispatch-[0-9]+\.md'
  'kalareach\.md'
  'kalareach-ledge[r]'
  'kalareach-goa[l]'
  'kalareach-artifact[s]'
  '(^|[^[:alnum:]_./-])/Volume[s]/[[:alnum:]]'
)

# The variables a step may inherit from the environment this script was started in. Everything
# else is left behind.
inherited=(PATH USER LOGNAME SHELL TERM LANG LC_ALL LC_CTYPE TZ XDG_RUNTIME_DIR CARGO_BUILD_JOBS
  CARGO_NET_GIT_FETCH_WITH_CLI DEVELOPER_DIR SDKROOT)

rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

say() {
  printf 'check-clean-checkout: %s\n' "$*"
}

# ---------------------------------------------------------------------------------------------
# The checks, on a clone that already exists.

refuse_records() {
  local clone="$1" arguments=() pattern hits
  for pattern in "${record_patterns[@]}"; do
    arguments+=(-e "$pattern")
  done
  local rc=0
  hits="$(clean git -C "$clone" grep -n -I -E "${arguments[@]}")" || rc=$?
  case "$rc" in
    0)
      say "refused: tracked files name records kept outside the repository:"
      printf '%s\n' "$hits" | sed 's/^/  /'
      return 1
      ;;
    1) say "no tracked file names a record kept outside the repository" ;;
    *) say "the search of the tracked files failed"; return 1 ;;
  esac
}

refuse_messages() {
  local clone="$1" range="$2" found
  if ! clean git -C "$clone" rev-list --quiet "$range" 2>/dev/null; then
    say "refused: $range is not a range of commits in the clone"
    return 1
  fi
  found="$(clean git -C "$clone" log --format='%H%x1f%s%x1f%b%x1e' "$range" | awk '
    BEGIN { RS = "\036"; FS = "\037"; bad = 0 }
    {
      sub(/^\n+/, "", $1)
      body = $3
      gsub(/^[ \t\n]+|[ \t\n]+$/, "", body)
      if ($1 == "" || body == "") next
      kind = "a trailer"
      count = split(body, lines, "\n")
      for (i = 1; i <= count; i++) {
        if (lines[i] != "" && lines[i] !~ /^[A-Za-z0-9-]+: /) kind = "a body"
      }
      printf "  %s %s: %s\n", substr($1, 1, 12), kind, $2
      bad = 1
    }
    END { exit bad }
  ')" || {
    say "refused: commits in $range carry more than a subject line:"
    printf '%s\n' "$found"
    return 1
  }
  say "every commit in $range is one subject line"
}

# Prints each relative Markdown link whose path the tree does not have, and fails when there is one.
broken_links() {
  clean python3 - "$1" <<'PYTHON'
import os
import re
import subprocess
import sys
import urllib.parse

root = sys.argv[1]
listing = subprocess.run(
    ["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True
).stdout.decode("utf-8", "surrogateescape")
tracked = {path for path in listing.split("\0") if path}
directories = set()
for path in tracked:
    parent = os.path.dirname(path)
    while parent:
        directories.add(parent)
        parent = os.path.dirname(parent)

fence = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
inline = re.compile(r"\]\(\s*(<[^>]*>|[^)\s]+)")
reference = re.compile(r"^ {0,3}\[[^\]]+\]:\s*(<[^>]*>|\S+)")
code_span = re.compile(r"(`+)(?:(?!\1).)*?\1")
scheme = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")

broken = 0
for path in sorted(p for p in tracked if p.endswith(".md")):
    open_fence = None
    with open(os.path.join(root, path), encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            marker = fence.match(line)
            if open_fence is not None:
                if (
                    marker
                    and marker.group(1)[0] == open_fence[0]
                    and len(marker.group(1)) >= len(open_fence)
                    and not marker.group(2).strip()
                ):
                    open_fence = None
                continue
            if marker and not (marker.group(1)[0] == "`" and "`" in marker.group(2)):
                open_fence = marker.group(1)
                continue
            text = code_span.sub("", line)
            targets = [m.group(1) for m in inline.finditer(text)]
            targets += [m.group(1) for m in reference.finditer(text)]
            for target in targets:
                target = target.strip("<>")
                if not target or target.startswith("#") or target.startswith("//"):
                    continue
                if scheme.match(target):
                    continue
                named = urllib.parse.unquote(target.split("#", 1)[0].split("?", 1)[0])
                if not named:
                    continue
                if named.startswith("/"):
                    resolved = os.path.normpath(named.lstrip("/"))
                else:
                    resolved = os.path.normpath(os.path.join(os.path.dirname(path), named))
                if resolved in tracked or resolved in directories or resolved == ".":
                    continue
                print(f"  {path}:{number}: {target}")
                broken += 1
sys.exit(1 if broken else 0)
PYTHON
}

refuse_links() {
  local clone="$1" broken
  if ! broken="$(broken_links "$clone")"; then
    say "refused: relative Markdown links name paths the tree does not have:"
    printf '%s\n' "$broken"
    return 1
  fi
  say "every relative Markdown link names a path the tree has"
}

# Prints each step README.md lists, as its group, a tab and its command, in README.md's order.
read_steps() {
  clean python3 - "$1/README.md" <<'PYTHON'
import re
import sys

lines = open(sys.argv[1], encoding="utf-8").read().split("\n")
marker = re.compile(r"^<!-- clean-checkout: ([a-z][a-z0-9-]*) -->\s*$")
fence = re.compile(r"^(`{3,}|~{3,})")
index = 0
while index < len(lines):
    named = marker.match(lines[index])
    index += 1
    if not named:
        continue
    while index < len(lines) and not lines[index].strip():
        index += 1
    opened = fence.match(lines[index]) if index < len(lines) else None
    if not opened:
        sys.exit(f"README.md: the group {named.group(1)} is not followed by a fenced block")
    index += 1
    pending = ""
    while index < len(lines) and not lines[index].startswith(opened.group(1)):
        line = lines[index].rstrip()
        index += 1
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        command = (pending + line).strip()
        pending = ""
        if command and not command.startswith("#"):
            print(f"{named.group(1)}\t{command}")
    index += 1
PYTHON
}

# Returns success when a group is selected by --only and --skip.
selected() {
  local group="$1"
  if [ -n "$only" ] && ! printf ',%s,' "$only" | grep -q ",$group,"; then
    return 1
  fi
  if [ -n "$skip" ] && printf ',%s,' "$skip" | grep -q ",$group,"; then
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------------------------
# The self-test: one fixture repository per refusal, each with its defect planted, and fixtures
# that must pass. A planted name is put together at run time, so this file never contains it.

fixture_git() {
  env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_AUTHOR_NAME=fixture \
    GIT_AUTHOR_EMAIL=fixture@example.invalid GIT_COMMITTER_NAME=fixture \
    GIT_COMMITTER_EMAIL=fixture@example.invalid git "$@"
}

# Creates a fixture repository with a README whose steps check the environment they run in, a
# document with sound links, and one commit.
make_fixture() {
  local directory="$1"
  mkdir -p "$directory/docs"
  fixture_git init -q -b main "$directory"
  cat > "$directory/README.md" <<'EOF'
# fixture

[the guide](docs/guide.md), [a section](#fixture), [the docs](docs), [the site](https://example.invalid/x)

<!-- clean-checkout: setup -->

```bash
test "$HOME" = "$KR_CLEAN_CHECKOUT_ROOT/home" && test -d "$HOME"
test "$CARGO_HOME" = "$KR_CLEAN_CHECKOUT_ROOT/cargo" && test -z "$(ls -A "$CARGO_HOME")"
test "$pnpm_config_store_dir" = "$KR_CLEAN_CHECKOUT_ROOT/pnpm-store"
case "$TMPDIR" in /tmp/kr-clean.*) test -d "$TMPDIR" ;; *) false ;; esac
```

<!-- clean-checkout: check -->

```bash
test -z "${CARGO_TARGET_DIR:-}" && test -z "${RUSTUP_TOOLCHAIN:-}"
test -z "${KR_CLEAN_SELF_TEST_LEAK:-}"
test "$(pwd -P)" = "$(cd "$KR_CLEAN_CHECKOUT_ROOT/clone" && pwd -P)" && test -z "$(git status --porcelain)"
test \
  -f README.md
```
EOF
  cat > "$directory/docs/guide.md" <<'EOF'
# Guide

Back to [the README](../README.md), and a [reference] link.

```text
[inside a fence](missing.md)
```

`[inside code](missing.md)`

[reference]: ../README.md
EOF
  fixture_git -C "$directory" add -A
  fixture_git -C "$directory" commit -q -m "Start the fixture"
}

commit_fixture() {
  local directory="$1" message="$2"
  fixture_git -C "$directory" add -A
  fixture_git -C "$directory" commit -q -m "$message"
}

self_test() {
  local work failures=0 case_name expected needle directory output rc
  work="${TMPDIR:-/tmp}"
  work="$(mktemp -d "${work%/}/kalareach-clean-checkout-self-test.XXXXXX")"
  # shellcheck disable=SC2064
  trap "rm -rf '${work:?}'" EXIT

  # A case is a name, the exit status it must end with (pass or refuse), a phrase its output must
  # contain, and the arguments after --repo.
  expect() {
    case_name="$1" expected="$2" needle="$3"
    shift 3
    rc=0
    output="$(KR_CLEAN_SELF_TEST_LEAK=1 CARGO_TARGET_DIR=/nonexistent RUSTUP_TOOLCHAIN=nonexistent \
      bash "$script_path" --repo "$directory" "$@" 2>&1)" || rc=$?
    if { [ "$expected" = pass ] && [ "$rc" -ne 0 ]; } \
      || { [ "$expected" = refuse ] && [ "$rc" -eq 0 ]; } \
      || ! printf '%s\n' "$output" | grep -qF -- "$needle"; then
      echo "self-test: $case_name FAILED (expected $expected, exit $rc)"
      printf '%s\n' "$output" | sed 's/^/    /'
      failures=$((failures + 1))
    else
      echo "self-test: $case_name ok"
    fi
  }

  directory="$work/clean"
  make_fixture "$directory"
  expect "a clean fixture passes" pass "== step check.4 exit 0"
  expect "an unknown group is refused" refuse "names no group README.md lists" --only nosuch

  local name planted
  for planted in \
    "task=see T-""123 for the reason" \
    "decision=as D-""456 decided" \
    "notes=tasks/x-hand""off.md" \
    "review=reviews/x-review-""2.md" \
    "dispatch=tasks/x-claude-dispatch-""3.md" \
    "specification=the kalareach"".md specification" \
    "ledger=kalareach-""ledger.md" \
    "goal=kalareach-""goal.md" \
    "records=kalareach-""artifacts/logs/run.log" \
    "volume=/Vol""umes/Work/notes.txt"; do
    name="${planted%%=*}"
    directory="$work/record-$name"
    make_fixture "$directory"
    printf 'A note: %s\n' "${planted#*=}" > "$directory/docs/note.md"
    commit_fixture "$directory" "Add a note"
    expect "a tracked file naming a record ($name) is refused" refuse "tracked files name records"
  done

  directory="$work/product-words"
  make_fixture "$directory"
  {
    echo "The plugin service answers with a Handoff, and pending_hand""off is a column."
    echo "macOS keeps it on /System/Volumes/Data, and a path under \"/Volumes/\" is removable."
    echo "SHA-256, UTF-8, KR-PERF-001 and PORT""-123 are not records."
  } > "$directory/docs/words.md"
  commit_fixture "$directory" "Add the product's own words"
  expect "the product's own words pass" pass "no tracked file names a record"

  directory="$work/commit-body"
  make_fixture "$directory"
  echo "more" >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Extend the guide

Because it needed more."
  expect "a commit with a body is refused" refuse "a body: Extend the guide" --no-steps

  directory="$work/commit-trailer"
  make_fixture "$directory"
  echo "more" >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Extend the guide

Signed-off-by: fixture <fixture@example.invalid>"
  expect "a commit with a trailer is refused" refuse "a trailer: Extend the guide" --no-steps
  expect "a range without that commit passes" pass "every commit in HEAD~1" --no-steps \
    --commits HEAD~1

  directory="$work/broken-link"
  make_fixture "$directory"
  echo "See [the missing page](missing.md)." >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Link a page that is not there"
  expect "a relative link to a missing path is refused" refuse "docs/guide.md:12: missing.md"

  directory="$work/failing-step"
  make_fixture "$directory"
  sed 's/^test \\$/false \\/' "$directory/README.md" > "$directory/README.new"
  mv "$directory/README.new" "$directory/README.md"
  commit_fixture "$directory" "Make the last step fail"
  expect "a step that fails fails the run" refuse "== step check.4 exit 1"
  expect "--keep-going still fails the run" refuse "one or more steps failed" --keep-going
  expect "--skip leaves the failing group out" pass "== step setup.4 exit 0" --skip check
  expect "--only runs the named group alone" pass "== step setup.4 exit 0" --only setup
  expect "--list prints the steps and runs none" pass "check.4: false" --list

  directory="$work/no-steps"
  make_fixture "$directory"
  sed '/clean-checkout:/d' "$directory/README.md" > "$directory/README.new"
  mv "$directory/README.new" "$directory/README.md"
  commit_fixture "$directory" "Remove the step markers"
  expect "a README without steps is refused" refuse "README.md lists no steps"

  if [ "$failures" -ne 0 ]; then
    echo "self-test: $failures case(s) failed"
    return 1
  fi
  echo "self-test: every case behaved"
}

if [ "$self_test" -eq 1 ]; then
  self_test
  exit $?
fi

# ---------------------------------------------------------------------------------------------
# The check.

if [ -z "$repo" ]; then
  repo="$(git -C "$script_directory" rev-parse --show-toplevel)"
fi

temporary="${TMPDIR:-/tmp}"
root="$(mktemp -d "${temporary%/}/kalareach-clean-checkout.XXXXXX")"
# A Unix socket's address is at most 104 bytes on macOS and 108 on Linux, and the tests make their
# runtime directories under the temporary directory, so the steps get a short one.
step_tmp="$(mktemp -d /tmp/kr-clean.XXXXXX)"
cleanup() {
  if [ "$keep" -eq 1 ]; then
    say "kept $root and $step_tmp"
  else
    chmod -R u+w "${root:?}" 2>/dev/null || true
    rm -rf "${root:?}" "${step_tmp:?}"
  fi
}
trap cleanup EXIT
mkdir -p "$root/home" "$root/cargo" "$root/pnpm-store"
clone="$root/clone"

environment=("HOME=$root/home" "CARGO_HOME=$root/cargo" "TMPDIR=$step_tmp"
  "pnpm_config_store_dir=$root/pnpm-store" "COREPACK_ENABLE_DOWNLOAD_PROMPT=0"
  "KR_CLEAN_CHECKOUT_ROOT=$root")
if [ -d "$rustup_home" ]; then
  environment+=("RUSTUP_HOME=$rustup_home")
fi
for name in "${inherited[@]}"; do
  if [ -n "${!name:-}" ]; then
    environment+=("$name=${!name}")
  fi
done

clean() {
  env -i "${environment[@]}" "$@"
}

# The commit is resolved where it names something, in the repository it comes from when that is
# a local one, so a HEAD that no branch holds is still the HEAD that was meant.
if [ -e "$repo" ] && resolved="$(clean git -C "$repo" rev-parse --verify --quiet "$commit^{commit}")"; then
  commit="$resolved"
fi
say "cloning $commit from $repo into $clone"
clean git init -q "$clone"
clean git -C "$clone" remote add origin "$repo"
clean git -C "$clone" fetch -q --tags origin '+refs/heads/*:refs/remotes/origin/*'
if clean git -C "$clone" cat-file -e "$commit^{commit}" 2>/dev/null; then
  commit="$(clean git -C "$clone" rev-parse --verify "$commit^{commit}")"
else
  # A commit no branch holds, or a name only the other repository resolves.
  clean git -C "$clone" fetch -q origin "$commit"
  commit="$(clean git -C "$clone" rev-parse --verify "FETCH_HEAD^{commit}")"
fi
clean git -C "$clone" checkout -q --detach "$commit"
say "checking $commit"

refused=0
refuse_records "$clone" || refused=1
refuse_messages "$clone" "${commits:-$commit}" || refused=1
refuse_links "$clone" || refused=1
if [ "$refused" -ne 0 ]; then
  say "refused $commit"
  exit 1
fi

if [ "$run_steps" -eq 0 ]; then
  say "no step was asked for"
  exit 0
fi

if ! steps="$(read_steps "$clone")"; then
  say "refused: README.md's step lists could not be read"
  exit 1
fi
if [ -z "$steps" ]; then
  say "refused: README.md lists no steps"
  exit 1
fi
groups="$(printf '%s\n' "$steps" | cut -f1 | uniq | tr '\n' ',')"
for group in $(printf '%s' "$only,$skip" | tr ',' ' '); do
  if ! printf ',%s' "$groups" | grep -q ",$group,"; then
    say "refused: --only or --skip names no group README.md lists: $group (README.md lists ${groups%,})"
    exit 2
  fi
done

failed=0
previous=""
index=0
while IFS="$(printf '\t')" read -r group command; do
  if ! selected "$group"; then
    continue
  fi
  if [ "$group" != "$previous" ]; then
    previous="$group"
    index=0
  fi
  index=$((index + 1))
  if [ "$list_steps" -eq 1 ]; then
    echo "$group.$index: $command"
    continue
  fi
  echo "== step $group.$index: $command"
  started="$SECONDS"
  rc=0
  # A step reads nothing from this script's input, which holds the steps still to come.
  (cd "$clone" && clean bash -c "$command" < /dev/null) || rc=$?
  echo "== step $group.$index exit $rc ($((SECONDS - started)) s)"
  if [ "$rc" -ne 0 ]; then
    failed=1
    if [ "$keep_going" -eq 0 ]; then
      break
    fi
  fi
done <<EOF
$steps
EOF

if [ "$list_steps" -eq 1 ]; then
  exit 0
fi
if [ "$failed" -ne 0 ]; then
  say "one or more steps failed at $commit"
  exit 1
fi
say "$commit passed from a clean checkout"
