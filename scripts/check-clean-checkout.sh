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
# and every step then runs in an environment reduced to the variables `inherited` lists below, with
# a home directory, a Cargo home, a pnpm store and a temporary directory of its own, so no cache,
# build output, installed package or setting this machine has collected can stand in for what the
# repository provides. PATH holds the system directories and the directories the programs in
# `tools` were found in, and the run starts by printing each program's path and SHA-256. The
# toolchains are used as they are installed: rustup's own directory is kept, and
# rust-toolchain.toml picks the toolchain from it. On macOS the fresh home directory gets a keychain
# of its own as its default, removed with it, so nothing a step runs finds no keychain and asks the
# person at the machine for one; the run fails if SecurityAgent opened a dialog while it ran.
#
# Before any step runs, the clone is refused when:
#
#   - a tracked file names a working record that is kept outside the repository: a task or a
#     decision identifier, a numbered review, a record file by its name, the phrases that name the
#     notes a task is dispatched with and the rulings made for it, the specification, the ledger,
#     the goal or the records directory by name, or a path on a named volume. A word the product
#     uses in its own sense is not a record, so each pattern matches a record's own form and
#     nothing wider;
#   - a commit in the range, which is the commit's whole history unless --commits names one, has a
#     message of more than one line: a body or a trailer, whether or not a blank line precedes it;
#   - a relative link in a tracked Markdown file names a path the tree does not have. The rule is
#     read from the text, not from rendered Markdown: every `](` followed by a destination, and
#     every `[label]: destination` definition, is a link, in a code example as much as anywhere,
#     so an example names a path that exists or uses an absolute URL.
#
# Each pattern in `record_patterns` is written so that its own text does not match it, which is
# what lets this file pass its own check.
#
# Then the steps run. README.md gives them as fenced blocks, each after a line
# `<!-- clean-checkout: <group> -->`; every line of a block is one step, a line ending in a
# backslash continues on the next, and a line that starts with `#` is a comment. A block that is
# never closed, or that ends inside a continued line, is refused. A step runs with bash in the
# clone's root, with nothing on its standard input, groups and steps in README.md's order, and the
# run stops at the first step that fails unless --keep-going is given. KR_CLEAN_CHECKOUT_ROOT names
# the run's directory to every step.
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
  '(^|[^[:alnum:]])[Rr]eview [0-9]+'
  '-hand[o]ff(-archive)?\.md'
  '-review-[0-9]+\.md'
  '-dispatch-[0-9]+\.md'
  'dispatch[ ]note'
  'lead[ ]ruling'
  'kalareach\.md'
  'kalareach-ledge[r]'
  'kalareach-goa[l]'
  'kalareach-artifact[s]'
  "(^|[^[:alnum:]_./-])/Volume[s]/[^/[:space:]\"'*)\`\\]"
)

# The programs README.md's list runs. A step's PATH holds the directories these are found in, in
# the order this script's PATH has them, and then the system directories.
tools=(bash git python3 cargo rustup rustc node pnpm corepack cc c++ cmake make patch tar curl
  pkg-config llvm-config msgfmt pwsh zsh fish podman)
system_path=/usr/bin:/bin:/usr/sbin:/sbin

# The variables a step inherits from the environment this script was started in. Everything else
# is left behind. The Cargo ones change how much a build keeps and how many jobs it runs, and the
# libclang ones where a binding generator finds its library, never what is built.
inherited=(USER LOGNAME SHELL TERM LANG LC_ALL LC_CTYPE TZ XDG_RUNTIME_DIR DEVELOPER_DIR SDKROOT
  CARGO_BUILD_JOBS CARGO_INCREMENTAL CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG
  CARGO_NET_GIT_FETCH_WITH_CLI LIBCLANG_PATH LLVM_CONFIG_PATH)

rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"

say() {
  printf 'check-clean-checkout: %s\n' "$*"
}

# Returns success when a word is one member of a comma-separated list.
member() {
  local word="$1" list="$2" item items=()
  IFS=, read -r -a items <<< "$list"
  for item in ${items[@]+"${items[@]}"}; do
    if [ "$item" = "$word" ]; then
      return 0
    fi
  done
  return 1
}

sha256() {
  if command -v shasum > /dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

# ---------------------------------------------------------------------------------------------
# The checks, on a clone that already exists.

refuse_records() {
  local clone="$1" arguments=() pattern hits rc=0
  for pattern in "${record_patterns[@]}"; do
    arguments+=(-e "$pattern")
  done
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
  # The raw message, because a subject folds the first paragraph's lines into one and a body
  # begins only after a blank line: a second line with no blank line before it is neither.
  found="$(clean git -C "$clone" log --format='%H%x1f%B%x1e' "$range" | awk '
    BEGIN { RS = "\036"; FS = "\037"; bad = 0 }
    {
      sub(/^\n+/, "", $1)
      if ($1 == "") next
      message = $2
      sub(/[ \t\n]+$/, "", message)
      count = split(message, lines, "\n")
      if (count <= 1) next
      kind = "a trailer"
      for (i = 2; i <= count; i++) {
        if (lines[i] != "" && lines[i] !~ /^[A-Za-z0-9-]+: /) kind = "a body"
      }
      printf "  %s %s: %s\n", substr($1, 1, 12), kind, lines[1]
      bad = 1
    }
    END { exit bad }
  ')" || {
    say "refused: commits in $range carry more than one line:"
    printf '%s\n' "$found"
    return 1
  }
  say "every commit in $range is one subject line"
}

# Prints each relative link in a tracked Markdown file whose path the tree does not have, and
# fails when there is one.
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

scheme = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
definition = re.compile(r"(?m)^ {0,3}\[[^\]\n]+\]:[ \t]*\n?[ \t]*(<[^>\n]*>|\S+)")


def destination(text, index):
    """Reads the destination that starts at index, delimited the way CommonMark delimits one."""
    while index < len(text) and text[index] in " \t\n":
        index += 1
    if text.startswith("<", index):
        end = text.find(">", index)
        if end < 0 or "\n" in text[index:end]:
            return None
        return text[index + 1 : end]
    start, depth = index, 0
    while index < len(text):
        character = text[index]
        if character == "\\" and index + 1 < len(text):
            index += 2
            continue
        if character.isspace() or ord(character) < 0x20:
            break
        if character == "(":
            depth += 1
        elif character == ")":
            if depth == 0:
                break
            depth -= 1
        index += 1
    return text[start:index]


broken = 0
for path in sorted(p for p in tracked if p.endswith(".md")):
    with open(os.path.join(root, path), encoding="utf-8", errors="replace") as handle:
        text = handle.read()
    found = []
    for match in re.finditer(r"\]\(", text):
        target = destination(text, match.end())
        if target is not None:
            found.append((match.start(), target))
    for match in definition.finditer(text):
        found.append((match.start(), match.group(1).strip("<>")))
    for offset, target in found:
        if not target or target.startswith(("#", "//")) or scheme.match(target):
            continue
        named = target.split("#", 1)[0].split("?", 1)[0]
        named = urllib.parse.unquote(re.sub(r"\\(.)", r"\1", named))
        if not named:
            continue
        if named.startswith("/"):
            resolved = os.path.normpath(named.lstrip("/"))
        else:
            resolved = os.path.normpath(os.path.join(os.path.dirname(path), named))
        if resolved in tracked or resolved in directories or resolved == ".":
            continue
        print(f"  {path}:{text.count(chr(10), 0, offset) + 1}: {target}")
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
    group = named.group(1)
    while index < len(lines) and not lines[index].strip():
        index += 1
    opened = fence.match(lines[index]) if index < len(lines) else None
    if not opened:
        sys.exit(f"README.md: the group {group} is not followed by a fenced block")
    character, length = opened.group(1)[0], len(opened.group(1))
    index += 1
    pending = ""
    closed = False
    while index < len(lines):
        line = lines[index].rstrip()
        index += 1
        stripped = line.strip()
        if len(stripped) >= length and set(stripped) == {character}:
            closed = True
            break
        if not pending and stripped.startswith("#"):
            continue
        if line.endswith("\\"):
            pending += line[:-1].rstrip() + " "
            continue
        command = (pending + line).strip()
        pending = ""
        if command:
            print(f"{group}\t{command}")
    if not closed:
        sys.exit(f"README.md: the group {group}'s block is not closed")
    if pending:
        sys.exit(f"README.md: the group {group}'s block ends inside a continued line")
PYTHON
}

# Returns success when a group is selected by --only and --skip.
selected() {
  local group="$1"
  if [ -n "$only" ] && ! member "$group" "$only"; then
    return 1
  fi
  if [ -n "$skip" ] && member "$group" "$skip"; then
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

# Creates a fixture repository with a README whose steps check the environment they run in,
# documents whose links are sound in every form the check reads, and one commit.
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
# a note that ends with a backslash, which is still a note \
test \
  -f README.md
```
EOF
  cat > "$directory/docs/guide.md" <<'EOF'
# Guide

Back to [the README](../README.md), a [reference] link, and a destination on the next line: [the
README again](
../README.md).

A destination with parentheses: [a page](a(b).md). One in angle brackets: [a page](<with space.md>).
One encoded: [a page](with%20space.md).

```text
An example that links: [the guide](guide.md)
```

[reference]:
  ../README.md
EOF
  : > "$directory/docs/a(b).md"
  : > "$directory/docs/with space.md"
  fixture_git -C "$directory" add -A
  fixture_git -C "$directory" commit -q -m "Start the fixture"
}

commit_fixture() {
  local directory="$1" message="$2"
  fixture_git -C "$directory" add -A
  fixture_git -C "$directory" commit -q --cleanup=verbatim -m "$message"
}

# Replaces a fixture's README with the given text and commits it.
replace_readme() {
  printf '%s\n' "$2" > "$1/README.md"
  commit_fixture "$1" "Replace the README"
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
  expect "the run records each program it found" pass "tool git: /"
  expect "an unknown group is refused" refuse "names no group README.md lists" --only nosuch
  expect "a group name is not a pattern" refuse "names no group README.md lists" --only 'check.*'
  expect "a selection of nothing is refused" refuse "select no step" --skip setup,check

  directory="$work/relative"
  make_fixture "$directory"
  expect "a relative repository path is cloned from where it points" pass "== step check.4 exit 0" \
    --repo "$(cd "$work" && pwd)/relative/../relative"
  (
    cd "$work"
    if bash "$script_path" --repo relative --no-steps > "$work/relative.log" 2>&1; then
      echo "self-test: a path relative to the caller is resolved ok"
    else
      echo "self-test: a path relative to the caller is resolved FAILED"
      sed 's/^/    /' "$work/relative.log"
      exit 1
    fi
  ) || failures=$((failures + 1))

  directory="$work/detached"
  make_fixture "$directory"
  echo "more" >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Extend the guide"
  fixture_git -C "$directory" checkout -q --detach HEAD
  fixture_git -C "$directory" branch -q -D main
  expect "a commit that no branch holds is fetched" pass "== step check.4 exit 0"

  local name planted
  for planted in \
    "task=see T-""123 for the reason" \
    "decision=as D-""456 decided" \
    "numbered-review=see review ""2 for the reason" \
    "notes=tasks/x-hand""off.md" \
    "review-file=reviews/x-review-""2.md" \
    "dispatch-file=tasks/x-claude-dispatch-""3.md" \
    "dispatch-note=the dispatch"" note says so" \
    "ruling=as the lead"" ruling says" \
    "specification=the kalareach"".md specification" \
    "ledger=kalareach-""ledger.md" \
    "goal=kalareach-""goal.md" \
    "records=kalareach-""artifacts/logs/run.log" \
    "volume=/Vol""umes/Work/notes.txt" \
    "volume-underscore=/Vol""umes/_work/notes.txt"; do
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
    echo "macOS keeps it on /System/Volumes/Data, and a path under \"/Vol""umes/\" is removable."
    echo 'A Rust string "/Vol''umes/\" and a JSON one \"/Vol''umes/\" name no volume.'
    echo "SHA-256, UTF-8, KR-PERF-001 and PORT""-123 are not records."
    echo "Pre""view 3 is a screen, and a review of the diff is not numbered."
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

  directory="$work/commit-second-line"
  make_fixture "$directory"
  echo "more" >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Extend the guide
Signed-off-by: fixture <fixture@example.invalid>"
  expect "a trailer with no blank line before it is refused" refuse "a trailer: Extend the guide" \
    --no-steps
  echo "more" >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Extend the guide again
and say why on the next line"
  expect "a second line with no blank line before it is refused" refuse \
    "a body: Extend the guide again" --no-steps

  directory="$work/broken-link"
  make_fixture "$directory"
  printf 'See [the missing page](\n  missing.md).\n' >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Link a page that is not there"
  expect "a relative link to a missing path is refused, across a line" refuse \
    "docs/guide.md:16: missing.md"

  directory="$work/example-link"
  make_fixture "$directory"
  printf '```text\n[an example](missing-example.md)\n```\n' >> "$directory/docs/guide.md"
  commit_fixture "$directory" "Add an example that links nowhere"
  expect "a link in a code example counts" refuse "missing-example.md"

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

  directory="$work/comment-backslash"
  make_fixture "$directory"
  replace_readme "$directory" '<!-- clean-checkout: check -->

```bash
# a note that ends with a backslash \
false
true
```'
  expect "a note ending in a backslash does not hide the next step" refuse "== step check.1 exit 1"

  directory="$work/unclosed"
  make_fixture "$directory"
  replace_readme "$directory" '<!-- clean-checkout: check -->

```bash
true'
  expect "a block that is never closed is refused" refuse "block is not closed"

  directory="$work/dangling"
  make_fixture "$directory"
  replace_readme "$directory" '<!-- clean-checkout: check -->

```bash
true \
```'
  expect "a block that ends inside a continued line is refused" refuse "inside a continued line"

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
elif [ -e "$repo" ]; then
  repo="$(cd "$repo" && pwd)"
fi

temporary="${TMPDIR:-/tmp}"
root="$(mktemp -d "${temporary%/}/kalareach-clean-checkout.XXXXXX")"
# A Unix socket's address is at most 104 bytes on macOS and 108 on Linux, and the tests make their
# runtime directories under the temporary directory, so the steps get a short one.
step_tmp="$(mktemp -d /tmp/kr-clean.XXXXXX)"
mkdir -p "$root/home" "$root/cargo" "$root/pnpm-store"
clone="$root/clone"
started_at="$(date '+%Y-%m-%d %H:%M:%S')"

step_path=""
add_directory() {
  case ":$step_path:" in
    *":$1:"*) ;;
    *) step_path="${step_path:+$step_path:}$1" ;;
  esac
}
tool_directories=()
for tool in "${tools[@]}"; do
  found="$(command -v "$tool" 2>/dev/null || true)"
  if [ "${found#/}" != "$found" ]; then
    tool_directories+=("$(dirname "$found")")
  fi
done
path_entries=()
IFS=: read -r -a path_entries <<< "$PATH"
for entry in ${path_entries[@]+"${path_entries[@]}"}; do
  for directory in ${tool_directories[@]+"${tool_directories[@]}"}; do
    if [ "$entry" = "$directory" ]; then
      add_directory "$entry"
    fi
  done
done
system_entries=()
IFS=: read -r -a system_entries <<< "$system_path"
for entry in "${system_entries[@]}"; do
  add_directory "$entry"
done

environment=("PATH=$step_path" "HOME=$root/home" "CARGO_HOME=$root/cargo" "TMPDIR=$step_tmp"
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

keychain=""
cleanup() {
  if [ "$keep" -eq 1 ]; then
    say "kept $root and $step_tmp"
    return
  fi
  if [ -n "$keychain" ]; then
    clean security delete-keychain "$keychain" 2>/dev/null || true
  fi
  chmod -R u+w "${root:?}" 2>/dev/null || true
  rm -rf "${root:?}" "${step_tmp:?}"
}
trap cleanup EXIT

for tool in "${tools[@]}"; do
  found="$(PATH="$step_path"; command -v "$tool" 2>/dev/null || true)"
  if [ "${found#/}" != "$found" ]; then
    say "tool $tool: $found sha256 $(sha256 "$found")"
  else
    say "tool $tool: not found"
  fi
done

# The account's own keychain settings are read before and after, and a change to them stops the
# run once they are put back: the fresh home directory's keychain is its own or it is nothing.
if [ "$(uname -s)" = Darwin ]; then
  own_default="$(security default-keychain -d user 2>/dev/null | tr -d ' "' || true)"
  own_list="$(security list-keychains -d user 2>/dev/null | tr -d ' "' || true)"
  keychain="$root/home/Library/Keychains/login.keychain-db"
  mkdir -p "$root/home/Library/Keychains"
  clean security create-keychain -p "" "$keychain"
  clean security set-keychain-settings "$keychain"
  clean security default-keychain -d user -s "$keychain"
  clean security list-keychains -d user -s "$keychain"
  if [ "$(security default-keychain -d user 2>/dev/null | tr -d ' "' || true)" != "$own_default" ] \
    || [ "$(security list-keychains -d user 2>/dev/null | tr -d ' "' || true)" != "$own_list" ]; then
    if [ -n "$own_default" ]; then
      security default-keychain -d user -s "$own_default"
    fi
    # shellcheck disable=SC2086
    security list-keychains -d user -s $own_list
    say "refused: this account's own keychain settings changed when the fresh home directory's"
    say "keychain was made its default; they have been put back"
    exit 1
  fi
  say "the fresh home directory has a keychain of its own as its default"
fi

# macOS names every SecurityAgent dialog in its log, and a run that opened one fails.
security_agent_opened() {
  local entries
  if [ "$(uname -s)" != Darwin ]; then
    return 1
  fi
  entries="$(log show --start "$started_at" --predicate 'process == "SecurityAgent"' \
    --style compact 2>/dev/null | grep -F SecurityAgent || true)"
  if [ -n "$entries" ]; then
    say "refused: SecurityAgent opened a dialog while this run ran:"
    printf '%s\n' "$entries" | head -20 | sed 's/^/  /'
    return 0
  fi
  return 1
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
  security_agent_opened || true
  say "refused $commit"
  exit 1
fi

if [ "$run_steps" -eq 0 ]; then
  if security_agent_opened; then
    exit 1
  fi
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
groups="${groups%,}"
for list in "$only" "$skip"; do
  names=()
  IFS=, read -r -a names <<< "$list"
  for group in ${names[@]+"${names[@]}"}; do
    if ! member "$group" "$groups"; then
      say "refused: --only or --skip names no group README.md lists: $group (README.md lists $groups)"
      exit 2
    fi
  done
done
chosen=0
while IFS="$(printf '\t')" read -r group command; do
  if selected "$group"; then
    chosen=$((chosen + 1))
  fi
done <<EOF
$steps
EOF
if [ "$chosen" -eq 0 ]; then
  say "refused: --only and --skip together select no step"
  exit 2
fi

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

if security_agent_opened; then
  failed=1
fi
if [ "$list_steps" -eq 1 ] && [ "$failed" -eq 0 ]; then
  exit 0
fi
if [ "$failed" -ne 0 ]; then
  say "one or more steps failed at $commit"
  exit 1
fi
say "$commit passed from a clean checkout"
