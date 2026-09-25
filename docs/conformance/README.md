# KalaReach conformance report

The conformance report answers one question per identifier of the specification: which tests prove
it, and what each of them came to on this platform, in this run. It writes the answer as one JSON
result keyed by identifier, with the command that reproduces each test and the exact versions the
run was taken at.

There is no index of identifiers anywhere in the repository. A test says which rows it proves, in a
comment, in its name or in a case table, and the report reads those at run time. Moving or renaming
a test moves its key with it, and a row nobody keys shows up as one with no test.

## Running it

```sh
scripts/run-conformance.sh                    # every group this platform runs
scripts/run-conformance.sh --group rust       # one group; repeat --group for several
scripts/run-conformance.sh --all-terminals    # every group, and then section 27's terminal matrix
```

The script fetches what the applications group needs, installs the TypeScript packages when that
group runs, builds the `kr-conformance` binary in `tests/conformance` and runs it. The result is
`<evidence>/conformance/result.json`, and each step's log is under `<evidence>/conformance/logs/`.

The evidence directory is `KR_TEST_ARTIFACTS_DIR`, or a new directory under the platform's temporary
directory when that is not set. The report refuses one outside the temporary directory (`/tmp` or
`TMPDIR` on Unix, the user's temporary directory on Windows) before it creates anything, because
section 21 keeps test artefacts there. It refuses a path with `..` in it as well, and resolves what
it made to check it again. Every step runs with `KR_TEST_ARTIFACTS_DIR` naming the same directory,
so what a test records beside its verdict, such as a performance figure, lands with the result.

Each run takes an evidence directory of its own. The report makes `<evidence>/conformance/` new for
the run, and refuses a directory that already holds one, so no log, test report or result of an
earlier run can be read as this run's.

The exit status is 0 when the run passed, 1 when it ran and did not, and 2 when it was refused
before running anything. A run passes when no identifier failed, every step exited 0 and its output
could be read, no test failed that names no identifier, and every record a test wrote for the report
could be read.

### Groups

| Group | Linux | macOS | Windows |
| --- | --- | --- | --- |
| `rust` | `cargo test --locked --workspace --no-fail-fast` | The same, leaving out by name the cases the landing workflow's macOS job leaves out (podman, a second filesystem, the platform credential store, a built shell package), each with its reason, and the two timed cases in a step of their own | The suites qualified on Windows, one command each, as the landing workflow's Windows job runs them. The case that writes the credential store runs where `KR_TEST_PLATFORM_SECRET_STORE=1` is set, as the conformance workflow's runner sets it |
| `end-to-end` | The suites `scripts/end-to-end.sh` runs, one test at a time, the network suite with its ignored tests | As on Linux | Not run: these drive Unix pseudo-terminals |
| `performance` | The measurements `scripts/performance.sh` takes, and the release-build terminal and transport measurements | As on Linux | Not run: these drive Unix pseudo-terminals |
| `typescript` | Each package's `test` script with vitest's JSON report, and the report's own TypeScript reading test | As on Linux | Not run |
| `applications` | The application matrix | As on Linux | Not run: each program is recorded with its reason |

The report's own tests check the `end-to-end` and `performance` lists against the two scripts, and
the macOS and Windows plans against the landing workflow's jobs, so the report cannot drift from
them unnoticed.

Every `cargo test` step that keeps each test's output captured runs with `--show-output`, which
prints what every passing test wrote under its name. A step that shows the output as it is written,
with `--nocapture`, keeps its script's command. Before a step runs, its tests are built and listed
through Cargo, package by package, and every test binary the build made then has to be run and
read: a listing that fails, a binary the log never ran, and a log that cannot be read are each the
step's error. A target whose manifest
gives it a harness of its own (`harness = false`) is a program that prints neither a list nor
verdicts: it is never named in a listing, it is run with the step, its exit status is the step's,
and a comment on it is a reference.

A test that no selected group runs on this platform is reported as not run, with the reason. It is
never reported as passed.

### The terminal matrix

`--all-terminals` runs every group this platform runs, and then takes section 27's terminal matrix:
iTerm2, Terminal.app, Ghostty, WezTerm, Windows Terminal, a VTE-based Linux terminal and the VS Code
terminal. Those terminals are qualified on the terminal matrix hosts and virtual machines, not by
this report, so the result records each one as not run, with that reason, the report names each on
its output, and the run exits 1. `--all-terminals` takes no `--group`.

## How a test names what it proves

### The identifiers

The report accepts three forms, and only these:

| Form | What it names |
| --- | --- |
| `KR-REQ-SS.II` | A requirement row: a two-digit section of the specification, 01 to 30, and a two-digit row, 01 or later |
| `KR-ACC-NNN` | A row of section 21's acceptance table, `KR-ACC-001` to `KR-ACC-035` |
| `KR-PERF-NNN` | A row of section 27's performance table, `KR-PERF-001` to `KR-PERF-010` |

A requirement row can be followed by more rows written short, joined by a comma, "and", "or" or a
slash: `KR-REQ-09.12, 09.13` names two rows. Nothing else continues a list.

Anything else that starts like an identifier is refused, and a refused mention stops the report
before it runs anything, naming the file and the line. That covers a bare section (`KR-REQ-09`), a
number of the wrong length, a row past the end of its table (`KR-ACC-036`), a bare family name and
any other family written the same way. Read loosely, an almost-right key would count a test for a
row that does not exist.

### Rust

| Form | What it keys |
| --- | --- |
| A documentation comment on a test function, or a plain comment directly above it with no blank line between | That test |
| A comment inside a test function's body | That test |
| A test function whose name spells an identifier in snake case: `kr_req_11_07_...`, `kr_acc_004_...` | That test. A name that spells no accepted form is only a name |
| A module comment (`//!`) of test code | Every test in that module and the modules inside it |
| In test code, a comment block with a blank line after it | Every test from there to the next such block, or the end of the module |
| In test code, a comment on a function | Every test of the same target whose body calls that function, where the report proves from the target's own source that the compiler resolves the call to it: through module definitions, `crate`, `self` and `super`, a `use` that keeps the item's own name, and globs, each judged by who may name what it brings in. A renaming `use`, a name or glob the calling body brings in for itself, a module whose macros make items, a glob it cannot follow and a visibility it cannot work out all stop it, and a call it cannot prove keys nothing, so the function's identifiers stay references rather than become a key the compiler would not make |
| A `covers` field of a `const` or `static` case table | Every test of the same package whose body names the table |

Test code is a test or bench target, or a module compiled under `cfg(test)`. A comment on product
code (a module's documentation, a function, a constant) is a reference: it is listed with the
identifier and it is never a test.

The report reads each target's crate root as Cargo describes it and follows every `mod`
declaration, `#[path]` included, so a test is named exactly as the test harness names it.

### Case tables kept as data

| Files | Run by |
| --- | --- |
| `tests/shells/*/*/case.json` | `kr-shell-integration --test qualification every_case_holds_against_the_package_it_names` |
| `fixtures/shell-bridge/*.json` | `kr-shell-integration --test harness every_committed_scenario_holds_against_the_contract` |

Each file's `covers` field keys the test that runs its cases. The report checks that the test exists
and refuses to run when it does not.

### TypeScript

The report reads TypeScript with the compiler the packages already depend on
(`tests/conformance/typescript-facts.mjs`), so a comment marker inside a string, a template or JSX
text is never taken for a comment.

- A comment inside a test's body keys that test.
- A comment directly above a test call, with no blank line between, keys that test; one above a
  `describe` keys every test inside it. A comment of several `//` lines is one comment.
- A comment before the file's first statement keys every test in the file.
- A test's title keys it, and a `describe`'s title keys every test inside it.
- Any other comment is a reference.

A test declared once for a table of cases (`it.each`, `test.each`) is as many tests as the table
has rows. Each is recorded under the title the run gave it, with a command that runs that one row.
Rows that share a title are told apart by their place among the rows with that title, and the
command that selects the title runs them all.

### Tests another toolchain builds

| Files | Why the report does not run them |
| --- | --- |
| `apps/companion/native/android/src/test/**` | Android unit tests: the Android build runs them |
| `apps/companion/native/ios/Tests/**` | iOS unit tests: Xcode runs them |
| `apps/companion/e2e/**` | Playwright over the built interface: the landing workflow's companion job runs it |

A comment in a Kotlin or Swift file of these lanes keys that file as a whole, which the report
shows as not built. A Playwright test is keyed as any TypeScript test is, and shown as not run with
the lane's reason.

## Outcomes and verdicts

Each keyed test has one outcome on this platform:

| Outcome | Meaning |
| --- | --- |
| `passed` | A step ran it and it passed |
| `failed` | A step ran it and it failed, or its binary's output could not be read against the summary the harness printed |
| `ignored` | Every step that listed it left it out, with the reason its `#[ignore]` gives |
| `not_run` | No step of this run ran it here: a step's own flags left it out, no selected group runs its target on this platform, another toolchain builds it, or it returned early and said why. The reason says which |
| `not_built` | A step ran its target and this platform's build of it has no such test |
| `known_difference` | It ran and held what the profile defines, and it recorded that the application it is about reads the same thing differently |

A test that returns early, because what it needs is absent, passes as far as the harness is
concerned. The suites say so on a line that starts `skipped:`, `skipping:` or `not exercised`, or
that names the suite and then says `: skipped, because`, and the report finds that line in what the
test wrote and reports the test as not run, with the line as its reason. A line of that kind the
report cannot give to one test makes its binary's output unreadable, which fails the step.

A test that several steps list takes the strongest outcome among them: failed, then passed, then
ignored, then not run, then not built. A test keyed to one identifier twice, by its own comment and
by its module's, is recorded once, by its own.

Each identifier has one verdict: `failed` when any of its tests failed, `passed` when at least one
passed and none failed, `known_difference` when none passed or failed and at least one is a known
difference, and `not_run` otherwise. An ignored or skipped test never counts as a pass, and neither
does a known difference.

A known difference is written by the test itself, to `known-differences.jsonl` in the evidence
directory, when a documented property of the profile makes an application read something otherwise.
The result lists each one in a section of its own, with both readings.

A performance test that records its figure under `KR_TEST_ARTIFACTS_DIR`, as a Markdown section
headed by the identifier it measures (`## KR-PERF-007 ...`), has that figure attached to the
identifier. Only what a file gained during this run is read, so a directory kept from an earlier
run lends the result no figures.

## The result

The result's schema is `kalareach.conformance/1`, and this section is where it is stated for every
KalaReach repository that publishes conformance results. Fields whose value would be empty or absent
are left out of a test's record: `reason`, `command`, `needs` and `known_differences`, and an
identifier's `references` and `figures`.

```json
{
  "schema": "kalareach.conformance/1",
  "repository": "kalareach",
  "run": {
    "started": "2026-09-25T10:00:00Z",
    "finished": "2026-09-25T10:41:07Z",
    "platform": "linux",
    "system": { "os": "linux", "release": "Ubuntu 24.04.3 LTS, Linux 6.11.0", "arch": "x86_64", "target": "x86_64-unknown-linux-gnu" },
    "commit": { "id": "<40 hex digits>", "modified": false },
    "toolchain": { "rustc": "rustc 1.97.1 (...)", "cargo": "cargo 1.97.1 (...)", "node": "v22.23.1", "pnpm": "11.14.0" },
    "terminal_profile": { "profile": "kr-vt/1", "term": "xterm-256color" },
    "packages": [ { "name": "kr-term", "version": "0.1.0" }, { "name": "@kalareach/protocol", "version": "0.34.0" } ],
    "applications": [ { "id": "neovim", "version": "0.12.5", "status": "installed", "url": "https://...", "sha256": "...", "build": "release", "reason": null } ],
    "selection": ["rust", "end-to-end", "performance", "typescript", "applications"],
    "all_terminals": false,
    "evidence_directory": "/tmp/kr-test-artifacts"
  },
  "steps": [
    { "number": 1, "group": "rust", "what": "the workspace's tests", "command": "cargo test --locked --workspace --no-fail-fast -- --show-output", "needs": [], "exit": 0, "seconds": 812, "log": "conformance/logs/01-the-workspace-s-tests.log", "error": null }
  ],
  "identifiers": {
    "KR-ACC-004": {
      "family": "acceptance",
      "verdict": "passed",
      "counts": { "passed": 19, "failed": 0, "ignored": 0, "not_run": 0, "not_built": 0, "known_difference": 1 },
      "tests": [
        {
          "test": "kr-conformance --test applications neovim::a_click_in_sgr_form_moves_the_cursor_to_the_wide_character_it_was_on",
          "source": "tests/conformance/tests/applications/neovim.rs:238",
          "keyed_by": "attached_comment",
          "outcome": "passed",
          "runs": [ { "step": 1, "outcome": "ignored", "reason": "runs the pinned applications; ..." }, { "step": 30, "outcome": "passed" } ],
          "command": "cargo test --locked -p kr-conformance --test applications -- --ignored --test-threads=1 --exact neovim::a_click_in_sgr_form_moves_the_cursor_to_the_wide_character_it_was_on",
          "needs": ["KR_CONFORMANCE_APPLICATIONS"]
        }
      ]
    },
    "KR-PERF-004": {
      "family": "performance",
      "verdict": "not_run",
      "counts": { "passed": 0, "failed": 0, "ignored": 0, "not_run": 0, "not_built": 0, "known_difference": 0 },
      "tests": [],
      "references": [ { "source": "scripts/performance.sh:4", "context": "a script" } ]
    }
  },
  "failures_outside_identifiers": [],
  "known_differences": [
    { "identifiers": ["KR-ACC-004", "KR-REQ-27.04"], "package": "kr-conformance", "target": "applications", "test": "neovim::...", "subject": "a skin tone (...)", "application": "Neovim draws it as one cluster of 2 cells", "grid": "section 8's per-codepoint widths give it 4 cells", "observed": "..." }
  ],
  "problems": [],
  "warnings": [],
  "summary": { "identifiers": 652, "passed": 598, "failed": 0, "known_difference": 0, "not_run": 54, "known_differences": 2, "tests": { "passed": 4012, "failed": 0, "ignored": 31, "not_run": 188, "not_built": 22, "known_difference": 2 }, "failed_steps": [] }
}
```

| Field | Meaning |
| --- | --- |
| `run` | What was tested, with what, where: the commit (and whether tracked files differed from it), the toolchain, the machine, the terminal profile from its committed fixture, every package's version, the applications and how each was installed, the groups selected, and whether the whole terminal matrix was asked for (`all_terminals`) |
| `steps` | Every command the run ran, as run, with its exit status, how long it took and its log, relative to the evidence directory. `needs` names the variables a step reads from the environment |
| `identifiers` | Every identifier a test or a reference names and, in a run of every group, every row of section 21's and section 27's tables whether named or not |
| `tests[].test` | The package, target and test name, or the TypeScript file and its titles as the run gave them, joined by ` > ` |
| `tests[].source` | Where the key is written |
| `tests[].keyed_by` | `attached_comment`, `comment_inside`, `test_name`, `section_comment`, `called_function`, `module_comment`, `case_table`, `title` or `file_comment` |
| `tests[].command` | The command that reproduces the test on its own, narrowed from the step that ran it |
| `tests[].runs` | Each step that listed the test and what it came to there |
| `references` | Mentions that key no test, with what they are on |
| `figures` | The figures the identifier's measurements recorded in this run |
| `failures_outside_identifiers` | Tests that failed in a step and name no identifier; any one fails the run |
| `known_differences` | Every known difference, with the identifiers of the test that recorded it |
| `terminals` | Present when `--all-terminals` asked for section 27's terminal matrix: each terminal, its outcome and why. A terminal that did not pass fails the run |
| `problems` | What makes the result incomplete, such as a record a test wrote that could not be read; any one fails the run |
| `warnings` | What the report noted and carried on past, such as a declared module whose file is not there |

The result carries only paths relative to the repository or to the evidence directory, the
evidence directory itself, and commands as they were run.

## The application matrix

Section 21's terminal-conformance row and section 27's matrix run the programs people use in a
terminal. `tests/conformance/tests/applications` starts each one as the root of a real session under
a worker, attaches to it over the worker's own endpoint with the product's client, and types through
the session's own input path. Each case compares the worker's snapshot of the canonical grid with the
screen the program itself says it is showing, and shows that no query the program asked reached the
attached terminal: the stream the attachment was sent is searched for every request a terminal
answers, independently of the engine's own class table. That search waits until the attachment has
provably been sent everything up to the end of the program's last query: the worker sends each event
with the position in the stream it starts at or describes, in order, so once a delivery from past
that point has arrived whole, nothing before it is still on its way. A delivery that takes several
events, a screen in chunks or a projected screen in pages, is whole only once its last event has
arrived. An attachment the worker tells to
resynchronise subscribes again, as the product's own client does, and is sent a fresh screen from
the session's position; one the worker moves to a projection is sent screens rather than bytes, so
nothing the program writes reaches it at all. A capture that broke, through a lost connection, an
event it could not decode, a refused subscription or a detach, fails the case.

`tests/conformance/applications.lock` pins each program by URL and SHA-256 for each platform. The
script fetches each release once into a cache outside the repository (`KR_CONFORMANCE_APPLICATIONS`,
or the platform's cache directory), checks its digest, and writes the cache's `index.json`. The cache
is named by an absolute path without `..`, resolved through its links before anything is made in it,
and refused inside the repository; nothing in it is read, written or replaced through a link. A
program whose project publishes source only is built there from that release's source, with the
flags the lock records, against the system's own curses library; tmux is built against a pinned
libevent built the same way. A release that cannot be fetched or built is recorded as not installed,
with the reason, and its cases are reported as not run. Nothing is taken from a package manager.

| Program | Version | Installed from | Cases |
| --- | --- | --- | --- |
| Neovim | 0.12.5 | The release's build | The alternate screen and back; a bracketed paste of CJK, combining marks, Hebrew, Arabic, an emoji and a flag, each landing where Neovim's ruler says; the emoji sequences it clusters, as a known difference; a click in SGR form on a wide character; the Kitty keyboard protocol it asks for; a character split between two writes |
| htop | 3.5.3 | The release's source | Its screen on the alternate screen and back; a click on its Quit label |
| lazygit | 0.65.1 | The release's build | Its panels over a repository and back; a click on a commit |
| fzf | 0.74.4 | The release's build | A typed query and its choice; a pasted CJK query; a click on an item |
| tmux | 3.7c | The release's source | Its pane against the grid, row for row, with every sample's width as tmux's own; a click between panes; a focus report reaching the pane; control-Enter in xterm's `modifyOtherKeys` protocol, which tmux asks the session for, reaching the pane that asked for it; an overlong control string and a broken character through it |
| GNU screen | 5.0.2 | The release's source | Its window against the grid, row for row, as its own hardcopy shows it |

A program with no build for a platform is not run there, and the result says why: htop, tmux and GNU
screen run on Unix only, and on Windows a console application is driven through the pseudo-console,
which is qualified on the Windows test machine.

### A known difference with Neovim

Section 8 pins `kr-vt/1` to per-codepoint widths: a wide emoji is two cells, a skin-tone modifier is
a wide emoji of its own, a joiner is none, and mode 2027 is not supported. Neovim draws a skin-tone
sequence and a joined sequence as one cluster two cells wide. The grid gives each four cells, so the
text Neovim writes after the sequence lands on the cells the sequence's second half took, and the row
shows the first emoji and then the text. tmux and GNU screen count per codepoint and agree with the
grid on every sample. The Neovim case asserts what the profile defines and records both readings as
a known difference.
