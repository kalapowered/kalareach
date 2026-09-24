# The managed shell packages

[README.md](README.md) is the contract. This is what the packages do to keep it: which lines of
each shell change, what the added sources are, how a package is built and identified, and under
which licence each part travels.

Three of the four are built from an upstream release the manifest pins by URL and SHA-256. Nothing
upstream is copied into this repository. What lives here is the patch sets, the bridge sources the
patches bring with them, the guarded startup entry and the manifest that ties them together:

```
shells/zsh/                          shells/bash/              shells/fish/
  manifest.json                        manifest.json             manifest.json
  LICENSE            (Zsh licence)     LICENSE  (GPL-3.0+)       LICENSE  (GPL-2.0-only)
  patches/*.patch                      patches/*.patch           patches/*.patch
  src/*                                src/*                     src/*
  startup/kr-zshrc.zsh                 startup/kr-bashrc.bash    startup/kr-fish.fish
```

The fourth rebuilds no shell. PSReadLine is the editor the person already has, so what
`shells/psreadline/` holds is a module of Kala Powered's own and the marked profile block that
loads it:

```
shells/psreadline/
  manifest.json      (the range it was qualified against, rather than a release to fetch)
  LICENSE            (BSD 3-Clause, because nothing upstream is copied or patched)
  module/*
  startup/kr-profile.ps1
```

## Why a patched reader at all

A prompt hook cannot say whose keystrokes reached the line editor, and a key binding runs after the
reader has already decided what an empty-line Ctrl-D means. Both shells recognise that end of file
before an ordinary binding gets a look, so the decision has to be taken inside the reader, at the
instant the character is selected. The same is true of everything else the contract asks for: the
queues a fence rests on, the moment a line is accepted, and the ability to end a key wait without
throwing away what the person typed. None of it can be done from outside.

So each package changes a small number of lines in its shell's reader and adds one bridge that
speaks `kr-shell-bridge/1` over a Unix socket. The changes are published as ordered patch files,
which is what `scripts/build-shells.sh` applies and what continuous integration verifies applies
cleanly.

## What Zsh changes

Four patches, against `zsh-5.9`.

| Patch | Files | What it adds |
| --- | --- | --- |
| `0001-zle-reader-mailbox` | `Src/Zle/zle.mdd`, `Src/Zle/zle_main.c` | The mailbox and everything that hangs off it |
| `0002-zle-reader-state` | `Src/Zle/zle_misc.c` | Three reader states the detach condition needs |
| `0003-terminfo-variable-checks` | `configure.ac`, `configure` | The published upstream fix for the terminfo capability-name probes |
| `0004-exec-command-resolve` | `Src/exec.c`, `Src/zsh.h`, `Src/Zle/zle_main.c` | The question in front of each command a line starts, and the launcher its answer can name |

The first patch does five things, all inside `zle_main.c`:

- **`raw_getbyte` waits on the bridge as well as the terminal.** The reader already selects over
  the terminal and any watched descriptors; the bridge's descriptor joins that set, and the wait is
  entered whenever the bridge is connected rather than only when something else asked for it. This
  is the reader's own idle point, so a fence, a cancellation or a launch reaches the reader thread
  without a keystroke and without the reader blocking on anything but its input.
- **`zlecore` reads the mailbox at every key-sequence boundary.** One call, immediately after
  `getkeycmd` has resolved a complete sequence and before anything is executed, answers whatever is
  in the mailbox and then takes the end-of-file decision for the key that was just read. That call
  sits ahead of both of ZLE's end-of-file branches, so an eligible gesture never reaches either one
  and the person's `IGNORE_EOF` setting is neither read nor changed.
- **`zleread` reports the reader's boundaries.** Entry before `zlecore`, and the leave before
  acceptance returns, with the reason ZLE's own state gives: an accepted command, a cancellation or
  the root shell exiting. `zlecontext` says which reader it is, so a `PS2` continuation and `vared`
  are not the root editor's prompt.
- **`getbyte` records where each byte came from.** A byte from `kungetbuf` was pushed back by a
  widget or `zle -U`, not typed, and the detach condition excludes it for that reason.
- **The editor module loads the bridge when it is set up**, before the first primary reader, and
  gains one builtin, `kr-bridge`, which is how the guarded startup entry says its hooks are live.

The second patch sets three flags around the reads that ZLE keeps no state for: `quoted-insert`
waiting for its character, `universal-argument` accumulating digits, and an open bracketed paste.
An incremental search already has `isearch_active`, and a vi motion already has `virangeflag`, so
those two need no change.

Immediate acceptance is the mailbox's own: the reader installs the command, answers, sets `done`
and returns from the read loop at the boundary it is already standing on. Cancellation is ZLE's
timeout path — the pending read ends, the longest complete prefix is dropped and the edit buffer is
untouched. A cancellation that finds nothing in progress ends nothing: it discards nothing, the
reader stays in the wait it is in, and the sequence the person starts next is their own.

The boundary is also where a key the person has just typed is still theirs. `getkeycmd` has
resolved a complete sequence and nothing has run it yet, so the reader reports that sequence as
input it is holding, and a launch that arrives at that moment is refused with `queued_prior_input`
rather than installed over it.

The fourth patch is the command integration's one point in the executor. `execcmd_exec` asks,
immediately before it forks an external command, when the command has no pipe, is not a background
job, holds no filename pattern still to expand and has no assignments in front of it: zsh expands a
pattern and applies those assignments only in the child, where `PATH` or `ARGV0` would change what
runs, so a command with either is not asked about. The question is a pointer, `kr_resolve_hook`,
that the editor module sets when it loads and clears in its `finish_`, so the executor never calls
into a module that is not there; the bridge answers it, and refuses everything but a top-level
command of the accepted line that the root shell starts itself. When the answer names a launcher,
the forked child's `execute` starts it in the command's place with the backend's variables added,
and a launcher that cannot be started leaves the child running the command as it was typed.

## What Bash changes

Four patches, against `bash-5.2.37`, which bundles Readline 8.2.

| Patch | Files | What it adds |
| --- | --- | --- |
| `0001-readline-reader-mailbox` | `lib/readline/{Makefile.in,input.c,macro.c,readline.c}` | The mailbox, the reader's private counts, the cancellation and the pre-EOF decision |
| `0002-readline-reader-state` | `lib/readline/{text.c,kill.c}` | Two reader states Readline keeps no flag for |
| `0003-bash-bridge-activation` | `Makefile.in`, `shell.c`, `builtins/{Makefile.in,read.def}` | Loading the bridge, the prompt context and the builtin |
| `0004-bash-command-resolve` | `execute_cmd.c` | The question in front of each command a line starts, and the launcher its answer can name |

Readline's buffering is why the mailbox is where it is. The reader returns pending and macro input
without consulting the character callback at all, and `rl_gather_tyi` can call that callback while
it fills a buffer, before preceding characters have changed `rl_end`. Testing `rl_end` from a
callback therefore classifies typeahead wrongly. So:

- **`rl_getc` reads the mailbox at the top**, which is the one point at which Readline has taken
  everything it had buffered and is about to wait for the terminal, and its `select` watches the
  bridge's descriptor beside the terminal's.
- **`rl_read_key` records the input source** in each of its four branches: pending input, a macro,
  the reader's own buffer, and the terminal.
- **A cancellation returns a negative key.** `KR_RL_CANCEL` is negative and distinct from `EOF` and
  `READERR`, so `_rl_dispatch_subseq`, `_rl_insert_next`, `rl_digit_loop` and `rl_vi_domove` each
  end their own operation through the path they already have for a negative key, which runs
  `_rl_abort_internal`: the executing macro is popped, pending input is cleared, the argument is
  reset, and `rl_line_buffer` is left exactly as it was. A cancellation that finds nothing in
  progress returns no key at all, so the reader stays in the read it is in.
- **`readline_internal_char` takes the end-of-file decision** immediately before Readline's own
  `c == EOF && rl_end` and empty-line branches, after the next character has been selected. It
  answers native or consume, replaces no binding, and a consume continues the same `readline` call.
- **`readline_internal` reports the reader's boundaries**, the leave before acceptance returns.
- **`input.c` and `macro.c` gain one accessor each**, for the bytes the reader still holds in its
  own buffer and the bytes left in an executing macro. A fence rests on the reader's state, so
  those counts have to come from the reader rather than from the kernel's idea of what is readable.

Which reader is running is Bash's to say, not Readline's, so `kr_shell_prompt_context` asks the
shell: `get_current_prompt_level()` returns 2 for a continuation line, and `this_shell_builtin`
names `read` while the `read` builtin is the one reading. Asking rather than tracking means the
answer is right however a reader is left, including through a signal or a timeout. The bridge
itself loads in `shell.c` before `run_startup_files`, so a startup file finds it already there.

The patch leaves Bash's parser alone on purpose. Bash ships a generated `y.tab.c`, and touching
`parse.y` makes the build regenerate it, which needs a Bison newer than several supported hosts
carry. Calling the two functions Bash already exports costs nothing and keeps the build to a C
compiler.

The fourth patch is the command integration's one point in the executor. `execute_disk_command`
asks after `search_for_command` has found the file and before `make_child`, when the command has no
pipe and is not a background job. `kr_bash_resolve`, in the shell's own half of the bridge, refuses
everything but a command of the accepted line: never one a function, a sourced or startup file, an
`eval`, a trap, `PROMPT_COMMAND` or a subshell runs. When the answer names a launcher, the forked
child starts it in the command's place with the backend's variables added to the environment it
would have had, and a launcher that cannot be started leaves the child running the command as it
was typed.

## What fish changes

Three patches, against `fish-4.9.3`. This shell's reader is Rust, so the reader's own half of the
bridge is Rust beside it and the shell-independent core is the same C the other packages compile,
built into the shell by the build script that already compiles C for the shell's own probes.

| Patch | Files | What it adds |
| --- | --- | --- |
| `0001-fish-reader-event-bridge` | `src/input/input.rs`, `src/input/decode.rs`, `src/input/binding.rs`, `src/reader/input.rs`, `src/reader/mod.rs`, `src/reader/reader.rs` | The mailbox, the reader's boundaries, the named binding and the bridge's view of the reader |
| `0002-fish-reader-state` | `src/input/binding.rs` | The states the detach condition needs that this reader keeps no flag for |
| `0003-fish-bridge-activation` | `build.rs`, `src/bin/fish.rs`, `src/builtins/mod.rs`, `src/builtins/shared/misc.rs` | The core compiled in, the `kr-bridge` builtin, and the bridge loading before the startup files |

The first patch does five things:

- **The reader waits on the bridge as well as the terminal.** `next_input_event` already selects
  over the input descriptor, the completion port and the universal-variable notifier; the bridge's
  descriptor joins that set. The terminal is checked first, because what the person typed is theirs
  and anything the worker asks for waits behind it.
- **The mailbox is read at every key-sequence boundary and before every wait.** One call after
  `binding_execute_matching_or_generic` has resolved a complete sequence and before its binding
  runs, and one immediately before the reader blocks, which is also where a reader with nothing
  left to read says so.
- **`kr-eof-decide` joins the reader's own command table**, so the gesture is a named binding with
  the actual reader context rather than a wrapper downstream of the decision.
- **`readline` reports the reader's boundaries**: the entry after the prompt has been drawn and
  before the read loop, and the leave with the reason the reader's own state gives.
- **The bridge's view of the reader** is one small block of accessors: which reader is running, the
  command line, whether a search is active, the two buffer operations a launch needs, the terminal's
  own end-of-file character and printing one line above the prompt.

The second patch adds what the exclusions need and the reader does not already keep: how many
events a sequence has peeked and not resolved, an input function waiting for the target character
it takes as an argument, `get-key` waiting for the literal key it reports, and where the character
being judged came from.

The guarded entry is a file of its own under `conf.d`. Files there run before the person's
`config.fish`, so the entry registers a one-shot handler on the first prompt: by then the person's
configuration and key bindings are in place, and the integration goes on top of them.

## What the PSReadLine package qualifies

Nothing is patched and nothing is rebuilt. The module wraps the host's own `PSConsoleHostReadLine`
for the reader's boundaries, wraps the editor's own functions that run an inner read loop so the
states they wait in are observable, and puts its end-of-file decision on the configured gesture in
front of whatever was bound there. It calls the editor's published API and reads the editor's own
key queue, which is what a fence rests on and what the editor publishes no count of.

`Publish-KalaReachQualification` is what `scripts/build-shells.sh` is for the others: it checks the
editor against the range the manifest pins, records what it found, installs the module and the
marked profile block under the same cache layout, and writes the identity record beside them. The
identity is a digest of the module, the manifest, the startup entry and the versions it qualified
against, so a changed module is a different package.

What that record qualifies is one editor, not a version range: two installations can both be inside
the supported range with only one of them qualified, so the module binds into an editor at the
directory the record names, at the version it names, and diagnoses any other by name. Which editor
a path names is the filesystem's answer rather than the path's spelling. The device and the inode
it reports name one directory whatever path led to it, so an editor reached through a link, or
through a parent directory reached another way, is the editor that was qualified; two directories
whose names differ only in case stay two editors wherever the filesystem keeps both. An editor
loaded from another directory, or at another version, is refused with the directory it was
qualified at and the one it is at now. The record holds that directory and that version and no
digest of the editor itself, so a different installation put at the recorded directory under the
recorded version is not something the record can tell apart.

It installs one executable of its own, `bin/pwsh`, which starts the host this qualification found
with the runtime location that host needs. The host and the editor are the person's and live
wherever they installed them, so the package records them under what it qualified rather than
among the paths it holds: every path a package declares is inside the package, which is what lets
a session resolve one without resolving into somebody else's installation. A record that named the
person's own host as the package's executable could not be read at all, which refuses a managed
PowerShell session by name and leaves the packages beside it alone.

[README.md](README.md) states what this mechanism can and cannot establish. The short of it is that
the reader is reached when it steps: the module's queue is serviced on the reader's own thread, and
a request that arrives while the reader is parked in its key wait is answered at its next boundary.

## What the packages add

Each package adds the same shell-independent bridge to its shell's source tree, plus a small
adapter for that reader:

| File | What it holds |
| --- | --- |
| `kr_bridge.c`, `kr_bridge.h` | The endpoint, the frames, the handshake, the fence view, the pre-EOF decision and the reader's launch check |
| `kr_bridge_cbor.c`, `kr_bridge_cbor.h` | KR-CBOR-1: canonical encoding with map keys checked into order as they are written, and a bounded decoder |
| `kr_bridge_crypto.c`, `kr_bridge_crypto.h` | SHA-256, HMAC-SHA-256 and base64url, for the one proof taken at startup |
| `kr_bridge_zle.c` / `kr_bridge_rl.c` | The reader's own state, read in one operation at one instant, and the shell's own string representation |
| `kr_bridge_bash.c` (Bash only) | What only the shell itself can do: put a variable in its exported environment or take one out, say which prompt it is at and what the last line exited with, and decide whether a command is one of the line's own |

The first three files are the same source in both packages, and a test in
`crates/kr-shell-integration/tests/` asserts they have not drifted. They are duplicated because
each patch set has to be publishable on its own, against its own upstream project, under that
project's licence.

Nothing in the bridge links against the rest of the host. It speaks to the worker over a socket,
and the reader calls into it through a small set of functions.

Two things the adapters do that are easy to get wrong. An argument vector is quoted a word at a
time, *including the first*, and with the enclosing single quotes: a bare word at command position
would be a reserved word, an assignment or an alias rather than the name the caller asked to run,
and an unquoted `$(...)` would run. Zsh's own `quotestring` escapes for the inside of single
quotes and leaves the quotes to its caller, which is a trap worth naming. And on Zsh the text goes
in through the editor's own string representation: `setline` unmetafies what it is handed, so raw
bytes above 0x7f would change on the way in.

Losing the bridge does not turn a managed root shell back into an ordinary one. The handshake
leaves a mark that is never cleared, so a shell whose worker has gone holds no fence, consumes an
eligible gesture with the hint, and does not end itself on an empty-prompt Ctrl-D.

## The guarded startup entry

The entry is one marked block. Everything between the two marker lines belongs to the integration,
and removing the integration removes exactly that block and nothing else:

```
# >>> kalareach shell integration >>>
...
# <<< kalareach shell integration <<<
```

It goes at the end of `$ZDOTDIR/.zshrc` for Zsh, and at the end of `.bashrc` for Bash — or, for a
login shell whose first-read login file does not source `.bashrc`, at the end of that file. The
installation never replaces either file, never uses an alternate `ZDOTDIR` or a substituted
`--rcfile`, and never disables an existing profile.

The block is guarded by `builtin kr-bridge status`, which fails in any shell that does not have the
packaged builtin and in any shell that did not register a root integration. That covers every
child of a managed root shell, because the two bootstrap variables leave the exported environment
as soon as the handshake succeeds and a child therefore has nothing to attempt.

What the entry does is report that the user's own configuration has run and the integration's
hooks are live, which is what moves a session from authenticated to qualified. Zsh does it through
a one-shot `precmd` that takes itself out of `precmd_functions` and leaves the rest of the list
alone. Bash does it in the block itself, which is why the block belongs at the end of the file.

## The identity, and rebuilding it

`scripts/build-shells.sh` fetches the pinned tarball, verifies its digest, applies the patches with
no fuzz at all, copies the bridge sources in, configures, compiles, runs the shell's own test suite
and installs the result:

```bash
scripts/build-shells.sh --all            # every package it builds
scripts/build-shells.sh --fish           # one
scripts/build-shells.sh --all --check-patches          # apply the patches and stop
```

fish is built through CMake rather than autotools, because that is what its own release ships with;
the manifest says which, and the Rust toolchain and the environment the build pins join its
identity for the same reason the C compiler joins the others'.

The identity is a SHA-256 over the inputs: the upstream archive's digest, the manifest, this build
script, every patch file, every added source, the startup entry, and the compiler and environment
the build honours. The first sixteen hex characters name the directory the package is installed
in, so the same inputs land in the same place and a second run reports that nothing changed.
Change one byte of any of them, or build with a different compiler, and the identity changes with
it. For a package whose own source is Rust the toolchain is pinned by name for the whole build, so
the compiler the identity records is the one that ran, and the flags it honours are recorded beside
it.

The identity names the inputs a package was built from rather than the bytes it produced. fish's
build records the directory it was built in, which is a fresh temporary one each time, so two runs
from the same inputs give the same identity and the same install path rather than an identical
file.

Packages are installed outside the repository, under `~/Library/Caches/kalareach/shells/` on macOS
and `${XDG_CACHE_HOME:-~/.cache}/kalareach/shells/` elsewhere. A process a service manager starts
gets its own privacy identity on macOS, and one that opens a path on a removable volume makes the
operating system ask the person for permission first, so a built shell lives on the internal disk
where a session can start it without a dialog.

Beside the binary is `kr-shell-identity.json`, which is what the package declares in its handshake:
the executable, the upstream version, the editor ABI, the integration version, every published
patch with the upstream revision it was rebased onto, the module tree with each module's ABI, the
five declared mechanisms, and the build's own inputs and compiler. The record also states what the
shell's own test suite did.

The manifest's compilation flags are part of the package rather than a local preference. Zsh 5.9
writes some of its configure probes in pre-C99 style, and a compiler that rejects implicit `int`
answers "missing" where the truth is "did not compile": that is how a build ends up with
`BROKEN_POSIX_SIGSUSPEND` and a shell that hangs on every command substitution. The manifest pins
`-std=gnu17` and the two warning flags that keep those probes compiling, and `--with-tcsetpgrp=yes`
states the platform assumption the probe cannot check without a controlling terminal. Both
assumptions hold on the platforms these packages are built for.

Two notes on that last field. Bash's `make tests` passes with these patches. Zsh's `make check`
runs 64 scripts and one of them, `A04redirect`, fails on macOS on arm64 over `print foo >&-`,
which writes to a closed descriptor and prints where the test expects silence. An unpatched 5.9
built from the same tarball and the same flags fails the same single script, so this is the release
meeting the host rather than anything the patches do. The build script runs each suite in its own
process group, ends it at a bound, records the outcome and its summary line in the identity, and
carries on; `--require-upstream-tests` turns anything but a pass into a build failure, which is
what continuous integration uses on Linux.

## The licence position

The repository is BSD 3-Clause. Three of these directories are not, because they are built from
other people's shells:

| Path | Licence |
| --- | --- |
| `shells/zsh/**` | The Zsh licence, in `shells/zsh/LICENSE` |
| `shells/bash/**` | GNU GPL, version 3 or later, in `shells/bash/LICENSE` |
| `shells/fish/**` | GNU GPL, version 2, in `shells/fish/LICENSE` |
| `shells/psreadline/**` | BSD 3-Clause, because nothing upstream is copied or patched |
| everything else, including `scripts/build-shells.sh` and this document | BSD 3-Clause |

The patch files change each shell's own source, and the sources under `src/` are compiled into that
shell, so both travel under the licence of the work they join. Kala Powered holds the copyright in
the added sources and in the changes the patches make, and licenses them on those terms as part of
each package.

No code under any of those licences is compiled into a crate. The crates speak to these packages over a
socket and share nothing but the wire format, and `crates/kr-shell-integration` is a pure contract
library with no link-time dependency on either shell.

## What is not here

Running the PSReadLine module on Windows, where the endpoint is a named pipe and the gesture is the
configured chord rather than the line discipline's own character, is qualified separately.

Signing the built executables and modules, and qualifying the hardened-runtime loading
configuration they are signed for, belongs to packaging rather than to the build script here.
