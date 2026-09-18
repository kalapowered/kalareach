# The managed Zsh and Bash packages

[README.md](README.md) is the contract. This is what the two Unix packages do to keep it: which
lines of Zsh and Bash change, what the added sources are, how the package is built and identified,
and under which licence each part travels.

Both packages are built from an upstream release the manifest pins by URL and SHA-256. Nothing
upstream is copied into this repository. What lives here is the patch sets, the bridge sources the
patches bring with them, the guarded startup entry and the manifest that ties them together:

```
shells/zsh/                          shells/bash/
  manifest.json                        manifest.json
  LICENSE            (Zsh licence)     LICENSE            (GPL-3.0-or-later)
  patches/*.patch                      patches/*.patch
  src/*                                src/*
  startup/kr-zshrc.zsh                 startup/kr-bashrc.bash
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

Two patches, against `zsh-5.9`.

| Patch | Files | What it adds |
| --- | --- | --- |
| `0001-zle-reader-mailbox` | `Src/Zle/zle.mdd`, `Src/Zle/zle_main.c` | The mailbox and everything that hangs off it |
| `0002-zle-reader-state` | `Src/Zle/zle_misc.c` | Three reader states the detach condition needs |

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
untouched.

## What Bash changes

Three patches, against `bash-5.2.37`, which bundles Readline 8.2.

| Patch | Files | What it adds |
| --- | --- | --- |
| `0001-readline-reader-mailbox` | `lib/readline/{Makefile.in,input.c,macro.c,readline.c}` | The mailbox, the reader's private counts, the cancellation and the pre-EOF decision |
| `0002-readline-reader-state` | `lib/readline/{text.c,kill.c}` | Two reader states Readline keeps no flag for |
| `0003-bash-bridge-activation` | `Makefile.in`, `shell.c`, `builtins/{Makefile.in,read.def}` | Loading the bridge, the prompt context and the builtin |

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
  reset, and `rl_line_buffer` is left exactly as it was.
- **`readline_internal_char` takes the end-of-file decision** immediately before Readline's own
  `c == EOF && rl_end` and empty-line branches, after the next character has been selected. It
  answers native or consume, replaces no binding, and a consume continues the same `readline` call.
- **`readline_internal` reports the reader's boundaries**, the leave before acceptance returns.
- **`input.c` and `macro.c` gain one accessor each**, for the bytes the reader still holds in its
  own buffer and the bytes left in an executing macro. A fence rests on the reader's state, so
  those counts have to come from the reader rather than from the kernel's idea of what is readable.

Which prompt the reader is at is Bash's to say, not Readline's, so `kr_shell_prompt_context` reads
the parser's own `current_prompt_string`: pointing at `PS2` means a continuation line. The `read`
builtin says so explicitly around its call to `readline`. The bridge itself loads in `shell.c`
before `run_startup_files`, so a startup file finds it already there.

The patch leaves Bash's parser alone on purpose. Bash ships a generated `y.tab.c`, and touching
`parse.y` makes the build regenerate it, which needs a Bison newer than several supported hosts
carry. Reading the parser's variables from a new file costs nothing and keeps the build to a C
compiler.

## What the packages add

Each package adds the same shell-independent bridge to its shell's source tree, plus a small
adapter for that reader:

| File | What it holds |
| --- | --- |
| `kr_bridge.c`, `kr_bridge.h` | The endpoint, the frames, the handshake, the fence view, the pre-EOF decision and the reader's launch check |
| `kr_bridge_cbor.c`, `kr_bridge_cbor.h` | KR-CBOR-1: canonical encoding with map keys checked into order as they are written, and a bounded decoder |
| `kr_bridge_crypto.c`, `kr_bridge_crypto.h` | SHA-256, HMAC-SHA-256 and base64url, for the one proof taken at startup |
| `kr_bridge_zle.c` / `kr_bridge_rl.c` | The reader's own state, read in one operation at one instant |
| `kr_bridge_bash.c` (Bash only) | The two things only the shell itself can do: remove a variable from its exported environment, and say which prompt it is at |

The first three files are the same source in both packages, and a test in
`crates/kr-shell-integration/tests/` asserts they have not drifted. They are duplicated because
each patch set has to be publishable on its own, against its own upstream project, under that
project's licence.

Nothing in the bridge links against the rest of the host. It speaks to the worker over a socket,
and the reader calls into it through fifteen functions.

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
scripts/build-shells.sh --zsh --bash     # both
scripts/build-shells.sh --bash           # one
scripts/build-shells.sh --check-patches  # apply the patches and stop
```

The identity is a SHA-256 over the inputs: the upstream archive's digest, every patch file, every
added source, the startup entry and the configure flags. The first sixteen hex characters name the
directory the package is installed in, so the same inputs land in the same place and a second run
reports that nothing changed. Change one byte of one patch and the identity changes with it.

Packages are installed outside the repository, under `~/Library/Caches/kalareach/shells/` on macOS
and `${XDG_CACHE_HOME:-~/.cache}/kalareach/shells/` elsewhere. A process a service manager starts
gets its own privacy identity on macOS, and one that opens a path on a removable volume makes the
operating system ask the person for permission first, so a built shell lives on the internal disk
where a session can start it without a dialog.

Beside the binary is `kr-shell-identity.json`, which is what the package declares in its handshake:
the executable, the upstream version, the editor ABI, the integration version, every published
patch with the upstream revision it was rebased onto, the module tree with each module's ABI, the
five declared mechanisms, and the build's own inputs. The record also states what the shell's own
test suite did.

Two notes on that last field. Bash's `make tests` passes with these patches. Zsh's `make check`
runs 64 scripts and one of them, `A04redirect`, fails on macOS on arm64 over `print foo >&-`,
which writes to a closed descriptor and prints where the test expects silence. An unpatched 5.9
built from the same tarball and the same flags fails the same single script, so this is the release
meeting the host rather than anything the patches do. The build script runs each suite in its own
process group, ends it at a bound, records the outcome and its summary line in the identity, and
carries on; `--require-upstream-tests` turns anything but a pass into a build failure, which is
what continuous integration uses on Linux.

## The licence position

The repository is BSD 3-Clause. These two directories are not, because they are built from other
people's shells:

| Path | Licence |
| --- | --- |
| `shells/zsh/**` | The Zsh licence, in `shells/zsh/LICENSE` |
| `shells/bash/**` | GNU GPL, version 3 or later, in `shells/bash/LICENSE` |
| everything else, including `scripts/build-shells.sh` and this document | BSD 3-Clause |

The patch files change each shell's own source, and the sources under `src/` are compiled into that
shell, so both travel under the licence of the work they join. Kala Powered holds the copyright in
the added sources and in the changes the patches make, and licenses them on those terms as part of
each package.

No code under either licence is compiled into a crate. The crates speak to these packages over a
socket and share nothing but the wire format, and `crates/kr-shell-integration` is a pure contract
library with no link-time dependency on either shell.

## What is not here

Fish and PSReadLine are separate packages with their own reader mechanisms; this document covers
the two Unix shells whose readers are patched. Windows is outside both of them.

Signing the built executables and modules, and qualifying the hardened-runtime loading
configuration they are signed for, belongs to packaging rather than to the build script here.
