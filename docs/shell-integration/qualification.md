# Qualifying the packages against the customisations people run

A managed shell package is not qualified by starting. Section 7 names the startup customisations it
has to work under — zsh-autosuggestions, zsh-syntax-highlighting, Powerlevel10k with its instant
prompt, starship, oh-my-zsh, fzf's widgets, atuin and ordinary distribution customisations — and
what has to hold under each of them. This is that qualification: a corpus of cases, a runner that
drives each one against a real package in a real terminal, and one command that does the whole
thing.

## Running it

```
bash scripts/e2e-fence.sh
```

That builds or verifies the packages from their pinned upstream releases, fetches the pinned
customisations by digest, starts a real control daemon and a real managed session, and then drives
every case. Its evidence goes to `${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}`, including
`qualification-cases.tsv`, which is one line per case: what it qualified, which package identity,
and which version of each customisation. A case with a drive that could not read the state it
names says so on that line, as `qualified, narrowed to what the reader reported:` followed by the
states.

The corpus on its own is `cargo test -p kr-shell-integration --test qualification`. With no package
built and no customisation fetched it says so and stops; with `KR_REQUIRE_SHELL_PACKAGES` or
`KR_REQUIRE_SHELL_STACKS` set, either absence is a failure instead, which is what continuous
integration does. It writes the same evidence to `KR_TEST_ARTIFACTS_DIR`, or, where that is unset,
to a directory of its own, `kr-test-artifacts-<process id>`, in the system's temporary directory.
Evidence it cannot write fails the run.

## The corpus

One directory per shell and customisation under `tests/shells/`:

```
tests/shells/<shell>/<case>/case.json     what the case is and what it claims to prove
tests/shells/<shell>/<case>/home/...      the startup files it installs under its own home
tests/shells/<shell>/unsupported.json     every customisation that shell does not have, with why
```

A case's startup files are the person's: the case writes them into a home of its own on the
internal disk and puts the package's own marked entry where the file's `# {kalareach-entry}` token
is, which is how each case states where in its own startup the integration is activated. Where a
shell activates the integration from a file of its own — fish's `conf.d` — the entry is written
there instead.

`case.json` carries:

| Field | What it is |
| --- | --- |
| `id`, `shell`, `stack`, `title` | which combination this is |
| `supported`, `reason` | whether the combination exists, and why not when it does not |
| `requires` | the pinned customisations it needs installed |
| `order` | the markers its startup writes, in the order it writes them |
| `warm_order` | the order a second start over the same home writes |
| `binding` | the person's own key binding, which has to survive |
| `checks` | what this case claims to prove |
| `plugin` | the command that asks the shell whether the customisation is loaded, and what it answers |
| `native_module` | the module the shell is meant to refuse, and what that proves |
| `covers` | the requirement rows |
| `home` | the startup files, and where each goes |

## What a case proves

| Check | What it drives |
| --- | --- |
| `identity` | the handshake's declaration against the identity record the build wrote beside the binary: the executable, the editor ABI, the integration version, the upstream version, the patch set and the module tree |
| `profile_order` | the markers the startup wrote, in the order the case declares |
| `profile_once` | each marker exactly once, which is what "a PowerShell profile executes exactly once" means here |
| `plugin_active` | the shell's own answer to "is this customisation loaded", and, where a case gives one, the customisation doing the thing it is for and the shell reading back what it did. A case's `notes` say where that is the customisation's own operation rather than the hook that calls it |
| `plugin_writes_buffer` | the customisation putting text in the reader's buffer that nobody typed: a remembered line accepted and then run, or a widget's own choice inserted by two keys that are not characters |
| `plugin_buffer` | the reader reporting a line a customisation has drawn over as a line, and a cleared one as cleared |
| `user_bindings` | the person's own key still running the person's own binding |
| `native_module` | a module this build cannot load: diagnosed by name, absent from the shell's own list, and the integration still qualified |
| `gesture_detaches` | an eligible gesture at a fenced empty primary prompt, as an attributable detach, under the customisation |
| `gesture_is_native_outside_the_condition` | every excluded state this reader can be put into, with the gesture kept by the editor |
| `every_exclusion_accounted_for` | the whole list: a continuation reader, the shell's own `read` through the editor, a macro being replayed, a vi motion waiting for its target, and each one this reader cannot be put into with its reason |
| `escape_then_gesture_is_native` | the whole invoking sequence being the gesture, so a character at the end of a longer one is the editor's |
| `unattributable_gesture_hints` | a missing and a stale fence, each consumed with one short hint per prompt |
| `gesture_follows_the_line_discipline` | the terminal's own end-of-file character changing, surviving a command, and being taken away |
| `takeover_under_the_stack` | a takeover while the customisation has the reader waiting for the rest of a key sequence: the queue reported, the wait ended, the line kept |
| `launch_deadline_installs_nothing` | a launch whose reader budget has gone: refused, nothing in the editor, nothing run |
| `instant_prompt` | a second start over the same home, where a theme draws a prompt from the cache the first wrote, and the managed reader is what answers afterwards |

## The customisations

`fixtures/shells/stacks.lock` pins each one to a release by URL and SHA-256, per platform where the
artefact is a binary. `scripts/fetch-shell-stacks.sh` is the only thing that fetches them: it
verifies the digest, keeps each verified archive by that digest so a rerun and a second platform
unpack the same bytes, and writes an index recording each one as installed, unreachable or not
pinned for this platform, with the reason. A test reads that index and never reaches the network.

A customisation the index calls unreachable is one this run did not qualify, and the case that
needed it says so. Nothing is substituted from the machine's own package manager: a qualification
has to name the build it qualified.

## What the corpus cannot do quietly

The suite refuses a check name it does not run, and refuses a pinned customisation that is neither
driven by a supported case nor recorded as unsupported for that shell with a reason. A combination
therefore cannot be dropped by deleting a case, by marking one unsupported, or by claiming a check
that does not exist.

Three states are recorded rather than driven, with their reasons in the code and in the evidence
each run writes:

* the ones a particular reader does not have, such as a quoted insertion in an editor with none;
* the ones it has and this corpus does not reach, such as a numeric argument in a shell that binds
  none by default;
* the ones a reader will not say it is in. A drive reads the state it is about out of the reader's
  own report: the keymap, what the reader is in the middle of, what its queues hold. Where the
  report carries the state, the run records the exclusion as driven; Zsh's reader reports the vi
  operator waiting for its target, so Zsh drives it. Where the drive reaches the keymap and the
  reader says no such thing — Bash's reader reports no pending operator, and Fish's reports nothing
  at all while it waits for the target — the run records the keymap it did observe and narrows the
  claim to that, under "narrowed to what the reader reported" in the case's own evidence file and
  on the case's line in the summary. What the qualification says about such a state is what the
  reader said, and no more.

Every line of a case's exclusion record comes from a report a reader wrote or from something the
run watched the shell do. A drive that offers the gesture in a state it could not confirm says so
rather than counting itself.

## How a drive knows what it proved

Every drive gets a shell of its own, not only the four that need a command run first. A drive that
ran in a shell another drive had already used would be measuring what that one left behind: a
gesture in a continuation reader leaves some shells part way through a command they could not
parse, a macro binding stays bound, a search leaves the editor in a listing, and a keymap one drive
changed is the keymap the next starts in. A shell costs a second to start; a drive that starts its
own has no recovery gesture standing between its claim and its evidence.

Each drive then has to answer three questions, and each answer is observed rather than arranged.
The reader says it is inside its read, so the keys reach the editor rather than the terminal's own
line discipline. The reader then says, in its own answer to a fence exchange, that it is in the
state the drive names — a reader waiting inside one of these operations reaches no key boundary of
its own, so it is asked rather than waited for. And afterwards the editor's answer is a positive
one: neither managed event arrived, and the shell ran a command of the run's own while the bridge
reported its reader leaving and coming back. Silence alone is not an answer, because a reader that
had died, one that had been replaced and one that never took the key at all are all equally silent.

A startup customisation can bind the key a drive types to a widget of its own, and fzf's history
widget is the one in this corpus that does. While a third-party widget holds the terminal the
package owes no fence answer; the drive records the state as unobserved, names the customisation,
sets proved to false and still asserts the native effect. A widget of that kind reaches no key
boundary and so answers no exchange while it is running, which is the editor behaving correctly
rather than the package failing, and the gesture the drive then offers still has to be kept: the
managed decision must not be reached, and the shell and the bridge both have to be working
afterwards. So the narrowing costs the run the claim about the reader's state and nothing else. The
same rule covers a shell with no observable of its own for a state: Zsh reports an empty line and
nothing pending while its incremental search is running, where Bash and Fish both report the
search, and the run records what the reader said instead of claiming what it did not.

The macro drive is the one with two offers at a single prompt. The first character arrives from the
reader's own replay and never reaches the managed decision: what answers it is the editor's own
binding, which on Zsh is the shell's own end of file and on Bash is the reader carrying on. Where
the shell ends, the exit status is read too, because a shell that died is not a shell that
answered. Where it carries on, the buffer is read back before anything else is typed and the same
key is then offered at that same untouched buffer, where it does reach the managed decision. One
prompt, one buffer, one key, and the only difference between the two offers is where the character
came from. That second offer shows the difference the source makes; what it does not show is that
the replay reached the editor's own handler at all, which only the reader can say. Zsh's reader
says it by ending the shell. Where a reader carries on and reports no replay of its own, the run
records both offers and narrows the claim to them.

## Upstream and the update target

`upstream.md` beside this file is the register of the sources each package tracks, the triage
record for security-relevant changes, and the update target each package is published under. The
qualification reads it: the pins in the register have to be the pins the builder uses and the
identity the build wrote, and a triage row past its target release date has to be flagged with its
compatibility-mode choices rather than leaving a stale package as a silent default.
