# kalareach/kimi-cli

Recognises MoonshotAI's kimi-cli, the Kimi distribution published on PyPI, reads its agent protocol
through a declarative table, and stops the turn it is running.

## What it does

KalaReach matches the `kimi` executable, and `kimi-cli`, the second name the package installs,
labels the session, and runs kimi-cli through its ordinary terminal path. That terminal is the
default and it stays exactly as kimi-cli draws it. What this package adds is a reading of the agent
protocol the same build speaks, and one control over the turn.

`connector.json` is the declarative native-proxy table for that protocol: one JSON document per line
over the bound process's standard streams, identifiers at `id`, methods at `method`, responses
matched by repeating the `id`. Core code reads that table directly, so nothing of this package's
sits on the forwarding path.

## Which distribution, and why that matters

Two distributions share the name Kimi and the executable name `kimi`. This package is the profile
for MoonshotAI's `kimi-cli`, the Python distribution published on PyPI as `kimi-cli`, which keeps
its data under `~/.kimi`. The other is the kimi.com distribution, which installs under
`~/.kimi-code`; it is a separate profile with its own package, `kalareach/kimi-code-cli`.

Both answer the agent protocol's handshake with the same agent name, Kimi Code CLI, so the name
settles nothing. What tells them apart is the published package the executable came from, its
version, and what the handshake advertises: this build offers listing and resuming sessions and
nothing more, where the kimi.com build also offers closing, deleting and forking them. The rule that
names the PyPI project is what identifies this one; a rule that recognises an executable called
`kimi` or `kimi-cli` by name alone is a guess, and it is reported as a guess. An executable with
that name establishes nothing about which server contract is available, and a directory of saved
sessions establishes nothing about which process owns the live one. When the installed evidence does
not match the distribution and the version this package pins, the capability is incompatible, every
control this package draws disappears, and the terminal is what is left.

The table is pinned to kimi-cli 1.51.0 and qualified against that version alone. MoonshotAI has
archived kimi-cli and names the kimi.com distribution as its replacement. Its final release, 1.52.0,
carries no agent protocol: run with no arguments it runs an install command for the kimi.com
distribution without asking, and run with any other it prints a deprecation notice. 1.51.0 is the
last release that runs the agent itself.

## The agent protocol is a mode you choose

`kimi acp` starts the agent-protocol mode, which creates its own execution over standard streams. It
is not a second engine attached to the conversation already running in a terminal, and nothing here
replaces the terminal route with it. The older `--acp` flag answers `initialize` with an error that
names the subcommand instead, and a name it does not implement with method not found. Attaching a
terminal to a server this package selected would need source or executable verification that this
qualification does not have, so the package neither claims it nor offers it.

The same build has an experimental Wire mode, `kimi --wire`, which speaks a different protocol over
the same streams. This table does not cover it, and no control here uses it.

## What it classifies

Twenty methods, each with the evidence it was classified against.

Eleven travel from the host to the agent. `initialize` negotiates what the connection may afterwards
be asked to do; `session/new`, `session/load`, `session/prompt` and `session/resume` change what
exists or what the agent is doing; `session/set_mode` changes the session's mode, of which this
build offers one; and `session/set_model` changes the model and saves it as the default in the
agent's own configuration. `session/list` reads the stored sessions without loading one, which makes
it an observation. `authenticate` is a credential method, because it concerns the vendor's own login
and the broker never passes a credential to a component; without a usable login this build sends no
answer to it at all. `session/cancel` ends the turn in flight. `session/fork` is a name this build
accepts and cannot carry out, so the table declares it unsupported.

Two methods the kimi.com build implements, `session/close` and `session/delete`, are not routed:
this build answered method not found to both, so a message that uses either is treated as a
mutation, like any other name the table does not list.

Nine travel the other way, because the agent asks the host for things. `session/update` carries the
turn's own stream and is an observation. `session/request_permission` is a reverse request naming a
tool call the agent is waiting on, and answering it runs or refuses that call, so it is a mutation
rather than a report. The filesystem and terminal requests are the rest: reading a file and reading
a terminal's output observe, while writing a file, starting a process, ending one and releasing a
terminal change something. Every one of them runs in the host environment the session selected,
under that environment's own identity and with resources the broker scopes.

A method this table does not list is treated as a mutation. That is the safe answer to a name a
publisher forgot, and nothing in the file changes it.

## What it does not carry

No component, and so no approval decoder. A pending tool approval stays with the gateway and the
terminal that asked for it; this package offers no button that would answer one.

No prompt action. A control supplies parameters, and the declarative binding has no way to say "the
broker fills the bound session here", so an action that sent `session/prompt` would have to let a
control name the session.

No attachment contribution, and nothing that depends on the vendor's own web interface or on the
Wire mode. The default route is the terminal, where the composer's own syntax is what inserts a
file, and this package qualifies no composer syntax.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
this package's own predicates against each one. They are display conformance and only that: the
runner reads no agent frame. One case is an installation of the kimi.com distribution, where both
controls disappear and the terminal path is what remains.

`fixtures/frames.json` is the other half: ten frames, each marked with where it came from. Five are
the exact messages that were sent to the pinned build over its standard streams, one is such a
request with its working directory replaced, and four are written from names the installed package
calls. Each carries the method the table should find, the route and class it should reach, the
identifier the table's path should extract with its JSON type, and the members its own situation is
about. The test `every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every
one of them through this package's own table, and
`the_kimi_distributions_share_an_agent_name_and_differ_in_what_their_handshake_advertises` compares
the handshake this package pins with the one `kalareach/kimi-code-cli` pins.

Each is a frame, not a sequence. What a host does across a pending permission, a reconnection or a
competing answer is the gateway's and is not settled here.
