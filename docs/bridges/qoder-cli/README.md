# The Qoder CLI bridge

Qoder CLI runs a hook for an event and reads what the hook answers, much as Claude Code does. It
reads hooks from the person's own settings files and from settings a launch passes with
`--settings`, and it runs the hooks from both for the same event. KalaReach uses the second way.
The launch passes KalaReach's hooks, so nothing is written into the person's Qoder CLI directory
and the hooks exist only in sessions KalaReach launched; "The fallback" below says what else would
work. Qoder CLI then starts `kr-hook`, the core
forwarder, for each event, and the forwarder carries the event to the worker that owns the launch.

The forwarder finds its worker, presents itself and is admitted exactly as it is for Claude Code:
see "Finding the worker" and "Admission" in [the Claude Code bridge](../claude-code/README.md). It
declares itself as Qoder CLI's hook, `{"application":"qoder-cli","surface":"hook"}`, and the
worker admits it only where the installation it recorded for the launch is Qoder CLI's.

## What the launch adds

Two elements, after the command name and before whatever the person typed: `--settings`, and the
inline JSON that follows it. The core repository keeps them in `fixtures/bridges/qoder-cli/flags.json`,
pinned by their SHA-256 digest, and `crates/kr-hook/tests/fixtures.rs` checks that the JSON holds
hooks and nothing else.

| Event | Timeout |
| --- | --- |
| `SessionStart` | 5 seconds |
| `SessionEnd` | 1 second |
| `PostToolUse` | 5 seconds |
| `PostToolUseFailure` | 5 seconds |
| `Notification` | 5 seconds |

Every entry is `kr-hook qoder-cli hook` in exec form, a `command` with its `args`, with no matcher,
so it runs for every tool, notification and session source. Qoder CLI starts an exec-form hook
itself, as its own child, with no shell between them; the `qoder` entry point execs `qodercli` in
place, so the process the worker launched is the one that starts the hooks. That is what lets a
Qoder CLI hook select the worker's thread.

## Why these five events

On these five, only exit code 2 refuses anything, and Qoder CLI reads a hook's standard output
only when the hook exits 0. The forwarder exits 0 with exactly `{}`, an object that sets nothing.
A forwarder that refuses its command line exits 64, and one Qoder CLI cannot find never starts;
Qoder CLI logs either and changes nothing else.

## What each event reports

| Event | Observation | What the worker does with it |
| --- | --- | --- |
| `SessionStart` | `thread_started`, with `source` as its detail; `thread_continued` when the source is `compact` | Selects the thread; a compaction changes nothing |
| `SessionEnd` | `thread_ended`, with `reason` | Leaves no thread selected |
| `PostToolUse` | `tool_finished`, with the tool's name | Records it; for the contact skill's `ask_user`, also records which thread ran the request |
| `PostToolUseFailure` | `tool_failed`, with the tool's name | Records it |
| `Notification` | `notification`, with its kind and text | Records it |

The thread is Qoder CLI's `session_id`. A session starting at startup, on a resume, after `/clear`
or as a new session selects its thread. Qoder CLI names an MCP tool `mcp__<server>__<tool>`, as
Claude Code does, and describes the call in `mcp_context`; a finished `mcp__kalareach__ask_user`
names its request only when that context, where it is given, names the `kalareach` server and the
`ask_user` tool. Whatever happens, a hook stops waiting for the worker 500 milliseconds after it
starts, then writes exactly `{}` and exits 0, and it never waits for a person, as the Claude Code
bridge's "Hooks" section describes.

## The fallback

A hooks key in the person's settings file is not a place for KalaReach's hooks: it holds the
person's own hooks for the same event, so adding KalaReach's there would replace theirs. An
installed plugin is not one either, because Qoder CLI loads it from an install record that names
its absolute path. A local marketplace is. Two keys the settings file does not otherwise hold,
`extraKnownMarketplaces.kalareach`, a directory source whose path is written as `${HOME}/...`,
which Qoder CLI expands, and `enabledPlugins.kalareach-hooks@kalareach`, beside three files (the
marketplace's manifest and a plugin with its hooks), make Qoder CLI copy the marketplace into its
own plugin state at the next start and run the plugin's hooks from the start after that, beside the
person's own. That was checked on the binary over two sessions.

It costs two keys in the person's `settings.json`, Qoder CLI's own copy and record of the
marketplace, which removal leaves behind, and no hooks in the first session after installation.
Like the launch, it gives a session a registration only when KalaReach launches it through a
command integration. It is the route to take if a later Qoder CLI stops reading `--settings`.

## Limits

A package declares these two elements as its command integration's flags, as
[the plugin reference](../../plugins/README.md#command-integration) describes, and the worker takes
them only from the verified package. A package that installs no native bridge gets a hook bridge
for its own application on each integrated launch, on this installation's own `kr-hook`: Qoder CLI
finds `kr-hook` on the launch's search path, and a hook that runs another copy, or says it is
another application's, is refused at admission.
The two elements are added together or not at all, so a Qoder CLI command typed with `--settings`
of its own runs as typed. Sessions are created with no command integration enabled, and the worker
holds no installed connector to launch from, so no launch passes these two elements and Qoder CLI
runs no KalaReach hook.

Qoder CLI runs no hook from any source, the launch's included, in a folder the person has not
trusted. It starts a session before the person answers its trust question, so the session in which
a person first trusts a folder reports no start; its later events are reported.

These facts were read from Qoder CLI 1.1.63 with no account signed in: a session starting and
ending, the hooks' parent and their environment on the binary, the other three events' payloads
from the vendor's hook reference. The host admits no bridge on Windows, because it writes a
launch's credential file only on Unix.
