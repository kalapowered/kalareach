# The Gemini CLI bridge

Gemini CLI runs a hook for an event and reads what the hook answers. The Gemini CLI connector
package installs a small extension that makes Gemini CLI start `kr-hook`, the core forwarder, for
three of its events, and the forwarder carries each event to the worker that owns the launch. The
forwarder finds its worker, presents itself and is admitted exactly as it is for Claude Code: see
"Finding the worker" and "Admission" in [the Claude Code bridge](../claude-code/README.md). It
declares itself as Gemini CLI's hook, `{"application":"gemini-cli","surface":"hook"}`, and the
worker admits it only where the installation it recorded for the launch is Gemini CLI's.

The forwarder runs under Gemini CLI's own permissions, outside the KalaReach plugin sandbox and
outside Wasmtime. The package's installation grant says so before anything is installed.

## What the package installs

Two files under the user's own Gemini CLI directory, and no settings key:

| File | What it registers |
| --- | --- |
| `extensions/kalareach/gemini-extension.json` | The extension `kalareach`: a name, a version and a description, and nothing it could load |
| `extensions/kalareach/hooks/hooks.json` | `kr-hook gemini-cli hook` for `SessionStart` and `Notification` with a timeout of 5000 milliseconds, and for `SessionEnd` with 1000 |

Gemini CLI loads every extension in that directory for every project and every later session,
unless the person disables it, and runs an extension's hooks beside the hooks in the person's own
settings files, whether or not the person trusts the folder. A hook in a settings file, the
person's own included, runs only in a trusted folder, and a hooks key there would hold the person's
own hooks for the same event; that is why the bridge is an extension. Removing it deletes the two
files. Gemini CLI then warns at every start about the empty `extensions/kalareach/` directory, so
whatever removes the files also removes the directories the installation created once they are
empty.

The core repository keeps a copy of both files in `fixtures/bridges/gemini-cli/`, pinned by the
SHA-256 digests the package's recipe records, and `crates/kr-hook/tests/fixtures.rs` checks that
every hook starts the forwarder's `gemini-cli hook` invocation as a command of plain words, for
exactly the events the forwarder reports, with a timeout its deadline fits inside.

## How Gemini CLI starts the forwarder

Gemini CLI runs every hook's command as `bash -c "<command>"`, with the `bash` it finds on the path,
and gives it Gemini CLI's own environment. Bash runs a command of plain words in its own process,
so `kr-hook gemini-cli hook` is started by Gemini CLI's process with no shell left between them,
and it inherits the launch's `KR_REGISTRATION`. Gemini CLI removes variables from a hook's
environment only where the person switched on its redaction setting, which leaves
`KR_REGISTRATION` alone, or where `GITHUB_SHA` is set or `SURFACE` is `Github`, which removes it;
there the forwarder answers `{}` and reports nothing.

## Why these three events

Gemini CLI reads a hook's standard error as its answer when standard output is empty, and turns
plain text with an exit code other than 0 and 1 into a refusal. On a finished tool, a refusal
replaces the result the model reads. The forwarder always writes `{}` on standard output, but a
forwarder that is not on the path makes bash exit 127 with "command not found", and one too old to
know this invocation exits 64 with its usage. Either would replace every tool result if the bridge
registered a tool event. On `SessionStart`, `SessionEnd` and `Notification` Gemini CLI ignores a
refusal, so the most such a failure can do there is a warning that names the hook, `kalareach`.

## What each event reports

| Event | Observation | What the worker does with it |
| --- | --- | --- |
| `SessionStart` | `thread_started`, with `source` (`startup`, `resume` or `clear`) as its detail | Records it; see "Limits" for the thread |
| `SessionEnd` | `thread_ended`, with `reason` | Records it |
| `Notification` | `notification`, with its kind (`ToolPermission`) and text | Records it |

The thread is Gemini CLI's `session_id`. `/clear` ends one session and starts another. Gemini CLI
waits for `SessionEnd` hooks when it exits and on `/clear`, and it waits for `Notification` hooks
before it shows the permission prompt they announce. Whatever happens, a hook stops waiting for the
worker 500 milliseconds after it starts, then writes exactly `{}` and exits 0, well inside the
shortest timeout the extension registers, and it never waits for a person, as the Claude Code
bridge's "Hooks" section describes. A hook that ran past its timeout would get SIGTERM and a
warning; the forwarder answers long before that.

## Limits

Gemini CLI starts a copy of itself as a child process and runs the session there, unless
`GEMINI_CLI_NO_RELAUNCH` or `SANDBOX` is set. The process that was started stays as the child's
parent: it sizes the child's heap, adding `--max-old-space-size` at half the machine's memory where
that is more than V8's own limit and `advanced.autoConfigureMemory` is not false; it starts the
session again when the child exits with code 199, as it does after an update or a restart it asks
for; and it relays administrator settings to the child. Every hook is the child's, not the process
KalaReach launched, so the worker admits each hook and records what it reports, and none of them
selects the session's thread. With `GEMINI_CLI_NO_RELAUNCH=true` in the launch's environment the
launched process starts the hooks itself, and it gives up the heap sizing and the restart. No
package can declare the environment a command integration sets yet, so today no launch sets it.

An interactive Gemini CLI runs its `SessionEnd` hooks twice when it exits, with the same session and
reason, and prints three lines of its own about the hooks it ran; the worker's second report of an
ended thread changes nothing.

These facts were read from Gemini CLI 0.60.0 with no account signed in and no model turn: a session
starting and ending, the hooks' parent and their environment on the binary, and the notification
and tool behaviour from the build's own code and the hook reference it ships. The host admits no
bridge on Windows, because it writes a launch's credential file only on Unix.
