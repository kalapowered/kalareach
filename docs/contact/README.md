# Agent contact

An agent running inside a KalaReach session can reach the person whose computer it is. It asks a
question, the person answers from the companion app or from the terminal, and the answer comes back
to the agent that asked. Nothing else: the tools cannot list another session, read its history or
send it input.

## The pieces

| Piece | Where it lives |
| --- | --- |
| The skill an agent reads | `skills/kalareach-contact/SKILL.md` and `TOOLS.md` |
| The installation manifest | `skills/kalareach-contact/manifest.json` |
| The tool server | `kr agent-tools --stdio` |
| The question ledger | the owning worker, in its private journal |
| The answering surface | the companion app, and `kr question` |
| The installer | `kr skill install|status|remove` |

## The four tools

`kr agent-tools --stdio` speaks the Model Context Protocol over its standard streams and offers
exactly four tools.

| Tool | Parameters | Result |
| --- | --- | --- |
| `ask_user` | `request_id`, `agent_name?`, `context`, `question`, `type`, `choices?`, `expiry_seconds?`, `wait_seconds?` | The question, and the `caller_token` that polls and cancels it |
| `wait_for_answer` | `question_id`, `caller_token`, `wait_seconds?` | The same question, answered or still pending |
| `cancel_question` | `question_id`, `caller_token` | The question, cancelled |
| `send_notification` | `dedup_id`, `agent_name?`, `text`, `severity`, `safe_session_link?` | The alert |

`TOOLS.md` in the skill package is the reference an agent reads, with every field, every error code
and every limit.

## What binds a helper to a session

A tool call reaches the worker that owns the session over its private socket. Before anything is
created, the worker establishes which session the caller is in, and it asks the operating system
rather than the caller:

1. **Peer credentials.** The runtime directory is owner-only and the listener refuses any other
   user before it reads a frame.
2. **Process identity.** The kernel names the calling process, and its start value is recorded with
   it, so a recycled process identifier cannot pass as the process that called a moment ago.
3. **Session membership.** The process is looked for inside the boundary the session owns: a
   control group where the platform has one, otherwise the controlling terminal and the process
   group the root shell leads.
4. **Ancestry.** The parent chain is walked to the root shell. Every link is read from the kernel
   and checked for consistency: a candidate parent that started after its child is an identifier
   the kernel has handed to something else since, and the chain stops there.

The identity read when the connection was accepted is the one every later call on it is checked
against, so a process identifier the kernel recycles mid-connection cannot be answered as though it
were the caller that opened it.

Either of the last two admits a source, and both are recorded on the question. Neither is a defence
against arbitrary code running under the same operating-system account, and the specification says
so plainly: that account is inside the operating system's trust boundary. What they establish is
which session this process belongs to, which is what decides where a question is created.

`KR_SESSION` is a lookup hint. It changes the order candidate sessions are tried in and nothing
else; a forged one reaches a worker that refuses it.

A helper that inherits a private launch channel registers it, and the question records that it did.
This build's root shell hands none down, so that flag is false and the binding rests on the checks
above.

Outside every session, every tool answers `NOT_IN_KR_SESSION` with the instruction to start the
agent inside one, and creates nothing.

## The identity a person sees

Answering surfaces lead with the application identity the host verified: the executable the kernel
names, its process identifier and the application instance the worker minted for it. The
`agent_name` the caller supplied is shown beside it and labelled unverified, because a label is not
an identity and a caller chooses its own.

## Questions

| State | What it means |
| --- | --- |
| `pending` | Waiting for a person. Dismissing the form leaves it here |
| `answered` | A person answered it. Terminal |
| `cancelled` | The source or a person withdrew it. Terminal |
| `expired` | Its deadline passed, or the application that asked has gone. Terminal |

Cancellation and expiry are different states, and dismissing a form is neither.

An answer is a tagged union of free text, a selected choice identifier, a boolean decision, or the
free-text `other` option. Every `select` and every `confirm` carries `something_else` with free
text; the host adds it and an agent cannot remove it. An `other` answer stays `other` everywhere it
is read: nothing folds it into a listed choice or into yes.

The first answer wins. Every resolution is one conditional update against the question's current
revision, so of two simultaneous answers exactly one changes the question and the other is told
`QUESTION_RESOLVED`.

| Limit | Value |
| --- | --- |
| Choices | 2 to 12, plus "Something else" |
| Answer | 16 KiB |
| Question text | 4 KiB |
| Decision context | 8 KiB |
| Lifetime | 24 hours, or the life of the application that asked, whichever ends first |
| Wait on creation | 30 seconds |
| Long poll | 300 seconds by default, 600 maximum, renewed in 20-second steps |
| Poll with no duration named | 300 seconds where the client's deadline is known, 45 where it is not |
| Declared client deadline | 660 seconds, written into the agent's own server entry, and into the environment it launches the server with |

A wait that runs out returns the same durable question. It recreates nothing and notifies nobody a
second time.

The client's own tool deadline is the other bound, and the shorter of the two decides. A server
cannot read a deadline the client never sends, so the installation tells it. Where the agent
supports a per-server deadline the installation declares 660 seconds in the agent's own
configuration — `tool_timeout_sec` for Codex, `toolTimeoutMs` for Kimi Code CLI, `timeout` for
Claude Code, Qoder CLI and Gemini CLI — and writes the same number into `KR_TOOL_DEADLINE_MS` in
the environment that agent launches the server with. Every wait is then cut to that deadline less
the room an answer needs to travel back in, whether the agent named a duration or not.

A document more than one agent reads carries neither, because those agents do not spell the
deadline the same way and the entry has to be the entry all of them read. Where nothing was
declared, a poll the agent puts no duration on runs for 45 seconds instead of the host's
five-minute default, so an agent whose client allows a minute loses nothing it was relying on. A
call the client cuts off loses the wait, never the question.

## The caller token

`ask_user` returns an unpredictable token with the question, over the private channel the question
was created on. It permits exactly two things: polling and cancelling that one question, from the
same verified application.

The worker stores a keyed verification tag and a sealed copy, both bound to the question
identifier. The key is generated when the ledger opens and lives in the worker's memory alone, so
the sealed copies stop being readable the moment the worker exits, which is when a question's
source access ends: a worker's death ends the session, and no later worker takes its place.

The token appears in no event, no notification, no backup and no log, and in no durable record but
that sealed copy. Two records would otherwise carry it. A created question's retained action result
is deliberately not written, and nothing is lost by that, because a question is de-duplicated by its
source and its own `request_id`, which returns the same question and the same token. A cancellation
from the source carries the token in its parameters, and the intent the journal keeps has it emptied
before it is encoded; what remains still says which question was to be cancelled and under whose
authority.

## Answering from the terminal

The companion app is the primary answering surface. `kr question` is the same surface on the
machine the session is on.

| Command | What it does |
| --- | --- |
| `kr question list [--session <id>] [--include-resolved]` | Lists what is waiting, with the verified identity that asked |
| `kr question show <question_id>` | One question in full, including the context and the choices |
| `kr question answer <question_id> (--text \| --choice <id> \| --yes \| --no \| --other <text>)` | Answers it |
| `kr question cancel <question_id>` | Withdraws it without answering |

Questions belong to the session, so these reach the session's worker directly, the way attaching
does. They keep working while the control daemon is restarting, and the authority behind them is
the operating-system owner the worker's socket authenticates. The revision the command read is the
revision it submits, so an answer to a question that moved underneath it is refused rather than
applied to something else.

## Installing the skill

`kr skill install --agent <agent> --scope <user|project> [--project-dir <path>]` writes the skill
package and registers the tool server. `kr skill status` reports what is installed and what has
changed since; `kr skill remove` undoes exactly what the installation recorded.

The agents are `codex`, `claude-code`, `opencode`, `gemini-cli`, `kimi-code-cli` and `qoder-cli`.
`manifest.json` in the skill package lists, for each one, where the skill goes at each scope, which
configuration document the server entry is added to, and whether that layout was verified against an
installed executable or taken from published documentation.

Three properties make an installation safe to undo:

* **Every change is recorded with the digest of what it wrote.** The record lives in this host's
  own state directory, not in the agent's, so an agent that rewrites its configuration cannot lose
  it. A removal replays the record in reverse and stops at anything whose digest no longer matches,
  because a changed file is somebody's edit.
* **Nothing is written until everything has been checked.** An installation refuses a file or a
  server entry that is already there and that this host did not write, and it refuses before its
  first write, so a refusal leaves the agent's tree exactly as it found it.
* **Other settings survive.** A TOML configuration is edited in place with a format-preserving
  editor, so ordering and comments are untouched. A JSON configuration is reparsed and rewritten:
  every setting survives, and the document's key order and indentation are normalised. The
  replacement keeps the permission bits of the document it replaces, because an agent's
  configuration can hold a credential. It does **not** carry an access-control list across that
  replacement, and on Windows, where a security descriptor is how a file is protected at all, an
  existing document is not replaced: the installation refuses and says to add the server with the
  agent's own command. On Unix an extended access-control list beyond the mode bits is likewise not
  carried.

A directory the installation created is removed only when it is empty, and a directory that was
already there is never claimed. A project's `.mcp.json` is read by more than one agent, so the entry
in one is written identically whichever installation wrote it and is removed only when no other
recorded installation still names it. A JSON document this host created goes with the entry when
nothing else was ever put in it; a TOML one does not, because a format-preserving editor keeps
comments and spacing this host cannot read as its own.

Installing and removing are mutations, and they carry section 9's receipt contract: the same action
retried returns what it produced the first time rather than changing anything again, the same
identifier with a different payload is `ID_CONFLICT`, and an action whose marker was written and
whose outcome was not is reported as unknown rather than repeated. One installation runs at a time
on a host, and the authority behind it and the deadline it was admitted under are checked again
immediately before anything durable happens.

Each change is noted in the record before it happens and recorded after it, and the record is marked
complete only when the last one is. An installation interrupted part way through is therefore not
mistaken for a finished one: `kr skill status` says it did not finish, and `kr skill remove` undoes
what was recorded. The one change that was in flight is named and left alone: a digest proves what a
file contains, not who wrote it, and removing something this host may never have written would
delete somebody else's file.

Installing again carries on from there. A skill file whose content is what the record names, whether
it was recorded or still in flight, is written again and claimed; a file at that path holding
anything else is somebody's own, and the installation refuses and says to move it aside. So a
repair finishes an interrupted installation, except where somebody has since put their own file
where one of its files goes.

## What contact is not

An agent question is not a native tool approval. Answering `yes` resolves that question and nothing
else: it cannot manufacture an upstream approval identifier and it does not widen a grant. A real
approval uses its connector's own resource and response path.

The tools and the skill need no paid entitlement. Managed billing applies to hosted resources used
for delivery or storage, never to asking somebody a question on their own computer.
