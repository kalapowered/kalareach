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
4. **Ancestry.** The parent chain is walked to the root shell, each link checked by start identity.

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

A wait that runs out returns the same durable question. It recreates nothing and notifies nobody a
second time.

## The caller token

`ask_user` returns an unpredictable token with the question, over the private channel the question
was created on. It permits exactly two things: polling and cancelling that one question, from the
same verified application.

The worker stores a keyed verification tag and a sealed copy, both bound to the question
identifier. The key is generated when the ledger opens and lives in the worker's memory alone, so
the sealed copies stop being readable the moment the worker exits — which is when a question's
source access ends. The token appears in no event, no notification, no backup and no log, and the
one durable record that would otherwise carry it, a retained action result, is deliberately not
written for a question creation. Nothing is lost by that: a question is de-duplicated by its source
and its own `request_id`, which returns the same question and the same token.

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
* **An entry is guarded rather than assumed.** An installation refuses to replace a server entry it
  did not write, which is what keeps an unrelated entry of the same name from being overwritten and
  then removed.
* **Other settings survive.** A TOML configuration is edited in place with a format-preserving
  editor, so ordering and comments are untouched. A JSON configuration is reparsed and rewritten:
  every setting survives, and the document's key order and indentation are normalised.

A directory the installation created is removed only when it is empty.

## What contact is not

An agent question is not a native tool approval. Answering `yes` resolves that question and nothing
else: it cannot manufacture an upstream approval identifier and it does not widen a grant. A real
approval uses its connector's own resource and response path.

The tools and the skill need no paid entitlement. Managed billing applies to hosted resources used
for delivery or storage, never to asking somebody a question on their own computer.
