# The contact tools

Four tools, served by `kr agent-tools --stdio` over the Model Context Protocol. Every call binds to
the KalaReach session this process is running in; nothing you send establishes that binding and
nothing you send can change it.

Each result is a JSON object in the call's structured content. A failure comes back as a tool error
whose structured content carries a stable `code`, a `message` and a `retry` category.

## `ask_user`

Creates a durable question and returns it with the token that polls and cancels it.

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `request_id` | string | yes | Your own unpredictable identifier. The same value with the same payload returns the same question; with a different payload it is `ID_CONFLICT` |
| `agent_name` | string | no | What to call you in the form. Unverified, and shown as such |
| `context` | string | yes | Concise decision context, at most 8 KiB. May be empty |
| `question` | string | yes | The question, at most 4 KiB |
| `type` | `input` \| `select` \| `confirm` | yes | The form |
| `choices` | array of `{choice_id, label}` | for `select` | Two to twelve, each identifier distinct and stable. "Something else" is added by the host |
| `expiry_seconds` | integer | no | Default and maximum 86400. The question also ends when this process does |
| `wait_seconds` | integer | no | Wait for an answer before returning, at most 30 |

Result:

```json
{
  "question_id": "0e2e...",
  "revision": 1,
  "state": "pending",
  "session_id": "b4a1...",
  "type": "select",
  "choices": [{"choice_id": "left", "label": "Left"},
              {"choice_id": "something_else", "label": "Something else"}],
  "expires_at_ms": 1770000000000,
  "answer": null,
  "caller_token": "…64 hex characters…",
  "deduplicated": false
}
```

Keep `question_id` and `caller_token` together. The token is how the host knows a later call is
still you; it is issued once, it is never shown to the person, and it appears in no event, no
notification and no log. It permits exactly two things: polling and cancelling that one question.

## `wait_for_answer`

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `question_id` | string | yes | The question `ask_user` returned |
| `caller_token` | string | yes | The token it returned with it |
| `wait_seconds` | integer | no | Default 300, maximum 600. Ask for less than your own client's tool deadline |

Returns the same question shape as `ask_user`, without the token. `state` is `pending`, `answered`,
`cancelled` or `expired`.

A wait that runs out returns the pending question unchanged. Nothing is recreated, nobody is
notified again and the question keeps its identity: call again with the same `question_id` to keep
waiting. Internally the wait is renewed in bounded steps, so cancelling the tool call ends it
promptly.

An `answer` is a tagged union:

| `kind` | Field | From |
| --- | --- | --- |
| `input` | `text` | An `input` question |
| `choice` | `choice_id` | One of your listed choices |
| `decision` | `decided` (boolean) | A `confirm` question |
| `other` | `text` | The "Something else" option on any `select` or `confirm` |

`other` is free text and stays free text. Do not map it onto a choice and do not read it as yes.

## `cancel_question`

| Parameter | Type | Required |
| --- | --- | --- |
| `question_id` | string | yes |
| `caller_token` | string | yes |

Cancels a pending question and returns it. A question that is already `answered`, `cancelled` or
`expired` is not changed: the call fails with `QUESTION_RESOLVED`, or `QUESTION_EXPIRED` when its
time had already run out.

## `send_notification`

| Parameter | Type | Required | Meaning |
| --- | --- | --- | --- |
| `dedup_id` | string | yes | Your own identifier. The same value with the same text raises nothing new |
| `agent_name` | string | no | Unverified label |
| `text` | string | yes | At most 2 KiB |
| `severity` | `info` \| `warning` \| `error` | yes | |
| `safe_session_link` | string | no | A link into this host's own session |

Result:

```json
{"session_id": "b4a1...", "dedup_id": "build-failed", "severity": "warning",
 "created_at_ms": 1770000000000, "deduplicated": false}
```

It asks for nothing and there is nothing to wait on.

## Error codes

| Code | What happened | What to do |
| --- | --- | --- |
| `NOT_IN_KR_SESSION` | This process is not inside a KalaReach session, and nothing was created | Start the agent inside one: `kr new --attach`. The message carries the instruction |
| `ID_CONFLICT` | That `request_id` or `dedup_id` already carries a different payload | Use a fresh identifier, or send the original payload |
| `QUESTION_RESOLVED` | Somebody answered or cancelled it first | Read the answer with `wait_for_answer` |
| `QUESTION_EXPIRED` | Its deadline passed, or the process that asked has gone | Ask again with a fresh `request_id` if it still matters |
| `PERMISSION_DENIED` | The token does not belong to this question, or to you | Use the token `ask_user` returned for that question |
| `INVALID_ARGUMENT` | The form breaks a rule: too few or too many choices, an answer over 16 KiB, a duplicate choice identifier | Fix the payload |

## Timeouts, cancellation and limits

| | |
| --- | --- |
| Wait on creation | up to 30 seconds |
| Long poll | 300 seconds by default, 600 maximum |
| Internal renewal | 20 seconds per broker wait, renewed until your deadline |
| Question lifetime | 24 hours, or the life of this process, whichever ends first |
| Answer size | 16 KiB |
| Choices | 2 to 12, plus "Something else" |

A timeout preserves the question. Cancelling a tool call ends the wait, not the question; use
`cancel_question` to end the question itself.

Your own client also has a tool deadline, and it is the shorter of the two that decides. Where the
agent lets a server declare one, the installation declares 660 seconds so a full poll can finish;
where it does not, the client's own default governs and it is often 60 seconds. Ask for a
`wait_seconds` below your client's deadline: a call your client cuts off loses the wait, never the
question, and calling `wait_for_answer` again resumes it.

## Limits of these tools

They reach the person running this session only. They cannot enumerate another session, read its
history or send it input. An answer is not an approval inside any other tool: it cannot produce an
upstream approval identifier and it does not widen any permission. A question identifier on its own
retrieves nothing; the token and the verified application together are what reach an answer.
