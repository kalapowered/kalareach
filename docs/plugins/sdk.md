# Answering approvals from a declarative package

A package with no component can declare everything an answer to its application's approval needs.
Three declarations have to agree. The connector table says where an answer goes, the manifest
registers an action that answers through that place, and every call to the action names the pending
resource it answers. A document drawn for one request can also say that its controls are for that
request alone.

The destination, the action and the visibility declarations are in version 0.1.1 of the package
contract. A package that uses only those declares `"sdk_range": ">=0.1.1, <0.2.0"`. A host on 0.1.0
cannot read the new members and refuses such a package. The `decision_response`, `observation` and
`operations` members of a table are in version 0.1.6: a package whose table declares any of them
declares `"sdk_range": ">=0.1.6, <0.2.0"`, and a host on an earlier contract refuses it.

The examples use the Claude Code Channels surface. Claude Code relays a tool approval as
`notifications/claude/channel/permission_request` with `params.request_id`, and it reads the answer
as `notifications/claude/channel/permission` with the same `params.request_id` and a
`params.behavior` of `allow` or `deny`.

## Where an answer goes

`connector.json` carries a `decision_destination`. Every table has the member. A table that answers
nothing writes `"decision_destination": null`, and a table that leaves the member out is refused.

```json
"decision_destination": {
  "answers": "channel.permission-request",
  "method": "channel.permission",
  "request_id_path": {
    "segments": [
      { "type": "member", "name": "params" },
      { "type": "member", "name": "request_id" }
    ]
  },
  "decision_path": {
    "segments": [
      { "type": "member", "name": "params" },
      { "type": "member", "name": "behavior" }
    ]
  },
  "decisions": [
    { "decision": "allow", "value": "allow" },
    { "decision": "deny", "value": "deny" }
  ]
}
```

| Member | What it says |
| --- | --- |
| `answers` | The routed method whose requests this destination answers. A message of this method is a pending approval. |
| `method` | The routed method that carries the answer. |
| `request_id_path` | Where the answer repeats the identifier of the request it answers. |
| `decision_path` | Where the answer carries the decision. |
| `decisions` | Each decision a person can make, and the exact value the application reads for it. |

The validator refuses a destination as `connector_table_invalid` unless all of these hold:

- `method` is routed `host_to_upstream` or `bidirectional`, and classified as a `mutation`.
- `answers` is routed `upstream_to_host` or `bidirectional`, and not classified as `unsupported`.
- The table matches responses by identifier (`matching_id`), and `request_id_path` is that
  identifier path. An answer is a response to the request it answers, so it carries the identifier
  where every response does.
- Both paths are one to eight member names. Neither meets the other or the table's method path, and
  the method path names no array element either.
- `decisions` has one to 24 entries with no decision twice and no value twice, and each value is 1
  to 256 bytes with no control character.

The table says which requests are approvals and which decisions they offer, and it writes the
answers. Interpreting a native request and answering one are separate grants, so a package whose
table declares a destination requests both `approval.decode` and `approval.respond`. Either one
missing is `effect_without_capability`.

### What an answer is

`ConnectorManifest::answer` writes an answer from the table and nothing else. It takes the method
the pending request arrived as, spelt the way the wire spells it, the identifier the table read from
that request, and a decision. Given this request and the decision `deny`:

```json
{
  "method": "notifications/claude/channel/permission_request",
  "params": { "request_id": "abcde", "tool_name": "Bash" }
}
```

it writes this answer:

```json
{
  "method": "notifications/claude/channel/permission",
  "params": { "request_id": "abcde", "behavior": "deny" }
}
```

It refuses a request of any other method, a decision the table does not map, an identifier that is
not a JSON string or number, and a table with no destination. The identifier goes back exactly as it
arrived and the value comes from `decisions`, so a caller supplies neither.

## An answer that is a response

A table of an application server may read the answer to an approval as the response to the request it
asked, with the request's own identifier and one member of the result that carries the decision. It
says so with a `decision_response` member instead of a `decision_destination`, and the table answers
one way. A table with a response leaves `decision_destination` as `null`.

```json
"decision_response": {
  "answers": [
    "item.command-execution.request-approval",
    "item.file-change.request-approval"
  ],
  "result_member": "decision",
  "decisions": [
    { "decision": "accept", "value": "accept" },
    { "decision": "accept-for-session", "value": "acceptForSession" },
    { "decision": "decline", "value": "decline" },
    { "decision": "decline-and-stop", "value": "cancel" }
  ]
}
```

`answers` lists one to eight routed methods that the application sends and that the table does not
classify as unsupported. The answer to one is `{"id": <the request's id>, "result": {"decision":
<the value>}}`, written from the table alone. Each decision maps to its own value, and the table
matches responses to requests by the identifier they repeat. The member needs the table's `messages`
member, and it must not name one the table reads a message by. A package whose table declares it
needs `approval.decode` and `approval.respond`, and its answer action is the `decision_destination`
implementation, whose choices the response maps.

## What the host reads from a stream

An `observation` member says where the messages of an application server name the conversation and
the turn the terminal is in:

```json
"observation": {
  "selections": [
    { "method": "thread.start", "thread": { "segments": [
      { "type": "member", "name": "result" },
      { "type": "member", "name": "thread" },
      { "type": "member", "name": "id" } ] } }
  ],
  "leaves": [
    { "method": "thread.closed", "thread": { "segments": [
      { "type": "member", "name": "params" },
      { "type": "member", "name": "threadId" } ] } }
  ],
  "turn_started": { "method": "turn.started",
    "thread": { "segments": [{ "type": "member", "name": "params" }, { "type": "member", "name": "threadId" }] },
    "turn": { "segments": [{ "type": "member", "name": "params" }, { "type": "member", "name": "turn" }, { "type": "member", "name": "id" }] } },
  "turn_ended": { "method": "turn.completed",
    "thread": { "segments": [{ "type": "member", "name": "params" }, { "type": "member", "name": "threadId" }] },
    "turn": { "segments": [{ "type": "member", "name": "params" }, { "type": "member", "name": "turn" }, { "type": "member", "name": "id" }] } },
  "request_resolved": { "method": "request.resolved",
    "request_id": { "segments": [{ "type": "member", "name": "params" }, { "type": "member", "name": "requestId" }] } }
}
```

A selection is a request of the terminal's, and the path names the thread in its success reply, from
the root of the reply. A leave is a request of the terminal's or a notification of the application's
that ends the conversation it names. The turn and the cleared request are notifications of the
application's. Every method is one the table routes the way the message travels, a path begins with
the member the table names for that kind of message (`result` for a reply, `params` for the rest),
and a method has one role. A table lists at most eight selections and eight leaves, needs its
`messages` member, and matches responses by identifier.

The package declares places and the host does the reading. A package cannot say that a conversation
changed, and the host never takes one from prompt text or timestamps.

## What the host writes for its own operations

An `operations` member says how the application's protocol spells a prompt, a steer and a
cancellation, so that the host can write them and a package cannot make it send anything it did not
qualify:

```json
"operations": {
  "prompt_submit": {
    "method": "turn.start",
    "params": {
      "threadId": { "$": "thread_id" },
      "input": [{ "type": "text", "text": { "$": "text" } }]
    },
    "reply_turn": { "segments": [
      { "type": "member", "name": "result" },
      { "type": "member", "name": "turn" },
      { "type": "member", "name": "id" } ] }
  },
  "turn_steer": {
    "method": "turn.steer",
    "params": {
      "threadId": { "$": "thread_id" },
      "expectedTurnId": { "$": "turn_id" },
      "input": [{ "type": "text", "text": { "$": "text" } }]
    }
  },
  "turn_cancel": {
    "method": "turn.interrupt",
    "params": { "threadId": { "$": "thread_id" }, "turnId": { "$": "turn_id" } }
  }
}
```

A hole is a whole value, `{"$": "thread_id"}`, `{"$": "turn_id"}` or `{"$": "text"}`, and the host
fills it with a JSON string. A prompt needs the thread and the text, a steer the thread, the turn and
the text, and a cancellation the thread and the turn. Each method is one the table routes from the
host to the application and classifies as a mutation, and no two operations share one. A template
nests at most eight levels, holds at most sixty-four values, and its literals are at most 256 bytes
without control characters. `reply_turn` is a path inside the table's result member. The table
needs its `messages` member. An operation a table does not declare is one the host does not send.

## The action that answers

An action answers through the destination with the `decision_destination` implementation:

```json
{
  "id": "approval.answer",
  "label": "Answer",
  "effect": "approval.respond",
  "implementation": { "type": "decision_destination", "decision": "decision" },
  "parameters": {
    "parameters": [
      {
        "name": "decision",
        "kind": {
          "type": "choice",
          "choices": [
            { "id": "allow", "label": "Allow" },
            { "id": "deny", "label": "Deny" }
          ]
        },
        "label": "Decision",
        "required": true
      }
    ]
  },
  "description": "Answer the tool approval the session is waiting on",
  "confirmation_required": false
}
```

It is the only declarative implementation that produces `approval.respond`. An `upstream_method`
action cannot answer an approval, and it cannot send the destination's method under another effect
class either: sent with free parameters, an answer would reach whichever request its bytes happened
to name.

The action declares exactly one parameter, the required choice that `decision` names, and the
destination maps every one of its choices. No choice parameter anywhere offers one identifier twice,
because a call names a choice by its identifier alone. The only right an answer needs is
`agent.approval.respond`, whatever its label says.

A control may narrow the decision to a single choice. That is how a package draws separate Allow and
Deny buttons for one action.

## The call names the request

`plugin.action.invoke` carries `resource_id`, the pending resource an `approval.respond` action
answers. Every other action sends `null`, and the member is always present.

`ActionDeclaration::check` refuses an answer without a resource, a resource on any other action, and
a decision the action does not offer. `ActionDeclaration::decision` reads the chosen decision from
the call.

The host checks the named resource before it marks anything. The resource must be one the host
holds, it must belong to the application instance the call targets, it must still be pending with
its deadline not passed, it must have a recorded interpretation, and everything the claim rechecks
must still hold. Each refusal is a rejection with a receipt: an unknown resource is `STALE_SESSION`,
another instance's is `PERMISSION_DENIED` and an answered one is `QUESTION_RESOLVED`.

The upstream identifier never comes from the caller. It is the one the host recorded with the
resource when the request arrived.

After these checks the call is admitted as the answer it is: its one transmission is reserved before
anything is marked, and it goes out on the connection the request arrived on, written as the verdict
the table maps. Its result names the action and says that the verdict was written on the connection; it does not say what the application did with it. A call
refused by any check leaves the request pending for another answer, such as the one a person gives
in the terminal.

## Showing a control for one request

Two visibility terms ask about approvals:

```json
{ "op": "flag", "flag": "pending_approval" }
{ "op": "pending_approval_for", "request_id": "abcde" }
```

The flag holds while any approval is pending. `pending_approval_for` holds while the named upstream
request is pending, and it is false for an identifier that names no pending approval. It has no form
without an identifier. The flag holds exactly when at least one request is pending.

A document drawn for one request names it with `pending_approval_for`, and its controls go away as
soon as that request is answered, even while others wait. A package's own `presentation.json` is
written before any request exists, so its answer controls use the flag and the grant:

```json
{
  "op": "all",
  "terms": [
    { "op": "grant", "right": "agent.approval.respond" },
    { "op": "flag", "flag": "pending_approval" }
  ]
}
```

A client that draws such a control beside a particular request must bind the press to that
request's resource and send it as `resource_id`. It never answers whichever request happens to be
current when the button is pressed. Visibility grants nothing either way: the host checks the named
resource again when the call arrives.

A client that has not been told which requests are pending treats `pending_approval_for` as unknown
and hides the control.

## A complete package

The example connector package in `fixtures/plugins/valid/example-connector/` has every part: an
approval route pair, a destination, the two approval capabilities, an answering action and a group
with Allow and Deny controls. It validates cleanly, and
`crates/kr-plugin-sdk/tests/approval_contract.rs` breaks it one declaration at a time to show each
refusal.
