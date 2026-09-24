# Answering approvals from a declarative package

A package with no component can answer an approval its application asks for. Three declarations have
to agree. The connector table says where an answer goes, the manifest registers an action that
answers through that place, and every call to the action names the pending resource it answers. A
document drawn for one request can also say that its controls are for that request alone.

All of this is in version 0.1.1 of the package contract. A package that uses any of it declares
`"sdk_range": ">=0.1.1, <0.2.0"`, so a host on 0.1.0 refuses it by its range rather than failing
to read it.

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
