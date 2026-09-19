# KalaReach protocol reference

This describes the shared interface layer: the canonical encoding, the framing, the message
envelopes, the receipt contract, the error codes and the method authority table. It covers what
this repository implements today. Transport, pairing cryptography and storage are separate.

Four pieces make it up:

- `crates/kr-cbor` is the KR-CBOR-1 codec: canonical encoding, strict decoding, digests and
  domain-separated signing input.
- `crates/kr-protocol` holds every wire type, the method registry and the schema generator.
- `packages/protocol` is the generated TypeScript package with a codec that produces the same
  bytes.
- `fixtures/` holds the vectors both languages are tested against.

Rust is canonical. The JSON Schema comes from the Rust types, and the TypeScript types come from
the schema. Both steps have a check mode, so a change on one side that is not carried to the other
fails the build rather than drifting quietly.

## KR-CBOR-1

Every signature, digest and frame in the protocol uses this encoding. It is RFC 8949 section 4.2.1
core deterministic encoding, narrowed by an application profile.

From RFC 8949 section 4.2.1:

- definite lengths only,
- shortest integer and length encodings, and
- map keys sorted by the bytewise lexicographic order of their complete encoded keys.

That last rule is not the length-first variant in section 4.2.3, which is a differently named
ordering.

The profile permits integers in CBOR's 64-bit argument range (`-2^64` to `2^64 - 1`), byte strings,
valid UTF-8 text, arrays, text-keyed maps, booleans and schema-declared `null`.

It forbids tags, floats, indefinite lengths, `undefined` and other simple values, duplicate keys,
non-shortest encodings and trailing bytes after the object.

Three rules are easy to get wrong:

- **No normalisation.** Byte-distinct strings stay distinct. `café` written with a precomposed
  U+00E9 and the same word written with a combining accent are two different strings with two
  different digests. Where a schema needs a canonical identifier, it validates it *before*
  encoding, not during.
- **Null is not omission.** A map without key `b` and a map with `b` set to null are different
  objects with different digests. Closed schemas therefore require every field to be present, and
  the Rust types use `Nullable<T>` rather than `Option<T>` so a missing field is an error.
- **Numbers are never floating point.** Decimal or scaled values use a schema-defined integer or
  text representation. UUIDs are 16-byte strings. Timestamps are integer UTC milliseconds, never
  tagged dates.

### Map key order

For text keys the encoded key is `head(length) || utf8`, and the head rises strictly with the
length: `0x60`-`0x77` for lengths 0 to 23, then `0x78`, `0x79`, `0x7a`, `0x7b`. Comparing complete
encoded keys is therefore comparing length first and then the UTF-8 bytes.

This is not the order you get by comparing the key text:

```text
key text order:    "aa" < "z"
encoded key order: "z"  < "aa"     (0x61 0x7a  <  0x62 0x61 0x61)
```

An implementation that sorts the strings instead of the encoded keys produces different bytes and
a different digest. `fixtures/cbor/map-ordering.json` pins the cases, including keys that straddle
the 23-to-24 byte head boundary.

### Limits

Depth, count and length limits apply before allocation. A declared length is checked against both
the configured limit and the bytes actually remaining in the input before any buffer is reserved,
so a peer cannot make the host allocate a gigabyte by claiming a large string.

| Limit | Default | Meaning |
| --- | --- | --- |
| `max_message_len` | 1 MiB | The complete encoded message |
| `max_depth` | 32 | Nesting depth; a top-level scalar is depth 1 |
| `max_items` | 65 536 | Every scalar, array, map and key in the message |
| `max_collection_len` | 4 096 | Members of one array or map |
| `max_bytes_len` | 1 MiB | One byte string |
| `max_text_len` | 1 MiB | One text string |

Callers override these per stream kind. A terminal input stream, for example, is bounded by a
64 KiB frame, so its message bound is 65 532 bytes: the frame less its four-byte length prefix. The
receive limits a peer declares in `hello` are complete-frame bounds for the same reason.

### Why a maintained encoder plus a strict layer

The specification requires maintained encoders with a strict validator and adaptation layer, and
forbids writing a new cryptographic implementation for canonicalisation. Both languages follow the
same split.

`ciborium` in Rust and `cborg` in TypeScript write the bytes and, in Rust, do the serde work. This
repository owns the byte rules on the way in, because a decoded value cannot answer the questions
the profile asks: whether a length was indefinite, whether an argument used a longer head than
necessary, whether two keys collided, what order the keys arrived in, or whether bytes followed the
object. A decoder that answers those questions has to read the bytes, so `kr_cbor::decode` and
`decodeCanonical` do, and each names the rule that failed.

Encoding needs no such reader. `CanonicalValue` admits only permitted shapes and keeps maps in key
order, so a validated tree serialises to canonical bytes: Rust hands it to `ciborium::into_writer`
and TypeScript to `cborg.encode` with `rfc8949EncodeOptions`, which sorts map keys by the encoded
key. The conformance tests check that against the fixture bytes rather than assuming it.

Both decoders finish by re-encoding the value they produced and requiring the input bytes back.
Every rule is already checked while reading, so that is unreachable in a correct decoder. It is
there because canonicity is what signatures rest on: a reader that normalised something instead of
rejecting it would show up as different bytes rather than as a valid signature over a different
value.

Deserialising into a Rust type runs the same check again at the typed level, because serde accepts
more than one representation of the same value. A unit enum variant, for example, arrives either as
its name or as a single-entry map holding null; both produce the same value, and only one of them
is what the type serialises back to. `from_canonical_value` serialises the typed value again and
requires the value it came from, so exactly one representation of each type is reachable. That is
what lets a later stage re-encode a decoded object and still get the bytes its signature covers.

`cborg`'s own decoder is not used for that check. It strips a leading U+FEFF from text strings, so
it reads `"﻿"` and `""` as the same key. That is a different interpretation rather than a
stricter one, and `fixtures/cbor/map-ordering.json` pins the case.

### Digests and signing input

A domain-separated signing input is `CBOR([domain, element, ...])`, encoded canonically. Everything
signed in the protocol has this shape, so no signature covers a fragment of a message and none
covers a re-serialised diagnostic document.

A collection inside a signed object cannot normalise on the way through, or the transcript would
cover bytes the peer never sent. Sets on the wire therefore use `CanonicalSet`, which serialises in
ascending element order and rejects an incoming sequence that is not already strictly ascending, so
a received value re-encodes to the bytes it arrived in. The action-right vocabulary orders by its
wire string, so a reader can verify the order from the encoded values alone.

Two domains live in this repository:

- `kr-connect/1` for the connection proof transcript.
- `kr-mutation/1` for the mutation payload digest.

The mutation digest covers the method and version, the actor and grant, the complete target, the
preconditions, the action identifier, the action window, the requested time to live, and the
parameters. Two exclusions are deliberate:

- `request_id` is **not** covered. It correlates a response on one connection, while the durable
  identity is `action_id`. An exact retry over a new connection carries a new `request_id` and has
  to produce the same digest, otherwise a legitimate retry would look like a reused identifier with
  a changed payload and be rejected as `ID_CONFLICT`.
- `action_window_id` **is** covered. Replacing an expired window changes the payload, which is what
  makes it a new first admission rather than an automatic retry.

## The two representations

| Kind | KR-CBOR-1 wire form | JSON form |
| --- | --- | --- |
| Identifiers | 16-byte string | `b4a1bc38-157d-4e84-bf52-1137b15b462b` |
| Counters, epochs, revisions | unsigned 64-bit integer | `"18446744073709551615"` |
| Timestamps and durations | unsigned integer milliseconds | decimal string |
| Opaque bytes, digests, nonces, keys | byte string | unpadded base64url |
| Text | UTF-8 text | string |

JSON is the managed HTTP representation. Counters are decimal strings because a JavaScript number
cannot carry a `u64` exactly. A JSON number is still accepted when reading a counter, so a
hand-written diagnostic document parses, but everything this repository emits uses the string form.

Base64url is unpadded, and non-canonical encodings are rejected in both languages: padding
characters, standard base64 characters and non-zero trailing bits all fail.

JSON is never a signing representation.

## Version negotiation

Each peer lists every version it supports, and the selection is the highest version present in both
lists. Supporting one minor says nothing about the minors below it, and the specification states no
such compatibility rule, so nothing infers one. A major mismatch returns `UNSUPPORTED_SCHEMA`
before any session data.

The `kr-connect/1` transcript covers the complete offer and the complete selection, so the
negotiated versions, capabilities and limits are all bound by the proof. The host selection echoes
the client nonce as well as carrying its own, which binds one exact offer to one exact selection.

## Framing

Each stream sends a bounded header first, declaring its kind and the authorised resource it
belongs to. The header is at most 1 KiB and is validated against the established control connection
before any data frame is accepted.

A data frame is a four-byte unsigned big-endian length followed by one KR-CBOR-1 object. The length
is validated before the payload is read or allocated. A zero length is invalid, because a
KR-CBOR-1 object is at least one byte.

| Stream kind | Maximum complete frame |
| --- | --- |
| `control` | 1 MiB |
| `terminal_output` | 1 MiB |
| `semantic_updates` | 1 MiB |
| `terminal_input` | 64 KiB |
| `attachment_chunks` | 1 MiB chunk plus 4 KiB of metadata and framing |

Each bound covers the bytes that go on the wire, length prefix included, so the largest payload is
the bound less four. The attachment allowance says so outright, and counting the prefix everywhere
keeps a payload inside the maximum message size as well.

The bound is a property of the stream kind, which is how the larger attachment limit stays
unavailable on a control stream.

## Envelopes

A request carries `request_id`, `method`, `method_version` and `params`.

A mutation carries those four plus `action_id`, the grant reference, the target identity, the
subject preconditions, `action_window_id` and `requested_ttl_ms`.

A response correlates `request_id` and carries an outcome that is either a result or an error. The
durable operation identity is `action_id`, not `request_id`.

A notification carries a stream identifier, a sequence, an event type and a payload.

`params` and `expected` are opaque canonical values in the envelope. The host validates the
envelope, resolves the method in the registry, and only then parses that method's own closed
parameter schema. That ordering is what lets an unknown method return a correlated error instead of
failing to parse.

An opaque value renders to JSON for diagnostics only. Byte strings become base64url and integers
become decimal strings, so nothing loses precision, but reading that JSON back cannot tell which
strings were byte strings or integers. The section 23 example shows small integers as JSON numbers;
that block is a diagnostic rendering, and section 4's exactness rule is what this implements.

An enum on the wire is externally tagged: a variant with fields is a single-entry map whose key
names the variant, and a variant without fields is that name as a text string. A tagged
representation would buffer the variant's content, which both hides unknown fields on a variant
that carries none and changes the representation of the scalars inside it.

Mutation types use `#[serde(deny_unknown_fields)]`. An unknown field rejects; it is never stripped
and then verified.

## Receipt states

A receipt has a monotonically increasing revision and moves only along these edges:

```text
received ──> accepted ──> dispatching ──> applied
    │            │              ├───────> refused
    └──> rejected└──> rejected  └───────> unknown ──> applied
                                                  └─> refused
```

| State | Meaning |
| --- | --- |
| `received` | A transient connection acknowledgement. Never durable acceptance. |
| `accepted` | The intent is durably committed. No dispatch marker yet. |
| `dispatching` | A durable marker was committed before crossing the external-effect boundary. |
| `applied` | The authoritative interface acknowledged the operation. Terminal. |
| `refused` | The authoritative interface proved refusal without the requested effect. Terminal. |
| `rejected` | Never dispatched: admission failure, expiry, cancellation, revocation or stale preconditions. Terminal. |
| `unknown` | Dispatch may have occurred. Never redispatched. Reconciliation may resolve it. |

There is no `dispatching -> rejected` edge. Once a dispatch marker exists, no later transition may
imply that an uncertain side effect did not happen. A rejection names its reason; no other state
carries one. `ReceiptState` and `Receipt::advance` enforce all of this, and the contract tests
check every pair of states.

`applied` for a submitted prompt means upstream admission, not task completion.

## Relay leases and receipts

A relay forwards encrypted payloads between two authenticated endpoints. Admitting an endpoint to a
relay says nothing about who agreed to pay for the traffic it then sends, so before a payload
crosses a forwarding boundary the relay must already hold a lease that binds the pair, the route,
the payer, a reserved block of bytes and a deadline. `crates/kr-protocol/src/relay.rs` holds those
objects and `packages/protocol/src/relay.ts` rebuilds them from the managed JSON representation, so
the service verifies exactly the bytes the relay signed.

Three keys meet in these messages, and no message is trusted because of what it claims about
itself:

| Key | Held by | Signs | Checked against |
| --- | --- | --- | --- |
| Service admission key | the managed service | leases and revocations | the issuer keys the relay pins in its configuration |
| Relay instance key | one relay host, generated there | consumption receipts and its own registration | the key recorded in the service's relay registry |
| Endpoint keys | the two peers | nothing here | the relay's own authenticated handshake |

| Object | Domain | What it settles |
| --- | --- | --- |
| `RelayLease` | `kr-relay/lease/1` | The pair, direction, payer, reservation, cumulative byte ceiling, expiry, route and metering boundary |
| `RelayLeaseRevocation` | `kr-relay/revoke/1` | Stops forwarding at one named relay, at a higher revision than the lease it fences |
| `RelayConsumptionReceipt` | `kr-relay/receipt/1` | What one reservation has spent so far |
| `RelayInstanceRegistration` | `kr-relay/instance/1` | Which key the service accepts receipts from, and the overlap window of a rotation |

Each signature covers `CBOR([domain, <the unsigned object as a map>])`. The objects are closed maps,
so their canonical encoding follows from their field names and there is no second positional
encoding to keep in step.

### The rules the types carry

- **A revision orders everything.** Installation and revocation carry the same `revision` scale per
  lease identity, so a relay keeps the highest it has seen and a replayed older lease cannot restore
  a spent ceiling or a passed deadline. A revocation also names the relay it is addressed to, so the
  same signed bytes replayed at the other relay of a route fence nothing.
- **The scope is a route, not a list.** A lease names an ingress position and an egress position,
  the same instance twice for the ordinary single-relay route. A payload is admitted only when it
  entered and leaves at those positions, swapping with the payload on the reverse direction of a
  two-way lease. A set of permitted instances would not do: it says which relays may forward without
  saying which route they forward on, so a pair could use a second relay of the set and never pass
  the boundary that counts.
- **One boundary counts.** `metering_relay_instance_id` and `metering_role` name one instance and
  one of its two boundaries, so a two-relay route charges a payload once rather than at both ends.
  Ingress counts a payload as it is read from the sender; egress counts it as it is written to the
  receiver, which is the difference between charging for what was accepted and charging for what was
  delivered.
- **One reservation, one running total.** `byte_ceiling` is the reservation's cumulative limit and
  `bytes_consumed` is its cumulative spend, so the relay compares two figures on one scale. A refill
  raises the ceiling of the same reservation; a change to the payer, the pair, the route or the
  metering boundary takes a new reservation, because those are the facts the reservation was priced
  against. `supersedes` enforces exactly that. Section 17's 8 MiB aggregate bounds what is
  *outstanding*, which is the ceiling less what has already been reported, so it is
  `outstanding_bytes` rather than the ceiling itself that a relay checks against its running total.
- **A registration is replaced, not amended.** It carries its own revision, so a registration an
  instance has replaced cannot be replayed to cancel a rotation. `replaces` states the rest: the key
  registered is one the current registration still accepts, so a retired key cannot put itself back;
  the
  announced successor may name itself only once the recorded retirement has passed, so receipts the
  predecessor signed but has not yet delivered still verify; a live succession cannot be dropped,
  only withdrawn before its overlap opens; and a succession a replacement announces retires in the
  future. Together those mean the key that signed a replacement is still accepted afterwards, so no
  single submission can hand an instance to a key that has proved nothing.
- **A grace survives a replacement.** Section 17 gives a principal one grace, starting at its first
  exhaustion, that reconnects cannot restart. `supersedes` therefore refuses a replacement that
  moves either end of a window still in force; it may be cut short. Leaving grace means the
  allowance was restored, which as a figure means a ceiling above what the grace itself permitted:
  without that rule a revision could drop the grace while restoring nothing, and the revision after
  it would be free to open a second window.
- **Grace raises the same ceiling.** The grace after exhaustion belongs to the principal, is shared
  across its connections and starts at the first exhaustion. A relay receives a slice of what is
  left as a raised cumulative ceiling and a deadline, so it cannot restart a grace, extend one or
  hold two allowances at once. `effective_byte_ceiling` and `effective_deadline_ms` derive what the
  relay actually enforces, and `grace_remaining_ms` counts down to that deadline rather than to the
  end of the grace window, so a lease that expires first never advertises time it will not honour.

### What the relay keeps, and what the service settles

A signed lease and a set of pinned keys are not enough to forward safely. A relay also keeps
durably: the highest revision it has seen per lease identity, whether that identity is revoked, the
cumulative bytes counted per reservation, and the receipts it has not yet had acknowledged. Without
the first two, a replayed older lease reopens a closed ceiling. Without the last two, a restart
either loses consumption or invents it, and an exact retry of an installation would hand back a
ceiling that was already spent.

Reporting is idempotent by reservation and sequence, and the sequence is unbroken. A cumulative
count means a duplicate delivery costs nothing and one lost message is repaired by replaying it, not
by skipping it: the service records receipts in order and answers every report with the position it
will accept next, which is where a restarted relay resumes from. It is not a licence to accept a
gap. A relay that cannot supply the receipt in between has lost the evidence for that stretch, and
the service settles the reservation conservatively instead of assuming it away. Section 17 forbids
that settlement from minting a new grace period.

## Error codes

An error carries a stable code, a plain message, a retry category and an optional opaque diagnostic
identifier. The 48 codes are defined in `crates/kr-protocol/src/error.rs` and appear in the
generated schema as the `ErrorCode` enumeration.

| Retry category | What a client may do |
| --- | --- |
| `no_retry` | Nothing automatic. A new user action, subject version or action identifier is needed. |
| `transient` | Retry an idempotent read, a transfer chunk, or a request whose receipt proves no dispatch, under jittered backoff. |
| `resync` | Request a new snapshot and resume from the returned cursor. |
| `configuration_change` | A configuration or software change is needed. Authentication and schema failures land here. |
| `outcome_unknown` | Never retry this action identifier. Show the unknown result. |

`ErrorCode::retry_category` is the single source for the mapping, and `ProtocolError::new` fills the
field from it.

Typed resource states such as `permission_required`, `restart_required`, pending revocation and
voice `creation_unknown` are not error codes. They belong to their own result schemas.

## The method and authority table

`crates/kr-protocol/src/method.rs` holds one exhaustive authority entry per method. The same table
is generated as data to `packages/protocol/schema/method-authority.json` for consumers that are not
written in Rust.

Anything not listed is denied. `decide(name, version, ingress)` returns a denial for an unknown
name, a schema failure for a known method at an unsupported version, and a denial for an ingress
class the entry does not list.

Each entry states:

| Field | What it says |
| --- | --- |
| `effect` | `read` or `write` |
| `ingress` | The only ingress classes that may reach the method |
| `required_rights` | Everything the actor must present, intersected |
| `resource_selectors` | The resources the request names and the host resolves first |
| `history_filter` | How the shared history filter applies to the result |
| `capability` | Which capability evidence is required, and which revision it is bound to |
| `freshness` | Which freshness context the request carries |
| `confirmation` | Whether a fresh owner confirmation is required |
| `idempotency` | How a repeated request is resolved |

Reading the fields:

- An empty `required_rights` list is not "no check". It means scoped read authority and nothing
  more: a valid, unexpired, unrevoked grant covering the named environment and the named resource.
  Only reads of host and environment configuration use it. It is not a universal prerequisite:
  pairing presents a transcript proof, a service method presents a service credential, and a
  private-IPC method presents its caller token, none of which involve a grant.
- `required_rights` is an intersection, not a choice. An entry with a condition other than `always`
  applies only when that condition holds, which is how `session.attach` requires `terminal.geometry`
  just for a geometry claim, and how `pair.status` accepts either the candidate's transcript proof
  or the issuing owner's context.
- Ingress is checked before rights. The private-IPC groups, root integration and the question
  source, list `local_ipc` alone, so a network caller is denied whatever grant it holds. No method
  in this table accepts `plugin` ingress: plugin effects carry their own authority entries.
- Only `pair.redeem`, `pair.finish` and `pair.status` accept an unpaired peer. That is the whole
  pre-authorisation surface.
- `input.write` is the only method with `ordered_stream` idempotency and an `input_lease` freshness
  context. Raw input is an ordered stream per connection, never replayed after a reconnect.

### Rights and capabilities are not the same thing

A right is what a grant permits. A capability is what a binding can currently do. Capability
evidence never creates authority, and a role or configuration label never short-circuits a rights
check: the entries above are the only thing that decides a method.

The one place the two meet is the attachment capability set, and they meet as an intersection
rather than as a substitution. `session.attach` carries the capabilities the attachment asks for,
and what it is granted is those intersected with the rights of the grant the host checked the
request against:

| Capability | The right that carries it |
| --- | --- |
| `observe_terminal` | `session.view` |
| `observe_semantic` | `session.view` |
| `input` | `terminal.input` |
| `geometry` | `terminal.geometry` |

The table is `kr_protocol::rights::attachment_capability_right`, beside the action vocabulary in
`crates/kr-protocol/src/rights.rs`, so a right added to the vocabulary has to be decided for the
capabilities rather than defaulting into one; `permitted_attachment_capabilities` applies it.

Three consequences follow, and they are the reason the mapping is one function rather than a
convention:

- **Asking is not holding.** A request for a capability the grant does not carry yields an
  attachment without it. `AttachmentSummary.granted` reports what was actually given, and every
  later operation on that attachment is checked against it *as well as* against the grant's current
  rights for the method it asks for. The two are separate checks and neither replaces the other.
- **An attachment identifier is not permission.** It names an attachment; what that attachment may
  do is the granted set, which the host wrote when it admitted it.
- **A caller acting under no grant is not narrowed.** A locally authenticated caller's authority is
  the operating-system identity the socket authenticated, so there is no grant to intersect with,
  and it receives what it asked for. `ForwardedMutation.grant_rights` is how the rights reach the
  component that admits the attachment; it is empty for such a caller.

## The root integration

Six methods carry the trusted root shell's side of section 7, and `crates/kr-protocol/src/root.rs`
holds the types they exchange. Five of them are private-IPC only: `root.editor.enter`,
`root.editor.leave`, `root.editor.fence`, `root.eof.detach` and `root.command.accepted` list
`local_ipc` alone, so a network caller is denied whatever grant it holds. `shell.launch` is
reachable from a paired device, because a launch button is a client action, but it still installs
through the reader rather than through the terminal.

| Method | Parameters | Result |
| --- | --- | --- |
| `root.editor.enter` | `RootEditorEnterParams`: the root process, prompt generation, reader revision, which reader started, the reader's state and the shell's working-directory revision | `RootEditorEnterResult`: the state, and the fence exchange the worker started |
| `root.editor.leave` | `RootEditorLeaveParams`: the prompt generation, the reader revision and the reason | `RootEditorLeaveResult`: the state. Leaving invalidates the fence |
| `root.editor.fence` | `RootEditorFenceParams`: the identity the fence will have, the prompt generation, the reader revision, the hold and the cause | `RootEditorFenceResult`: an acknowledgement carrying the queue drain report, the atomic key-queue snapshot, the buffer state and the working-directory revision, or a refusal with its reason |
| `root.eof.detach` | `RootEofDetachParams`: `fence_id`, `prompt_generation`, `input_epoch` | `RootEofDetachResult`: the attachment that was removed, the state and the discarded bytes |
| `root.command.accepted` | `RootCommandAcceptedParams`: the fence, the prompt generation and the origin the reader can prove | `RootCommandAcceptedResult`: the origin the worker recorded |
| `shell.launch` | `ShellLaunchParams`: an argument vector or an already-quoted command, the expected prompt generation and the expected empty-buffer revision, which are the three section 7 gives the caller | `ShellLaunchResult`: the fence, the prompt generation and the buffer revision at acceptance |

`EditorFence` is the ownership proof the whole group rests on: the root process with the kernel's
record of when it started, the prompt generation, the reader revision, the input-lease epoch and
exactly one originating attachment. `FencePublication` is how the worker states whether a fence
became live, stayed withheld, or has since been invalidated. A bridge can infer none of the three:
the 250 ms hold may have expired while its acknowledgement was in flight, and a fence it was given
lasts only until the worker says otherwise.

The hold is `FENCE_EXCHANGE_TIMEOUT`, 250 milliseconds, and it applies to editor entry, to a lease
takeover and to a launch transaction alike. When it expires the lease change still stands: the held
input is released in its original order, the editor stays unfenced for a fence exchange or returns to
fenced for a launch, and `EditorBusyEvent` is emitted on the attachments stream as `editor_busy`.
That event is an editor event, not a failed `input.acquire` response, which is why it carries the
attachment it goes to, the epoch that now holds input and the number of bytes that were released. A
fence acknowledgement that arrives after its hold expired publishes nothing.

`LAUNCH_READER_BUDGET` is 200 milliseconds: the reader's own budget for a launch, shorter than the
worker's hold because the two measure on their own clocks. The decision between installing and
cancelling belongs to the reader, in the step where it reads its mailbox: the frames on the bridge
endpoint are ordered, the worker revokes the transaction when its hold expires, and the reader
checks for that revocation in the same atomic step in which it would install. The caller's answer
then waits for the reader's word: `EDITOR_BUSY` when it installed nothing, the installed result when
it had already installed, and `OUTCOME_UNKNOWN` when the reader can no longer answer at all. The
host installs no command by any other means.

Section 23's other preconditions of `shell.launch`, the current input lease, the qualified root
editor with its fence and empty prompt, the working-directory revision and the launch profile, are
the worker's own: `CwdRevision` travels on the reader-boundary events so the worker has a recorded
revision to check, and the profile is the session's configuration rather than a client field.

Three error codes belong to this group. `EDITOR_BUSY` says the editor could not be fenced or
reserved, and it is transient. `DRAFT_CONFLICT` says the editor's own state had moved, which is an
intervening local edit rather than a busy editor. `AMBIGUOUS_ATTACHMENT` answers a `kr detach` with
no attachment identifier when the recorded origin is mixed or no longer verifiable.

[docs/shell-integration/README.md](../shell-integration/README.md) is the contract a shell-package
author implements against: the bridge endpoint, the `kr-shell-bridge/1` handshake, the reader-thread
rules, the state machine and the cross-shell scenarios.

## Account authority objects

An organisation states membership with a signed object, so a host can check it while the service is
unreachable. `crates/kr-protocol/src/account.rs` holds three of them, and `packages/protocol`
builds the same bytes in TypeScript.

| Domain | Payload | What it says |
| --- | --- | --- |
| `kr-membership-lease/1` | `MembershipLeasePayload` | One account held one role in one organisation until a stated time |
| `kr-policy-authority/1` | `PolicyAuthorityLinkPayload` | One revision of an organisation's policy-signing key, signed by the revision it follows |
| `kr-policy-authority-head/1` | `PolicyAuthorityHeadPayload` | Which revision signs leases now, signed by that revision |

Each signature covers `CBOR([domain, payload])`, where the payload is the record without its
signature, encoded as a canonical map. The domain is what stops one statement being read as
another.

A lease lasts at most fifteen minutes and is refreshed every five. It names `maximum_grants` from
the action-right vocabulary the rest of the protocol uses, so a host intersects a lease with the
grants it already understands rather than with a second set of names. The role is a label for that
ceiling: `TeamRole::maximum_grants` is the most a role may ever carry, a lease may name less, and
`MembershipLeasePayload::grants_within_role` is the check that it names no more. Authority still
comes from the grants, never from the label.

The first revision of a chain signs itself and names no predecessor, which is what a host pins.
Every later revision names the revision whose key signed it, so a host walks forward from the
revision it pinned without being told which key to trust. Any prefix of a chain verifies on its
own, so the head statement is what says the chain is complete.

`PolicyAuthority::check_structure` makes every check that needs neither a signature nor the clock:
ordering, succession, activation times, that the head names the last revision, and that it was not
issued before that revision took over. Accepting a chain is that check, then matching the pinned
link against the pin itself — organisation, revision and public key — rather than verifying its
signature, which belongs to its predecessor at every revision after the first, then the signature
of each later link under the key of the revision it names as its predecessor, then the head under
the key of the revision the head names, then that the head is valid at the current time, then
refusing a head below the highest revision this host has already accepted — and only then
recording the new highest revision.

A chain authenticates forward. `PolicyAuthority::authenticated_from` returns the links a host may
verify anything against, given the revision it pinned: the pin and everything after it. A lease
naming a revision from before the pin is refused rather than checked against a key nothing the host
holds authenticates.

What that proves has a boundary worth stating. A head expires, so a captured head stops being
usable, and a host that has accepted a later revision refuses one naming an earlier revision.
Neither fact proves that the private key of a retired revision is gone: a host that never saw the
rotation cannot tell a fresh revision-1 head signed by a retained revision-1 key from a legitimate
one. Rotation therefore destroys the private half of the revision it retires, and a host that must
detect a compromised predecessor needs evidence from outside this chain.

## The service credential

Every method in the `Services` group of section 23 is authenticated the same way, by one credential
defined in `crates/kr-protocol/src/service.rs`. No account is involved. What a caller proves is that
it holds the private half of one key, and that the request in front of the service is the request
that key signed.

A signature covers `CBOR([domain, ServiceRequestPayload])`, and the payload carries five fields:

| Field | What omitting it would allow |
| --- | --- |
| `gateway_origin` | A signature made for one deployment replayed against another |
| `method` | A signature for a read presented as the authorisation for a write |
| `nonce` | The same signed request accepted twice |
| `signed_at_ms` | A captured request held and presented much later |
| `body_digest` | The body swapped for another under a signature that still verifies |

Two kinds of caller reach these methods, so there are two domains and no other difference. A native
installation signs under `kr-service-request/1` with its device authorisation key. A host signs under
`kr-service-request/1/host` with its host signing key, which is how `push.sender.renew`,
`push.sender.revoke` and a host's `authority.sync` are proven. The separation is in the bytes rather
than in a label beside them, so relabelling a signature cannot turn one into the other.

A service admits a signature whose `signed_at_ms` is inside five minutes of its own clock, in either
direction, and remembers the nonce for twice that long: a signature dated the full window ahead is
still admissible for another whole window after it was made. `ServiceRequestPayload::is_fresh_at` is
the first check and `nonce_retained_until_ms` says how long the second one has to remember.

`InstallationId` is the first sixteen bytes of the SHA-256 of the device authorisation public key,
written in hyphenated form. It is derived rather than asserted: a caller that presents a key and a
signature has already proved which installation it is, so nothing in a request body says who the
caller is. An identifier is 128 bits, so it names a key rather than standing in for one: a service
records the whole key it first saw, looks it up by the identifier, and compares against the key. A
later request carrying a different key is refused, which makes replacing an installation key a
deliberate step rather than a side effect of asking.

An origin is an origin, so `GatewayOrigin` uses the grammar `RendezvousOrigin` already fixes: a
scheme, a canonically spelled host, an optional non-default port, and nothing else. The one
difference is that plain HTTP is admitted for a loopback host, which is what a development
deployment serves on. `fixtures/service/requests.json` publishes every origin both languages accept
and every spelling both refuse, and each language's tests run the whole list.

## Push objects

`crates/kr-protocol/src/push.rs` holds the notification contract of section 16. Three things happen
in order, and each refuses to start before the one before it finished.

**Registration.** An installation asks the gateway to bind a provider token to its identity. The
gateway sends a single-use challenge through the provider, to that token, and waits for it to come
back signed under `kr-push-registration/1`. An authenticated request proves the caller holds a key;
only the round trip proves the caller receives what is sent to that token. Until the answer returns,
the registration stays pending and no sender credential is issued.

The answer covers the whole challenge: the token digest, the registration identifier, the gateway
origin, the platform, the installation and the five-minute expiry. Without the token digest an answer
would activate a token nobody proved receipt of; without the origin it would answer a different
deployment's challenge; without the registration identifier it would complete whichever attempt
happened to be pending.

A token is indexed by `SHA-256(CBOR(["kr-push-token/1", token]))`. Nothing about the caller is in
that digest, the platform label least of all: receiving the challenge proves the token reaches this
device and proves nothing about the label beside it, so a digest that included the label would let
one device register one token twice and start its rate history again. There is exactly one canonical
active binding per token digest, and the rate history stays with the digest through a key
replacement.

The gateway does hold the token itself, because FCM needs it to deliver and to retry and no hash
recovers one. It lives with the gateway's own secrets; the records that travel carry the digest.

A signed request's body is a `PushRequest`: one type for the four signed methods, so there is one
rule for what a service-request signature covers. `PushRequest::digest` is the `body_digest` the
signature carries and `PushRequest::method` is the method it must name, which is what stops a body
built for one method being presented under another. Delivery is not one of them: it carries the
bearer credential the host was issued, and its digest is how the gateway recognises a request it has
already handled.

**Authorisation.** `PushSenderBinding` holds everything one authorisation fixes for its lifetime:
the destination installation, the host's endpoint and signing keys, the gateway and the rate policy.
It is digested under `kr-push-sender/1`, so `PushSenderRecord::renewal_preserves_binding` is a
comparison of one digest rather than a list of fields somebody has to remember to extend.

The authorisation and the credential have different lifetimes on purpose. The authorisation is the
installation's decision and lasts until it is revoked. The credential is a bearer a host keeps on
disk, so it expires in thirty days and is renewed by the host signing `kr-push-sender-renewal/1` over
a nonce the gateway issued. Renewal opens seven days before expiry and does not close at expiry: a
host that was offline for a month renews on reconnect, because its credential lapsed and the
authorisation behind it did not. A revoked record renews never. The gateway stores the SHA-256 of the
bearer under `kr-push-credential/1`, never the bearer, so a copy of the database is not a set of
working credentials.

**Delivery.** A `PushDeliveryRequest` carries a notification identifier, a collapse label, an
expiry, the sealed preview and a choice from a closed alert vocabulary. There is no field for text a
sender supplies, and the rest of the shape is what a gateway can actually check:

- the alert is one of six values whose words live in `PushAlert::generic_text`, which is how section
  16's "the plaintext alert is generic" is enforced rather than asked for;
- the notification and collapse identifiers are 128-bit values rather than text, so nothing that
  reads as a project or session name fits in either;
- the preview is a `SealedEnvelope` rather than arbitrary bytes, and
  `PushDeliveryRequest::preview_is_well_formed` checks that the envelope expires when the
  notification does, that its declared size bucket is a notification bucket, and that its ciphertext
  is exactly that bucket plus the seal's overhead.

Those are checks of format and length. They do not inspect a producer, and they cannot: nothing here
proves the ciphertext is ciphertext, that it was sealed to the right key, or that the identifiers
mean nothing. A host that encoded something into its own identifiers, or sealed the wrong thing, has
disclosed it to the provider and to the gateway. Section 16 puts that obligation on the producer,
and so does this contract: generate the notification identifier at random, derive the collapse label
from a host-local secret, and seal the preview to the destination's notification-preview key.

Previews may be disabled on the device, in which case `preview` is null and the generic alert still
arrives.

The size bounds are enforced where each can be. 1,800 bytes is a plaintext bound, so the host checks
it while it still has the plaintext and moves anything larger into a referenced encrypted object; a
gateway holds no key that opens a preview and does not pretend to check it. 3,500 bytes is the
complete provider payload after encryption and base64, so the gateway measures the request it is
about to send. Both bounds are exclusive where section 16 words them that way.

Delivery is answered with a `PushDeliveryAck`. `queued` means the provider accepted it for delivery
and nothing more: it does not mean displayed, read or executed, and review state comes from host
events and client acknowledgements instead. The other states are an acknowledgement that something
else happened, and each is a fact the host needs: a transient provider failure the gateway is still
retrying, a duplicate notification identifier, a destination over its rate policy whose notification
collapsed into an attention update, a token the provider rejected and the gateway disabled, or a
notification that expired first. A suppressed notification is reported back with what it collapsed
into and when the next update may be sent, so the host can record the suppression locally and keep
the pending decision visible.

## Fixtures

`fixtures/cbor/`, `fixtures/protocol/`, `fixtures/relay/`, `fixtures/accounts/`, `fixtures/service/`
and `fixtures/push/` hold the vectors
both languages run against. The Rust
tests read them from `crates/*/tests/`, and the vitest suites read the same files.

Values use a small tagged grammar, so a fixture can express a byte string, a 64-bit integer and a
deliberately unsorted map, none of which plain JSON can carry:

| Form | Means |
| --- | --- |
| `{"int": "-18446744073709551616"}` | An integer, as a decimal string |
| `{"bytes": "00ff"}` | A byte string, as hex |
| `{"text": "café"}` | A text string |
| `{"bool": true}` | A boolean |
| `{"null": true}` | Null |
| `{"array": [value, ...]}` | An array |
| `{"map": [["key", value], ...]}` | A map, listed in source order |

Map entries are listed in source order and a conforming encoder sorts them, which is how the
ordering cases test what they claim to test.

| File | Covers |
| --- | --- |
| `cbor/integers.json` | Every argument width boundary in the 64-bit range |
| `cbor/strings.json` | Non-ASCII text, precomposed against decomposed, case, and byte strings that are not valid UTF-8 |
| `cbor/map-ordering.json` | Key ordering, including where the key text and the encoded key disagree |
| `cbor/null-and-absent.json` | Absent fields against explicit nulls, with digests |
| `cbor/structures.json` | Arrays, booleans and nesting |
| `cbor/invalid.json` | Every forbidden representation, each with the rule a decoder must report |
| `cbor/digests.json` | A signed object with its digest, and a domain-separated signing input |
| `protocol/frames.json` | Encoded `hello`, mutation, receipt, error, notification and stream header, with their frames |
| `protocol/transcripts.json` | The `kr-connect/1` transcript and the mutation digest |
| `relay/leases.json` | A two-way lease on a two-relay route, a sponsored single-relay lease inside its grace, and a revocation |
| `relay/receipts.json` | Two consumption receipts of one reservation, showing the cumulative count |
| `relay/instances.json` | A relay instance registration and an announced key rotation |
| `relay/envelopes.json` | The install, revoke, report and registration messages that carry them |
| `crypto/relay.json` | Ed25519 signatures over those objects, by the relay instance key and the service admission key |
| `accounts/leases.json` | The signing input of every account authority object, with the role ceilings and lifetimes |

An invalid case names its rule with the same string in both languages, for example
`unsorted_map_keys` or `non_shortest_integer`. `CborError::rule` in Rust and `KrCborError.rule` in
TypeScript return those strings. A case may carry a `limits` object, merged over the defaults, so a
short vector can test a bound without a megabyte of input.

A relay case states the same object four ways: `value` in the grammar above, `cbor_hex` for its
canonical encoding, `signing_input_hex` with `sha256` for what a signature covers, and `json` for
the managed HTTP representation. Each one catches a different mistake, and a change to the type
fails the vector in whichever of the four it actually altered. Both languages also rebuild the
object from `json` alone and check that it signs the same bytes, because that is the path the
managed service takes with a receipt that arrives over HTTPS.

The relay's signature vectors are in `fixtures/crypto/relay.json`, because they need a signing
implementation: `kr-crypto` holds the relay instance key and the service admission key as purposes
of their own, and the TypeScript suite verifies what it produced with the Node runtime, which
shares no code with libsodium.

These fixtures cover bytes, digests and signing input. Signature vectors need a signing
implementation, which lives with the cryptography crate rather than here; that crate consumes
`fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` as its inputs and adds fixed
keys, expected signatures and negative verification cases beside them.

## Generation and checking

```text
Rust types  ──generate──>  packages/protocol/schema/*.json  ──generate──>  src/generated/protocol.ts
            <──  check  ──                                  <──  check  ──
            ──generate──>  fixtures/service/*.json, fixtures/push/*.json
            <──  check  ──
```

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Regenerate the schema, the method table and the service and push vectors, then check them
cargo run -p kr-protocol --bin kr-protocol-gen
cargo run -p kr-protocol --bin kr-protocol-gen -- --check

# TypeScript
pnpm install --frozen-lockfile
pnpm -C packages/protocol generate
pnpm -r test
```

`kr-protocol-gen --check` compares the committed files with what the current Rust types produce and
names the first differing line. `pnpm -C packages/protocol generate:check` does the same for the
generated TypeScript, and the vitest suite runs it, so `pnpm -r test` fails when the types are
stale.

Changing a wire type means: edit the Rust type, run the generator, run the TypeScript generator,
and commit all four artefacts together.
