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

Callers override these per stream kind. A terminal input stream, for example, uses a 64 KiB message
bound.

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

| Stream kind | Maximum frame payload |
| --- | --- |
| `control` | 1 MiB |
| `terminal_output` | 1 MiB |
| `semantic_updates` | 1 MiB |
| `terminal_input` | 64 KiB |
| `attachment_chunks` | 1 MiB chunk plus 4 KiB of metadata |

The attachment bound is a property of the stream kind, which is how the larger limit stays
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

- An empty `required_rights` list is not "no check". It means the baseline only: a valid, unexpired,
  unrevoked grant covering the named environment. Everything else adds to that baseline.
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

## Fixtures

`fixtures/cbor/` and `fixtures/protocol/` hold the vectors both languages run against. The Rust
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

An invalid case names its rule with the same string in both languages, for example
`unsorted_map_keys` or `non_shortest_integer`. `CborError::rule` in Rust and `KrCborError.rule` in
TypeScript return those strings. A case may carry a `limits` object, merged over the defaults, so a
short vector can test a bound without a megabyte of input.

These fixtures cover bytes, digests and signing input. Signature vectors need a signing
implementation, which lives with the cryptography crate rather than here; that crate consumes
`fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` as its inputs and adds fixed
keys, expected signatures and negative verification cases beside them.

## Generation and checking

```text
Rust types  ──generate──>  packages/protocol/schema/*.json  ──generate──>  src/generated/protocol.ts
            <──  check  ──                                  <──  check  ──
```

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Regenerate the schema and the method table, then check them
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
