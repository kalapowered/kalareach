# KalaReach protocol reference

This describes the shared interface layer: the canonical encoding, the framing, the message
envelopes, the receipt contract, the error codes and the method authority table. It covers what
this repository implements. Transport, pairing cryptography and storage are separate.

[methods.md](methods.md) lists every method in the registry, generated from it, with its effect,
its ingress, its summary and the section that describes it. [method-reference.md](method-reference.md)
describes the methods that none of the other guides describes. [glossary.md](glossary.md) defines
the terms the protocol relies on.

Four pieces make it up:

- `crates/kr-cbor` is the KR-CBOR-1 codec: canonical encoding, strict decoding, digests and
  domain-separated signing input.
- `crates/kr-protocol` holds the wire types the host, its workers and its clients exchange, the method
  registry and the schema generator. The request bodies of the mailbox, authority-feed, settings-sync,
  backup-manifest and storage methods are JSON documents that `crates/kr-client/src/services` builds
  and that the managed service reads; [the service credential](#the-service-credential) says how
  they are signed.
- `packages/protocol` is the generated TypeScript package with a codec that produces the same
  bytes.
- `fixtures/` holds the vectors both languages are tested against.

Rust is canonical. The JSON Schema comes from the Rust types, and the TypeScript types come from the
schema. Both steps have a check mode, so a change on one side that is not carried to the other fails
the build rather than drifting unnoticed.

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
  objects with different digests. A closed schema therefore requires every field to be present, and
  the Rust types use `Nullable<T>` rather than `Option<T>` so that a missing field is an error. The
  exception is a member that a type declares absent when unset. It is left out of the encoding when
  it holds nothing: `None` for an optional member, `false` for the three flags `error_withheld` of a
  receipt, `link_fenced` of an error and `holds_local_access` of a worker launch, and the empty or
  default value for a few others, such as the extension offers of a hello. A value that states such a
  member at its default is refused as non-canonical, because it would re-encode to different bytes: a
  sender that writes `"link_fenced": false` or `"line_token": null` is refused, and one that leaves
  the member out is not. The members are `presentation_reason` of an attachment summary,
  `line_token` of a detach, `link_fenced` of an error, `machine`, `privacy`, `default_shell_mode`
  and `metrics` of the host reads, `cause` of a history gap, `error_withheld` of a receipt,
  `session_id` of an action read, `environment_sources`, `root` and `application` of a session
  summary, `metrics` of a session read, `session` of a close result, `origin` and `build` of the
  local hello and its acknowledgement and `build` of the bridge hello acknowledgement, `history`,
  `screen_basis`, `workflow_run_id` and `lease` of a forwarded request or mutation, and the optional
  members of a worker launch and of an authority revision notice. The generated schema and
  TypeScript type accept the explicit default that the decoder refuses: null for an optional member
  and `false` for a flag. The host configuration document, which is JSON read from a file and not a
  wire message, leaves out its sections of later levels, its `disable_policy` and a test suite's
  `outputs` in the same way.
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

The first two domains below are described in this section. The table after them lists every domain
the protocol defines: every domain of a signature, a digest, a derived key or an associated-data
string that a second program or device has to compute again or verify. Each constant sits beside the
type it covers in `crates/kr-protocol/src`, except the ones the table's file column names in another
crate. A domain that labels a value only the program that made it reads back is not part of the
protocol, and a second table after the first names those.

- `kr-connect/1` for the connection proof transcript.
- `kr-mutation/1` for the mutation payload digest.

| Domain | What it covers | File |
| --- | --- | --- |
| `kr-connect/1`, `kr-mutation/1` | The connection proof transcript; the mutation payload digest | `hello.rs`, `digest.rs` |
| `kr-action-subject/1` | The subject digest of an action | `action.rs` |
| `kr-extension/1`, `kr-declarative-table/1` | The schema hash of an extension; the content digest of a declarative table | `extension.rs`, `gateway.rs` |
| `kr-key-id/1` | A key identifier, derived from a key purpose and a public key | `pairing.rs` |
| `kr-pair/spake2-ed25519/1`, `kr-pair/host`, `kr-pair/client` | The short-code pairing transcript and the two role identities of the key exchange | `pairing.rs` |
| `kr-pair/verify/1`, `kr-pair/direct/1`, `kr-pair/direct-verify/1` | The short-code verification value; the direct-mode transcript and its verification value | `pairing.rs` |
| `kr-pair/host-bundle/1`, `kr-pair/client-bundle/1`, `kr-pair/finish/1` | The signed device bundle of each side; the binding tag of `pair.finish` | `pairing.rs` |
| `kr-pair/owner-confirm/1`, `kr-pair/issue-invitation/1` | An owner-confirmation proof; an owner's confirmation to issue an invitation | `pairing.rs`, `invitation.rs` |
| `kr-pair/confirm-device/short-code/1`, `kr-pair/confirm-device/direct/1` | The action digest of a device confirmation, one for each entry mode, so a confirmation for one cannot approve a candidate that arrived by the other | `kr-pairing` |
| `kr-pair/1/client-confirm`, `kr-pair/1/host-confirm`, `kr-pair/1/client-to-host`, `kr-pair/1/host-to-client`, `kr-pair/1/iroh-bind` | The HKDF-SHA256 information strings of the five keys one pairing attempt derives: the client's and the host's confirmation keys, the key of each direction's bundle and the key of the `pair.finish` tag that binds the transcript to the two iroh endpoints | `pairing.rs` |
| `kr-pair/client-budget/1` | The key under which a device counts its own short-code attempts | `kr-pairing` |
| `kr-device-keys/1` | A device's declaration of its four public keys (`device.keys.complete`) | `sharing.rs` |
| `kr-revocation/1`, `kr-authority/1` | A revocation request signature; a host authority revision record signature | `pairing.rs` |
| `kr-membership-lease/2`, `kr-policy-authority/1`, `kr-policy-authority-head/1`, `kr-organisation-policy/1` | The four account authority objects | `account.rs` |
| `kr-mailbox-claim/1` | The value that claims a mailbox | `mailbox.rs` |
| `kr-archive-manifest/1`, `kr-recovery-bundle/1`, `kr-backup-writer/1`, `kr-backup-publication/1` | An archive manifest signature; the context a recovery bundle's key is derived from; a collection's writer enrolment; one published generation | `archive.rs` |
| `kr-collection-keys/1` | A shared collection's key record | `collection_keys.rs` |
| `kr-relay/lease/1`, `kr-relay/revoke/1`, `kr-relay/receipt/1`, `kr-relay/instance/1` | A relay lease, its revocation, a consumption receipt and an instance registration | `relay.rs` |
| `kr-service-request/1`, `kr-service-request/1/host` | A service request signed by an installation; one signed by a host | `service.rs` |
| `kr-push-registration/1`, `kr-push-sender/1`, `kr-push-sender-renewal/1`, `kr-push-sender-revocation/1` | A registration answer; the immutable half of a sender record; a renewal proof; a revocation | `push.rs` |
| `kr-push-delivery/1`, `kr-push-token/1`, `kr-push-credential/1`, `kr-push-request/1` | Digests: a delivery request, a provider token, a delivery credential's bearer and a signed push request body | `push.rs` |
| `kr-voice/confirm/1`, `kr-voice/action/1` | A voice confirmation signature; a voice action digest | `voice.rs` |
| `kr-worker/1/rendezvous`, `kr-worker/1/verify`, `kr-controller/1/generation` | A worker's startup rendezvous; its answer to a verification challenge; a controller's generation token | `worker.rs` |
| `kr-host-clock/1`, `kr-catalogue-trust/2`, `kr-plugin-grant/1`, `kr-plugin-install/2`, `kr-organisation/enrol/1`, `kr-organisation/exclusive/1`, `kr-transfer/2` | What an owner confirms: the host clock again, a repository's trust root, a package's grant, a package's installation, an organisation's enrolment, the exclusive-management setting of an organisation set, the complete plan of a grant transfer. Each is the first member of the value whose digest the confirmation covers, and an owner device computes the same digest again from what it is shown | `confirmation.rs` |
| `kr-plugin-host/1/rendezvous`, `kr-plugin-host/1/verify` | A plugin host's startup claim; its answer to a verification challenge | `crates/kr-plugin-service/src/protocol.rs` |
| `kr-relay-lease-request/1`, `kr-relay-lease-revoke/1`, `kr-relay-payer-sign-in/1`, `kr-relay-admission-request/1` | The body digests of the four relay control-plane requests ([The relay requests](#the-relay-requests)) | `crates/kr-client/src/services/relay.rs`, `admission.rs` |
| `kr-sync-object/1` | The associated data every synchronised object is sealed under, so that a ciphertext made for one purpose cannot be opened as another | `crates/kr-crypto/src/envelope/sync.rs` |
| `kr-collection-key-mark/1`, `kr-sync-membership-plan/1` | The digest by which members compare a collection's key without keeping it; the digest that binds an owner's membership plan to the one operation it confirms ([the cryptography reference](../crypto/README.md)) | `crates/kr-client/src/sync/membership` |
| `kalareach-recovery-kit-fingerprint/1` | The eight-symbol fingerprint of a recovery kit's recipient key, which a person compares to tell one kit from another | `crates/kr-client/src/recovery/setup.rs` |
| `kr-describe/profile/1` | The detached signature of a model profile: its identifier, its revision and the digest of its document, which a host checks before it maps a model | `crates/kr-describe/src/profile.rs` |

A format tag is not a domain. `kr-keywrap/1`, `kr-mailbox/1`, `kr-collection-key-wrap/1` and
`kr-sync-membership/1` are the only value that a record's version member accepts, and a record
that holds another value is not read.

A domain that labels a value only the program that made it reads back is not part of the protocol,
and the table does not list it. The crates hold several, and this reference does not enumerate them.
These are the ones a reader of the other sections meets:

| Domain | What it labels | File |
| --- | --- | --- |
| `kr-sharing/1` | A grant or invitation identity, derived from an action identifier and a purpose label, so that a retry finds the identity it made | `sharing.rs` |
| `kr-project-location-authorise/1`, `kr-project-location-attach/1` | What an owner confirms when a project location is authorised or a repository is attached to one: the exact request and the identity of the directory the host opened for it. The host computes the digest and places it in the challenge | `crates/kr-project/src/policy.rs` |
| `kr-project-location-authorise-request/1`, `kr-project-location-attach-request/1` | A request without its proof, which a repeat of the request has to match | `crates/kr-project/src/policy.rs` |
| `kr-question/create/1`, `kr-alert/create/1` | A question or an alert as created, which tells an exact repeat from a reused request or deduplication identifier | `crates/kr-worker/src/questions/store.rs` |
| `kr-question/caller-token/1` | A question's caller token, separating its sealed copy from its verification tag | `crates/kr-worker/src/questions/token.rs` |
| `kr-delivery/collapse/1`, `kr-delivery/detail-object/1` | Keyed digests under a secret that only the environment's delivery journal holds: a notification group's collapse identifier and the identifier of the encrypted object that holds a notification's detail | `crates/kr-delivery/src/budget.rs`, `preview.rs` |
| `kr-voice/prepare/1` | What a planned voice call would be bound to: its sessions, its actions and its provider | `crates/kr-voice/src/delegate.rs` |
| `kr-pair/client-budget-key-id/1` | The digest that names the key a device counted its short-code attempts under | `crates/kr-pairing/src/budget.rs` |
| `kalareach-account-mark/1` | The mark of one account at one service, from the issuer, the account's subject and the service's origin, so that a caller can tell that a token is still its account's | `crates/kr-client/src/services/account.rs` |
| `kalareach-backup-session/1`, `kalareach-backup-source/2` | The digest of one session as a backup generation keeps it, and the digest of everything a pass could pack | `crates/kr-controller/src/service/backup_production.rs` |
| `kalareach phone boot v1`, `kalareach.changeset.version.v1` | A phone's boot identity for its pairing clock; the version digest of a captured tree, which never travels on the wire | `crates/kr-client/src/pairing/clock.rs`, `crates/kr-changeset/src/version.rs` |

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

JSON is never a signing representation. The one thing that looks like an exception is not one: the
body of a managed-service request is a JSON document, and what is signed is its KR-CBOR-1 encoding,
as [the service credential](#the-service-credential) describes. The answers of the managed service
carry some timestamps as ISO 8601 strings (`expires_at`, `stored_at`, `published_at`), which these
rules do not cover, because they are service data and not protocol objects.

## Version negotiation

Each peer lists every version it supports, and the selection is the highest version present in both
lists. Supporting one minor says nothing about the minors below it, and the specification states no
such compatibility rule, so nothing infers one. A major mismatch returns `UNSUPPORTED_SCHEMA`
before any session data.

The `kr-connect/1` transcript covers the complete offer and the complete selection, so the
negotiated versions, capabilities, limits and extensions are all bound by the proof. The host
selection echoes the client nonce as well as carrying its own, which binds one exact offer to one
exact selection.

Extensions are negotiated in the same exchange, by identifier and schema hash. The offer's
`extensions` maps each extension the client implements to the hash of the schema it holds; the
selection's `extensions` holds exactly the offered entries the host implements with the identical
hash. A host that does not implement an offered extension, or holds another schema for it, leaves
it out and the connection goes on without it. A client refuses, with `UNSUPPORTED_SCHEMA`, a
selection that names an extension it did not offer with that hash, on the paired path and on the
candidate path to the pairing surface alike. Both maps are left out of the message when they are
empty, so an offer or selection without extensions has the bytes it had before; a present, empty
map does not re-encode to itself and is refused. See [Read-only metadata and
extensions](#read-only-metadata-and-extensions).

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

Every object is closed: a field its schema does not declare is refused, never stripped and then
verified. Every type says so in serde as well, with `#[serde(deny_unknown_fields)]`, and in the
published schema, with `"additionalProperties": false`. The one exception is read-only metadata,
below. The answers of the managed service are a separate case: a service client reads them through
its own closed reader, and a few of those answers accept members they do not know, so that a newer
service does not break an older client. They are not protocol objects and no signature covers them.

## Reading a message

A receiver reads every protocol message in the order section 9 sets, and stops at the first step
the message fails:

1. **Bytes.** `kr_cbor::decode` applies every KR-CBOR-1 rule before it builds a value: duplicate
   keys, invalid UTF-8, key order, forbidden representations and the limits.
2. **Schema.** `kr_cbor::check` reads the value against the structure its type publishes and refuses
   a key that structure does not declare. The structure is compiled, once per type, from the JSON
   Schema that `schema_for::<T>()` derives from the Rust type, which is the schema this repository
   publishes in `packages/protocol/schema/`. Variants told apart by a tag
   field are checked against the variant the tag names, exactly as the typed decoder selects it; a
   tag that names no variant is refused.
3. **Type.** serde builds the typed value, and the round trip holds it to the one encoding the type
   writes.

A message refused at the first or second step never reaches the typed decoder. `kr_protocol::wire`
is the entry point, and the frame codec, both frame readers, the stream header and
`ParamsValue::to_typed` go through it. An opaque value, such as a method's parameters, is not read
by the envelope's structure; its own schema is checked when it is read with `to_typed`.

| Refusal | Rule | Code |
| --- | --- | --- |
| A duplicate key, invalid UTF-8 or any other byte rule | `duplicate_key`, `invalid_utf8`, ... | `INVALID_ARGUMENT` |
| A field the schema does not declare | `unknown_field` | `UNSUPPORTED_SCHEMA` |
| A tag naming a variant the schema does not have | `unknown_variant` | `UNSUPPORTED_SCHEMA` |
| A member of an extension not negotiated where it appears | `unnegotiated_extension` | `UNSUPPORTED_SCHEMA` |

`kr_protocol::wire::refusal_code` and `FrameError::code` classify a refusal, and
`TransportError::to_protocol_error` and `IpcError::code` report a frame refusal under that code. A
receiver that cannot read a frame does not answer it in place: a hello offer it refuses, for
example, ends the handshake. A method handler that parses its parameters answers `INVALID_ARGUMENT`
for every parameter refusal, an undeclared field included. The plugin runtime's and the shell
bridge's own frames publish no schema; their readers apply the byte rules and then their closed
types, without the schema step.

## Read-only metadata and extensions

Mutation schemas are closed for the negotiated version. Read-only metadata may carry explicitly
optional fields a receiver does not know: a type opts in with the schema keyword
`x-kalareach-read-only-metadata` and without `deny_unknown_fields`, and the check removes an
undeclared field there before typed decoding and never delivers it. `HostInfoResult`,
`EnvironmentListResult`, `EnvironmentSummary`, `HostPrivacyState` and `DefaultShellMode` are
read-only metadata. A field a newer host adds
to one of them is optional, absent when unset, and an older client ignores it. A test holds that no
parameter schema, envelope, handshake message, signed object, event or write result reaches a
read-only metadata type, so an ignored field is never one a signature or a digest covers.

An extension adds one member to each read-only metadata type it extends: an entry whose key is the
extension's identifier, two or more dot-separated lower-case segments such as
`org.example.thermal`, and whose value its schema describes. No declared field name has a dot, so a
receiver tells an extension member from a field without knowing the extension. Its schema hash is
SHA-256 of the KR-CBOR-1 encoding of `["kr-extension/1", identifier, {type name: member schema}]`,
which covers the identifier, every type it extends and the exact JSON Schema of each member.

A member of an extension that the connection did not negotiate, or that does not extend the object
carrying it, is refused before typed decoding. A member of a negotiated extension is a protocol type
of its own (`MemberBlock::of::<T>`), and the hash covers that type's published schema. It is read
into that type, structure first and then typed decoding, before the message carrying it is read, so
a member that is missing a field, carries one of the wrong kind or out of range is refused like any
message; it is then removed and returned beside the message by `kr_protocol::wire::decode_extended`.
This build implements no extension, so it offers and selects none and every extension member it
receives is refused. Local connections negotiate none.

## Expiry and freshness

The bounds below are the ones the protocol fixes in this repository. The documents named beside them
hold the rest of each rule; a lifetime that a service or a configuration sets is described where that
service or configuration is.

| What | Bound | Described in |
| --- | --- | --- |
| A pairing invitation | Five minutes, single use | [Pairing](../pairing/README.md) |
| An owner-confirmation challenge | Two minutes, single use | [Pairing](../pairing/README.md) |
| An action window | At most five minutes, issued for one connection and the host's boot, and replaced on the live connection at half its validity | [Action windows](../transport/README.md#action-windows) |
| A mutation's lifetime | Requested as a time to live, two minutes by default and five minutes at most. The accepted deadline is the earliest of the window's expiry, the receipt time plus the requested lifetime and any authority deadline | [Action windows](../transport/README.md#action-windows) |
| The remote dispatch lease | At most five seconds, taken when the daemon forwards an action, and held by the worker as well as the daemon | [The remote dispatch lease](../transport/README.md#the-remote-dispatch-lease) |
| A membership lease, and a policy-authority head | At most fifteen minutes; a lease is refreshed every five | [Account authority objects](#account-authority-objects) |
| A push registration challenge and a mailbox claim challenge | Five minutes each | [Push objects](#push-objects), [The mailbox](method-reference.md#the-mailbox) |
| A push delivery credential | Thirty days, and a host may renew it from seven days before it ends | [Push objects](#push-objects) |
| A signed service request | Admitted within five minutes of the service's clock in either direction; its nonce is remembered for twice that long | [The service credential](#the-service-credential) |
| A relay lease | The lease states its own end; a revocation and a consumption receipt are signed objects | [Relay leases and receipts](#relay-leases-and-receipts) |
| A grant | The expiry it states, the end of the grantee's pairing, whichever comes first; a delegated grant never outlives its parent | [Grants, sharing and revocation](../host/README.md#grants-sharing-and-revocation) |
| A mutation's receipt and a de-duplication record | Thirty days | [Journals and the receipt contract](../host/README.md#journals-and-the-receipt-contract) |
| Retained session output | Seven days, 128 MiB for a session and 1 GiB for the host, whichever applies first | [Retained output, and what eviction leaves behind](../host/README.md#retained-output-and-what-eviction-leaves-behind) |
| A session invitation | One hour by default; the issuer may choose less or extend it to at most 30 days, and a longer lifetime is refused and not shortened | [Grants, sharing and revocation](../host/README.md#grants-sharing-and-revocation) |
| The longest grant lifetime an organisation policy may permit | At most 90 days; zero, or more than 90 days, is refused | `MAX_POLICY_GRANT_LIFETIME_MS` in `crates/kr-protocol/src/account.rs` |
| A question | 24 hours by default and at most, or the life of the application that asked, whichever ends first | [Questions](../contact/README.md#questions) |
| A mailbox item | 24 hours at most; a replay identifier is kept for 24 hours past its envelope's expiry | `MAX_MAILBOX_ITEM_LIFETIME_MS` and `REPLAY_ID_RETENTION_MS` in `crates/kr-protocol/src/mailbox.rs`; [The mailbox](method-reference.md#the-mailbox) |
| A voice confirmation challenge | Two minutes, the same as an owner confirmation | `VOICE_CONFIRMATION_LIFETIME_MS` in `crates/kr-protocol/src/voice.rs`; [Pairing and the host's owner](../host/README.md#pairing-and-the-hosts-owner) |
| A staged transfer | An unfinished upload and a download snapshot 24 hours; a completed attachment that is not submitted seven days | [Limits](../transfer/README.md#limits) |
| An automation's causal root and a workflow run | A causal root lives one hour and a workflow run has a 30-minute deadline unless a definition shortens them | [Causal roots and budgets](../automation/README.md#causal-roots-and-budgets), [Limits, deadlines and admission](../automation/README.md#limits-deadlines-and-admission) |

Every deadline is measured on a clock that counts suspended time, and a host that cannot prove its
wall clock decides nothing by it ([The host time contract](../host/README.md#the-host-time-contract)).

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

A receipt carries `error_withheld`, left out of the encoding when it is false. A reader that is not
the local owner is shown a receipt's error with its code, retry category and diagnostic identifier
and with the message replaced, because a message can quote an upstream, a session or a person and
has no date to hold to a history bound; the flag is true then.

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

An error also carries `link_fenced`, which is left out of the encoding when it is false. A worker
sets it on the refusal of a link that no longer holds the worker's authority. It travels from the
worker to the control daemon on the same machine, which ends the link and does not pass the member
on to a device.

Typed resource states such as `permission_required`, pending revocation and voice
`creation_unknown` are not error codes. The host reports each in its own result schema:
`permission_required` as a capability state, a pending revocation as a revocation barrier with its
per-worker status, and `creation_unknown` as a voice start outcome.

`restart_required` is not a host result and has no schema of its own. It is the setup assistant's
state, which the companion works out from two readings of one capability: the host still reports
`permission_required` after the person was offered the permission. A running host cannot see a
grant given after it started, so it cannot report that a restart would change the answer.

## The method and authority table

`crates/kr-protocol/src/method.rs` holds one exhaustive authority entry per method. The same table
is generated as data to `packages/protocol/schema/method-authority.json` for consumers that are not
written in Rust, and as [the method index](methods.md) for people: every method in the registry's
groups, with its effect, its ingress, its summary and the section that describes it.

Anything not listed is denied. `decide(name, version, ingress)` returns a denial for an unknown
name, a schema failure for a known method at an unsupported version, and a denial for an ingress
class the entry does not list.

Each entry states:

| Field | What it says |
| --- | --- |
| `effect` | `read` or `write` |
| `ingress` | The only ingress classes that may reach the method |
| `required_rights` | Everything the actor must present, intersected: grant rights and the proofs presented beside them, such as a service credential or an account token |
| `resource_selectors` | The resources the request names and the host resolves first, such as a session, a transfer or one stored archive object |
| `history_filter` | How the shared history filter applies to the result |
| `capability` | Which capability evidence is required, and which revision it is bound to |
| `freshness` | Which freshness context the request carries |
| `confirmation` | Whether a fresh owner confirmation is required |
| `idempotency` | How a repeated request is resolved: an idempotent read, deduplication by action, a protocol key, a comparison against a revision, or an ordered stream |

Reading the fields:

- An empty `required_rights` list is not "no check". It means scoped read authority and nothing
  more: a valid, unexpired, unrevoked grant covering the named environment and the named resource.
  Only nine reads use it: `host.info`, `environment.list`, `environment.capabilities`,
  `host.doctor`, `environment.inventory`, `plugin.list`, `plugin.capabilities`, `project.read` and
  `workspace.read`. It is not a universal prerequisite:
  pairing presents a transcript proof, a service method presents a service credential, and a
  private-IPC method presents its caller token, none of which involve a grant.
- The entries of `sync.compare_exchange` and `backup.manifest` list only the service credential. The
  requests of those methods that touch an account's recovery bundle also carry the account token, for
  `backup.write` when the device writes it and `backup.restore` when it only reads it, and a backup
  generation's publication carries the token for `backup.write`, as [the service
  credential](#the-service-credential) describes; the entry does not record that, and neither entry
  names the collection or archive it addresses as its resource (it says `mailbox`).
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
- The only thing that correlates a response with a request is its `request_id`. On a local client's
  connection, the worker answers an `input.write` as soon as it has taken the batch, so the answer
  can come before the answer to an earlier read on the same connection, or to an earlier
  `terminal.resize`, `terminal.geometry.transfer`, `attachment.configure` or `attachment.viewport`.
  However, a write still follows every earlier write, and it follows every other earlier mutation,
  an attach, a detach, an input acquire, release or interrupt, or a close among them. The exceptions
  are a `shell.launch` that waits for the reader, the five agent mutations and a
  `plugin.action.invoke` that goes to an upstream, whose answers a task of their own writes later,
  and a `plugin.action.invoke` that a component prepares, which the worker runs after the frames
  sent while it was prepared. A read that is answered after a write can show what the write did. A
  client does not assume that answers come back in the order it sent the requests.
- On a paired device's connection, the host also answers an `input.write` as soon as the worker has
  taken the batch, once the connection has opened its link to a session's worker. The answer can
  come before the answer to an earlier read on that connection, or to an earlier `terminal.resize`,
  `terminal.geometry.transfer`, `attachment.configure` or `attachment.viewport`, but only when that
  earlier request, like the write, is decided over the session and under the grant the connection
  acts under, or over no session, which the device's pairing grant decides. A read of another
  session, `session.open`, a voice read, and a write that names another session keep their place. So
  does a read of an action that names no session, unless the route recorded for the action names the
  session the connection acts for. A write follows every other earlier mutation on the connection
  without exception. The host forwards `plugin.action.invoke`, `shell.launch` and the agent
  mutations and waits for them, so a write behind one of them waits until the host has its answer or
  has stopped waiting for it. The answer to an `events.subscribe` can follow the first batch of
  output its subscription relays.

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

### What version 1 offers an agent

An agent running in a session reaches the host through its contact tools, which call four
private-IPC methods over a connection bound to its own verified application: `question.create`,
`question.read_own`, `question.cancel_own` and `alert.create`. Each names one question or one
session, and none is a listing or a search. No method lets an agent list sessions, search a
session's history, read another session's output, send input to another session, route a message
between sessions or schedule other agents. The method table is the whole of what a host answers, so
this is a property of the table. The methods a person uses to find sessions and page history,
`session.list`, `history.page` and `events.subscribe`, need a person's rights, and no method at all
accepts the plugin ingress.

This is a statement about what the product offers an agent as an agent. Code an agent runs under the
person's own operating-system account has that account's authority, which no table narrows.
`crates/kr-protocol/tests/future_access.rs` reads the table and holds both halves of the statement,
and `crates/kr-cli/tests/contact.rs` drives a helper in a host with two sessions and shows it
reaching only its own.

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
| `root.command.accepted` | `RootCommandAcceptedParams`: the fence, the prompt generation and the origin the reader can prove | `RootCommandAcceptedResult`: the origin the worker recorded, the `detach_token` this line's own execution presents to `kr detach` (a bearer capability, null where the host could not attribute the line) and the fence state after acceptance |
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

An organisation states membership and policy with signed objects, so a host can check them while the
service is unreachable. `crates/kr-protocol/src/account.rs` holds four of them, and
`packages/protocol` builds the same bytes in TypeScript.

| Domain | Payload | What it says |
| --- | --- | --- |
| `kr-membership-lease/2` | `MembershipLeasePayload` | One account held one role in one organisation until a stated time, for one device |
| `kr-policy-authority/1` | `PolicyAuthorityLinkPayload` | One revision of an organisation's policy-signing key, signed by the revision it follows |
| `kr-policy-authority-head/1` | `PolicyAuthorityHeadPayload` | Which revision signs leases now, signed by that revision |
| `kr-organisation-policy/1` | `OrganisationPolicyPayload` | One revision of an organisation's host policy: the adapters its members may run and the other settings it states |

Each signature covers `CBOR([domain, payload])`, where the payload is the record without its
signature, encoded as a canonical map. The domain is what stops one statement being read as
another.

A lease lasts at most fifteen minutes and is refreshed every five. It names `maximum_grants` from
the action-right vocabulary the rest of the protocol uses, so a host intersects a lease with the
grants it already understands rather than with a second set of names. The role is a label for that
ceiling: `TeamRole::maximum_grants` is the most a role may ever carry, a lease may name less, and
`MembershipLeasePayload::grants_within_role` is the check that it names no more. Authority still
comes from the grants, never from the label.

A lease names the device it is for by that device's authorisation public key, `device_key`: the
key the device's `kr-connect/1` proof is made with on every connection. A host takes a lease only
from the connection that proves that key, so a host that receives a member's lease cannot pass it
to a device it controls. The member's client asks the service for a lease naming its own key.
`fixtures/crypto/organisation.json` publishes a signed chain, its head and two device-bound leases,
with the negative cases a verifier must reject.

The first revision of a chain signs itself and names no predecessor, which is what a host pins.
Every later revision names the revision whose key signed it, so a host walks forward from the
revision it pinned without being told which key to trust. Any prefix of a chain verifies on its
own, so the head statement is what says the chain is complete.

`PolicyAuthority::check_structure` makes every check that needs neither a signature nor the clock:
ordering, succession, activation times, that the head names the last revision, and that it was not
issued before that revision took over. Accepting a chain is that check, then matching the pinned
link against the pin itself (organisation, revision and public key), rather than verifying its
signature, which belongs to its predecessor at every revision after the first, then the signature
of each later link under the key of the revision it names as its predecessor, then the head under
the key of the revision the head names, then that the head is valid at the current time, then
refusing a head below the highest revision this host has already accepted, and only then
recording the new highest revision.

A chain authenticates forward. `PolicyAuthority::authenticated_from` returns the links a host may
verify anything against, given the revision it pinned: the pin and everything after it. A lease
naming a revision from before the pin is refused rather than checked against a key nothing the host
holds authenticates.

A host applies a policy only when it is signed by the key the chain ends with, the revision the host
has accepted: a policy under a later revision needs the chain beside it, and one under an earlier
revision is refused, so a key the organisation retired signs nothing a host applies. The policy's
own `policy_revision` is a floor, and a host refuses a policy at or below the one it holds, except
the same policy again. The host reads no clock for a policy, which has no lifetime. What a host
does with one is in [Applying a policy](../host/README.md#applying-a-policy).

What that proves has a limit. A head expires, so a captured head stops being usable, and a host that
has accepted a later revision refuses one naming an earlier revision. Neither fact proves that the
private key of a retired revision is gone: a host that never saw the rotation cannot tell a fresh
revision-1 head signed by a retained revision-1 key from a legitimate one. Rotation therefore
destroys the private half of the revision it retires, and a host that must detect a compromised
predecessor needs evidence from outside this chain.

## The service credential

All the methods of the `Services` group of section 23 share the same authentication method and the
same credential (defined in `crates/kr-protocol/src/service.rs`). What a caller proves is that it
holds the private half of one key, and that the request in front of the service is the request that
key signed. For the methods related to the managed storage, the requests also contain the token of
the account they concern. For the methods `backup.manifest` and `sync.compare_exchange`, some of the
requests (a backup generation's publication, and the requests about the recovery bundle) contain
the token of the account they concern, but not all of them.

A signature covers `CBOR([domain, ServiceRequestPayload])`, and the payload carries five fields:

| Field | What omitting it would allow |
| --- | --- |
| `gateway_origin` | A signature made for one deployment replayed against another |
| `method` | A signature for a read presented as the authorisation for a write |
| `nonce` | The same signed request taking effect twice |
| `signed_at_ms` | A captured request held and presented much later |
| `body_digest` | The body swapped for another under a signature that still verifies |

Two kinds of caller reach these methods, so there are two domains and no other difference. A native
installation signs under `kr-service-request/1` with its device authorisation key. A host signs under
`kr-service-request/1/host` with its host signing key, which is how `push.sender.renew`,
`push.sender.revoke` and a host's `authority.sync` are proven, and how the host proves its own
mailbox, backup storage and `backup.manifest` requests. The separation is in the bytes rather
than in a label beside them, so relabelling a signature cannot turn one into the other.

The five mailbox, authority-feed, settings-sync, backup-manifest and storage groups send a JSON
document as the request body, and a signature covers bytes and not a document. So the signed
`body_digest` is the SHA-256 of `canonical_body`, the document encoded in KR-CBOR-1: member names
as text in canonical order, every string as CBOR text (decimal counters, identifiers and base64url
data stay text, and are not turned into integers or byte strings), and a JSON number only where it
is an exact unsigned integer no greater than 2^53-1. The rule is on the value and not the spelling:
`1000` and `1e3` are one number and give one digest. A fraction, a negative number and an integer
above the bound are refused before anything is signed. The function receives a parsed document, so
it cannot see a member that an earlier parse of the JSON text repeated. The service recomputes the
digest from the document it holds, so neither side depends on how the other wrote its JSON. `canonical_body_digest` in `crates/kr-protocol/src/service.rs` is that function and
`fixtures/service/services.json` holds its cases, with the bodies it refuses. This differs from
the typed objects of [the two representations](#the-two-representations), which are rebuilt from
their typed fields.

The request travels as a JSON object with two members, `body`, the document the digest covers, and
`signature`, which carries the five signed fields, the signer's kind, its public key and the
signature itself. The one
exception is a storage part. Its HTTP body is the ciphertext, and the same signed JSON travels in
the `kr-service-request` header as unpadded base64url, so the signature covers the part's declared
length and SHA-256 and the service bounds what it reads before it reads any of it. A request for
something an account owns also carries the account token as an `authorization: Bearer <token>`
header, which the signature does not cover.

A service admits a signature whose `signed_at_ms` is inside five minutes of its own clock, in either
direction, and remembers the nonce for twice that long: a signature dated the full window ahead is
still admissible for another whole window after it was made. `ServiceRequestPayload::is_fresh_at` is
the first check and `nonce_retained_until_ms` says how long the second one has to remember.

`InstallationId` is the first sixteen bytes of the SHA-256 of the device authorisation public key,
formatted with hyphens. It is derived rather than asserted: a caller that presents a key and a
signature has already proved which installation it is, so no request body is taken to say who the
caller is. A storage body does name its installation, but the service compares that name with the
identifier the key derives and refuses a mismatch. An identifier is 128 bits, so it names a key
rather than standing in for one. A service that keeps an installation record, as the push gateway
does for registration, records the whole key it first saw, looks it up by the identifier, and
compares against the key. Replacing a recorded key is then a deliberate step, taken by a registration
whose challenge the new key signs, and not a side effect of asking. The storage methods keep no such
record. They verify the signature under the key the request presents, then apply the name check
above.

Each of the eight `storage.*` methods lists `account_token` beside `service_credential` in its
`required_rights`. This token must have the scope `backup.write`, and it names the account whose
storage the request reads or changes. This token is not bound to any installation; instead, the
installation specified in the body of the storage method is checked against the signing key as
described above. That ties the two proofs to one caller.

For the storage methods, a key that names the request nonce, as `installation id + request nonce`
does, means a request carrying that nonce. A key without one, as `upload id` does, means a fresh
signature for the same identity. That is not permission to send a request again; a client decides
that for each request. `storage.retention.set` is compared against the retention revision instead: a
request decided against a revision the record has left changes nothing, and the answer carries the
retention as it stands.

An origin is an origin, so `GatewayOrigin` uses the grammar `RendezvousOrigin` already fixes: a
scheme, a canonically spelled host, an optional non-default port, and nothing else. The one
difference is that plain HTTP is admitted for a loopback host, which is what a development
deployment serves on. `fixtures/service/requests.json` publishes every origin both languages accept
and every spelling both refuse, and each language's tests run the whole list.

### The relay requests

Four requests of the relay control plane are signed under the same credential, but they are not
entries of the method registry. The credential therefore names the method as text, and the signed
`body_digest` is not the `canonical_body` digest above. The body is a typed object, and its digest
is the SHA-256 of `CBOR([domain, body])` in KR-CBOR-1, with the body's scalars in their wire form (a
counter as an integer, an identifier as sixteen bytes), so JSON is still never what a signature
covers.

| Method named in the credential | Path | Body digest domain |
| --- | --- | --- |
| `relay.lease.issue` | `/api/relay/lease` | `kr-relay-lease-request/1` |
| `relay.lease.revoke` | `/api/relay/lease/revoke` | `kr-relay-lease-revoke/1` |
| `relay.payer.sign_in` | `/api/relay/payer-authorisation/sign-in` | `kr-relay-payer-sign-in/1` |
| `relay.admission.issue` | `/api/relay/admission` | `kr-relay-admission-request/1` |

`fixtures/relay/requests.json` holds the payer sign-in vector, and the lease and admission vectors
are in `crates/kr-client/tests/relay_service.rs`.

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
rule for what a service-request signature covers. `push.installation.register` and
`push.sender.issue` are the installation's own decisions, signed on the device;
`push.sender.renew` and `push.sender.revoke` are the host's, signed with the host key the
installation named. `PushRequest::digest` is the `body_digest` the signature carries and
`PushRequest::method` is the method it must name, which is what stops a body built for one method
being presented under another. Delivery is not one of them: it carries the bearer credential the
host was issued, and its digest is how the gateway recognises a request it has already handled.

**Authorisation.** `PushSenderBinding` holds everything one authorisation fixes for its lifetime:
the destination installation, the host's endpoint and signing keys, the gateway and the rate policy.
It is digested under `kr-push-sender/1`, so `PushSenderRecord::renewal_preserves_binding` is a
comparison of one digest rather than a list of fields somebody has to remember to extend.

The authorisation and the credential have different lifetimes on purpose. The authorisation is the
installation's decision and lasts until it is revoked. The credential is a bearer a host keeps on
disk, so it expires in thirty days and is renewed by the host signing `kr-push-sender-renewal/1`
over a nonce the gateway issued. Renewal opens seven days before expiry and does not close at
expiry: a host that was offline for a month renews on reconnect, because its credential lapsed and
the authorisation behind it did not. A revoked record is never renewed. The gateway stores the
SHA-256 of the bearer under `kr-push-credential/1`, never the bearer, so a copy of the database is
not a set of working credentials.

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

`fixtures/cbor/`, `fixtures/protocol/`, `fixtures/relay/`, `fixtures/accounts/`, `fixtures/service/`,
`fixtures/push/` and `fixtures/metrics/` hold the vectors both languages run against. The Rust tests
read them from `crates/*/tests/`, and the vitest suites read the same files, with the exceptions
below. The signature vectors are in `fixtures/crypto/`, and the pairing vectors are in
`fixtures/pairing/` ([the pairing reference](../pairing/README.md)).

Some files are not shared vectors. `fixtures/accounts/rotated-policy.json` is a record
captured from the managed service's own signing code across a rotation of an organisation's
policy-signing key, which only the daemon's test reads. Five files in `fixtures/service/` are
answers recorded from the managed service, which only the Rust tests of the service clients in
`crates/kr-client/tests/` read: `authority-answers.json`, `bundle-answers.json`,
`bundle-write-answers.json`, `settings-answers.json` and `storage-answers.json`; each records the
web commit it was taken at. The generator does not write or check these six files, because the
service produced them and not this repository. Three more files have only a Rust reader:
`fixtures/metrics/host.json`, `fixtures/relay/requests.json` and
`fixtures/cbor/before-deserialisation.json`. The generator writes and checks
`fixtures/service/requests.json`, `fixtures/service/services.json`, `fixtures/push/push.json` and
`fixtures/metrics/host.json`.

Values use a small tagged grammar, so a fixture can express a byte string, a 64-bit integer and a
deliberately unsorted map, none of which plain JSON can carry:

| Form | Means |
| --- | --- |
| `{"int": "-18446744073709551616"}` | An integer, as a decimal string |
| `{"bytes": "00ff"}` | A byte string, as hex |
| `{"text": "café"}` | A text string |
| `{"bool": true}` | A boolean |
| `{"null": null}` | Null |
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
| `cbor/before-deserialisation.json` | Protocol messages refused before typed decoding, with the rule and the error code, and messages admitted |
| `cbor/digests.json` | A signed object with its digest, and a domain-separated signing input |
| `protocol/frames.json` | Encoded `hello`, mutation, receipt, error, notification and stream header, with their frames |
| `protocol/transcripts.json` | The `kr-connect/1` transcript and the mutation digest |
| `relay/leases.json` | A two-way lease on a two-relay route, a sponsored single-relay lease inside its grace, and a revocation |
| `relay/receipts.json` | Two consumption receipts of one reservation, showing the cumulative count |
| `relay/instances.json` | A relay instance registration and an announced key rotation |
| `relay/envelopes.json` | The install, revoke, report and registration messages that carry them |
| `relay/requests.json` | The body a host signs to ask the relay service to make its signed-in account the payer, with the bytes its digest covers |
| `crypto/relay.json` | Ed25519 signatures over those objects, by the relay instance key and the service admission key |
| `accounts/leases.json` | The signing input of the membership lease and the two policy-authority objects (the policy itself is in `service/services.json`), with the role ceilings and lifetimes |
| `service/services.json` | Canonical request bodies with the bodies refused, the mailbox claim and limits, key identifiers, the settings-sync request cases and limits, and the exact signed bytes of a mailbox item, a revocation request, an authority revision record, a sync object record, a conflict copy, a backup writer record, a backup generation publication and an organisation's policy |
| `service/requests.json` | Signed service requests by an installation and by a host, one payload under the two domains, and the accepted origins and freshness window |
| `push/push.json` | The six fixed alert sentences, the signing input and digests of the push objects, the rate policy and the request methods |
| `metrics/host.json` | The closed labels of the host's own metrics; the Rust metrics tests hold it |
| `service/*-answers.json` | Answers recorded from the managed service, as listed above |

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
            ──generate──>  fixtures/service/requests.json, fixtures/service/services.json,
            <──  check  ──      fixtures/push/push.json, fixtures/metrics/host.json
            ──generate──>  crates/kr-protocol/worker-surface.json
            <──  check  ──
            ──generate──>  docs/protocol/methods.md
            <──  check  ──
```

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Regenerate the schema, the method table, the service, push and metrics vectors, the worker
# surface and the method index, then check them
cargo run -p kr-protocol --bin kr-protocol-gen
cargo run -p kr-protocol --bin kr-protocol-gen -- --check

# TypeScript
pnpm install --frozen-lockfile
pnpm -C packages/protocol generate
pnpm -r test
```

The published schema is compiled from the Rust types (`schema_for::<T>()`), and
`kr-protocol-gen --check` compares the committed files with what the current Rust types produce and
names the first differing line. It also names every method in the registry that no document under
`docs/` other than the index mentions, every link in the method index whose document or heading is
no longer there, and every problem with the retained levels of the support window.
The generator's own tests make the same checks, so `cargo test --workspace` fails on them too.
`pnpm -C packages/protocol generate:check` does the same for the generated TypeScript, and the
vitest suite runs it, so `pnpm -r test` fails when the types are stale.

Changing a wire type means: edit the Rust type, run the generator, run the TypeScript generator,
and commit everything they write together. Adding a method also means deciding which section
describes it, in `described_in` in `crates/kr-protocol/src/bin/kr-protocol-gen/method_index.rs`; the
match there covers every method, so the generator does not build until that is decided.
