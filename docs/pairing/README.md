# Pairing reference

`crates/kr-pairing` is the two pairing flows of section 10: the short code over a rendezvous
service, and the self-contained direct QR. It owns the state machines, the budgets and the
transcripts. It owns no transport, no database and no user-verification ceremony: each of those is
a trait in `kr_pairing::platform` with an implementation in the tests, so the rules can be
exercised without a network, a disk, a real clock or a person.

## The short code

A code is ten characters from the Bitcoin Base58 alphabet, displayed `XXXX-XXX-XXX`. Four locate a
temporary rendezvous record and six are the PAKE password. Characters are drawn with rejection
sampling: a byte of 232 or more is discarded rather than reduced, because reducing it would make
the first 24 characters of the alphabet half again as likely as the rest and cost the code part of
the entropy the bound below assumes.

Six characters carry about 35.15 bits, so five guesses against the host succeed with probability at
most `5 / 58^6`, about 1.3e-10 — and only because the PAKE prevents an offline guess. The locator
adds no secret entropy, and the bound is per host, not an aggregate across clients.

Parsing removes ASCII spaces and hyphens, preserves case and requires exactly ten valid characters.
Case matters: folding it would throw away entropy. The six secret characters never enter a service
request, a URL, a log or an analytics event; `ShortCode`, `CodeSecret`, `GeneratedCode` and
`EnteredCode` all redact themselves in debug output and clear their buffers when dropped.

### The exchange

| Step | What happens |
| --- | --- |
| 1 | The owner calls `pair.invite`. The host makes a 128-bit invitation identity, a five-minute monotonic deadline, a code, and a separate random 256-bit record-control token, and reserves the locator. The service stores the locator, the identity, the expiry and a **hash** of the token. A collision makes the host generate another locator. |
| 2 | The candidate sends only the four locator characters to its configured origin and gets an invitation identity and an advertised expiry. Both are the service's word until the PAKE confirms them. |
| 3 | The candidate makes a 128-bit attempt identity and a 256-bit nonce; the host admits the attempt under its budget and makes its own nonce. Both devices build the context `C` themselves and reject an inconsistent one. |
| 4 | The host is role A and calls `start_a`; the candidate is role B and calls `start_b`. Both pass the same two identities, host first, and the six characters. Each sends its library message unchanged and calls `finish` exactly once. |
| 5 | `T = SHA256(CBOR([C, message_A, message_B]))`. HKDF-SHA256 with the shared key as input key material and `T` as salt derives five 32-byte keys under five literal information strings. |
| 6 | The candidate sends `HMAC-SHA256(client-confirm-key, T)`. The host verifies it in constant time and answers with `HMAC-SHA256(host-confirm-key, T)`. The candidate verifies that **before** it trusts any host metadata. |
| 7 | The two bundles are exchanged under the directional keys with fresh nonces, sequence numbers and deterministic-CBOR additional data. Each device signs its own bundle and `T`. |
| 8 | The candidate connects to the endpoint the authenticated bundle pinned. `pair.finish` carries the identities, `T`, both bundle hashes and a tag under the iroh-bind key whose input includes both endpoint identities. Each side checks the live peer against the authenticated bundle. |
| 9 | Only then does the issuing device show the owner the new device, the proposed permissions and the eight-hex verification value. `pair.confirm` names the exact transcript and client bundle hash. |

The confirmation tags are not decoration: receiving a key from `finish` does not establish that the
peer entered the same password. That is why `finish` succeeds for two different passwords and the
tags do not.

### Budgets

**The host** permits five failed client-confirmation tags per invitation, counted in one serial
path: `HostInvitation` is one type with `&mut self` methods, so the candidate being served is the
only candidate being served, and the count it reads is the count the next one will read. Only a tag
that verified and did not match consumes a guess; a malformed message, an unreachable service, a
local configuration error and an abandoned candidate consume rate and slot budgets instead, because
none of them produced a password confirmation result. The count is persisted before the failure is
reported, so a host that dies there comes back having spent the guess.

A successful `pair.finish` locks the invitation to that candidate and cancels the others. Denial,
expiry, cancellation and five failures each consume it; a new invitation needs another owner action.
A host restart cancels every unfinished invitation, because a candidate's attempt state lives only
in memory and nothing can resume it — consumed records and failure counts survive.

**The candidate** permits five attempts per entered code, and never retries a failed key
confirmation automatically. The counter is keyed by an HMAC of the configured origin and the
normalised full code under a distinct random local key from secure storage, never a transport or
control key, and never by the service-supplied identity or expiry. Its five-minute window starts at
local first entry on monotonic time and the boot identity; the count survives an application
restart, an operating-system reboot expires an unfinished entry, and an exhausted or expired entry
leaves a tombstone for 24 hours so another advertised expiry cannot reset it.

The two counters are separate by design. The host's bound is not an aggregate across clients:
reusing one code on several devices increases the total guessing opportunities, and each device
limiting itself is what keeps each endpoint's own online oracle bounded.

### What a failure may say

The user interface distinguishes a known local configuration error, an unreachable service, an
expired invitation, a denied approval and exhausted attempts. An ambiguous authentication failure
stays ambiguous: `PairingError::AuthenticationFailed` carries no reason, because a host cannot
establish whether the code or the origin was wrong, and saying more would be guessing on the user's
behalf. There is no cheap locator-existence answer either.

## Direct QR

An owner may issue a five-minute, single-use invitation carrying the host endpoint key, the
selected discovery and relay configuration, a random 256-bit secret and the proposed grant. It
grants nothing until the candidate proves possession of that secret over an iroh connection
authenticated against the pinned endpoint.

A redemption starts with a fresh host challenge and the host's complete purpose-key bundle, so a
proof cannot be prepared before the host agrees to serve one. The transcript `D` is
`CBOR(["kr-pair/direct/1", invitation_id, host_endpoint, client_endpoint, host_keys, client_keys,
proposed_grant_digest, host_nonce, client_nonce, expires_at])`. The candidate supplies
`HMAC-SHA256(invitation_secret, D)` **and** an Ed25519 signature over `D`: the tag proves possession
and the signature binds the key-purpose declarations. The host requires the submitted endpoint to
equal the live authenticated peer before it locks anything.

A challenge is single use and expires with the invitation; issuing another retires the first. The
verification value is the first eight hexadecimal characters of
`SHA256(CBOR(["kr-pair/direct-verify/1", D]))`, grouped identically on both devices. `pair.confirm`
is accepted only from the issuing owner and binds that exact transcript and client-key digest.
`pair.status` reports only to the candidate's authenticated endpoint or the issuing owner and never
reveals secret material; `pair.cancel` consumes the invitation without a grant. An idempotent retry
retrieves the committed result and cannot change the submitted keys or the proposed rights.

The two entry modes use distinct proof domains, so a proof from one route is not a proof in the
other, and one atomic candidate and consumption record, so neither route replaces a candidate
already awaiting owner approval.

## Grants

A session invitation defaults to `session.view` for one hour. The issuer may choose a shorter
duration or extend it to at most 30 days; persistent co-owner access needs explicit owner pairing.
A personal owner grant is the other kind: valid until revoked, so independent operation does not
depend on a cloud lease.

Delegation narrows. `issue_grant` refuses a child that asks for more rights, more resources, more
history or a longer life than its parent, that names a parent it was not given, or that omits one it
was. The candidate cannot enlarge the grant through its bundle either: the host commits the grant
the invitation proposed.

A remote owner publishes a signed revocation **request**, which carries no host revision: only the
target host issues ordered authority revisions, and a device that could name one would be assigning
itself a place in the host's order. A host rejects a revision record that does not follow the one it
last accepted, whatever its signature says.

## Owner confirmation

Six actions need a fresh confirmation bound to the exact action digest, destination keys and rights,
host, nonce and a short expiry: issuing a persistent invitation, confirming a new device, enlarging
a persistent grant, trusting a new repository root, granting executable or native-bridge
capabilities, and changing host-management authority. Already-authorised restriction, revocation and
emergency session stop need none, and `SensitiveAction` lists only the six, so a caller cannot ask
for a confirmation of something that never needed one.

The ceremony is platform code. What this crate checks is that the proof answers *that* challenge
byte for byte, that the channel can carry a confirmation at all, that the challenge has not expired,
that the signer is the enrolled one, and that the signature covers the request **and the channel**
together — a channel beside an unsigned signature would be the signer's unauthenticated claim about
how the confirmation was obtained.

A session, plugin or contact-tool channel is refused outright. The interactive controlling terminal
is the initial local bootstrap exception and nothing more: afterwards a host with no
user-presence-capable signer and no separately paired owner refuses rather than downgrading. The
challenge is consumed exactly once, which is part of the host's acceptance record.

## The PAKE profile

This build uses the maintained RustCrypto `spake2` crate's own `Spake2<Ed25519Group>` profile,
version 0.4.0, with explicit A and B roles.

- It is **not** the RFC 9382 P-256 ciphersuite.
- The crate's documentation references its earlier draft profile, discloses the absence of an
  independent security audit, and cautions that its implementation is probably not constant-time.
- **External review of this profile, its side-channel behaviour and its integration here is a
  release gate.** Its status stays open until that evidence and the remediation decisions exist. A
  rejected implementation needs a separately reviewed profile revision; a different RFC name or a
  longer ad hoc shared secret is not an automatic security-equivalent substitution.
- No PAKE is implemented here. Malformed messages, a wrong role and invalid group elements are all
  rejected through the library's own error path.

The review artefact must cover the exact source and dependency hashes and build configurations:
role and transcript binding, element validation, the confirmation and HKDF domains, RNG failure,
side-channel behaviour, zeroisation, and positive and negative cross-language vectors.

## Profile decisions

Section 10 fixes the context, the identities, the transcript, the five information strings, the
verification values and the `pair.finish` inputs. What it does not fix is decided once, in
`crates/kr-protocol/src/pairing.rs`, and frozen by the vectors: the bundle-signature, finish,
owner-confirmation, key-identifier, revocation and authority domain strings; the element order
inside the additional data, the finish tag and `D`; the positional key array inside `D`; and the
canonical `XXXX-XXX-XXX` spelling a QR payload carries. That module's own table lists each one with
the reason. The confirmation lifetime, two minutes, is the other one: section 10 says "short
expiry" without a number.

## Vectors

`fixtures/pairing/` holds three documents, regenerated with
`cargo run -p kr-pairing --bin kr-pairing-vectors` and checked in continuous integration with
`--check`:

| File | Contents |
| --- | --- |
| `transcript.json` | The context and its hash, both role identities, `T` for two fixed library messages, the five HKDF keys, both confirmation tags, four bundle additional-data cases, the `pair.finish` message and tag, and the verification value |
| `direct.json` | The transcript `D`, its digest, the secret proof over it and the direct verification value |
| `codes.json` | The alphabet, the accepted and rejected parsing cases, and both QR payload encodings |

SPAKE2 draws fresh randomness per attempt, so the two library messages and the shared key are fixed
literals rather than the output of an exchange; everything else is derived from them exactly as a
real attempt derives it. `packages/protocol/test/pairing.test.ts` recomputes all of it with the Node
runtime's own SHA-256, HMAC-SHA256 and HKDF-SHA256 and this repository's own TypeScript codec, so a
value that drifts in one language fails in both.

## Release manifest

Pin `spake2` 0.4.0 with its resolved dependency graph and its interoperability vectors, alongside
the cryptography pins in [docs/crypto/README.md](../crypto/README.md). The profile is the crate's
own, so a different version could be a different profile.
