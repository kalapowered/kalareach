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
| 6 | The candidate sends `HMAC-SHA256(client-confirm-key, T)`. The host verifies it in constant time. A tag that matches **locks the invitation to that candidate**, persisted before the host answers with `HMAC-SHA256(host-confirm-key, T)`; the competing candidates are cancelled there. The candidate verifies the host's tag **before** it trusts any host metadata. |
| 7 | The two bundles are exchanged under the directional keys with fresh nonces, sequence numbers and deterministic-CBOR additional data. Each device signs its own bundle and `T`. |
| 8 | The candidate connects to the endpoint the authenticated bundle pinned. `pair.finish` carries the identities, `T`, both bundle hashes and a tag under the iroh-bind key whose input includes both endpoint identities. Each side checks the live peer against the authenticated bundle. |
| 9 | Only then does the issuing device show the owner the new device, the proposed permissions and the eight-hex verification value. `pair.confirm` needs a fresh owner confirmation naming the exact transcript and client bundle hash, and commits the device record, the grant and the consumed invitation in one store transaction. |

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

The lock is at the PAKE, not at `pair.finish`: a matching confirmation tag locks the invitation to
that candidate and cancels the others before the host answers. Leaving it open until `finish` would
let a second candidate keep guessing against an invitation someone had already proved. Denial,
expiry, cancellation and five failures each consume it; a new invitation needs another owner action.
A host restart cancels every unfinished invitation, a locked one included, because a candidate's
attempt state lives only in memory and nothing can resume it — consumed records and failure counts
survive.

Each candidate also has ten seconds to finish its handshake, and holding the invitation does not
suspend that. Every transition applies the deadline, asking for the status included, so an
invitation does not report a candidate that stopped as though it were still arriving. A slot that runs out frees itself and charges no guess, `abort` frees one on request,
and a candidate that proved the code and then stopped consumes the invitation instead of holding it
for the remaining five minutes: the owner issues another rather than waiting.

Every durable decision is written before it is acted on, and a write that fails **fences** the
invitation: it reports no status, accepts no candidate, consumes nothing and commits nothing until
a restart cancels it. Handing a spent guess back is the one outcome that must not happen, so a host
that cannot record one stops instead of guessing which way the write went.

The store is the authority on the record, and every write is conditional on the record the
decision was made from. Both entry modes reload before they decide and write back only if nothing
has moved since, so an invitation that offers a short code and a direct QR has one candidate and
one consumption whichever route reaches it first, and the slower of two writers is refused rather
than allowed to undo the faster one's lock, spent guess or consumption.

A restart loses the invitation object but not a completed pairing. The device record, the grant
and the owner's proof are in the store under the invitation identity, so a host that comes back
answers the retry and tells that candidate, on its own endpoint, that it is paired. The endpoint is
what identifies a candidate throughout; the attempt identity is checked when the asker has one and
is never required, because a direct candidate whose redemption response was lost never learnt it:
that identity is the host's, while a short-code candidate makes its own. A host answers nothing
short of a commitment that way: the endpoint a candidate authenticated with lives in the object the
restart lost, so a host with no way to tell one authenticated asker from another says nothing
rather than telling a stranger that somebody's pairing was denied.

**The candidate** permits five attempts per entered code, and never retries a failed key
confirmation automatically. The counter is keyed by an HMAC of the configured origin and the
normalised full code under a distinct random local key from secure storage, never a transport or
control key, and never by the service-supplied identity or expiry. Its five-minute window starts at
local first entry on monotonic time and the boot identity; the count survives an application
restart, and an operating-system reboot expires an unfinished entry. Expiring is not forgetting: a
reboot and a window that ran out both leave the same 24-hour tombstone as exhaustion does, so a
device cannot buy five more guesses by restarting and another advertised expiry cannot reset the
counter. The tombstone's retention is on the wall clock, because a monotonic deadline from the
previous boot means nothing after one.

Retention is kept on both clocks, and a record is forgotten only when **both** say it may be.
Within the boot that wrote it the monotonic deadline holds it however the wall clock moves; a wall
clock that runs backwards holds it longer still. A record from an earlier boot is *anchored* the
first time it is seen: it becomes a tombstone and gets a full fresh 24 hours on this boot's
monotonic clock. Reading the remaining time off the wall clock instead would hand an attacker the
answer, because jumping the clock forward before the first sweep after a reboot would make that
remainder zero. Repeated reboots therefore keep a tombstone alive longer than the required day,
which is the safe direction: a spent code stays spent, and the owner issues a new one.

The whole rule is one pure function applied inside the store's own lock, so the read, the decision
and the write are one transition: two entries of the same code cannot both see four attempts and
both proceed. The tag is computed over a buffer that clears itself, so the code does not reach an
encoder's internal copies.

The two counters are separate by design. The host's bound is not an aggregate across clients:
reusing one code on several devices increases the total guessing opportunities, and each device
limiting itself is what keeps each endpoint's own online oracle bounded.

### What a failure may say

The user interface distinguishes a known local configuration error, an unreachable service, an
expired invitation, a denied approval and exhausted attempts. An ambiguous authentication failure
stays ambiguous: `PairingError::AuthenticationFailed` carries no reason, because a host cannot
establish whether the code or the origin was wrong, and saying more would be guessing on the user's
behalf. There is no cheap locator-existence answer either. An invitation consumed *because* it ran
out reports as expired rather than refused, whichever step noticed, because that is the difference
a caller acts on.

## Direct QR

An owner may issue a five-minute, single-use invitation carrying the host endpoint key, the
selected discovery and relay configuration, a random 256-bit secret and the proposed grant. It
grants nothing until the candidate proves possession of that secret over an iroh connection
authenticated against the pinned endpoint.

A redemption starts with a fresh host challenge and the host's complete purpose-key bundle, so a
proof cannot be prepared before the host agrees to serve one. The challenge is bound to the
connection it was issued on: it is an offer to that candidate, and answering it from anywhere else
is another device using a challenge it was not given. It is spent only once a redemption is one it
could answer, so a stale nonce or a stranger's message cannot cancel the candidate's redemption.

A direct invitation is single use, so once a candidate has redeemed it the host issues no further
challenge and accepts no further redemption, by this route or the other. The one exception is the
candidate's own retry: the attempt identity is the host's, so a device whose response was lost has
no other way to learn it. An identical proof, over the same authenticated connection, with every
member of the transcript matching and both proofs verifying again, retrieves the candidate the
first redemption produced. Nothing is written and no challenge is spent. A cancelled or expired
invitation hands nothing back; a committed one does, because that device is paired and asking
about its own pairing. The transcript `D` is
`CBOR(["kr-pair/direct/1", invitation_id, host_endpoint, client_endpoint, host_keys, client_keys,
proposed_grant_digest, host_nonce, client_nonce, expires_at])`. The candidate supplies
`HMAC-SHA256(invitation_secret, D)` **and** an Ed25519 signature over `D`: the tag proves possession
and the signature binds the key-purpose declarations. The host requires the submitted endpoint to
equal the live authenticated peer before it locks anything.

The candidate checks the connection too: it refuses to send a proof unless the live authenticated
peer is the endpoint the QR pinned, and refuses to send one at all over a connection still in early
data. Without that check a relay or a discovery answer pointing elsewhere would be enough to collect
the tag over the invitation secret. Every mutation on both sides is refused in QUIC 0-RTT, because
early data is replayable by anything that captured it.

Both routes also require a declared endpoint to **be** the declared transport key, in the two
bundles and in the direct proof. Letting them differ would give a device two identities: one the
connection authenticates and one the device record is written from.

A challenge is single use and expires with the invitation; issuing another retires the first. The
verification value is the first eight hexadecimal characters of
`SHA256(CBOR(["kr-pair/direct-verify/1", D]))`, grouped identically on both devices. `pair.confirm`
is accepted only from the issuing owner and binds that exact transcript and client-key digest.
`pair.status` reports only to the candidate's authenticated endpoint or the issuing owner and never
reveals secret material, and the candidate's identity outlives its attempt, so a denied, cancelled
or expired invitation still tells the device that redeemed it what happened; `pair.cancel` consumes
the invitation without a grant. An idempotent retry
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

Neither check is optional. An invitation validates its proposal against the rules for its kind
before it is reserved or written, so a grant that could never be issued does not become an
invitation somebody can answer; and the grant itself is issued through `issue_grant` inside the
committing transaction, so what is written is a grant that passed both rules rather than one a
caller handed in.

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
user-presence-capable signer and no separately paired owner refuses rather than downgrading.

The challenge is consumed exactly once, which is part of the host's acceptance record. Verification
comes first and consumption second, so rubbish cannot burn an owner's outstanding challenge and a
proof replayed at the next sensitive step finds nothing outstanding. The deadline the host enforces
is monotonic and tied to the boot the challenge was issued in; the `expires_at_ms` inside the
request is the same interval on the wall clock, for the signer to read. Winding the wall clock back
therefore reopens nothing, and a reboot ends every outstanding challenge.

The challenge is compared member for member before the proof is verified: the action, the digest,
the host device and endpoint, the destination keys and the rights. Checking the digest alone would
accept a challenge answered for a different device or a different set of permissions than the one
about to be written. The host also keeps the challenge it issued, not just its identity, and
compares the presented one against it, so nothing can substitute different text under an identity
the host did issue.

Both flows depend on this rather than describing it. `HostInvitation::issue` and
`DirectInvitation::issue` require a confirmation naming `issue_invitation`, this host, the proposed
rights, the digest of the exact proposed grant and **no** destination device, because an invitation
is issued before anybody answers it. `confirm` on either requires one naming `confirm_device`, this
host, the candidate's own key bundle, the proposed rights, and a digest over exactly what the owner
was shown: the transcript and both bundle hashes for a short code, the transcript and key digests
for a redemption. The two entry modes compute that digest under different domains, so a
confirmation obtained for one cannot approve a candidate that arrived by the other.

The accepted proof is written with the pairing rather than checked and forgotten. Afterwards the
host can show which challenge, which channel and which signer authorised each device it holds.

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
- `spake2::Password` does not clear itself. The six characters therefore live in a heap buffer the
  library owns until it is dropped, which this crate cannot reach. Everything on this side of the
  boundary — `CodeSecret`, `GeneratedCode`, `EnteredCode`, the shared key and the five derived keys
  — zeroises. Closing this needs a change in the dependency, so it belongs to the same release gate
  as the profile itself.

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
the reason. Two intervals are decided here instead, because section 10 gives neither a number:

| Decision | Value | Why |
| --- | --- | --- |
| Owner-confirmation lifetime | 2 minutes | Section 10 says "short expiry". Long enough for a native ceremony on an unlocked device, short enough that a captured challenge is useless later. |
| Candidate handshake deadline | 10 seconds | Far more than a PAKE and two bundles need over any working link, and short enough that four candidates cannot hold the four slots shut for five minutes. |

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

## What the host does with a grant afterwards

This crate issues grants and validates the rules for the kind being issued. What happens to a grant
after it exists belongs to the control daemon, and `docs/host/README.md` states it: the intersection
it takes when it decides a request, the revocation cascade along the parent link, the per-worker
dispatch barrier a revocation completes through, the organisation lease that stops a grant while the
transport stays connected once the host holds one, and the bounded offline-validity policy an owner
may choose.

Two rules cross the boundary and are worth stating on both sides.

**Only the host issues revisions.** A revocation request carries none, and a host rejects a revision
record that does not follow the one it last accepted. The daemon keeps the highest revision it has
ever accepted as a floor, so a restored old policy cannot revive authority that has already been
withdrawn.

**Owner confirmation is for persistent enlargement.** Both halves of that phrase are checked: the
grant never expires, *and* no live grant the recipient already holds reaches everything it would.
Comparing the rights by name alone would miss the case that matters most, where a device with a
one-hour view of one session is handed a permanent view of every session. A bounded session
invitation is not a persistent enlargement however wide it is.

Transfer of control is separate, because it changes who holds authority rather than adding to what
somebody has. The digest an owner confirms for a transfer covers the whole plan: the session, both
devices, both grants and every action handed over. A confirmation obtained for one transfer
therefore authorises no other. The evidence that acceptance produces is bound to the host it was
accepted for, to the boot it was accepted in, and to the ceremony's monotonic deadline, and the
transfer checks all three.
