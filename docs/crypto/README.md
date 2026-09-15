# Cryptography reference

`crates/kr-crypto` is the only crate in the tree that performs cryptography. It implements no
primitive. Everything it does is a narrow, typed wrapper around a maintained implementation, plus
the rules that make those implementations hard to misuse.

| What | Implementation |
| --- | --- |
| `crypto_box_easy`, Ed25519, `crypto_secretstream_xchacha20poly1305`, XChaCha20-Poly1305, `crypto_kdf`, the CSPRNG | libsodium, through the pinned `libsodium-sys-stable` binding, which builds the C library from source |
| HKDF-SHA256, HMAC-SHA256, SHA-256 | the maintained RustCrypto `hkdf`, `hmac` and `sha2` crates |
| Canonical encoding and digests | `crates/kr-cbor` |
| Wire shapes | `crates/kr-protocol` |

## The unsafe boundary

`src/sodium.rs` is the only module that calls the C library and the only module that may use
`unsafe`. The crate denies unsafe code everywhere else, and every other crate in the workspace
forbids it outright.

It is also **private**. The raw primitives are not part of the crate's interface, so a caller
cannot reach an encryption function that accepts a nonce, a `secretstream` without the
final-record rule, or a private key as a bare array. Every public entry point is typed and carries
its own rule.

`initialise()` runs `sodium_init` once and then compares every length the wrapper relies on with
the linked library's own accessors: the key, nonce, MAC, header and record sizes, and the
`secretstream` message and final tag values. A build that links a different libsodium fails there,
before a buffer is sized from a constant the library does not agree with. Every public function
calls it first, so an application never has to remember to.

## Purpose-separated keys

Section 10 of the specification gives a device four independent keys and forbids converting or
reusing one private key across purposes:

| Purpose | Algorithm | What it does |
| --- | --- | --- |
| Transport | Ed25519 seed | The iroh endpoint identity that pairing pins |
| Authorisation | Ed25519 | Signs bundles, connection proofs, grants, revocations, confirmations and manifests |
| Stored envelope | X25519 | Opens mailbox envelopes and backup key wraps |
| Notification preview | X25519 | Opens notification previews, and nothing else |

The separation is structural, not a convention:

- The four keypairs are four Rust types with no conversion between them.
- Their private material lives in per-purpose seed types whose bytes are readable only inside the
  crate, so code outside it cannot take one purpose's seed and construct another purpose's key.
- Each purpose has its own item in the secret store, so a round trip through storage keeps them
  apart.
- `DevicePublicKeys::purposes_are_distinct()` fails if two purposes ever declare the same key.

The one deliberate export is `TransportIdentityKeyPair::export_endpoint_seed`, because iroh owns
the transport handshake and builds its endpoint from that seed.

A key identifier is `SHA256(CBOR(["kr-key-id/1", purpose, public_key]))`. The purpose is inside the
hash, so the same 32 bytes declared under two purposes produce two identifiers.

## Secrets in memory

`Secret<N>` and `SecretVec` zeroise on drop through `sodium_memzero`, which the compiler may not
elide, and redact themselves in debug output. `Secret<N>` is deliberately not `Copy`: a copy that
moves leaves a duplicate behind, and a duplicate cannot be zeroised. Reading a secret goes through
`expose()`, so every call site that touches key material is greppable.

The notification extension receives only the notification-preview private key and paired sender
public keys. It receives no stored-envelope, archive, recovery or control-signing private key.

## Nonces

Every sealing function generates its own 24-byte nonce from libsodium's random generator and
returns it alongside the ciphertext. No public function accepts a nonce for encryption, so no
caller can repeat one. That covers mailbox envelopes, notification previews, backup key wraps and
the pairing bundle exchange. Resuming an upload reuses stored ciphertext; it never reuses a nonce
for a new wrap, because a new wrap is a new call.

The cross-language vectors need reproducible output, so they call the libsodium wrapper directly
with a fixed nonce. The fixture documents say so, and nothing else does it.

## Domain separation

`sign` has no function that signs a bare message. Signing takes a `SigningTranscript`, which is
either built from a domain and its elements or built from bytes another module produced and then
checked: the bytes must decode as a canonical array whose first element is the claimed domain. The
three transcripts the specification writes as arrays reach a signature that way, and nothing else
can. The domains this crate and `kr-protocol` define:

| Domain | Covers |
| --- | --- |
| `kr-key-id/1` | A key purpose and public key, giving the key identifier |
| `kr-connect/1` | The complete client offer, host selection and both endpoint identities |
| `kr-pair/spake2-ed25519/1` | The short-code pairing context `C`, and the bundle exchange's additional authenticated data |
| `kr-pair/host`, `kr-pair/client` | The two PAKE role identities |
| `kr-pair/host-bundle/1`, `kr-pair/client-bundle/1` | A device bundle and the transcript it belongs to |
| `kr-pair/finish/1` | The invitation, attempt, transcript, both endpoint identities and both bundle hashes |
| `kr-pair/verify/1` | The short-code verification value |
| `kr-pair/direct/1`, `kr-pair/direct-verify/1` | The direct transcript `D` and its verification value |
| `kr-pair/owner-confirm/1` | An owner-confirmation challenge |
| `kr-revocation/1`, `kr-authority/1` | A revocation request and a host authority revision record |
| `kr-archive-manifest/1` | A signed archive manifest |
| `kr-recovery-bundle/1` | The retrieval context a recovery bundle's key is derived from |
| `KRRECOV1` | The `crypto_kdf` context of the recovery seed |

## Encrypted objects

A backup object is encrypted under its own random 256-bit key with `secretstream` in 1 MiB records.
The last record carries the final tag, and `decrypt_object` requires it: an upload cut short is not
a shorter valid object, it is an error. Record boundaries follow from the format rather than from a
length prefix, so there is no unauthenticated framing for an attacker to rewrite.

Each object key is wrapped separately for each recipient with `crypto_box_easy`. The wrap's
authenticated plaintext is `CBOR([context, object_key])`, where the context carries the format,
purpose, archive, generation, object, encrypted-object hash and both key identifiers. A wrap moved
to another object, generation or recipient fails to authenticate rather than yielding a key.

Opening a wrap does not decode it. `crypto_box` derives one shared secret from either direction, so
the same ciphertext opens both ways; the expected context's sender and recipient identifiers are
therefore checked against the two keys actually being used before anything is opened. The expected
prefix, `0x82 || CBOR(context) || 0x58 0x20`, is then rebuilt and compared with the opened bytes, and
the key is the remaining 32 bytes. Rebuilding rather than decoding is both the context check and the
reason no value tree ever holds a copy of the key.

`ArchiveDescriptor::from_canonical_bytes` is the entry point a restore uses: it bounds the bytes
before decoding them, then validates the version, the recipient count, and every wrap's archive,
generation, object, hash, purpose and recipient. An invalid descriptor therefore fails before any
object is allocated or written.

A manifest is verified against a writer key from the owner's recovery bundle. `verify_manifest`
takes the trusted writers as an argument and has no way to read one out of the archive, so a
descriptor cannot introduce a writer. A writer whose identifier is not the identifier of its own
signing key is rejected even if it reaches the trusted list.

## Envelopes and padding

Section 20 puts envelope sizes in declared buckets. A bucket that only described the plaintext would
describe nothing, because the ciphertext would still be the plaintext's length plus a constant. The
canonical plaintext is therefore padded to its bucket with libsodium's ISO/IEC 7816-4 padding before
it is encrypted, and the padding is inside the box.

The bucket is the next multiple of the granularity that is strictly larger than the plaintext, so
there is always at least one padding byte to remove. Granularity follows section 20: 1 KiB up to
16 KiB, 4 KiB up to 64 KiB, 64 KiB above that. The three bands do not overlap, so a reader recovers
the granularity from the padded length before it unpads, and then recomputes the bucket from the
unpadded length and compares it with both the padded length and the routing record. A service that
declares one size and stores another fails that comparison.

A notification preview over 16 KiB is refused rather than padded: below that, the notification rule
and the mailbox rule are the same 1 KiB granularity, and above it a reader with only the padded
length could not tell which rule produced it.

This reduces precision. It does not hide traffic patterns, and section 20 says so.

A notification preview over 16 KiB is refused on both sides: a paired sender is authenticated, not
trusted.

Opening an envelope also checks the expiry, and `ReplayLedger` refuses an envelope that has expired
as well as one it has already seen, so the retention window cannot be outlasted. The ledger's
durable store belongs to the controller: `entries` and `restore` are how it survives a restart.

## Recovery

The recovery seed is 256 random bits. `crypto_kdf` with context `KRRECOV1` derives the
recovery-bundle key from subkey 1 and the recovery recipient's `crypto_box` seed from subkey 2. A
backup producer holds only the recipient's public key, so every new archive stays recoverable
without copying a device private key.

The bundle is encrypted under a key that mixes subkey 1 with its retrieval context: the canonical
encoding of the service origin and the stable bundle locator. A bundle served from another origin
or under another locator does not authenticate, which is how origin and locator substitution fail
rather than causing trust in archive-supplied writer keys. Nothing else signs the bundle: the
`secretstream` object authenticates it under a key only the seed derives, so a restore that has
only the kit can authenticate what it retrieved.

`RecoverySeed::to_kit` exports the user's copy and `from_kit` reads it back after checking the kit's
profile version and its checksum. The kit's seed is a redacted, zeroising secret, so printing a kit
does not print the owner's recovery authority. `store::store_recovery_seed` and `store::load_recovery_seed` keep the owner's copy in the
secure store.

The recovery recipient is an ordinary stored-envelope `crypto_box` recipient. It is not a fifth key
purpose: what makes it different is that it is derived from the seed rather than generated on a
device.

The seed's checksum is the first four bytes of its SHA-256, so a mistyped recovery kit fails before
anything is decrypted.

## Secret storage

`SecretStore` has three implementations:

- `PlatformStore` uses the `keyring` crate, which selects Keychain Services on macOS and iOS, the
  Credential Manager on Windows and the Secret Service on other Unix systems.
- `FileStore` is the documented fallback, and **only** on a Unix system that is not macOS, iOS or
  Android: those platforms always have a protected store, so a missing one is an error rather than a
  downgrade to files. iOS and Android keys belong to the companion application's platform layer,
  which owns Keychain and Keystore access.

  The directory is mode 0700, owned by this account, and neither it nor any component of its path
  is a symbolic link. Every secret is created
  exclusively at mode 0600 under a staging name no valid secret name can collide with, flushed,
  renamed into place and the directory entry flushed, so a reader never sees a partial secret, one
  with the wrong mode, or a lost write after a crash. **That is the whole protection.** It depends on
  operating-system account isolation and on disk encryption, and it protects nothing from code
  already running as the same user. Deletion overwrites before unlinking, which a journalling or
  copy-on-write filesystem may not honour.
- `MemoryStore` is for tests, never touches a disk and redacts itself in debug output.

`open_store` records which store a host chose in a `.store-kind` marker beside the fallback
directory, and keeps using it. A host that chose files keeps using files even when a secret service
appears later, reporting that a migration is available; a host that chose the platform store and
now finds it missing fails rather than starting from an empty fallback. Switching on whichever
backend happens to work today would leave the application reading an empty store while its secrets
sat elsewhere. Moving them is an explicit, verified step.

A secret name may not contain a segment beginning with a dot, and the store's staging files and its
marker all do, so a secret can never collide with them.

Loading a device's keys reads four items. A partially written set is an error, never a silent
regeneration: regenerating one purpose would change that public key and break every record that
names it. Two purposes sharing a seed is also an error, because the two algorithms would give two
different public keys and nothing downstream would notice the reuse.

## Connection proofs

`connect` builds and verifies the `kr-connect/1` mutual proof. iroh authenticates the two transport
keys; these two signatures authenticate the two authorisation keys, so a peer holding only a
transport key cannot substitute the authorised application identity.

Verification checks, in order: the selection echoes the client nonce; both device identities match
the paired records; both key revisions match, so a stale key is rejected; the selection names the
host's paired endpoint; both live iroh endpoints equal the paired ones; and both signatures verify
over the exact transcript. A downgraded limit changes the transcript, so it fails as an
authentication error rather than passing unnoticed.

It also checks the negotiation itself before trusting the signatures over it: the selected version
must be one the client offered, every selected capability must be one the client offered, and no
negotiated limit may exceed what the client said it could receive. Signatures authenticate those
values; they do not establish that the negotiation was valid.

`ChallengeLedger` holds each challenge from the moment the host issues it until the connection's
proofs consume it, exactly once, and never issues a consumed one again. `verify_connect_once` is
the entry point a host uses: it is given the nonce this connection issued, requires the selection to
name that exact nonce, and consumes it before it checks anything. One set of proofs is therefore
accepted once, on the connection it belongs to. The outstanding set is bounded, and a full ledger is
answered by ending idle connections rather than by forgetting a challenge.

## Vectors

`fixtures/crypto/` holds three documents, regenerated with
`cargo run -p kr-crypto --bin kr-crypto-vectors` and checked in continuous integration with
`--check`:

| File | Contents |
| --- | --- |
| `signatures.json` | Ed25519 signatures over the domain-separated transcripts `fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` publish, both `kr-connect/1` proofs over the published connection transcript, the RFC 8032 section 7.1 test vector, and three negative cases a verifier must reject |
| `envelopes.json` | A sealed mailbox envelope with its authenticated plaintext and canonical bytes; a sealed manifest key wrap with its plaintext; the section 20 size buckets |
| `kdf.json` | The RFC 5869 HKDF-SHA256 vector, an HMAC-SHA256 vector, the `KRRECOV1` subkeys with the recovery recipient's public key, and the context-bound bundle key |

Only domain-separated transcripts are signed. `fixtures/cbor/digests.json` also publishes a complete
mutation object, which is hashed rather than signed: section 23 authenticates a live mutation
through its connection and its receipt digest, so a signature vector for it would describe an
operation the protocol does not perform.

The RFC 8032 and RFC 5869 vectors are there so a reader can confirm that this is standard Ed25519
and standard HKDF, not a variant. `packages/protocol/test/crypto.test.ts` checks the same documents
with the Node runtime's own SHA-256, HMAC-SHA256, HKDF-SHA256 and Ed25519 verification, and with
this repository's own TypeScript codec for the encodings, so a value that drifts in one language
fails in both.

## Known limitations

Two secret buffers in this path are not cleared, and neither is reachable from this wrapper.

1. **An envelope payload passes through `serde` and `ciborium` value trees that do not zeroise.**
   Encoding and decoding an `EnvelopePlaintext` builds an intermediate value tree whose byte and
   text buffers this crate does not own and cannot reach. The buffers it does own are cleared: the
   canonical encoding, the padded plaintext and the opened `SecretVec` all zeroise. The
   key-carrying paths avoid the trees entirely: a key wrap is assembled and read by hand, every key
   lives in a `Secret`, and the QR payload's encoding is assembled by hand around its secret.

   `EnvelopePlaintext` itself carries the payload in an ordinary `Bytes`, which does not zeroise
   either. That does not make the intermediate copies harmless; it means the whole chain is
   uncleared, and closing it means either a value tree whose temporaries clear themselves or a
   secret-bearing payload type. Both belong with the crate that owns the encoder.

   Reading a QR payload is the same case in miniature. Writing one is not: its encoding is
   assembled around the secret, so no encoder ever sees it. Reading one still goes through the
   strict decoder, which is the right place for the canonical-form rules; a payload that decodes
   has its value tree cleared, and one that fails to decode leaves a partial tree inside `kr-cbor`
   that this crate cannot reach. Closing that means the same thing as the envelope case: a value
   tree whose temporaries clear themselves, in the crate that owns the decoder.
2. **`hkdf` 0.13.0 keeps its pseudorandom key and expansion buffers uncleared.** The crate has no
   `zeroize` feature; `hmac` and `sha2` are built with theirs. Closing this means a maintained
   release that clears them, or a reviewed patch. Section 20 requires a maintained implementation,
   so a private fork is not the answer.

Both are recorded for the external cryptographic review that section 10 makes a release gate.

## Release manifest

Pin these in the release manifest, with their exact versions and the resolved dependency graph:

| Crate | Version |
| --- | --- |
| `libsodium-sys-stable` | 1.24.0 |
| `hkdf` | 0.13.0 |
| `hmac` | 0.13.0 |
| `sha2` | 0.11.0 |
| `subtle` | 2.6.1 |
| `zeroize` | 1.9.0 |
| `keyring` | 4.2.0 |
| `spake2` | 0.4.0 |

`libsodium-sys-stable` builds libsodium from the source archive it ships, so the manifest records
the crate version rather than a system library version. Compile and verify it on every Tauri target.

`hmac` and `sha2` are built with their `zeroize` features, so their internal buffers are cleared.
`hkdf` 0.13.0 has no such feature; its pseudorandom key and expansion buffers are not cleared, which
is a limitation of the pinned implementation rather than of this wrapper. The same applies to the
`serde` and `ciborium` value trees an envelope's payload passes through on its way to and from
canonical bytes. The paths that carry key material avoid both: a key wrap is assembled and read
without a value tree, and every key lives in a `Secret`.
