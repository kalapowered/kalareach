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
`unsafe`. The crate denies unsafe code everywhere else, and every other module in the workspace
forbids it outright.

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

`sign` has no function that signs a bare message. Every signature covers
`CBOR([domain, element, ...])` built through `kr-cbor`, which is the shape section 23 requires. The
domains this crate and `kr-protocol` define:

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
| `kr-archive-manifest/1`, `kr-recovery-bundle/1` | A signed archive manifest and a recovery bundle |
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

A manifest is verified against a writer key from the owner's recovery bundle. `verify_manifest`
takes the trusted writers as an argument and has no way to read one out of the archive, so a
descriptor cannot introduce a writer. A writer whose identifier is not the identifier of its own
signing key is rejected even if it reaches the trusted list.

## Recovery

The recovery seed is 256 random bits. `crypto_kdf` with context `KRRECOV1` derives the
recovery-bundle key from subkey 1 and the recovery recipient's `crypto_box` seed from subkey 2. A
backup producer holds only the recipient's public key, so every new archive stays recoverable
without copying a device private key.

The recovery recipient is an ordinary stored-envelope `crypto_box` recipient. It is not a fifth key
purpose: what makes it different is that it is derived from the seed rather than generated on a
device.

The seed's checksum is the first four bytes of its SHA-256, so a mistyped recovery kit fails before
anything is decrypted.

## Secret storage

`SecretStore` has three implementations:

- `PlatformStore` uses the `keyring` crate, which selects Keychain Services on macOS and iOS, the
  Credential Manager on Windows and the Secret Service on other Unix systems.
- `FileStore` is the documented fallback for a Unix system with no secret service. The directory is
  mode 0700 and every file is mode 0600, written to a temporary file and renamed so a reader never
  sees a partial secret or one with the wrong mode. **That is the whole protection.** It depends on
  operating-system account isolation and on disk encryption, and it protects nothing from code
  already running as the same user. Deletion overwrites before unlinking, which a journalling or
  copy-on-write filesystem may not honour.
- `MemoryStore` is for tests and never touches a disk.

`open_store` tries the platform store and falls back, reporting which one it opened, so setup can
tell the user when a host is relying on the fallback.

Loading a device's keys reads four items. A partially written set is an error, never a silent
regeneration: regenerating one purpose would change that public key and break every record that
names it.

## Connection proofs

`connect` builds and verifies the `kr-connect/1` mutual proof. iroh authenticates the two transport
keys; these two signatures authenticate the two authorisation keys, so a peer holding only a
transport key cannot substitute the authorised application identity.

Verification checks, in order: the selection echoes the client nonce; both device identities match
the paired records; both key revisions match, so a stale key is rejected; the selection names the
host's paired endpoint; both live iroh endpoints equal the paired ones; and both signatures verify
over the exact transcript. A downgraded limit changes the transcript, so it fails as an
authentication error rather than passing unnoticed.

`ChallengeLedger` rejects a reused host challenge and is bounded, so a replayed transcript cannot be
accepted and the ledger cannot grow without limit.

## Vectors

`fixtures/crypto/` holds three documents, regenerated with
`cargo run -p kr-crypto --bin kr-crypto-vectors` and checked in continuous integration with
`--check`:

| File | Contents |
| --- | --- |
| `signatures.json` | Ed25519 signatures over the canonical bytes `fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` publish, the RFC 8032 section 7.1 test vector, and three negative cases a verifier must reject |
| `envelopes.json` | A mailbox envelope's authenticated plaintext, canonical bytes and `crypto_box_easy` output; a manifest key wrap's plaintext and ciphertext; the section 20 size buckets |
| `kdf.json` | The RFC 5869 HKDF-SHA256 vector, an HMAC-SHA256 vector, and the `KRRECOV1` subkeys with the recovery recipient's public key |

The RFC 8032 and RFC 5869 vectors are there so a reader can confirm that this is standard Ed25519
and standard HKDF, not a variant. The TypeScript package checks the same documents with the Node
runtime's own SHA-256, HMAC and HKDF, so a value that drifts in one language fails in both.

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

`libsodium-sys-stable` builds libsodium from the source archive it ships, so the manifest records
the crate version rather than a system library version. Compile and verify it on every Tauri
target.
