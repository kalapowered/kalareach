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
| `kr-collection-keys/1` | A synchronised collection's key record: its members, its epoch and each member's key wrap |
| `kr-recovery-bundle/1` | The retrieval context a recovery bundle's key is derived from |
| `KRRECOV1` | The `crypto_kdf` context of the recovery seed |

`kr-client` adds two digest domains of its own, neither of them a signature: `kr-collection-key-mark/1`,
the SHA-256 of a collection key a member compares keys by without keeping them, and
`kr-sync-membership-plan/1`, the digest that binds an owner's plan to the one operation it confirms.

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

## Producing one backup generation

`backup` is the layer above those primitives. It puts them in the order section 20 fixes, so a
producer does not have to remember it, and it is the only thing in the tree that writes an archive.

1. **Stage each object.** One random 256-bit key, `secretstream` in 1 MiB records, the final
   authenticated record required. A staged object also holds the SHA-256 of the plaintext it was
   made from; that digest and the object key are encryption state, they stay on the device, and a
   producer uploads the ciphertext and nothing else from it.
2. **Resume by reusing ciphertext.** An upload that stopped is continued with the bytes already
   created when the source digest still matches, and encryption restarts under a *new* key when it
   does not: continuing the old ciphertext would produce an object whose records came from two
   different sources under one key. A source that was only renamed keeps its ciphertext and records
   the name it has now. A resume never reuses a wrap nonce, because sealing a generation is a new
   call and every call draws a fresh nonce.
3. **Seal the generation.** The manifest is signed, every member key is wrapped once per recipient,
   the signed manifest *and those wraps* become the plaintext of one more encrypted object, and the
   manifest key is wrapped once per recipient into the public descriptor. The member wraps travel
   inside the manifest object because each one names an object identifier and an encrypted hash,
   and section 20 keeps both inside the encrypted manifest: only the opaque archive identifier and
   the encrypted-object references stay outside.
4. **Open it again.** The descriptor is bounded and validated before anything is allocated; it is
   checked against the archive the caller said it was restoring and against the generation the
   owner's checkpoint admits; the manifest is decrypted and its signature verified against the
   owner's trusted writers; the manifest is checked against the descriptor it came with and against
   the schema version this build reads; and only then can a member object be restored.
   `OpenArchive` cannot be built any other way, so a caller cannot reach the reading half without
   the checking half. `read_descriptor` exists for a caller that wants to *show* what it is about
   to restore first; reading one grants nothing, because opening enforces the same rules again.

The producer encodes the manifest payload under the same bounds the restore decodes with
(`MANIFEST_PAYLOAD_LIMITS`), and refuses more objects, more wraps or more bytes than those bounds
carry. A producer with looser bounds than its reader would write archives nothing could open, which
is the one failure a backup must not have: it looks complete until the day somebody needs it.

### Two limits, and which one binds

The public descriptor has two defaults, 64 KiB and 128 recipients, and the first applicable one
binds. In this encoding that is the byte limit, at about **100 recipients**, because a sealed key
wrap carries its whole authenticated context beside the box and comes to 648 bytes at a small
generation number. It is a figure rather than a guarantee: a wrap grows with the generation's
integer width, so an archive at generation 65 536 fits fewer. `seal_archive` enforces the *encoded
size*, which is the quantity section 20 bounds, and names the limit it hit;
`a_descriptor_refuses_the_recipient_that_takes_it_over_the_byte_limit` and
`a_larger_generation_number_fits_fewer_recipients` keep the figure honest.

### Revocation, rotation and the checkpoint

Revoking recipients removes them from every future wrap, and for a mutable shared collection it
rotates the keys as well. `ArchiveRecipients::revoke` takes every recipient that leaves in one step
and advances the rotation once for all of them. The rotation is a rule rather than a report: revoking advances
`ArchiveRecipients::rotation`, every staged object carries the rotation it was made under, and
`seal_archive` refuses one from before the current rotation. Resuming it makes it again under a new
key. `StagedObject`'s fields are private for that reason - the only ways to obtain one are
`stage_object` and `resume_object`, both of which take the rotation as an argument - so a caller
cannot revoke and then relabel and seal the ciphertext that revocation invalidated, whatever it
does with `Revocation::may_reuse_staged_ciphertext`. A device that kept reading what the others
wrote after it left would have lost nothing by being removed. Nothing here claims retroactive
secrecy.
`still_readable_after_revocation` computes what the removed device keeps - every generation
published before the revocation - so a host shows a person that rather than implying otherwise, and
`Revocation::describe` says it in a sentence.

Old object keys are held against the retained backup that needs them. `RetainedObjectKeys::
retain_only` is the whole policy: a host passes the backups it still retains and every key kept for
one it no longer retains goes, keys zeroising as they are dropped.

A signed manifest stops forgery; it does not stop a service handing back an older archive the owner
really did write. `GenerationExpectation` is the three questions a restore can be asking, because
they have different answers: nothing to compare against, the latest generation the owner verified,
or exactly one generation with exactly one manifest. `RestoreGeneration::against` answers it and
says where the archive stands: at the checkpoint, ahead of it, replayed from before it, claiming
its generation with another manifest, for a different archive altogether, or not the generation
this restore was authorised for. The last four are refused, and refused by `open_archive` itself
rather than only reported, so a caller that never looked at the report still cannot restore a
replay. Where the checkpoint came from travels with the answer, because a paired device's and a
recovery bundle's mean different things to a person. `proves_no_newer_archive` is always false and is a method rather than a comment: a service
holding a newer archive back looks exactly like an owner who has not written one, and
`RestoreGeneration::describe` says so in the sentence a restore displays, alongside the generation
it is restoring.

### What a backup carries

`may_back_up` and `may_restore` are one table, here rather than in each caller, so a device and a
host cannot answer the question differently. Session data, device configuration, generation
checkpoints and grant records may be carried. A reusable endpoint or control-signing private key,
the notification extension's preview key, the recovery seed and this host's grant and revocation
authority may not, and each refusal carries the reason; a restore refuses all of those and one
more, a grant that had been revoked. `RestoreLimits` states what a restore cannot do whatever it
put back: it always requires fresh owner-authorised pairing, and it never creates remote-control
authority.

**It is the decision, not the gate.** The layer below carries opaque bytes: `stage_object` encrypts
whatever it is handed, and `restore_object` returns whatever the manifest named. A caller that
wrote a private key into a member object and never asked this table about it would get that object
back. What closes the rule is each export and import path asking, for every kind it carries; this
crate supplies one answer so those paths cannot disagree.

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

### Opening what a service delivered

`open_delivered_envelope` is the path a delivered item takes, and it is the one that holds section
20's rule that decryption runs only against previously paired sender keys. The routing record names
a sender; that name is used to look a key up in `PairedSenders`, never to supply one. A name the
device has no key for stops there, before anything is decrypted.

The order is fixed. The keyless rules of the item's own shape run first, so a malformed item costs
no key at all. An identifier the ledger already holds is refused next, on the record's own claim, so
a redelivery costs no decryption; the claim is untrusted and that is only an early exit. Then the
sender is selected, the box is opened and every binding is checked. The replay identifier is
recorded **last**, after the payload's own verification has succeeded, because an item refused for a
reason that may pass, such as an issuer key this host has not learnt yet, has to stay openable when
it does. An item that was accepted is one that will never be accepted again.

`open_envelope` stays public beneath it, for a caller that already knows which key it means. That
caller takes on the two duties the delivery path discharges: selecting the sender from what it has
paired with, and recording the replay identifier.

### Synchronised objects

A synchronised object takes the same declared buckets, so one padding rule serves both and a
service checks one length rule. `seal_sync_object` pads, seals under the symmetric key a person's
devices share and returns the object a service stores; `open_sync_object` runs the keyless shape
rules first, opens, and removes the padding.

The additional authenticated data is the format domain and nothing else, so a ciphertext produced
for one purpose cannot be opened as another. What identifies an object, its own identity and its
kind, is inside the sealed plaintext, and the reader checks both there against the collection it
asked for. The revision travels with it so a reader can see whether the two devices hold the same
content.
Binding the requested collection into the additional data would be sound as well; it is left out
because the check inside the plaintext is the one a reader has to make either way.

### Collection keys

A synchronised collection is sealed under one key per epoch, and the devices that hold it are the
members a signed key record names (`kr_protocol::collection_keys`). The record carries, for every
member, the epoch's key wrapped to that member's stored-envelope key: `crypto_box_easy` from the
issuer's stored-envelope key under a fresh random nonce, over `CBOR([context, key])`, where the
context names the format `kr-collection-key-wrap/1`, the collection, the epoch and both key
identifiers. A wrap therefore opens for one collection, one epoch and one recipient, and
`open_collection_key` checks both parties against the expected context before it opens anything,
because a box sealed from A to B also opens from B to A. It opens against a sender key the caller
chose from its own paired records; nothing reads a sender key out of a record.

`issue_collection_key_record` wraps the key for every member, the issuer included, and signs the
record under `kr-collection-keys/1`, so every wrap in a record has one sender and every record names
its issuer among its members. `check_genesis` is the first record's rule: revision one, the first
epoch, nothing before it, and its issuer alone, whose installation is the collection's home.
`check_successor` is the rule between two records: the same collection and home, the next revision,
the previous record's digest, an issuer that was already a member with the same keys, and an epoch
that stays or moves on by one, where an unchanged epoch only adds members. A removal therefore
cannot be recorded without a new epoch; whether the new epoch's key is fresh is the issuer's to
ensure, since nothing that reads a record can see it.

`CollectionMembers` is the member set: an `ArchiveRecipients` of a mutable shared collection, whose
rotation is the epoch, with each member's authorisation key beside it. Adding a member keeps the
epoch; removing members advances it once and returns the same `Revocation` a backup recipient's
removal does, which claims no retroactive secrecy. `Revocation::describe_settings_sync` is the
sentence a person reads: the devices that stay get a new key, and the one that left keeps what it
already had. The rotation counter has no successor at its last value, so a removal that would need
one is refused whole, with `CryptoError::RotationExhausted`, rather than recorded at an epoch the
removed devices still hold the key of.

A member's side of the record is `kr_client::sync::membership`. Before a member uses a key from a
record it checks the chain from the record it holds, the issuer against its hosts' reports, the
signature, and its own wrap, opened against the issuer's stored-envelope key; for a new epoch the
key must differ from every key it holds and every key it opened from an earlier record since it
joined. No record may carry the key of a record the member sent since it joined that settled
without applying, since a service could still have handed out that record's wraps. The membership
file it keeps holds records, which carry only public keys and wraps, and no key: what it compares
keys by, the withdrawn ones included, is each key's mark, the SHA-256 of the key under
`kr-collection-key-mark/1`, and the key itself goes only to the device's secret store.

## Authority inside an envelope

A paired device is authenticated, not trusted. Section 19 makes content data rather than authority,
and section 20 says what follows: an authorisation-bearing payload is signed by its issuer **before**
encryption, so pairwise message authentication never substitutes for an issuer's grant signature.

`open_envelope` will not return an authority-bearing payload without a verification result. The
check is a required argument rather than a later step a caller can forget, and
`verify_authority_payload` is what a host passes. It resolves the issuer through
`AuthorityDirectory`, which is the reader's own authority and answers two questions:

| Question | What it establishes |
| --- | --- |
| Which authorisation key do you record for this device, as a producer of this kind of object? | The key is the reader's, not the envelope's. The role is part of the question because the two kinds have different issuers: any paired owner may publish a revocation request, and only the target host issues an ordered authority revision. |
| Do you hold this grant under that device's authority? | A grant reference on an envelope names the authority the payload acts under. Naming a grant is not holding one. |

The identifier the object carries must be that resolved key's own identifier, so an object signed by
one recorded key cannot name another device or another role and be accepted. The signature is then
verified over the object's own domain-separated transcript. A host satisfies the seam from its
paired-device directory and its grant directory together; a test satisfies it from a map; nothing
satisfies it from an envelope.

`ForwardedAuthority` is the closed set of objects this path carries: a signed revocation request and
a host's ordered authority revision record. Those are the two objects the protocol gives a signature
and an issuer key identifier. A grant is not among them, because `Grant` carries no signature and no
signing transcript of its own: a grant reaches a device over its authenticated connection and
through the authority feed, and forwarding one as a signed mailbox object would need a signed grant
object the protocol does not define.

Verification applies nothing. Whether a verified revocation or revision may be acted on is the
reader's own decision, made against its current authority afterwards.

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

The kit's printable and QR forms are one document rather than two encodings: a scanner reads the
bytes a person could have typed, and there is one format to get right. `kr_client::recovery`
renders and parses it. The seed is grouped Crockford base32, which leaves out `I`, `L`, `O` and
`U`, so the pairs a hand-written kit is misread as are not both in the alphabet; reading accepts
either case and maps `I` and `L` to `1` and `O` to `0`, and the checksum catches what the alphabet
does not. `fixtures/crypto/recovery-kit.json` publishes the exact document for the same test seed
`kdf.json` derives its subkeys from.

## Secret storage

`SecretStore` has three implementations:

- `PlatformStore` uses the `keyring` crate, which selects Keychain Services on macOS, the
  Credential Manager on Windows and the Secret Service on other Unix systems. It reports iOS and
  Android as unsupported.
- `FileStore` is the documented fallback, and as a fallback **only** on a Unix system that is not
  macOS, iOS or Android: those platforms always have a protected store, so a missing one is an
  error rather than a downgrade to files. iOS and Android keys belong to the companion
  application's platform layer, which owns Keychain and Keystore access. `open_store_in` reaches a
  `FileStore` on any platform, and the next section is what that is for.

  The directory is mode 0700, owned by this account, and neither it nor any component of its path
  is a symbolic link. Every secret is created
  exclusively at mode 0600 under a staging name no valid secret name can collide with, flushed,
  renamed into place and the directory entry flushed, so a reader never sees a partial secret, one
  with the wrong mode, or a lost write after a crash. **That is the whole protection.** It depends on
  operating-system account isolation and on disk encryption, and it protects nothing from code
  already running as the same user. Deletion overwrites before unlinking, which a journalling or
  copy-on-write filesystem may not honour.
- `MemoryStore` is for a unit test, never touches a disk and redacts itself in debug output.

### Where a test keeps its secrets

`open_store` decides which store belongs to a host. On macOS, iOS, Android and Windows it returns
the platform's credential store or it fails. `open_store_in(directory)` takes the directory as an
argument instead, and it is the only way to reach a `FileStore` where the fallback is compiled out.
A test, a bench or a demonstration run calls it with a directory of its own, and a daemon one of
them starts is given `--secret-store file`, which makes the same choice on the command line. An
item written to a person's credential store belongs to the account rather than to the run and
outlives it, and nothing collects it, so a run that wrote there would leave its keys behind every
time.

The named directory must not be a link, and every path below it is checked against a link on each
read, write and deletion. On Unix it is created mode 0700 and refused unless it belongs to this
account, which are the rules the fallback root carries. Windows has no mode bits and this crate
sets no access-control list there, so a directory carries the one it inherits and the caller is the
one protecting it; that is part of why section 10 offers no fallback on Windows.

The directory's ancestors are checked for nothing on any platform, and the caller is the one
vouching for them. That is what lets a run keep its secrets under the system temporary directory:
on macOS that is below `/var`, a link to `/private/var`, which the fallback's own rule refuses. The
name is reduced to its components first, so `store/` and `store/.` cannot slip a link past the
check on the directory itself.

`open_store_in` records nothing. The `.store-kind` marker is `open_store`'s record of a choice made
once for a host, and this choice is passed in at every start.

### The recorded choice

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

`fixtures/crypto/` holds the documents below. The first three are regenerated with
`cargo run -p kr-crypto --bin kr-crypto-vectors` and checked in continuous integration with
`--check`, as are `relay.json` and `collection-keys.json`. `recovery-kit.json` is checked by `crates/kr-client/tests/
recovery.rs::the_printed_kit_is_the_document_the_fixture_publishes` instead, because the rendering
it pins belongs to `kr-client` rather than to the vector generator:

| File | Contents |
| --- | --- |
| `signatures.json` | Ed25519 signatures over the domain-separated transcripts `fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` publish, both `kr-connect/1` proofs over the published connection transcript, the RFC 8032 section 7.1 test vector, and three negative cases a verifier must reject |
| `envelopes.json` | A sealed mailbox envelope with its authenticated plaintext and canonical bytes; a signed revocation request forwarded in an envelope, with the exact bytes its signature covers; a sealed manifest key wrap with its plaintext; the section 20 size buckets |
| `kdf.json` | The RFC 5869 HKDF-SHA256 vector, an HMAC-SHA256 vector, the `KRRECOV1` subkeys with the recovery recipient's public key, and the context-bound bundle key |
| `collection-keys.json` | A synchronised collection's first two key records, one member creating it and then adding a second at the same epoch, with the bytes each signature covers, each record's digest, and the second member's key wrap with its plaintext |
| `recovery-kit.json` | The printable and QR recovery kit for the same test seed: its profile version, checksum, grouped base32 seed, locator, origins and the exact document bytes |

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

   Reading a QR payload is the same case. Writing one is not: its encoding is assembled around the
   secret, into a buffer reserved at its exact final size, so no encoder ever sees the secret and
   no reallocation ever moves it. Reading one goes through the strict decoder, which is where the
   canonical-form rules belong; writing a second decoder to avoid its buffers would mean a second
   implementation of those rules, which section 23 tells this project not to do.

   The decoder's copies are therefore uncleared in both outcomes: a payload that fails to decode
   leaves a partial tree, and one that succeeds leaves the tree the decoder re-encoded to check the
   canonical form, plus those output bytes. This crate clears the tree it is handed back; it cannot
   reach the rest. Closing it means the same thing as the envelope case: a value tree whose
   temporaries clear themselves, in `crates/kr-cbor`, which owns the decoder.
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
