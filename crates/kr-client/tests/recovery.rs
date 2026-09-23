//! The recovery seed, its kit, the bundle at its locator, and what a fresh restore puts back.
//!
//! Section 20 ¶9 to ¶13 and KR-ACC-033. Nothing here talks to a real service: the compare-and-swap
//! seam is `kr_client::services::SyncBackupService`, and the scripted implementation below is one
//! store's worth of bytes and positions.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::recovery::{
    Admission, BundleStore, FreshRestore, LostWrite, MAX_RECOVERY_KIT_BYTES, Material,
    OfflineExport, RECOVERY_KIT_FORMAT, RecoveryError, RestoreLimits, RetrievalPolicy, SeedSource,
    ServiceAccess, bundle_collection, may_back_up, may_restore, parse_kit, qr_payload, render_kit,
};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_crypto::backup::{
    ArchiveExpectation, ArchivePlan, ArchiveReader, ArchiveRecipients, CheckpointSource,
    CollectionKind, GenerationExpectation, ObjectSource, RestoreGeneration, open_archive,
    seal_archive, stage_object,
};
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_protocol::archive::{
    ArchiveCheckpoint, CollectionLocator, RecoveryContext, RecoveryKit, TrustedWriter,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ArchiveId, BackupGeneration, BackupObjectId, DeviceId, SyncConflictId};
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};

const ORIGIN: &str = "https://reach.kala.to";
const OTHER_ORIGIN: &str = "https://self-hosted.example";
const LOCATOR: &str = "b7f1c0d2-recovery-bundle";

// ---------------------------------------------------------------------------------------------
// One scripted sync and backup service: bytes and a place in the order per collection.
// ---------------------------------------------------------------------------------------------

/// The position this suite's service gives the nth write of a collection.
///
/// A deployed service names each write with an opaque identifier of its own. Deriving it from the
/// write sequence lets a test say where it expects a write to land, and every comparison here is
/// within one collection, which is what makes deriving it safe.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
    )
}

/// What this service did with one exchange, as the suite asked it to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Interruption {
    /// It answers.
    #[default]
    None,
    /// It applies the write and the answer never comes back.
    LoseTheAnswerAfterTheWrite,
    /// The request never reaches it.
    LoseTheRequest,
}

/// One exchange as the service received it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Attempt {
    collection: String,
    request_id: Uuid,
    signed_at_ms: u64,
    expected: Option<SyncPosition>,
    /// The bytes it carried, which are what a delayed request would apply if it landed later.
    ciphertext: Vec<u8>,
}

/// One fence as the service received it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Fence {
    collection: String,
    request_id: Uuid,
    first_signed_at_ms: u64,
    last_signed_at_ms: u64,
}

/// What this service recorded about one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Receipt {
    Applied(SyncPosition),
    Refused(Option<SyncConflictId>),
    /// The fence recorded what it concluded about the past, so asking again concludes the same.
    Fenced {
        never_ran: bool,
    },
}

#[derive(Debug, Default)]
struct StoredCollection {
    position: Option<SyncPosition>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Default)]
struct ScriptedService {
    collections: Mutex<BTreeMap<String, StoredCollection>>,
    attempts: Mutex<Vec<Attempt>>,
    receipts: Mutex<BTreeMap<Uuid, Receipt>>,
    fences: Mutex<Vec<Fence>>,
    /// How many times anything asked this service for a request's recorded state.
    statuses_asked: Mutex<u64>,
    interruption: Mutex<Interruption>,
    /// A position the next fetch answers with instead of the one it holds.
    fetch_answers: Mutex<Option<SyncPosition>>,
    /// A position the next applied exchange answers with instead of the one it assigned.
    exchange_answers: Mutex<Option<SyncPosition>>,
    /// The copy this service keeps of a write it refuses, when it keeps one.
    keeps_refused_copies_as: Mutex<Option<SyncConflictId>>,
    /// Whether a fence that finds no receipt can still say nothing ever ran under the identity.
    fence_cannot_say_nothing_ran: Mutex<bool>,
}

impl ScriptedService {
    fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Replaces one collection's bytes without moving it on.
    ///
    /// This is a service that serves something other than what the owner wrote, which is the whole
    /// of what the bundle's context binding has to catch. It keeps the place in the order the
    /// collection already had, and gives a collection that had none the first place, because a
    /// service that serves bytes has served them from somewhere.
    fn substitute(&self, collection: &str, ciphertext: Vec<u8>) {
        let mut collections = self.collections.lock().expect("the store");
        let entry = collections.entry(collection.to_owned()).or_default();
        entry.position = entry.position.or_else(|| Some(at(1)));
        entry.ciphertext = ciphertext;
    }

    /// Serves one collection's bytes as a write of their own, at the next place in its order.
    ///
    /// This is a service replaying an old ciphertext as though somebody had written it again: the
    /// place moves on, so nothing about the order gives it away, and only what the bytes say can.
    fn republish(&self, collection: &str, ciphertext: Vec<u8>) {
        let mut collections = self.collections.lock().expect("the store");
        let entry = collections.entry(collection.to_owned()).or_default();
        entry.position = Some(at(entry.position.map_or(1, |held| held.write_sequence + 1)));
        entry.ciphertext = ciphertext;
    }

    fn position_of(&self, collection: &str) -> Option<SyncPosition> {
        self.collections
            .lock()
            .expect("the store")
            .get(collection)
            .and_then(|entry| entry.position)
    }

    /// Makes the next exchange behave as the suite asks.
    fn interrupt_the_next_exchange(&self, interruption: Interruption) {
        *self.interruption.lock().expect("the script") = interruption;
    }

    /// Makes the next fetch answer with a position of the suite's choosing.
    fn next_fetch_answers(&self, position: SyncPosition) {
        *self.fetch_answers.lock().expect("the script") = Some(position);
    }

    /// Makes the next applied exchange answer with a position of the suite's choosing.
    fn next_exchange_answers(&self, position: SyncPosition) {
        *self.exchange_answers.lock().expect("the script") = Some(position);
    }

    /// Makes this service keep a copy of every write it refuses, under one name.
    fn keeps_refused_copies_as(&self, conflict_id: SyncConflictId) {
        *self.keeps_refused_copies_as.lock().expect("the script") = Some(conflict_id);
    }

    fn attempts(&self) -> Vec<Attempt> {
        self.attempts.lock().expect("the attempts").clone()
    }

    fn fences(&self) -> Vec<Fence> {
        self.fences.lock().expect("the fences").clone()
    }

    /// Removes the receipt of one request, as a sweep past its retention would.
    ///
    /// A fence then finds nothing, and the service can no longer say that nothing ever ran under
    /// the identity, because a receipt of a run is exactly what it has just stopped holding.
    fn sweep_the_receipt_of(&self, request_id: Uuid) {
        self.receipts
            .lock()
            .expect("the receipts")
            .remove(&request_id);
        *self
            .fence_cannot_say_nothing_ran
            .lock()
            .expect("the script") = true;
    }

    fn statuses_asked(&self) -> u64 {
        *self.statuses_asked.lock().expect("the count")
    }

    /// Executes one exchange, or answers it from the receipt this service already holds.
    ///
    /// Every exchange goes through here, whether it arrives when it was sent or long afterwards,
    /// so a delayed request meets exactly the rules a prompt one meets: a receipt is history and
    /// is answered from, a fenced identity executes nothing, and the comparison is by the object
    /// the caller named rather than by its place in the order.
    fn execute(&self, attempt: &Attempt) -> Result<SyncExchanged, ClientError> {
        let mut receipts = self.receipts.lock().expect("the receipts");
        match receipts.get(&attempt.request_id) {
            Some(Receipt::Applied(position)) => {
                return Ok(SyncExchanged::Applied {
                    position: *position,
                });
            }
            Some(Receipt::Refused(retained)) => {
                return Ok(SyncExchanged::Refused {
                    retained: *retained,
                });
            }
            Some(Receipt::Fenced { .. }) => {
                return Err(ClientError::Host(ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "that request identity is fenced, so nothing executes under it",
                )));
            }
            None => {}
        }
        let mut collections = self.collections.lock().expect("the store");
        let entry = collections.entry(attempt.collection.clone()).or_default();
        if names(entry.position) != names(attempt.expected) {
            let retained = *self.keeps_refused_copies_as.lock().expect("the script");
            receipts.insert(attempt.request_id, Receipt::Refused(retained));
            return Ok(SyncExchanged::Refused { retained });
        }
        let position = self
            .exchange_answers
            .lock()
            .expect("the script")
            .take()
            .unwrap_or_else(|| at(entry.position.map_or(1, |held| held.write_sequence + 1)));
        entry.position = Some(position);
        entry.ciphertext.clone_from(&attempt.ciphertext);
        receipts.insert(attempt.request_id, Receipt::Applied(position));
        Ok(SyncExchanged::Applied { position })
    }

    /// Delivers an exchange this service was sent and had not executed when it was sent.
    ///
    /// It is a request that was still on its way while the device read the bundle and decided what
    /// to do next.
    fn deliver_the_delayed_attempt(&self, attempt: &Attempt) -> Result<SyncExchanged, ClientError> {
        self.execute(attempt)
    }
}

/// An answer that never came back, which is the one refusal that establishes nothing.
fn lost(what: &'static str) -> ClientError {
    ClientError::Host(ProtocolError::new(ErrorCode::UpstreamUnavailable, what))
}

/// Returns the object a position names, which is its revision and never its place in the order.
///
/// No position at all and a removal's position both name no object, and the service compares by
/// the object. The place in the order is how a device tells a later answer from an earlier one.
fn names(position: Option<SyncPosition>) -> Option<SyncRevision> {
    position.and_then(|position| position.revision.as_ref().copied())
}

impl SyncBackupService for ScriptedService {
    fn compare_exchange<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        let attempt = Attempt {
            collection: collection.to_owned(),
            request_id,
            signed_at_ms,
            expected,
            ciphertext: ciphertext.to_vec(),
        };
        Box::pin(async move {
            self.attempts
                .lock()
                .expect("the attempts")
                .push(attempt.clone());
            let interruption = std::mem::take(&mut *self.interruption.lock().expect("the script"));
            if interruption == Interruption::LoseTheRequest {
                return Err(lost("the request never reached the service"));
            }
            let answered = self.execute(&attempt);
            if interruption == Interruption::LoseTheAnswerAfterTheWrite {
                return Err(lost("the answer never came back"));
            }
            answered
        })
    }

    /// The bundle path never asks this, and the count beside it is what proves so.
    ///
    /// Settlement from a receipt belongs to the settings-sync outbox, whose work is session content
    /// under a privacy generation and which keeps a durable account of every request it dispatches.
    /// A recovery bundle keeps no such account: it recognises its own write by reading, and it ends
    /// one it lost the answer to by fencing the identity.
    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move {
            *self.statuses_asked.lock().expect("the count") += 1;
            Ok(SyncRequestStatus::Unknown)
        })
    }

    fn fence_request<'a>(
        &'a self,
        collection: &'a str,
        request_id: Uuid,
        first_signed_at_ms: u64,
        last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            self.fences.lock().expect("the fences").push(Fence {
                collection: collection.to_owned(),
                request_id,
                first_signed_at_ms,
                last_signed_at_ms,
            });
            // A request the service has already decided keeps its outcome; one it has not is
            // fenced, and the receipt of the fence is what refuses an exchange arriving afterwards.
            let never_ran = !*self
                .fence_cannot_say_nothing_ran
                .lock()
                .expect("the script");
            let recorded = *self
                .receipts
                .lock()
                .expect("the receipts")
                .entry(request_id)
                .or_insert(Receipt::Fenced { never_ran });
            Ok(match recorded {
                Receipt::Applied(position) => SyncRequestFence::Applied { position },
                Receipt::Refused(retained) => SyncRequestFence::Refused { retained },
                Receipt::Fenced { never_ran } => SyncRequestFence::Fenced { never_ran },
            })
        })
    }

    fn fetch<'a>(&'a self, collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        Box::pin(async move {
            let scripted = self.fetch_answers.lock().expect("the script").take();
            let collections = self.collections.lock().expect("the store");
            collections.get(collection).map_or_else(
                || {
                    Err(ClientError::Host(ProtocolError::new(
                        ErrorCode::UnknownSession,
                        "no such collection",
                    )))
                },
                |entry| {
                    let position = scripted
                        .or(entry.position)
                        .expect("the collection holds a write");
                    Ok((position, entry.ciphertext.clone()))
                },
            )
        })
    }

    /// Nothing to drop: a refusal here names the copy the script says it kept, and nothing is held
    /// under that name, so every copy a resolution could name is already gone.
    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async move { Ok(false) })
    }
}

fn context(origin: &str) -> RecoveryContext {
    RecoveryContext {
        service_origin: origin.to_owned(),
        bundle_locator: LOCATOR.to_owned(),
    }
}

fn kit_of(seed: &RecoverySeed, origins: &[&str]) -> RecoveryKit {
    seed.to_kit(
        origins.iter().map(|origin| (*origin).to_owned()).collect(),
        LOCATOR.to_owned(),
    )
}

fn trusted(writer: &AuthorisationKeyPair) -> TrustedWriter {
    TrustedWriter {
        writer_key_id: writer.key_id(),
        signing_key: *writer.public(),
        enrolled_at_ms: TimestampMs::new(1_700_000_000_000),
    }
}

fn archive_id() -> ArchiveId {
    ArchiveId::new(Uuid::from_bytes([0x11; 16]))
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.14: the seed, its checksum and the printable and QR representation.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_kit_round_trips_through_its_printable_and_scanned_forms() {
    let seed = RecoverySeed::generate().expect("a seed");
    let kit = kit_of(&seed, &[ORIGIN, OTHER_ORIGIN]);
    let document = render_kit(&kit).expect("a printable kit");

    assert!(document.starts_with(RECOVERY_KIT_FORMAT));
    assert!(document.contains(LOCATOR));
    assert!(document.contains(ORIGIN));
    assert!(document.contains(OTHER_ORIGIN));
    assert!(document.len() <= MAX_RECOVERY_KIT_BYTES);
    // The printed seed is the alphabet's, so the characters a person confuses are not in it.
    let printed_seed = document
        .lines()
        .find_map(|line| line.strip_prefix("seed: "))
        .expect("a seed line");
    assert!(
        printed_seed.chars().all(|character| character == '-'
            || character.is_ascii_digit()
            || (character.is_ascii_uppercase() && !matches!(character, 'I' | 'L' | 'O' | 'U'))),
        "the printed seed is Crockford base32: {printed_seed}"
    );

    let read = parse_kit(&document).expect("the kit reads back");
    assert_eq!(read.seed.expose(), kit.seed.expose());
    assert_eq!(read.seed_checksum, kit.seed_checksum);
    assert_eq!(read.service_origins, kit.service_origins);
    assert_eq!(read.bundle_locator, kit.bundle_locator);

    // What a QR code carries is what a person could have typed.
    let scanned = qr_payload(&kit).expect("a QR payload");
    assert_eq!(scanned.as_slice(), document.as_bytes());
    let from_scan = parse_kit(std::str::from_utf8(&scanned).expect("text")).expect("a kit");
    assert_eq!(from_scan.seed.expose(), kit.seed.expose());

    // The seed the kit carries derives the same two subkeys as the seed it came from.
    let restored = RecoverySeed::from_kit(&read).expect("the seed");
    assert_eq!(restored.checksum(), seed.checksum());
    assert_eq!(
        restored.recipient().expect("a recipient").public(),
        seed.recipient().expect("a recipient").public()
    );
    assert!(
        restored
            .bundle_key_for(&context(ORIGIN))
            .expect("a key")
            .constant_time_eq(&seed.bundle_key_for(&context(ORIGIN)).expect("a key"))
    );
}

#[test]
fn the_printed_kit_is_the_document_the_fixture_publishes() {
    // `fixtures/crypto/recovery-kit.json` pins the exact bytes a person types and a camera reads,
    // for the same test seed `fixtures/crypto/kdf.json` derives its subkeys from. A change to the
    // rendering is a change to something already printed on paper, so it fails here rather than
    // leaving two builds that disagree about what a kit is.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/crypto/recovery-kit.json");
    let text = std::fs::read_to_string(&path).expect("the recovery kit fixture");
    let fixture: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    let seed_hex = fixture["kit"]["seed_hex"].as_str().expect("a seed");
    let seed_bytes: Vec<u8> = (0..seed_hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&seed_hex[index..index + 2], 16).expect("hexadecimal"))
        .collect();
    let seed = RecoverySeed::from_stored_bytes(&seed_bytes).expect("the seed");
    let kit = seed.to_kit(
        fixture["kit"]["service_origins"]
            .as_array()
            .expect("origins")
            .iter()
            .map(|origin| origin.as_str().expect("an origin").to_owned())
            .collect(),
        fixture["kit"]["bundle_locator"]
            .as_str()
            .expect("a locator")
            .to_owned(),
    );

    let document = render_kit(&kit).expect("a printable kit");
    assert_eq!(
        document.as_str(),
        fixture["printed"]["document"].as_str().expect("a document")
    );
    let scanned = qr_payload(&kit).expect("a QR payload");
    assert_eq!(
        scanned.len() as u64,
        fixture["printed"]["qr_payload_len"]
            .as_u64()
            .expect("a length")
    );
    assert_eq!(
        kit.seed_checksum
            .as_slice()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        fixture["kit"]["seed_checksum_hex"]
            .as_str()
            .expect("a checksum")
    );

    // And the published document reads back to the kit it was printed from.
    let read = parse_kit(fixture["printed"]["document"].as_str().expect("a document"))
        .expect("the published document is a kit");
    assert_eq!(read.seed.expose(), kit.seed.expose());
    assert_eq!(read.bundle_locator, kit.bundle_locator);
    assert_eq!(read.service_origins, kit.service_origins);
}

#[test]
fn a_mistyped_kit_fails_on_its_checksum_before_anything_is_derived() {
    let seed = RecoverySeed::generate().expect("a seed");
    let kit = kit_of(&seed, &[ORIGIN]);
    let document = render_kit(&kit).expect("a printable kit");

    // One transcription slip in the seed, keeping the alphabet and the length.
    let printed = document
        .lines()
        .find_map(|line| line.strip_prefix("seed: "))
        .expect("a seed line")
        .to_owned();
    let mut characters: Vec<char> = printed.chars().collect();
    let position = characters
        .iter()
        .position(|character| *character != '-')
        .expect("a symbol");
    characters[position] = if characters[position] == '2' {
        '3'
    } else {
        '2'
    };
    let mistyped: String = characters.into_iter().collect();
    let document = document.replace(&printed, &mistyped);

    assert!(matches!(
        parse_kit(&document),
        Err(RecoveryError::MistypedKit)
    ));
}

#[test]
fn a_kit_read_by_hand_forgives_the_letters_the_alphabet_leaves_out() {
    let seed = RecoverySeed::from_stored_bytes(&[0x5a; 32]).expect("a seed");
    let kit = kit_of(&seed, &[ORIGIN]);
    let document = render_kit(&kit).expect("a printable kit");

    // A person writes the kit down in lower case and reads a `0` back as an `O` and a `1` as an
    // `l`. Neither letter is in the alphabet, so both are unambiguous.
    let hand_written = document
        .to_lowercase()
        .replace(&ORIGIN.to_lowercase(), ORIGIN);
    let mut lines: Vec<String> = Vec::new();
    for line in hand_written.lines() {
        if let Some(seed_line) = line.strip_prefix("seed: ") {
            lines.push(format!(
                "seed: {}",
                seed_line.replace('0', "O").replace('1', "l")
            ));
        } else {
            lines.push(line.to_owned());
        }
    }
    let document = format!("{}\n", lines.join("\n"));
    let read = parse_kit(&document).expect("a kit written down by hand still reads");
    assert_eq!(read.seed.expose(), kit.seed.expose());
}

#[test]
fn a_document_this_format_does_not_define_is_refused() {
    let seed = RecoverySeed::generate().expect("a seed");
    let kit = kit_of(&seed, &[ORIGIN]);
    let document = render_kit(&kit).expect("a printable kit");

    for broken in [
        document.replace(RECOVERY_KIT_FORMAT, "kalareach-recovery-kit/2"),
        document.replace("locator: ", "somethingelse: "),
        document
            .lines()
            .filter(|line| !line.starts_with("origin: "))
            .collect::<Vec<_>>()
            .join("\n"),
        document
            .lines()
            .filter(|line| !line.starts_with("seed: "))
            .collect::<Vec<_>>()
            .join("\n"),
    ] {
        assert!(
            parse_kit(&broken).is_err(),
            "a document this format does not define is refused: {broken}"
        );
    }

    // And a kit whose origin could not be written on a line is refused when it is built.
    let mut unprintable = kit_of(&seed, &["https://reach.kala.to\nlocator: elsewhere"]);
    assert!(matches!(
        render_kit(&unprintable),
        Err(RecoveryError::UnprintableKit { .. })
    ));
    unprintable.service_origins = Vec::new();
    assert!(matches!(
        render_kit(&unprintable),
        Err(RecoveryError::UnprintableKit { .. })
    ));
    let mut other_profile = kit_of(&seed, &[ORIGIN]);
    other_profile.profile_version = U64::new(2);
    assert!(matches!(
        render_kit(&other_profile),
        Err(RecoveryError::UnsupportedProfile { version: 2 })
    ));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.15: the bundle is committed before a writer is declared recovery-enabled.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_writer_is_declared_recovery_enabled_only_after_its_bundle_has_landed() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    let enabled = store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits and the writer is declared");
    assert_eq!(enabled.writer_key_id(), writer.key_id());
    assert_eq!(enabled.bundle_revision(), 1);

    // The declaration is only true because the bundle is at the locator: a fresh device reads it
    // back and finds the writer there.
    let mut reader = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let read = reader.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.revision.get(), enabled.bundle_revision());
    assert!(
        read.trusted_writers
            .iter()
            .any(|held| held.writer_key_id == writer.key_id())
    );

    assert_eq!(
        service.position_of(bundle_collection(&context(ORIGIN))),
        Some(enabled.bundle_position())
    );
}

#[tokio::test]
async fn a_writer_whose_bundle_did_not_commit_is_not_declared() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let first = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("a writer key");

    // Another device writes first, so this one's compare-and-swap loses.
    let mut other = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut theirs = BundleStore::empty(TimestampMs::new(1));
    other
        .enable_writer(&seed, &mut theirs, trusted(&first), TimestampMs::new(1_000))
        .await
        .expect("their bundle commits");

    let mut ours = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    let refusal = ours
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&second),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("the comparison is lost");
    assert!(matches!(
        refusal,
        RecoveryError::BundleConflict {
            expected: None,
            retained: None
        }
    ));
    assert_eq!(
        bundle.revision.get(),
        0,
        "a revision advanced for a write that did not land goes back"
    );

    // What is at the locator is still the first device's bundle, with only its writer in it.
    let read = ours.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.trusted_writers.len(), 1);
    assert!(
        read.trusted_writers
            .iter()
            .any(|held| held.writer_key_id == first.key_id())
    );
}

#[tokio::test]
async fn a_refused_bundle_write_names_the_copy_the_service_kept_of_it() {
    let service = ScriptedService::shared();
    let kept = SyncConflictId::new(Uuid::from_bytes([0xc0; 16]));
    service.keeps_refused_copies_as(kept);
    let seed = RecoverySeed::generate().expect("a seed");
    let first = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("a writer key");

    let mut other = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut theirs = BundleStore::empty(TimestampMs::new(1));
    other
        .enable_writer(&seed, &mut theirs, trusted(&first), TimestampMs::new(1_000))
        .await
        .expect("their bundle commits");

    // A refusal says the comparison did not hold. It does not say the service kept nothing of what
    // it was sent, and a refusal that dropped the name of the copy would be an owner who could not
    // be shown the artefact the service is holding.
    let mut ours = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    let refusal = ours
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&second),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("the comparison is lost");
    assert!(matches!(
        refusal,
        RecoveryError::BundleConflict {
            expected: None,
            retained: Some(named)
        } if named == kept
    ));
    assert_eq!(
        ours.lost_write(),
        None,
        "a refusal is an answer, so nothing is outstanding"
    );
}

// ---------------------------------------------------------------------------------------------
// A bundle write whose answer never came back. The bundle is key material at a stable locator,
// so it settles by reading rather than through a durable request account.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn every_bundle_write_carries_a_fresh_identity_the_instant_of_the_call_and_where_it_last_saw_the_bundle()
 {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let producer = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    let first = store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    store
        .enable_producer(
            &seed,
            &mut bundle,
            producer.key_id(),
            *producer.public(),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the producer is enrolled");

    let attempts = service.attempts();
    assert_eq!(attempts.len(), 2);
    assert!(attempts.iter().all(|attempt| attempt.collection == LOCATOR));
    assert_ne!(
        attempts[0].request_id, attempts[1].request_id,
        "nothing is ever resent here, so each attempt is its own request"
    );
    assert_eq!(
        (attempts[0].signed_at_ms, attempts[1].signed_at_ms),
        (1_000, 2_000),
        "the caller states the instant, and the service is not left to read a clock of its own"
    );
    assert_eq!(
        attempts[0].expected, None,
        "the first write names no object, because nothing has ever been at the locator"
    );
    assert_eq!(
        attempts[1].expected,
        Some(first.bundle_position()),
        "the second replaces the first write, at the place the service gave it"
    );
}

#[tokio::test]
async fn a_lost_answer_to_a_write_that_landed_is_this_devices_own_bundle_on_the_next_read() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second_writer = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    // The service applies the write and the answer is lost on the way back.
    service.interrupt_the_next_exchange(Interruption::LoseTheAnswerAfterTheWrite);
    let unknown = store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect_err("no answer came back");
    assert!(matches!(
        unknown,
        RecoveryError::BundleOutcomeUnknown { .. }
    ));
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
    assert_eq!(
        bundle.revision.get(),
        0,
        "the caller's bundle is where it was, because this device knows nothing yet"
    );

    // Nothing is retried on its own, and the store will not write again into the dark: a second
    // write would compare against a place the first one may have left, and its refusal would be
    // reported as another device's conflict when it was this device's own write.
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&second_writer),
                TimestampMs::new(1_100),
            )
            .await,
        Err(RecoveryError::BundleWriteUnsettled { .. })
    ));
    assert_eq!(
        service.attempts().len(),
        1,
        "the write was not resent, by this store or by anything under it"
    );

    // The read settles it: what is at the locator is the very bundle this device sent, and a
    // service answers a repeated identity from the receipt it already holds, so that write cannot
    // land a second time.
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(store.lost_write(), Some(LostWrite::Applied));
    assert_eq!(read.revision.get(), 1);
    assert!(
        read.trusted_writers
            .iter()
            .any(|held| held.writer_key_id == writer.key_id())
    );

    // The evidence for the writer that lost write enabled comes from that read, without writing
    // the bundle a second time: the bundle carrying the writer is at the locator, which is the
    // whole of what the declaration rests on.
    let evidence = store
        .writer_enabled(writer.key_id())
        .expect("the bundle at the locator carries the writer");
    assert_eq!(evidence.bundle_revision(), 1);
    assert_eq!(Some(evidence.bundle_position()), store.position());
    assert!(
        store.writer_enabled(second_writer.key_id()).is_none(),
        "and no evidence is offered for a writer the bundle does not carry"
    );

    // And the next write is accepted rather than refused, at the place that lost write took.
    let mut carried = read;
    let enabled = store
        .enable_writer(
            &seed,
            &mut carried,
            trusted(&second_writer),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the next write lands");
    assert_eq!(store.lost_write(), None);
    assert_eq!(enabled.bundle_revision(), 2, "one bundle, moved on once");
    assert_eq!(
        service.position_of(LOCATOR),
        Some(enabled.bundle_position())
    );
    let settled = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(
        settled.trusted_writers.len(),
        2,
        "and neither writer is lost"
    );
    assert!(
        service.fences().is_empty(),
        "a write recognised by reading needs nothing ended"
    );
    assert_eq!(
        service.statuses_asked(),
        0,
        "and this path settles from the bundle rather than from a receipt"
    );
}

#[tokio::test]
async fn a_write_still_on_its_way_is_ended_before_another_goes_out() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let first = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(&seed, &mut bundle, trusted(&first), TimestampMs::new(1_000))
        .await
        .expect("the first bundle commits");

    // The request is held somewhere between this device and the service, so no answer comes back
    // and the service has not executed it either.
    service.interrupt_the_next_exchange(Interruption::LoseTheRequest);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&second),
                TimestampMs::new(2_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    let delayed = service.attempts().pop().expect("the attempt that was held");

    // Reading finds the bundle as it was, and that settles nothing: what is at the locator now
    // says nothing about what a request still on its way will do to it.
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.revision.get(), 1);
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
    let mut carried = read;
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut carried,
                trusted(&second),
                TimestampMs::new(2_500)
            )
            .await,
        Err(RecoveryError::BundleWriteUnsettled { .. })
    ));

    // Ending it is what makes the next write safe. The service is asked to fence the identity, so
    // nothing executes under it from that moment.
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("the fence is made"),
        Some(LostWrite::Ended { retained: None })
    );
    let fences = service.fences();
    assert_eq!(fences.len(), 1);
    assert_eq!(fences[0].collection, LOCATOR);
    assert_eq!(fences[0].request_id, delayed.request_id);
    assert_eq!(
        (fences[0].first_signed_at_ms, fences[0].last_signed_at_ms),
        (2_000, 2_000),
        "one attempt names its own instant twice"
    );

    // The held request arrives afterwards and the fence receipt refuses it outright, so the write
    // that follows is accepted rather than refused by this device's own earlier write.
    let delivered = service
        .deliver_the_delayed_attempt(&delayed)
        .expect_err("a fenced identity executes nothing");
    assert_eq!(delivered.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        service.position_of(LOCATOR),
        Some(at(1)),
        "and the bundle at the locator is untouched by it"
    );
    store
        .enable_writer(
            &seed,
            &mut carried,
            trusted(&second),
            TimestampMs::new(3_000),
        )
        .await
        .expect("the write lands on what is there");
    assert_eq!(store.lost_write(), None);
    assert_eq!(carried.trusted_writers.len(), 2);
    assert_eq!(carried.revision.get(), 2, "one bundle, not two");
    assert_eq!(service.statuses_asked(), 0);
}

#[tokio::test]
async fn a_receipt_older_than_what_this_device_has_read_is_still_this_devices_own_write() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let ours = AuthorisationKeyPair::generate().expect("a writer key");
    let theirs = AuthorisationKeyPair::generate().expect("another writer key");
    let third = AuthorisationKeyPair::generate().expect("a third writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(&seed, &mut bundle, trusted(&ours), TimestampMs::new(1_000))
        .await
        .expect("the first bundle commits");

    // This device's second write applies at the next place and its answer is lost.
    service.interrupt_the_next_exchange(Interruption::LoseTheAnswerAfterTheWrite);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&theirs),
                TimestampMs::new(2_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));

    // Another device writes on top of it, and this one reads that. Its baseline is now past its
    // own lost write, so the receipt of that write is older than what this store knows.
    let mut other = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut ahead = other.fetch(&seed).await.expect("the bundle");
    other
        .enable_writer(&seed, &mut ahead, trusted(&third), TimestampMs::new(2_500))
        .await
        .expect("their write lands");
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.revision.get(), 3);
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));

    // The fence answers with the receipt of a write two places back. That is history and not a
    // service going back, so it settles the write and leaves the newer baseline alone.
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("the fence is made"),
        Some(LostWrite::Applied)
    );
    assert_eq!(store.position(), Some(at(3)));
    let mut carried = read;
    store
        .enable_writer(&seed, &mut carried, trusted(&ours), TimestampMs::new(3_000))
        .await
        .expect("the next write lands on what is there");
    assert_eq!(carried.revision.get(), 4);
}

#[tokio::test]
async fn a_fence_that_cannot_say_nothing_ran_reads_before_the_store_writes_again() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    service.interrupt_the_next_exchange(Interruption::LoseTheAnswerAfterTheWrite);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&writer),
                TimestampMs::new(1_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    let sent = service.attempts().pop().expect("the attempt");

    // The write applied and its receipt has since gone, so the fence can say only that nothing
    // will run from now on. This device's baseline is from before its own applied write, so a
    // commit made on that answer alone would meet that write and be told another device wrote.
    service.sweep_the_receipt_of(sent.request_id);
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("the fence is made"),
        Some(LostWrite::Applied),
        "the read that follows the fence recognises this device's own bundle"
    );
    assert_eq!(store.position(), service.position_of(LOCATOR));

    let mut carried = store.fetch(&seed).await.expect("the bundle");
    store
        .enable_writer(
            &seed,
            &mut carried,
            trusted(&second),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the next write lands rather than conflicting");
    assert_eq!(carried.trusted_writers.len(), 2);
}

#[tokio::test]
async fn a_receipt_and_a_read_that_disagree_under_one_place_in_the_order_are_two_histories() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let other = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    service.interrupt_the_next_exchange(Interruption::LoseTheAnswerAfterTheWrite);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&writer),
                TimestampMs::new(1_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));

    // The service serves other content at the same place in its order. It authenticates, because
    // the owner's key made it, so the read adopts it as the baseline at that place.
    let mut theirs = BundleStore::empty(TimestampMs::new(1));
    theirs.revision = U64::new(1);
    theirs.trusted_writers = [trusted(&other)].into_iter().collect();
    let key = seed
        .bundle_key_for(&context(ORIGIN))
        .expect("the bundle key");
    service.substitute(
        LOCATOR,
        kr_crypto::archive::encrypt_recovery_bundle(&key, &theirs).expect("the ciphertext"),
    );
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.trusted_writers.len(), 1);
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));

    // The receipt then names that same place for a different bundle. One place holds one write for
    // the life of a collection, so this is two histories rather than something to choose between,
    // and the write stays outstanding rather than quietly replacing what was read.
    assert!(matches!(
        store.end_lost_write(&seed).await,
        Err(RecoveryError::BundleHistoryForked { .. })
    ));
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));
}

#[tokio::test]
async fn a_first_write_that_never_arrived_leaves_the_locator_writable_again() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    // Nothing has ever been at the locator, so there is nothing to read: the way out cannot be a
    // read, and it is not.
    service.interrupt_the_next_exchange(Interruption::LoseTheRequest);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&writer),
                TimestampMs::new(1_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    assert!(store.fetch(&seed).await.is_err(), "there is no bundle yet");

    // The service cannot even say that nothing ever ran under the identity, so the fence ends the
    // request and settles nothing about the past. There is no baseline for that to leave stale,
    // because a locator this device has never read anything from has nothing to be behind.
    let sent = service.attempts().pop().expect("the attempt");
    service.sweep_the_receipt_of(sent.request_id);
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("the fence is made"),
        Some(LostWrite::Ended { retained: None })
    );
    let enabled = store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the first bundle commits");
    assert_eq!(enabled.bundle_revision(), 1);
    assert_eq!(
        store.fetch(&seed).await.expect("the bundle").revision.get(),
        1
    );
}

#[tokio::test]
async fn ending_a_write_the_service_had_already_applied_says_so() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));

    service.interrupt_the_next_exchange(Interruption::LoseTheAnswerAfterTheWrite);
    assert!(matches!(
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&writer),
                TimestampMs::new(1_000)
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));

    // A fence finds the receipt of a write the service had already applied and keeps its outcome,
    // so this device learns what happened without reading and without writing again.
    assert_eq!(
        store
            .end_lost_write(&seed)
            .await
            .expect("the fence is made"),
        Some(LostWrite::Applied)
    );
    assert_eq!(store.position(), service.position_of(LOCATOR));
    assert_eq!(
        store
            .writer_enabled(writer.key_id())
            .expect("the write landed")
            .bundle_revision(),
        1
    );

    // And the baseline the fence established is the right one to write against next.
    let mut carried = store.fetch(&seed).await.expect("the bundle");
    store
        .enable_writer(
            &seed,
            &mut carried,
            trusted(&second),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the next write lands");
    assert_eq!(carried.revision.get(), 2);
}

#[tokio::test]
async fn a_position_no_write_of_the_bundle_can_be_at_is_declined_rather_than_read() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // A removal took a place in the order and produced no object, so it is not where a write of
    // the bundle can be. Reading it as one would leave this store comparing its next write against
    // no object while the bundle was there.
    service.next_fetch_answers(SyncPosition::removed_at(2));
    assert!(matches!(
        store.fetch(&seed).await,
        Err(RecoveryError::BundleNotAWrite { found }) if found.is_removal()
    ));

    // Nought is a place nothing occupies, because a place in the order counts from one. It is
    // refused even when the answer names an object, which is the only way to tell this check from
    // the removal check above.
    service.next_fetch_answers(at(0));
    assert!(matches!(
        store.fetch(&seed).await,
        Err(RecoveryError::BundleNotAWrite { found }) if !found.is_removal()
    ));

    // The refusals leave the store where it was, so the bundle is still readable.
    assert_eq!(store.position(), Some(at(1)));
    assert_eq!(
        store.fetch(&seed).await.expect("the bundle").revision.get(),
        1
    );

    // An applied write may not stand still either: every one takes the next place in the order, so
    // a service that answers the place the bundle was already at is saying it wrote and did not
    // write. A read of that same place is ordinary, which is why the two are checked apart.
    service.next_exchange_answers(at(1));
    let refusal = store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a write that did not move the bundle on");
    assert!(matches!(
        refusal,
        RecoveryError::BundleDidNotMoveOn { found } if found == at(1)
    ));
    assert!(
        matches!(store.lost_write(), Some(LostWrite::Unsettled { .. })),
        "an answer this device cannot read leaves the write outstanding, not recorded"
    );
}

#[tokio::test]
async fn a_locator_that_went_back_or_forked_is_refused_rather_than_written_over() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&second),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the second write lands");

    // A write sequence only goes forward, so an answer behind what this device has already read is
    // a service that has gone back rather than news.
    service.next_fetch_answers(at(1));
    assert!(matches!(
        store.fetch(&seed).await,
        Err(RecoveryError::BundleWentBack {
            expected: 2,
            found: 1
        })
    ));

    // And one sequence names one write for the life of a collection, so the same place under
    // another name is two histories: the locator is not the collection this store has been reading.
    let other_history = SyncPosition::at(2, SyncRevision::new(Uuid::from_bytes([0xaa; 16])));
    service.next_fetch_answers(other_history);
    assert!(matches!(
        store.fetch(&seed).await,
        Err(RecoveryError::BundleHistoryForked { found, .. }) if found == other_history
    ));

    // A store that knows nothing reads either of them, which is the owner's way out: read the
    // bundle from a store with no history of its own, and judge what comes back.
    service.next_fetch_answers(other_history);
    let mut fresh = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    assert_eq!(
        fresh.fetch(&seed).await.expect("the bundle").revision.get(),
        2
    );
}

#[tokio::test]
async fn a_second_reading_of_one_place_with_other_content_is_a_fork_rather_than_a_newer_copy() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let other = AuthorisationKeyPair::generate().expect("another writer key");
    let mut writing = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    writing
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // Another device reads the bundle, and reads it again later: a read followed by a read, with
    // no write of its own in between and no lost answer to settle.
    let mut reader = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let first = reader.fetch(&seed).await.expect("the bundle");
    let place = reader.position().expect("the place it was read at");

    // In between, the service starts serving other content under that very place and that very
    // name. It authenticates, because the owner's key made it, so nothing about the bytes or the
    // position gives it away; only holding it against what was read there does.
    let mut other_content = first.clone();
    other_content.trusted_writers = [trusted(&other)].into_iter().collect();
    let key = seed
        .bundle_key_for(&context(ORIGIN))
        .expect("the bundle key");
    service.substitute(
        LOCATOR,
        kr_crypto::archive::encrypt_recovery_bundle(&key, &other_content).expect("the ciphertext"),
    );
    assert_eq!(service.position_of(LOCATOR), Some(place));

    // One place names one content, so the second reading is a fork the reader is told about.
    assert!(matches!(
        reader.fetch(&seed).await,
        Err(RecoveryError::BundleHistoryForked { expected, found })
            if expected == place && found == place
    ));
    // It is not a silent replacement: the reader still holds what it authenticated there, and
    // offers no evidence for a writer only the other content names.
    assert_eq!(reader.position(), Some(place));
    assert!(reader.writer_enabled(writer.key_id()).is_some());
    assert!(reader.writer_enabled(other.key_id()).is_none());
    // Asking again is refused again. A refusal that adopted what it refused would let the same
    // content through on the next read.
    assert!(matches!(
        reader.fetch(&seed).await,
        Err(RecoveryError::BundleHistoryForked { .. })
    ));
    // The device that wrote the bundle holds the same place with the content it committed, and
    // meets the same refusal.
    assert!(matches!(
        writing.fetch(&seed).await,
        Err(RecoveryError::BundleHistoryForked { .. })
    ));

    // A store that knows nothing reads it, which is the owner's way out: read the bundle from a
    // store with no history of its own, and judge what comes back.
    let mut fresh = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    assert_eq!(fresh.fetch(&seed).await.expect("the bundle"), other_content);
}

#[tokio::test]
async fn rotating_a_writers_key_replaces_it_in_one_commit() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let retiring = AuthorisationKeyPair::generate().expect("a writer key");
    let replacement = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&retiring),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the first writer");

    let rotated = store
        .rotate_writer(
            &seed,
            &mut bundle,
            trusted(&replacement),
            TimestampMs::new(2_000),
        )
        .await
        .expect("the rotation commits");
    assert_eq!(rotated.writer_key_id(), replacement.key_id());

    // Both keys are in the bundle. Dropping the rotated-out key would leave every archive it had
    // already signed unverifiable, which would make a rotation destroy the backups it protects.
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.trusted_writers.len(), 2);
    for key in [replacement.key_id(), retiring.key_id()] {
        assert!(
            read.trusted_writers
                .iter()
                .any(|held| held.writer_key_id == key)
        );
    }

    // Retiring it is the separate, deliberate step, taken when no retained archive needs it.
    store
        .retire_writer(
            &seed,
            &mut bundle,
            &retiring.key_id(),
            TimestampMs::new(3_000),
        )
        .await
        .expect("the retirement commits");
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(read.trusted_writers.len(), 1);
    assert!(
        !read
            .trusted_writers
            .iter()
            .any(|held| held.writer_key_id == retiring.key_id())
    );
}

#[tokio::test]
async fn a_verified_generation_never_moves_backwards() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    let newest = ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: Digest256::from_bytes([0xab; 32]),
        verified_at_ms: TimestampMs::new(2),
    };
    store
        .record_checkpoint(&seed, &mut bundle, newest.clone(), TimestampMs::new(1_000))
        .await
        .expect("the checkpoint commits");

    // A verification of an older generation arriving late is a late answer, not a newer fact.
    // Writing it would give a service five generations it could replay unnoticed.
    let late = ArchiveCheckpoint {
        backup_generation: BackupGeneration::new(4),
        ..newest.clone()
    };
    assert!(matches!(
        store
            .record_checkpoint(&seed, &mut bundle, late, TimestampMs::new(2_000))
            .await,
        Err(RecoveryError::CheckpointWentBackwards {
            recorded: 9,
            offered: 4
        })
    ));

    // And the same generation with a different manifest is a substitution, not an update.
    let substituted = ArchiveCheckpoint {
        encrypted_manifest_hash: Digest256::from_bytes([0xcd; 32]),
        ..newest.clone()
    };
    assert!(
        store
            .record_checkpoint(&seed, &mut bundle, substituted, TimestampMs::new(2_000))
            .await
            .is_err()
    );

    // Forward is fine.
    let newer = ArchiveCheckpoint {
        backup_generation: BackupGeneration::new(11),
        ..newest
    };
    store
        .record_checkpoint(&seed, &mut bundle, newer, TimestampMs::new(3_000))
        .await
        .expect("a later generation is recorded");
    let read = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(
        read.checkpoints
            .iter()
            .next()
            .expect("a checkpoint")
            .backup_generation,
        BackupGeneration::new(11)
    );
}

#[test]
fn a_kit_value_whose_spacing_would_change_when_read_is_refused() {
    // Reading trims the line, so a locator that ends in a space would come back a different
    // string, and a different locator derives a different bundle key: the kit would round-trip to
    // something that authenticates nothing.
    let seed = RecoverySeed::generate().expect("a seed");
    let mut kit = seed.to_kit(vec![ORIGIN.to_owned()], "opaque-locator ".to_owned());
    assert!(matches!(
        render_kit(&kit),
        Err(RecoveryError::UnprintableKit { .. })
    ));
    kit.bundle_locator = "opaque-locator".to_owned();
    kit.service_origins = vec![format!(" {ORIGIN}")];
    assert!(matches!(
        render_kit(&kit),
        Err(RecoveryError::UnprintableKit { .. })
    ));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.16 and KR-ACC-033: a restore trusts only bundle-supplied writer keys.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_restore_with_only_the_kit_reaches_the_archive_and_trusts_only_the_bundles_writers() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let recovery = seed.recipient().expect("a recovery recipient");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let producer = StoredEnvelopeKeyPair::generate().expect("a producer key");

    // The owner's bundle names the writer and where the collection lives.
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    bundle.collections.push(CollectionLocator {
        service_origin: ORIGIN.to_owned(),
        locator: "collection-1".to_owned(),
        archive_id: archive_id(),
    });
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    store
        .enable_producer(
            &seed,
            &mut bundle,
            producer.key_id(),
            *producer.public(),
            TimestampMs::new(1_100),
        )
        .await
        .expect("the producer is enrolled");

    // A recovery-enabled collection wraps its manifest key for the recovery recipient.
    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add_recovery(&recovery));
    let staged = stage_object(
        &ObjectSource {
            object_id: BackupObjectId::new(Uuid::from_bytes([0x21; 16])),
            filename: "session-history.cbor",
            plaintext: b"what the session did",
        },
        recipients.rotation(),
    )
    .expect("a staged object");
    let sealed = seal_archive(
        &writer,
        &producer,
        &recipients,
        &ArchivePlan {
            archive_id: archive_id(),
            backup_generation: BackupGeneration::new(4),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            manifest_object_id: BackupObjectId::new(Uuid::from_bytes([0xf0; 16])),
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        std::slice::from_ref(&staged),
    )
    .expect("a sealed archive");

    // A fresh device holds the kit and the ciphertext it can reach, and nothing else. Everything
    // the producer had is dropped here, so anything the restore still needs has to come out of the
    // authenticated bundle.
    let descriptor_bytes = sealed.descriptor_bytes.clone();
    let encrypted_manifest = sealed.encrypted_manifest.clone();
    let object_bytes = staged.bytes().to_vec();
    let member_id = staged.object_id();
    let forged = {
        let impostor = AuthorisationKeyPair::generate().expect("a writer key");
        seal_archive(
            &impostor,
            &producer,
            &recipients,
            &ArchivePlan {
                archive_id: archive_id(),
                backup_generation: BackupGeneration::new(5),
                owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                manifest_object_id: BackupObjectId::new(Uuid::from_bytes([0xf1; 16])),
                created_at_ms: TimestampMs::new(1_700_000_001_000),
            },
            std::slice::from_ref(&staged),
        )
        .expect("a sealed archive")
    };
    drop(producer);
    drop(writer);
    drop(sealed);
    drop(staged);

    // The kit goes through its printed form and back, and the recovery recipient is derived from
    // the seed that came out of it. Nothing of the device that made the archive is still held.
    let printed = render_kit(&kit_of(&seed, &[ORIGIN])).expect("a printable kit");
    drop(recovery);
    drop(seed);
    let kit = parse_kit(&printed).expect("the kit reads back");
    let recovered = RecoverySeed::from_kit(&kit).expect("the seed");
    let recovery = recovered.recipient().expect("a recovery recipient");

    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess {
            policy: RetrievalPolicy::Account,
            service_origin: ORIGIN.to_owned(),
        })
        .expect("the configured policy granted access");
    let material = restore
        .open_bundle(Arc::clone(&service) as Arc<_>, ORIGIN)
        .await
        .expect("the bundle authenticates under the kit");
    assert_eq!(material.trusted_writers.len(), 1);
    assert_eq!(material.collections.len(), 1);

    // The producer's public key comes out of the bundle, keyed by the identifier the descriptor's
    // wrap context names. It cannot come from the descriptor: that carries a hash.
    let descriptor = kr_crypto::backup::read_descriptor(&descriptor_bytes).expect("a descriptor");
    let sender_key_id = descriptor.manifest_key_wraps[0].context.sender_key_id;
    let sender = material
        .producer(sender_key_id)
        .expect("the bundle names the producer")
        .stored_envelope_key;

    let reader = ArchiveReader::Recovery(&recovery);
    let expectation = ArchiveExpectation {
        archive_id: archive_id(),
        generation: material.checkpoint(archive_id()).map_or(
            GenerationExpectation::Unverified,
            |checkpoint| {
                GenerationExpectation::Checkpoint(CheckpointSource::RecoveryBundle, checkpoint)
            },
        ),
    };
    let opened = open_archive(
        &reader,
        &sender,
        &material.trusted_writers,
        &expectation,
        &descriptor_bytes,
        &encrypted_manifest,
    )
    .expect("the archive opens against the bundle's writers");
    let restored = opened
        .restore_object(&reader, &sender, member_id, &object_bytes)
        .expect("the member object restores");
    assert_eq!(restored.plaintext.expose(), b"what the session did");

    // The same archive, re-signed by a writer the bundle does not name, is refused. A restore has
    // no way to take that writer's key from the archive: the trusted set is the bundle's.
    assert!(
        open_archive(
            &reader,
            &sender,
            &material.trusted_writers,
            &expectation,
            &forged.descriptor_bytes,
            &forged.encrypted_manifest,
        )
        .is_err(),
        "an archive signed by a writer the bundle does not name is refused"
    );

    // The bundle's checkpoint is what a recovery-only restore compares the generation against, and
    // it still cannot claim that no newer archive exists.
    let standing = RestoreGeneration::against(
        &descriptor,
        material
            .checkpoint(archive_id())
            .map_or(GenerationExpectation::Unverified, |checkpoint| {
                GenerationExpectation::Checkpoint(CheckpointSource::RecoveryBundle, checkpoint)
            }),
    );
    assert!(standing.describe().contains("generation 4"));
    assert!(!standing.proves_no_newer_archive());
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.19: access is not decryption, and substitution fails authentication.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn service_access_alone_does_not_decrypt_the_bundle() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // A restore that has not been through the retrieval policy has nothing.
    let restore = FreshRestore::new(kit_of(&seed, &[ORIGIN]), RetrievalPolicy::Account);
    assert!(matches!(
        restore
            .open_bundle(Arc::clone(&service) as Arc<_>, ORIGIN)
            .await,
        Err(RecoveryError::NoServiceAccess)
    ));

    // Access granted under another policy than the configured one is not the configured policy.
    let mut restore = FreshRestore::new(kit_of(&seed, &[ORIGIN]), RetrievalPolicy::Account);
    assert!(matches!(
        restore.obtained_access(ServiceAccess {
            policy: RetrievalPolicy::SelfHosted,
            service_origin: ORIGIN.to_owned(),
        }),
        Err(RecoveryError::NoServiceAccess)
    ));

    // And the ciphertext itself, which access does reach, is nothing without the seed.
    let (_, ciphertext) = SyncBackupService::fetch(service.as_ref(), LOCATOR)
        .await
        .expect("access reaches the bytes");
    assert!(!ciphertext.is_empty());
    let another_owner = RecoverySeed::generate().expect("a seed");
    let key = another_owner
        .bundle_key_for(&context(ORIGIN))
        .expect("a key");
    assert!(
        kr_crypto::archive::decrypt_recovery_bundle(&key, &ciphertext).is_err(),
        "the bytes a signed-in caller can fetch open only under the owner's own seed"
    );

    // The seed comes from the kit or from a device's secure store, and from nowhere else.
    assert_eq!(SeedSource::ALL.len(), 2);
    assert!(SeedSource::ALL.contains(&SeedSource::Kit));
    assert!(SeedSource::ALL.contains(&SeedSource::SecureStore));
}

#[tokio::test]
async fn substituting_the_origin_or_the_locator_fails_authentication() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // A kit that names only one origin will not even build a context for another.
    let mut restore = FreshRestore::new(kit_of(&seed, &[ORIGIN]), RetrievalPolicy::Account);
    assert!(matches!(
        restore.obtained_access(ServiceAccess {
            policy: RetrievalPolicy::Account,
            service_origin: OTHER_ORIGIN.to_owned(),
        }),
        Err(RecoveryError::UnknownServiceOrigin)
    ));

    // A kit that names both origins reaches the second one, and the bundle written for the first
    // does not authenticate there: the key is bound to the origin it was written at.
    let both = kit_of(&seed, &[ORIGIN, OTHER_ORIGIN]);
    let mut restore = FreshRestore::new(both, RetrievalPolicy::Account);
    restore
        .obtained_access(ServiceAccess {
            policy: RetrievalPolicy::Account,
            service_origin: OTHER_ORIGIN.to_owned(),
        })
        .expect("access to the second origin");
    assert!(matches!(
        restore
            .open_bundle(Arc::clone(&service) as Arc<_>, OTHER_ORIGIN)
            .await,
        Err(RecoveryError::BundleNotAuthentic)
    ));

    // And a locator substitution: the service serves this bundle under another name.
    let (_, ciphertext) = SyncBackupService::fetch(service.as_ref(), LOCATOR)
        .await
        .expect("the bytes");
    service.substitute("another-locator", ciphertext);
    let elsewhere = RecoveryContext {
        service_origin: ORIGIN.to_owned(),
        bundle_locator: "another-locator".to_owned(),
    };
    let mut moved = BundleStore::new(Arc::clone(&service) as Arc<_>, elsewhere);
    assert!(matches!(
        moved.fetch(&seed).await,
        Err(RecoveryError::BundleNotAuthentic)
    ));
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.18: multiple-service kits, the migration record, and the offline export.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_destination_write_whose_answer_was_lost_is_ended_before_the_migration_is_retried() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // The destination is a store the caller holds, so a write it never gets an answer to is
    // remembered by the thing that made it rather than lost with a temporary one.
    let destination_service = ScriptedService::shared();
    let elsewhere = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let mut destination = BundleStore::new(
        Arc::clone(&destination_service) as Arc<_>,
        elsewhere.clone(),
    );
    destination_service.interrupt_the_next_exchange(Interruption::LoseTheRequest);
    assert!(matches!(
        store
            .migrate(
                &seed,
                &mut bundle,
                &kit_of(&seed, &[ORIGIN]),
                &mut destination,
                TimestampMs::new(2_000),
            )
            .await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    let delayed = destination_service
        .attempts()
        .pop()
        .expect("the attempt that was held");

    // Retrying against the same destination is refused while that write could still land: clearing
    // the object at the destination would not help, because the delayed request would write it
    // again under this migration's nose.
    assert!(matches!(
        store
            .migrate(
                &seed,
                &mut bundle,
                &kit_of(&seed, &[ORIGIN]),
                &mut destination,
                TimestampMs::new(2_500),
            )
            .await,
        Err(RecoveryError::BundleWriteUnsettled { .. })
    ));

    destination
        .end_lost_write(&seed)
        .await
        .expect("the destination is asked to end it");
    assert!(
        destination_service
            .deliver_the_delayed_attempt(&delayed)
            .is_err(),
        "the fenced identity executes nothing at the destination"
    );

    let migrated = store
        .migrate(
            &seed,
            &mut bundle,
            &kit_of(&seed, &[ORIGIN]),
            &mut destination,
            TimestampMs::new(3_000),
        )
        .await
        .expect("the migration lands and reads back");
    assert_eq!(migrated.record.to, elsewhere);
    assert_eq!(
        destination_service.position_of("moved-bundle-locator"),
        Some(migrated.record.bundle_position)
    );

    // One collection answers to one store. The caller holds the destination store and writes
    // through it; this store still names the old location, where the superseded copy stays, and
    // it is not a second handle to the new one.
    assert_eq!(store.context().service_origin, ORIGIN);
    destination
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(4_000),
        )
        .await
        .expect("the destination store is the one that writes there now");
    assert_eq!(
        destination_service.position_of("moved-bundle-locator"),
        destination.position()
    );
}

#[tokio::test]
async fn a_migration_into_a_destination_that_already_holds_a_bundle_writes_nothing_there() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let other = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // Somebody else's bundle is already at the destination, under this seed's key there and at the
    // same revision as the one being moved. Nothing the migration compares would tell the two
    // apart: the destination's own token matches, and a read back after the write would return
    // what the write had just put there.
    let destination_service = ScriptedService::shared();
    let elsewhere = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let mut theirs = BundleStore::empty(TimestampMs::new(1));
    theirs.revision = bundle.revision;
    theirs.trusted_writers = [trusted(&other)].into_iter().collect();
    let key = seed.bundle_key_for(&elsewhere).expect("the bundle key");
    destination_service.substitute(
        "moved-bundle-locator",
        kr_crypto::archive::encrypt_recovery_bundle(&key, &theirs).expect("the ciphertext"),
    );
    let mut destination = BundleStore::new(
        Arc::clone(&destination_service) as Arc<_>,
        elsewhere.clone(),
    );
    let read = destination
        .fetch(&seed)
        .await
        .expect("the bundle that is there");
    assert_eq!(read.revision, bundle.revision);
    let occupied_at = destination_service.position_of("moved-bundle-locator");

    // The source holds the bundle the caller holds, so the migration reaches the destination
    // rather than stopping at a comparison of the old location.
    assert!(matches!(
        store
            .migrate(
                &seed,
                &mut bundle,
                &kit_of(&seed, &[ORIGIN]),
                &mut destination,
                TimestampMs::new(2_000),
            )
            .await,
        Err(RecoveryError::DestinationHoldsABundle)
    ));

    // What is there is what was there, at the place it was: a bundle is the only thing a restore
    // takes a writer key from, so replacing one would take its archives with it.
    let mut reader = BundleStore::new(Arc::clone(&destination_service) as Arc<_>, elsewhere);
    assert_eq!(
        reader
            .fetch(&seed)
            .await
            .expect("the bundle that is still there"),
        theirs
    );
    assert_eq!(
        destination_service.position_of("moved-bundle-locator"),
        occupied_at
    );
}

#[tokio::test]
async fn a_migration_produces_an_updated_kit_and_a_verified_record() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    let kit = kit_of(&seed, &[ORIGIN]);
    // A different service, because migrating to another origin means writing somewhere else: a
    // migration that wrote back to the service it was leaving would verify the wrong thing.
    let destination_service = ScriptedService::shared();
    let destination = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let migrated = store
        .migrate(
            &seed,
            &mut bundle,
            &kit,
            &mut BundleStore::new(
                Arc::clone(&destination_service) as Arc<_>,
                destination.clone(),
            ),
            TimestampMs::new(3_000),
        )
        .await
        .expect("the bundle moves and reads back there");

    assert_eq!(migrated.record.from, context(ORIGIN));
    assert_eq!(migrated.record.to, destination);
    assert_eq!(migrated.record.verified_at_ms, TimestampMs::new(3_000));
    assert_eq!(migrated.record.bundle_revision, bundle.revision.get());

    // The updated kit is explicit: it points at the new origin and the new locator, and the old
    // one does not.
    assert_eq!(migrated.updated_kit.service_origins, vec![OTHER_ORIGIN]);
    assert_eq!(migrated.updated_kit.bundle_locator, "moved-bundle-locator");
    assert_eq!(migrated.updated_kit.seed.expose(), kit.seed.expose());
    let document = render_kit(&migrated.updated_kit).expect("the updated kit prints");
    assert!(document.contains(OTHER_ORIGIN));
    assert!(!document.contains(ORIGIN));

    // A restore with the updated kit reads the bundle at the new location.
    let mut restore = FreshRestore::new(migrated.updated_kit.clone(), RetrievalPolicy::SelfHosted);
    restore
        .obtained_access(ServiceAccess {
            policy: RetrievalPolicy::SelfHosted,
            service_origin: OTHER_ORIGIN.to_owned(),
        })
        .expect("access to the new origin");
    let material = restore
        .open_bundle(Arc::clone(&destination_service) as Arc<_>, OTHER_ORIGIN)
        .await
        .expect("the bundle authenticates at its new home");
    assert_eq!(material.trusted_writers.len(), 1);

    // The old kit still opens what was left at the old location, and what it opens is the bundle
    // as it was before the move. This seam publishes and fetches; it does not delete, and removing
    // the superseded object is the service's own operation. The record says exactly that, so an
    // owner is told to destroy the old kit rather than left to find out.
    let mut stale = FreshRestore::new(kit, RetrievalPolicy::SelfHosted);
    stale
        .obtained_access(ServiceAccess {
            policy: RetrievalPolicy::SelfHosted,
            service_origin: ORIGIN.to_owned(),
        })
        .expect("access to the old origin");
    let superseded = stale
        .open_bundle(Arc::clone(&service) as Arc<_>, ORIGIN)
        .await
        .expect("the copy left behind still opens under the old kit");
    assert!(
        superseded.bundle_revision < material.bundle_revision,
        "what the old kit opens is the bundle as it was before the move"
    );
    let sentence = migrated.record.describe();
    assert!(sentence.contains("destroy the old one"));
    assert!(sentence.contains(ORIGIN));
    assert!(sentence.contains(OTHER_ORIGIN));
}

#[tokio::test]
async fn migrating_a_kit_with_several_origins_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    let kit = kit_of(&seed, &[ORIGIN, OTHER_ORIGIN]);
    let destination_service = ScriptedService::shared();
    let destination = RecoveryContext {
        service_origin: "https://third.example".to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let err = store
        .migrate(
            &seed,
            &mut bundle,
            &kit,
            &mut BundleStore::new(destination_service.clone() as Arc<_>, destination),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a kit naming multiple origins cannot be migrated one service at a time");
    assert!(matches!(
        err,
        RecoveryError::MigrationWouldLoseAnOrigin { origins: 2 }
    ));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty(),
        "refused migration must not touch destination service"
    );
}

#[tokio::test]
async fn migrating_a_kit_with_mismatched_context_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // The kit points to a different locator than the store was opened for.
    let kit = RecoverySeed::to_kit(
        &seed,
        vec![ORIGIN.to_owned()],
        "completely-different-locator".to_owned(),
    );
    let destination_service = ScriptedService::shared();
    let destination = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let err = store
        .migrate(
            &seed,
            &mut bundle,
            &kit,
            &mut BundleStore::new(destination_service.clone() as Arc<_>, destination),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a kit pointing to another locator is refused");
    // The caller's kit is wrong, and nothing was fetched: saying an authentication failed would be
    // saying something that never happened.
    assert!(matches!(err, RecoveryError::KitLocatorMismatch));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty()
    );
}

#[tokio::test]
async fn migrating_a_bundle_whose_revision_moved_on_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    let kit = kit_of(&seed, &[ORIGIN]);
    let destination_service = ScriptedService::shared();
    let destination = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    let mut stale_bundle = bundle.clone();
    stale_bundle.revision = U64::new(99);
    let err = store
        .migrate(
            &seed,
            &mut stale_bundle,
            &kit,
            &mut BundleStore::new(destination_service as Arc<_>, destination),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a bundle whose revision differs from held is refused");
    assert!(matches!(err, RecoveryError::BundleConflict { .. }));
}

#[tokio::test]
async fn one_kit_serves_several_services() {
    let first = ScriptedService::shared();
    let second = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");

    // The same bundle is written at both origins, each under its own derived key.
    for (service, origin) in [
        (Arc::clone(&first), ORIGIN),
        (Arc::clone(&second), OTHER_ORIGIN),
    ] {
        let mut store = BundleStore::new(service as Arc<_>, context(origin));
        let mut bundle = BundleStore::empty(TimestampMs::new(1));
        store
            .enable_writer(
                &seed,
                &mut bundle,
                trusted(&writer),
                TimestampMs::new(1_000),
            )
            .await
            .expect("the bundle commits");
    }

    let kit = kit_of(&seed, &[ORIGIN, OTHER_ORIGIN]);
    for (service, origin) in [
        (Arc::clone(&first), ORIGIN),
        (Arc::clone(&second), OTHER_ORIGIN),
    ] {
        let mut restore = FreshRestore::new(kit.clone(), RetrievalPolicy::Account);
        restore
            .obtained_access(ServiceAccess {
                policy: RetrievalPolicy::Account,
                service_origin: origin.to_owned(),
            })
            .expect("access");
        let material = restore
            .open_bundle(service as Arc<_>, origin)
            .await
            .expect("the kit opens the bundle at each service it names");
        assert_eq!(material.context.service_origin, origin);
        assert_eq!(material.trusted_writers.len(), 1);
    }

    // A third origin the kit does not name is refused before anything is fetched.
    let mut restore = FreshRestore::new(kit, RetrievalPolicy::Account);
    assert!(matches!(
        restore.obtained_access(ServiceAccess {
            policy: RetrievalPolicy::Account,
            service_origin: "https://not-in-the-kit.example".to_owned(),
        }),
        Err(RecoveryError::UnknownServiceOrigin)
    ));
}

#[tokio::test]
async fn the_encrypted_bundle_and_selected_archives_export_offline() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let producer = StoredEnvelopeKeyPair::generate().expect("a producer key");
    let recovery = seed.recipient().expect("a recovery recipient");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    store
        .enable_producer(
            &seed,
            &mut bundle,
            producer.key_id(),
            *producer.public(),
            TimestampMs::new(1_100),
        )
        .await
        .expect("the producer is enrolled");

    let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
    assert!(recipients.add_recovery(&recovery));
    let staged = stage_object(
        &ObjectSource {
            object_id: BackupObjectId::new(Uuid::from_bytes([0x21; 16])),
            filename: "notes.cbor",
            plaintext: b"kept offline",
        },
        recipients.rotation(),
    )
    .expect("a staged object");
    let sealed = seal_archive(
        &writer,
        &producer,
        &recipients,
        &ArchivePlan {
            archive_id: archive_id(),
            backup_generation: BackupGeneration::new(2),
            owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
            manifest_object_id: BackupObjectId::new(Uuid::from_bytes([0xf0; 16])),
            created_at_ms: TimestampMs::new(1_700_000_000_000),
        },
        std::slice::from_ref(&staged),
    )
    .expect("a sealed archive");

    // The export is ciphertext and nothing else: the encrypted bundle as the service holds it, and
    // the selected archive's own bytes.
    let (_, encrypted_bundle) = SyncBackupService::fetch(service.as_ref(), LOCATOR)
        .await
        .expect("the encrypted bundle");
    let export = OfflineExport::new(
        encrypted_bundle,
        sealed.descriptor_bytes.clone(),
        sealed.encrypted_manifest.clone(),
        vec![staged.bytes().to_vec()],
    );
    let bytes = export.to_canonical_bytes().expect("canonical bytes");
    assert!(
        !contains(&bytes, b"notes.cbor"),
        "an offline export carries no filename in the clear"
    );

    // Read back with nothing but the kit and the export, no service in sight.
    let restored = OfflineExport::from_canonical_slice(&bytes).expect("the export");
    let key = seed.bundle_key_for(&context(ORIGIN)).expect("a key");
    let offline_bundle =
        kr_crypto::archive::decrypt_recovery_bundle(&key, restored.encrypted_bundle.as_slice())
            .expect("the bundle opens offline");
    let writers: Vec<TrustedWriter> = offline_bundle.trusted_writers.iter().cloned().collect();
    // The producer key comes out of the exported bundle, not out of anything the restoring device
    // was handed: the export is the encrypted bundle and the archive's own ciphertext.
    let descriptor =
        kr_crypto::backup::read_descriptor(restored.descriptor.as_slice()).expect("a descriptor");
    let sender = offline_bundle
        .trusted_producers
        .iter()
        .find(|held| held.sender_key_id == descriptor.manifest_key_wraps[0].context.sender_key_id)
        .expect("the bundle names the producer")
        .stored_envelope_key;
    let reader = ArchiveReader::Recovery(&recovery);
    let opened = open_archive(
        &reader,
        &sender,
        &writers,
        &ArchiveExpectation {
            archive_id: archive_id(),
            generation: GenerationExpectation::Unverified,
        },
        restored.descriptor.as_slice(),
        restored.encrypted_manifest.as_slice(),
    )
    .expect("the exported archive opens");
    let object = opened
        .restore_object(
            &reader,
            &sender,
            staged.object_id(),
            restored.objects[0].as_slice(),
        )
        .expect("the exported object restores");
    assert_eq!(object.plaintext.expose(), b"kept offline");
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-20.17: what a backup carries, what a restore puts back, and what neither does.
// ---------------------------------------------------------------------------------------------

/// The table's answers. It is the decision an export or import path acts on, not a gate over
/// bytes: the archive layer carries opaque objects, and what closes section 20 ¶11 is each path
/// asking for every kind it carries.
#[test]
fn the_material_table_refuses_a_reusable_key_and_a_revoked_grant() {
    for allowed in [
        Material::SessionData,
        Material::DeviceConfiguration,
        Material::BackupGenerationCheckpoint,
        Material::Grant { revoked: false },
    ] {
        assert_eq!(may_back_up(allowed), Admission::Allowed, "{allowed:?}");
        assert_eq!(may_restore(allowed), Admission::Allowed, "{allowed:?}");
    }

    for refused in [
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::RecoverySeed,
        Material::HostGrantAuthority,
    ] {
        assert!(
            !may_back_up(refused).is_allowed(),
            "{refused:?} is never backed up"
        );
        assert!(
            !may_restore(refused).is_allowed(),
            "{refused:?} is never restored"
        );
    }

    // A grant that was revoked is backed up as a record and never restored as access.
    assert_eq!(
        may_back_up(Material::Grant { revoked: true }),
        Admission::Allowed
    );
    assert!(!may_restore(Material::Grant { revoked: true }).is_allowed());
}

#[test]
fn the_admitted_set_is_data_and_configuration_and_the_limits_still_require_owner_pairing() {
    let admitted = FreshRestore::admits(&[
        Material::SessionData,
        Material::DeviceConfiguration,
        Material::BackupGenerationCheckpoint,
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ]);
    assert_eq!(admitted.restored.len(), 3);
    assert!(admitted.restored.contains(&Material::SessionData));
    assert!(admitted.restored.contains(&Material::DeviceConfiguration));

    for refused in [
        Material::EndpointPrivateKey,
        Material::ControlSigningPrivateKey,
        Material::NotificationPreviewPrivateKey,
        Material::Grant { revoked: true },
        Material::HostGrantAuthority,
    ] {
        assert!(admitted.refused_kind(refused), "{refused:?} is refused");
    }
    // Every refusal says why, so a person is told rather than left with a gap.
    for (_, because) in &admitted.refused {
        assert!(!because.is_empty());
    }

    assert!(admitted.limits.requires_fresh_owner_authorised_pairing());
    assert!(!admitted.limits.creates_remote_control_authority());
    assert!(RestoreLimits.describe().contains("pair it with the host"));
}

#[test]
fn a_checkpoint_the_bundle_carries_is_the_one_a_restore_compares_against() {
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    bundle.checkpoints = [ArchiveCheckpoint {
        archive_id: archive_id(),
        backup_generation: BackupGeneration::new(9),
        encrypted_manifest_hash: Digest256::from_bytes([0xab; 32]),
        verified_at_ms: TimestampMs::new(2),
    }]
    .into_iter()
    .collect();
    let material = kr_client::recovery::TrustedMaterial {
        context: context(ORIGIN),
        trusted_writers: Vec::new(),
        trusted_producers: Vec::new(),
        collections: Vec::new(),
        checkpoints: bundle.checkpoints.iter().cloned().collect(),
        bundle_revision: bundle.revision.get(),
    };
    assert_eq!(
        material
            .checkpoint(archive_id())
            .expect("a checkpoint")
            .backup_generation,
        BackupGeneration::new(9)
    );
    assert!(
        material
            .checkpoint(ArchiveId::new(Uuid::from_bytes([0x99; 16])))
            .is_none()
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// A destination that takes a write and then serves something else back.
///
/// It is the one failure a migration cannot check before it writes, so it is the one the caller
/// has to be left able to recover from.
#[derive(Debug, Default)]
struct ForgetfulService {
    write_sequence: Mutex<u64>,
}

impl SyncBackupService for ForgetfulService {
    fn compare_exchange<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _signed_at_ms: u64,
        _expected: Option<SyncPosition>,
        _ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            let mut write_sequence = self.write_sequence.lock().expect("the order");
            *write_sequence += 1;
            Ok(SyncExchanged::Applied {
                position: at(*write_sequence),
            })
        })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async move { Ok(SyncRequestStatus::Unknown) })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move { Ok(SyncRequestFence::Fenced { never_ran: true }) })
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, (SyncPosition, Vec<u8>)> {
        Box::pin(async move {
            let write_sequence = *self.write_sequence.lock().expect("the order");
            Ok((at(write_sequence), vec![0u8; 64]))
        })
    }

    /// Nothing to drop: this destination refuses nothing, so it keeps no copy a resolution could
    /// name.
    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async move { Ok(false) })
    }
}

#[tokio::test]
async fn migrating_a_kit_that_belongs_to_another_seed_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let other = RecoverySeed::generate().expect("another seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // The kit names the right origin and the right locator, and belongs to another recovery
    // authority. The updated kit is built from the seed, so accepting this one would hand back a
    // kit that opens nothing the owner's archives were wrapped for.
    let kit = kit_of(&other, &[ORIGIN]);
    let destination_service = ScriptedService::shared();
    let err = store
        .migrate(
            &seed,
            &mut bundle,
            &kit,
            &mut BundleStore::new(
                Arc::clone(&destination_service) as Arc<_>,
                RecoveryContext {
                    service_origin: OTHER_ORIGIN.to_owned(),
                    bundle_locator: "moved-bundle-locator".to_owned(),
                },
            ),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a kit for another seed is refused");
    assert!(matches!(err, RecoveryError::KitIsForAnotherSeed));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty(),
        "nothing is written at the destination"
    );
}

#[tokio::test]
async fn migrating_a_kit_this_build_cannot_read_is_refused_before_anything_is_written() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    let destination = RecoveryContext {
        service_origin: OTHER_ORIGIN.to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    };
    for broken in [
        RecoveryKit {
            profile_version: U64::new(2),
            ..kit_of(&seed, &[ORIGIN])
        },
        RecoveryKit {
            seed_checksum: kr_protocol::scalars::Bytes::new(vec![0, 0, 0, 0]),
            ..kit_of(&seed, &[ORIGIN])
        },
    ] {
        let destination_service = ScriptedService::shared();
        let err = store
            .migrate(
                &seed,
                &mut bundle,
                &broken,
                &mut BundleStore::new(
                    Arc::clone(&destination_service) as Arc<_>,
                    destination.clone(),
                ),
                TimestampMs::new(2_000),
            )
            .await
            .expect_err("a kit this build cannot read is refused");
        assert!(matches!(err, RecoveryError::Crypto(_)));
        assert!(
            destination_service
                .collections
                .lock()
                .expect("store")
                .is_empty(),
            "nothing is written at the destination"
        );
    }
}

#[tokio::test]
async fn migrating_a_bundle_another_device_has_written_since_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second_writer = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // Another device enrols a second writer at the same locator. This store's snapshot is now one
    // revision behind, and moving it would take the new writer's enrolment off the bundle.
    let mut elsewhere = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut theirs = elsewhere.fetch(&seed).await.expect("they read it");
    elsewhere
        .enable_writer(
            &seed,
            &mut theirs,
            trusted(&second_writer),
            TimestampMs::new(1_500),
        )
        .await
        .expect("their commit lands");

    let destination_service = ScriptedService::shared();
    let err = store
        .migrate(
            &seed,
            &mut bundle,
            &kit_of(&seed, &[ORIGIN]),
            &mut BundleStore::new(
                Arc::clone(&destination_service) as Arc<_>,
                RecoveryContext {
                    service_origin: OTHER_ORIGIN.to_owned(),
                    bundle_locator: "moved-bundle-locator".to_owned(),
                },
            ),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a snapshot from before somebody else's write is refused");
    assert!(matches!(err, RecoveryError::BundleConflict { .. }));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty(),
        "nothing is written at the destination"
    );
}

#[tokio::test]
async fn a_migration_that_does_not_read_back_leaves_the_caller_holding_what_it_had() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    let before = bundle.clone();

    let err = store
        .migrate(
            &seed,
            &mut bundle,
            &kit_of(&seed, &[ORIGIN]),
            &mut BundleStore::new(
                Arc::new(ForgetfulService::default()) as Arc<_>,
                RecoveryContext {
                    service_origin: OTHER_ORIGIN.to_owned(),
                    bundle_locator: "moved-bundle-locator".to_owned(),
                },
            ),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a migration that cannot be read back is not a migration");
    assert!(matches!(err, RecoveryError::BundleNotAuthentic));

    // The caller still holds the bundle at the old location, so reading it again and trying once
    // more is a retry rather than a revision it can never commit.
    assert_eq!(bundle, before);
    assert_eq!(store.context(), &context(ORIGIN));
    let still_there = store
        .fetch(&seed)
        .await
        .expect("the old location is intact");
    assert_eq!(still_there, before);
}

#[tokio::test]
async fn migrating_a_bundle_the_service_serves_older_than_this_device_knows_is_refused() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let second_writer = AuthorisationKeyPair::generate().expect("another writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");
    let superseded = bundle.clone();
    let replayed = service
        .collections
        .lock()
        .expect("store")
        .get(LOCATOR)
        .expect("the bundle is there")
        .ciphertext
        .clone();

    // A second writer is enrolled, so this device knows the bundle has moved to revision 2.
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&second_writer),
            TimestampMs::new(1_500),
        )
        .await
        .expect("the second commit lands");

    // The service now serves the first revision's ciphertext again, as a write of its own at the
    // next place. It authenticates, because the owner wrote it; authentication says who could have
    // written it and never how long ago, and the place moving on says nothing either. The revision
    // inside is what gives it away.
    service.republish(LOCATOR, replayed);
    let destination_service = ScriptedService::shared();
    let mut stale = superseded;
    let err = store
        .migrate(
            &seed,
            &mut stale,
            &kit_of(&seed, &[ORIGIN]),
            &mut BundleStore::new(
                Arc::clone(&destination_service) as Arc<_>,
                RecoveryContext {
                    service_origin: OTHER_ORIGIN.to_owned(),
                    bundle_locator: "moved-bundle-locator".to_owned(),
                },
            ),
            TimestampMs::new(2_000),
        )
        .await
        .expect_err("a source that has gone backwards is a conflict");
    assert!(matches!(err, RecoveryError::BundleConflict { .. }));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty(),
        "the second writer is not dropped by a replay"
    );

    // And the refusal does not become the baseline for the next attempt. A store that adopted the
    // replayed bundle would let the very thing it had just refused through a second time.
    let again = store
        .migrate(
            &seed,
            &mut stale,
            &kit_of(&seed, &[ORIGIN]),
            &mut BundleStore::new(
                Arc::clone(&destination_service) as Arc<_>,
                RecoveryContext {
                    service_origin: OTHER_ORIGIN.to_owned(),
                    bundle_locator: "moved-bundle-locator".to_owned(),
                },
            ),
            TimestampMs::new(2_500),
        )
        .await
        .expect_err("the replay is still refused");
    assert!(matches!(again, RecoveryError::BundleConflict { .. }));
    assert!(
        destination_service
            .collections
            .lock()
            .expect("store")
            .is_empty()
    );
}

#[tokio::test]
async fn migrating_to_a_destination_whose_kit_cannot_be_kept_is_refused_before_the_write() {
    let service = ScriptedService::shared();
    let seed = RecoverySeed::generate().expect("a seed");
    let writer = AuthorisationKeyPair::generate().expect("a writer key");
    let mut store = BundleStore::new(Arc::clone(&service) as Arc<_>, context(ORIGIN));
    let mut bundle = BundleStore::empty(TimestampMs::new(1));
    store
        .enable_writer(
            &seed,
            &mut bundle,
            trusted(&writer),
            TimestampMs::new(1_000),
        )
        .await
        .expect("the bundle commits");

    // A locator a line-oriented document cannot hold, and one that would not fit a scannable code.
    // A migration that wrote first would leave the bundle somewhere its owner has no kit for.
    for locator in [
        "moved\nbundle\tlocator".to_owned(),
        "m".repeat(MAX_RECOVERY_KIT_BYTES),
    ] {
        let destination_service = ScriptedService::shared();
        let err = store
            .migrate(
                &seed,
                &mut bundle,
                &kit_of(&seed, &[ORIGIN]),
                &mut BundleStore::new(
                    Arc::clone(&destination_service) as Arc<_>,
                    RecoveryContext {
                        service_origin: OTHER_ORIGIN.to_owned(),
                        bundle_locator: locator,
                    },
                ),
                TimestampMs::new(2_000),
            )
            .await
            .expect_err("a destination whose kit cannot be kept is refused");
        assert!(matches!(
            err,
            RecoveryError::UnprintableKit { .. } | RecoveryError::KitTooLarge { .. }
        ));
        assert!(
            destination_service
                .collections
                .lock()
                .expect("store")
                .is_empty(),
            "nothing is written at the destination"
        );
    }
}
