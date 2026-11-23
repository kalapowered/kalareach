//! The device's settings as one member of the recovery bundle.
//!
//! KR-REQ-20.17, KR-REQ-18.05, KR-REQ-20.15: what the member carries and how it is bounded, how it
//! is written and removed through the bundle's own compare-and-swap, and how a restore with the kit
//! alone, from a service or from an export file, reads it. Nothing here talks to a real service:
//! the seam is [`SyncBackupService`], and the one below keeps the one bundle a test needs.
//!
//! | Case | What it shows |
//! | --- | --- |
//! | `the_member_is_padded_to_a_1_kib_bucket_and_holds_only_what_it_was_given` | the member's bucket and its contents |
//! | `a_member_that_cannot_be_written_or_read_is_unusable_settings` | the cap, a garbage member, a bad name |
//! | `a_bundle_that_opened_and_cannot_be_read_says_what_it_needs` | the error for a bundle written by a later build |
//! | `a_settings_write_that_would_leave_less_room_than_the_trust_entries_need_is_refused` | the room a settings write leaves |
//! | `a_trust_write_that_would_not_fit_with_the_settings_is_written_without_them` | who wins near the bound |
//! | `a_migration_whose_destination_left_the_settings_out_for_want_of_room_is_completed` | a move that lost the member to the bound still completes |
//! | `a_changed_setting_is_written_once_and_an_unchanged_one_is_not_written` | the comparison before a write |
//! | `an_unreadable_settings_file_keeps_the_member_the_bundle_holds` | an absent choice and an unreadable file |
//! | `a_save_reads_the_bundle_again_after_it_moved_three_times_in_all` | the save's three reads and the conflict after them |
//! | `a_valid_member_over_the_cap_is_refused_at_the_read_and_one_at_the_cap_is_read` | the cap at the read |
//! | `clearing_the_member_from_a_bundle_with_little_room_is_written_as_a_trust_write` | a clear makes room |
//! | `a_removal_that_meets_a_bundle_which_moved_is_a_conflict_and_removes_nothing` | a removal that meets another write |
//! | `removing_the_member_leaves_collections_keys_and_checkpoints_byte_for_byte` | the removal by its own compare-and-swap |
//! | `a_removal_whose_answer_is_lost_stays_unconfirmed_until_it_is_ended` | an unconfirmed removal stays visible |
//! | `a_restore_with_only_the_kit_returns_the_settings_member_and_nothing_that_grants` | the restore from a service |
//! | `a_bundle_with_no_settings_member_restores_no_settings_and_says_so` | a bundle from before the member |
//! | `a_restore_from_an_export_file_returns_the_settings_with_no_account_and_no_network` | the restore from a file |
//! | `a_settings_member_that_no_build_can_read_fails_only_the_settings_restore` | what a bad member leaves alone |
//! | `the_member_and_the_settings_a_restore_returns_hold_none_of_the_private_keys_the_device_keeps` | the key scan |

use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::recovery::{
    ArchiveEntries, BundleStore, DeviceSettings, ExportSource, FilesRestore, FreshRestore,
    LocalSettings, LostWrite, MAX_DEVICE_SETTINGS_BYTES, OfflineExport, RecoveryError,
    RestoreError, RestoreSource, RetrievalPolicy, SavedSettings, ServiceAccess, SettingsRemoval,
    SettingsSaved, SourceService, SourceSignIn, TRUST_ROOM_BYTES, advance_checkpoint,
    decode_member, encode_member,
};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::SettingValue;
use kr_crypto::kdf::RecoverySeed;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::archive::{CollectionLocator, RecoveryBundle, RecoveryContext};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ArchiveId;
use kr_protocol::scalars::{Bytes, TimestampMs, U64, Uuid};
use kr_protocol::sync::MAX_SEALED_RECOVERY_BUNDLE_BYTES;

const ORIGIN: &str = "https://reach.kala.to";
const LOCATOR: &str = "0b7f1c0d-2a3b-4c5d-8e6f-7a8b9c0d1e2f";

/// The position this service gives the nth write.
fn at(write_sequence: u64) -> SyncPosition {
    SyncPosition::at(
        write_sequence,
        SyncRevision::new(Uuid::from_bytes([write_sequence as u8; 16])),
        None,
    )
}

/// One bundle's worth of bytes and a place in the order.
#[derive(Debug, Default)]
struct MemoryBundles {
    held: Mutex<Option<(u64, Vec<u8>)>>,
    /// Whether the next write applies and its answer never comes back.
    loses_the_next_answer: Mutex<bool>,
    /// Whether the next write never reaches the service.
    drops_the_next_request: Mutex<bool>,
    /// Where each applied request landed, as a receipt.
    receipts: Mutex<std::collections::BTreeMap<Uuid, SyncPosition>>,
    /// How many more fetches another writer's write follows at once, which moves the bundle on to
    /// the next place before the fetcher writes.
    moves_after_a_fetch: Mutex<u32>,
}

impl MemoryBundles {
    fn put(&self, ciphertext: Vec<u8>) {
        let mut held = self.held.lock().expect("the bundle");
        let next = held.as_ref().map_or(1, |(place, _)| place + 1);
        *held = Some((next, ciphertext));
    }

    fn sealed(&self) -> Vec<u8> {
        self.held
            .lock()
            .expect("the bundle")
            .as_ref()
            .expect("a bundle is held")
            .1
            .clone()
    }
}

fn unsupported() -> ClientError {
    ClientError::refusal(
        ErrorCode::UnsupportedCapability,
        kr_client::shown::Shown::said("this service keeps one bundle and nothing else"),
    )
}

impl SyncBackupService for MemoryBundles {
    fn compare_exchange<'a>(
        &'a self,
        _collection: &'a str,
        request_id: Uuid,
        _signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
            if std::mem::take(&mut *self.drops_the_next_request.lock().expect("a flag")) {
                return Err(unsupported());
            }
            let mut held = self.held.lock().expect("the bundle");
            let current = held.as_ref().map(|(place, _)| at(*place));
            if current != expected {
                return Ok(SyncExchanged::Refused {
                    retained: None,
                    current,
                    recovery: None,
                });
            }
            let next = held.as_ref().map_or(1, |(place, _)| place + 1);
            *held = Some((next, ciphertext.to_vec()));
            self.receipts
                .lock()
                .expect("the receipts")
                .insert(request_id, at(next));
            if std::mem::take(&mut *self.loses_the_next_answer.lock().expect("a flag")) {
                return Err(unsupported());
            }
            Ok(SyncExchanged::Applied { position: at(next) })
        })
    }

    fn request_status<'a>(
        &'a self,
        _collection: &'a str,
        _request_id: Uuid,
    ) -> ServiceFuture<'a, SyncRequestStatus> {
        Box::pin(async { Err(unsupported()) })
    }

    fn fence_request<'a>(
        &'a self,
        _collection: &'a str,
        request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async move {
            Ok(
                match self.receipts.lock().expect("the receipts").get(&request_id) {
                    Some(position) => SyncRequestFence::Applied {
                        position: *position,
                    },
                    None => SyncRequestFence::Fenced {
                        never_ran: true,
                        recovery: None,
                    },
                },
            )
        })
    }

    fn fetch<'a>(&'a self, _collection: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            let mut held = self.held.lock().expect("the bundle");
            let answer = match held.as_ref() {
                Some((place, ciphertext)) => SyncFetched::Held {
                    position: at(*place),
                    ciphertext: ciphertext.clone(),
                },
                None => SyncFetched::Absent { recovery: None },
            };
            let mut moves = self.moves_after_a_fetch.lock().expect("a count");
            if *moves > 0 {
                *moves -= 1;
                if let Some((place, _)) = held.as_mut() {
                    *place += 1;
                }
            }
            Ok(answer)
        })
    }

    fn resolve<'a>(
        &'a self,
        _collection: &'a str,
        _retained: kr_protocol::ids::SyncConflictId,
    ) -> ServiceFuture<'a, bool> {
        Box::pin(async { Ok(false) })
    }
}

fn context() -> RecoveryContext {
    RecoveryContext {
        service_origin: ORIGIN.to_owned(),
        bundle_locator: LOCATOR.to_owned(),
    }
}

/// A bundle store over a fresh service, and the directory its write record lives in.
fn store_over(service: &Arc<MemoryBundles>) -> (BundleStore, tempfile::TempDir) {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let store = BundleStore::open(
        Arc::clone(service) as Arc<dyn SyncBackupService>,
        context(),
        directory.path(),
    )
    .expect("the bundle store");
    (store, directory)
}

fn colour(mode: &str) -> DeviceSettings {
    DeviceSettings::new(
        [(
            "colour_mode".to_owned(),
            SettingValue::Text(mode.to_owned()),
        )]
        .into_iter()
        .collect(),
    )
    .expect("settings")
}

fn now() -> TimestampMs {
    TimestampMs::new(1_767_225_600_000)
}

/// KR-REQ-20.17: the member is a whole number of 1 KiB buckets, so the colour modes "dark", "light"
/// and "system" are not told apart by length, and it holds the values it was given and nothing
/// else: no name beside `values` and `pad`, no key, no identifier.
#[test]
fn the_member_is_padded_to_a_1_kib_bucket_and_holds_only_what_it_was_given() {
    let lengths: Vec<usize> = ["dark", "light", "system"]
        .into_iter()
        .map(|mode| {
            let member = encode_member(&colour(mode)).expect("a member");
            assert_eq!(
                member.as_slice().len() % 1024,
                0,
                "a whole bucket for {mode}"
            );
            assert_eq!(decode_member(&member).expect("it reads back"), colour(mode));
            member.as_slice().len()
        })
        .collect();
    assert_eq!(lengths, [1024, 1024, 1024]);

    let member = encode_member(&colour("dark")).expect("a member");
    let value = kr_cbor::decode(member.as_slice(), &kr_cbor::Limits::DEFAULT).expect("canonical");
    let kr_cbor::CanonicalValue::Map(map) = value else {
        panic!("the member is a map");
    };
    let names: Vec<&str> = map
        .entries()
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        names,
        ["pad", "values"],
        "the member holds its values and its pad"
    );

    // Values of any size land on a bucket, and the empty choice is a bucket too.
    let long = DeviceSettings::new(
        [(
            "colour_mode".to_owned(),
            SettingValue::Text("x".repeat(1500)),
        )]
        .into_iter()
        .collect(),
    )
    .expect("settings");
    assert_eq!(
        encode_member(&long).expect("a member").as_slice().len(),
        2048
    );
    assert_eq!(
        encode_member(&DeviceSettings::default())
            .expect("a member")
            .as_slice()
            .len(),
        1024
    );
}

/// KR-REQ-20.17: a member that cannot be written, read or decoded is unusable settings and nothing
/// else, and one over the cap does not fit.
#[test]
fn a_member_that_cannot_be_written_or_read_is_unusable_settings() {
    let too_much = DeviceSettings::new(
        [(
            "colour_mode".to_owned(),
            SettingValue::Text("x".repeat(MAX_DEVICE_SETTINGS_BYTES)),
        )]
        .into_iter()
        .collect(),
    )
    .expect("settings");
    assert!(matches!(
        encode_member(&too_much),
        Err(RecoveryError::SettingsDoNotFit { .. })
    ));

    for (what, bytes) in [
        ("garbage", Bytes::new(vec![0xff; 40])),
        ("nothing", Bytes::new(Vec::new())),
        (
            "more than a member may be",
            Bytes::new(vec![0; MAX_DEVICE_SETTINGS_BYTES + 1]),
        ),
    ] {
        assert!(
            matches!(
                decode_member(&bytes),
                Err(RecoveryError::SettingsUnusable { .. })
            ),
            "{what} is unusable settings"
        );
    }

    // A name that is not a word is refused before it is written.
    for name in ["", "Colour", "colour-mode", &"a".repeat(65)] {
        assert!(
            matches!(
                DeviceSettings::new(
                    [(name.to_owned(), SettingValue::Flag(true))]
                        .into_iter()
                        .collect()
                ),
                Err(RecoveryError::SettingsUnusable { .. })
            ),
            "{name:?} is not a setting's name"
        );
    }
}

/// KR-REQ-20.17: a bundle that opened under the kit and holds what this build does not read, as a
/// later build writes it, says that a later version may have written it and to update; one that did
/// not open says it did not authenticate.
#[tokio::test]
async fn a_bundle_that_opened_and_cannot_be_read_says_what_it_needs() {
    let seed = RecoverySeed::generate().expect("a seed");
    let key = seed.bundle_key_for(&context()).expect("the bundle's key");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);

    // A bundle a later build wrote: the same bundle with a member this build has no name for.
    let mut bundle = BundleStore::empty(now());
    bundle.device_settings = Some(encode_member(&colour("dark")).expect("a member"));
    let value = kr_cbor::to_canonical_value(&bundle).expect("a bundle's value");
    let kr_cbor::CanonicalValue::Map(map) = value else {
        panic!("a bundle is a map");
    };
    let mut entries = map.entries().to_vec();
    entries.push((
        "a_later_member".to_owned(),
        kr_cbor::CanonicalValue::integer(1).expect("an integer"),
    ));
    let later =
        kr_cbor::CanonicalValue::Map(kr_cbor::CanonicalMap::from_entries(entries).expect("a map"));
    service.put(kr_crypto::stream::encrypt_object(&key, &kr_cbor::encode(&later)).expect("sealed"));
    let error = store.fetch(&seed).await.expect_err("it cannot be read");
    assert!(matches!(error, RecoveryError::BundleNeedsANewerKr));
    assert_eq!(
        error.to_string(),
        "Your recovery bundle opened, but this version of KalaReach cannot read it. A later \
         version may have written it. Update KalaReach, then try again."
    );

    // The same bytes under another seed do not open, which is another failure.
    let other = RecoverySeed::generate().expect("another seed");
    let (mut elsewhere, _kept) = store_over(&service);
    assert!(matches!(
        elsewhere.fetch(&other).await,
        Err(RecoveryError::BundleNotAuthentic)
    ));
}

/// One collection whose locator is as long as it takes for the sealed bundle to leave `room` bytes
/// under the bound a service keeps, with the member `settings` saved in it.
fn bundle_leaving(
    seed: &RecoverySeed,
    settings: Option<&DeviceSettings>,
    room: usize,
) -> RecoveryBundle {
    let key = seed.bundle_key_for(&context()).expect("the bundle's key");
    let target = usize::try_from(MAX_SEALED_RECOVERY_BUNDLE_BYTES).expect("a length") - room;
    let mut bundle = BundleStore::empty(now());
    bundle.device_settings = settings.map(|settings| encode_member(settings).expect("a member"));
    let mut length = 100_000_usize;
    for _ in 0..6 {
        bundle.collections = vec![collection(&"x".repeat(length))];
        let sealed = kr_crypto::archive::encrypt_recovery_bundle(&key, &bundle).expect("sealed");
        if sealed.len() == target {
            return bundle;
        }
        length = (length + target).saturating_sub(sealed.len());
    }
    panic!("the bundle never reached {room} bytes under the bound");
}

fn collection(locator: &str) -> CollectionLocator {
    CollectionLocator {
        service_origin: ORIGIN.to_owned(),
        locator: locator.to_owned(),
        archive_id: ArchiveId::new(Uuid::from_bytes([0x38; 16])),
    }
}

/// KR-REQ-20.17: a settings write that would leave the sealed bundle with less room under the
/// bound than the trust entries are kept is refused, with nothing sent; the same write with the
/// room lands.
#[tokio::test]
async fn a_settings_write_that_would_leave_less_room_than_the_trust_entries_need_is_refused() {
    let seed = RecoverySeed::generate().expect("a seed");
    let trust_room = usize::try_from(TRUST_ROOM_BYTES).expect("a length");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);

    let mut tight = bundle_leaving(&seed, Some(&colour("dark")), trust_room - 1);
    tight.device_settings = None;
    let refused = store
        .set_settings(&seed, &mut tight, Some(&colour("dark")), now())
        .await
        .expect_err("less room than the trust entries need");
    assert!(matches!(refused, RecoveryError::SettingsDoNotFit { .. }));
    assert!(
        service.held.lock().expect("the bundle").is_none(),
        "nothing was sent"
    );
    assert!(
        tight.device_settings.is_none(),
        "the caller's bundle is as it was"
    );

    let mut roomy = bundle_leaving(&seed, Some(&colour("dark")), trust_room);
    roomy.device_settings = None;
    store
        .set_settings(&seed, &mut roomy, Some(&colour("dark")), now())
        .await
        .expect("the room is there");
    assert_eq!(
        decode_member(roomy.device_settings.as_ref().expect("the member")).expect("it reads"),
        colour("dark")
    );

    // A member over its cap does not fit, whatever room the bundle has.
    let big = DeviceSettings::new(
        [(
            "colour_mode".to_owned(),
            SettingValue::Text("x".repeat(MAX_DEVICE_SETTINGS_BYTES)),
        )]
        .into_iter()
        .collect(),
    )
    .expect("settings");
    assert!(matches!(
        store
            .set_settings(&seed, &mut roomy, Some(&big), now())
            .await,
        Err(RecoveryError::SettingsDoNotFit { .. })
    ));
}

/// KR-REQ-20.17: a write of a writer, a producer, a collection or a checkpoint that would not fit
/// with the settings saved in the bundle is written without them, and the store says so; one that
/// does not fit without them either is refused.
#[tokio::test]
async fn a_trust_write_that_would_not_fit_with_the_settings_is_written_without_them() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);

    // Twenty bytes of room, then a collection that takes more.
    let mut bundle = bundle_leaving(&seed, Some(&colour("dark")), 20);
    bundle.collections.push(collection(&"y".repeat(60)));
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the trust entry wins");
    assert!(bundle.device_settings.is_none(), "the member was left out");
    assert!(store.settings_dropped());
    let held = store.fetch(&seed).await.expect("the bundle");
    assert!(held.device_settings.is_none());
    assert_eq!(
        held.collections.len(),
        2,
        "the trust entry is in the bundle"
    );

    // A write that fits with the member keeps it, and the store says it dropped nothing.
    let mut fits = held.clone();
    fits.collections = vec![collection("short")];
    fits.device_settings = Some(encode_member(&colour("dark")).expect("a member"));
    store.commit(&seed, &mut fits, now()).await.expect("fits");
    assert!(fits.device_settings.is_some());
    assert!(!store.settings_dropped());

    // Over the bound without the member as well: refused, and nothing is written.
    let current = store.fetch(&seed).await.expect("the bundle");
    let mut over = bundle_leaving(&seed, None, 20);
    over.collections.push(collection(&"z".repeat(60)));
    over.device_settings = Some(encode_member(&colour("dark")).expect("a member"));
    over.revision = current.revision;
    let before = service.sealed();
    assert!(matches!(
        store.commit(&seed, &mut over, now()).await,
        Err(RecoveryError::BundleTooLarge { .. })
    ));
    assert_eq!(service.sealed(), before, "nothing was written");
}

/// Where the migrations in these cases move the bundle to.
fn moved_context() -> RecoveryContext {
    RecoveryContext {
        service_origin: "https://self-hosted.example".to_owned(),
        bundle_locator: "moved-bundle-locator".to_owned(),
    }
}

/// Saved settings that take two buckets of the bundle.
fn two_buckets() -> DeviceSettings {
    DeviceSettings::new(
        [(
            "colour_mode".to_owned(),
            SettingValue::Text("x".repeat(1500)),
        )]
        .into_iter()
        .collect(),
    )
    .expect("settings")
}

/// A migration that went out and whose answer was lost.
struct LostMigration {
    seed: RecoverySeed,
    kit: kr_protocol::archive::RecoveryKit,
    /// The old location, which still holds the bundle that was moved.
    source: Arc<MemoryBundles>,
    store: BundleStore,
    destination: BundleStore,
    /// What the caller holds: the bundle it was moving.
    bundle: RecoveryBundle,
    _directories: [tempfile::TempDir; 2],
}

/// The old location holds a bundle at `revision`, sealed at exactly the bound with its settings. A
/// migration moves it to the destination, which takes the write at the next revision, and the
/// answer never comes back.
async fn a_migration_with_its_answer_lost(revision: u64) -> LostMigration {
    let seed = RecoverySeed::generate().expect("a seed");
    let source_key = seed.bundle_key_for(&context()).expect("the bundle's key");
    let source = Arc::new(MemoryBundles::default());
    let mut held = bundle_leaving(&seed, Some(&two_buckets()), 0);
    held.revision = U64::new(revision);
    source.put(kr_crypto::archive::encrypt_recovery_bundle(&source_key, &held).expect("sealed"));
    assert_eq!(
        source.sealed().len() as u64,
        MAX_SEALED_RECOVERY_BUNDLE_BYTES,
        "the bundle is at the bound with its settings"
    );

    let (mut store, first) = store_over(&source);
    let mut bundle = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(bundle, held);
    let destination_service = Arc::new(MemoryBundles::default());
    let second = tempfile::tempdir().expect("a directory on the internal disk");
    let mut destination = BundleStore::open(
        Arc::clone(&destination_service) as Arc<dyn SyncBackupService>,
        moved_context(),
        second.path(),
    )
    .expect("the destination store");
    *destination_service
        .loses_the_next_answer
        .lock()
        .expect("a flag") = true;
    let kit = seed.to_kit(vec![ORIGIN.to_owned()], LOCATOR.to_owned());
    let migrating = store
        .migrate(&seed, &mut bundle, &kit, &mut destination, now())
        .await;
    assert!(
        matches!(migrating, Err(RecoveryError::BundleOutcomeUnknown { .. })),
        "the destination took the write and its answer was lost"
    );
    assert_eq!(bundle, held, "the caller still holds what it was moving");
    LostMigration {
        seed,
        kit,
        source,
        store,
        destination,
        bundle,
        _directories: [first, second],
    }
}

/// KR-REQ-20.17: a migration whose destination left the settings out for want of room is completed
/// by the one step that finishes a migration, and the old location is still held to what was moved.
///
/// The bundle at the old location is sealed at the bound with its settings. A revision of 22 moves
/// to 23 and a revision of 23 to 24, which takes one more byte, so the destination write is the
/// one that leaves the settings out.
#[tokio::test]
async fn a_migration_whose_destination_left_the_settings_out_for_want_of_room_is_completed() {
    // One byte under: the move still fits with the settings, and completes as it always did.
    let mut fits = a_migration_with_its_answer_lost(22).await;
    let completed = fits
        .store
        .complete_migration(
            &fits.seed,
            &mut fits.bundle,
            &fits.kit,
            &mut fits.destination,
            now(),
        )
        .await;
    assert!(completed.is_ok(), "{:?}", completed.err());
    assert!(fits.bundle.device_settings.is_some(), "the settings stay");
    assert_eq!(fits.bundle.revision.get(), 23);

    // At the bound: the destination wrote the bundle without the settings, and that is the write
    // this migration made.
    let mut over = a_migration_with_its_answer_lost(23).await;
    let moving = over.bundle.clone();
    let completed = over
        .store
        .complete_migration(
            &over.seed,
            &mut over.bundle,
            &over.kit,
            &mut over.destination,
            now(),
        )
        .await;
    assert!(completed.is_ok(), "{:?}", completed.err());
    assert_eq!(over.bundle.revision.get(), 24);
    assert!(
        over.bundle.device_settings.is_none(),
        "the caller holds the bundle at the destination, which lacks the settings"
    );
    let at_destination = over
        .destination
        .fetch(&over.seed)
        .await
        .expect("the bundle");
    assert_eq!(at_destination, over.bundle);
    let source_key = over
        .seed
        .bundle_key_for(&context())
        .expect("the bundle's key");
    assert_eq!(
        kr_crypto::archive::decrypt_recovery_bundle(&source_key, &over.source.sealed())
            .expect("the old location's bundle"),
        moving,
        "the old location still holds the bundle that was moved, settings included"
    );

    // The old location is held to what was moved: the same bundle with settings that would have
    // fitted is not the bundle whose move this was, because nothing then left them out.
    let mut changed = a_migration_with_its_answer_lost(23).await;
    let changed_key = changed
        .seed
        .bundle_key_for(&context())
        .expect("the bundle's key");
    let mut smaller = changed.bundle.clone();
    smaller.device_settings = Some(encode_member(&colour("dark")).expect("a member"));
    changed
        .source
        .put(kr_crypto::archive::encrypt_recovery_bundle(&changed_key, &smaller).expect("sealed"));
    let refused = changed
        .store
        .complete_migration(
            &changed.seed,
            &mut changed.bundle,
            &changed.kit,
            &mut changed.destination,
            now(),
        )
        .await;
    assert!(
        matches!(refused, Err(RecoveryError::BundleConflict { .. })),
        "{:?}",
        refused.err()
    );
}

/// Makes the bundle move once more after each of the next `times` fetches, as another device's
/// write does between a read and the write that follows it.
fn the_bundle_moves_after_the_next(service: &MemoryBundles, times: u32) {
    *service.moves_after_a_fetch.lock().expect("a count") = times;
}

/// KR-REQ-20.17: a removal that meets a bundle that moved since it was read is a conflict, and the
/// member stays where it was; read again, the same removal goes through.
#[tokio::test]
async fn a_removal_that_meets_a_bundle_which_moved_is_a_conflict_and_removes_nothing() {
    let seed = RecoverySeed::generate().expect("a seed");
    let key = seed.bundle_key_for(&context()).expect("the bundle's key");
    let service = Arc::new(MemoryBundles::default());
    let mut held = BundleStore::empty(now());
    held.device_settings = Some(encode_member(&colour("dark")).expect("a member"));
    service.put(kr_crypto::archive::encrypt_recovery_bundle(&key, &held).expect("sealed"));
    let (mut store, _directory) = store_over(&service);

    the_bundle_moves_after_the_next(&service, 1);
    let removal = store.remove_settings(&seed, now()).await;
    assert!(
        matches!(removal, Err(RecoveryError::BundleConflict { .. })),
        "{:?}",
        removal.ok()
    );
    assert_eq!(
        kr_crypto::archive::decrypt_recovery_bundle(&key, &service.sealed()).expect("the bundle"),
        held,
        "the member is where it was"
    );

    let removal = store.remove_settings(&seed, now()).await;
    assert!(
        matches!(removal, Ok(SettingsRemoval::Removed { .. })),
        "{:?}",
        removal.err()
    );
}

/// KR-REQ-20.17: a save reads the bundle again after it moved, three reads in all, and returns the
/// last conflict after that.
#[tokio::test]
async fn a_save_reads_the_bundle_again_after_it_moved_three_times_in_all() {
    let seed = RecoverySeed::generate().expect("a seed");
    let key = seed.bundle_key_for(&context()).expect("the bundle's key");
    let service = Arc::new(MemoryBundles::default());
    service.put(
        kr_crypto::archive::encrypt_recovery_bundle(&key, &BundleStore::empty(now()))
            .expect("sealed"),
    );
    let (mut store, _directory) = store_over(&service);

    // The bundle moves after the first two reads and the third attempt writes.
    the_bundle_moves_after_the_next(&service, 2);
    let saved = store.save_settings(&seed, local("dark"), now()).await;
    assert!(
        matches!(saved, Ok(SettingsSaved::Saved { .. })),
        "{:?}",
        saved.err()
    );

    // It moves after all three reads: the conflict of the last is what the caller gets, and
    // nothing of this save was written.
    the_bundle_moves_after_the_next(&service, 3);
    let refused = store.save_settings(&seed, local("light"), now()).await;
    assert!(
        matches!(refused, Err(RecoveryError::BundleConflict { .. })),
        "{:?}",
        refused.ok()
    );
    assert_eq!(
        *service.moves_after_a_fetch.lock().expect("a count"),
        0,
        "three reads were made, and no fourth"
    );
    let held =
        kr_crypto::archive::decrypt_recovery_bundle(&key, &service.sealed()).expect("the bundle");
    assert_eq!(
        decode_member(held.device_settings.as_ref().expect("the member")).expect("it reads"),
        colour("dark")
    );
}

/// A member as `encode_member` makes it, except that its pad brings it to `len` bytes, whatever
/// the cap says.
fn a_member_of_length(len: usize) -> Bytes {
    let sample = encode_member(&colour("dark")).expect("a member");
    let kr_cbor::CanonicalValue::Map(map) =
        kr_cbor::decode(sample.as_slice(), &kr_cbor::Limits::DEFAULT).expect("canonical")
    else {
        panic!("the member is a map");
    };
    let padded = |pad: usize| -> Vec<u8> {
        let entries = map
            .entries()
            .iter()
            .map(|(name, value)| {
                if name == "pad" {
                    (name.clone(), kr_cbor::CanonicalValue::bytes(vec![0; pad]))
                } else {
                    (name.clone(), value.clone())
                }
            })
            .collect::<Vec<_>>();
        kr_cbor::encode(&kr_cbor::CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_entries(entries).expect("a map"),
        ))
    };
    // A pad of 256 bytes or more has a three-byte header, so the member grows byte for byte.
    let encoded = padded(1024 + len - padded(1024).len());
    assert_eq!(encoded.len(), len);
    Bytes::new(encoded)
}

/// KR-REQ-20.17: the read holds a member to the cap as the write does. A member that is the right
/// shape and canonical, and over the cap, is refused for its size; one at the cap is read.
#[test]
fn a_valid_member_over_the_cap_is_refused_at_the_read_and_one_at_the_cap_is_read() {
    let at_the_cap = a_member_of_length(MAX_DEVICE_SETTINGS_BYTES);
    assert_eq!(
        decode_member(&at_the_cap).expect("a member at the cap reads"),
        colour("dark")
    );
    let over = a_member_of_length(MAX_DEVICE_SETTINGS_BYTES + 1);
    let refused = decode_member(&over);
    assert!(
        matches!(&refused, Err(RecoveryError::SettingsUnusable { what }) if what.contains("larger")),
        "{:?}",
        refused.ok()
    );
}

/// KR-REQ-20.17: taking the member out is a trust write, which makes room, so a bundle with less
/// room than a settings write needs still has it cleared: by the removal, and by the choice of
/// nothing.
#[tokio::test]
async fn clearing_the_member_from_a_bundle_with_little_room_is_written_as_a_trust_write() {
    for removal in [true, false] {
        let seed = RecoverySeed::generate().expect("a seed");
        let key = seed.bundle_key_for(&context()).expect("the bundle's key");
        let service = Arc::new(MemoryBundles::default());
        // One bucket of room with the member in, two without it: under what a settings write
        // leaves for the trust entries.
        let full = bundle_leaving(&seed, Some(&colour("dark")), 1024);
        service.put(kr_crypto::archive::encrypt_recovery_bundle(&key, &full).expect("sealed"));
        let (mut store, _directory) = store_over(&service);

        let mut held = store.fetch(&seed).await.expect("the bundle");
        assert!(
            matches!(
                store
                    .set_settings(&seed, &mut held, Some(&colour("light")), now())
                    .await,
                Err(RecoveryError::SettingsDoNotFit { .. })
            ),
            "a settings write does not fit here"
        );

        if removal {
            let cleared = store.remove_settings(&seed, now()).await;
            assert!(
                matches!(cleared, Ok(SettingsRemoval::Removed { .. })),
                "{:?}",
                cleared.err()
            );
        } else {
            let nothing = LocalSettings::Values(DeviceSettings::default());
            let cleared = store.save_settings(&seed, nothing, now()).await;
            assert!(
                matches!(cleared, Ok(SettingsSaved::Saved { .. })),
                "{:?}",
                cleared.err()
            );
        }
        let after = kr_crypto::archive::decrypt_recovery_bundle(&key, &service.sealed())
            .expect("the bundle");
        assert!(after.device_settings.is_none(), "the member is out");
    }
}

fn local(mode: &str) -> LocalSettings {
    LocalSettings::Values(colour(mode))
}

/// KR-REQ-20.17: a write is made when what the bundle holds differs from what the device has
/// chosen, and not otherwise; the choice of nothing clears the member.
#[tokio::test]
async fn a_changed_setting_is_written_once_and_an_unchanged_one_is_not_written() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);
    let place = || {
        service
            .held
            .lock()
            .expect("the bundle")
            .as_ref()
            .map(|held| held.0)
    };

    // The first bundle is the one a turn-on writes, and a choice not yet made leaves no member.
    let mut first = BundleStore::empty(now());
    store
        .commit(&seed, &mut first, now())
        .await
        .expect("the first bundle");
    assert_eq!(place(), Some(1));
    assert_eq!(
        store
            .save_settings(
                &seed,
                LocalSettings::Values(DeviceSettings::default()),
                now()
            )
            .await
            .expect("nothing to save"),
        SettingsSaved::AlreadySaved
    );
    assert_eq!(place(), Some(1), "no write for no choice");

    assert!(matches!(
        store
            .save_settings(&seed, local("dark"), now())
            .await
            .expect("saved"),
        SettingsSaved::Saved { .. }
    ));
    assert_eq!(place(), Some(2));
    assert_eq!(
        store
            .save_settings(&seed, local("dark"), now())
            .await
            .expect("settled"),
        SettingsSaved::AlreadySaved
    );
    assert_eq!(place(), Some(2), "the same choice is not written again");

    assert!(matches!(
        store
            .save_settings(&seed, local("light"), now())
            .await
            .expect("saved"),
        SettingsSaved::Saved { .. }
    ));
    assert_eq!(place(), Some(3));
    let held = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(
        decode_member(held.device_settings.as_ref().expect("the member")).expect("it reads"),
        colour("light")
    );

    // A choice taken back, which is a readable file with nothing chosen in it, clears the member.
    assert!(matches!(
        store
            .save_settings(
                &seed,
                LocalSettings::Values(DeviceSettings::default()),
                now()
            )
            .await
            .expect("cleared"),
        SettingsSaved::Saved { .. }
    ));
    assert!(
        store
            .fetch(&seed)
            .await
            .expect("the bundle")
            .device_settings
            .is_none()
    );
}

/// KR-REQ-20.17: a settings file that cannot be read is not a choice of nothing. The member the
/// bundle holds stays, and nothing is written.
#[tokio::test]
async fn an_unreadable_settings_file_keeps_the_member_the_bundle_holds() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);
    let mut first = BundleStore::empty(now());
    store
        .commit(&seed, &mut first, now())
        .await
        .expect("the first bundle");
    store
        .save_settings(&seed, local("dark"), now())
        .await
        .expect("saved");
    let before = service.sealed();

    assert!(matches!(
        store
            .save_settings(&seed, LocalSettings::Unreadable, now())
            .await,
        Err(RecoveryError::SettingsUnusable { .. })
    ));
    assert_eq!(service.sealed(), before, "nothing was written");
    let held = store.fetch(&seed).await.expect("the bundle");
    assert_eq!(
        decode_member(held.device_settings.as_ref().expect("the member kept")).expect("it reads"),
        colour("dark")
    );
}

/// KR-REQ-20.17: removing the member writes the bundle by its own compare-and-swap and changes
/// nothing else in it: the collections, the writers, the producers and the checkpoints are the
/// same bytes. A bundle with no member is left alone.
#[tokio::test]
async fn removing_the_member_leaves_collections_keys_and_checkpoints_byte_for_byte() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);
    let mut bundle = BundleStore::empty(now());
    bundle.collections.push(collection("collection-1"));
    bundle.trusted_writers = [kr_protocol::archive::TrustedWriter {
        writer_key_id: kr_protocol::scalars::KeyId::from_bytes([0x73; 32]),
        signing_key: kr_protocol::scalars::AuthorisationKey::from_bytes([0x74; 32]),
        enrolled_at_ms: now(),
    }]
    .into_iter()
    .collect();
    bundle.trusted_producers = [kr_protocol::archive::TrustedProducer {
        sender_key_id: kr_protocol::scalars::KeyId::from_bytes([0x78; 32]),
        stored_envelope_key: kr_protocol::scalars::StoredEnvelopeKey::from_bytes([0x79; 32]),
        enrolled_at_ms: now(),
    }]
    .into_iter()
    .collect();
    bundle.checkpoints = [kr_protocol::archive::ArchiveCheckpoint {
        archive_id: ArchiveId::new(Uuid::from_bytes([0x38; 16])),
        backup_generation: kr_protocol::ids::BackupGeneration::new(7),
        encrypted_manifest_hash: kr_protocol::scalars::Digest256::from_bytes([0x7a; 32]),
        verified_at_ms: now(),
    }]
    .into_iter()
    .collect();
    store
        .commit(&seed, &mut bundle, now())
        .await
        .expect("the bundle");
    store
        .save_settings(&seed, local("dark"), now())
        .await
        .expect("saved");
    let with_member = store.fetch(&seed).await.expect("the bundle");
    assert!(with_member.device_settings.is_some());

    assert!(matches!(
        store.remove_settings(&seed, now()).await.expect("removed"),
        SettingsRemoval::Removed { .. }
    ));
    let without = store.fetch(&seed).await.expect("the bundle");
    assert!(without.device_settings.is_none());
    assert_eq!(without.revision.get(), with_member.revision.get() + 1);
    // Everything else is the same bytes: the two bundles agree once the member, the revision and
    // the instant are put aside.
    let rest = |bundle: &RecoveryBundle| {
        kr_cbor::to_canonical_vec(&RecoveryBundle {
            device_settings: None,
            revision: kr_protocol::scalars::U64::new(0),
            written_at_ms: TimestampMs::new(0),
            ..bundle.clone()
        })
        .expect("canonical bytes")
    };
    assert_eq!(rest(&without), rest(&with_member));
    assert_eq!(rest(&without), rest(&bundle));

    // Nothing to remove: nothing is written.
    let place = service
        .held
        .lock()
        .expect("the bundle")
        .as_ref()
        .map(|held| held.0);
    assert!(matches!(
        store
            .remove_settings(&seed, now())
            .await
            .expect("nothing saved"),
        SettingsRemoval::NothingSaved
    ));
    assert_eq!(
        service
            .held
            .lock()
            .expect("the bundle")
            .as_ref()
            .map(|held| held.0),
        place
    );
}

/// KR-REQ-20.15, KR-REQ-20.17: a removal whose answer never came back is not reported as done. The
/// store still says the write is unsettled, and a second removal ends it first, then reads the
/// bundle and finds the member gone.
#[tokio::test]
async fn a_removal_whose_answer_is_lost_stays_unconfirmed_until_it_is_ended() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);
    let mut first = BundleStore::empty(now());
    store
        .commit(&seed, &mut first, now())
        .await
        .expect("the first bundle");
    store
        .save_settings(&seed, local("dark"), now())
        .await
        .expect("saved");

    *service.loses_the_next_answer.lock().expect("a flag") = true;
    let lost = store
        .remove_settings(&seed, now())
        .await
        .expect_err("the answer never came back");
    assert!(matches!(lost, RecoveryError::BundleOutcomeUnknown { .. }));
    assert!(matches!(
        store.lost_write(),
        Some(LostWrite::Unsettled { .. })
    ));

    assert_eq!(
        store
            .remove_settings(&seed, now())
            .await
            .expect("ended, then read"),
        SettingsRemoval::NothingSaved,
        "the first removal applied, and the second finds nothing to remove"
    );
    assert!(matches!(store.lost_write(), Some(LostWrite::Applied)));

    // A removal that never reached the service leaves the member where it was, and the next one
    // ends the lost write first and then goes out.
    store
        .save_settings(&seed, local("dark"), now())
        .await
        .expect("saved again");
    *service.drops_the_next_request.lock().expect("a flag") = true;
    assert!(matches!(
        store.remove_settings(&seed, now()).await,
        Err(RecoveryError::BundleOutcomeUnknown { .. })
    ));
    assert!(
        store
            .fetch(&seed)
            .await
            .expect("the bundle")
            .device_settings
            .is_some()
    );
    assert!(matches!(
        store
            .remove_settings(&seed, now())
            .await
            .expect("ended, then removed"),
        SettingsRemoval::Removed { .. }
    ));
    assert!(
        store
            .fetch(&seed)
            .await
            .expect("the bundle")
            .device_settings
            .is_none()
    );
}

// ---------------------------------------------------------------------------------------------
// A restore with the kit alone.
// ---------------------------------------------------------------------------------------------

/// A service as a restore reaches it: the one bundle this suite keeps, and no archive.
#[derive(Debug)]
struct ServiceSource {
    bundles: Arc<MemoryBundles>,
}

impl RestoreSource for ServiceSource {
    fn service(&self) -> ServiceFuture<'_, SourceService> {
        Box::pin(async {
            Ok(SourceService {
                origin: ORIGIN.to_owned(),
                managed_origin: ORIGIN.to_owned(),
                sign_in: SourceSignIn::Usable,
            })
        })
    }

    fn bundle<'a>(&'a self, locator: &'a str) -> ServiceFuture<'a, SyncFetched> {
        Box::pin(async move {
            self.bundles
                .fetch(&format!("recovery_bundle/{locator}"))
                .await
        })
    }

    fn generation<'a>(
        &'a self,
        _archive: ArchiveId,
        _checkpoint: Option<&'a kr_protocol::archive::ArchiveCheckpoint>,
    ) -> ServiceFuture<'a, Option<kr_protocol::archive::BackupGenerationPublication>> {
        Box::pin(async { Ok(None) })
    }

    fn object(
        &self,
        _archive: ArchiveId,
        _object: kr_protocol::ids::BackupObjectId,
        _offset: u64,
        _length: u64,
    ) -> ServiceFuture<'_, Vec<u8>> {
        Box::pin(async { Err(unsupported()) })
    }
}

fn kit_of(seed: &RecoverySeed) -> kr_protocol::archive::RecoveryKit {
    seed.to_kit(vec![ORIGIN.to_owned()], LOCATOR.to_owned())
}

/// A bundle store over a service that keeps one bundle with the settings `mode` saved in it.
async fn saved(seed: &RecoverySeed, mode: Option<&str>) -> Arc<MemoryBundles> {
    let service = Arc::new(MemoryBundles::default());
    let (mut store, _directory) = store_over(&service);
    let mut bundle = BundleStore::empty(now());
    bundle.collections.push(collection("collection-1"));
    store
        .commit(seed, &mut bundle, now())
        .await
        .expect("the bundle");
    if let Some(mode) = mode {
        store
            .save_settings(seed, local(mode), now())
            .await
            .expect("the settings are saved");
    }
    service
}

/// KR-REQ-20.17: a restore that holds only the kit reads the member out of the bundle at the
/// service and returns the settings. What comes back is the settings and the instant the bundle
/// was last written, and nothing that grants.
#[tokio::test]
async fn a_restore_with_only_the_kit_returns_the_settings_member_and_nothing_that_grants() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = saved(&seed, Some("dark")).await;
    let source = Arc::new(ServiceSource {
        bundles: Arc::clone(&service),
    });
    let restored = FilesRestore::settings(kit_of(&seed), source)
        .await
        .expect("the settings come back");
    assert_eq!(
        restored,
        SavedSettings::Found {
            settings: colour("dark"),
            bundle_written_at_ms: now(),
        }
    );
    // What it returns names a setting and its value: no key, no membership and no note.
    let SavedSettings::Found { settings, .. } = restored else {
        panic!("settings were saved");
    };
    assert_eq!(
        settings.values().keys().collect::<Vec<_>>(),
        ["colour_mode"]
    );

    // Another kit does not open it: the settings are not a way round the kit.
    let other = RecoverySeed::generate().expect("another seed");
    assert!(matches!(
        FilesRestore::settings(
            kit_of(&other),
            Arc::new(ServiceSource { bundles: service })
        )
        .await,
        Err(RestoreError::Recovery(error)) if matches!(*error, RecoveryError::BundleNotAuthentic)
    ));
}

/// KR-REQ-20.17: a bundle with no settings member, as one written before the member or by a device
/// that chose nothing is, restores no settings and says so, and the person's own settings stay as
/// they are.
#[tokio::test]
async fn a_bundle_with_no_settings_member_restores_no_settings_and_says_so() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = saved(&seed, None).await;
    assert_eq!(
        FilesRestore::settings(kit_of(&seed), Arc::new(ServiceSource { bundles: service }))
            .await
            .expect("an answer"),
        SavedSettings::NoneSaved
    );
}

/// KR-REQ-20.17: a restore from an export file returns the settings with no account and no
/// network. The service is gone when the file is read; the kit and the file are all that is left.
#[tokio::test]
async fn a_restore_from_an_export_file_returns_the_settings_with_no_account_and_no_network() {
    let seed = RecoverySeed::generate().expect("a seed");
    let service = saved(&seed, Some("light")).await;
    let file = OfflineExport::new(ORIGIN.to_owned(), service.sealed(), None)
        .to_canonical_bytes()
        .expect("the file");
    drop(service);

    let export = OfflineExport::from_canonical_slice(&file).expect("the file reads back");
    let restored = FilesRestore::settings(kit_of(&seed), Arc::new(ExportSource::new(export)))
        .await
        .expect("the settings come back from the file");
    assert!(matches!(
        restored,
        SavedSettings::Found { settings, .. } if settings == colour("light")
    ));
}

/// KR-REQ-20.17: a settings member that no build can read fails the settings restore and nothing
/// else. The member is garbage, or over its cap: a data restore reads the bundle, a checkpoint
/// carries it through unchanged, and a host's cover writes the bundle with it as it is, while the
/// settings restore says the settings cannot be used.
#[tokio::test]
async fn a_settings_member_that_no_build_can_read_fails_only_the_settings_restore() {
    for (what, member) in [
        ("garbage", Bytes::new(vec![0xff; 64])),
        (
            "over its cap",
            Bytes::new(vec![0; MAX_DEVICE_SETTINGS_BYTES + 1]),
        ),
    ] {
        let seed = RecoverySeed::generate().expect("a seed");
        let service = Arc::new(MemoryBundles::default());
        let (mut store, _directory) = store_over(&service);
        let mut bundle = BundleStore::empty(now());
        bundle.collections.push(collection("collection-1"));
        bundle.device_settings = Some(member.clone());
        store
            .commit(&seed, &mut bundle, now())
            .await
            .expect("a bundle with a member is written");

        // The settings restore.
        assert!(
            matches!(
                FilesRestore::settings(
                    kit_of(&seed),
                    Arc::new(ServiceSource {
                        bundles: Arc::clone(&service)
                    })
                )
                .await,
                Err(RestoreError::Recovery(error))
                    if matches!(*error, RecoveryError::SettingsUnusable { .. })
            ),
            "{what}: the settings restore says they cannot be used"
        );

        // The data restore reads the same bundle and finds the collection.
        let mut fresh = FreshRestore::new(kit_of(&seed), RetrievalPolicy::Account);
        fresh
            .obtained_access(ServiceAccess::new(
                RetrievalPolicy::Account,
                ORIGIN,
                Arc::clone(&service) as Arc<dyn SyncBackupService>,
            ))
            .expect("access");
        let material = fresh.open_bundle(ORIGIN).await.expect("the data restore");
        assert_eq!(material.collections, [collection("collection-1")]);

        // A checkpoint and a host's cover write the bundle on and carry the member as it is.
        let checkpoint = kr_protocol::archive::ArchiveCheckpoint {
            archive_id: ArchiveId::new(Uuid::from_bytes([0x38; 16])),
            backup_generation: kr_protocol::ids::BackupGeneration::new(1),
            encrypted_manifest_hash: kr_protocol::scalars::Digest256::from_bytes([1; 32]),
            verified_at_ms: now(),
        };
        let held = store.fetch(&seed).await.expect("the bundle");
        let advanced = advance_checkpoint(&held, &checkpoint)
            .expect("a checkpoint")
            .expect("it advances");
        assert_eq!(advanced.device_settings, Some(member.clone()));
        let writer = kr_protocol::archive::TrustedWriter {
            writer_key_id: kr_protocol::scalars::KeyId::from_bytes([0x73; 32]),
            signing_key: kr_protocol::scalars::AuthorisationKey::from_bytes([0x74; 32]),
            enrolled_at_ms: now(),
        };
        let entries = ArchiveEntries {
            collection: collection("collection-2"),
            writer,
            producer: kr_protocol::archive::TrustedProducer {
                sender_key_id: kr_protocol::scalars::KeyId::from_bytes([0x78; 32]),
                stored_envelope_key: kr_protocol::scalars::StoredEnvelopeKey::from_bytes(
                    [0x79; 32],
                ),
                enrolled_at_ms: now(),
            },
        };
        let mut covered = store.fetch(&seed).await.expect("the bundle");
        entries
            .commit(&mut store, &seed, &mut covered, now())
            .await
            .expect("a cover still runs");
        let after = store.fetch(&seed).await.expect("the bundle");
        assert_eq!(
            after.device_settings,
            Some(member),
            "{what}: carried as it is"
        );
        assert_eq!(after.collections.len(), 2);
    }
}

/// KR-REQ-20.17, 18.05: the private keys a device keeps are in neither the member as it is
/// encoded, nor the bundle as a restore opens it, nor the settings a restore returns when they are
/// encoded again. Each key is looked for as bytes, in hexadecimal of either case, in either base64
/// alphabet and as a list of numbers. The controls are the scan finding a key where one is put: in
/// a setting's value, in each form. The sealed bundle the service holds is ciphertext and is
/// read only as that.
#[tokio::test]
async fn the_member_and_the_settings_a_restore_returns_hold_none_of_the_private_keys_the_device_keeps()
 {
    let keys = DeviceKeys::generate().expect("a device's keys");
    let kept = private_keys_of(&keys);
    let seed = RecoverySeed::generate().expect("a seed");
    let service = saved(&seed, Some("dark")).await;
    let key = seed.bundle_key_for(&context()).expect("the bundle's key");

    let opened = kr_crypto::archive::decrypt_recovery_bundle(&key, &service.sealed())
        .expect("the kit's seed opens the bundle");
    let member = opened.device_settings.clone().expect("the member");
    let restored = FilesRestore::settings(
        kit_of(&seed),
        Arc::new(ServiceSource {
            bundles: Arc::clone(&service),
        }),
    )
    .await
    .expect("the settings come back");
    let SavedSettings::Found { settings, .. } = restored else {
        panic!("settings were saved");
    };
    let encoded_again = encode_member(&settings).expect("the restored settings, encoded again");
    assert_eq!(encoded_again, member, "what comes back is what went in");

    let looked_at = [
        ("the member as encoded", member.as_slice().to_vec()),
        (
            "the bundle as a restore opens it",
            kr_cbor::to_canonical_vec(&opened).expect("canonical bytes"),
        ),
        (
            "the restored settings, encoded again",
            encoded_again.as_slice().to_vec(),
        ),
        (
            "the restored settings as JSON",
            serde_json::to_vec(
                &settings
                    .values()
                    .iter()
                    .map(|(name, value)| (name.clone(), format!("{value:?}")))
                    .collect::<std::collections::BTreeMap<_, _>>(),
            )
            .expect("json"),
        ),
        ("the sealed bundle the service holds", service.sealed()),
    ];
    for (label, bytes) in &looked_at {
        for (name, private) in &kept {
            assert_eq!(
                carried_in(bytes, private),
                None,
                "{label} carries the {name}"
            );
        }
    }

    // The controls: put each key in a setting's value in each form, spelled here and not by the
    // scan's own list of forms, and the scan finds it in the member. A form dropped from the scan
    // fails here.
    for (name, private) in &kept {
        let lower: String = private.iter().map(|byte| format!("{byte:02x}")).collect();
        let url = kr_protocol::scalars::to_base64url(private);
        let numbers = private
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        for (form, text) in [
            ("in lower-case hexadecimal", lower.clone()),
            ("in upper-case hexadecimal", lower.to_uppercase()),
            ("in base64url", url.clone()),
            ("in base64", url.replace('-', "+").replace('_', "/")),
            ("as a list of numbers", format!("[{numbers}]")),
        ] {
            let planted = DeviceSettings::new(
                [("colour_mode".to_owned(), SettingValue::Text(text))]
                    .into_iter()
                    .collect(),
            )
            .expect("settings");
            let encoded = encode_member(&planted).expect("a member");
            assert!(
                carried_in(encoded.as_slice(), private).is_some(),
                "the scan misses the {name} {form}"
            );
        }
        let raw = [b"colour_mode".as_slice(), private.as_slice()].concat();
        assert!(
            carried_in(&raw, private).is_some(),
            "the scan misses the {name} as bytes"
        );
    }
}

/// The forms in which a document could carry `key`, as the bytes to look for in it: the bytes
/// themselves and their hexadecimal in either case; and base64 in either alphabet, which puts three
/// bytes in four characters, so that the characters standing for the key's whole groups of three are
/// the same wherever the key lies in a longer value. Which groups those are depends on where the key
/// starts, so each of the three ways it can start is looked for.
fn forms_of(key: &[u8]) -> Vec<(String, Vec<u8>)> {
    let hex = |upper: bool| -> Vec<u8> {
        key.iter()
            .map(|byte| {
                if upper {
                    format!("{byte:02X}")
                } else {
                    format!("{byte:02x}")
                }
            })
            .collect::<String>()
            .into_bytes()
    };
    let mut forms = vec![
        ("as bytes".to_owned(), key.to_vec()),
        ("in lower-case hexadecimal".to_owned(), hex(false)),
        ("in upper-case hexadecimal".to_owned(), hex(true)),
    ];
    for start in 0..3 {
        let whole = &key[start..start + (key.len() - start) / 3 * 3];
        let url = kr_protocol::scalars::to_base64url(whole);
        forms.push((
            format!("in base64url from its byte {start}"),
            url.clone().into_bytes(),
        ));
        forms.push((
            format!("in base64 from its byte {start}"),
            url.replace('-', "+").replace('_', "/").into_bytes(),
        ));
    }
    forms
}

/// How `key` is carried in `haystack`, in a form [`forms_of`] names or as serde writes a list of
/// bytes, a list of numbers, with any space between its items; nothing when it is not.
fn carried_in(haystack: &[u8], key: &[u8]) -> Option<String> {
    let found = |needle: &[u8], haystack: &[u8]| {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    };
    if let Some((form, _)) = forms_of(key)
        .into_iter()
        .find(|(_, needle)| found(needle, haystack))
    {
        return Some(form);
    }
    let compact: Vec<u8> = haystack
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    let numbers = key
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes();
    found(&numbers, &compact).then(|| "as a list of numbers".to_owned())
}

/// The private keys a device keeps, as their bytes with a name: the four seeds, and the private
/// keys of the two X25519 pairs, which are made from their seeds by a hash (the first half of the
/// seed's SHA-512, which is what libsodium's `crypto_box_seed_keypair` makes of it) and are checked
/// here against the public key the pair has.
fn private_keys_of(keys: &DeviceKeys) -> Vec<(String, Vec<u8>)> {
    use kr_crypto::store::{MemoryStore, SecretName, SecretStore as _, store_device_keys};
    use kr_protocol::pairing::KeyPurpose;
    use sha2::Digest as _;

    // The seeds are read from a store they are written to, as the device's own are.
    let store = MemoryStore::new();
    store_device_keys(&store, "device", keys).expect("the keys are stored");
    let mut kept = Vec::new();
    for (purpose, public) in [
        (KeyPurpose::Transport, None),
        (KeyPurpose::Authorisation, None),
        (
            KeyPurpose::StoredEnvelope,
            Some(*keys.stored_envelope.public().as_bytes()),
        ),
        (
            KeyPurpose::NotificationPreview,
            Some(*keys.notification_preview.public().as_bytes()),
        ),
    ] {
        let name = SecretName::device_key("device", purpose).expect("a name");
        let seed = store
            .get(&name)
            .expect("the store reads")
            .unwrap_or_else(|| panic!("the store kept a {purpose:?} key"))
            .expose()
            .to_vec();
        kept.push((format!("{purpose:?} seed"), seed.clone()));
        if let Some(public) = public {
            let secret = sha2::Sha512::digest(&seed)[..32].to_vec();
            let derived = aws_lc_rs::agreement::PrivateKey::from_private_key(
                &aws_lc_rs::agreement::X25519,
                &secret,
            )
            .expect("an X25519 private key")
            .compute_public_key()
            .expect("its public key");
            assert_eq!(
                derived.as_ref(),
                public.as_slice(),
                "the {purpose:?} private key is the first half of its seed's hash"
            );
            kept.push((format!("{purpose:?} private key (derived)"), secret));
        }
    }
    assert_eq!(kept.len(), 6, "four seeds and two keys made from them");
    for (name, key) in &kept {
        assert!(key.len() >= 32, "the {name} is a key, not a stub");
    }
    kept
}
