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
//! | `a_changed_setting_is_written_once_and_an_unchanged_one_is_not_written` | the comparison before a write |
//! | `an_unreadable_settings_file_keeps_the_member_the_bundle_holds` | an absent choice and an unreadable file |
//! | `removing_the_member_leaves_collections_keys_and_checkpoints_byte_for_byte` | the removal by its own compare-and-swap |
//! | `a_removal_whose_answer_is_lost_stays_unconfirmed_until_it_is_ended` | an unconfirmed removal stays visible |

use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::recovery::{
    BundleStore, DeviceSettings, LocalSettings, LostWrite, MAX_DEVICE_SETTINGS_BYTES,
    RecoveryError, SettingsRemoval, SettingsSaved, TRUST_ROOM_BYTES, decode_member, encode_member,
};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::SettingValue;
use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::{CollectionLocator, RecoveryBundle, RecoveryContext};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ArchiveId;
use kr_protocol::scalars::{Bytes, TimestampMs, Uuid};
use kr_protocol::sync::MAX_SEALED_RECOVERY_BUNDLE_BYTES;

const ORIGIN: &str = "https://reach.kala.to";
const LOCATOR: &str = "b7f1c0d2-recovery-bundle";

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
            Ok(match self.held.lock().expect("the bundle").as_ref() {
                Some((place, ciphertext)) => SyncFetched::Held {
                    position: at(*place),
                    ciphertext: ciphertext.clone(),
                },
                None => SyncFetched::Absent { recovery: None },
            })
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
/// later build writes it, says what it needs; one that did not open says it did not authenticate.
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
        "this bundle holds saved settings that need `kr` 0.79 or later"
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
