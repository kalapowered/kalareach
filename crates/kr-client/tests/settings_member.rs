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

use std::sync::{Arc, Mutex};

use kr_client::error::ClientError;
use kr_client::recovery::{
    BundleStore, DeviceSettings, MAX_DEVICE_SETTINGS_BYTES, RecoveryError, decode_member,
    encode_member,
};
use kr_client::services::{
    ServiceFuture, SyncBackupService, SyncExchanged, SyncFetched, SyncPosition, SyncRequestFence,
    SyncRequestStatus, SyncRevision,
};
use kr_client::sync::SettingValue;
use kr_crypto::kdf::RecoverySeed;
use kr_protocol::archive::RecoveryContext;
use kr_protocol::error::ErrorCode;
use kr_protocol::scalars::{Bytes, TimestampMs, Uuid};

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
        _request_id: Uuid,
        _signed_at_ms: u64,
        expected: Option<SyncPosition>,
        ciphertext: &'a [u8],
    ) -> ServiceFuture<'a, SyncExchanged> {
        Box::pin(async move {
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
        _request_id: Uuid,
        _first_signed_at_ms: u64,
        _last_signed_at_ms: u64,
    ) -> ServiceFuture<'a, SyncRequestFence> {
        Box::pin(async { Err(unsupported()) })
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
