//! A device whose key store loses a key it sealed under.
//!
//! The device's keys live in a directory store on its disk. A key that vanishes between two calls,
//! whatever took it, must leave the device saying which key is missing, and must leave the device
//! without a replacement: a key made in its place would seal content no other device could read
//! while looking, from here, exactly like success. The store here is the product's own directory
//! store, the sealer is the product's own, and the fault is the key's file taken away from outside
//! them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_client::drafts::DraftSealer;
use kr_client::sync::{CollectionKeys, CollectionSealer, StoredCollectionKeys};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_crypto::store::{SecretName, open_store_in};
use kr_protocol::error::ErrorCode;

const SCOPE: &str = "kr-faults-keys";
const COLLECTION: &str = "settings";

/// Every file the store holds, relative to its directory.
fn files(root: &Path) -> BTreeSet<PathBuf> {
    fn walk(root: &Path, at: &Path, into: &mut BTreeSet<PathBuf>) {
        for entry in std::fs::read_dir(at).expect("the store's directory reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                walk(root, &path, into);
            } else {
                into.insert(path.strip_prefix(root).expect("below the root").to_owned());
            }
        }
    }
    let mut found = BTreeSet::new();
    walk(root, root, &mut found);
    found
}

/// KR-REQ-27.05, missing keys: a collection key taken out of the device's store between two calls
/// is reported as missing, by the epoch it belongs to, for reading and for writing; no key is made
/// in its place and the store gains no file; the epoch whose key is still there goes on working;
/// and the sealed object, which nothing touched, opens again once the key is back.
#[test]
fn a_collection_key_that_vanishes_from_the_device_store_is_reported_and_never_replaced() {
    let parent = tempfile::tempdir().expect("a place for the store");
    let directory = parent.path().join("secrets");
    let keys = Arc::new(StoredCollectionKeys::of(
        open_store_in(&directory).expect("a directory store"),
        SCOPE,
    ));
    for epoch in [1_u64, 2] {
        let key: SymmetricKey = Secret::random().expect("a key");
        keys.put(COLLECTION, epoch, &key)
            .expect("the key is stored");
    }
    let sealer = |epoch| {
        CollectionSealer::new(
            Arc::clone(&keys) as Arc<dyn CollectionKeys>,
            COLLECTION,
            epoch,
        )
    };
    let first = sealer(1)
        .seal(b"written at epoch one")
        .expect("sealed at epoch one");
    let second = sealer(2)
        .seal(b"written at epoch two")
        .expect("sealed at epoch two");

    // The fault: epoch one's key file goes, from outside the store and the sealer.
    let name = SecretName::collection_key(SCOPE, COLLECTION, 1).expect("a name");
    let file = directory.join(name.as_str());
    let kept_copy = std::fs::read(&file).expect("the key is a file the store wrote");
    std::fs::remove_file(&file).expect("the key's file goes");
    let before = files(&directory);

    // Reading what that epoch sealed names a missing key and not a failure to authenticate.
    let unreadable = sealer(1).open(&first).expect_err("the key is gone");
    assert_eq!(
        unreadable.code(),
        ErrorCode::HostNotConfigured,
        "{unreadable}"
    );
    // Writing under it is refused by epoch, and asking again changes nothing.
    for _ in 0..2 {
        let unwritable = sealer(1)
            .seal(b"written after the loss")
            .expect_err("no key to seal under");
        assert_eq!(
            unwritable.code(),
            ErrorCode::HostNotConfigured,
            "{unwritable}"
        );
        assert!(
            unwritable.to_string().contains("epoch 1"),
            "the refusal names the epoch a person has to restore: {unwritable}"
        );
    }
    assert_eq!(
        files(&directory),
        before,
        "asking for a missing key made no key"
    );

    // The epoch whose key is still held is unaffected.
    assert_eq!(
        sealer(2).open(&second).expect("epoch two opens"),
        b"written at epoch two"
    );

    // The object was never touched: with the key back, it opens as it was written.
    std::fs::write(&file, &kept_copy).expect("the key is put back");
    assert_eq!(
        sealer(1).open(&first).expect("epoch one opens again"),
        b"written at epoch one"
    );
}
