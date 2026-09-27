//! The check that stands between this product and a substituted model: a downloaded file is used
//! only when it is the file its signed profile records, by size and by digest.

use kr_crypto::keys::AuthorisationKeyPair;
use kr_describe::error::DescribeError;
use kr_describe::profile::catalogue::{self, Catalogue};
use kr_describe::profile::{ModelProfile, ProfileDocument, ProfileTrust, SignedProfile};
use kr_describe_model::assets::verify_file;

/// The default profile this build ships.
fn default_profile() -> ModelProfile {
    Catalogue::builtin()
        .expect("this build ships profiles it can run")
        .default_profile()
        .clone()
}

/// Signs a profile document with a test key, which is the only way to get a [`ModelProfile`].
fn sign(document: &str, keys: &AuthorisationKeyPair) -> SignedProfile {
    let document = ProfileDocument::new(document.as_bytes().to_vec());
    let transcript = document.transcript().expect("a transcript");
    let signature = kr_crypto::sign::sign(keys, &transcript).expect("a signature");
    SignedProfile {
        document,
        key: *keys.public(),
        signature,
    }
}

/// KR-REQ-22.09: an asset that is not the recorded file is refused by size and by digest.
#[test]
fn an_asset_that_is_not_the_recorded_file_is_refused() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let profile = default_profile();
    let asset = &profile.assets()[0];
    let path = directory.path().join(&asset.file_name);
    std::fs::write(&path, b"not two gigabytes of weights").expect("a file");
    assert!(matches!(
        verify_file(asset, &path),
        Err(DescribeError::AssetSizeMismatch { .. })
    ));
    assert!(matches!(
        verify_file(asset, &directory.path().join("absent.gguf")),
        Err(DescribeError::AssetUnreadable { .. })
    ));

    // A file larger than one digest block, so the streaming path is the one under test. The
    // profile is rewritten to describe this file exactly, and then one byte of it is changed.
    let body = vec![0x5a_u8; (1 << 20) + 4096];
    let digest = {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(&body);
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let keys = AuthorisationKeyPair::generate().expect("a keypair");
    let trust = ProfileTrust::new(vec![*keys.public()]);
    let document = catalogue::DEFAULT_PROFILE_DOCUMENT
        .replace(&asset.sha256, &digest)
        .replace(&asset.bytes.to_string(), &body.len().to_string());
    let rewritten = trust
        .verify(&sign(&document, &keys))
        .expect("a profile over the file this test wrote");
    let big = directory.path().join(&rewritten.assets()[0].file_name);
    std::fs::write(&big, &body).expect("a large file");
    verify_file(&rewritten.assets()[0], &big)
        .expect("a file that matches across several blocks verifies");

    let mut changed = body.clone();
    changed[(1 << 20) + 1] = 0x5b;
    std::fs::write(&big, &changed).expect("a changed file");
    assert!(matches!(
        verify_file(&rewritten.assets()[0], &big),
        Err(DescribeError::AssetDigestMismatch { .. })
    ));
}
