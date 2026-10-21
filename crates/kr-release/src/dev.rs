//! Keys and a channel root made for one run, to sign what the run builds.
//!
//! A release is signed by a threshold of keys that the update channel's root names. The keys of the
//! channel live in hardware and on offline media, and nothing here touches them. A run that proves
//! the whole signing path makes a root and keys of its own, signs with them, and throws them away
//! with the run: a release they sign is trusted by no host.

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::Path;

use aws_lc_rs::signature::Ed25519KeyPair;
use tough::schema::{Role, RoleKeys, RoleType, Root, Signature, Signed};
use tough::sign::Sign;

use crate::refusal::{Refusal, Result};

/// Writes `root.json`, `root-key.pk8` and `targets-<n>.pk8` for each of `signers` keys that must
/// sign, in a directory that only its owner reads.
///
/// # Errors
///
/// Returns a refusal when the directory cannot be made or a file cannot be written.
pub fn write_keys(out: &Path, signers: u64) -> Result<()> {
    let threshold = NonZeroU64::new(signers)
        .ok_or_else(|| Refusal("a release is signed by at least one key".to_owned()))?;
    create_private(out)?;
    let random = aws_lc_rs::rand::SystemRandom::new();
    let make = |name: &str| -> Result<Ed25519KeyPair> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| Refusal("a key could not be made".to_owned()))?;
        write_private(&out.join(name), pkcs8.as_ref())?;
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| Refusal("a key could not be read back".to_owned()))
    };
    let root_key = make("root-key.pk8")?;
    let mut targets = Vec::new();
    for index in 1..=signers {
        targets.push(make(&format!("targets-{index}.pk8"))?);
    }

    let identifier = |pair: &Ed25519KeyPair| {
        Sign::tuf_key(pair)
            .key_id()
            .map_err(|error| Refusal(format!("a key has no identifier: {error}")))
    };
    let mut keys = HashMap::new();
    let root_id = identifier(&root_key)?;
    keys.insert(root_id.clone(), Sign::tuf_key(&root_key));
    let mut target_ids = Vec::new();
    for pair in &targets {
        let id = identifier(pair)?;
        keys.insert(id.clone(), Sign::tuf_key(pair));
        target_ids.push(id);
    }
    let one = NonZeroU64::MIN;
    let named = |ids: Vec<_>, threshold: NonZeroU64| RoleKeys {
        keyids: ids,
        threshold,
        _extra: HashMap::new(),
    };
    let mut roles = HashMap::new();
    roles.insert(RoleType::Root, named(vec![root_id.clone()], one));
    roles.insert(RoleType::Targets, named(target_ids, threshold));
    roles.insert(RoleType::Snapshot, named(vec![root_id.clone()], one));
    roles.insert(RoleType::Timestamp, named(vec![root_id.clone()], one));
    let root = Root {
        spec_version: "1.0.0".to_owned(),
        consistent_snapshot: false,
        version: one,
        expires: "2099-01-01T00:00:00Z"
            .parse()
            .map_err(|_| Refusal("the expiry is not a time".to_owned()))?,
        keys,
        roles,
        _extra: HashMap::new(),
    };
    let canonical = Role::canonical_form(&root)
        .map_err(|error| Refusal(format!("the root has no canonical form: {error}")))?;
    let signed = Signed {
        signatures: vec![Signature {
            keyid: root_id,
            sig: root_key.sign(&canonical).as_ref().to_vec().into(),
        }],
        signed: root,
    };
    let text = serde_json::to_string_pretty(&signed)
        .map_err(|error| Refusal(format!("the root is not JSON: {error}")))?;
    std::fs::write(out.join("root.json"), text)
        .map_err(|error| Refusal(format!("root.json cannot be written: {error}")))
}

fn create_private(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    let made = {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(directory)
    };
    #[cfg(not(unix))]
    let made = std::fs::create_dir_all(directory);
    made.map_err(|error| Refusal(format!("{} cannot be made: {error}", directory.display())))
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    let written = {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut file| file.write_all(contents))
    };
    #[cfg(not(unix))]
    let written = std::fs::write(path, contents);
    written.map_err(|error| Refusal(format!("{} cannot be written: {error}", path.display())))
}
