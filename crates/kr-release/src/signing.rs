//! The release manifest's signing and verification.

use std::collections::HashSet;
use std::num::NonZeroU64;

use kr_protocol::update::{MANIFEST_FILE, SignedMembers};
use tough::schema::key::Key;
use tough::schema::{Role, RoleType, Root, Signature, Signed};
use tough::sign::Sign;

/// A release manifest as the release keys sign it: the manifest's own JSON, whole, members this
/// build does not know included, so what is checked is exactly what was signed.
///
/// It is checked as The Update Framework checks a targets role: over its canonical JSON, by a
/// threshold of the keys the channel root names for that role.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Signable(pub SignedMembers);

impl Role for Signable {
    const TYPE: RoleType = RoleType::Targets;

    /// A release does not expire: what it is stays what it was signed as.
    fn expires(&self) -> jiff::Timestamp {
        jiff::Timestamp::MAX
    }

    fn version(&self) -> NonZeroU64 {
        NonZeroU64::MIN
    }

    fn filename(&self, _consistent_snapshot: bool) -> String {
        MANIFEST_FILE.to_owned()
    }
}

/// Why a signed document is not accepted.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The document is not a signed envelope.
    #[error("it is not a signed document: {0}")]
    Document(serde_json::Error),
    /// A role of the root names one key under two key identifiers.
    #[error("the root names one key under two identifiers for its {role} role")]
    ReusedKey {
        /// The role.
        role: &'static str,
    },
    /// Fewer distinct keys than the role's threshold signed.
    #[error("it is not signed by the number of keys the root names for the role")]
    Threshold,
}

/// Why a manifest could not be signed.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The members could not be put in canonical form.
    #[error("the manifest has no canonical form: {0}")]
    Canonical(String),
    /// A key could not name itself.
    #[error("a key could not state its identifier: {0}")]
    KeyId(String),
    /// A key refused to sign.
    #[error("a key could not sign: {0}")]
    Key(String),
}

/// A key as it is, whatever its description says: the kind of key and its decoded public bytes.
///
/// The Update Framework names a key by a digest of its description, so the spelling of the public
/// value (hexadecimal in either case), a member added to the description and the name of an
/// elliptic-curve key's type all change the name and leave the key as it was.
fn key_material(key: &Key) -> (&'static str, Vec<u8>) {
    match key {
        Key::Rsa { keyval, .. } => ("rsa", keyval.public.to_vec()),
        Key::Ed25519 { keyval, .. } => ("ed25519", keyval.public.to_vec()),
        Key::Ecdsa { keyval, .. } | Key::EcdsaOld { keyval, .. } => {
            ("ecdsa", keyval.public.to_vec())
        }
    }
}

/// Checks that no role of `root` names one key under two identifiers.
///
/// # Errors
///
/// Returns [`VerifyError::ReusedKey`] naming the first role that does.
pub fn check_root_keys(root: &Root) -> Result<(), VerifyError> {
    let mut roles: Vec<_> = root.roles.iter().collect();
    roles.sort_by_key(|(role, _)| role_name(**role));
    for (role, keys) in roles {
        let mut identifiers = HashSet::new();
        let mut material = HashSet::new();
        for identifier in &keys.keyids {
            if !identifiers.insert(identifier) {
                continue;
            }
            // A key the root does not describe is named by nothing a signature could be counted
            // against, so it stands for itself.
            let found = root
                .keys
                .get(identifier)
                .map_or_else(|| (role_name(*role), identifier.to_vec()), key_material);
            material.insert(found);
        }
        if material.len() != identifiers.len() {
            return Err(VerifyError::ReusedKey {
                role: role_name(*role),
            });
        }
    }
    Ok(())
}

const fn role_name(role: RoleType) -> &'static str {
    match role {
        RoleType::Root => "root",
        RoleType::Targets => "targets",
        RoleType::Snapshot => "snapshot",
        RoleType::Timestamp => "timestamp",
        RoleType::DelegatedTargets => "delegated targets",
    }
}

/// Checks a release manifest's document against `root`: that it is a signed envelope, that no role
/// of the root names one key twice, and that a threshold of the keys the root names for its targets
/// role signed it. Returns the members as the signer wrote them.
///
/// # Errors
///
/// Returns [`VerifyError`] for a document that is not an envelope, a root that reuses a key, or
/// signatures short of the threshold.
pub fn verify_manifest(root: &Root, document: &[u8]) -> Result<SignedMembers, VerifyError> {
    let signed: Signed<Signable> =
        serde_json::from_slice(document).map_err(VerifyError::Document)?;
    check_root_keys(root)?;
    root.verify_role(&signed)
        .map_err(|_| VerifyError::Threshold)?;
    Ok(signed.signed.0)
}

/// Checks that `signed` is signed by the root keys it names itself.
///
/// # Errors
///
/// Returns [`VerifyError`] when a role reuses a key or the signatures are short of the threshold.
pub fn verify_root_itself(signed: &Signed<Root>) -> Result<(), VerifyError> {
    verify_root_by(&signed.signed, signed)
}

/// Checks that `next` is signed by a threshold of the root keys `trusted` names.
///
/// # Errors
///
/// Returns [`VerifyError`] when `trusted` or `next` reuses a key in a role, or the signatures are
/// short of the threshold.
pub fn verify_root_by(trusted: &Root, next: &Signed<Root>) -> Result<(), VerifyError> {
    check_root_keys(trusted)?;
    check_root_keys(&next.signed)?;
    trusted
        .verify_role(next)
        .map_err(|_| VerifyError::Threshold)
}

/// Signs a manifest's members with each of `signers`, and returns the signed document.
///
/// Each signature is over the canonical JSON of the members, and names its key by the identifier
/// The Update Framework gives it.
///
/// # Errors
///
/// Returns [`SignError`] when the members have no canonical form, or a key cannot name itself or
/// sign.
pub async fn sign_manifest(
    members: &SignedMembers,
    signers: &[&dyn Sign],
) -> Result<String, SignError> {
    let role = Signable(members.clone());
    let canonical =
        Role::canonical_form(&role).map_err(|error| SignError::Canonical(error.to_string()))?;
    let random = aws_lc_rs::rand::SystemRandom::new();
    let mut signatures = Vec::with_capacity(signers.len());
    for signer in signers {
        let keyid = signer
            .tuf_key()
            .key_id()
            .map_err(|error| SignError::KeyId(error.to_string()))?;
        let signature = signer
            .sign(&canonical, &random)
            .await
            .map_err(|error| SignError::Key(error.to_string()))?;
        signatures.push(Signature {
            keyid,
            sig: signature.into(),
        });
    }
    serde_json::to_string_pretty(&serde_json::json!({
        "signed": members,
        "signatures": signatures,
    }))
    .map_err(|error| SignError::Canonical(error.to_string()))
}
