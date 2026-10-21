//! Signing a release, and checking that it was signed.
//!
//! A release's manifest, `release.json`, is signed by a threshold of the release keys the update
//! channel's root names for its targets role, in the envelope The Update Framework's metadata uses.
//! This crate is the one place that envelope is made and the one place it is read back: the host
//! that installs a release verifies it here, and the tool that builds one signs it here, so a
//! signature that verifies for one verifies for the other.
//!
//! What a signature covers is the manifest's own JSON, whole: every member the signer wrote, members
//! a reading build does not know included. The manifest's `_type`, `kalareach-release`, is inside
//! it, which keeps a signature over the channel's targets metadata, or over a plugin catalogue's,
//! from passing for one over a release.
//!
//! A threshold counts keys, not names for a key. The Update Framework names a key by a digest of
//! its description, so one public key described twice, once with a member added, has two names, and
//! one private key could answer for both. A root that names one key under two identifiers in a role
//! is refused here, before any signature is counted.

mod signing;

pub use signing::{
    SignError, Signable, VerifyError, check_root_keys, sign_manifest, verify_manifest,
    verify_root_by, verify_root_itself,
};
