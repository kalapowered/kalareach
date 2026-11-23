//! How much room the settings member takes from the recovery bundle, and who wins when there is
//! not enough.
//!
//! A service keeps a sealed bundle up to [`MAX_SEALED_RECOVERY_BUNDLE_BYTES`]. What a restore
//! verifies an archive with (the collections, the writers, the producers and the checkpoints) is
//! worth more than a person's saved settings, so the two are held to one policy, and every write of
//! the bundle seals through [`seal`]: [`BundleStore::commit`](super::BundleStore::commit),
//! [`PreparedRestore::record_checkpoint`](super::PreparedRestore::record_checkpoint) and the first
//! bundle of [`prepare_setup`](super::prepare_setup) alike.
//!
//! * **A settings write** ([`Write::Settings`]) is refused with [`RecoveryError::SettingsDoNotFit`]
//!   when the sealed bundle would leave less than [`TRUST_ROOM_BYTES`] of room under the bound, so
//!   the next writer, producer or checkpoint always has somewhere to go.
//! * **A trust write** ([`Write::Trust`]) that would not fit with the member present is sealed
//!   without it, and the caller is told the member was dropped. It is refused with
//!   [`RecoveryError::BundleTooLarge`] only when it does not fit without the member either.

use kr_crypto::secret::SymmetricKey;
use kr_protocol::archive::RecoveryBundle;
use kr_protocol::sync::MAX_SEALED_RECOVERY_BUNDLE_BYTES;

use crate::recovery::{RecoveryError, Result};

/// The room a settings write leaves under the sealed bound, for the trust entries that follow it.
pub const TRUST_ROOM_BYTES: u64 = 8 * 1024;

/// Whether a sealed bundle of `len` bytes is over the bound a service keeps.
const fn over_the_bound(len: u64) -> bool {
    len > MAX_SEALED_RECOVERY_BUNDLE_BYTES
}

/// What a write of the bundle is for, which decides who wins when the bundle is near its bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Write {
    /// A writer, a producer, a collection, a checkpoint, or the removal of the settings member.
    Trust,
    /// The settings member is set or changed.
    Settings,
}

/// A bundle sealed under the policy.
pub(super) struct Sealed {
    /// The ciphertext a service stores.
    pub(super) ciphertext: Vec<u8>,
    /// Whether the settings member was left out for want of room.
    pub(super) dropped_settings: bool,
}

/// Seals `bundle` under `key`, applying the policy.
///
/// `bundle` is changed when the member is dropped, so the caller holds what was written.
///
/// # Errors
///
/// Returns [`RecoveryError::SettingsDoNotFit`] for a settings write that would leave too little
/// room, [`RecoveryError::BundleTooLarge`] for a bundle that is over the bound without its member,
/// and the encoding errors of [`kr_crypto::archive::encrypt_recovery_bundle`].
pub(super) fn seal(
    key: &SymmetricKey,
    bundle: &mut RecoveryBundle,
    write: Write,
) -> Result<Sealed> {
    let ciphertext = kr_crypto::archive::encrypt_recovery_bundle(key, bundle)?;
    let len = ciphertext.len() as u64;
    match write {
        Write::Settings => {
            if len + TRUST_ROOM_BYTES > MAX_SEALED_RECOVERY_BUNDLE_BYTES {
                return Err(RecoveryError::SettingsDoNotFit {
                    len: ciphertext.len(),
                    limit: usize::try_from(MAX_SEALED_RECOVERY_BUNDLE_BYTES - TRUST_ROOM_BYTES)
                        .unwrap_or(usize::MAX),
                });
            }
            Ok(Sealed {
                ciphertext,
                dropped_settings: false,
            })
        }
        Write::Trust => {
            if !over_the_bound(len) {
                return Ok(Sealed {
                    ciphertext,
                    dropped_settings: false,
                });
            }
            let held_settings = bundle.device_settings.take().is_some();
            let ciphertext = if held_settings {
                kr_crypto::archive::encrypt_recovery_bundle(key, bundle)?
            } else {
                ciphertext
            };
            if over_the_bound(ciphertext.len() as u64) {
                return Err(RecoveryError::BundleTooLarge {
                    len: ciphertext.len(),
                    limit: MAX_SEALED_RECOVERY_BUNDLE_BYTES,
                });
            }
            Ok(Sealed {
                ciphertext,
                dropped_settings: held_settings,
            })
        }
    }
}

/// Whether a trust write of `bundle` is sealed without its settings member under `key`.
///
/// It is the question [`seal`] answers for a trust write, asked without writing anything: a
/// migration whose answer was lost uses it to tell a destination that left the member out because
/// the bundle would not have fitted from one that lost it for another reason.
///
/// # Errors
///
/// Returns the encoding errors of [`kr_crypto::archive::encrypt_recovery_bundle`].
pub(super) fn leaves_settings_out(key: &SymmetricKey, bundle: &RecoveryBundle) -> Result<bool> {
    if bundle.device_settings.is_none() {
        return Ok(false);
    }
    let ciphertext = kr_crypto::archive::encrypt_recovery_bundle(key, bundle)?;
    Ok(over_the_bound(ciphertext.len() as u64))
}
