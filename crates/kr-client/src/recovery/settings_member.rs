//! The device's settings as one member of the recovery bundle.
//!
//! Section 20 ¶10 lists what the bundle holds for a restore, and the list is not exclusive: the
//! bundle may also carry the owner device's configuration, the values a person chose on it. They
//! are not session content and they grant nothing, so the member follows the colour mode's rule: it
//! goes whether or not privacy mode is on. What the bundle carries is allowlisted values and
//! nothing else. It holds no key, no label, no membership, no revision, no device identifier and
//! no note of where an object stood on a sync service.
//!
//! The member is opaque to every reader of the bundle but the settings restore. The bundle holds
//! its bytes ([`kr_protocol::archive::RecoveryBundle::device_settings`]); a data restore, a
//! checkpoint write and a host's cover read and write them as they are, so a member no build can
//! read fails the settings restore alone.
//!
//! # The bytes
//!
//! A canonical KR-CBOR-1 map `{ values: { name: Text | Number | Flag }, pad: Bytes }`. `pad` is
//! zero bytes that bring the encoded length to a multiple of [`DEVICE_SETTINGS_BUCKET_BYTES`],
//! because the sealed bundle has no size bucket of its own and a colour mode of "dark", "light" or
//! "system" would otherwise differ by a byte. The most the encoded member may be is
//! [`MAX_DEVICE_SETTINGS_BYTES`], checked when it is written and again when it is read.

use std::collections::BTreeMap;

use kr_crypto::backup::{Admission, Material, may_back_up, may_restore};
use kr_protocol::scalars::Bytes;
use serde::{Deserialize, Serialize};

use crate::recovery::{MaterialName, RecoveryError, Result};
use crate::services::SyncPosition;
use crate::sync::SettingValue;

/// The most one encoded, padded settings member may be.
pub const MAX_DEVICE_SETTINGS_BYTES: usize = 8 * 1024;

/// The size the encoded member is padded up to a multiple of.
pub const DEVICE_SETTINGS_BUCKET_BYTES: usize = 1024;

/// The most a setting's name may be.
const MAX_NAME_BYTES: usize = 64;

/// What the member carries: the device's settings, by their stable names, and nothing else.
///
/// `Debug` shows how many there are and never a value: a setting is what a person chose.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct DeviceSettings {
    values: BTreeMap<String, SettingValue>,
}

impl std::fmt::Debug for DeviceSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeviceSettings")
            .field("values", &self.values.len())
            .finish()
    }
}

impl DeviceSettings {
    /// Settings from their values.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::SettingsUnusable`] for a name that is not a lowercase word of
    /// letters, digits and underscores.
    pub fn new(values: BTreeMap<String, SettingValue>) -> Result<Self> {
        if values.keys().any(|name| !is_a_name(name)) {
            return Err(RecoveryError::SettingsUnusable {
                what: "a setting has a name that is not a word",
            });
        }
        Ok(Self { values })
    }

    /// Returns the value of one setting.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&SettingValue> {
        self.values.get(name)
    }

    /// Returns every setting, by name.
    #[must_use]
    pub const fn values(&self) -> &BTreeMap<String, SettingValue> {
        &self.values
    }

    /// Whether the person has chosen nothing that is saved.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// The bytes as they are encoded.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    values: BTreeMap<String, SettingValue>,
    pad: Bytes,
}

fn is_a_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The table's answer, as a refusal that names the material and the reason.
const fn admitted(material: Material, admission: Admission) -> Result<()> {
    match admission {
        Admission::Allowed => Ok(()),
        Admission::Refused { because } => Err(RecoveryError::Refused {
            material: MaterialName(material),
            because,
        }),
    }
}

/// Encodes the settings as the member bytes, padded to the bucket.
///
/// # Errors
///
/// Returns [`RecoveryError::Refused`] when the table refuses device configuration for a backup and
/// [`RecoveryError::SettingsDoNotFit`] when the encoded member is over
/// [`MAX_DEVICE_SETTINGS_BYTES`].
pub fn encode_member(settings: &DeviceSettings) -> Result<Bytes> {
    admitted(
        Material::DeviceConfiguration,
        may_back_up(Material::DeviceConfiguration),
    )?;
    let limits = &kr_protocol::archive::RECOVERY_BUNDLE_LIMITS;
    let encode = |pad: usize| -> Result<Vec<u8>> {
        Ok(kr_cbor::to_canonical_vec_within(
            &Member {
                values: settings.values.clone(),
                pad: Bytes::new(vec![0; pad]),
            },
            limits,
        )?)
    };
    let bare = encode(0)?;
    // The pad's own length is encoded ahead of it, in one, two or three bytes, so the length that
    // lands on a bucket is found by trying each size of that header.
    let mut bucket =
        bare.len().div_ceil(DEVICE_SETTINGS_BUCKET_BYTES) * DEVICE_SETTINGS_BUCKET_BYTES;
    loop {
        for header in 1..=3_usize {
            // `bare` already holds the one-byte header of an empty pad.
            let Some(pad) = (bucket + 1).checked_sub(bare.len() + header) else {
                continue;
            };
            let header_of_pad = match pad {
                0..=23 => 1,
                24..=255 => 2,
                _ => 3,
            };
            if header_of_pad != header {
                continue;
            }
            let encoded = encode(pad)?;
            if encoded.len() == bucket {
                if encoded.len() > MAX_DEVICE_SETTINGS_BYTES {
                    return Err(RecoveryError::SettingsDoNotFit {
                        len: encoded.len(),
                        limit: MAX_DEVICE_SETTINGS_BYTES,
                    });
                }
                return Ok(Bytes::new(encoded));
            }
        }
        bucket += DEVICE_SETTINGS_BUCKET_BYTES;
        if bucket > MAX_DEVICE_SETTINGS_BYTES {
            return Err(RecoveryError::SettingsDoNotFit {
                len: bucket,
                limit: MAX_DEVICE_SETTINGS_BYTES,
            });
        }
    }
}

/// Decodes the member bytes the bundle holds.
///
/// # Errors
///
/// Returns [`RecoveryError::Refused`] when the table refuses device configuration for a restore
/// and [`RecoveryError::SettingsUnusable`] for bytes over [`MAX_DEVICE_SETTINGS_BYTES`], bytes that
/// are not the member in its canonical encoding and a name that is not a word.
pub fn decode_member(member: &Bytes) -> Result<DeviceSettings> {
    admitted(
        Material::DeviceConfiguration,
        may_restore(Material::DeviceConfiguration),
    )?;
    if member.as_slice().len() > MAX_DEVICE_SETTINGS_BYTES {
        return Err(RecoveryError::SettingsUnusable {
            what: "the saved settings are larger than a settings member may be",
        });
    }
    let decoded: Member = kr_cbor::from_canonical_slice(
        member.as_slice(),
        &kr_protocol::archive::RECOVERY_BUNDLE_LIMITS,
    )
    .map_err(|_| RecoveryError::SettingsUnusable {
        what: "the saved settings are not a settings member this build reads",
    })?;
    DeviceSettings::new(decoded.values)
}

/// What this device has chosen, as its settings file says.
///
/// A file that cannot be read is not a choice of nothing: [`Self::Unreadable`] keeps the member
/// the bundle holds, where [`Self::Values`] with no value in it clears it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalSettings {
    /// The file was read and these are the values it holds, none when the person chose nothing.
    Values(DeviceSettings),
    /// The file exists and could not be read.
    Unreadable,
}

/// What saving the settings did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSaved {
    /// The bundle already held these settings, so nothing was written.
    AlreadySaved,
    /// The bundle was written, and is now at this place.
    Saved {
        /// Where the service put the write.
        position: SyncPosition,
    },
}

/// What removing the settings from the bundle did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsRemoval {
    /// The member was taken out of the bundle, which is now at this place.
    Removed {
        /// Where the service put the write.
        position: SyncPosition,
    },
    /// The bundle held no settings, so nothing was written.
    NothingSaved,
}
