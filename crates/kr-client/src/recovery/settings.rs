//! This device's settings, as a recovery-enabled archive carries them and a fresh restore puts them
//! back.
//!
//! Section 20: *recovery restores data and device configuration, then requires fresh
//! owner-authorised host pairing*. The settings object is device configuration
//! ([`Material::DeviceConfiguration`]), and it is the whole of what these two paths carry. What
//! stays out is named, because each would be a way round a rule that holds everywhere else:
//!
//! | Never carried | Why |
//! | --- | --- |
//! | A settings collection's key, at any epoch | The recovery seed opens the archive, so a key inside it would make the seed a way into the collection. A device reads the collection only through its own wrap in a key record, once a member has authorised it. The table refuses [`Material::SyncCollectionKey`] both ways. |
//! | The collection's key records, and this device's membership of it | Both say who may read the collection, which is authority, and restored settings cannot overwrite authority. |
//! | Where the object stood on the sync service | A restored device is a new installation with keys of its own. A note carried over from the old one would compare against a place on a service the restored object never reached. |
//!
//! # Export
//!
//! [`export_settings`] reads the device's own settings object from its sync store and hands the
//! archive producer its plaintext, to be carried under [`SETTINGS_FILENAME`]. It asks the table
//! for the material it carries, and it refuses while privacy mode is on: section 24 disables
//! backup production as it disables sync production. The export names the privacy generation it
//! was read under, so the producer publishes the archive only while that generation is in force.
//!
//! # Import
//!
//! [`import_settings`] takes one member a restore opened, with the material the archive says it
//! is. It asks the table first, so a refused kind is refused with its reason before a byte of it is
//! read. It imports device configuration and nothing else, reads the bytes as a settings object
//! under the store's own limits, and writes that object as this device's own, into a store that
//! holds neither the object nor a note of where it stood. It writes no key, no key record, no
//! membership and no note. A restored device therefore holds no collection: the owner pairs it with
//! a host again, and it then joins a collection a member shares with it, or starts one with these
//! settings.

use kr_crypto::backup::{Admission, Material, RestoreLimits, may_back_up, may_restore};
use kr_crypto::secret::SecretVec;
use kr_protocol::ids::SyncObjectId;
use kr_protocol::sync::SyncObjectKind;

use crate::recovery::{RecoveryError, Result};
use crate::sync::{SyncObject, SyncStore};

/// The name a recovery-enabled archive carries this device's settings object under.
///
/// Filenames live inside the encrypted manifest, so the name tells a restore what a member is
/// without telling the service anything.
pub const SETTINGS_FILENAME: &str = "device-configuration/settings.cbor";

/// This device's settings object, ready for an archive producer to stage.
///
/// The plaintext is the object's canonical encoding and is cleared when this is dropped. Its
/// `Debug` names the object and the length, and never the settings.
#[derive(Debug)]
pub struct ExportedSettings {
    object_id: SyncObjectId,
    produced_under: u64,
    plaintext: SecretVec,
}

impl ExportedSettings {
    /// What this member is, which is what a restore asks the table about.
    pub const MATERIAL: Material = Material::DeviceConfiguration;

    /// The material this member is.
    #[must_use]
    pub const fn material(&self) -> Material {
        Self::MATERIAL
    }

    /// The name the archive carries it under.
    #[must_use]
    pub const fn filename(&self) -> &'static str {
        SETTINGS_FILENAME
    }

    /// The settings object it is.
    #[must_use]
    pub const fn object_id(&self) -> SyncObjectId {
        self.object_id
    }

    /// The privacy generation it was read under.
    ///
    /// A producer publishes the archive only while this generation is still in force, which is
    /// section 24's rule that no late old-generation result is published.
    #[must_use]
    pub const fn produced_under(&self) -> u64 {
        self.produced_under
    }

    /// The bytes the producer encrypts.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        self.plaintext.expose()
    }
}

/// What a restore put back: this device's settings, as its own, and nothing that grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportedSettings {
    /// The settings object, now this device's own.
    pub object_id: SyncObjectId,
    /// What a restore still cannot do, whatever it put back.
    pub limits: RestoreLimits,
}

impl ImportedSettings {
    /// The sentence a restore shows once the settings are back.
    #[must_use]
    pub fn describe(&self) -> String {
        "Your settings are back on this device. To sync them, pair it with the host again and \
         confirm the pairing as the owner, then join the settings another of your devices shares \
         or start syncing them from here."
            .to_owned()
    }
}

/// Reads this device's settings object for a recovery-enabled archive.
///
/// # Errors
///
/// Returns [`RecoveryError::Sync`] with [`crate::sync::SyncError::Fenced`] while privacy mode is
/// on and with [`crate::sync::SyncError::Unknown`] when no such object is stored,
/// [`RecoveryError::NotSettings`] when the object is not settings, and [`RecoveryError::Cbor`] when
/// it cannot be encoded.
pub fn export_settings(store: &SyncStore, object_id: SyncObjectId) -> Result<ExportedSettings> {
    admitted(
        ExportedSettings::MATERIAL,
        may_back_up(ExportedSettings::MATERIAL),
    )?;
    let (object, produced_under) = store.read_for_backup(object_id)?;
    if object.kind() != SyncObjectKind::Settings {
        return Err(RecoveryError::NotSettings {
            what: "it is where a client was looking, which is not device configuration",
        });
    }
    Ok(ExportedSettings {
        object_id,
        produced_under,
        plaintext: SecretVec::new(kr_cbor::to_canonical_vec(&object)?),
    })
}

/// Puts back one archive member a restore opened, as this device's own settings.
///
/// `material` is what the archive says the member is. Every kind is asked about, and only device
/// configuration is imported: a kind the table refuses is refused with its reason, and one it
/// allows that is not settings is another path's.
///
/// # Errors
///
/// Returns [`RecoveryError::Refused`] for a kind the table refuses, [`RecoveryError::NotSettings`]
/// for another kind or for bytes that are not a settings object, and [`RecoveryError::Sync`] with
/// [`crate::sync::SyncError::AlreadyHeld`] when this device already holds the object or a note of
/// where it stood.
pub fn import_settings(
    store: &SyncStore,
    material: Material,
    plaintext: &[u8],
) -> Result<ImportedSettings> {
    admitted(material, may_restore(material))?;
    if material != ExportedSettings::MATERIAL {
        return Err(RecoveryError::NotSettings {
            what: "the archive does not carry it as device configuration",
        });
    }
    // The object's own reader and limits: a member that is not a settings object in this encoding
    // is refused whole, and what it held is not repeated in the refusal.
    let object: SyncObject = kr_cbor::from_canonical_slice(plaintext, &kr_cbor::Limits::DEFAULT)
        .map_err(|_| RecoveryError::NotSettings {
            what: "its bytes are not a settings object",
        })?;
    if object.kind() != SyncObjectKind::Settings {
        return Err(RecoveryError::NotSettings {
            what: "it is where a client was looking, which is not device configuration",
        });
    }
    store.put_restored(&object)?;
    Ok(ImportedSettings {
        object_id: object.object_id,
        limits: RestoreLimits,
    })
}

/// The table's answer, as a refusal that names the material and the reason.
const fn admitted(material: Material, admission: Admission) -> Result<()> {
    match admission {
        Admission::Allowed => Ok(()),
        Admission::Refused { because } => Err(RecoveryError::Refused { material, because }),
    }
}
