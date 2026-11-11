//! The identity of a file or directory on a volume: which volume, and which object on it.
//!
//! The walk, the private root and the journal name an object by this key and never by a path, so
//! that a rename, a link or a replaced name cannot change which object an action reaches. The
//! identifier has the 128 bits that every file system of the platform can fill; NTFS fills the
//! low 64 and leaves the rest zero.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A volume's serial number and an object's 128-bit identifier on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileKey {
    /// The serial number of the volume the object is on.
    pub volume_serial: u64,
    /// The object's identifier on that volume.
    pub file_id: [u8; 16],
}

impl FileKey {
    /// A key for an NTFS object, whose identifier is a 64-bit reference.
    #[must_use]
    pub fn ntfs(volume_serial: u64, reference: u64) -> FileKey {
        let mut file_id = [0_u8; 16];
        file_id[..8].copy_from_slice(&reference.to_le_bytes());
        FileKey {
            volume_serial,
            file_id,
        }
    }
}

impl fmt::Display for FileKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:016x}:{}",
            self.volume_serial,
            hex::encode(self.file_id)
        )
    }
}

/// The key as text, so that a journal row stays readable and one field wide.
impl Serialize for FileKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for FileKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<FileKey, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The text is not a key.
#[derive(Debug, thiserror::Error)]
#[error("not a file key: {0}")]
pub struct ParseError(String);

impl std::str::FromStr for FileKey {
    type Err = ParseError;

    fn from_str(text: &str) -> Result<FileKey, ParseError> {
        let bad = || ParseError(text.to_owned());
        let (volume, id) = text.split_once(':').ok_or_else(bad)?;
        let volume_serial = u64::from_str_radix(volume, 16).map_err(|_| bad())?;
        let bytes = hex::decode(id).map_err(|_| bad())?;
        let file_id: [u8; 16] = bytes.try_into().map_err(|_| bad())?;
        Ok(FileKey {
            volume_serial,
            file_id,
        })
    }
}
