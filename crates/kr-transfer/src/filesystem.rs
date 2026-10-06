//! Which filesystem a recorded directory is on, and the one rule that decides whether the
//! directory found where it was recorded is the recorded one.
//!
//! A directory's device number and inode name it while the filesystem stays mounted. The device
//! number is not the filesystem's own: it names one mounting, so a container's root filesystem
//! comes back under another number when the container starts again after another has started,
//! and a different filesystem can be given the number a detached one had. The inode says which
//! object it is within a filesystem, and two filesystems built in the same order give their
//! directories the same inodes. So a store that records a directory records, beside its device
//! number and inode, an identity of the filesystem that survives a mounting and differs between
//! two filesystems:
//!
//! * **Linux** records the filesystem id `statfs` reports. A container's overlay root keeps it
//!   across a stop and a start, with another container started in between, while its device
//!   number moves; two tmpfs mounted one after the other at one path get one device number and
//!   two ids. The mount id of `statx` is not recorded: every mounting has its own, so it would
//!   refuse the container that starts again. Some filesystems on a block device (XFS, FAT,
//!   exFAT, ISO 9660, squashfs, f2fs) report the device's own number as their id, which names no
//!   filesystem, so a directory on one is taken for a directory on a filesystem that reports
//!   none.
//! * **macOS** records the volume's UUID. `statfs` reports the device in `f_fsid`, so a disk
//!   image attached in place of another one that was detached, which is given the same device
//!   number, reports the same `f_fsid`; the volume UUID differs between the two and is the same
//!   every time one volume is attached.
//! * **Windows** records the volume serial number, the 64 bits `FILE_ID_INFO` carries, with the
//!   directory's own 128-bit file id, whole, which the 64-bit file index of the inode does not
//!   always hold, so a volume whose ids need more than 64 bits does not take one directory for
//!   another. A volume keeps its serial wherever it is mounted, which is why a device number there
//!   never needed a renumbering, and a record found under another device number there is another
//!   volume's; a volume that keeps no 128-bit ids is given the 32-bit serial the device number
//!   holds. This was measured on NTFS only. A directory keeps its 128-bit id when it is renamed
//!   into another directory on NTFS, which a publication relies on; whether it does on ReFS has
//!   not been measured, and on a ReFS volume that changes it a publication would not recognise the
//!   directory it moved.
//!
//! An overlay reports the id of the filesystem its upper directory is on unless it has a
//! persistent UUID of its own, so overlays over one backing filesystem share an id: one mounted
//! with `uuid=null` or `uuid=off` does, and so does an existing one that was never mounted with
//! `uuid=on` under the default `uuid=auto` (the kernel's overlayfs documentation). A new overlay
//! mounted by default on Linux 7.0 (the build box) reports one of its own, which is what a
//! container's root filesystem has there; older kernels were not measured. What an overlay
//! reports of its upper filesystem is that filesystem's own id: where that is one of the
//! filesystems that report their device's number (XFS, for example), a directory on the overlay is
//! refused when its disk comes back under another number.
//!
//! A copy of a whole filesystem carries its identity with it (a block-for-block copy of a disk or of
//! a disk image keeps its UUID, its serial number and its inodes), so a directory on such a copy is
//! the recorded one for this purpose, as it is for every program that tells filesystems apart by
//! the identity they carry. What this tells apart is two filesystems that were made separately.
//!
//! A filesystem that reports no such identity records none, and a directory on it is decided by
//! the device number and the inode alone, as every directory was before one was recorded. Apart
//! from a copy, that is the only case in which a different filesystem that gives a directory its
//! recorded inode is taken for the recorded one.
//!
//! One function, `settle`, decides every comparison of a recorded directory with the directory
//! found where it was recorded. The services that persist one directory identity call it through
//! [`crate::AuthorisedDirectory::check_recorded`] and do not decide for themselves.

use std::fmt;

use crate::authority::ObjectIdentity;

/// The identity of the filesystem an object is on, as it is recorded.
///
/// Twenty-four bytes, which is what the longest of the platforms' identities needs: a Windows
/// volume's 64-bit serial number and the directory's 128-bit file id (so on Windows the value also
/// names the directory it was read for). The value says which filesystem it is and nothing about
/// where it is mounted. It is not a secret and it is not
/// a credential: it tells two filesystems apart, as a device number does for as long as the
/// filesystem stays mounted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FilesystemId([u8; FilesystemId::LEN]);

impl FilesystemId {
    /// What a filesystem that reports no identity of its own is given.
    pub const NONE: Self = Self([0; Self::LEN]);

    /// The length of an identity in bytes.
    pub const LEN: usize = 24;

    /// Returns the identity that these bytes make.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// Returns the identity that the first eight bytes make, for a platform whose own identity is
    /// eight bytes long.
    #[must_use]
    pub const fn from_u64(value: u64) -> Self {
        let mut bytes = [0_u8; Self::LEN];
        let value = value.to_le_bytes();
        let mut index = 0;
        while index < value.len() {
            bytes[index] = value[index];
            index += 1;
        }
        Self(bytes)
    }

    /// Returns the identity that these bytes make, zero filled to the length of an identity, for a
    /// platform whose own identity is shorter. Bytes past the length of an identity are ignored.
    #[must_use]
    pub fn from_prefix(bytes: &[u8]) -> Self {
        let mut whole = [0_u8; Self::LEN];
        let kept = bytes.len().min(Self::LEN);
        whole[..kept].copy_from_slice(&bytes[..kept]);
        Self(whole)
    }

    /// Returns the bytes of this identity.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }

    /// Returns the identity that a stored slice holds, or `None` when it is not as long as an
    /// identity.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        <[u8; Self::LEN]>::try_from(bytes).ok().map(Self)
    }

    /// Returns true when the filesystem reports no identity of its own.
    #[must_use]
    pub fn is_none(&self) -> bool {
        *self == Self::NONE
    }

    /// Reads back an identity as [`fmt::Display`] writes it.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != Self::LEN * 2 || !text.is_ascii() {
            return None;
        }
        let mut bytes = [0_u8; Self::LEN];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for FilesystemId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl rusqlite::types::ToSql for FilesystemId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::Borrowed(
            rusqlite::types::ValueRef::Blob(&self.0),
        ))
    }
}

impl rusqlite::types::FromSql for FilesystemId {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        let blob = value.as_blob()?;
        Self::from_slice(blob).ok_or(rusqlite::types::FromSqlError::InvalidBlobSize {
            expected_size: Self::LEN,
            blob_size: blob.len(),
        })
    }
}

/// A directory's identity as a store records it: the object, and the filesystem it was on.
///
/// A record written before filesystem identities were recorded holds the object alone, and its
/// first successful check records the filesystem ([`Settled::Revised`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordedIdentity {
    /// The directory's device number and inode, as they were when it was recorded.
    pub object: ObjectIdentity,
    /// The filesystem it was on, or `None` for a record written before one was recorded.
    pub filesystem: Option<FilesystemId>,
}

impl RecordedIdentity {
    /// Returns the identity a record holds when it carries no filesystem: what a record written
    /// before filesystem identities were recorded holds.
    #[must_use]
    pub const fn without_filesystem(object: ObjectIdentity) -> Self {
        Self {
            object,
            filesystem: None,
        }
    }

    /// Returns the identity that the three stored parts make.
    #[must_use]
    pub const fn from_parts(device: u64, file_id: u64, filesystem: Option<FilesystemId>) -> Self {
        Self {
            object: ObjectIdentity { device, file_id },
            filesystem,
        }
    }
}

impl fmt::Display for RecordedIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.object)
    }
}

/// What the directory found where an identity was recorded says about the record, when it is the
/// recorded directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Settled {
    /// The directory is the recorded one, and the record is as the directory is.
    AsRecorded,
    /// The directory is the recorded one, and its record is to be replaced by what it is now: its
    /// filesystem is numbered differently from when the record was made, or the record was made
    /// before filesystems were recorded.
    ///
    /// The holder of the record replaces `was` by `now` where it keeps it, only while the record
    /// still carries `was`, and in the transaction that moves whatever else it recorded on the
    /// same filesystem under the number it had ([`Self::carried`]).
    Revised {
        /// The identity the record carries.
        was: RecordedIdentity,
        /// The identity the directory has now.
        now: RecordedIdentity,
    },
}

impl Settled {
    /// Returns what an object recorded on the same filesystem as the directory is under the
    /// numbering the filesystem has now.
    ///
    /// An object is on the directory's filesystem when its recorded device number is the one the
    /// directory's record carried. Its inode does not change with the number.
    #[must_use]
    pub const fn carried(&self, recorded: ObjectIdentity) -> ObjectIdentity {
        match self {
            Self::Revised { was, now } if recorded.device == was.object.device => ObjectIdentity {
                device: now.object.device,
                file_id: recorded.file_id,
            },
            Self::AsRecorded | Self::Revised { .. } => recorded,
        }
    }

    /// Returns the revision, when the record is to be replaced.
    #[must_use]
    pub const fn revision(&self) -> Option<(RecordedIdentity, RecordedIdentity)> {
        match self {
            Self::AsRecorded => None,
            Self::Revised { was, now } => Some((*was, *now)),
        }
    }

    /// Returns what `recorded`, the identity this settled, is once the revision is made.
    #[must_use]
    pub const fn current(&self, recorded: RecordedIdentity) -> RecordedIdentity {
        match self {
            Self::Revised { now, .. } => *now,
            Self::AsRecorded => recorded,
        }
    }
}

/// Decides whether the directory found where an identity was recorded is the recorded one.
///
/// `found` is the directory's device number and inode, `found_filesystem` the filesystem it is
/// on, and `above` the device number of the directory it is in, which is read only when it is
/// needed. `None` says it is not the recorded directory.
///
/// The inode decides which object it is, and the filesystem decides which filesystem it is on. A
/// directory under another device number is the recorded one when the filesystem is the recorded
/// one and the directory is on the filesystem of the directory above it, which a mount over it
/// is not. A record that holds no usable filesystem, because it was made before one was
/// recorded or because the filesystem then reported none, is decided as every record was: by the
/// exact device number and inode, or by the inode alone on the filesystem of the directory above
/// it. The filesystem found then becomes the record's.
///
/// Remove the reading of a record without a usable filesystem, and the columns each store adds
/// for it, once no supported upgrade starts from a store written before filesystems were
/// recorded; a record that no use has settled by then is refused.
#[must_use]
pub(crate) fn settle(
    expected: RecordedIdentity,
    found: ObjectIdentity,
    found_filesystem: FilesystemId,
    above: impl FnOnce() -> Option<u64>,
) -> Option<Settled> {
    if expected.object.file_id != found.file_id {
        return None;
    }
    if let Some(recorded) = expected.filesystem
        && !recorded.is_none()
        && recorded != found_filesystem
    {
        return None;
    }
    if expected.object.device != found.device && above() != Some(found.device) {
        return None;
    }
    let now = RecordedIdentity {
        object: found,
        filesystem: Some(found_filesystem),
    };
    Some(if expected == now {
        Settled::AsRecorded
    } else {
        Settled::Revised { was: expected, now }
    })
}

/// Returns the identity of the filesystem an open directory is on.
///
/// # Errors
///
/// Returns the operating system's error when the handle cannot be asked.
#[cfg(target_os = "linux")]
pub(crate) fn filesystem_of(directory: &cap_std::fs::Dir) -> std::io::Result<FilesystemId> {
    use std::os::fd::AsFd as _;

    use cap_fs_ext::MetadataExt as _;

    // The 64 bits `statfs` reports as `f_fsid`; a filesystem that reports none gives zero.
    let reported = rustix::fs::fstatvfs(directory.as_fd())?.f_fsid;
    Ok(identity_from_statfs(
        reported,
        directory.dir_metadata()?.dev(),
    ))
}

/// Returns the identity a `statfs` id makes, given the device number of a directory on the same
/// filesystem.
///
/// Some filesystems on a block device (XFS, FAT, exFAT, ISO 9660, squashfs, f2fs) report the number
/// of that device as their id, and a number that is the device's says nothing about the filesystem:
/// the same disk comes back under another number when it is attached to another port, and another
/// filesystem on the same device is given the same one. Such a filesystem reports no identity of
/// its own, and a directory on it is decided by the numbers alone.
#[cfg(any(target_os = "linux", test))]
const fn identity_from_statfs(reported: u64, device: u64) -> FilesystemId {
    if reported == device {
        FilesystemId::NONE
    } else {
        FilesystemId::from_u64(reported)
    }
}

/// Returns the identity of the filesystem an open directory is on.
///
/// # Errors
///
/// Returns the operating system's error when the handle cannot be asked.
#[cfg(target_os = "macos")]
pub(crate) fn filesystem_of(directory: &cap_std::fs::Dir) -> std::io::Result<FilesystemId> {
    use std::os::fd::AsFd as _;

    crate::apple::volume_uuid(directory.as_fd())
}

/// Returns the identity of the filesystem an open directory is on.
///
/// # Errors
///
/// Returns the operating system's error when the handle cannot be asked.
#[cfg(windows)]
pub(crate) fn filesystem_of(directory: &cap_std::fs::Dir) -> std::io::Result<FilesystemId> {
    use cap_fs_ext::MetadataExt as _;
    use std::os::windows::io::AsHandle as _;

    // The 64-bit serial the id query carries and the directory's own 128-bit id, whole: the 64-bit
    // file index of its inode is not always the lower half of it. Where the volume keeps no such ids
    // (it says so), the 32-bit serial the device number holds. Any other failure is a failure and
    // is not recorded as the volume's identity, because a later success would then be another one.
    match crate::windows::file_id(directory.as_handle()) {
        Ok(found) => {
            let mut bytes = [0_u8; FilesystemId::LEN];
            bytes[..8].copy_from_slice(&found.volume.to_le_bytes());
            bytes[8..].copy_from_slice(&found.id);
            Ok(FilesystemId::from_bytes(bytes))
        }
        Err(error) if crate::windows::gives_no_file_id(&error) => {
            Ok(FilesystemId::from_u64(directory.dir_metadata()?.dev()))
        }
        Err(error) => Err(error),
    }
}

/// Returns the identity of the filesystem an open directory is on, which this platform does not
/// report.
///
/// # Errors
///
/// Never fails.
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) fn filesystem_of(_directory: &cap_std::fs::Dir) -> std::io::Result<FilesystemId> {
    Ok(FilesystemId::NONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn object(device: u64, file_id: u64) -> ObjectIdentity {
        ObjectIdentity { device, file_id }
    }

    const FIRST: FilesystemId = FilesystemId::from_u64(0x1111);
    const SECOND: FilesystemId = FilesystemId::from_u64(0x2222);

    fn recorded(device: u64, file_id: u64, filesystem: Option<FilesystemId>) -> RecordedIdentity {
        RecordedIdentity::from_parts(device, file_id, filesystem)
    }

    #[test]
    fn a_directory_on_the_recorded_filesystem_under_the_recorded_numbers_is_as_recorded() {
        assert_eq!(
            settle(
                recorded(7, 42, Some(FIRST)),
                object(7, 42),
                FIRST,
                || unreachable!("the device is the recorded one")
            ),
            Some(Settled::AsRecorded)
        );
    }

    #[test]
    fn another_filesystem_that_gives_the_directory_its_device_and_inode_is_not_the_recorded_one() {
        // A filesystem attached in place of another one is given the device number the first had,
        // and a filesystem built in the same order gives its directories the same inodes.
        assert_eq!(
            settle(
                recorded(7, 42, Some(FIRST)),
                object(7, 42),
                SECOND,
                || Some(7)
            ),
            None
        );
    }

    #[test]
    fn the_recorded_filesystem_under_another_device_number_is_the_recorded_one() {
        let now = recorded(9, 42, Some(FIRST));
        let was = recorded(7, 42, Some(FIRST));
        assert_eq!(
            settle(was, object(9, 42), FIRST, || Some(9)),
            Some(Settled::Revised { was, now })
        );
    }

    #[test]
    fn a_directory_that_is_not_on_the_filesystem_of_the_one_above_it_is_not_the_recorded_one() {
        // Mounted over, or its parent cannot be read: the recorded filesystem is not enough.
        for above in [Some(8), None] {
            assert_eq!(
                settle(recorded(7, 42, Some(FIRST)), object(9, 42), FIRST, || above),
                None,
                "{above:?}"
            );
        }
    }

    #[test]
    fn another_inode_is_never_the_recorded_directory() {
        for filesystem in [Some(FIRST), Some(FilesystemId::NONE), None] {
            assert_eq!(
                settle(recorded(7, 42, filesystem), object(7, 43), FIRST, || Some(
                    7
                )),
                None
            );
        }
    }

    #[test]
    fn a_record_without_a_filesystem_is_decided_as_it_was_before_one_was_recorded() {
        // The exact device and inode, or the inode on the filesystem of the directory above, and
        // the filesystem found becomes the record's.
        let was = recorded(7, 42, None);
        assert_eq!(
            settle(was, object(7, 42), FIRST, || unreachable!("same device")),
            Some(Settled::Revised {
                was,
                now: recorded(7, 42, Some(FIRST))
            })
        );
        assert_eq!(
            settle(was, object(9, 42), FIRST, || Some(9)),
            Some(Settled::Revised {
                was,
                now: recorded(9, 42, Some(FIRST))
            })
        );
        assert_eq!(settle(was, object(9, 42), FIRST, || Some(8)), None);
        assert_eq!(settle(was, object(9, 43), FIRST, || Some(9)), None);
    }

    #[test]
    fn a_filesystem_that_reported_none_is_decided_by_the_numbers_until_it_reports_one() {
        let was = recorded(7, 42, Some(FilesystemId::NONE));
        assert_eq!(
            settle(was, object(7, 42), FilesystemId::NONE, || unreachable!(
                "same device"
            )),
            Some(Settled::AsRecorded)
        );
        assert_eq!(
            settle(was, object(7, 42), FIRST, || unreachable!("same device")),
            Some(Settled::Revised {
                was,
                now: recorded(7, 42, Some(FIRST))
            })
        );
        assert_eq!(
            settle(was, object(9, 42), FilesystemId::NONE, || Some(8)),
            None
        );
    }

    #[test]
    fn a_filesystem_that_stopped_reporting_its_identity_is_not_the_recorded_one() {
        assert_eq!(
            settle(
                recorded(7, 42, Some(FIRST)),
                object(7, 42),
                FilesystemId::NONE,
                || Some(7)
            ),
            None
        );
    }

    #[test]
    fn the_objects_on_a_renumbered_filesystem_are_carried_to_its_new_number() {
        let revised = Settled::Revised {
            was: recorded(7, 42, Some(FIRST)),
            now: recorded(9, 42, Some(FIRST)),
        };
        assert_eq!(revised.carried(object(7, 99)), object(9, 99));
        // An object recorded on another filesystem keeps what it was recorded under.
        assert_eq!(revised.carried(object(5, 99)), object(5, 99));
        assert_eq!(Settled::AsRecorded.carried(object(7, 99)), object(7, 99));
    }

    #[test]
    fn a_statfs_id_that_is_the_devices_own_number_is_no_identity() {
        assert_eq!(identity_from_statfs(0xfd00, 0xfd00), FilesystemId::NONE);
        assert_eq!(identity_from_statfs(0, 0xfd00), FilesystemId::NONE);
        assert_eq!(
            identity_from_statfs(0x1f23_9642_b31c_fc7d, 55),
            FilesystemId::from_u64(0x1f23_9642_b31c_fc7d)
        );
    }

    #[test]
    fn an_identity_reads_back_as_it_is_written() {
        for id in [
            FilesystemId::NONE,
            FIRST,
            FilesystemId::from_bytes([0xab; FilesystemId::LEN]),
        ] {
            assert_eq!(FilesystemId::from_hex(&id.to_string()), Some(id));
            assert_eq!(FilesystemId::from_slice(id.as_bytes()), Some(id));
        }
        assert_eq!(FilesystemId::from_hex("11"), None);
        assert_eq!(
            FilesystemId::from_hex(&"zz".repeat(FilesystemId::LEN)),
            None
        );
        assert_eq!(FilesystemId::from_slice(&[1, 2, 3]), None);
    }
}
