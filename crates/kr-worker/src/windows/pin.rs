//! Holding the directory a command's program works in, so that the directory a launch is granted is
//! the directory the program is in.
//!
//! A program started with a current directory resolves that string when its loader opens the
//! directory, which is after this host has decided what to grant, so a directory renamed away and
//! replaced at that path in between puts the program somewhere other than where the grant was
//! made. The kernel's own record of a process's directory cannot be read in time, and reading it
//! from the process's handle table races a handle number the program can free and reuse. What
//! cannot race is holding the path: a handle on every component of it, from the drive's root to the
//! directory itself, opened without sharing deletion. A rename, a replace or a delete of any of
//! them is then refused with a sharing violation, so the string names the same object for as long
//! as the pin is held, and the program's loader opens that object.
//!
//! A pin is taken only of what it can hold. The path is an absolute `X:\...` path by its shape (a
//! network path, a verbatim path, a device path or a relative one is refused before anything is
//! resolved), on a drive that names a local volume and not another path (a `subst` drive resolves
//! through a path that can change), on a volume that identifies its objects by the 64-bit index the
//! directory grant compares by. Each component is opened without following a link, and a link of
//! any kind at any component (a junction, a symbolic link, a mount point), or a file, refuses the
//! pin.
//!
//! What a pin does not do is stop a principal that may write to the directory from converting the
//! empty directory itself to a junction in place, whatever the sharing: that changes the object
//! the path reaches and not the object held. The directory the grant keeps naming stays the
//! pinned one, and a read through it after the conversion is refused and never served from the
//! junction's target; the conversion is seen by reading the leaf's attributes again, which the
//! caller does at the commit.

/// The first part of the device name a local volume's drive letter resolves to.
const VOLUME_DEVICE_PREFIX: &str = r"\Device\HarddiskVolume";

/// The one file system the grant's identity is recorded for: NTFS identifies an object by the
/// 64-bit index a directory grant compares, and another file system (ReFS names its objects by 128
/// bits) is refused by name.
const SUPPORTED_FILE_SYSTEM: &str = "NTFS";

/// The longest path a pin takes, in characters.
const MAX_PATH_CHARACTERS: usize = 32_000;

/// What the system says about one drive letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriveFacts {
    /// The device name the letter resolves to: `\Device\HarddiskVolume1` for a local volume, and
    /// another path for a `subst` drive.
    pub device: String,
    /// The name of the volume's file system.
    pub file_system: String,
}

/// What the system says about a drive, behind a seam a test can script.
pub trait Drives {
    /// Reads the facts of one drive letter.
    ///
    /// # Errors
    ///
    /// Returns why the drive cannot be described.
    fn facts(&self, letter: char) -> Result<DriveFacts, String>;
}

/// Splits a path into its drive letter and the text after the drive's root, where it is an
/// absolute `X:\...` path by its shape.
///
/// Forward slashes are accepted where a backslash is. A network path, a verbatim or device path
/// (`\\?\`, `\\.\`), a path with no drive, a drive-relative path (`C:name`) and a path with a
/// character no path holds are refused before anything is resolved.
///
/// # Errors
///
/// Returns why the path is not of the shape a pin takes.
pub fn shape(path: &str) -> Result<(char, &str), String> {
    if path.is_empty() {
        return Err("the directory's path is empty".to_owned());
    }
    if path.chars().count() > MAX_PATH_CHARACTERS {
        return Err("the directory's path is longer than a path can be".to_owned());
    }
    if path.contains('\0') {
        return Err("the directory's path holds a character no path holds".to_owned());
    }
    let mut characters = path.chars();
    let letter = characters.next();
    let colon = characters.next();
    let separator = characters.next();
    match (letter, colon, separator) {
        (Some(letter), Some(':'), Some('\\' | '/')) if letter.is_ascii_alphabetic() => Ok((
            letter.to_ascii_uppercase(),
            path.get(3..).unwrap_or_default(),
        )),
        _ if path.starts_with(r"\\") || path.starts_with("//") => Err(format!(
            "{path} is a network, verbatim or device path, and only a path on a local drive is \
             held"
        )),
        _ => Err(format!(
            "{path} is not an absolute path on a drive, and only that is held"
        )),
    }
}

/// Checks what a drive's facts must be for its paths to be held.
///
/// # Errors
///
/// Returns why the drive's paths cannot be held.
pub fn check_drive(letter: char, facts: &DriveFacts) -> Result<(), String> {
    if !facts
        .device
        .to_ascii_lowercase()
        .starts_with(&VOLUME_DEVICE_PREFIX.to_ascii_lowercase())
    {
        return Err(format!(
            "drive {letter}: is not a local volume but {}, whose path can change under a pin",
            facts.device
        ));
    }
    if !facts
        .file_system
        .eq_ignore_ascii_case(SUPPORTED_FILE_SYSTEM)
    {
        return Err(format!(
            "drive {letter}: is {}, and only {SUPPORTED_FILE_SYSTEM} gives the directory an id the \
             grant can compare",
            facts.file_system
        ));
    }
    Ok(())
}

/// Splits the part of a normalised path after its root into its components, which hold no
/// separator, no `.` and no `..`.
///
/// # Errors
///
/// Returns why the path is not one the system has finished normalising.
pub fn components(normalised_rest: &str) -> Result<Vec<&str>, String> {
    let mut parts = Vec::new();
    for part in normalised_rest.split(['\\', '/']) {
        match part {
            "" => {}
            "." | ".." => {
                return Err(format!("{normalised_rest} still holds a {part} segment"));
            }
            other => parts.push(other),
        }
    }
    Ok(parts)
}

/// A directory's identity as the directory grant compares it: the volume's serial number and the
/// object's file index.
pub type Identity = kr_transfer::authority::ObjectIdentity;

/// A path held from its drive's root to its directory.
#[cfg(windows)]
pub use platform::{Kernel, Pin, pin, pin_with};

/// The calls with no safe form, and the handles they own.
#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "asking the system about a drive, a path and an opened directory are calls with \
                  out-parameters that only the caller can promise"
    )]

    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;

    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
        FileAttributeTagInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFullPathNameW, GetVolumeInformationW, QueryDosDeviceW, SYNCHRONIZE,
    };

    use super::{DriveFacts, Drives, Identity, check_drive, components, shape};

    /// The system's own answers about drives.
    #[derive(Debug, Clone, Copy)]
    pub struct Kernel;

    impl Drives for Kernel {
        fn facts(&self, letter: char) -> Result<DriveFacts, String> {
            let name: Vec<u16> = format!("{letter}:").encode_utf16().chain([0]).collect();
            let mut device = vec![0_u16; 1024];
            // SAFETY: the name is terminated, and the buffer is a local of the length told.
            let written = unsafe {
                QueryDosDeviceW(
                    name.as_ptr(),
                    device.as_mut_ptr(),
                    u32::try_from(device.len()).unwrap_or(0),
                )
            };
            if written == 0 {
                return Err(format!(
                    "drive {letter}: has no device name: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // The first of the strings written, which is the device the letter resolves to.
            let end = device
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(device.len());
            let device = String::from_utf16_lossy(device.get(..end).unwrap_or_default());
            let root: Vec<u16> = format!("{letter}:\\").encode_utf16().chain([0]).collect();
            let mut system = vec![0_u16; 64];
            // SAFETY: the root is terminated, the buffer is a local of the length told, and every
            // other out-parameter is null, which the call permits.
            let read = unsafe {
                GetVolumeInformationW(
                    root.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    system.as_mut_ptr(),
                    u32::try_from(system.len()).unwrap_or(0),
                )
            };
            if read == 0 {
                return Err(format!(
                    "drive {letter}: has no file system the system will name: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let end = system
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(system.len());
            Ok(DriveFacts {
                device,
                file_system: String::from_utf16_lossy(system.get(..end).unwrap_or_default()),
            })
        }
    }

    /// A path held from its drive's root to its directory.
    ///
    /// Dropping it lets every component go.
    #[derive(Debug)]
    pub struct Pin {
        /// The normalised path that was held.
        path: String,
        /// One handle for each component, the drive's root first and the directory last.
        handles: Vec<std::fs::File>,
        /// The directory's identity, read from its own handle.
        identity: Identity,
    }

    impl Pin {
        /// Returns the normalised path this pin holds.
        #[must_use]
        pub fn path(&self) -> &str {
            &self.path
        }

        /// Returns the directory's identity as the directory grant compares it.
        #[must_use]
        pub const fn identity(&self) -> Identity {
            self.identity
        }

        /// Reads the directory's own attributes again and refuses a directory that has become a
        /// link, or stopped being a directory.
        ///
        /// A principal that may write to an empty directory can convert it to a junction in place
        /// whatever the sharing, and the pin's own handle then reads the reparse attribute. A
        /// conversion made and undone between two readings is not seen, and the grant is not moved
        /// by one: it keeps naming the pinned object.
        ///
        /// # Errors
        ///
        /// Returns why the directory is not the directory the pin was taken of.
        pub fn recheck(&self) -> Result<(), String> {
            let leaf = self
                .handles
                .last()
                .ok_or_else(|| "the pin holds nothing".to_owned())?;
            let tag = attributes(leaf).map_err(|error| {
                format!("the pinned directory's attributes cannot be read again: {error}")
            })?;
            refuse_link_or_file(tag, &self.path)
        }
    }

    /// Holds a path, as [`pin_with`] does, on this machine's own drives.
    ///
    /// # Errors
    ///
    /// Returns why the path cannot be held.
    pub fn pin(path: &str) -> Result<Pin, String> {
        pin_with(&Kernel, path)
    }

    /// Holds a path from its drive's root to its directory.
    ///
    /// The system normalises the path first, as it does for any program that opens it: separators,
    /// case, a trailing separator and `.` and `..` segments are what it makes them, and what is
    /// held is what the string the program is given reaches. Each prefix is then opened by its
    /// path while the earlier components are held and checked, so an open resolves only through
    /// objects already held.
    ///
    /// # Errors
    ///
    /// Returns why the path cannot be held: its shape, its drive, a component that is a link or a
    /// file, or one that cannot be opened.
    pub fn pin_with(drives: &impl Drives, path: &str) -> Result<Pin, String> {
        let (letter, _) = shape(path)?;
        check_drive(letter, &drives.facts(letter)?)?;
        let full = normalised(path)?;
        let (full_letter, rest) = shape(&full)?;
        if full_letter != letter {
            return Err(format!("{path} is on another drive once it is resolved"));
        }
        let parts = components(rest)?;
        let mut handles = Vec::with_capacity(parts.len() + 1);
        let mut prefix = format!("{letter}:\\");
        handles.push(open_component(&prefix)?);
        for part in parts {
            if !prefix.ends_with('\\') {
                prefix.push('\\');
            }
            prefix.push_str(part);
            handles.push(open_component(&prefix)?);
        }
        let leaf = handles
            .last()
            .ok_or_else(|| "the pin holds nothing".to_owned())?;
        let identity = identity_of(leaf)
            .map_err(|error| format!("the identity of {prefix} cannot be read: {error}"))?;
        Ok(Pin {
            path: prefix,
            handles,
            identity,
        })
    }

    /// Opens one component without following a link and without letting it be renamed, replaced or
    /// deleted, and checks that it is a directory and no kind of link.
    fn open_component(path: &str) -> Result<std::fs::File, String> {
        let opened = std::fs::OpenOptions::new()
            .access_mode(FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
            // Reading and writing are shared and deleting never is: a rename, a replace or a delete
            // of the component is a sharing violation while this is held.
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| format!("{path} cannot be held: {error}"))?;
        let tag = attributes(&opened)
            .map_err(|error| format!("the attributes of {path} cannot be read: {error}"))?;
        refuse_link_or_file(tag, path)?;
        Ok(opened)
    }

    fn refuse_link_or_file(attributes: u32, path: &str) -> Result<(), String> {
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "{path} is a link (a junction, a symbolic link or a mount point), and a path \
                 through one is not held"
            ));
        }
        if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(format!("{path} is not a directory"));
        }
        Ok(())
    }

    /// Reads an opened object's attributes, which carry whether it is a link.
    fn attributes(file: &std::fs::File) -> std::io::Result<u32> {
        // SAFETY: all zeroes is a structure of integers.
        let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the call and the structure is a local of the size told.
        let read = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FileAttributeTagInfo,
                std::ptr::from_mut(&mut tag).cast(),
                u32::try_from(std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>()).unwrap_or(0),
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(tag.FileAttributes)
    }

    /// Reads a directory's identity the way the directory grant does: the volume's serial number
    /// and the 64-bit file index.
    pub(super) fn identity_of(file: &std::fs::File) -> std::io::Result<Identity> {
        // SAFETY: all zeroes is a structure of integers.
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is open for the call and the structure is a local.
        let read = unsafe {
            GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information)
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Identity {
            device: u64::from(information.dwVolumeSerialNumber),
            file_id: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
        })
    }

    /// Returns the path as the system normalises it for a program that opens it.
    fn normalised(path: &str) -> Result<String, String> {
        let wide: Vec<u16> = std::ffi::OsStr::new(path)
            .encode_wide()
            .chain([0])
            .collect();
        let mut capacity = 512_u32;
        loop {
            let mut buffer = vec![0_u16; usize::try_from(capacity).unwrap_or(512)];
            // SAFETY: the path is terminated, the buffer is a local of the length told and the file
            // part is not wanted.
            let length = unsafe {
                GetFullPathNameW(
                    wide.as_ptr(),
                    capacity,
                    buffer.as_mut_ptr(),
                    std::ptr::null_mut(),
                )
            };
            if length == 0 {
                return Err(format!(
                    "{path} cannot be resolved: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if length >= capacity {
                capacity = length.saturating_add(1);
                continue;
            }
            buffer.truncate(usize::try_from(length).unwrap_or(0));
            return std::ffi::OsString::from_wide(&buffer)
                .into_string()
                .map_err(|_| format!("{path} resolves to a path that is not text"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absolute_path_on_a_drive_has_the_shape_a_pin_takes() {
        assert_eq!(shape(r"C:\a\b"), Ok(('C', r"a\b")));
        assert_eq!(
            shape("c:/a/b"),
            Ok(('C', "a/b")),
            "forward slashes and a lower case letter"
        );
        assert_eq!(shape(r"D:\"), Ok(('D', "")));
        assert_eq!(shape(r"Z:\a\.\..\b\"), Ok(('Z', r"a\.\..\b\")));
    }

    #[test]
    fn a_path_of_any_other_shape_is_refused_before_anything_is_resolved() {
        for refused in [
            r"\\server\share\a",
            "//server/share/a",
            r"\\?\C:\a",
            r"\\.\C:\a",
            r"a\b",
            r"\a",
            "C:a",
            "C:",
            "1:\\a",
            "",
            "C:\\a\0b",
        ] {
            assert!(shape(refused).is_err(), "{refused:?}");
        }
        let why = shape(r"\\?\C:\a").expect_err("verbatim");
        assert!(why.contains("network, verbatim or device"), "{why}");
        let long = format!("C:\\{}", "a".repeat(40_000));
        assert!(shape(&long).is_err());
    }

    #[test]
    fn only_a_local_ntfs_volume_can_be_held() {
        let local = DriveFacts {
            device: r"\Device\HarddiskVolume3".to_owned(),
            file_system: "NTFS".to_owned(),
        };
        assert_eq!(check_drive('C', &local), Ok(()));
        assert_eq!(
            check_drive(
                'C',
                &DriveFacts {
                    device: r"\device\harddiskvolume3".to_owned(),
                    file_system: "ntfs".to_owned(),
                }
            ),
            Ok(()),
            "case is the system's own"
        );
        let substituted = DriveFacts {
            device: r"\??\C:\work".to_owned(),
            file_system: "NTFS".to_owned(),
        };
        let why = check_drive('R', &substituted).expect_err("a subst drive");
        assert!(why.contains("not a local volume"), "{why}");
        let fat = DriveFacts {
            file_system: "FAT32".to_owned(),
            ..local.clone()
        };
        let why = check_drive('E', &fat).expect_err("a FAT volume");
        assert!(why.contains("FAT32"), "{why}");
        let refs = DriveFacts {
            file_system: "ReFS".to_owned(),
            ..local
        };
        assert!(check_drive('E', &refs).is_err());
    }

    #[test]
    fn a_normalised_path_splits_into_its_components() {
        assert_eq!(components(r"a\b\c"), Ok(vec!["a", "b", "c"]));
        assert_eq!(components(r"a\b\"), Ok(vec!["a", "b"]));
        assert_eq!(components(""), Ok(Vec::new()));
        assert!(
            components(r"a\..\b").is_err(),
            "the system has not finished with it"
        );
        assert!(components(r"a\.\b").is_err());
    }
}
