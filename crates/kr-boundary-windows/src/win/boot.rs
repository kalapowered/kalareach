//! The boot marker: an identifier of the current start of Windows that a clock correction does
//! not change.
//!
//! The marker is a GUID in a volatile registry key under the broker's own service key. The service
//! makes the key when it finds none, and reads it otherwise; the system drops a volatile key of
//! the local machine's hive only at a full shutdown. A hibernation and its resume keep the marker,
//! with the processes; a full restart removes it; a fast-startup shutdown can keep it while every
//! process and session is gone. So the marker says that the start of Windows is the same or has
//! changed, and it says nothing more: an administrator can reset or delete the key within a boot,
//! and a journal that finds the marker unlike its own never takes that as proof that the old
//! processes ended. The session's absence stays the evidence.
//!
//! The marker is trusted only when nobody but the system and the administrators can write the key
//! or the service key above it. The check runs at every read.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_CREATED_NEW_KEY,
    REG_OPTION_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};

use super::ffi::{Result, error, wide};
use super::sd::{self, Principals, SdKind, Summary};

/// The service key the installation lays, and the key under it that holds the marker.
const SERVICE_KEY: &str = r"SYSTEM\CurrentControlSet\Services\KalaReachBoundary";
const MARKER_KEY: &str = r"SYSTEM\CurrentControlSet\Services\KalaReachBoundary\Boot";
const VALUE: &str = "Id";

const READ_CONTROL: u32 = 0x0002_0000;
const SYSTEM: &str = "S-1-5-18";
const ADMINISTRATORS: &str = "S-1-5-32-544";
const INHERIT_ONLY_ACE: u8 = 0x08;
/// The rights on a key that change it or who may: set a value, make a subkey or a link, delete
/// it, write its list or its owner, and the generic rights that map to them.
const CHANGING: u32 = 0x0002
    | 0x0004
    | 0x0020
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x4000_0000
    | 0x1000_0000
    | 0x0200_0000;

/// The identifier of the current boot and whether it can be believed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootMarker {
    /// The marker: a GUID in text.
    pub id: String,
    /// Whether nobody but the system and the administrators can write the key and the key above.
    pub trusted: bool,
    /// Why it is not trusted, when it is not.
    pub reason: Option<String>,
    /// Whether this call made the key: the first read since the start of Windows.
    pub made: bool,
}

/// Why a descriptor lets someone else change a key, or nothing when it does not.
///
/// A deny entry never opens anything and is not looked at. An entry that applies only to the keys
/// below this one does not apply to this key.
#[must_use]
pub fn who_else_can_change(summary: &Summary) -> Option<String> {
    if summary.owner != SYSTEM && summary.owner != ADMINISTRATORS {
        return Some(format!("it is owned by {}", summary.owner));
    }
    let Some(entries) = &summary.entries else {
        return Some("it has no permission list, so everyone may change it".to_owned());
    };
    for entry in entries {
        if entry.kind != 0 {
            continue;
        }
        if entry.flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if entry.sid != SYSTEM && entry.sid != ADMINISTRATORS && entry.mask & CHANGING != 0 {
            return Some(format!("{} may change it", entry.sid));
        }
    }
    None
}

struct OpenKey(HKEY);

impl Drop for OpenKey {
    fn drop(&mut self) {
        // SAFETY: the key is owned by this value and closed once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

fn open_for_reading_the_list(subkey: &str) -> Result<Option<OpenKey>> {
    let name = wide(subkey);
    let mut key: HKEY = null_mut();
    // SAFETY: the name is NUL-terminated and the key is an out-parameter.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            READ_CONTROL,
            &raw mut key,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(OpenKey(key))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        other => Err(error(other, format!("opening the key {subkey}"))),
    }
}

fn read_id(key: &OpenKey) -> Result<Option<String>> {
    let name = wide(VALUE);
    let mut kind = 0_u32;
    let mut buffer = [0_u16; 64];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: the name is NUL-terminated and the buffer is the size passed.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            name.as_ptr(),
            null(),
            &raw mut kind,
            buffer.as_mut_ptr().cast::<u8>(),
            &raw mut size,
        )
    };
    match status {
        ERROR_SUCCESS if kind == REG_SZ => {
            let units = (size as usize / 2).min(buffer.len());
            let end = buffer[..units]
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units);
            let text = String::from_utf16_lossy(&buffer[..end]);
            Ok(uuid::Uuid::parse_str(&text).ok().map(|_| text))
        }
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(None),
        other => Err(error(other, "reading the boot marker")),
    }
}

fn write_id(key: &OpenKey, id: &str) -> Result<()> {
    let name = wide(VALUE);
    let data = wide(id);
    // SAFETY: the name and the data are NUL-terminated; the size is the data's length in bytes.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            name.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            (data.len() * 2) as u32,
        )
    };
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(error(status, "writing the boot marker"))
    }
}

/// Reads the marker, making the key and the identifier when this is the first read since Windows
/// started, and says whether it can be believed.
///
/// # Errors
///
/// Returns an error when the platform refuses a call.
pub fn marker() -> Result<BootMarker> {
    let mut problems = Vec::new();
    match open_for_reading_the_list(SERVICE_KEY)? {
        Some(parent) => {
            if let Some(why) = who_else_can_change(&sd::summary_of_key(parent.0.cast::<c_void>())?)
            {
                problems.push(format!("the service key: {why}"));
            }
        }
        None => problems.push("the service key does not exist".to_owned()),
    }
    let descriptor = sd::descriptor(SdKind::BootMarker, &Principals::default())?;
    let attributes = descriptor.attributes();
    let name = wide(MARKER_KEY);
    let mut raw: HKEY = null_mut();
    let mut disposition = 0_u32;
    // SAFETY: the name is NUL-terminated, the attributes point at a descriptor that lives through
    // the call, and the key and the disposition are out-parameters.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            null(),
            REG_OPTION_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | READ_CONTROL,
            &raw const attributes,
            &raw mut raw,
            &raw mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(error(status, "making the boot marker's key"));
    }
    let key = OpenKey(raw);
    let made = disposition == REG_CREATED_NEW_KEY;
    if let Some(why) = who_else_can_change(&sd::summary_of_key(key.0.cast::<c_void>())?) {
        problems.push(format!("the marker's key: {why}"));
    }
    let id = match read_id(&key)? {
        Some(id) => id,
        None => {
            let id = uuid::Uuid::new_v4().to_string();
            write_id(&key, &id)?;
            id
        }
    };
    Ok(BootMarker {
        id,
        trusted: problems.is_empty(),
        reason: if problems.is_empty() {
            None
        } else {
            Some(problems.join("; "))
        },
        made,
    })
}

/// Deletes the marker's key, which the installation's removal does before it deletes the service.
/// A key that is not there counts as deleted.
///
/// # Errors
///
/// Returns an error when the platform refuses the deletion.
pub fn remove() -> Result<()> {
    super::registry::delete_key(MARKER_KEY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::win::sd::Entry;

    fn entry(kind: u8, flags: u8, mask: u32, sid: &str) -> Entry {
        Entry {
            kind,
            flags,
            mask,
            sid: sid.to_owned(),
        }
    }

    fn summary(owner: &str, entries: Option<Vec<Entry>>) -> Summary {
        Summary {
            owner: owner.to_owned(),
            protected: true,
            entries,
        }
    }

    #[test]
    fn a_key_only_the_system_and_the_administrators_can_change_is_trusted() {
        let list = vec![
            entry(0, 0, 0xf003f, SYSTEM),
            entry(0, 0, 0xf003f, ADMINISTRATORS),
            // Users may read: the read rights change nothing.
            entry(0, 0, 0x2_0019, "S-1-5-32-545"),
            // An entry for the keys below this one does not apply to this key.
            entry(0, INHERIT_ONLY_ACE, 0xf003f, "S-1-3-0"),
            // A deny never opens anything.
            entry(1, 0, 0xf003f, "S-1-1-0"),
        ];
        assert_eq!(who_else_can_change(&summary(SYSTEM, Some(list))), None);
    }

    #[test]
    fn a_key_that_another_principal_can_change_is_not_trusted() {
        for (mask, sid) in [
            (0x0002, "S-1-5-32-545"),
            (0x0004, "S-1-5-11"),
            (0x0001_0000, "S-1-1-0"),
            (0x0004_0000, "S-1-5-32-545"),
            (0x1000_0000, "S-1-5-32-545"),
        ] {
            let list = vec![entry(0, 0, 0xf003f, SYSTEM), entry(0, 0, mask, sid)];
            assert!(
                who_else_can_change(&summary(ADMINISTRATORS, Some(list))).is_some(),
                "{sid} with {mask:#x} may change the key"
            );
        }
        assert!(who_else_can_change(&summary("S-1-5-32-545", Some(Vec::new()))).is_some());
        assert!(who_else_can_change(&summary(SYSTEM, None)).is_some());
    }
}
