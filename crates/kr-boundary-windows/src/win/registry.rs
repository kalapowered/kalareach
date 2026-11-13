//! Values in the machine's registry: what the installation sets, reads back and restores.

#![allow(unsafe_code)]

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_ENUMERATE_SUB_KEYS, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD,
    REG_OPTION_NON_VOLATILE, RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW,
    RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use super::ffi::{Result, error, wide};

/// An open key under the local machine's hive.
pub struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key is owned by this value and closed once.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

/// Opens a key for reading and for setting values, or says it does not exist.
///
/// # Errors
///
/// Returns the platform's error for any failure but a missing key.
pub fn open(subkey: &str) -> Result<Option<Key>> {
    let name = wide(subkey);
    let mut key: HKEY = null_mut();
    // SAFETY: the name is NUL-terminated and the key is an out-parameter.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS,
            &raw mut key,
        )
    };
    match status {
        ERROR_SUCCESS => Ok(Some(Key(key))),
        ERROR_FILE_NOT_FOUND => Ok(None),
        // text: registry_open-1
        other => Err(error(other, format!("opening the key {subkey}"))),
    }
}

/// Opens a key, making it and the keys above it when they are missing.
///
/// # Errors
///
/// Returns the platform's error when the key cannot be made.
pub fn create(subkey: &str) -> Result<Key> {
    let name = wide(subkey);
    let mut key: HKEY = null_mut();
    // SAFETY: the name is NUL-terminated and the key is an out-parameter.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            name.as_ptr(),
            0,
            null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_ENUMERATE_SUB_KEYS,
            null(),
            &raw mut key,
            null_mut(),
        )
    };
    if status == ERROR_SUCCESS {
        Ok(Key(key))
    } else {
        // text: registry-1
        Err(error(status, format!("opening or making the key {subkey}")))
    }
}

/// Deletes a key that has no subkeys. A key that is not there counts as deleted.
///
/// # Errors
///
/// Returns the platform's error for any failure but a missing key.
pub fn delete_key(subkey: &str) -> Result<()> {
    let name = wide(subkey);
    // SAFETY: the name is NUL-terminated.
    let status = unsafe { RegDeleteKeyW(HKEY_LOCAL_MACHINE, name.as_ptr()) };
    match status {
        ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
        // text: registry_delete_key-1
        other => Err(error(other, format!("deleting the key {subkey}"))),
    }
}

impl Key {
    /// Sets a number value.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the value cannot be set.
    pub fn set_dword(&self, name: &str, value: u32) -> Result<()> {
        let wide_name = wide(name);
        let bytes = value.to_le_bytes();
        // SAFETY: the name is NUL-terminated and the data is four bytes.
        let status =
            unsafe { RegSetValueExW(self.0, wide_name.as_ptr(), 0, REG_DWORD, bytes.as_ptr(), 4) };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            // text: registry_set_dword-1
            Err(error(status, format!("setting the value {name}")))
        }
    }

    /// Reads a number value, or says there is none.
    ///
    /// # Errors
    ///
    /// Returns the platform's error for any failure but a missing value.
    pub fn dword(&self, name: &str) -> Result<Option<u32>> {
        let wide_name = wide(name);
        let mut kind = 0_u32;
        let mut data = [0_u8; 4];
        let mut size = 4_u32;
        // SAFETY: the name is NUL-terminated and the buffer is the size passed.
        let status = unsafe {
            RegQueryValueExW(
                self.0,
                wide_name.as_ptr(),
                null(),
                &raw mut kind,
                data.as_mut_ptr(),
                &raw mut size,
            )
        };
        match status {
            ERROR_SUCCESS if kind == REG_DWORD => Ok(Some(u32::from_le_bytes(data))),
            // text: registry-2
            ERROR_SUCCESS => Err(error(
                0,
                format!("the value {name} is not a DWORD (type {kind})"),
            )),
            ERROR_FILE_NOT_FOUND => Ok(None),
            // text: registry_dword-1
            other => Err(error(other, format!("reading the value {name}"))),
        }
    }

    /// Deletes a value. A value that is not there counts as deleted.
    ///
    /// # Errors
    ///
    /// Returns the platform's error for any failure but a missing value.
    pub fn delete_value(&self, name: &str) -> Result<()> {
        let wide_name = wide(name);
        // SAFETY: the name is NUL-terminated.
        let status = unsafe { RegDeleteValueW(self.0, wide_name.as_ptr()) };
        match status {
            ERROR_SUCCESS | ERROR_FILE_NOT_FOUND => Ok(()),
            // text: registry_delete_value-1
            other => Err(error(other, format!("deleting the value {name}"))),
        }
    }

    /// The names of the values under the key.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the key cannot be read.
    pub fn value_names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut buffer = vec![0_u16; 16_384];
            let mut length = buffer.len() as u32;
            // SAFETY: the buffer is the length passed.
            let status = unsafe {
                RegEnumValueW(
                    self.0,
                    index,
                    buffer.as_mut_ptr(),
                    &raw mut length,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                ERROR_SUCCESS => names.push(String::from_utf16_lossy(&buffer[..length as usize])),
                ERROR_NO_MORE_ITEMS => break,
                other => return Err(error(other, "listing the values")),
            }
        }
        Ok(names)
    }

    /// The names of the subkeys under the key.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the key cannot be read.
    pub fn subkey_names(&self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0.. {
            let mut buffer = vec![0_u16; 512];
            let mut length = buffer.len() as u32;
            // SAFETY: the buffer is the length passed.
            let status = unsafe {
                RegEnumKeyExW(
                    self.0,
                    index,
                    buffer.as_mut_ptr(),
                    &raw mut length,
                    null(),
                    null_mut(),
                    null_mut(),
                    null_mut(),
                )
            };
            match status {
                ERROR_SUCCESS => names.push(String::from_utf16_lossy(&buffer[..length as usize])),
                ERROR_NO_MORE_ITEMS => break,
                // text: registry_subkey_names-1
                other => return Err(error(other, "listing the subkeys")),
            }
        }
        Ok(names)
    }
}
