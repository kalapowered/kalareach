//! The security descriptors the broker makes.
//!
//! This module is the one place that writes a descriptor: no other module in the broker's own
//! path builds a descriptor string or a permission list. What a descriptor must name is a policy
//! of the boundary, so it is kept apart from the calls that apply one.
//!
//! The module has one kind of entry so far, construction: [`descriptor`] makes a descriptor for an
//! object the broker is about to create. Functions that change the descriptor of an object that
//! already exists, and the one that computes what a new object under a parent inherits, are a
//! different kind of work and will be separate functions of this module beside it.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use super::ffi::{Result, Sid, error, last, wide};

const SDDL_REVISION_1: u32 = 1;
const ERROR_INVALID_PARAMETER: u32 = 87;

/// Every right on a process or a thread.
const ALL_ACCESS: &str = "0x1fffff";
/// Every right on a process or a thread but the two that change who may use it: `WRITE_DAC` and
/// `WRITE_OWNER`.
const ALL_BUT_CHANGING_THE_DESCRIPTOR: &str = "0x13ffff";
/// Read, write, execute and delete on a file or directory: everything but changing the
/// permission list or the owner.
const MODIFY: &str = "0x1301bf";
/// Read a pipe's data and its attributes, and nothing else.
const PIPE_READ: &str = "0x120089";
/// Read and enter, for every account.
const READ_AND_ENTER: &str = "0x1200a9";

/// What an object's descriptor is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SdKind {
    /// An invocation's private directory and what is made under it: the system owns it and has
    /// every right, the invocation's group may modify it, and nothing else is named.
    PrivateRoot,
    /// The server end of one of an invocation's data pipes: the system has every right and the
    /// client may read.
    DataPipe,
    /// A child's process and its thread: the invocation's group and the system, protected, and the
    /// group cannot change the descriptor or the owner of the object. A child of the broker's own
    /// token names the system alone.
    ProcessThread,
    /// A folder only the system and administrators may change, which every account may read and
    /// enter when the principals say so.
    AdminDir,
}

/// The identities a descriptor names. A kind uses the ones it needs and refuses a descriptor
/// without them.
#[derive(Clone, Debug, Default)]
pub struct Principals {
    /// The invocation's group. [`SdKind::PrivateRoot`] needs it; [`SdKind::ProcessThread`] names it
    /// when it is given.
    pub group: Option<Sid>,
    /// The client of a data pipe. [`SdKind::DataPipe`] needs it.
    pub client: Option<Sid>,
    /// Whether every account may read and enter an [`SdKind::AdminDir`].
    pub users_may_read: bool,
}

/// A security descriptor the platform allocated, freed when dropped.
pub struct OwnedSd {
    raw: *mut c_void,
    text: String,
}

// SAFETY: the descriptor is a block of memory that this value alone owns and never changes.
unsafe impl Send for OwnedSd {}
// SAFETY: the block is read-only after construction.
unsafe impl Sync for OwnedSd {}

impl OwnedSd {
    /// Makes a descriptor from its text form.
    fn from_text(text: String) -> Result<OwnedSd> {
        let wide_text = wide(&text);
        let mut raw: *mut c_void = null_mut();
        // SAFETY: the text is NUL-terminated and the descriptor is an out-parameter freed on drop.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(last(format!("reading the descriptor {text}")));
        }
        Ok(OwnedSd { raw, text })
    }

    /// The descriptor as the platform's pointer type, for a call that takes one.
    #[must_use]
    pub fn as_ptr(&self) -> *mut c_void {
        self.raw
    }

    /// The text the descriptor was made from.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The attribute record for a call that creates an object with this descriptor. The handle the
    /// call returns is not inheritable.
    #[must_use]
    pub fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.raw,
            bInheritHandle: 0,
        }
    }
}

impl Drop for OwnedSd {
    fn drop(&mut self) {
        // SAFETY: the block came from the platform's allocator and is freed once.
        unsafe {
            LocalFree(self.raw);
        }
    }
}

impl std::fmt::Debug for OwnedSd {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_tuple("OwnedSd").field(&self.text).finish()
    }
}

fn needed<'a>(sid: Option<&'a Sid>, what: &str) -> Result<&'a Sid> {
    sid.ok_or_else(|| {
        error(
            ERROR_INVALID_PARAMETER,
            format!("a descriptor needs {what} and none was given"),
        )
    })
}

/// The text form of a kind's descriptor, for the identities given.
///
/// # Errors
///
/// Returns an error when the kind needs an identity that was not given.
pub fn descriptor_text(kind: SdKind, principals: &Principals) -> Result<String> {
    match kind {
        SdKind::PrivateRoot => {
            let group = needed(principals.group.as_ref(), "the invocation's group")?;
            Ok(format!(
                "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;{MODIFY};;;{})",
                group.to_text()
            ))
        }
        SdKind::DataPipe => {
            let client = needed(principals.client.as_ref(), "the client")?;
            Ok(format!(
                "O:SYD:P(A;;GA;;;SY)(A;;{PIPE_READ};;;{})",
                client.to_text()
            ))
        }
        SdKind::ProcessThread => Ok(match principals.group.as_ref() {
            Some(group) => format!(
                "O:SYD:P(A;;{ALL_BUT_CHANGING_THE_DESCRIPTOR};;;{})(A;;{ALL_ACCESS};;;SY)",
                group.to_text()
            ),
            None => format!("O:SYD:P(A;;{ALL_ACCESS};;;SY)"),
        }),
        SdKind::AdminDir => Ok(if principals.users_may_read {
            format!("D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{READ_AND_ENTER};;;BU)")
        } else {
            "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned()
        }),
    }
}

/// Makes the descriptor of an object the broker is about to create.
///
/// # Errors
///
/// Returns an error when the kind needs an identity that was not given, or the platform refuses the
/// descriptor.
pub fn descriptor(kind: SdKind, principals: &Principals) -> Result<OwnedSd> {
    OwnedSd::from_text(descriptor_text(kind, principals)?)
}
