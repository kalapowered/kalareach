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
use std::mem::size_of;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACE_HEADER, ACL, GetAce, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorOwner, SECURITY_ATTRIBUTES,
};

use super::ffi::{Handle, Result, Sid, error, last, wide};

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
/// Read and enter a folder, or read and run a file, and nothing else: no write, no delete, no
/// change of the list or the owner.
const READ_AND_EXECUTE: &str = "0x1200a9";

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
    /// token names the system alone. The Administrators group owns both, so that they can be made
    /// by the system and by an elevated administrator alike (the installer's own event log queries
    /// make them): only the system's own token may name the system as an owner.
    ProcessThread,
    /// A folder only the system and administrators may change, which every account may read and
    /// enter when the principals say so. The Administrators group owns it, named in the descriptor
    /// that makes it, so that its owner is the same whoever makes it: the system, or an
    /// administrator whose token's default owner is the account itself.
    AdminDir,
    /// A file only the system and administrators may use, owned by the Administrators group for the
    /// same reason as an [`SdKind::AdminDir`]: the installation's manifest, its earlier-state
    /// record and the files it hands to another program by path.
    AdminFile,
    /// A program file of the installation's program directory, which every account may read and
    /// run and none may change: the system and the administrators have every right, owned by the
    /// Administrators group as an [`SdKind::AdminFile`] is.
    ProgramFile,
    /// The proof's unlisted program, a copy of the system's own `hostname.exe` made in the proof's
    /// directory for one run. The file holds the bytes of a program that ships with Windows and no
    /// secret. The system and the administrators have every right; the invocation's group, which
    /// is enabled in the token of both boundary accounts, may read and run it, because the file
    /// system would otherwise refuse the launch before application control could, and the proof
    /// would prove nothing. The account's own identifier is deny-only in that token, so naming the
    /// account would let nothing through. Nobody else is named, and nobody but the system and the
    /// administrators may write, delete or change the file. Only the proof makes this kind.
    ProofProgram,
    /// The volatile registry key that holds the identifier of the current boot: the system and the
    /// administrators alone may do anything with it, and nobody else may even read it.
    BootMarker,
    /// One of the anonymous pipes that carry a child's standard output and error to the broker.
    /// Only the system may open the pipe object. The child is not given the object to open: it
    /// receives its end of the pipe as an inherited handle, which is not an access check, and no
    /// account, the child's own included, can open the pipe by any other route. The Administrators
    /// group owns it, so that it can be made by the system and by an elevated administrator alike: only
    /// the system's own token may name the system as an owner.
    CapturePipe,
    /// The `%ProgramData%\KalaReach` folder that holds the installation's data directory: the
    /// Administrators group owns it, and only the system and the administrators may do anything
    /// with it. The list is protected, so it takes nothing from `%ProgramData%`, and no other
    /// account can create, rename or delete anything in it.
    DataParent,
}

/// The identities a descriptor names. A kind uses the ones it needs and refuses a descriptor
/// without them.
#[derive(Clone, Debug, Default)]
pub struct Principals {
    /// The invocation's group. [`SdKind::PrivateRoot`] and [`SdKind::ProofProgram`] need it;
    /// [`SdKind::ProcessThread`] names it when it is given.
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
                "O:BAD:P(A;;{ALL_BUT_CHANGING_THE_DESCRIPTOR};;;{})(A;;{ALL_ACCESS};;;SY)",
                group.to_text()
            ),
            None => format!("O:BAD:P(A;;{ALL_ACCESS};;;SY)"),
        }),
        SdKind::BootMarker => Ok("O:SYD:P(A;;KA;;;SY)(A;;KA;;;BA)".to_owned()),
        SdKind::CapturePipe => Ok("O:BAD:P(A;;GA;;;SY)".to_owned()),
        SdKind::DataParent => Ok("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned()),
        SdKind::AdminDir => Ok(if principals.users_may_read {
            format!("O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;{READ_AND_EXECUTE};;;BU)")
        } else {
            "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".to_owned()
        }),
        SdKind::AdminFile => Ok("O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_owned()),
        SdKind::ProgramFile => Ok(format!(
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{READ_AND_EXECUTE};;;BU)"
        )),
        SdKind::ProofProgram => {
            let group = needed(principals.group.as_ref(), "the invocation's group")?;
            Ok(format!(
                "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;{READ_AND_EXECUTE};;;{})",
                group.to_text()
            ))
        }
    }
}

/// A descriptor from text the case writes, for a control that needs a list the broker never makes.
///
/// # Errors
///
/// Returns an error when the platform refuses the text.
#[cfg(feature = "testing")]
pub fn descriptor_from_text(text: &str) -> Result<OwnedSd> {
    OwnedSd::from_text(text.to_owned())
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

/// One entry of a permission list, as an access check reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// The entry's type: 0 allows, 1 denies.
    pub kind: u8,
    /// The entry's inheritance flags.
    pub flags: u8,
    /// The rights it names.
    pub mask: u32,
    /// Who it names, as text.
    pub sid: String,
}

/// What a descriptor says that an access check uses: its owner, whether its list is protected from
/// inheritance, and every entry in order. It is how the broker compares the descriptor an object
/// ended up with against the one it asked for, without depending on how either is written as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The owner, as text.
    pub owner: String,
    /// Whether the list does not take entries from the parent.
    pub protected: bool,
    /// The entries, or none when the descriptor has no list.
    pub entries: Option<Vec<Entry>>,
}

const SE_DACL_PROTECTED: u16 = 0x1000;
const SE_FILE_OBJECT: i32 = 1;
const SE_REGISTRY_KEY: i32 = 4;
const OWNER_AND_DACL: u32 = 0x1 | 0x4;

/// Reads the summary of a descriptor the platform gave.
///
/// # Safety
///
/// `descriptor` must point at a valid absolute or self-relative descriptor.
unsafe fn summarise(descriptor: *mut c_void) -> Result<Summary> {
    let mut owner: *mut c_void = null_mut();
    let mut defaulted = 0;
    // SAFETY: the caller promises the descriptor is valid; the out-parameters are local.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) } == 0 {
        return Err(last("reading a descriptor's owner"));
    }
    if owner.is_null() {
        return Err(error(
            ERROR_INVALID_PARAMETER,
            "the descriptor has no owner",
        ));
    }
    // SAFETY: the owner pointer is inside the valid descriptor.
    let owner = unsafe { Sid::from_ptr(owner) }.to_text();
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: as above.
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
    {
        return Err(last("reading a descriptor's flags"));
    }
    let mut present = 0;
    let mut list: *mut ACL = null_mut();
    // SAFETY: as above.
    if unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut list,
            &raw mut defaulted,
        )
    } == 0
    {
        return Err(last("reading a descriptor's list"));
    }
    let entries = if present == 0 || list.is_null() {
        None
    } else {
        // SAFETY: the list pointer is inside the valid descriptor.
        let count = unsafe { (*list).AceCount };
        let mut entries = Vec::new();
        for index in 0..u32::from(count) {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: the index is below the entry count.
            if unsafe { GetAce(list, index, &raw mut ace) } == 0 {
                return Err(last("reading a list entry"));
            }
            // SAFETY: an access-allowed or access-denied entry is a header, a mask and a
            // identifier; the platform returned a pointer to a whole entry.
            let (kind, flags, mask, sid) = unsafe {
                let header = &*ace.cast::<ACE_HEADER>();
                let mask = *ace.cast::<u8>().add(size_of::<ACE_HEADER>()).cast::<u32>();
                let sid = ace
                    .cast::<u8>()
                    .add(size_of::<ACE_HEADER>() + 4)
                    .cast::<c_void>();
                (header.AceType, header.AceFlags, mask, Sid::from_ptr(sid))
            };
            entries.push(Entry {
                kind,
                flags,
                mask,
                sid: sid.to_text(),
            });
        }
        Some(entries)
    };
    Ok(Summary {
        owner,
        protected: control & SE_DACL_PROTECTED != 0,
        entries,
    })
}

impl OwnedSd {
    /// What the descriptor says, for comparing with what an object has.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform cannot read the descriptor.
    pub fn summary(&self) -> Result<Summary> {
        // SAFETY: the descriptor was built by the platform and lives as long as `self`.
        unsafe { summarise(self.raw) }
    }
}

/// What the descriptor of an open object says.
///
/// # Errors
///
/// Returns an error when the platform cannot read the object's descriptor.
pub fn summary_of_handle(handle: &Handle) -> Result<Summary> {
    summary_of_object(handle.raw(), SE_FILE_OBJECT)
}

/// What the descriptor of an open registry key says.
///
/// # Errors
///
/// Returns an error when the platform cannot read the key's descriptor.
pub fn summary_of_key(key: *mut c_void) -> Result<Summary> {
    summary_of_object(key, SE_REGISTRY_KEY)
}

fn summary_of_object(object: *mut c_void, kind: i32) -> Result<Summary> {
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: the handle is open with the right to read the descriptor; the out-parameter is local
    // and the block it receives is freed below.
    let code = unsafe {
        GetSecurityInfo(
            object,
            kind,
            OWNER_AND_DACL,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &raw mut descriptor,
        )
    };
    if code != 0 {
        return Err(error(code, "reading an object's descriptor"));
    }
    // SAFETY: the call returned a valid descriptor, which is freed once after it is read.
    let summary = unsafe { summarise(descriptor) };
    // SAFETY: the block came from the platform's allocator.
    unsafe {
        LocalFree(descriptor);
    }
    summary
}
