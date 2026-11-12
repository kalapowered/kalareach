//! What a client may do with the broker's pipe, as one value for both sides: the entry the broker
//! puts in the pipe's permission list for the Administrators group and for each enrolled person,
//! and the rights the installer asks for when it opens the pipe. A client asks for exactly what the
//! list grants and no more, so a request can never outgrow the grant.

/// Read from the pipe.
pub const READ_DATA: u32 = 0x0001;
/// Write to the pipe.
pub const WRITE_DATA: u32 = 0x0002;
/// Make another instance of the pipe's name. It is the same bit as appending to a file, and no
/// client has it: only the system makes instances of the broker's pipe.
pub const CREATE_INSTANCE: u32 = 0x0004;
/// Read the pipe's attributes.
pub const READ_ATTRIBUTES: u32 = 0x0080;
/// Write the pipe's attributes.
pub const WRITE_ATTRIBUTES: u32 = 0x0100;
/// Read the pipe's permission list and owner.
pub const READ_CONTROL: u32 = 0x0002_0000;
/// Wait on the handle.
pub const SYNCHRONIZE: u32 = 0x0010_0000;

/// The rights of a client: read, write and read and write the attributes, with the standard rights
/// to read the list and to wait. Not the right to make another instance, which the generic write
/// right of a file would add through the append bit.
pub const CLIENT: u32 =
    READ_DATA | WRITE_DATA | READ_ATTRIBUTES | WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// The entry of the pipe's permission list that gives a client its rights, for the account or the
/// group the identifier names (a SID in text or a two-letter alias).
#[must_use]
pub fn entry(who: &str) -> String {
    format!("(A;;{CLIENT:#x};;;{who})")
}
