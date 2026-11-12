//! What a client may do with the broker's pipe, as one value for both sides: the entry the broker
//! puts in the pipe's permission list for the Administrators group and for each enrolled person,
//! and the rights the installer asks for when it opens the pipe. A client asks for exactly what the
//! list grants and no more, so a request can never outgrow the grant, and the grant is the least
//! that the client's calls need.

/// Read from the pipe.
pub const READ_DATA: u32 = 0x0001;
/// Write to the pipe.
pub const WRITE_DATA: u32 = 0x0002;
/// Make another instance of the pipe's name. It is the same bit as appending to a file, and no
/// client has it: only the system makes instances of the broker's pipe.
pub const CREATE_INSTANCE: u32 = 0x0004;

/// Read the pipe's attributes. `CreateFileW` asks for it with every open.
pub const READ_ATTRIBUTES: u32 = 0x0080;
/// Wait on the handle. `CreateFileW` asks for it with every open.
pub const SYNCHRONIZE: u32 = 0x0010_0000;

/// The rights of a client: the two that its calls use, to read from the pipe and to write to it, and
/// the two that every open of a file or a pipe asks for by itself, the pipe's attributes and the wait.
/// A list that grants less refuses the open of an administrator and of every enrolled person. Not the
/// right to change the attributes or to read the permission list, which no call of the client uses
/// and which would let each enrolled person read every other person's identifier, and not the right
/// to make another instance, which the generic write right of a file would add through the append
/// bit.
pub const CLIENT: u32 = READ_DATA | WRITE_DATA | READ_ATTRIBUTES | SYNCHRONIZE;

/// The entry of the pipe's permission list that gives a client its rights, for the account or the
/// group the identifier names (a SID in text or a two-letter alias).
#[must_use]
pub fn entry(who: &str) -> String {
    format!("(A;;{CLIENT:#x};;;{who})")
}
