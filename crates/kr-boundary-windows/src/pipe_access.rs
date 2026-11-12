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

/// The rights of a client: read from the pipe and write to it, and nothing more. The installer's
/// client opens the pipe for overlapped transfers, asks for the process that serves it, writes a
/// request, reads the answer and cancels a read that is late; none of that needs the attributes,
/// the permission list or the right to wait on the handle; with the right to read the list, each
/// enrolled person could read every other enrolled person's identifier. Not the right to make
/// another instance, which the generic write right of a file would add through the append bit.
pub const CLIENT: u32 = READ_DATA | WRITE_DATA;

/// The entry of the pipe's permission list that gives a client its rights, for the account or the
/// group the identifier names (a SID in text or a two-letter alias).
#[must_use]
pub fn entry(who: &str) -> String {
    format!("(A;;{CLIENT:#x};;;{who})")
}
