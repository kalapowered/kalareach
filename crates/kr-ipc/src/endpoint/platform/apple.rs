//! What the Apple kernels say about a local socket that the standard library and `rustix` do not
//! reach: the process behind a connected socket.

#![expect(
    unsafe_code,
    reason = "the process behind a connected local socket is a socket option that no safe \
              interface offers on Apple systems"
)]

use std::os::fd::{AsRawFd as _, BorrowedFd};

/// The process that holds the other end of a connected local socket, where the kernel says.
///
/// This is the effective process: the one that made the listening socket this socket was
/// connected to.
pub(super) fn peer_process(socket: BorrowedFd<'_>) -> Option<u32> {
    let mut process: libc::pid_t = 0;
    let mut length = libc::socklen_t::try_from(size_of::<libc::pid_t>()).ok()?;
    // SAFETY: the descriptor is open for the whole call, because the borrow outlives it. The
    // option writes at most `length` bytes through the pointer, which is to a live local of that
    // size, and `length` is a live local of the type the call reads and writes.
    let status = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEEREPID,
            (&raw mut process).cast(),
            &raw mut length,
        )
    };
    if status == 0 {
        u32::try_from(process).ok().filter(|process| *process > 0)
    } else {
        None
    }
}
