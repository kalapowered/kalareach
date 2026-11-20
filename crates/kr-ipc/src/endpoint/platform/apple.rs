//! What the Apple kernels say about a local socket and its volume that the standard library and
//! `rustix` do not reach: the process behind a connected socket, and whether the volume gives an
//! object number out again.

#![expect(
    unsafe_code,
    reason = "the process behind a connected local socket is a socket option that no safe \
              interface offers on Apple systems"
)]

use std::os::fd::{AsRawFd as _, BorrowedFd};
use std::path::Path;

use super::live::Volume;

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

/// What the volume of `folder` says about its object numbers.
///
/// The system's contract for the flag read here is that object ids on the file system are
/// persistent and not recycled, so an inode number that names a socket now never names another
/// file later. A volume that does not say so, and a read that fails, are told apart from a volume
/// that says it does.
pub(super) fn volume_ids(folder: &Path) -> Volume {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    /// What `getattrlist` returns for the volume capabilities: its own length, then the
    /// capabilities and the mask of those the volume answers for.
    #[repr(C)]
    struct Reply {
        length: u32,
        capabilities: [u32; 4],
        valid: [u32; 4],
    }

    let Ok(folder) = CString::new(folder.as_os_str().as_bytes()) else {
        return Volume::ReadFailed;
    };
    let mut wanted = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: 0,
        volattr: libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut reply = Reply {
        length: 0,
        capabilities: [0; 4],
        valid: [0; 4],
    };
    // SAFETY: the path is a valid C string for the whole call. The attribute list is a live local
    // of the type the call reads, and the reply buffer is a live local of the size passed with it,
    // which the call fills and never writes past.
    let status = unsafe {
        libc::getattrlist(
            folder.as_ptr(),
            (&raw mut wanted).cast(),
            (&raw mut reply).cast(),
            size_of::<Reply>(),
            0,
        )
    };
    if status != 0 || usize::try_from(reply.length).is_ok_and(|length| length < size_of::<Reply>())
    {
        return Volume::ReadFailed;
    }
    decode_ids(
        reply.capabilities[libc::VOL_CAPABILITIES_FORMAT],
        reply.valid[libc::VOL_CAPABILITIES_FORMAT],
    )
}

/// What the format word of a volume's capabilities says about persistent object numbers: the flag
/// must be both valid, meaning the volume answers for it, and supported.
pub(super) const fn decode_ids(capabilities: u32, valid: u32) -> Volume {
    const PATH_FROM_ID: u32 = libc::VOL_CAP_FMT_PATH_FROM_ID;
    if valid & PATH_FROM_ID == 0 {
        Volume::Unknown
    } else if capabilities & PATH_FROM_ID != 0 {
        Volume::Persistent
    } else {
        Volume::NotPersistent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A volume is persistent only when the flag is both valid and supported: every other word of
    /// the volume's answer, and every failed read, keeps a socket.
    #[test]
    fn a_volume_read_is_persistent_only_when_valid_and_supported() {
        let flag = libc::VOL_CAP_FMT_PATH_FROM_ID;
        assert_eq!(decode_ids(flag, flag), Volume::Persistent);
        assert_eq!(decode_ids(0, flag), Volume::NotPersistent);
        assert_eq!(decode_ids(flag, 0), Volume::Unknown);
        assert_eq!(decode_ids(0, 0), Volume::Unknown);
        // Every other bit set changes nothing.
        assert_eq!(decode_ids(!0, !0), Volume::Persistent);
        assert_eq!(decode_ids(!flag, !0), Volume::NotPersistent);
        assert_eq!(decode_ids(!0, !flag), Volume::Unknown);
        assert_eq!(
            volume_ids(Path::new("/this/folder/is/not/there")),
            Volume::ReadFailed
        );
    }
}
