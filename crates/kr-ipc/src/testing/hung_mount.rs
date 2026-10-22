//! A filesystem that never answers, or whose server has stopped, for the tests of every service
//! that opens a directory.
//!
//! A network mount whose server has gone makes every call that reaches it wait: a look at its
//! root included. [`HungMount`] is that for a caller: a filesystem in user space that is mounted
//! and never served. A test places it on a directory it owns, shows that the code under test
//! does not wait on it, and lets it go, which aborts the connection and so ends every call still
//! waiting on the mount.
//!
//! A mount whose server has stopped is the other way a network mount fails: nothing waits, and
//! every call that reaches it, a look at its root included, fails at once with an error that is
//! not a missing name. [`HungMount::stop_server`] makes the mount that.
//!
//! A host without `/dev/fuse` or the setuid helper a distribution installs for it cannot place
//! the mount. [`HungMount::attach_where_possible`] leaves the case out and says why, unless
//! `KR_REQUIRE_FUSE` is set, which a run that has to show the case ran sets.

use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, recvmsg};

/// A filesystem in user space that is mounted and never served: every request made of it, a look
/// at its root included, waits for an answer that does not come.
///
/// It is what a network mount whose server has gone is to a caller. The server end is held here,
/// and letting it go aborts the connection, which ends every call waiting on the mount. The
/// mount itself stays in place until this value is dropped.
#[derive(Debug)]
pub struct HungMount {
    server: Option<OwnedFd>,
    at: PathBuf,
}

impl HungMount {
    /// Mounts it at `at`, an empty directory this account owns, through the setuid helper a
    /// user-space filesystem is mounted with by an unprivileged account.
    ///
    /// The helper opens the control device, mounts it, and passes the descriptor back over the
    /// socket it is told of, which is how a server is given its end.
    ///
    /// # Errors
    ///
    /// Returns what this host lacks when it cannot place the mount.
    pub fn attach(at: &Path) -> Result<Self, String> {
        if !Path::new("/dev/fuse").exists() {
            return Err("this host has no /dev/fuse".to_owned());
        }
        let (ours, theirs) = UnixStream::pair().map_err(|error| error.to_string())?;
        // Held open across the helper's start, which a descriptor is not by default.
        rustix::io::fcntl_setfd(&theirs, rustix::io::FdFlags::empty())
            .map_err(|error| error.to_string())?;
        let helper = std::process::Command::new("fusermount3")
            .args(["-o", "rw,nosuid,nodev,fsname=kr-hung", "--"])
            .arg(at)
            .env("_FUSE_COMMFD", theirs.as_raw_fd().to_string())
            .output()
            .map_err(|error| format!("fusermount3 could not be run: {error}"))?;
        drop(theirs);
        if !helper.status.success() {
            return Err(format!(
                "fusermount3 would not place the mount: {}",
                String::from_utf8_lossy(&helper.stderr).trim()
            ));
        }
        let mut data = [0_u8; 1];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        // Marked to close on exec as it arrives, so that no process another case starts while the
        // mount is there keeps the server's end open and the connection alive.
        recvmsg(
            &ours,
            &mut [IoSliceMut::new(&mut data)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
        .map_err(|error| format!("the descriptor did not arrive: {error}"))?;
        let server = control.drain().find_map(|message| match message {
            RecvAncillaryMessage::ScmRights(mut descriptors) => descriptors.next(),
            _ => None,
        });
        Ok(Self {
            server: Some(server.ok_or("fusermount3 passed no descriptor")?),
            at: at.to_owned(),
        })
    }

    /// Mounts it at `at`, or says why this host cannot and returns nothing, so that the case
    /// returns without running.
    ///
    /// # Panics
    ///
    /// Panics, with what this host lacks, when it cannot place the mount and `KR_REQUIRE_FUSE` is
    /// set: a run that has to show the case ran must not count one that returned early.
    #[must_use]
    pub fn attach_where_possible(at: &Path) -> Option<Self> {
        match Self::attach(at) {
            Ok(mount) => Some(mount),
            Err(why) => {
                assert!(
                    std::env::var_os("KR_REQUIRE_FUSE").is_none(),
                    "this host cannot place the mount this check needs: {why}"
                );
                eprintln!("skipped: {why}");
                None
            }
        }
    }

    /// Stops the server and leaves the mount where it is: every call that reaches the mount fails
    /// at once with `ENOTCONN`, a look at its root included, as it does on a network mount whose
    /// server has stopped. A call already waiting on the mount ends with an error too.
    pub fn stop_server(&mut self) {
        drop(self.server.take());
    }
}

impl Drop for HungMount {
    fn drop(&mut self) {
        // The connection is aborted first, so that nothing is left waiting on the mount while it
        // comes off.
        drop(self.server.take());
        let _ = std::process::Command::new("fusermount3")
            .args(["-u", "-z"])
            .arg(&self.at)
            .status();
    }
}
