//! The revocation requests this computer put in a host's feed that no read of that feed has since
//! shown refused or gone.
//!
//! A request in a host's feed can still revoke the device it names: the host reads its feed when it
//! is next online, and acts on what it finds. Until it has, a device the settings were taken away
//! from because of the request must not be given them again, or a host that acts afterwards would
//! find a device holding a key the person revoked it to lose.
//!
//! **What is not known is in force.** A record of a request is written before the request leaves,
//! and kept whatever becomes of the send, since a reply can be lost after a feed stored the
//! request. It is let go of only when a read of that host's feed, begun after the send ended, shows
//! the request refused, acted on or not there. A restart, a feed that cannot be read, a host that
//! is asleep and a request that was sent and not heard of all leave it where it is, so nothing is
//! offered on the strength of not knowing. A record that cannot be read holds every device.
//!
//! The record is a file beside the other records of settings sync, kept across a restart and seen
//! by a second companion over the same data directory. A read here is ordered against this
//! process's own sends only: a send by a second companion at the moment this one's read ends is
//! not, and the next read of the feed settles it.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use kr_protocol::scalars::AuthorisationKey;

use super::kept::Kept;
use crate::error::Result;

/// The file the requests are kept in.
const FILE: &str = "requested.json";

/// The file whose lock makes a change to [`FILE`] one act across companions.
const LOCK: &str = "requested.lock";

/// A request in a feed: the host whose feed holds it, by the reference the page knows the host by,
/// and the device it names.
type Request = (String, AuthorisationKey);

/// The requests this computer has in hosts' feeds that may still be carried out.
#[derive(Debug)]
pub struct Requests {
    kept: Kept,
    /// The same requests as this process knows them, so that a record that cannot be written down
    /// still holds this process's sends.
    held: Mutex<BTreeSet<Request>>,
}

impl Requests {
    /// The record kept in `directory`.
    #[must_use]
    pub(in crate::settings) fn in_directory(directory: &Path) -> Self {
        Self {
            kept: Kept::in_directory(
                directory,
                FILE,
                LOCK,
                "this computer's record of revocation requests in a feed",
            ),
            held: Mutex::new(BTreeSet::new()),
        }
    }

    fn held(&self) -> std::sync::MutexGuard<'_, BTreeSet<Request>> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records that the feed of `host` is about to hold a request for each of `devices`. The
    /// request is not sent unless this returns `Ok`.
    ///
    /// A write can fail after it has done its work, and the record then names the requests all the
    /// same: that is held, as a request not sent is let go of by the first read that finds none.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be made durable.
    pub fn raise(&self, host: &str, devices: &[AuthorisationKey]) -> Result<()> {
        let wanted: Vec<Request> = devices
            .iter()
            .map(|device| (host.to_owned(), *device))
            .collect();
        let outcome = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.extend(wanted.iter().cloned()),
            |kept| wanted.iter().all(|request| kept.contains(request)),
        );
        match outcome {
            Ok(()) => {
                self.held().extend(wanted);
                Ok(())
            }
            Err(unwritten) => {
                if unwritten.landed {
                    self.held().extend(wanted);
                }
                Err(unwritten.error)
            }
        }
    }

    /// Records requests a read of the feed of `host` found there that the record does not name, as
    /// far as the file allows: this process holds them from memory when it cannot be written.
    pub fn found(&self, host: &str, devices: &[AuthorisationKey]) {
        let found: Vec<Request> = devices
            .iter()
            .map(|device| (host.to_owned(), *device))
            .collect();
        self.held().extend(found.iter().cloned());
        let _ = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.extend(found.iter().cloned()),
            |_| false,
        );
    }

    /// Lets go of the requests for `devices` in the feed of `host`, which a read of that feed has
    /// shown refused, acted on or not there. A record that cannot be written lets go of nothing.
    pub fn release(&self, host: &str, devices: &[AuthorisationKey]) {
        let gone: Vec<Request> = devices
            .iter()
            .map(|device| (host.to_owned(), *device))
            .collect();
        let written = self.kept.change(
            |kept: &mut BTreeSet<Request>| {
                for request in &gone {
                    kept.remove(request);
                }
            },
            |_| false,
        );
        if written.is_ok() {
            self.held().retain(|request| !gone.contains(request));
        }
    }

    /// Lets go of every request recorded for the feed of `host`, which this computer no longer
    /// reads: nothing could ever say they are settled. A record that cannot be written lets go of
    /// nothing.
    pub fn forget_host(&self, host: &str) {
        let written = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.retain(|(each, _)| each != host),
            |_| false,
        );
        if written.is_ok() {
            self.held().retain(|(each, _)| each != host);
        }
    }

    /// The devices a request is recorded for in the feed of `host`, as far as this process can say:
    /// those it holds, and those in the file when it can be read.
    #[must_use]
    pub fn of(&self, host: &str) -> Vec<AuthorisationKey> {
        let mut all: BTreeSet<Request> = self.kept.on_disk().unwrap_or_default();
        all.extend(self.held().iter().cloned());
        all.into_iter()
            .filter(|(each, _)| each == host)
            .map(|(_, device)| device)
            .collect()
    }

    /// Whether any request is recorded. A record that cannot be read says yes.
    #[must_use]
    pub fn any(&self) -> bool {
        !self.held().is_empty()
            || self
                .kept
                .on_disk::<Request>()
                .map_or(true, |kept| !kept.is_empty())
    }

    /// Whether a request for `device` is recorded in any host's feed. A record that cannot be read
    /// holds every device: nothing is offered that a record this computer cannot read might forbid.
    #[must_use]
    pub fn holds(&self, device: &AuthorisationKey) -> bool {
        self.held().iter().any(|(_, held)| held == device)
            || self
                .kept
                .on_disk::<Request>()
                .map_or(true, |kept| kept.iter().any(|(_, held)| held == device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> AuthorisationKey {
        AuthorisationKey::from_bytes([byte; 32])
    }

    /// A request is recorded before it is sent, and a second companion over the same directory, or
    /// this one after a restart, finds it there.
    #[test]
    fn a_recorded_request_is_found_by_a_record_opened_over_the_same_directory() {
        let directory = tempfile::tempdir().expect("a directory");
        let kept = directory.path().join("settings-sync");
        Requests::in_directory(&kept)
            .raise("host-a", &[key(7)])
            .expect("the record is written");

        let restarted = Requests::in_directory(&kept);
        assert!(restarted.holds(&key(7)));
        assert!(!restarted.holds(&key(8)));
        assert_eq!(restarted.of("host-a"), vec![key(7)]);
        assert!(restarted.of("host-b").is_empty());
    }

    /// A request for one host's feed is let go of for that host alone: a device with requests in
    /// two feeds is still held while the other host's is.
    #[test]
    fn a_request_is_let_go_of_for_its_own_host_only() {
        let directory = tempfile::tempdir().expect("a directory");
        let requests = Requests::in_directory(&directory.path().join("settings-sync"));
        requests.raise("host-a", &[key(7)]).expect("written");
        requests.raise("host-b", &[key(7)]).expect("written");

        requests.release("host-a", &[key(7)]);
        assert!(
            requests.holds(&key(7)),
            "host-b's request is still in force"
        );
        requests.release("host-b", &[key(7)]);
        assert!(!requests.holds(&key(7)));
    }

    /// A record that cannot be read holds every device, so that nothing is offered on the strength
    /// of not knowing.
    #[test]
    fn a_record_that_cannot_be_read_holds_every_device() {
        let directory = tempfile::tempdir().expect("a directory");
        let kept = directory.path().join("settings-sync");
        let requests = Requests::in_directory(&kept);
        kr_ipc::paths::create_private_directory(&kept).expect("the directory");
        std::fs::write(kept.join(FILE), b"not a record").expect("a record this build cannot read");

        assert!(requests.holds(&key(1)));
        assert!(requests.holds(&key(2)));
    }
}
