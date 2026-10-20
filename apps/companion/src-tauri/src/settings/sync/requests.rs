//! The revocation requests this computer published in a host's feed, which keep a device from being
//! shared with again.
//!
//! A request in a host's feed can still revoke the device it names: the host reads its feed when it
//! is next online and acts on what it finds. A device the settings were taken away from because of
//! it must not be given them again, or a host that acts afterwards would find a device holding a
//! key the person revoked it to lose. And a host that did act and is asleep again says nothing of
//! it, so a request the host carried out holds the device as well.
//!
//! **A record is let go of only by what names the request.** Each request is recorded by its own
//! identity before it leaves. Two things release it: the service answering that it refused the
//! request or that nothing was sent, which says the request is in no feed, and the feed showing
//! that the host refused it. Nothing else does. A feed that does not show the request, a restart, a
//! host that is asleep, an answer that was lost and a service this computer no longer uses all
//! leave it where it is, because none of them says the request cannot be carried out. Another
//! request, however it ends, cannot release this one. A record that cannot be read holds every
//! device.
//!
//! A request found in a feed that the record does not name, as one an earlier version published, is
//! recorded too. Forgetting a host lets go of what was recorded for its feed, since this computer
//! reads that feed no more, and a look at the feeds that began before the host was forgotten
//! records nothing.
//!
//! The record is a file beside the other records of settings sync, kept across a restart and seen
//! by a second companion over the same data directory.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use kr_protocol::scalars::AuthorisationKey;

use super::kept::Kept;
use crate::error::Result;

/// The file the requests are kept in.
const FILE: &str = "requested.json";

/// The file whose lock makes a change to [`FILE`] one act across companions.
const LOCK: &str = "requested.lock";

/// A request in a feed: the host whose feed it was published in, by the reference the page knows
/// the host by, the device it names, and the request's own identity.
type Request = (String, AuthorisationKey, String);

/// What this process knows of the record.
#[derive(Debug, Default)]
struct Known {
    /// The same requests as this process knows them, so that a record that cannot be written down
    /// still holds this process's sends.
    held: BTreeSet<Request>,
    /// How many times a host was forgotten: a look that began before one has not seen it.
    forgotten: u64,
}

/// The requests this computer has published in hosts' feeds.
#[derive(Debug)]
pub struct Requests {
    kept: Kept,
    known: Mutex<Known>,
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
            known: Mutex::new(Known::default()),
        }
    }

    fn known(&self) -> MutexGuard<'_, Known> {
        self.known.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Where a look at the feeds begins, to be given back to [`Self::found`].
    #[must_use]
    pub fn look_begins(&self) -> u64 {
        self.known().forgotten
    }

    /// Records the request `request` published in the feed of `host` for the device `device`. The
    /// request is not sent unless this returns `Ok`.
    ///
    /// A write can fail after it has done its work, and the record then names the request all the
    /// same: that is held.
    ///
    /// # Errors
    ///
    /// Returns why the record could not be made durable.
    pub fn raise(&self, host: &str, device: AuthorisationKey, request: &str) -> Result<()> {
        let wanted: Request = (host.to_owned(), device, request.to_owned());
        let outcome = self.kept.change(
            |kept: &mut BTreeSet<Request>| {
                kept.insert(wanted.clone());
            },
            |kept| kept.contains(&wanted),
        );
        match outcome {
            Ok(()) => {
                self.known().held.insert(wanted);
                Ok(())
            }
            Err(unwritten) => {
                if unwritten.landed {
                    self.known().held.insert(wanted);
                }
                Err(unwritten.error)
            }
        }
    }

    /// Records requests a look at the feed of `host` found there that the record does not name, as
    /// far as the file allows: this process holds them from memory when it cannot be written. A
    /// look that began before a host was forgotten records nothing.
    pub fn found(&self, began: u64, host: &str, requests: &[(AuthorisationKey, String)]) {
        // Every look at every host comes here, and most find nothing: no lock, no flush for that.
        if requests.is_empty() {
            return;
        }
        let mut known = self.known();
        if known.forgotten != began {
            return;
        }
        let found: Vec<Request> = requests
            .iter()
            .map(|(device, request)| (host.to_owned(), *device, request.clone()))
            .collect();
        known.held.extend(found.iter().cloned());
        let _ = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.extend(found.iter().cloned()),
            |_| false,
        );
    }

    /// Lets go of the requests `requests` names in the feed of `host`: the service refused them, or
    /// the feed shows the host refused them. A record that cannot be written lets go of nothing.
    pub fn release(&self, host: &str, requests: &[String]) {
        if requests.is_empty() {
            return;
        }
        let gone = |request: &Request| request.0 == host && requests.contains(&request.2);
        let written = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.retain(|request| !gone(request)),
            |_| false,
        );
        if written.is_ok() {
            self.known().held.retain(|request| !gone(request));
        }
    }

    /// Lets go of every request recorded for the feed of `host`, which this computer reads no more:
    /// nothing could ever say they are settled. A record that cannot be written lets go of nothing.
    pub fn forget_host(&self, host: &str) {
        let mut known = self.known();
        known.forgotten += 1;
        let written = self.kept.change(
            |kept: &mut BTreeSet<Request>| kept.retain(|request| request.0 != host),
            |_| false,
        );
        if written.is_ok() {
            known.held.retain(|request| request.0 != host);
        }
    }

    /// Whether a request for `device` is recorded in any host's feed. A record that cannot be read
    /// holds every device: nothing is offered that a record this computer cannot read might forbid.
    #[must_use]
    pub fn holds(&self, device: &AuthorisationKey) -> bool {
        self.known().held.iter().any(|(_, held, _)| held == device)
            || self
                .kept
                .on_disk::<Request>()
                .map_or(true, |kept| kept.iter().any(|(_, held, _)| held == device))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> AuthorisationKey {
        AuthorisationKey::from_bytes([byte; 32])
    }

    fn requests_in(directory: &tempfile::TempDir) -> Requests {
        Requests::in_directory(&directory.path().join("settings-sync"))
    }

    /// A request is recorded before it is sent, and a second companion over the same directory, or
    /// this one after a restart, finds it there.
    #[test]
    fn a_recorded_request_is_found_by_a_record_opened_over_the_same_directory() {
        let directory = tempfile::tempdir().expect("a directory");
        requests_in(&directory)
            .raise("host-a", key(7), "one")
            .expect("the record is written");

        let restarted = requests_in(&directory);
        assert!(restarted.holds(&key(7)));
        assert!(!restarted.holds(&key(8)));
    }

    /// A request is let go of by its own identity alone: a second request for the device in the same
    /// feed is still held, and a request of another host's feed is not released by one of this
    /// feed's.
    #[test]
    fn a_request_is_let_go_of_by_its_own_identity_only() {
        let directory = tempfile::tempdir().expect("a directory");
        let requests = requests_in(&directory);
        requests.raise("host-a", key(7), "one").expect("written");
        requests.raise("host-a", key(7), "two").expect("written");
        requests.raise("host-b", key(8), "one").expect("written");

        requests.release("host-a", &["one".to_owned()]);
        assert!(requests.holds(&key(7)), "the second request is still held");
        requests.release("host-b", &["two".to_owned()]);
        assert!(
            requests.holds(&key(8)),
            "no request of host-b has that identity"
        );
        requests.release("host-a", &["one".to_owned(), "two".to_owned()]);
        assert!(!requests.holds(&key(7)));
        assert!(
            requests.holds(&key(8)),
            "host-b's request is another feed's"
        );
        requests.release("host-b", &["one".to_owned()]);
        assert!(!requests.holds(&key(8)));
    }

    /// A record that cannot be read holds every device, so that nothing is offered on the strength
    /// of not knowing.
    #[test]
    fn a_record_that_cannot_be_read_holds_every_device() {
        let directory = tempfile::tempdir().expect("a directory");
        let kept = directory.path().join("settings-sync");
        let requests = requests_in(&directory);
        kr_ipc::paths::create_private_directory(&kept).expect("the directory");
        std::fs::write(kept.join(FILE), b"not a record").expect("a record this build cannot read");

        assert!(requests.holds(&key(1)));
        assert!(requests.holds(&key(2)));
    }

    /// A look at the feeds that began before a host was forgotten records nothing of it: what it
    /// found was read from a feed this computer no longer reads, and nothing would ever settle it.
    #[test]
    fn a_look_that_began_before_a_host_was_forgotten_records_nothing() {
        let directory = tempfile::tempdir().expect("a directory");
        let requests = requests_in(&directory);
        let began = requests.look_begins();
        requests.forget_host("host-a");

        requests.found(began, "host-a", &[(key(7), "one".to_owned())]);
        assert!(!requests.holds(&key(7)));
        requests.found(
            requests.look_begins(),
            "host-a",
            &[(key(7), "one".to_owned())],
        );
        assert!(
            requests.holds(&key(7)),
            "a look that began after it records what it finds"
        );
    }
}
