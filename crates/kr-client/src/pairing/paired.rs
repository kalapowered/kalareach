//! What a device keeps about the hosts it paired with, and about an attempt still waiting.
//!
//! A paired-host record is everything the device needs to reach a host as what it became: the
//! host's device identity, key revision, keys, endpoint and network configuration; the identity
//! and grant the host gave this device; the rights it proposed; and the name the host gives
//! people. None of it is secret, so it lives in files in the application's own directory rather
//! than in the secret store, each written whole to a temporary file, flushed and renamed.
//!
//! A waiting attempt's state is kept beside it from the moment before the device proves itself to
//! the host, so a device that restarts while the owner decides can ask again rather than lose the
//! pairing: the host identifies a candidate by its endpoint, and nothing in that state is a secret
//! either.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use kr_crypto::connect::PairedPeer;
use kr_protocol::ids::{DeviceId, DeviceKeyRevision, GrantId, InvitationId};
use kr_protocol::pairing::{DevicePublicKeys, NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::EndpointKey;
use serde::{Deserialize, Serialize};

use super::failure::{FailureKind, PairingFailure};
use crate::shown::Shown;

/// The version of the records this store writes and reads.
const FORMAT_VERSION: u32 = 1;

/// The largest file this store reads. A record is a few kilobytes.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The file the paired hosts are kept in.
const HOSTS_FILE: &str = "hosts.json";

/// The file a waiting attempt is kept in.
const ATTEMPT_FILE: &str = "attempt.json";

/// A host this device is paired with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairedHost {
    /// The host's device identity.
    pub host_device_id: DeviceId,
    /// The revision of the host's keys.
    pub host_key_revision: DeviceKeyRevision,
    /// The host's purpose-separated public keys.
    pub host_keys: DevicePublicKeys,
    /// The host's iroh endpoint identity.
    pub host_endpoint_id: EndpointKey,
    /// The host's selected discovery and relay configuration, with its address hints.
    pub network_config: NetworkConfig,
    /// The identity the host gave this device.
    pub device_id: DeviceId,
    /// The grant the host issued this device.
    pub grant_id: GrantId,
    /// The rights the invitation proposed, which the host committed.
    pub proposed_grant: ProposedGrant,
    /// The name the host gives people, once it could be read.
    pub name: Option<String>,
    /// When the pairing committed, in UTC milliseconds.
    pub paired_at_ms: u64,
}

impl PairedHost {
    /// The host as this device's connection proof is checked against it.
    #[must_use]
    pub const fn peer(&self) -> PairedPeer {
        PairedPeer {
            device_id: self.host_device_id,
            device_key_revision: self.host_key_revision,
            authorisation: self.host_keys.authorisation,
            endpoint_id: self.host_endpoint_id,
        }
    }

    /// True when this device holds owner authority on the host: its grant manages the host.
    #[must_use]
    pub fn is_owner(&self) -> bool {
        self.proposed_grant
            .actions
            .contains(&ActionRight::HostManage)
    }
}

/// How a waiting attempt was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptMode {
    /// A short code.
    Code,
    /// A direct invitation.
    Direct,
}

/// An attempt that has proved itself to the host and waits for the owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingAttempt {
    /// How it was made.
    pub mode: AttemptMode,
    /// The invitation it answers.
    pub invitation_id: InvitationId,
    /// The host's device identity.
    pub host_device_id: DeviceId,
    /// The revision of the host's keys.
    pub host_key_revision: DeviceKeyRevision,
    /// The host's keys.
    pub host_keys: DevicePublicKeys,
    /// The host's endpoint.
    pub host_endpoint_id: EndpointKey,
    /// The host's network configuration.
    pub network_config: NetworkConfig,
    /// The rights the invitation proposes.
    pub proposed_grant: ProposedGrant,
    /// The value both devices display, as this device computed it.
    pub verification_value: String,
    /// True once the host has answered with the value this device computed. Until then the value
    /// is not shown: a device shows it only when the host's value is the one it computed.
    pub value_confirmed: bool,
    /// When the invitation expires, in UTC milliseconds, once the host has said.
    pub expires_at_ms: Option<u64>,
    /// When this device stops asking, in UTC milliseconds on its own clock.
    ///
    /// It is set when the attempt starts, from what this device knows without the service's word:
    /// an invitation lives five minutes, so a code entered now cannot be open much past five
    /// minutes from now, and a direct invitation's expiry is in the payload the device read. The
    /// host's own expiry, once it names one, can only bring it forward.
    pub recover_until_ms: u64,
    /// How many tries this device has left with the code, for a code attempt.
    pub tries_left: Option<u32>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostsFile {
    version: u32,
    hosts: Vec<PairedHost>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptFile {
    version: u32,
    attempt: PendingAttempt,
}

/// The paired-host records and the waiting attempt, in one directory of the application's own.
#[derive(Debug)]
pub struct PairedHosts {
    directory: PathBuf,
    /// Serialises this process's read-modify-write of the records.
    writing: Mutex<()>,
}

impl PairedHosts {
    /// Opens the records in `directory`, creating it owner-only when it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the directory cannot be created or is not one this
    /// user owns alone.
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, PairingFailure> {
        let directory = directory.into();
        kr_ipc::paths::create_private_directory(&directory).map_err(|error| {
            store_failed(crate::shown!(
                "{}: {}",
                Shown::root(&directory),
                Shown::ipc(&error)
            ))
        })?;
        Ok(Self {
            directory,
            writing: Mutex::new(()),
        })
    }

    /// The directory the records live in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Every host this device is paired with, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read. Records that cannot be
    /// read are an error, never an empty list: forgetting a pairing silently would leave a host
    /// holding a grant this device no longer knows it has.
    pub fn list(&self) -> Result<Vec<PairedHost>, PairingFailure> {
        let Some(bytes) = self.read(HOSTS_FILE)? else {
            return Ok(Vec::new());
        };
        let file: HostsFile = serde_json::from_slice(&bytes).map_err(|error| {
            store_failed(unreadable_host(&bytes).map_or_else(
                || crate::shown!("the paired hosts cannot be read: {}", Shown::json(&error)),
                |host| {
                    crate::shown!(
                        "the paired host {} in hosts.json cannot be read: {}",
                        host,
                        Shown::json(&error)
                    )
                },
            ))
        })?;
        if file.version != FORMAT_VERSION {
            return Err(store_failed(crate::shown!(
                "the paired hosts are version {}, and this release reads {}",
                file.version,
                FORMAT_VERSION
            )));
        }
        Ok(file.hosts)
    }

    /// The paired host whose endpoint is `endpoint_id`, if there is one.
    ///
    /// # Errors
    ///
    /// As [`Self::list`].
    pub fn by_endpoint(
        &self,
        endpoint_id: &EndpointKey,
    ) -> Result<Option<PairedHost>, PairingFailure> {
        Ok(self
            .list()?
            .into_iter()
            .find(|host| &host.host_endpoint_id == endpoint_id))
    }

    /// The paired host whose device identity is `host_device_id`, if there is one.
    ///
    /// # Errors
    ///
    /// As [`Self::list`].
    pub fn by_device(
        &self,
        host_device_id: DeviceId,
    ) -> Result<Option<PairedHost>, PairingFailure> {
        Ok(self
            .list()?
            .into_iter()
            .find(|host| host.host_device_id == host_device_id))
    }

    /// Records a paired host, replacing an earlier record of the same host.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read or written.
    pub fn record(&self, host: PairedHost) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        let mut hosts = self.list()?;
        hosts.retain(|existing| {
            existing.host_device_id != host.host_device_id
                && existing.host_endpoint_id != host.host_endpoint_id
        });
        hosts.push(host);
        self.write_hosts(hosts)
    }

    /// Forgets a paired host.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read or written.
    pub fn forget(&self, host_device_id: DeviceId) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        let mut hosts = self.list()?;
        hosts.retain(|existing| existing.host_device_id != host_device_id);
        self.write_hosts(hosts)
    }

    /// Keeps a waiting attempt, replacing any earlier one.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when it cannot be written.
    pub fn keep_attempt(&self, attempt: &PendingAttempt) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        let bytes = serde_json::to_vec(&AttemptFile {
            version: FORMAT_VERSION,
            attempt: attempt.clone(),
        })
        .map_err(|error| {
            store_failed(crate::shown!(
                "the attempt cannot be written: {}",
                Shown::json(&error)
            ))
        })?;
        self.write(ATTEMPT_FILE, &bytes)
    }

    /// The waiting attempt, if one is kept.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when it cannot be read.
    pub fn waiting_attempt(&self) -> Result<Option<PendingAttempt>, PairingFailure> {
        let Some(bytes) = self.read(ATTEMPT_FILE)? else {
            return Ok(None);
        };
        let file: AttemptFile =
            serde_json::from_slice(&bytes).map_err(|error| {
                store_failed(unreadable_attempt(&bytes).map_or_else(
                || crate::shown!("the waiting attempt cannot be read: {}", Shown::json(&error)),
                |invitation| {
                    crate::shown!(
                        "the waiting attempt for invitation {} in attempt.json cannot be read: {}",
                        invitation,
                        Shown::json(&error)
                    )
                },
            ))
            })?;
        if file.version != FORMAT_VERSION {
            return Err(store_failed(crate::shown!(
                "the waiting attempt is version {}, and this release reads {}",
                file.version,
                FORMAT_VERSION
            )));
        }
        Ok(Some(file.attempt))
    }

    /// Forgets the waiting attempt.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when it cannot be removed.
    pub fn clear_attempt(&self) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        let path = self.directory.join(ATTEMPT_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(store_failed(crate::shown!(
                "{}: {}",
                Shown::within(&self.directory, ATTEMPT_FILE),
                Shown::io(&error)
            ))),
        }
    }

    fn write_hosts(&self, hosts: Vec<PairedHost>) -> Result<(), PairingFailure> {
        let bytes = serde_json::to_vec(&HostsFile {
            version: FORMAT_VERSION,
            hosts,
        })
        .map_err(|error| {
            store_failed(crate::shown!(
                "the paired hosts cannot be written: {}",
                Shown::json(&error)
            ))
        })?;
        self.write(HOSTS_FILE, &bytes)
    }

    fn read(&self, name: &'static str) -> Result<Option<Vec<u8>>, PairingFailure> {
        let path = self.directory.join(name);
        kr_ipc::paths::read_owner_only_file(&path, MAX_FILE_BYTES)
            .map_err(|error| self.file_failed(name, &error))
    }

    fn write(&self, name: &'static str, bytes: &[u8]) -> Result<(), PairingFailure> {
        let path = self.directory.join(name);
        kr_ipc::paths::write_owner_only_file(&path, bytes)
            .map_err(|error| self.file_failed(name, &error))
    }

    /// Says which of the records' files could not be used, and why.
    fn file_failed(&self, name: &'static str, error: &kr_ipc::IpcError) -> PairingFailure {
        store_failed(crate::shown!(
            "{}: {}",
            Shown::within(&self.directory, name),
            Shown::ipc(error)
        ))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn store_failed(detail: Shown) -> PairingFailure {
    PairingFailure::new(FailureKind::StoreFailed, detail)
}

/// Names the paired host a file this build cannot read fails on: the host's device identity, or
/// where the host stands in the file when that identity cannot be read either. A record is named so
/// it can be found and removed; nothing else of it is said.
fn unreadable_host(bytes: &[u8]) -> Option<Shown> {
    let file: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    file.get("hosts")?
        .as_array()?
        .iter()
        .enumerate()
        .find(|(_, host)| serde_json::from_value::<PairedHost>((*host).clone()).is_err())
        .map(|(position, host)| {
            host.get("host_device_id")
                .and_then(|id| serde_json::from_value::<DeviceId>(id.clone()).ok())
                .map_or_else(
                    || crate::shown!("at position {}", position),
                    |id| crate::shown!("{}", id),
                )
        })
}

/// Names the invitation a waiting attempt this build cannot read was made for, when that
/// identity can be read.
fn unreadable_attempt(bytes: &[u8]) -> Option<Shown> {
    let file: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let invitation = file.get("attempt")?.get("invitation_id")?;
    serde_json::from_value::<InvitationId>(invitation.clone())
        .ok()
        .map(|invitation| crate::shown!("{}", invitation.get()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::DeviceKeys;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::scalars::{CanonicalSet, Nullable, Uuid};

    fn grant(actions: &[ActionRight]) -> ProposedGrant {
        ProposedGrant {
            parent_grant_id: Nullable::null(),
            environment_selector: EnvironmentSelector::Any,
            session_selector: SessionSelector::Any,
            actions: actions.iter().copied().collect::<CanonicalSet<_>>(),
            history: HistoryScope {
                lower_bound_ms: Nullable::null(),
                include_live_screen: true,
                named_questions: CanonicalSet::new(),
                named_approvals: CanonicalSet::new(),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    fn host(byte: u8, actions: &[ActionRight]) -> PairedHost {
        let keys = DeviceKeys::generate().expect("keys").public_keys();
        PairedHost {
            host_device_id: DeviceId::new(Uuid::from_bytes([byte; 16])),
            host_key_revision: DeviceKeyRevision::new(1),
            host_endpoint_id: keys.transport,
            host_keys: keys,
            network_config: NetworkConfig::empty(),
            device_id: DeviceId::new(Uuid::from_bytes([byte + 1; 16])),
            grant_id: GrantId::new(Uuid::from_bytes([byte + 2; 16])),
            proposed_grant: grant(actions),
            name: Some("r on macos".to_owned()),
            paired_at_ms: 1_764_000_000_000,
        }
    }

    /// A record written is the record read back, from a second store over the same directory, and
    /// a host paired again replaces its earlier record rather than standing beside it.
    #[test]
    fn a_paired_host_is_kept_and_read_back() {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let store = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        assert!(store.list().expect("readable").is_empty());
        let owner = host(1, &[ActionRight::HostManage, ActionRight::SessionView]);
        let viewer = host(7, &[ActionRight::SessionView]);
        store.record(owner.clone()).expect("recorded");
        store.record(viewer.clone()).expect("recorded");

        let reopened = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        assert_eq!(
            reopened.list().expect("readable"),
            vec![owner.clone(), viewer.clone()]
        );
        assert!(owner.is_owner());
        assert!(!viewer.is_owner());
        assert_eq!(
            reopened
                .by_endpoint(&viewer.host_endpoint_id)
                .expect("readable"),
            Some(viewer.clone())
        );

        let mut renamed = owner.clone();
        renamed.name = Some("studio".to_owned());
        reopened.record(renamed.clone()).expect("recorded");
        assert_eq!(reopened.list().expect("readable"), vec![viewer, renamed]);
    }

    /// Records that cannot be read are an error, never an empty list.
    #[test]
    fn records_that_cannot_be_read_are_an_error() {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let store = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        store
            .record(host(1, &[ActionRight::HostManage]))
            .expect("recorded");
        kr_ipc::paths::write_owner_only_file(
            &directory.path().join("pairing").join(HOSTS_FILE),
            b"{\"version\":1,\"hosts\":[{}]}",
        )
        .expect("overwritten");
        assert_eq!(
            store.list().expect_err("unreadable").kind,
            FailureKind::StoreFailed
        );
    }
}
