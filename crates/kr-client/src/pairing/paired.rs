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
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::ids::{DeviceId, DeviceKeyRevision, GrantId, InvitationId};
use kr_protocol::pairing::{DevicePublicKeys, NetworkConfig, ProposedGrant};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{EndpointKey, Nullable};
use serde::{Deserialize, Serialize};

use super::checkpoint::{PairedCheckpoints, PairingId};
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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The revision of this device's own keys that the host holds, which a connection offers: the
    /// host refuses a device that offers another. It is 1 from the pairing and moves forward only,
    /// when the host takes a higher revision of this device's preview key. A record at 1 leaves it
    /// out, so the file is what a device wrote before the revision was kept.
    #[serde(default = "first_revision", skip_serializing_if = "is_first_revision")]
    pub device_key_revision: DeviceKeyRevision,
}

fn first_revision() -> DeviceKeyRevision {
    DeviceKeyRevision::new(1)
}

fn is_first_revision(revision: &DeviceKeyRevision) -> bool {
    *revision == first_revision()
}

crate::debug_fields!(PairedHost {
    host_device_id,
    host_key_revision,
    device_id,
    grant_id,
    paired_at_ms,
    device_key_revision
});

/// What a device needs to reach a host as the device it became: who the host is, where it is, and
/// the organisation its grant answers to.
///
/// It is read from a paired-host record or from an attempt that has not yet written one, so a
/// device that was committed while it was not listening reaches the host through the same connect;
/// `pairing` says which of the two it was read from. It is owned, never stored and never
/// serialised.
#[derive(Clone, PartialEq, Eq)]
pub struct HostCredentials {
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
    /// The organisation membership the host's grant to this device requires, if it does.
    pub organisation: Nullable<OrganisationRequirement>,
    /// The identity the host gave this device in the pairing that a record holds. None for an
    /// attempt that has written no record, which dials as the identity derived for it.
    pub pairing: Option<DeviceId>,
}

crate::debug_fields!(HostCredentials {
    host_device_id,
    host_key_revision
});

impl HostCredentials {
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
}

impl PairedHost {
    /// What this device needs to reach the host as the device it became.
    #[must_use]
    pub fn credentials(&self) -> HostCredentials {
        HostCredentials {
            host_device_id: self.host_device_id,
            host_key_revision: self.host_key_revision,
            host_keys: self.host_keys,
            host_endpoint_id: self.host_endpoint_id,
            network_config: self.network_config.clone(),
            organisation: self.proposed_grant.organisation,
            pairing: Some(self.device_id),
        }
    }

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
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl PendingAttempt {
    /// What this device needs to reach the host as the device it will become, read from what the
    /// attempt already holds of the host.
    #[must_use]
    pub fn credentials(&self) -> HostCredentials {
        HostCredentials {
            host_device_id: self.host_device_id,
            host_key_revision: self.host_key_revision,
            host_keys: self.host_keys,
            host_endpoint_id: self.host_endpoint_id,
            network_config: self.network_config.clone(),
            organisation: self.proposed_grant.organisation,
            pairing: None,
        }
    }
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

/// What the first write of a completion did, and why it wrote nothing when it did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstWrite {
    /// The waiting attempt names the completion's invitation, and the host is recorded.
    Recorded,
    /// No waiting attempt is kept: nothing of this attempt stands.
    AttemptGone,
    /// The waiting attempt names another invitation, which a newer pairing started: that pairing's
    /// record and attempt file were left as they were.
    NewerAttempt,
}

/// How the waiting attempt that is kept stands toward one invitation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptStanding {
    Names,
    NamesAnother,
    Absent,
}

/// The paired-host records and the waiting attempt, in one directory of the application's own.
pub struct PairedHosts {
    directory: PathBuf,
    /// Serialises this process's read-modify-write of the records.
    writing: Mutex<()>,
}

crate::debug_as_name!(PairedHosts);

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

    /// The checkpoints the hosts gave this device, kept in the same directory.
    #[must_use]
    pub fn checkpoints(&self) -> PairedCheckpoints {
        PairedCheckpoints::at(self.directory.clone())
    }

    /// Every host this device is paired with, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read. Records that cannot be
    /// read are an error, never an empty list: forgetting a pairing silently would leave a host
    /// holding a grant this device no longer knows it has.
    pub fn list(&self) -> Result<Vec<PairedHost>, PairingFailure> {
        read_hosts(&self.directory)
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
        self.record_locked(host)
    }

    /// Records the paired host that the attempt of `invitation_id` made, replacing an earlier record
    /// of the same host, only while the waiting attempt that is kept still names that invitation.
    ///
    /// Another window's attempt that finished first records its own pairing and takes the attempt
    /// file, and this one must not replace that record. Says whether the host was recorded, and why
    /// not when it was not: nothing was written then.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records or the attempt cannot be read or written.
    pub fn record_first(
        &self,
        host: PairedHost,
        invitation_id: InvitationId,
    ) -> Result<FirstWrite, PairingFailure> {
        let _writing = self.lock();
        match self.attempt_standing(invitation_id)? {
            AttemptStanding::Names => {
                self.record_locked(host)?;
                Ok(FirstWrite::Recorded)
            }
            AttemptStanding::Absent => Ok(FirstWrite::AttemptGone),
            AttemptStanding::NamesAnother => Ok(FirstWrite::NewerAttempt),
        }
    }

    /// Sets the name of the recorded pairing `id`, and nothing else of the record.
    ///
    /// The pairing is found by all three parts of its identity, the host's endpoint among them, so
    /// the record of a pairing that was removed, or replaced by another one of the host, is not
    /// written again. Returns whether the pairing is recorded; when it is not, nothing was written.
    /// A name that is `None` or already the record's changes nothing.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read or written.
    pub fn name_pairing(
        &self,
        id: PairingId,
        name: Option<String>,
    ) -> Result<bool, PairingFailure> {
        let _writing = self.lock();
        let mut hosts = self.list()?;
        let Some(host) = hosts.iter_mut().find(|host| PairingId::of(host) == id) else {
            return Ok(false);
        };
        let Some(name) = name.filter(|name| host.name.as_ref() != Some(name)) else {
            return Ok(true);
        };
        host.name = Some(name);
        self.write_hosts(hosts)?;
        Ok(true)
    }

    /// The write of [`Self::record`], with the lock held.
    fn record_locked(&self, host: PairedHost) -> Result<(), PairingFailure> {
        let mut hosts = self.list()?;
        hosts.retain(|existing| {
            existing.host_device_id != host.host_device_id
                && existing.host_endpoint_id != host.host_endpoint_id
        });
        hosts.push(host);
        self.write_hosts(hosts)
    }

    /// How the waiting attempt that is kept stands toward `invitation_id`.
    fn attempt_standing(
        &self,
        invitation_id: InvitationId,
    ) -> Result<AttemptStanding, PairingFailure> {
        Ok(match self.waiting_attempt()? {
            None => AttemptStanding::Absent,
            Some(attempt) if attempt.invitation_id == invitation_id => AttemptStanding::Names,
            Some(_) => AttemptStanding::NamesAnother,
        })
    }

    /// Records that the host holds `revision` of this device's keys, for the pairing that gave this
    /// device `device_id` on `host_device_id`. The revision moves forward only: one that is not
    /// higher than the record's changes nothing, and a pairing that is another's is left alone.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the records cannot be read or written.
    pub fn raise_revision(
        &self,
        host_device_id: DeviceId,
        device_id: DeviceId,
        revision: DeviceKeyRevision,
    ) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        let mut hosts = self.list()?;
        let Some(host) = hosts
            .iter_mut()
            .find(|host| host.host_device_id == host_device_id && host.device_id == device_id)
        else {
            return Ok(());
        };
        if revision <= host.device_key_revision {
            return Ok(());
        }
        host.device_key_revision = revision;
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
        self.remove_attempt()
    }

    /// Forgets the waiting attempt only while it names `invitation_id`: the attempt file that
    /// another window's attempt took the place of is left as it is. Nothing is written otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`FailureKind::StoreFailed`] when the attempt cannot be read or removed.
    pub fn clear_attempt_of(&self, invitation_id: InvitationId) -> Result<(), PairingFailure> {
        let _writing = self.lock();
        if self.attempt_standing(invitation_id)? != AttemptStanding::Names {
            return Ok(());
        }
        self.remove_attempt()
    }

    /// The removal of the attempt file, whose name is fixed, with the lock held.
    fn remove_attempt(&self) -> Result<(), PairingFailure> {
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
        read_in(&self.directory, name)
    }

    fn write(&self, name: &'static str, bytes: &[u8]) -> Result<(), PairingFailure> {
        let path = self.directory.join(name);
        kr_ipc::paths::write_owner_only_file(&path, bytes)
            .map_err(|error| self.file_failed(name, &error))
    }

    /// Says which of the records' files could not be used, and why.
    fn file_failed(&self, name: &'static str, error: &kr_ipc::IpcError) -> PairingFailure {
        file_failed_in(&self.directory, name, error)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Every host recorded in `directory`, oldest first, read as [`PairedHosts::list`] reads them.
///
/// It takes no store: a holder that never writes the records, and so opens none, reads them
/// through this.
///
/// # Errors
///
/// As [`PairedHosts::list`].
pub(super) fn read_hosts(directory: &Path) -> Result<Vec<PairedHost>, PairingFailure> {
    let Some(bytes) = read_in(directory, HOSTS_FILE)? else {
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

fn read_in(directory: &Path, name: &'static str) -> Result<Option<Vec<u8>>, PairingFailure> {
    let path = directory.join(name);
    kr_ipc::paths::read_owner_only_file(&path, MAX_FILE_BYTES)
        .map_err(|error| file_failed_in(directory, name, &error))
}

fn file_failed_in(
    directory: &Path,
    name: &'static str,
    error: &kr_ipc::IpcError,
) -> PairingFailure {
    store_failed(crate::shown!(
        "{}: {}",
        Shown::within(directory, name),
        Shown::ipc(error)
    ))
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
            device_key_revision: kr_protocol::ids::DeviceKeyRevision::new(1),
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

    /// The revision of this device's keys the host holds moves forward only, for the pairing it
    /// names, and a record at the first revision is the file an earlier build wrote.
    #[test]
    fn the_revision_the_host_holds_moves_forward_only_for_its_own_pairing() {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let store = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        let paired = host(1, &[ActionRight::SessionView]);
        store.record(paired.clone()).expect("recorded");
        let first = std::fs::read(store.directory().join(HOSTS_FILE)).expect("the file");
        assert!(
            !String::from_utf8_lossy(&first).contains("device_key_revision"),
            "a record at the first revision leaves it out"
        );
        let held = |store: &PairedHosts| {
            store
                .by_device(paired.host_device_id)
                .expect("readable")
                .expect("the host")
                .device_key_revision
                .get()
        };
        let revision = DeviceKeyRevision::new;

        store
            .raise_revision(paired.host_device_id, paired.device_id, revision(3))
            .expect("raised");
        assert_eq!(held(&store), 3);
        store
            .raise_revision(paired.host_device_id, paired.device_id, revision(2))
            .expect("a lower revision changes nothing");
        assert_eq!(held(&store), 3);
        let another = DeviceId::new(Uuid::from_bytes([9; 16]));
        store
            .raise_revision(paired.host_device_id, another, revision(5))
            .expect("another pairing is left alone");
        assert_eq!(held(&store), 3);
        let reopened = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        assert_eq!(held(&reopened), 3, "it is kept");
    }

    /// The attempt that made `paired`, under the invitation numbered `invitation`.
    fn attempt_of(paired: &PairedHost, invitation: u8) -> PendingAttempt {
        PendingAttempt {
            mode: AttemptMode::Direct,
            invitation_id: InvitationId::new(Uuid::from_bytes([invitation; 16])),
            host_device_id: paired.host_device_id,
            host_key_revision: paired.host_key_revision,
            host_keys: paired.host_keys,
            host_endpoint_id: paired.host_endpoint_id,
            network_config: NetworkConfig::empty(),
            proposed_grant: grant(&[ActionRight::SessionView]),
            verification_value: "f3c146fd".to_owned(),
            value_confirmed: true,
            expires_at_ms: None,
            recover_until_ms: 1,
            tries_left: None,
        }
    }

    /// A store in a folder of its own, and the folder that holds it.
    fn store_in_a_folder() -> (tempfile::TempDir, PairedHosts) {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let store = PairedHosts::open(directory.path().join("pairing")).expect("a store");
        (directory, store)
    }

    /// The bytes of a file of the store, when it stands.
    fn file_of(store: &PairedHosts, name: &str) -> Option<Vec<u8>> {
        std::fs::read(store.directory().join(name)).ok()
    }

    /// A name is written on the record of the pairing it is made for, and nothing else of the
    /// record changes.
    #[test]
    fn a_name_is_set_on_the_record_and_nothing_else_of_it_changes() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.record(paired.clone()).expect("recorded");
        store
            .raise_revision(
                paired.host_device_id,
                paired.device_id,
                DeviceKeyRevision::new(3),
            )
            .expect("raised");
        assert_eq!(
            store.name_pairing(PairingId::of(&paired), Some("kitchen-pc".to_owned())),
            Ok(true)
        );
        assert_eq!(
            store.list().expect("readable"),
            vec![PairedHost {
                name: Some("kitchen-pc".to_owned()),
                device_key_revision: DeviceKeyRevision::new(3),
                ..paired
            }]
        );
    }

    /// A name for a pairing that was removed writes nothing, and says so.
    #[test]
    fn a_name_for_a_pairing_that_is_not_recorded_writes_nothing() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.record(paired.clone()).expect("recorded");
        store.forget(paired.host_device_id).expect("forgotten");
        let before = file_of(&store, HOSTS_FILE);
        assert_eq!(
            store.name_pairing(PairingId::of(&paired), Some("kitchen-pc".to_owned())),
            Ok(false)
        );
        assert_eq!(file_of(&store, HOSTS_FILE), before);
    }

    /// A name for the pairing at another endpoint of the same declared identities writes nothing:
    /// the record that stands is another pairing.
    #[test]
    fn a_name_for_the_pairing_at_another_endpoint_writes_nothing() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.record(paired.clone()).expect("recorded");
        let other = PairedHost {
            host_endpoint_id: host(2, &[ActionRight::SessionView]).host_endpoint_id,
            ..paired.clone()
        };
        let before = file_of(&store, HOSTS_FILE);
        assert_eq!(
            store.name_pairing(PairingId::of(&other), Some("kitchen-pc".to_owned())),
            Ok(false)
        );
        assert_eq!(file_of(&store, HOSTS_FILE), before);
    }

    /// A name that is absent, or is the record's own, writes nothing and still finds the pairing.
    #[test]
    fn an_absent_name_and_the_records_own_name_write_nothing() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.record(paired.clone()).expect("recorded");
        let before = file_of(&store, HOSTS_FILE);
        assert_eq!(store.name_pairing(PairingId::of(&paired), None), Ok(true));
        assert_eq!(
            store.name_pairing(PairingId::of(&paired), paired.name.clone()),
            Ok(true)
        );
        assert_eq!(file_of(&store, HOSTS_FILE), before);
    }

    /// The first write of an attempt records the host while the attempt file names its invitation.
    #[test]
    fn the_first_write_records_the_host_while_the_attempt_names_its_invitation() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.keep_attempt(&attempt_of(&paired, 4)).expect("kept");
        assert_eq!(
            store.record_first(paired.clone(), InvitationId::new(Uuid::from_bytes([4; 16]))),
            Ok(FirstWrite::Recorded)
        );
        assert_eq!(store.list().expect("readable"), vec![paired]);
    }

    /// The first write of an attempt whose file another attempt took the place of writes nothing.
    #[test]
    fn the_first_write_writes_nothing_when_the_attempt_file_names_another_invitation() {
        let (_directory, store) = store_in_a_folder();
        let newer = host(1, &[ActionRight::SessionView]);
        store.record(newer.clone()).expect("recorded");
        store.keep_attempt(&attempt_of(&newer, 9)).expect("kept");
        let before = file_of(&store, HOSTS_FILE);
        let ours = host(1, &[ActionRight::SessionView]);
        assert_eq!(
            store.record_first(ours, InvitationId::new(Uuid::from_bytes([4; 16]))),
            Ok(FirstWrite::NewerAttempt)
        );
        assert_eq!(file_of(&store, HOSTS_FILE), before);
    }

    /// The first write of an attempt whose file was cleared writes nothing.
    #[test]
    fn the_first_write_writes_nothing_when_no_attempt_is_kept() {
        let (_directory, store) = store_in_a_folder();
        let ours = host(1, &[ActionRight::SessionView]);
        assert_eq!(
            store.record_first(ours, InvitationId::new(Uuid::from_bytes([4; 16]))),
            Ok(FirstWrite::AttemptGone)
        );
        assert_eq!(file_of(&store, HOSTS_FILE), None);
    }

    /// The attempt file is removed while it names the invitation the clearing was started for.
    #[test]
    fn an_attempt_is_cleared_while_it_names_the_invitation() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.keep_attempt(&attempt_of(&paired, 4)).expect("kept");
        store
            .clear_attempt_of(InvitationId::new(Uuid::from_bytes([4; 16])))
            .expect("cleared");
        assert_eq!(file_of(&store, ATTEMPT_FILE), None);
    }

    /// The attempt file of another invitation is left as it is, byte for byte.
    #[test]
    fn an_attempt_that_names_another_invitation_is_left_as_it_is() {
        let (_directory, store) = store_in_a_folder();
        let paired = host(1, &[ActionRight::SessionView]);
        store.keep_attempt(&attempt_of(&paired, 9)).expect("kept");
        let before = file_of(&store, ATTEMPT_FILE);
        assert!(before.is_some());
        store
            .clear_attempt_of(InvitationId::new(Uuid::from_bytes([4; 16])))
            .expect("nothing to clear");
        assert_eq!(file_of(&store, ATTEMPT_FILE), before);
    }

    /// A record's credentials name the pairing the record holds, and an attempt's, which has
    /// written no record, name none.
    #[test]
    fn credentials_name_a_pairing_only_where_a_record_holds_it() {
        let paired = host(1, &[ActionRight::SessionView]);
        assert_eq!(paired.credentials().pairing, Some(paired.device_id));

        let pending = PendingAttempt {
            mode: AttemptMode::Direct,
            invitation_id: InvitationId::new(Uuid::from_bytes([4; 16])),
            host_device_id: paired.host_device_id,
            host_key_revision: paired.host_key_revision,
            host_keys: paired.host_keys,
            host_endpoint_id: paired.host_endpoint_id,
            network_config: NetworkConfig::empty(),
            proposed_grant: grant(&[ActionRight::SessionView]),
            verification_value: "f3c146fd".to_owned(),
            value_confirmed: true,
            expires_at_ms: None,
            recover_until_ms: 1,
            tries_left: None,
        };
        let credentials = pending.credentials();
        assert_eq!(credentials.pairing, None);
        assert_eq!(credentials.host_device_id, paired.host_device_id);
        assert_eq!(credentials.host_endpoint_id, paired.host_endpoint_id);
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
