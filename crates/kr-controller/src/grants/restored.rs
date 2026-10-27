//! The record that a restored policy row waits for the owner, in a store of its own.
//!
//! The host compares the revision its authority feed holds for it with the registry's. A feed that
//! is ahead means the registry, and the policy row in it, is an earlier state than one this host
//! issued. The host then carries out again what the feed shows completed and raises the registry,
//! but the row itself (the enrolments, the exclusive-management flag, the offline bound and the
//! lease records) is the restored one, and the feed holds none of it. This file is how the host
//! remembers that it found the row restored and that nobody has looked at it: while it stands,
//! every remote grant is refused until the person at this machine confirms
//! (`host.policy.confirm`), which removes it.
//!
//! The record is written when the host first finds the feed ahead, before it carries out anything
//! again and before it raises the registry. Once the registry has moved, the comparison finds
//! nothing, so the finding has to be on disk first. A start reads it and waits again: when it names
//! the row the host holds, when it names another row (an earlier release rewrote the row, or the
//! owner changed it while the wait stood, and nobody confirmed the row now held), and when it
//! cannot be read. A host that finds no record waits for nothing, which is all it can do: a record
//! removed by hand, or never written because an earlier release found the restore, leaves nothing
//! to read.
//!
//! The file names the row by a digest ([`subject_of`]) of its content less what ordinary running
//! rewrites. The digest does not decide whether the host waits, which the three cases above leave
//! to the file's presence alone; it says whether the row changed since the restore was found, and
//! the file is rewritten to name the row held.
//!
//! The file also holds what the wait owes: the devices and grants that the requests its authority
//! feed holds name and that the host has not carried out or dismissed on evidence. A confirmation
//! is refused while one of them is live in the registry, so a device an owner revoked through the
//! feed after the copy is not served again by the lift, whatever became of the scan that was to
//! carry the request out: the list outlives a stop, a feed that removed the host and a start that
//! reads no feed. It names the identifiers a request states, with a digest of the feed's origin,
//! and is checked against the registry's own record of what is live when it is used. An entry whose
//! target is not live stays while the wait stands and gives its place to a live one when the list
//! holds [`MOST_OWED`] entries; a host that reads no feed reads a list of exactly that length as
//! full.
//!
//! An earlier release does not name this store, so it neither reads nor writes the file, and a host
//! that goes back to it serves the restored row to remote devices as that release always did. The
//! file stays, and the release that knows it waits again on the next start.
//!
//! The limits. The file is in the state directory, so a restore of that directory removes or
//! replaces it. A host that is stopped between its first finding and the write, and starts with
//! its feed unreachable, finds nothing to wait for.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::durable::StoredPolicy;
use crate::error::{ControllerError, Result};
use kr_protocol::ids::{DeviceId, GrantId};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs};

/// The name this store has in a release's list of the stores it reads.
pub const STORE_NAME: &str = "restored-policy";

/// The format of the file this build writes, recorded in it as `version`. A file that records
/// another is refused: an earlier one was never written, and a later one holds what this build
/// would write back without.
pub const RECORD_VERSION: u32 = 1;

/// The largest file this host will read, in bytes: room for a full list of owed entries.
const MAX_RECORD_LEN: u64 = 64 * 1024;

/// The most entries the list of what is owed holds. About 74 bytes each, so a full list is about
/// 38 KB, inside the file limit and the reader's collection limit.
pub const MOST_OWED: usize = 512;

/// What the file holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The format this file is written in.
    pub version: u32,
    /// The digest of the policy row the restore was found on ([`subject_of`]).
    pub subject: Digest256,
    /// When the host first found the restore, in UTC milliseconds.
    pub found_at_ms: TimestampMs,
    /// What the requests the authority feed holds name, until a scan dismisses them on evidence
    /// while the target is live: sorted, with no entry twice, and at most [`MOST_OWED`] long. A
    /// confirmation is refused while a target in it is live in the registry.
    pub owed: Vec<Owed>,
}

impl Record {
    /// A record of this format that owes nothing.
    #[must_use]
    pub const fn of(subject: Digest256, found_at_ms: TimestampMs) -> Self {
        Self {
            version: RECORD_VERSION,
            subject,
            found_at_ms,
            owed: Vec::new(),
        }
    }
}

/// A device or a grant that a request the feed holds names, as the request states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Target {
    /// A device, by its identifier.
    Device(DeviceId),
    /// A grant, by its identifier. A pairing grant is revoked by revoking the device that holds
    /// it, so it is live while that device is.
    Grant(GrantId),
}

/// One entry of what a restored policy's wait owes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Owed {
    /// The digest of the feed's origin that holds the request that names the target
    /// ([`origin_digest`]): a feed the person points the host at does not clear what an earlier
    /// one owed.
    pub origin: Digest256,
    /// What the request names.
    pub target: Target,
}

/// The digest that names a feed's origin in the list.
#[must_use]
pub fn origin_digest(origin: &str) -> Digest256 {
    Digest256::from_bytes(kr_cbor::sha256(origin.as_bytes()))
}

/// A change to the list: what a page of the feed names, in the order of the lowest feed sequence
/// that names it, and what a scan that settled the requests naming them clears.
#[derive(Clone, Copy, Debug)]
pub struct Change<'a> {
    /// The origin the change is for. It adds and clears only entries of this origin.
    pub origin: Digest256,
    /// Targets to add, lowest feed sequence first.
    pub add: &'a [Target],
    /// Targets of this origin to take out: each was named only by requests this scan settled. One
    /// that is not live stays.
    pub clear: &'a [Target],
}

/// The list after a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Merged {
    /// The new list, sorted.
    pub owed: Vec<Owed>,
    /// Whether the cap kept an entry out.
    pub full: bool,
}

/// The list `held` becomes under `change`.
///
/// An entry leaves it when `change` clears it and its target is live, and never because no request
/// names it now (a request the feed dropped after its retention left its entry where it was) or
/// because its target is not live now, whoever revoked it: a registry put back again brings the
/// target back, and the request that owed it may be gone by then. For the same reason a target that
/// is not live when it is added (revoked at the machine before the scan reached its page, or absent
/// from this copy of the registry) is added too. An entry whose target is not live blocks no
/// confirmation, counts toward no cap and yields its place to a live target when the list holds
/// `most` entries. The entries held stay and new ones are added in order until `most` entries are
/// held. A live target that finds no room is left out and `full` is set; one that is not live and
/// finds no room is left out and `full` stays as it was.
#[must_use]
pub fn merged(
    held: &[Owed],
    change: &Change<'_>,
    most: usize,
    live: impl Fn(&Target) -> bool,
) -> Merged {
    let mut owed: BTreeSet<Owed> = held
        .iter()
        .filter(|entry| {
            !(entry.origin == change.origin
                && change.clear.contains(&entry.target)
                && live(&entry.target))
        })
        .copied()
        .collect();
    let mut full = false;
    for target in change.add {
        let entry = Owed {
            origin: change.origin,
            target: *target,
        };
        if owed.contains(&entry) {
            continue;
        }
        if owed.len() >= most {
            // Only a live target takes the place of an entry that is not live.
            let target_live = live(target);
            let spent = owed
                .iter()
                .find(|held| target_live && !live(&held.target))
                .copied();
            let Some(spent) = spent else {
                full |= target_live;
                continue;
            };
            owed.remove(&spent);
        }
        owed.insert(entry);
    }
    Merged {
        owed: owed.into_iter().collect(),
        full,
    }
}

/// What a start finds at the file's place.
#[derive(Debug, PartialEq, Eq)]
pub enum Found {
    /// There is no file.
    Missing,
    /// The file is a record of this format.
    Record(Record),
    /// The file is there and is not a record of this format: damaged, not a map, of another
    /// version, not a regular file, or larger than a record is. The text says which.
    Unreadable(String),
}

/// Where the file is, beside the registry's database.
#[must_use]
pub fn file_beside(registry_database: &Path) -> PathBuf {
    registry_database.with_file_name("restored-policy.cbor")
}

/// The digest that names a policy row.
///
/// It covers what an owner's act or a restore changes: whether the host is exclusively
/// organisation-managed, the offline bound's maximum, and every enrolment with its links, its
/// accepted head, its enrolment revision and the devices bound to members. It leaves out what
/// ordinary running rewrites at every start or decision: the two floors, the moment the bound was
/// last synchronised, and the lease records (a lease lives at most fifteen minutes). A member
/// device's first lease, or a chain an organisation presents, still changes it: a record can go
/// stale without an owner's act, which the host answers as it answers any stale record.
#[must_use]
pub fn subject_of(policy: &StoredPolicy) -> Digest256 {
    let mut named = policy.clone();
    named.accepted_floor = kr_protocol::ids::AuthorityRevision::new(0);
    named.utc_floor_ms = TimestampMs::new(0);
    if let Some(offline) = named.offline.0.as_mut() {
        offline.last_synchronised_at_ms = Nullable::null();
    }
    named.lease_records = Vec::new();
    // A policy row encodes, as it is written down every start. If it somehow did not, the empty
    // bytes name every such row alike, which only makes a record stale less often.
    let bytes = kr_cbor::to_canonical_vec(&named).unwrap_or_default();
    Digest256::from_bytes(kr_cbor::sha256(&bytes))
}

/// Reads the file.
#[must_use]
pub fn read(file: &Path) -> Found {
    let bytes = match kr_ipc::paths::read_owner_only_file(file, MAX_RECORD_LEN) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Found::Missing,
        Err(error) => return Found::Unreadable(error.to_string()),
    };
    let record: Record = match kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT) {
        Ok(record) => record,
        Err(error) => return Found::Unreadable(error.to_string()),
    };
    if record.version != RECORD_VERSION {
        return Found::Unreadable(format!(
            "it is of format {}, and this build reads format {RECORD_VERSION}",
            record.version
        ));
    }
    if record.owed.len() > MOST_OWED || !record.owed.windows(2).all(|pair| pair[0] < pair[1]) {
        return Found::Unreadable(
            "the list of what is owed is longer than it can be, or not sorted, or names an entry twice"
                .to_owned(),
        );
    }
    Found::Record(record)
}

/// Writes the file in one write, owner only.
///
/// # Errors
///
/// Returns an error when the record cannot be written. What was there is then as it was, except
/// when the file was replaced and the directory then could not be flushed: the new file is there,
/// and the error says the write is not known to be durable.
pub fn write(file: &Path, record: &Record) -> Result<()> {
    publish(file, &encode(record)?)
}

fn encode(record: &Record) -> Result<Vec<u8>> {
    kr_cbor::to_canonical_vec(record)
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
}

fn publish(file: &Path, bytes: &[u8]) -> Result<()> {
    kr_ipc::paths::write_owner_only_file(file, bytes)
        .map_err(|error| ControllerError::registry(error.to_string()))
}

/// Flushes the directory the file is in, after a name in it was given or taken away.
fn flush_beside(file: &Path) -> std::io::Result<()> {
    kr_flush::flush_directory(
        file.parent().unwrap_or_else(|| Path::new(".")),
        kr_flush::NameKind::File,
    )
}

/// Removes the file, flushing the directory so that a stop that follows does not bring it back.
/// A file that is not there is removed already, and the directory is flushed all the same: an
/// earlier call may have removed it and failed to flush, and this call is its retry.
///
/// # Errors
///
/// Returns an error when the file cannot be removed: while another program holds it, or when
/// something other than a file is there. When the file is gone and the directory then could not be
/// flushed, the error says the removal is not known to be durable.
pub fn remove(file: &Path) -> Result<()> {
    unlink(file)?;
    flush_after_removal(file)
}

/// Takes the file away. A file that is not there is gone already.
fn unlink(file: &Path) -> Result<()> {
    match kr_flush::retry_while_held(|| std::fs::remove_file(file)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(ControllerError::registry(format!(
            "could not remove {}: {error}",
            file.display()
        ))),
    }
}

/// Flushes the directory after the file was taken away.
fn flush_after_removal(file: &Path) -> Result<()> {
    flush_beside(file).map_err(|error| {
        ControllerError::registry(format!(
            "removed {}, but the directory could not be flushed, so the removal is not known to \
             be durable: {error}",
            file.display()
        ))
    })
}

/// The record this daemon holds, whether it is proven durable, and where it is.
///
/// A record counts as durable only when a write of it returned success in this run, or a start read
/// it from disk and then flushed the directory it is in. A write that failed after the rename
/// leaves a file with the right bytes that a crash can still lose, so a matching file proves
/// nothing: the next call writes again. What the daemon holds of the record (`known`, the list
/// included) is kept apart from that: a flush that failed at a start leaves the record unproven,
/// and the next write still carries the list it read, not an empty one.
#[derive(Debug)]
pub struct Kept {
    file: PathBuf,
    known: Option<Record>,
    durable: bool,
    most: usize,
    /// Whether the start found a file here that it could not read. Nothing is written over it: the
    /// list in it is lost, and the confirmation removes it.
    unreadable: bool,
}

impl Kept {
    /// A daemon that knows of no record.
    #[must_use]
    pub const fn new(file: PathBuf) -> Self {
        Self {
            file,
            known: None,
            durable: false,
            most: MOST_OWED,
            unreadable: false,
        }
    }

    /// Where the file is.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// The most entries the list holds.
    #[must_use]
    pub const fn most(&self) -> usize {
        self.most
    }

    /// Lowers the most the list holds, for a suite that fills it.
    #[cfg(any(test, feature = "testing"))]
    pub const fn limit_the_list_to(&mut self, most: usize) {
        self.most = most;
    }

    /// Whether the file here could not be read at the start and is still there: the list in it is
    /// lost.
    #[must_use]
    pub const fn is_unreadable(&self) -> bool {
        self.unreadable
    }

    /// Notes that the start found a file here that it could not read, so that no write goes over it.
    pub fn found_unreadable(&mut self) {
        // Something that is not a file here is an obstacle and not a record: writing over it fails
        // and stops the pass, which is what keeps a host that cannot write its record from going on.
        self.unreadable = self.file.is_file();
    }

    /// Takes a record a start read from disk as durable once the directory it is in is flushed.
    ///
    /// An earlier run can have stopped after the rename that gave the file its name, when the
    /// flush that makes the name survive a crash failed. The file reads the same, so the flush is
    /// made here. A flush that fails leaves the record unproven, and the next call to
    /// [`Self::ensure`] writes it again; the record, its list included, is held all the same.
    pub fn adopt(&mut self, record: Record) {
        self.durable = flush_beside(&self.file).is_ok();
        self.known = Some(record);
    }

    /// The record known to be durable.
    #[must_use]
    pub const fn record(&self) -> Option<&Record> {
        if self.durable {
            self.known.as_ref()
        } else {
            None
        }
    }

    /// The record the daemon holds, durable or not: what a start read, or what it last wrote. None
    /// when the file could not be read, or none was written.
    #[must_use]
    pub const fn known(&self) -> Option<&Record> {
        self.known.as_ref()
    }

    /// Makes sure a record naming `subject` is durable, and writes one if it is not. The moment
    /// the restore was first found stays as it was while the daemon holds a record as durable; a
    /// record it cannot prove durable is written again with the moment of that write. The list the
    /// daemon holds is written with it.
    ///
    /// # Errors
    ///
    /// Returns the write's error; the record is then not known to be durable.
    pub fn ensure(&mut self, subject: Digest256, now_ms: u64) -> Result<()> {
        self.ensure_by(subject, now_ms, publish)
    }

    fn ensure_by(
        &mut self,
        subject: Digest256,
        now_ms: u64,
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<()> {
        if self.unreadable {
            return Ok(());
        }
        if self.durable
            && self
                .known
                .as_ref()
                .is_some_and(|known| known.subject == subject)
        {
            return Ok(());
        }
        let owed = self
            .known
            .as_ref()
            .map(|known| known.owed.clone())
            .unwrap_or_default();
        let found_at_ms = self
            .known
            .as_ref()
            .filter(|_| self.durable)
            .map_or_else(|| TimestampMs::new(now_ms), |known| known.found_at_ms);
        let record = Record {
            version: RECORD_VERSION,
            subject,
            found_at_ms,
            owed,
        };
        self.durable = false;
        publish(&self.file, &encode(&record)?)?;
        self.known = Some(record);
        self.durable = true;
        Ok(())
    }

    /// Changes the list the record holds, and writes the record when the list is not the one that
    /// stands or the record is not proven durable. Says whether the cap kept an entry out. The
    /// record's subject and the moment it was found stay as they are.
    ///
    /// Does nothing when the daemon holds no record to change: a file that could not be read is
    /// not written over.
    ///
    /// # Errors
    ///
    /// Returns the write's error. The list the daemon holds is then as it was, and the record is
    /// not known to be durable.
    pub fn keep(&mut self, change: &Change<'_>, live: impl Fn(&Target) -> bool) -> Result<bool> {
        self.keep_by(change, live, publish)
    }

    fn keep_by(
        &mut self,
        change: &Change<'_>,
        live: impl Fn(&Target) -> bool,
        publish: impl FnOnce(&Path, &[u8]) -> Result<()>,
    ) -> Result<bool> {
        let Some(known) = self.known.as_ref() else {
            return Ok(false);
        };
        let merged = merged(&known.owed, change, self.most, live);
        if self.durable && merged.owed == known.owed {
            return Ok(merged.full);
        }
        let record = Record {
            owed: merged.owed,
            ..known.clone()
        };
        self.durable = false;
        publish(&self.file, &encode(&record)?)?;
        self.known = Some(record);
        self.durable = true;
        Ok(merged.full)
    }

    /// Removes the file, and with it what the daemon knows of it.
    ///
    /// # Errors
    ///
    /// Returns the removal's error. The file and what the daemon knows are then as they were,
    /// except when the file is gone and the directory could not be flushed: the daemon no longer
    /// holds the record as on disk, the error says the removal is not known to be durable, and the
    /// next call, which finds the file gone, flushes the directory again before it succeeds.
    pub fn lift(&mut self) -> Result<()> {
        unlink(&self.file)?;
        self.known = None;
        self.durable = false;
        self.unreadable = false;
        flush_after_removal(&self.file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grants::durable::{StoredBinding, StoredEnrolment, StoredLeaseRecord};
    use kr_protocol::account::{PolicyAuthorityLink, PolicyAuthorityLinkPayload};
    use kr_protocol::ids::{
        AccountId, AuthorityRevision, ControllerGeneration, DeviceId, OrganisationId,
        PolicyKeyRevision,
    };
    use kr_protocol::scalars::{AuthorisationKey, DurationMs, Signature64, Uuid};
    use kr_protocol::sharing::OfflineValidityPolicy;

    fn link() -> PolicyAuthorityLink {
        PolicyAuthorityLink {
            payload: PolicyAuthorityLinkPayload {
                organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
                key_revision: PolicyKeyRevision::new(1),
                previous_key_revision: Nullable::null(),
                public_key: AuthorisationKey::from_bytes([3; 32]),
                not_before_ms: TimestampMs::new(1_000),
            },
            signature: Signature64::from_bytes([9; 64]),
        }
    }

    fn enrolment() -> StoredEnrolment {
        StoredEnrolment {
            organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
            root: link(),
            links: vec![link()],
            accepted_head: PolicyKeyRevision::new(1),
            enrolment_revision: AuthorityRevision::new(4),
            members: Vec::new(),
        }
    }

    fn member() -> StoredBinding {
        StoredBinding {
            device_id: DeviceId::new(Uuid::from_bytes([0x31; 16])),
            account_id: AccountId::new("8f14e45f-ea1e-4b9e-9f3a-0a3a9b0d2f61").expect("an account"),
            device_key: AuthorisationKey::from_bytes([7; 32]),
            bound_at_ms: TimestampMs::new(1_700),
            lease_digest: Digest256::from_bytes([6; 32]),
        }
    }

    fn lease_record() -> StoredLeaseRecord {
        StoredLeaseRecord {
            organisation_id: OrganisationId::new(Uuid::from_bytes([0x21; 16])),
            account_id: AccountId::new("8f14e45f-ea1e-4b9e-9f3a-0a3a9b0d2f61").expect("an account"),
            device_key: AuthorisationKey::from_bytes([7; 32]),
            issued_at_ms: TimestampMs::new(1_900),
            expires_at_ms: TimestampMs::new(2_800),
            digest: Digest256::from_bytes([5; 32]),
            installed_in: ControllerGeneration::new(1),
        }
    }

    /// A row with an enrolment, an exclusive flag and an offline bound.
    fn row() -> StoredPolicy {
        StoredPolicy {
            accepted_floor: AuthorityRevision::new(7),
            utc_floor_ms: TimestampMs::new(4_000),
            exclusively_managed: true,
            offline: Nullable::some(OfflineValidityPolicy {
                maximum_offline_ms: DurationMs::new(86_400_000),
                last_synchronised_at_ms: Nullable::some(TimestampMs::new(3_000)),
            }),
            enrolments: vec![enrolment()],
            lease_records: Vec::new(),
        }
    }

    fn hex(digest: &Digest256) -> String {
        digest
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn tree() -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("a directory");
        let file = file_beside(&directory.path().join("registry.sqlite"));
        (directory, file)
    }

    /// The names of two rows, pinned: a change to what the digest reads or clears fails here, and
    /// the stored-formats lock does not see it, since it pins the types and not this function.
    #[test]
    fn the_digest_that_names_a_row_is_pinned() {
        assert_eq!(
            hex(&subject_of(&row())),
            "243ef422fc5761e9667f7da078ef53702f747309eff67cceb8067adb3daec6df",
            "a row with an enrolment, an exclusive flag and a bound"
        );
        let mut bare = row();
        bare.exclusively_managed = false;
        bare.offline = Nullable::null();
        bare.enrolments = Vec::new();
        assert_eq!(
            hex(&subject_of(&bare)),
            "7f5a050b0bf205393d81055512dfb34a0265df311b1e2874a9d63e41d499157d",
            "a row with none of them"
        );
    }

    /// What ordinary running rewrites does not change the name.
    #[test]
    fn what_ordinary_running_rewrites_does_not_change_a_rows_name() {
        let before = subject_of(&row());
        let mut floors = row();
        floors.accepted_floor = AuthorityRevision::new(900);
        floors.utc_floor_ms = TimestampMs::new(9_000_000);
        assert_eq!(
            subject_of(&floors),
            before,
            "the floors rise at every start"
        );
        let mut synchronised = row();
        if let Some(offline) = synchronised.offline.0.as_mut() {
            offline.last_synchronised_at_ms = Nullable::some(TimestampMs::new(8_000_000));
        }
        assert_eq!(subject_of(&synchronised), before, "a synchronisation");
        let mut leased = row();
        leased.lease_records = vec![lease_record()];
        assert_eq!(subject_of(&leased), before, "a lease record");
    }

    /// What an owner's act or a restore changes does.
    #[test]
    fn what_an_owner_or_a_restore_changes_changes_a_rows_name() {
        let before = subject_of(&row());
        let differs = |name: &str, changed: StoredPolicy| {
            assert_ne!(subject_of(&changed), before, "{name}");
        };
        let mut exclusive = row();
        exclusive.exclusively_managed = false;
        differs("the exclusive flag", exclusive);
        let mut bound = row();
        if let Some(offline) = bound.offline.0.as_mut() {
            offline.maximum_offline_ms = DurationMs::new(60_000);
        }
        differs("the bound's maximum", bound);
        let mut unbounded = row();
        unbounded.offline = Nullable::null();
        differs("no bound", unbounded);
        let mut withdrawn = row();
        withdrawn.enrolments = Vec::new();
        differs("an enrolment withdrawn", withdrawn);
        let mut bound_member = row();
        bound_member.enrolments[0].members = vec![member()];
        differs("a member bound", bound_member);
        let mut rotated = row();
        rotated.enrolments[0].links.push(link());
        rotated.enrolments[0].accepted_head = PolicyKeyRevision::new(2);
        differs("a chain presented", rotated);
        let mut enrolled_again = row();
        enrolled_again.enrolments[0].enrolment_revision = AuthorityRevision::new(5);
        differs("an enrolment made again", enrolled_again);
    }

    #[test]
    fn a_record_is_written_read_and_removed() {
        let (_directory, file) = tree();
        assert_eq!(read(&file), Found::Missing);
        let record = Record::of(subject_of(&row()), TimestampMs::new(55));
        write(&file, &record).expect("written");
        assert_eq!(read(&file), Found::Record(record.clone()));
        write(
            &file,
            &Record::of(Digest256::from_bytes([1; 32]), record.found_at_ms),
        )
        .expect("replaced");
        remove(&file).expect("removed");
        assert_eq!(read(&file), Found::Missing);
        remove(&file).expect("a file that is not there is removed already");
    }

    #[test]
    fn a_file_that_is_not_a_record_of_this_format_is_unreadable() {
        let (_directory, file) = tree();
        let unreadable = |what: &str| match read(&file) {
            Found::Unreadable(_) => {}
            other => panic!("{what}: {other:?}"),
        };
        std::fs::write(&file, b"junk").expect("junk");
        unreadable("not a map");
        let other = Record {
            version: RECORD_VERSION + 1,
            subject: Digest256::from_bytes([2; 32]),
            found_at_ms: TimestampMs::new(1),
            owed: Vec::new(),
        };
        std::fs::write(&file, kr_cbor::to_canonical_vec(&other).expect("encodes"))
            .expect("written");
        unreadable("another version");
        std::fs::write(
            &file,
            vec![0u8; usize::try_from(MAX_RECORD_LEN).unwrap() + 1],
        )
        .expect("written");
        unreadable("over the limit");
        std::fs::remove_file(&file).expect("removed");
        std::fs::create_dir(&file).expect("a directory");
        unreadable("not a regular file");
        assert!(
            remove(&file).is_err(),
            "a directory is not removed as a file"
        );
        assert!(
            write(
                &file,
                &Record::of(Digest256::from_bytes([3; 32]), TimestampMs::new(1))
            )
            .is_err(),
            "nor written over"
        );
    }

    /// A write that fails after the rename leaves a file with the right bytes that a crash can
    /// lose, so the daemon writes again, and the moment kept is that of the write that held.
    #[test]
    fn a_write_that_failed_after_the_rename_is_written_again() {
        let (_directory, file) = tree();
        let mut kept = Kept::new(file.clone());
        let subject = subject_of(&row());
        let failed = kept.ensure_by(subject, 100, |file, bytes| {
            publish(file, bytes).expect("the file is in place");
            Err(ControllerError::registry(
                "the directory could not be flushed",
            ))
        });
        assert!(failed.is_err());
        assert!(kept.record().is_none(), "not known to be durable");
        assert!(
            matches!(read(&file), Found::Record(_)),
            "the bytes are there"
        );
        kept.ensure(subject, 200).expect("written again");
        assert_eq!(
            kept.record(),
            Some(&Record::of(subject, TimestampMs::new(200))),
            "durable now"
        );
        kept.ensure_by(subject, 300, |_, _| {
            panic!("a durable record is not written again")
        })
        .expect("nothing to do");
        let renamed = Digest256::from_bytes([8; 32]);
        kept.ensure(renamed, 400)
            .expect("a changed row is named again");
        assert_eq!(
            kept.record(),
            Some(&Record::of(renamed, TimestampMs::new(200))),
            "the moment the restore was first found stays"
        );
        kept.lift().expect("lifted");
        assert!(kept.record().is_none());
        assert_eq!(read(&file), Found::Missing);
    }

    /// A flush that failed leaves the renamed file readable. A daemon that starts and reads it does
    /// not count it as durable, or a pass would carry out and raise the registry on a record that
    /// a crash can still lose.
    #[test]
    fn a_record_whose_directory_could_not_be_flushed_is_written_again_after_a_start() {
        let (_directory, file) = tree();
        let subject = subject_of(&row());
        let directory = file.parent().expect("a directory").to_path_buf();
        let refused = kr_flush::testing::refuse_flushes_of(directory);
        let mut earlier = Kept::new(file.clone());
        assert!(
            earlier.ensure(subject, 100).is_err(),
            "the write is not known to be durable"
        );
        let Found::Record(first) = read(&file) else {
            panic!("the bytes are there");
        };

        let mut started = Kept::new(file.clone());
        started.adopt(first);
        assert!(
            started.record().is_none(),
            "a record read while the directory cannot be flushed is not proven"
        );
        let mut written = 0;
        let again = started.ensure_by(subject, 200, |file, bytes| {
            written += 1;
            publish(file, bytes)
        });
        assert!(again.is_err(), "and the write still cannot be proven");
        assert_eq!(written, 1, "the record is written again");

        drop(refused);
        let Found::Record(on_disk) = read(&file) else {
            panic!("the bytes are there");
        };
        let mut flushed = Kept::new(file);
        flushed.adopt(on_disk.clone());
        assert_eq!(
            flushed.record(),
            Some(&on_disk),
            "durable once the flush holds"
        );
        flushed
            .ensure_by(subject, 300, |_, _| {
                panic!("a durable record is not written again")
            })
            .expect("nothing to do");
    }

    /// A removal whose directory flush failed has taken the file away: the daemon no longer holds
    /// the record as on disk, and the next finding writes it again.
    #[test]
    fn a_removal_whose_directory_could_not_be_flushed_is_not_held_as_on_disk() {
        let (_directory, file) = tree();
        let subject = subject_of(&row());
        let mut kept = Kept::new(file.clone());
        kept.ensure(subject, 100).expect("written");
        {
            let directory = file.parent().expect("a directory").to_path_buf();
            let _refused = kr_flush::testing::refuse_flushes_of(directory);
            assert!(
                kept.lift().is_err(),
                "the removal is not known to be durable"
            );
        }
        assert_eq!(read(&file), Found::Missing, "the file is gone");
        assert!(
            kept.record().is_none(),
            "and the daemon does not hold it as on disk"
        );
        kept.ensure(subject, 200)
            .expect("a finding writes it again");
        assert!(matches!(read(&file), Found::Record(_)));
    }

    /// A confirmation whose removal could not be made durable is asked again: the file is gone
    /// then, and the retry still flushes the directory before it succeeds, so that a crash cannot
    /// bring the record back after the wait has been lifted.
    #[test]
    fn a_retry_after_a_removal_whose_directory_could_not_be_flushed_flushes_before_it_succeeds() {
        let (_directory, file) = tree();
        let subject = subject_of(&row());
        let directory = file.parent().expect("a directory").to_path_buf();
        let mut kept = Kept::new(file.clone());
        kept.ensure(subject, 100).expect("written");
        let refused = kr_flush::testing::refuse_flushes_of(directory);
        assert!(
            kept.lift().is_err(),
            "the first removal is not known to be durable"
        );
        assert_eq!(read(&file), Found::Missing, "the file is gone");
        assert!(
            kept.lift().is_err(),
            "the retry finds the file gone and still cannot flush the directory"
        );
        drop(refused);
        kept.lift().expect("the retry that flushes succeeds");
        assert!(
            remove(&file).is_ok(),
            "and so does a removal of a file that is not there"
        );
    }

    fn device(byte: u8) -> Target {
        Target::Device(DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
            [byte; 16],
        )))
    }

    fn grant(byte: u8) -> Target {
        Target::Grant(GrantId::new(kr_protocol::scalars::Uuid::from_bytes(
            [byte; 16],
        )))
    }

    fn entry(origin: u8, target: Target) -> Owed {
        Owed {
            origin: Digest256::from_bytes([origin; 32]),
            target,
        }
    }

    fn with_a_list(owed: Vec<Owed>) -> Record {
        Record {
            owed,
            ..Record::of(subject_of(&row()), TimestampMs::new(55))
        }
    }

    #[test]
    fn a_record_with_a_list_is_written_and_read_back() {
        let (_directory, file) = tree();
        let record = with_a_list(vec![
            entry(1, device(2)),
            entry(1, grant(1)),
            entry(2, device(1)),
        ]);
        let mut sorted = record.owed.clone();
        sorted.sort();
        let record = Record {
            owed: sorted,
            ..record
        };
        write(&file, &record).expect("written");
        assert_eq!(read(&file), Found::Record(record));
    }

    #[test]
    fn a_list_that_is_not_sorted_or_repeats_an_entry_or_is_too_long_is_unreadable() {
        let (_directory, file) = tree();
        let unreadable = |what: &str, owed: Vec<Owed>| {
            std::fs::write(
                &file,
                kr_cbor::to_canonical_vec(&with_a_list(owed)).expect("encodes"),
            )
            .expect("written");
            match read(&file) {
                Found::Unreadable(_) => {}
                other => panic!("{what}: {other:?}"),
            }
        };
        unreadable("not sorted", vec![entry(1, device(3)), entry(1, device(2))]);
        unreadable(
            "an entry twice",
            vec![entry(1, device(2)), entry(1, device(2))],
        );
        // A list over the cap, sorted and without repeats: made long with distinct origins.
        let mut distinct: Vec<Owed> = (0..=MOST_OWED)
            .map(|index| Owed {
                origin: Digest256::from_bytes({
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    bytes
                }),
                target: device(1),
            })
            .collect();
        distinct.sort();
        unreadable("longer than the cap", distinct);
    }

    #[test]
    fn a_list_at_the_cap_is_written_and_read_and_fits_the_file_limit() {
        let (_directory, file) = tree();
        let mut full: Vec<Owed> = (0..MOST_OWED)
            .map(|index| Owed {
                origin: Digest256::from_bytes({
                    let mut bytes = [0u8; 32];
                    bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    bytes
                }),
                target: grant(7),
            })
            .collect();
        full.sort();
        let record = with_a_list(full);
        write(&file, &record).expect("written");
        assert_eq!(read(&file), Found::Record(record));
        assert!(
            std::fs::metadata(&file).expect("a file").len() < MAX_RECORD_LEN,
            "a full list is inside the file limit"
        );
    }

    #[test]
    fn a_change_adds_in_order_clears_only_its_origin_and_keeps_what_is_not_named_now() {
        let alive = |_: &Target| true;
        let held = vec![
            entry(1, device(1)),
            entry(1, device(2)),
            entry(2, device(2)),
        ];
        let origin = Digest256::from_bytes([1; 32]);
        let merged = merged(
            &held,
            &Change {
                origin,
                add: &[device(9), grant(3), device(1)],
                clear: &[device(2)],
            },
            MOST_OWED,
            alive,
        );
        assert_eq!(
            merged.owed,
            vec![
                entry(1, device(1)),
                entry(1, device(9)),
                entry(1, grant(3)),
                entry(2, device(2)),
            ],
            "an entry of another origin stays, one of this origin that was cleared goes, and what no \
             request names now stays too"
        );
        assert!(!merged.full);
    }

    #[test]
    fn a_clear_takes_out_an_entry_only_while_its_target_is_live() {
        let origin = Digest256::from_bytes([1; 32]);
        let held = vec![entry(1, device(1)), entry(1, device(2))];
        let merged = merged(
            &held,
            &Change {
                origin,
                add: &[],
                clear: &[device(1), device(2)],
            },
            MOST_OWED,
            |target| *target != device(2),
        );
        assert_eq!(
            merged.owed,
            vec![entry(1, device(2))],
            "device 2 was revoked, so a registry put back again can bring it back when the request \
             that owed it is gone"
        );
    }

    #[test]
    fn an_entry_that_is_not_live_stays_and_a_target_that_is_not_live_is_added() {
        let held = vec![entry(1, device(1)), entry(2, device(2))];
        let origin = Digest256::from_bytes([1; 32]);
        let merged = merged(
            &held,
            &Change {
                origin,
                add: &[device(3), device(4)],
                clear: &[],
            },
            MOST_OWED,
            |target| *target != device(2) && *target != device(3),
        );
        assert_eq!(
            merged.owed,
            vec![
                entry(1, device(1)),
                entry(1, device(3)),
                entry(1, device(4)),
                entry(2, device(2))
            ],
            "a registry put back again can bring device 2 and device 3 back, with the request that \
             owed them gone"
        );
        assert!(!merged.full);
    }

    #[test]
    fn a_target_that_is_not_live_finds_no_room_at_the_cap_and_does_not_say_the_list_is_full() {
        let origin = Digest256::from_bytes([1; 32]);
        let held = vec![entry(1, device(1)), entry(1, device(2))];
        let change = Change {
            origin,
            add: &[device(3)],
            clear: &[],
        };
        // Device 2 is not live, and device 3 is not live either: it takes nobody's place.
        let left_out = merged(&held, &change, 2, |target| *target == device(1));
        assert_eq!(left_out.owed, held);
        assert!(!left_out.full);
        // Device 3 is live: it takes the place of device 2, which is not.
        let takes_it = merged(&held, &change, 2, |target| *target != device(2));
        assert_eq!(
            takes_it.owed,
            vec![entry(1, device(1)), entry(1, device(3))]
        );
        assert!(!takes_it.full);
        // Both entries are live and device 3 is not: it is left out, and the list is not full for it.
        let alone = merged(&held, &change, 2, |target| *target != device(3));
        assert_eq!(alone.owed, held);
        assert!(!alone.full);
    }

    #[test]
    fn an_entry_that_is_not_live_yields_its_place_at_the_cap_and_a_live_one_does_not() {
        let origin = Digest256::from_bytes([1; 32]);
        let held = vec![
            entry(1, device(1)),
            entry(1, device(2)),
            entry(1, device(3)),
        ];
        let change = Change {
            origin,
            add: &[device(4)],
            clear: &[],
        };
        let spent = merged(&held, &change, 3, |target| *target != device(2));
        assert_eq!(
            spent.owed,
            vec![
                entry(1, device(1)),
                entry(1, device(3)),
                entry(1, device(4))
            ]
        );
        assert!(!spent.full);
        let kept = merged(&held, &change, 3, |_| true);
        assert_eq!(kept.owed, held);
        assert!(kept.full);
    }

    #[test]
    fn the_cap_keeps_what_is_held_adds_in_order_and_says_it_is_full() {
        let origin = Digest256::from_bytes([1; 32]);
        let held = vec![entry(1, device(1))];
        let merged = merged(
            &held,
            &Change {
                origin,
                add: &[device(5), device(4), device(3)],
                clear: &[],
            },
            3,
            |_| true,
        );
        assert_eq!(
            merged.owed,
            vec![
                entry(1, device(1)),
                entry(1, device(4)),
                entry(1, device(5))
            ],
            "the held entry and the first two added, in the order they were given"
        );
        assert!(merged.full);
    }

    /// A start that read the record and could not flush the directory holds it unproven, and the
    /// next write carries the list it read and not an empty one.
    #[test]
    fn a_flush_that_failed_at_a_start_does_not_cost_the_list() {
        let (_directory, file) = tree();
        let subject = subject_of(&row());
        let record = Record {
            owed: vec![entry(1, device(1))],
            ..Record::of(subject, TimestampMs::new(55))
        };
        write(&file, &record).expect("written");
        let directory = file.parent().expect("a directory").to_path_buf();
        let refused = kr_flush::testing::refuse_flushes_of(directory);
        let mut started = Kept::new(file.clone());
        started.adopt(record.clone());
        assert!(started.record().is_none(), "not proven durable");
        assert_eq!(started.known(), Some(&record), "but held, list and all");
        drop(refused);
        started.ensure(subject, 200).expect("written again");
        assert_eq!(
            read(&file),
            Found::Record(Record {
                found_at_ms: TimestampMs::new(200),
                ..record
            }),
            "the list read is the list written, with the moment of the write that held"
        );
    }

    /// A write of the list that fails after the rename leaves the list the daemon holds as it was
    /// and the record not known to be durable; the next write that holds succeeds.
    #[test]
    fn a_list_write_that_failed_after_the_rename_leaves_the_list_as_it_was() {
        let (_directory, file) = tree();
        let subject = subject_of(&row());
        let mut kept = Kept::new(file.clone());
        kept.ensure(subject, 100).expect("written");
        let origin = Digest256::from_bytes([1; 32]);
        let change = Change {
            origin,
            add: &[device(1)],
            clear: &[],
        };
        let failed = kept.keep_by(
            &change,
            |_| true,
            |file, bytes| {
                publish(file, bytes).expect("the file is in place");
                Err(ControllerError::registry(
                    "the directory could not be flushed",
                ))
            },
        );
        assert!(failed.is_err());
        assert!(kept.record().is_none(), "not known to be durable");
        assert_eq!(
            kept.known().map(|known| known.owed.clone()),
            Some(Vec::new()),
            "the list the daemon holds is as it was"
        );
        kept.keep(&change, |_| true).expect("written again");
        assert_eq!(
            kept.record().map(|known| known.owed.clone()),
            Some(vec![entry(1, device(1))])
        );
        kept.keep_by(
            &change,
            |_| true,
            |_, _| panic!("a list that stands on a durable record is not written again"),
        )
        .expect("nothing to do");
    }

    /// A file that could not be read is not written over: a daemon that holds no record changes
    /// nothing.
    #[test]
    fn a_record_that_could_not_be_read_is_not_written_over() {
        let (_directory, file) = tree();
        std::fs::write(&file, b"junk").expect("junk");
        let mut kept = Kept::new(file.clone());
        assert!(matches!(read(&file), Found::Unreadable(_)));
        let origin = Digest256::from_bytes([1; 32]);
        kept.keep_by(
            &Change {
                origin,
                add: &[device(1)],
                clear: &[],
            },
            |_| true,
            |_, _| panic!("nothing is written over a file that could not be read"),
        )
        .expect("nothing to do");
        assert_eq!(std::fs::read(&file).expect("the file"), b"junk");

        // The record of a finding is not written over it either, and the confirmation that removes
        // the file leaves the daemon free to write again.
        kept.found_unreadable();
        assert!(kept.is_unreadable());
        kept.ensure_by(subject_of(&row()), 9, |_, _| {
            panic!("nothing is written over a file that could not be read")
        })
        .expect("nothing to do");
        assert_eq!(std::fs::read(&file).expect("the file"), b"junk");
        kept.lift().expect("the file is removed");
        assert!(!kept.is_unreadable());
        kept.ensure(subject_of(&row()), 9)
            .expect("a record is written");
        assert!(matches!(read(&file), Found::Record(_)));
    }
}
