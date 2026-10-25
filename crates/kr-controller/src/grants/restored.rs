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
//! An earlier release does not name this store, so it neither reads nor writes the file, and a host
//! that goes back to it serves the restored row to remote devices as that release always did. The
//! file stays, and the release that knows it waits again on the next start.
//!
//! The limits. The file is in the state directory, so a restore of that directory removes or
//! replaces it. A host that is stopped between its first finding and the write, and starts with
//! its feed unreachable, finds nothing to wait for.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::durable::StoredPolicy;
use crate::error::{ControllerError, Result};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs};

/// The name this store has in a release's list of the stores it reads.
pub const STORE_NAME: &str = "restored-policy";

/// The format of the file this build writes, recorded in it as `version`. A file that records
/// another is refused: an earlier one was never written, and a later one holds what this build
/// would write back without.
pub const RECORD_VERSION: u32 = 1;

/// The largest file this host will read, in bytes.
const MAX_RECORD_LEN: u64 = 4 * 1024;

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
}

impl Record {
    /// A record of this format.
    #[must_use]
    pub const fn of(subject: Digest256, found_at_ms: TimestampMs) -> Self {
        Self {
            version: RECORD_VERSION,
            subject,
            found_at_ms,
        }
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

/// Removes the file, flushing the directory so that a stop that follows does not bring it back.
/// A file that is not there is removed already.
///
/// # Errors
///
/// Returns an error when the file cannot be removed: while another program holds it, or when
/// something other than a file is there.
pub fn remove(file: &Path) -> Result<()> {
    let refused = |error: std::io::Error| {
        ControllerError::registry(format!("could not remove {}: {error}", file.display()))
    };
    match kr_flush::retry_while_held(|| std::fs::remove_file(file)) {
        Ok(()) => kr_flush::flush_directory(
            file.parent().unwrap_or_else(|| Path::new(".")),
            kr_flush::NameKind::File,
        )
        .map_err(refused),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(refused(error)),
    }
}

/// The record this daemon knows to be on disk, and where.
///
/// A record counts as durable only when a write of it returned success in this run, or a start read
/// it from disk. A write that failed after the rename leaves a file with the right bytes that a
/// crash can still lose, so a matching file proves nothing: the next call writes again.
#[derive(Debug)]
pub struct Kept {
    file: PathBuf,
    durable: Option<Record>,
}

impl Kept {
    /// A daemon that knows of no record.
    #[must_use]
    pub const fn new(file: PathBuf) -> Self {
        Self {
            file,
            durable: None,
        }
    }

    /// Where the file is.
    #[must_use]
    pub fn file(&self) -> &Path {
        &self.file
    }

    /// Takes a record a start read from disk as durable.
    pub fn adopt(&mut self, record: Record) {
        self.durable = Some(record);
    }

    /// The record known to be durable.
    #[must_use]
    pub const fn record(&self) -> Option<&Record> {
        self.durable.as_ref()
    }

    /// Makes sure a record naming `subject` is durable, and writes one if it is not. The moment
    /// the restore was first found stays as it was.
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
        if self
            .durable
            .as_ref()
            .is_some_and(|durable| durable.subject == subject)
        {
            return Ok(());
        }
        let found_at_ms = self
            .durable
            .as_ref()
            .map_or_else(|| TimestampMs::new(now_ms), |durable| durable.found_at_ms);
        let record = Record::of(subject, found_at_ms);
        publish(&self.file, &encode(&record)?)?;
        self.durable = Some(record);
        Ok(())
    }

    /// Removes the file, and with it what the daemon knows of it.
    ///
    /// # Errors
    ///
    /// Returns the removal's error; the file and what the daemon knows are then as they were.
    pub fn lift(&mut self) -> Result<()> {
        remove(&self.file)?;
        self.durable = None;
        Ok(())
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
    /// lose, so the daemon writes again, with the moment the restore was first found.
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
}
