//! The last policy this host wrote, kept beside the registry in a store of its own.
//!
//! The policy is written to the registry's `host_authority` table, with a sequence beside it that
//! every write raises ([`super::store::GrantDirectory::store_policy`]). After each write the host
//! keeps the same policy and the same sequence in `policy-mirror.cbor`. At a start the host reads
//! both, and a registry whose sequence is below the mirror's was put back to an earlier state:
//! the mirror is the policy then, and the older row, with the enrolments an owner left, the
//! exclusive management that was ended, the offline bound that was changed and the leases it
//! recorded since, revives nothing.
//!
//! The mirror is written after the registry's row has committed, never before. A stop between the
//! two leaves the mirror one write behind, and the row is then the newer of the two, which is the
//! row the host keeps. A write of the mirror that fails is reported and leaves the same state, so
//! the protection waits for the next write rather than stopping the host.
//!
//! An earlier release neither reads the file nor raises the sequence, so a host that goes back to
//! it and forward again meets a row that is newer than its sequence says: the row is kept, as it
//! is whenever the sequences are equal.
//!
//! The limits. A registry and a mirror put back together are one earlier state, and nothing in
//! this host can tell it from the host's own. A mirror that cannot be read protects nothing: a
//! registry put back to an earlier state while the mirror is damaged keeps the older row, and the
//! next write replaces the mirror with a copy of it. A registry put back to an earlier state that
//! an earlier release then writes keeps the sequence it had, so the mirror still stands above it
//! when this build starts again, and the mirror's policy replaces what that release wrote.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::durable::StoredPolicy;
use crate::error::{ControllerError, Result};

/// The format of the file this build writes, recorded in it as `version`. A file that records
/// another is refused: an earlier one was never written, and a later one holds what this build
/// would write back without.
pub const RECORD_VERSION: u32 = 1;

/// The largest file this host will read, in bytes.
const MAX_RECORD_LEN: u64 = 16 * 1024 * 1024;

/// What the file holds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Record {
    /// The format this file is written in.
    version: u32,
    /// The sequence the registry's row carried when it was written.
    sequence: u64,
    /// The policy that row held.
    policy: StoredPolicy,
}

/// Where the file is, beside the registry's database.
#[must_use]
pub fn file_beside(registry_database: &Path) -> PathBuf {
    registry_database.with_file_name("policy-mirror.cbor")
}

/// Reads the mirror, none when the file is not there.
///
/// # Errors
///
/// Returns an error when the file is there and is not a record of this format.
pub fn read(file: &Path) -> Result<Option<(u64, StoredPolicy)>> {
    let refused = |why: String| {
        ControllerError::registry(format!(
            "{} is not a policy mirror this build understands: {why}",
            file.display()
        ))
    };
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(file, MAX_RECORD_LEN)
        .map_err(|error| ControllerError::registry(error.to_string()))?
    else {
        return Ok(None);
    };
    let record: Record = kr_cbor::from_canonical_slice(&bytes, &kr_cbor::Limits::DEFAULT)
        .map_err(|error| refused(error.to_string()))?;
    if record.version != RECORD_VERSION {
        return Err(refused(format!(
            "it is of format {}, and this build reads format {RECORD_VERSION}",
            record.version
        )));
    }
    Ok(Some((record.sequence, record.policy)))
}

/// Writes the mirror in one write, owner only.
///
/// # Errors
///
/// Returns an error when the policy cannot be encoded or the file cannot be written. What was
/// there is then as it was, except when the file was replaced and the directory then could not be
/// flushed: the new file is there, and the error says the write is not known to be durable.
pub fn write(file: &Path, sequence: u64, policy: &StoredPolicy) -> Result<()> {
    let bytes = kr_cbor::to_canonical_vec(&Record {
        version: RECORD_VERSION,
        sequence,
        policy: policy.clone(),
    })
    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
    kr_ipc::paths::write_owner_only_file(file, &bytes)
        .map_err(|error| ControllerError::registry(error.to_string()))
}
