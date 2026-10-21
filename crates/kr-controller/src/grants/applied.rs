//! The policies the owner applied for the organisations this host is enrolled in, in a store of
//! their own.
//!
//! An applied policy is the revision an organisation's policy stands at on this host, which is the
//! floor under it, and the adapters the policy allows. It is kept in `organisation-policy.json`
//! beside the registry and not in the registry's enrolment rows: an earlier release reads the
//! registry and has no place for it, so a registry that held one could not be read when the host
//! goes back to that release. That release does not name this file, so it leaves it alone, and it
//! applied no policy.
//!
//! One record holds every enrolment's policy and is written in one write, owner only, so a reader
//! sees the policies as they were or as they are. A host that has applied none has no file.
//!
//! An entry belongs to one enrolment: it names the organisation and the authority revision the
//! host took when it enrolled, which no other enrolment in that organisation shares. A policy
//! applies at a start only to the enrolment it was applied for, so what a withdrawal left behind,
//! because the host stopped between the registry's write and this file's, never applies to a later
//! enrolment: a new enrolment holds no policy.
//!
//! The file is written before the registry row of the request that applied the policy. A stop
//! between the two leaves the file holding a policy the registry has not recorded the chain advance
//! for, if the request carried one. The policy applies at the next start, as the request verified
//! it, and the same request made again completes the advance.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use kr_protocol::ids::{AuthorityRevision, OrganisationId, OrganisationPolicyRevision, PluginId};
use kr_protocol::scalars::{CanonicalSet, Nullable};

use crate::error::{ControllerError, Result};

/// The format of the file this build writes, recorded in it as `version`. A file that records
/// another is refused: an earlier one was never written, and a later one holds what this build
/// would write back without.
pub const RECORD_VERSION: u32 = 1;

/// The largest file this host will read, in bytes.
const MAX_RECORD_LEN: u64 = 1024 * 1024;

/// The policy applied for one enrolment, as it is written down.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAppliedPolicy {
    /// The organisation.
    pub organisation_id: OrganisationId,
    /// The host authority revision in force when this host enrolled in the organisation, which
    /// names the enrolment the policy was applied for.
    pub enrolment_revision: AuthorityRevision,
    /// The revision of the policy. A policy at or below it is not applied again.
    pub organisation_policy_revision: OrganisationPolicyRevision,
    /// The adapters the policy allows, or null for every adapter this host qualifies.
    pub adapter_allowlist: Nullable<CanonicalSet<PluginId>>,
}

/// The file this host keeps the applied policies in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    /// The format this file is written in.
    version: u32,
    /// The applied policies, by organisation.
    policies: Vec<StoredAppliedPolicy>,
}

/// Where the file is, in an environment's state directory.
#[must_use]
pub fn file_in(state_dir: &Path) -> PathBuf {
    state_dir.join("organisation-policy.json")
}

/// Reads the applied policies, none when the file is not there.
///
/// # Errors
///
/// Returns an error when the file is there and is not a record of this format that names each
/// organisation once. A host that started without the restrictions it was left with would be
/// unrestricted by a damaged file, so the start stops instead.
pub fn read(state_dir: &Path) -> Result<Vec<StoredAppliedPolicy>> {
    let path = file_in(state_dir);
    let refused = |why: String| {
        ControllerError::registry(format!(
            "{} is not an organisation policy record this build understands: {why}",
            path.display()
        ))
    };
    let Some(bytes) = kr_ipc::paths::read_owner_only_file(&path, MAX_RECORD_LEN)
        .map_err(|error| ControllerError::registry(error.to_string()))?
    else {
        return Ok(Vec::new());
    };
    let record: Record =
        serde_json::from_slice(&bytes).map_err(|error| refused(error.to_string()))?;
    if record.version != RECORD_VERSION {
        return Err(refused(format!(
            "it is of format {}, and this build reads format {RECORD_VERSION}",
            record.version
        )));
    }
    let mut organisations = std::collections::BTreeSet::new();
    for policy in &record.policies {
        if !organisations.insert(policy.organisation_id) {
            return Err(refused(format!(
                "it names organisation {} twice",
                policy.organisation_id
            )));
        }
    }
    Ok(record.policies)
}

/// Writes the applied policies in one write, or removes the file when there are none.
///
/// # Errors
///
/// Returns an error when the file cannot be written or removed. What was there is then as it was.
pub fn write(state_dir: &Path, policies: &[StoredAppliedPolicy]) -> Result<()> {
    let path = file_in(state_dir);
    if policies.is_empty() {
        // A removal is refused, as a rename is, while another program holds the file.
        return match kr_flush::retry_while_held(|| std::fs::remove_file(&path)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(
                ControllerError::registry(format!("could not remove {}: {error}", path.display())),
            ),
            _ => Ok(()),
        };
    }
    let bytes = serde_json::to_vec_pretty(&Record {
        version: RECORD_VERSION,
        policies: policies.to_vec(),
    })
    .map_err(ControllerError::registry)?;
    kr_ipc::paths::write_owner_only_file(&path, &bytes)
        .map_err(|error| ControllerError::registry(error.to_string()))
}
