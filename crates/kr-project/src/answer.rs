//! The rule, applied inside a stored answer.
//!
//! A successful reply is kept whole: an action's row holds the canonical encoding of the typed
//! result, and a repeat of that action is answered from it rather than performed again. The reply
//! carries free text of its own — a workspace's reason, what a removal found the workspace holding,
//! an operation's reason, the limitations a preview states — and text is where a credential can be.
//!
//! So the same rule that covers a refusal covers a stored reply. It is applied where the answer is
//! read out of the journal, which is the last place this host can reach it before it goes to a
//! caller, and again over the file itself when a store an earlier build wrote is upgraded.
//!
//! What it does **not** touch is data. A label, a display path, a preview's paths, an inclusion's
//! unapplied paths, a base reference and a validated remote URL are all values the request named or
//! the repository holds, and the caller asked for them; replacing them would answer a different
//! question. The distinction is the same one the diagnostics make everywhere else in this service:
//! explanatory text is repeated only when this host can vouch for it, and a requested value is
//! returned.

use kr_protocol::method::Method;
use kr_protocol::project::{
    InclusionPreview, OperationRecord, ProjectAdoptResult, ProjectCloneResult, ProjectInitResult,
    ProjectLocationAttachResult, ProjectLocationAuthoriseResult, ProjectLocationWithdrawResult,
    ProjectOperationCancelResult, RetainedItem, WorkspaceCreateResult, WorkspaceRemoveResult,
    WorkspaceSummary,
};

use crate::error::{ProjectError, Result};

/// Returns one stored answer with every diagnostic in it through the rule.
///
/// The method the action was claimed under says which result type the bytes hold. A method this
/// build does not serve, or an encoding it cannot read, is refused rather than repeated: this host
/// does not hand a caller text it has not been able to look at.
///
/// # Errors
///
/// Returns [`ProjectError::StoreUnavailable`] when the method is not one of the nine that record a
/// result, or when the stored bytes are not that method's result.
pub fn protect_stored_result(method: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    match Method::from_wire(method) {
        Some(Method::ProjectInit) => rewrite::<ProjectInitResult>(encoded),
        Some(Method::ProjectClone) => rewrite::<ProjectCloneResult>(encoded),
        Some(Method::ProjectAdopt) => rewrite::<ProjectAdoptResult>(encoded),
        Some(Method::ProjectOperationCancel) => rewrite::<ProjectOperationCancelResult>(encoded),
        Some(Method::WorkspaceCreate) => rewrite::<WorkspaceCreateResult>(encoded),
        Some(Method::WorkspaceRemove) => rewrite::<WorkspaceRemoveResult>(encoded),
        Some(Method::ProjectLocationAuthorise) => {
            rewrite::<ProjectLocationAuthoriseResult>(encoded)
        }
        Some(Method::ProjectLocationWithdraw) => rewrite::<ProjectLocationWithdrawResult>(encoded),
        Some(Method::ProjectLocationAttach) => rewrite::<ProjectLocationAttachResult>(encoded),
        _ => Err(ProjectError::StoreUnavailable {
            detail: format!(
                "a recorded answer to {} is not one this build can read back",
                crate::git::redact(method)
            )
            .into(),
        }),
    }
}

/// Decodes one answer, puts its diagnostics through the rule and encodes it again.
///
/// The encoding is canonical in and canonical out, so an answer whose text the rule leaves alone
/// comes back byte for byte as it was stored.
fn rewrite<T>(encoded: &[u8]) -> Result<Vec<u8>>
where
    T: Protected + serde::de::DeserializeOwned + serde::Serialize,
{
    let mut answer: T = kr_cbor::from_canonical_slice(encoded, &kr_cbor::Limits::DEFAULT)
        .map_err(ProjectError::store)?;
    answer.protect();
    kr_cbor::to_canonical_vec(&answer).map_err(ProjectError::store)
}

/// One answer, or a part of one, whose diagnostics can be put through the rule in place.
///
/// Implemented for every result a mutation records, so a result type that gains a diagnostic field
/// gains it here rather than in nine separate places.
trait Protected {
    /// Replaces every diagnostic this value carries with what this host will repeat.
    fn protect(&mut self);
}

impl Protected for String {
    fn protect(&mut self) {
        *self = crate::git::redact(self);
    }
}

impl<T: Protected> Protected for Option<T> {
    fn protect(&mut self) {
        if let Some(value) = self.as_mut() {
            value.protect();
        }
    }
}

impl<T: Protected> Protected for Vec<T> {
    fn protect(&mut self) {
        for value in self.iter_mut() {
            value.protect();
        }
    }
}

impl<T: Protected> Protected for kr_protocol::scalars::Nullable<T> {
    fn protect(&mut self) {
        self.0.protect();
    }
}

impl Protected for RetainedItem {
    fn protect(&mut self) {
        // What a workspace holds is read back in a successful answer, and the reason names what
        // the host found rather than what the caller asked for.
        self.detail.protect();
    }
}

impl Protected for InclusionPreview {
    fn protect(&mut self) {
        // The limitations are sentences about the repository's own configuration. The counts, the
        // entries and their paths are the measurement the caller asked for.
        self.limitations.protect();
    }
}

impl Protected for WorkspaceSummary {
    fn protect(&mut self) {
        self.detail.protect();
        self.retained.protect();
    }
}

impl Protected for OperationRecord {
    fn protect(&mut self) {
        // The staging paths are names this host chose; the reason is the one free-text field.
        self.detail.protect();
    }
}

impl Protected for ProjectInitResult {
    fn protect(&mut self) {
        self.operation.protect();
    }
}

impl Protected for ProjectCloneResult {
    fn protect(&mut self) {
        self.operation.protect();
    }
}

impl Protected for ProjectAdoptResult {
    fn protect(&mut self) {
        self.operation.protect();
    }
}

impl Protected for ProjectOperationCancelResult {
    fn protect(&mut self) {
        self.operation.protect();
    }
}

impl Protected for WorkspaceCreateResult {
    fn protect(&mut self) {
        self.workspace.protect();
        self.preview.protect();
    }
}

impl Protected for WorkspaceRemoveResult {
    fn protect(&mut self) {
        self.workspace.protect();
        self.retained.protect();
    }
}

// The owner's location decisions carry no diagnostic. A location's label and path, a repository's
// summary and the name a binding resolved by are all values the owner named or the host recorded,
// and replacing them would answer a different question. A challenge is never recorded at all: it is
// the answer to a submission that performs nothing.

impl Protected for ProjectLocationAuthoriseResult {
    fn protect(&mut self) {}
}

impl Protected for ProjectLocationWithdrawResult {
    fn protect(&mut self) {}
}

impl Protected for ProjectLocationAttachResult {
    fn protect(&mut self) {}
}

#[cfg(test)]
mod tests {
    use kr_protocol::ids::{ChangeSetId, EnvironmentId, ProjectRepositoryId, WorkspaceId};
    use kr_protocol::project::{
        InclusionPolicy, IsolationMechanism, RetainedKind, WorkspaceKind, WorkspaceState,
    };
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    use super::*;

    fn summary(detail: &str, retained: &str) -> WorkspaceSummary {
        WorkspaceSummary {
            workspace_id: WorkspaceId::new(Uuid::from_bytes([1; 16])),
            project_repository_id: ProjectRepositoryId::new(Uuid::from_bytes([2; 16])),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            label: "a label the caller chose".to_owned(),
            kind: WorkspaceKind::Isolated,
            isolation: Nullable(Some(IsolationMechanism::GitWorktree)),
            policy: InclusionPolicy::base_only(),
            state: WorkspaceState::RemovalPending,
            base_revision: "a".repeat(40),
            base_change_set_id: Nullable(None),
            filesystem_identity: Nullable(None),
            display_path: "/work/a-tree".to_owned(),
            detail: Nullable(Some(detail.to_owned())),
            bound_sessions: Vec::new(),
            bound_runs: Vec::new(),
            retained: vec![RetainedItem {
                kind: RetainedKind::PinnedChangeSet,
                detail: retained.to_owned(),
                change_set_id: Nullable(Some(ChangeSetId::new(Uuid::from_bytes([4; 16])))),
            }],
            created_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn a_recorded_answer_keeps_its_data_and_loses_what_this_host_will_not_repeat() {
        let stored = WorkspaceRemoveResult {
            workspace: summary(
                "the tree at /w/access_token=FIRST could not be read",
                "/w/access_token=SECOND holds work this host has not read",
            ),
            working_files_removed: false,
            retained: vec![RetainedItem {
                kind: RetainedKind::DirtyContent,
                detail: "/w/access_token=THIRD holds uncommitted work".to_owned(),
                change_set_id: Nullable(None),
            }],
        };
        let encoded = kr_cbor::to_canonical_vec(&stored).expect("it encodes");
        let protected = protect_stored_result("workspace.remove", &encoded).expect("it rewrites");
        let answer: WorkspaceRemoveResult =
            kr_cbor::from_canonical_slice(&protected, &kr_cbor::Limits::DEFAULT)
                .expect("it decodes");
        for secret in ["FIRST", "SECOND", "THIRD"] {
            assert!(
                !format!("{answer:?}").contains(secret),
                "no diagnostic in a stored answer repeats what this host cannot vouch for: \
                 {answer:?}"
            );
        }
        // And the answer is still the answer: what the caller asked about is unchanged.
        assert_eq!(answer.workspace.workspace_id, stored.workspace.workspace_id);
        assert_eq!(answer.workspace.label, stored.workspace.label);
        assert_eq!(answer.workspace.display_path, stored.workspace.display_path);
        assert_eq!(answer.workspace.state, stored.workspace.state);
        assert_eq!(answer.retained.len(), 1);
        assert_eq!(answer.retained[0].kind, RetainedKind::DirtyContent);
        assert_eq!(
            answer.workspace.retained[0].change_set_id,
            stored.workspace.retained[0].change_set_id
        );
        // An answer that was composed under the rule already is returned as it was stored.
        let again = protect_stored_result("workspace.remove", &protected).expect("it rewrites");
        assert_eq!(again, protected, "the rule leaves its own output alone");
    }

    #[test]
    fn an_answer_this_build_cannot_read_is_refused_rather_than_repeated() {
        let stored = WorkspaceRemoveResult {
            workspace: summary("a reason", "a pin"),
            working_files_removed: true,
            retained: Vec::new(),
        };
        let encoded = kr_cbor::to_canonical_vec(&stored).expect("it encodes");
        // A method that records no result, and a method this build does not serve at all.
        for method in ["workspace.read", "something.else"] {
            assert_eq!(
                protect_stored_result(method, &encoded)
                    .expect_err("it is refused")
                    .code(),
                kr_protocol::error::ErrorCode::StorageUnavailable
            );
        }
        // And bytes that are not this method's result.
        assert!(protect_stored_result("project.init", &encoded).is_err());
    }
}
