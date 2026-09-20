//! The rule, applied inside a stored answer.
//!
//! A successful reply is kept whole: an action's row holds the canonical encoding of the typed
//! result, and a repeat of that action is answered from it rather than performed again. The reply
//! carries free text of its own — what decided a consistency class, why a path was left out, what
//! an apply came to, what a result does and does not attest — and text is where a credential can
//! be.
//!
//! So the same rule that covers a refusal covers a stored reply, applied where the answer is read
//! out of the journal, which is the last place this host can reach it before it goes to a caller.
//!
//! What it does **not** touch is data. A label, a path, a note the caller wrote, a command it ran
//! and a digest are values the request named or this host measured, and the caller asked for them;
//! replacing them would answer a different question. What goes through the rule is the text this
//! host composed as an explanation.

use kr_protocol::changeset::{
    ChangeSetVersionRecord, ChangesetCaptureResult, ChangesetMaterializeResult, DiffApplyResult,
};
use kr_protocol::method::Method;

use crate::error::{ChangeSetError, Result};

/// Returns one stored answer with every diagnostic in it through the rule.
///
/// The method the action was claimed under says which result type the bytes hold. A method this
/// build does not serve, or an encoding it cannot read, is refused rather than repeated: this host
/// does not hand a caller text it has not been able to look at.
///
/// # Errors
///
/// Returns [`ChangeSetError::StoreUnavailable`] when the method is not one that records a result,
/// or when the stored bytes are not that method's result.
pub fn protect_stored_result(method: &str, encoded: &[u8]) -> Result<Vec<u8>> {
    match Method::from_wire(method) {
        Some(Method::ChangesetCapture) => rewrite::<ChangesetCaptureResult>(encoded),
        Some(Method::ChangesetMaterialize) => rewrite::<ChangesetMaterializeResult>(encoded),
        Some(Method::DiffApply | Method::DiffRevert) => rewrite::<DiffApplyResult>(encoded),
        _ => Err(ChangeSetError::StoreUnavailable {
            detail: format!(
                "a recorded answer to {} is not one this build can read back",
                kr_project::git::redact(method)
            )
            .into(),
        }),
    }
}

/// Decodes one answer, puts its diagnostics through the rule and encodes it again.
fn rewrite<T>(encoded: &[u8]) -> Result<Vec<u8>>
where
    T: Protected + serde::de::DeserializeOwned + serde::Serialize,
{
    let mut answer: T = crate::service::decode_stored(encoded)?;
    answer.protect();
    crate::service::encode_stored(&answer)
}

/// One answer, or a part of one, whose diagnostics can be put through the rule in place.
trait Protected {
    /// Replaces every diagnostic this value carries with what this host will repeat.
    fn protect(&mut self);
}

impl Protected for String {
    fn protect(&mut self) {
        *self = kr_project::git::redact(self);
    }
}

impl<T: Protected> Protected for Vec<T> {
    fn protect(&mut self) {
        for item in self {
            item.protect();
        }
    }
}

impl<T: Protected> Protected for kr_protocol::scalars::Nullable<T> {
    fn protect(&mut self) {
        if let Some(inner) = self.0.as_mut() {
            inner.protect();
        }
    }
}

impl Protected for ChangeSetVersionRecord {
    fn protect(&mut self) {
        self.consistency_detail.protect();
        self.limitations.protect();
        self.provenance.derivation.protect();
        for exclusion in &mut self.exclusions {
            exclusion.detail.protect();
        }
    }
}

impl Protected for ChangesetCaptureResult {
    fn protect(&mut self) {
        self.version.protect();
    }
}

impl Protected for ChangesetMaterializeResult {
    fn protect(&mut self) {
        self.limitations.protect();
    }
}

impl Protected for DiffApplyResult {
    fn protect(&mut self) {
        self.detail.protect();
        self.limitations.protect();
        self.recovery.detail.protect();
        for row in &mut self.progress {
            row.detail.protect();
        }
        for conflict in &mut self.conflicts {
            conflict.detail.protect();
        }
        if let Some(reference) = self.reference.0.as_mut() {
            reference.limitation.protect();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_method_this_build_does_not_record_a_result_for_is_refused() {
        // This host does not hand a caller text it has not been able to look at.
        for method in [
            "diff.read",
            "changeset.read",
            "project.init",
            "not a method",
        ] {
            assert!(
                protect_stored_result(method, &[]).is_err(),
                "{method} records no result this build reads back"
            );
        }
    }

    #[test]
    fn an_explanation_goes_through_the_rule_and_a_value_the_caller_named_does_not() {
        let hostile = "https://user:SECRET-TOKEN@host.invalid/x";
        let mut result = DiffApplyResult {
            action_id: kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            outcome: kr_protocol::scalars::Nullable(None),
            destination: kr_protocol::changeset::DestinationClass::Proposal,
            applied_version: kr_protocol::changeset::VersionRef {
                change_set_id: kr_protocol::ids::ChangeSetId::new(kr_ipc::new_uuid()),
                version: kr_protocol::ids::ChangeSetVersion::new(1),
            },
            proposal_version: kr_protocol::scalars::Nullable(None),
            reference: kr_protocol::scalars::Nullable(None),
            changed_paths: vec![hostile.to_owned()],
            unresolved_paths: Vec::new(),
            conflicts: Vec::new(),
            progress: Vec::new(),
            recovery: kr_protocol::changeset::RecoveryObjects {
                before_version: kr_protocol::scalars::Nullable(None),
                after_version: kr_protocol::scalars::Nullable(None),
                applied_version: kr_protocol::scalars::Nullable(None),
                staged_path: kr_protocol::scalars::Nullable(None),
                staged_leftovers: vec![hostile.to_owned()],
                detail: hostile.to_owned(),
            },
            limitations: vec![hostile.to_owned()],
            detail: hostile.to_owned(),
            decided_at_ms: kr_ipc::now_ms(),
        };
        result.protect();
        assert!(!result.detail.contains("SECRET-TOKEN"));
        assert!(!result.recovery.detail.contains("SECRET-TOKEN"));
        assert!(!result.limitations[0].contains("SECRET-TOKEN"));
        // A path is a value the caller named and asked about; the rule leaves it alone, and the
        // wire boundary's own rule covers what reaches a message.
        assert_eq!(result.changed_paths[0], hostile);
        assert_eq!(result.recovery.staged_leftovers[0], hostile);
    }
}
