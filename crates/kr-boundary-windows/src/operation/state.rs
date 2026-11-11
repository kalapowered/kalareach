//! What state of the repository a command needs, and what the readers' answers say about it.
//!
//! Each function is pure: it takes the names the broker listed in the held `.git` folder, the
//! `HEAD` it read through the held handle, or a reader's parsed answer, and says whether the
//! command may go on. A refusal names the rule and a name this module holds, never a name the
//! repository supplied.

use crate::frame::invocation::RefusedKind;
use crate::refusal::Refusal;
use crate::repository::head::HeadKind;
use crate::repository::readers::{RULE_UNRESOLVED, Symbolic};

/// The entries of `.git` that say an operation is in progress. A command that writes refuses to
/// go on while any is there: a cherry-pick state, for one, supplies the author despite the
/// identity the broker sets. The read commands run.
pub const STATE_NAMES: [&str; 8] = [
    "MERGE_HEAD",
    "CHERRY_PICK_HEAD",
    "REVERT_HEAD",
    "REBASE_HEAD",
    "BISECT_LOG",
    "rebase-merge",
    "rebase-apply",
    "sequencer",
];

/// An operation is in progress in the repository.
pub const RULE_OPERATION_IN_PROGRESS: &str = "repository-operation-in-progress";
/// A branch reference that is symbolic.
pub const RULE_SYMBOLIC_REF: &str = "operation-symbolic-ref";
/// A branch name that a tag also carries.
pub const RULE_AMBIGUOUS_NAME: &str = "operation-ambiguous-name";
/// The implicit `HEAD` could not be checked.
pub const RULE_HEAD_UNCHECKED: &str = "repository-head-unchecked";

/// Checks the names of the entries of the held `.git` folder for a state a writing command refuses.
/// Names compare without regard to case, as the file system does.
///
/// # Errors
///
/// Returns a refusal of kind `repository` that names the state.
pub fn check_operation_state<S: AsRef<str>>(entries: &[S]) -> Result<(), Refusal> {
    for state in STATE_NAMES {
        if entries
            .iter()
            .any(|entry| entry.as_ref().eq_ignore_ascii_case(state))
        {
            return Err(Refusal::new(
                RefusedKind::Repository,
                RULE_OPERATION_IN_PROGRESS,
                &format!("operation in progress {state}"),
            ));
        }
    }
    Ok(())
}

/// Checks the reference a command writes through when it names none, which is `HEAD`'s target.
///
/// A symbolic reference to a branch needs R2's answer and passes only when the target is not
/// symbolic (a branch that does not exist yet is not). A detached `HEAD` writes no reference.
///
/// # Errors
///
/// Returns a refusal when the target is symbolic, or when `HEAD` names a branch and R2's answer
/// is not given.
pub fn check_implicit_head(head: &HeadKind, target: Option<Symbolic>) -> Result<(), Refusal> {
    match (head, target) {
        (HeadKind::Detached { .. }, _) | (HeadKind::Branch { .. }, Some(Symbolic::No)) => Ok(()),
        (HeadKind::Branch { name }, Some(Symbolic::Yes)) => check_not_symbolic(
            &format!("{}{name}", crate::names::BRANCH_PREFIX),
            Symbolic::Yes,
        ),
        (HeadKind::Branch { .. }, None) => Err(Refusal::new(
            RefusedKind::Repository,
            RULE_HEAD_UNCHECKED,
            "HEAD names a branch whose reference was not checked",
        )),
    }
}

/// Checks R2's answer for a reference a command writes.
///
/// # Errors
///
/// Returns a refusal of kind `operation` that names the reference when it is symbolic.
pub fn check_not_symbolic(refname: &str, answer: Symbolic) -> Result<(), Refusal> {
    match answer {
        Symbolic::No => Ok(()),
        Symbolic::Yes => Err(Refusal::new(
            RefusedKind::Operation,
            RULE_SYMBOLIC_REF,
            &format!("symbolic ref {refname}"),
        )),
    }
}

/// Checks R1's answer for `refs/tags/<name>`: a branch is never taken for a tag, so a tag of the
/// same name makes the name ambiguous. The lookup must fail by finding nothing; a failure of any
/// other kind, a deadline or a cut answer, is returned as it is.
///
/// # Errors
///
/// Returns a refusal that says the name is ambiguous when the tag resolves, and the reader's own
/// refusal when the lookup failed for another reason than an unresolved name.
pub fn check_no_tag(name: &str, tag_lookup: &Result<String, Refusal>) -> Result<(), Refusal> {
    match tag_lookup {
        Ok(_) => Err(Refusal::new(
            RefusedKind::Operation,
            RULE_AMBIGUOUS_NAME,
            &format!("ambiguous name {name}"),
        )),
        Err(refusal) if refusal.rule == RULE_UNRESOLVED => Ok(()),
        Err(refusal) => Err(refusal.clone()),
    }
}
