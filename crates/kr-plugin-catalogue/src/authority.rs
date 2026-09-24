//! Who may change the catalogue, asked where the change becomes durable.
//!
//! A catalogue change is admitted before it starts and becomes durable much later: after the
//! repository's lock, after a download, after a package has been staged and checked. Asking only
//! at the start proves the admission stood at the start, which is not the question. So the
//! admission travels with the change as an [`Authority`], and the change commits inside
//! [`Authority::commit`], which holds the admission standing for exactly as long as the commit
//! takes.
//!
//! This is enforced by what the store accepts rather than by where calls happen to be. Every
//! durable effect the catalogue has (a state transaction, a payload written into the cache, a
//! package moved into place, a payload reclaimed) takes a [`Permit`], and the only place a permit
//! exists is inside [`committed`], which obtains it from the authority's own commit. A code path
//! that wrote without asking has nothing to write with.
//!
//! Every commit also names the [`Effect`] it makes. An action can commit several changes before
//! the one it was asked for, and when it then stops, what committed is still there. A
//! [`Recording`] wraps the admission and keeps the list, so the action's receipt says what the
//! action left behind instead of claiming it had no effect.

use std::sync::Mutex;

use kr_plugin_sdk::digest::PayloadDigest;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::receipt::ReceiptState;

use crate::error::{CatalogueError, CatalogueResult};
use crate::repository::RepositoryId;

/// Whoever admitted a catalogue change.
pub trait Authority: Send + Sync {
    /// Checks that the admission still stands.
    ///
    /// Asked before slow work, so a change whose admission has already lapsed stops without
    /// downloading anything. It proves nothing about any later moment: that is what
    /// [`Self::commit`] is for.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admitting authority decided.
    fn check(&self) -> CatalogueResult<()>;

    /// Runs `commit`, which makes `effect` durable, with the admission held standing for all of
    /// it.
    ///
    /// The implementation checks the admission once more and then runs `commit` without
    /// releasing whatever orders it against a withdrawal, so a withdrawal lands wholly before the
    /// check or wholly after the commit. It must not wait for anything slow while it holds that
    /// order; `commit` itself is short and never awaits. An implementation that wraps another
    /// authority passes `effect` on unchanged.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admitting authority decided, in which case `commit` did not run,
    /// or the error `commit` returned.
    fn commit(
        &self,
        effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()>;

    /// Returns true when this authority carries the owner's confirmation of the change.
    ///
    /// A new root, and trust wider than the one already accepted, are the owner's decisions. The
    /// catalogue asks the authority it was given rather than taking a flag from whoever called:
    /// the daemon's authority answers yes only when it was built from a confirmation its own
    /// ceremony accepted, and it checks that confirmation again inside [`Self::commit`].
    fn owner_confirmed(&self) -> bool;
}

/// The owner's own authority on this host, with no admission window to lapse.
///
/// This is what a process holds when it is the owner acting directly, with nothing admitted per
/// connection: the catalogue's own suites, and a tool running as the owner. The daemon never uses
/// it for a request it admitted; it passes the admission it carried instead.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owner {
    confirmed: bool,
}

impl Owner {
    /// The owner acting, without having confirmed a new root or wider trust.
    #[must_use]
    pub const fn acting() -> Self {
        Self { confirmed: false }
    }

    /// The owner acting, having confirmed the new root or the wider trust in front of them.
    #[must_use]
    pub const fn confirming() -> Self {
        Self { confirmed: true }
    }
}

impl Authority for Owner {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        _effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        commit()
    }

    fn owner_confirmed(&self) -> bool {
        self.confirmed
    }
}

/// One durable change a commit makes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    /// The catalogue's records, with the receipt of the action that changed them.
    Records,
    /// A repository's newer trust root, kept the moment verification reached it.
    Root(RepositoryId),
    /// A repository's trust checkpoint, the metadata a verification accepted.
    Checkpoint(RepositoryId),
    /// A verified generation's index document, written into its repository's store.
    Index(RepositoryId),
    /// A verified payload, written into the cache under its digest.
    Payload(PayloadDigest),
    /// A verified package, moved into place under its manifest digest.
    Package(PayloadDigest),
    /// Extracted packages and cached payloads nothing protects, removed to make room.
    Reclaim {
        /// How many extracted packages.
        packages: u64,
        /// How many payloads.
        payloads: u64,
        /// How many bytes they held.
        bytes: u64,
    },
    /// The index documents of generations a repository no longer keeps, removed once no record
    /// names them.
    Forgotten(RepositoryId),
}

impl core::fmt::Display for Effect {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Records => f.write_str("the catalogue's records"),
            Self::Root(id) => write!(f, "a new trust root for {id}"),
            Self::Checkpoint(id) => write!(f, "the trust checkpoint for {id}"),
            Self::Index(id) => write!(f, "a generation index for {id}"),
            Self::Payload(digest) => write!(f, "the payload {digest}"),
            Self::Package(digest) => write!(f, "the package {digest}"),
            Self::Reclaim {
                packages,
                payloads,
                bytes,
            } => write!(
                f,
                "the removal of {packages} extracted packages and {payloads} cached payloads \
                 ({bytes} bytes) to make room"
            ),
            Self::Forgotten(id) => write!(
                f,
                "the removal of the index documents of generations {id} no longer keeps"
            ),
        }
    }
}

/// One change a [`Recording`] saw commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Committed {
    /// The change.
    pub effect: Effect,
    /// False when the change reached the store and its durability was not confirmed.
    pub confirmed: bool,
}

/// An authority that keeps a record of what its commits made durable.
///
/// Every durable change takes a [`Permit`], every permit is lent inside [`Authority::commit`],
/// and this authority wraps that commit, so no change reaches the store without this record
/// seeing it. What the wrapped commit returns decides what is recorded: success is a change that
/// committed, [`CatalogueError::PublicationUncertain`] is one that may have, and any other error
/// is one that left nothing behind, which is what every change the catalogue makes reports when
/// it fails before writing.
pub struct Recording<'a> {
    authority: &'a dyn Authority,
    committed: Mutex<Vec<Committed>>,
}

impl<'a> Recording<'a> {
    /// Starts recording the commits made under `authority`.
    #[must_use]
    pub fn new(authority: &'a dyn Authority) -> Self {
        Self {
            authority,
            committed: Mutex::new(Vec::new()),
        }
    }

    /// Returns what has committed so far, in the order it committed.
    #[must_use]
    pub fn committed(&self) -> Vec<Committed> {
        self.committed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Returns how an action that stopped with `error` is settled, from what it committed first.
    ///
    /// Refused only when nothing committed and the error is not itself an uncertain outcome:
    /// section 9 reserves refused for an action proved to have had no effect. Anything else is
    /// unknown, and the answer names what the action committed before it stopped and what stopped
    /// it, so the first answer and every retained one say what the action left behind.
    #[must_use]
    pub fn failure(&self, error: &ProtocolError) -> Failure {
        let committed = self.committed();
        if committed.is_empty() {
            let state = if error.code == ErrorCode::OutcomeUnknown {
                ReceiptState::Unknown
            } else {
                ReceiptState::Refused
            };
            return Failure {
                state,
                answer: error.clone(),
            };
        }
        Failure {
            state: ReceiptState::Unknown,
            answer: ProtocolError::new(ErrorCode::OutcomeUnknown, left_behind(&committed, error)),
        }
    }

    fn note(&self, effect: &Effect, confirmed: bool) {
        self.committed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Committed {
                effect: effect.clone(),
                confirmed,
            });
    }
}

impl Authority for Recording<'_> {
    fn check(&self) -> CatalogueResult<()> {
        self.authority.check()
    }

    fn commit(
        &self,
        effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.authority.commit(effect, &mut || {
            let outcome = commit();
            match &outcome {
                Ok(()) => self.note(effect, true),
                Err(CatalogueError::PublicationUncertain { .. }) => self.note(effect, false),
                Err(_) => {}
            }
            outcome
        })
    }

    fn owner_confirmed(&self) -> bool {
        self.authority.owner_confirmed()
    }
}

/// How an action that stopped is settled: the state its receipt takes and what it answers with.
///
/// Only [`Recording::failure`] makes one, so the state always follows from what the action
/// committed rather than from what its caller believes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    state: ReceiptState,
    answer: ProtocolError,
}

impl Failure {
    /// Returns the state the receipt takes: refused or unknown.
    #[must_use]
    pub const fn state(&self) -> ReceiptState {
        self.state
    }

    /// Returns what the action answers with, first and on every resubmission.
    #[must_use]
    pub const fn answer(&self) -> &ProtocolError {
        &self.answer
    }

    /// Returns what the action answers with.
    #[must_use]
    pub fn into_answer(self) -> ProtocolError {
        self.answer
    }
}

/// Says what an action committed before `error` stopped it.
///
/// Payloads are counted rather than named, because a full mirror can write thousands of them, and
/// the removals of several reclaims are added up for the same reason.
fn left_behind(committed: &[Committed], error: &ProtocolError) -> String {
    let mut confirmed: Vec<String> = Vec::new();
    let mut unconfirmed: Vec<String> = Vec::new();
    let mut payloads = [0u64; 2];
    let mut removed = [(0u64, 0u64, 0u64); 2];
    for change in committed {
        let at = usize::from(!change.confirmed);
        match &change.effect {
            Effect::Payload(_) => payloads[at] = payloads[at].saturating_add(1),
            Effect::Reclaim {
                packages,
                payloads,
                bytes,
            } => {
                removed[at].0 = removed[at].0.saturating_add(*packages);
                removed[at].1 = removed[at].1.saturating_add(*payloads);
                removed[at].2 = removed[at].2.saturating_add(*bytes);
            }
            effect => {
                let list = if change.confirmed {
                    &mut confirmed
                } else {
                    &mut unconfirmed
                };
                list.push(effect.to_string());
            }
        }
    }
    for (at, list) in [(0usize, &mut confirmed), (1, &mut unconfirmed)] {
        match payloads[at] {
            0 => {}
            1 => list.push("1 payload written into the cache".to_owned()),
            count => list.push(format!("{count} payloads written into the cache")),
        }
        let (packages, payloads, bytes) = removed[at];
        if packages > 0 || payloads > 0 {
            list.push(
                Effect::Reclaim {
                    packages,
                    payloads,
                    bytes,
                }
                .to_string(),
            );
        }
    }
    let mut said = String::from("this action stopped part way and is not performed again");
    if !confirmed.is_empty() {
        said.push_str("; it had committed ");
        said.push_str(&confirmed.join(", "));
    }
    if !unconfirmed.is_empty() {
        said.push_str("; it may have committed ");
        said.push_str(&unconfirmed.join(", "));
    }
    said.push_str(&format!(
        "; it stopped on {}: {}",
        error.code.as_str(),
        error.message
    ));
    said
}

/// The proof that an [`Authority`] is holding the admission standing right now.
///
/// It cannot be made outside this module, cannot be copied and cannot be kept: [`committed`]
/// lends one to the closure it runs and takes it back when that closure returns.
pub(crate) struct Permit {
    _private: (),
}

/// Runs one durable change under the authority's commit, lending it a [`Permit`].
///
/// `effect` names what the change makes durable. The change reports an error that follows a
/// durable write as [`CatalogueError::PublicationUncertain`] and any other error only when it left
/// nothing behind, which is what lets a [`Recording`] tell the two apart.
///
/// A commit that ran and an authority that then reported a failure is an uncertain outcome, never
/// a refusal: the change may already be what every reader sees, so it is reported as
/// [`CatalogueError::PublicationUncertain`] and not as something that did not happen.
///
/// # Errors
///
/// Returns the authority's refusal when the change did not run, the change's own error when it
/// failed, and [`CatalogueError::PublicationUncertain`] when it ran and the authority failed after.
pub(crate) fn committed<T>(
    authority: &dyn Authority,
    effect: &Effect,
    change: impl FnOnce(&Permit) -> CatalogueResult<T>,
) -> CatalogueResult<T> {
    let mut change = Some(change);
    let mut outcome: Option<T> = None;
    let result = authority.commit(effect, &mut || {
        let change = change
            .take()
            .ok_or_else(|| CatalogueError::StorageUnavailable {
                detail: "a change was committed twice by the authority that admitted it".to_owned(),
            })?;
        outcome = Some(change(&Permit { _private: () })?);
        Ok(())
    });
    match (result, outcome) {
        (Ok(()), Some(value)) => Ok(value),
        (Ok(()), None) => Err(CatalogueError::StorageUnavailable {
            detail: "the authority that admitted this change did not run it".to_owned(),
        }),
        (Err(error), Some(_)) => Err(CatalogueError::PublicationUncertain {
            detail: format!(
                "the change was committed and the authority that admitted it then failed: {error}"
            ),
        }),
        (Err(error), None) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An authority that refuses before running the change.
    struct Refusing;

    impl Authority for Refusing {
        fn check(&self) -> CatalogueResult<()> {
            Ok(())
        }

        fn commit(
            &self,
            _effect: &Effect,
            _commit: &mut dyn FnMut() -> CatalogueResult<()>,
        ) -> CatalogueResult<()> {
            Err(CatalogueError::PermissionDenied {
                detail: "withdrawn".to_owned(),
            })
        }

        fn owner_confirmed(&self) -> bool {
            false
        }
    }

    /// An authority that runs the change and then fails.
    struct FailingAfter;

    impl Authority for FailingAfter {
        fn check(&self) -> CatalogueResult<()> {
            Ok(())
        }

        fn commit(
            &self,
            _effect: &Effect,
            commit: &mut dyn FnMut() -> CatalogueResult<()>,
        ) -> CatalogueResult<()> {
            commit()?;
            Err(CatalogueError::StorageUnavailable {
                detail: "the order could not be released".to_owned(),
            })
        }

        fn owner_confirmed(&self) -> bool {
            false
        }
    }

    fn payload() -> PayloadDigest {
        PayloadDigest::of(b"component")
    }

    #[test]
    fn a_refused_commit_runs_nothing() {
        let mut ran = false;
        let refusal = committed(&Refusing, &Effect::Records, |_permit| {
            ran = true;
            Ok(())
        })
        .expect_err("refused");
        assert!(!ran, "the change never ran");
        assert!(matches!(refusal, CatalogueError::PermissionDenied { .. }));
    }

    #[test]
    fn a_change_that_ran_under_a_failing_authority_is_uncertain() {
        let mut ran = false;
        let outcome = committed(&FailingAfter, &Effect::Records, |_permit| {
            ran = true;
            Ok(())
        })
        .expect_err("the authority failed after the change");
        assert!(ran);
        assert!(
            matches!(outcome, CatalogueError::PublicationUncertain { .. }),
            "{outcome:?}"
        );
    }

    #[test]
    fn the_owner_commits_and_says_whether_it_confirmed() {
        assert_eq!(
            committed(&Owner::acting(), &Effect::Records, |_permit| Ok(7)).expect("committed"),
            7
        );
        assert!(!Owner::acting().owner_confirmed());
        assert!(Owner::confirming().owner_confirmed());
    }

    #[test]
    fn a_recording_keeps_what_committed_and_what_may_have() {
        let owner = Owner::acting();
        let recording = Recording::new(&owner);
        committed(&recording, &Effect::Payload(payload()), |_permit| Ok(())).expect("committed");
        let _ = committed(&recording, &Effect::Package(payload()), |_permit| {
            Err::<(), _>(CatalogueError::PublicationUncertain {
                detail: "the directory did not confirm it".to_owned(),
            })
        });
        let _ = committed(&recording, &Effect::Records, |_permit| {
            Err::<(), _>(CatalogueError::StorageUnavailable {
                detail: "nothing was written".to_owned(),
            })
        });
        let _ = committed(&Recording::new(&Refusing), &Effect::Records, |_permit| {
            Ok(())
        });
        assert_eq!(
            recording.committed(),
            vec![
                Committed {
                    effect: Effect::Payload(payload()),
                    confirmed: true,
                },
                Committed {
                    effect: Effect::Package(payload()),
                    confirmed: false,
                },
            ],
            "a change that failed before writing, and one never run, left nothing to record"
        );
    }

    #[test]
    fn an_action_that_committed_nothing_is_refused_with_its_own_answer() {
        let owner = Owner::acting();
        let recording = Recording::new(&owner);
        let error = ProtocolError::new(ErrorCode::PermissionDenied, "withdrawn");
        let failure = recording.failure(&error);
        assert_eq!(failure.state(), ReceiptState::Refused);
        assert_eq!(failure.answer(), &error);

        // An error that is itself an uncertain outcome is never a refusal.
        let uncertain = ProtocolError::new(ErrorCode::OutcomeUnknown, "not confirmed");
        let failure = recording.failure(&uncertain);
        assert_eq!(failure.state(), ReceiptState::Unknown);
        assert_eq!(failure.into_answer(), uncertain);
    }

    #[test]
    fn an_action_that_committed_part_of_its_work_is_unknown_and_says_what_it_left() {
        let owner = Owner::acting();
        let recording = Recording::new(&owner);
        let repository = RepositoryId::new("development").expect("a valid identifier");
        committed(&recording, &Effect::Root(repository), |_permit| Ok(())).expect("committed");
        for _ in 0..3 {
            committed(&recording, &Effect::Payload(payload()), |_permit| Ok(()))
                .expect("committed");
        }
        let failure = recording.failure(&ProtocolError::new(
            ErrorCode::PermissionDenied,
            "the admission was withdrawn",
        ));
        assert_eq!(failure.state(), ReceiptState::Unknown);
        let answer = failure.answer();
        assert_eq!(answer.code, ErrorCode::OutcomeUnknown);
        assert!(
            answer
                .message
                .contains("a new trust root for development, 3 payloads written into the cache"),
            "{answer:?}"
        );
        assert!(
            answer
                .message
                .contains("PERMISSION_DENIED: the admission was withdrawn"),
            "{answer:?}"
        );
    }
}
