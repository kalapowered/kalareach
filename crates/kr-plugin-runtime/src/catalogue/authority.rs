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

use crate::catalogue::error::{CatalogueError, CatalogueResult};

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

    /// Runs `commit` with the admission held standing for all of it.
    ///
    /// The implementation checks the admission once more and then runs `commit` without
    /// releasing whatever orders it against a withdrawal, so a withdrawal lands wholly before the
    /// check or wholly after the commit. It must not wait for anything slow while it holds that
    /// order; `commit` itself is short and never awaits.
    ///
    /// # Errors
    ///
    /// Returns the refusal the admitting authority decided, in which case `commit` did not run,
    /// or the error `commit` returned.
    fn commit(&self, commit: &mut dyn FnMut() -> CatalogueResult<()>) -> CatalogueResult<()>;

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

    fn commit(&self, commit: &mut dyn FnMut() -> CatalogueResult<()>) -> CatalogueResult<()> {
        commit()
    }

    fn owner_confirmed(&self) -> bool {
        self.confirmed
    }
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
    change: impl FnOnce(&Permit) -> CatalogueResult<T>,
) -> CatalogueResult<T> {
    let mut change = Some(change);
    let mut outcome: Option<T> = None;
    let result = authority.commit(&mut || {
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

        fn commit(&self, _commit: &mut dyn FnMut() -> CatalogueResult<()>) -> CatalogueResult<()> {
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

        fn commit(&self, commit: &mut dyn FnMut() -> CatalogueResult<()>) -> CatalogueResult<()> {
            commit()?;
            Err(CatalogueError::StorageUnavailable {
                detail: "the order could not be released".to_owned(),
            })
        }

        fn owner_confirmed(&self) -> bool {
            false
        }
    }

    #[test]
    fn a_refused_commit_runs_nothing() {
        let mut ran = false;
        let refusal = committed(&Refusing, |_permit| {
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
        let outcome = committed(&FailingAfter, |_permit| {
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
            committed(&Owner::acting(), |_permit| Ok(7)).expect("committed"),
            7
        );
        assert!(!Owner::acting().owner_confirmed());
        assert!(Owner::confirming().owner_confirmed());
    }
}
