//! What the doors hand an owner's mutation so that the records it lands ask its standing in the
//! order the rule asks.
//!
//! The record of an owner's request and the record of its answer land in one transaction of the
//! pairing records. After the last wait before the write, the landing asks the question of the
//! mutation's footing, and nothing is allocated or awaited between that question and the write.
//! The authority feed's refusal is asked first, where it takes its locks, and again with no lock
//! immediately before the write: it moves no revision, so the footing's question does not see it.
//!
//! A [`Landing`] is what a door gives the caller of such a mutation: the feed's ask, the footing
//! made once at the door, and the held bound of the local owner's lease. The same parts give the
//! admission of the pairing methods that ask their standing inside their own writes
//! ([`Landing::admission`]), so the two cannot disagree.

use std::sync::Arc;

use kr_protocol::ids::{AuthorityRevision, ConnectionId};
use kr_transport::clock::ContinuousInstant;

use super::invitations::Admission;
use crate::authority::{AdmissionLapse, AdmittedMutation};
use crate::error::{ControllerError, Result};
use crate::grants::policy::HeldBound;
use crate::service::Controller;
use crate::service::admission::ConnectionGrants;
use crate::service::footing::{Ask, CopiedBound, Footing, Lapse, LeasedFooting, LeasedLapse};

/// The standing an owner's mutation carries to the records it lands.
#[derive(Clone)]
pub(crate) struct Landing {
    /// The daemon the mutation was admitted by, which holds the authority feed's refusal. A
    /// landing made for a pairing store's own case has none, and the feed asks nothing of it.
    daemon: Option<Arc<Controller>>,
    /// The connection the mutation arrived on, whose grants the feed's refusal is asked of.
    connection_id: ConnectionId,
    /// The footing of the mutation, made once at the door, or why there is none.
    standing: std::result::Result<Standing, AdmissionLapse>,
}

/// The footing of a mutation, and the same footing holding the bound of the local owner's lease
/// where the caller was decided under one.
#[derive(Clone)]
struct Standing {
    footing: Footing,
    leased: Option<LeasedFooting>,
}

impl std::fmt::Debug for Landing {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Landing")
            .field("connection_id", &self.connection_id)
            .field("standing", &self.standing.as_ref().map(|_| ()))
            .finish_non_exhaustive()
    }
}

/// The grants the authority feed's refusal was asked of where it takes its locks, kept for the
/// second ask that takes none ([`Landing::feed_still_clear`]).
pub(crate) struct Kept(Option<ConnectionGrants>);

/// The refusal a caller that no door gave a landing is told: the words of a mutation that carries
/// no freshness, which may be answered from what this host holds and may not write.
pub(crate) fn no_landing() -> ControllerError {
    ControllerError::WindowExpired {
        detail: "this action carries no freshness, so it may be answered from what this host \
                 holds and may not write"
            .to_owned(),
    }
}

impl Landing {
    /// This landing, holding `bound`, the bound of the local owner's lease that the caller was
    /// decided under, and none where that decision found none to hold.
    #[must_use]
    pub(crate) fn holding(mut self, bound: Option<HeldBound>) -> Self {
        if let Ok(standing) = &mut self.standing {
            standing.leased = bound.map(|bound| standing.footing.clone().holding(bound));
        }
        self
    }

    /// The admission of the pairing methods that ask their standing inside their own writes: the
    /// fence this host owes, the authority feed's refusal and the footing's question, from the
    /// parts the landing holds.
    pub(crate) fn admission(&self) -> Admission {
        let landing = self.clone();
        Arc::new(move || landing.admit())
    }

    /// The admission's one asking.
    fn admit(&self) -> Result<()> {
        if let Some(daemon) = &self.daemon {
            daemon.check_fence()?;
        }
        let standing = self.standing_or_refusal()?;
        self.asks_the_feed()?;
        // The feed's check took the connection's shares lock, and what lands while it waited is
        // read here, after that lock, as the last reading of the check: the footing's one question
        // takes no lock, so nothing can be waited for after it.
        #[cfg(feature = "testing")]
        if let Some(daemon) = &self.daemon {
            daemon.before_the_last_fence_read.wait();
        }
        standing.footing.stands(Ask::MUTATION)
    }

    fn standing_or_refusal(&self) -> Result<&Standing> {
        self.standing
            .as_ref()
            .map_err(|lapse| crate::service::footing::admission_refusal(*lapse))
    }

    /// The authority feed's refusal, asked where it takes its locks: the connection table's read
    /// lock and the connection's shares lock, which a withdrawal or a commit can hold. It is the
    /// last ask of a landing that takes a lock. The grants it was asked of are copied and kept for
    /// [`Self::feed_still_clear`].
    ///
    /// # Errors
    ///
    /// Returns the refusal the feed puts on the connection's grants.
    pub(crate) fn asks_the_feed(&self) -> Result<Kept> {
        let Some(daemon) = &self.daemon else {
            return Ok(Kept(None));
        };
        let grants = daemon.feed_grants_on(self.connection_id);
        let refused = grants
            .as_ref()
            .and_then(|grants| daemon.feed_refusal_in(grants));
        // The last wait of a record: where this host's own tests stop it, after the locks of the
        // ask have been taken and let go, and before anything that follows the ask is read.
        #[cfg(feature = "testing")]
        daemon.after_the_record_asks_the_feed.wait();
        match refused {
            Some(refusal) => Err(ControllerError::PermissionDenied {
                detail: refusal.detail(),
            }),
            None => Ok(Kept(grants)),
        }
    }

    /// The feed's refusal asked again of the kept grants, with no lock: it reads one atomic word.
    /// A refusal that rose in the waits since the first ask stops the landing here, which is
    /// immediately before the write it guards.
    ///
    /// # Errors
    ///
    /// Returns the refusal the feed puts on the connection's grants.
    pub(crate) fn feed_still_clear(&self, kept: &Kept) -> Result<()> {
        let (Some(daemon), Some(grants)) = (&self.daemon, &kept.0) else {
            return Ok(());
        };
        match daemon.feed_refusal_in(grants) {
            Some(refusal) => Err(ControllerError::PermissionDenied {
                detail: refusal.detail(),
            }),
            None => Ok(()),
        }
    }

    /// Where this host's own tests stop a record before its transaction begins.
    #[cfg(feature = "testing")]
    pub(crate) fn waits_before_the_record_begins(&self) {
        if let Some(daemon) = &self.daemon {
            daemon.before_the_record_begins.wait();
        }
    }

    /// The copy of the held bound's cell that the question compares. It is taken after the feed's
    /// locked ask and before the question: loading a cell can allocate, and the question after it
    /// allocates nothing.
    #[must_use]
    pub(crate) fn copies_the_bound(&self) -> CopiedBound {
        match &self.standing {
            Ok(Standing {
                leased: Some(leased),
                ..
            }) => leased.copy(Ask::MUTATION),
            _ => CopiedBound::NONE,
        }
    }

    /// The footing's one question, with the bound copied by [`Self::copies_the_bound`]: the fence,
    /// the revision, the registration's latch, the deadline and the bound. It reads atomics and
    /// clocks alone.
    ///
    /// # Errors
    ///
    /// Returns the member that refuses, and the bound that moved as itself.
    pub(crate) fn asks(&self, copied: &CopiedBound) -> std::result::Result<(), LeasedLapse> {
        match &self.standing {
            Err(lapse) => Err(LeasedLapse::Lapse(Lapse::Admission(*lapse))),
            Ok(Standing {
                leased: Some(leased),
                ..
            }) => leased.ask_copied(Ask::MUTATION, copied),
            Ok(Standing {
                footing,
                leased: None,
            }) => footing.ask(Ask::MUTATION).map_err(LeasedLapse::from),
        }
    }
}

impl Controller {
    /// The landing of one owner mutation, made once at its door from the connection it arrived
    /// on, the revision it was admitted under and the deadline it was accepted with: the feed's
    /// ask, the footing, and no bound yet, which the caller's own decision adds.
    ///
    /// A mutation that carries no freshness at all may be answered from what this host already
    /// holds and may not write, so it has no landing.
    pub(crate) fn pairing_landing(
        self: &Arc<Self>,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
        deadline: Option<ContinuousInstant>,
    ) -> Option<Landing> {
        let (Some(admitted_revision), Some(deadline)) = (admitted, deadline) else {
            return None;
        };
        let carried = AdmittedMutation {
            connection_id,
            admitted_revision,
            deadline: Some(deadline),
        };
        Some(Landing {
            daemon: Some(Arc::clone(self)),
            connection_id,
            standing: self
                .footing_of_a_mutation(&carried)
                .map(|footing| Standing {
                    footing,
                    leased: None,
                }),
        })
    }
}

#[cfg(feature = "testing")]
impl Landing {
    /// A landing that stands for ever and asks no feed, for the pairing store's own cases, which
    /// run no daemon.
    pub(crate) fn standing_for_ever() -> Self {
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        Self {
            daemon: None,
            connection_id,
            standing: Ok(Standing {
                footing: Footing::admitted(
                    Arc::new(crate::service::footing::Copies::standing_for_ever()),
                    connection_id,
                    AuthorityRevision::new(0),
                    None,
                    None,
                ),
                leased: None,
            }),
        }
    }
}
