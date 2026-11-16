//! The checks of a mutation's admission that change nothing, in one place.
//!
//! A mutation is admitted once and dispatched later, and what was true of its caller at the first
//! moment is asked again at the second. The checks that change no state of the authority or of
//! the receipt (the authority, the validated revision, the local owner's access, the envelope, the
//! uncertain outcome in the way, the subject's preconditions, the dispatch lease, the accepted
//! deadline and the broker's own admission) are written here as the four pieces of one function,
//! so that the first admission and every later ask of it put the same question and cannot drift
//! apart.
//!
//! # The pieces
//!
//! * **A** (`authority`): the authority, the validated revision and, in a pass that asks again,
//!   the local owner's access as a comparison that changes nothing.
//! * **B1** (`envelope` and `limits`): the envelope of the request, and the uncertain outcome that
//!   stands in the way together with the actor's outstanding limit. The first admission asks both
//!   before anything is written; a pass that asks again asks the second alone, under the session
//!   that reaches the accept.
//! * **B2** (`subject`): the request's parameters against the session, and the preconditions its
//!   caller stated.
//! * **C** (`dispatch`): the dispatch lease, the accepted deadline and the broker's admission.
//!
//! # What stays outside
//!
//! The first admission's own work stands outside the pieces: the local owner's full check (which
//! raises the host's clock floor, owes its record and keeps the readings), the session's take for
//! the envelope, and the note of a journal that could not answer the limits' reads, which the
//! limits hand back and the first admission makes. A piece reads the clock only through the pure
//! readers of the time contract.
//!
//! # What a piece writes
//!
//! No piece notes a fault and none writes a receipt. Three writes are made inside the pieces, each
//! as at the base:
//!
//! * `subject`, in the first mode, runs the expiry sweep of the questions (through `validate`)
//!   before it reads the question a method names, so a question that is due or whose binding
//!   moved is `expired` by the time the check refuses it;
//! * a journal that fails a read of the limits records the fault itself, inside the read;
//! * `dispatch`, for a mutation the broker owns, takes the broker's claim, its permit and its
//!   token (`decidable`), which is the admission itself: a second pass cannot run it again.

use super::{
    Caller, ConnectionFacts, ConnectionState, ContinuousInstant, Made, Method, MutationRequest,
    Prepared, Result, Session, WorkerService,
};

/// Whether a pass is the first admission's or a later one's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mode {
    /// The first admission: its refusals are plain errors, and it makes the work that changes
    /// something (the sweep of the questions, the note of a failed journal).
    First,
    /// A pass that asks again, after a wait and before an effect: it changes nothing.
    Again,
}

impl Mode {
    /// Whether this pass runs the expiry sweep of the questions inside its check of the subject.
    const fn question_sweep(self) -> Sweep {
        match self {
            Self::First => Sweep::Run,
            Self::Again => Sweep::Never,
        }
    }
}

/// Whether a check of the subject expires the questions that are due before it reads them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Sweep {
    /// Expire what is due first, as the first admission does.
    Run,
    /// Read the questions as they stand.
    Never,
}

/// What the first admission read of the person's view of a receipt, kept so that a later pass puts
/// the same question to the same value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ShownAtAdmission(pub(super) Option<u64>);

/// What the limits read, for the pass's caller.
pub(super) struct Limited {
    /// What the person was shown, kept so that a later pass puts the same question to the same
    /// value.
    pub(super) shown: ShownAtAdmission,
    /// The failure of a journal read that the method goes on without, which the first admission
    /// notes for the session. The pass writes no note.
    pub(super) unreadable: Option<String>,
}

/// One pass of the standing function, in one mode.
pub(super) struct StandingPass<'a> {
    service: &'a WorkerService,
    mode: Mode,
}

impl WorkerService {
    /// Starts a pass of the standing function in `mode`.
    pub(super) const fn standing_pass(&self, mode: Mode) -> StandingPass<'_> {
        StandingPass {
            service: self,
            mode,
        }
    }
}

impl StandingPass<'_> {
    /// Piece A: the authority the request was admitted under.
    ///
    /// The first admission's local owner check is the full one, which raises the host's clock
    /// floor and owes its record, so the first admission makes it itself, after this piece, and
    /// lays the caller's end again from what it returns. A pass that asks again compares the
    /// owner's access without a change.
    ///
    /// # Errors
    ///
    /// Returns what the check that refused returns.
    pub(super) fn authority(
        &self,
        facts: &ConnectionFacts,
        caller: &Caller,
        method: Method,
    ) -> Result<()> {
        let service = self.service;
        service.check_authority(facts)?;
        service.check_validated_revision(caller)?;
        match self.mode {
            Mode::First => Ok(()),
            Mode::Again => service.check_local_standing(facts, method, caller),
        }
    }

    /// Piece B1, the envelope: the target the worker will act on, the grant the caller claims and
    /// the resources the method names.
    ///
    /// # Errors
    ///
    /// Returns what the check that refused returns.
    pub(super) fn envelope(
        &self,
        session: &Session,
        mutation: &MutationRequest,
        entry: &'static kr_protocol::authority::MethodEntry,
        caller: &Caller,
    ) -> Result<()> {
        self.service
            .check_envelope(session, mutation, entry, caller)
    }

    /// Piece B1, the limits: the uncertain outcome that stands in the way of a fresh identifier,
    /// and the actor's outstanding mutations.
    ///
    /// The first admission takes the session for its reads. A pass that asks again is given the
    /// session that stands between it and the accept, and the value of what the person was shown
    /// that the first admission read. It writes no receipt when it refuses.
    ///
    /// # Errors
    ///
    /// Returns what the check that refused returns.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn limits(
        &self,
        held: Option<&mut Session>,
        caller: &Caller,
        state: &ConnectionState,
        mutation: &MutationRequest,
        method: Method,
        subject: kr_protocol::scalars::Digest256,
        shown: Option<ShownAtAdmission>,
    ) -> Result<Limited> {
        self.service
            .check_admission_limits(held, caller, state, mutation, method, subject, shown)
    }

    /// Piece B2: the request's parameters against the session, and the preconditions the caller
    /// stated.
    ///
    /// # Errors
    ///
    /// Returns what the check that refused returns.
    pub(super) fn subject(
        &self,
        session: &Session,
        state: &ConnectionState,
        mutation: &MutationRequest,
        method: Method,
        caller: &Caller,
    ) -> Result<()> {
        self.service.validate(
            session,
            state,
            mutation,
            method,
            caller,
            self.mode.question_sweep(),
        )?;
        WorkerService::check_preconditions(session, mutation)
    }

    /// Piece C: the remote dispatch lease, the accepted deadline and what the effect itself would
    /// have refused. For a mutation the broker owns, what comes back is the admission itself.
    ///
    /// # Errors
    ///
    /// Returns what the check that refused returns.
    pub(super) fn dispatch(
        &self,
        session: &Session,
        mutation: &MutationRequest,
        method: Method,
        caller: &Caller,
        deadline: ContinuousInstant,
        preparation: Option<Made>,
    ) -> Result<Option<Prepared>> {
        let service = self.service;
        service.check_dispatch_lease(caller, method)?;
        service.check_accepted_deadline(deadline)?;
        service.decidable(session, mutation, method, caller, preparation)
    }
}
