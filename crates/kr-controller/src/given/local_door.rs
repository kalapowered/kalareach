//! The boundary of the local door: the one place where a mutation's outcome is told.
//!
//! A mutation is answered in one of two ways. A refusal that names no record and was made before
//! any effect is declined ([`declined`]). Everything else, an answer a service gave or a refusal
//! that may derive from a record, is told ([`told`]), and what is told is what the authority the
//! caller still has allows it to be shown. [`DoorReply`] can be made by no other function, and a
//! reply is written only by the [`ReplySink`] that consumes it, so a reply that was not asked this
//! check cannot reach the caller.

use kr_ipc::framed::FrameWriter;
use kr_protocol::envelope::{ControlFrame, Outcome, Response};
use kr_protocol::error::ErrorCode;
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::RequestId;
use kr_protocol::method::Method;

use super::{Origin, Settled, may_have_taken_effect, names_a_reused_identifier};
use crate::authority::AdmissionLapse;
use crate::error::ControllerError;
use crate::grants::policy::HeldBound;
use crate::service::{
    Ask, Controller, EnvelopeRefused, Footing, HostWithdrawal, Lapse, LeaseAsked, LeaseNotLive,
    LeasedLapse, SpendFailed, Unauthorised, error_reply, respond,
};

/// What the local door answers a mutation with, and so how the answer is written.
///
/// Its fields are private to this module: only [`told`] and [`declined`] make one.
#[must_use = "a reply reaches the caller only through the sink that writes it"]
pub(crate) struct DoorReply {
    frame: ControlFrame,
    /// The request the frame answers, for the lease's own word when the lease ends while the frame
    /// is written.
    request_id: RequestId,
    /// What a result, or an answer that may derive from a record, is written under: the question
    /// the sink asks again where the transport takes its bytes. A refusal that carries none has no
    /// such standing and is written as it is.
    written_under: Option<WrittenUnder>,
    /// Whether the daemon stops once this reply has been written: it answers a stop request whose
    /// wait for the creates under way has ended.
    stops_the_daemon: bool,
}

/// What a frame is written under: the footing of the request it answers, the question that is asked
/// of it again where the transport takes its bytes, and in whose words a frame that question stops
/// is replaced.
///
/// The writer asks the question after its last wait, immediately before every transport write, and
/// the reply in place of a frame it stopped comes from the member that refused at that ask: no
/// further ask follows it.
#[derive(Clone)]
pub(crate) struct WrittenUnder {
    footing: Footing,
    ask: Ask,
    words: Words,
    /// What a list that was decided under the local owner's lease is replaced by where that lease
    /// has ended when the writer asks.
    instead: Option<Instead>,
}

/// What a list is replaced by where the local owner's lease ended after the list was decided under
/// it: the same list under the scope that no lease serves, and the bound of the lease the list was
/// decided under.
///
/// The list and its replacement are made from the same entries by one function before any
/// question is asked ([`Listed`](crate::service::net::owner::Listed)). The writer chooses between
/// them with the footing's question asked with this bound and with nothing else: the replacement is
/// written as it was prepared.
#[derive(Clone)]
pub(crate) struct Instead {
    frame: ControlFrame,
    bound: HeldBound,
}

impl Instead {
    /// The replacement `frame` for a list decided under `bound`.
    pub(crate) const fn new(frame: ControlFrame, bound: HeldBound) -> Self {
        Self { frame, bound }
    }
}

/// In whose words a frame that the writer's last question stopped is replaced.
#[derive(Clone, Copy, Debug)]
enum Words {
    /// A read's answer, or an attention read's release: a registration that has gone is refused in
    /// the words of the door's own check of the registration.
    Read,
    /// A mutation's reply that carries only what the request itself did: not shown where the door
    /// found that the request took effect or may have, and the refusal of the member that refused
    /// where it says nothing was done. The door's verdict is `taken_effect`: the writer does not
    /// make it again from the frame, whose code can say that nothing was done of a request that
    /// first changed something.
    OwnEffect { taken_effect: bool },
    /// A reply read from a record: the refusal of the member that refused for a reply that says
    /// another request spent the identifier of this one (that request had no effect of its own),
    /// and the outcome that is not shown for a copy of what an earlier request did.
    Record { conflict: bool },
}

impl WrittenUnder {
    /// The standing of a read's answer: the registration and the lease.
    pub(crate) const fn of_a_read(footing: Footing) -> Self {
        Self {
            footing,
            ask: Ask::READ,
            words: Words::Read,
            instead: None,
        }
    }

    /// The standing of a mutation's reply that carries only what the request did: the registration
    /// and the lease, and no fence, since the door told it while no fence was owed. `taken_effect`
    /// is the door's verdict that the request took effect or may have.
    const fn of_an_own_effect(footing: Footing, taken_effect: bool) -> Self {
        Self {
            footing,
            ask: Ask::READ,
            words: Words::OwnEffect { taken_effect },
            instead: None,
        }
    }

    /// As [`Self::of_an_own_effect`], for the reply of a request whose own barrier withdrew every
    /// connection of the host, its own included: the registration is gone by the request's own
    /// doing, so what is asked is that no fence is owed and no later barrier has moved the
    /// revision that withdrawal set, and the lease.
    const fn of_an_own_withdrawal(
        footing: Footing,
        withdrew: &HostWithdrawal,
        taken_effect: bool,
    ) -> Self {
        Self {
            footing,
            ask: withdrew.ask().and_the_lease(),
            words: Words::OwnEffect { taken_effect },
            instead: None,
        }
    }

    /// The standing of a reply read from a record: the registration at the revision the request
    /// was admitted under, the fence, and the lease. `conflict` says the reply is that another
    /// request spent the identifier.
    const fn of_a_record(footing: Footing, conflict: bool) -> Self {
        Self {
            footing,
            ask: Ask::KEPT_ANSWER.and_the_lease(),
            words: Words::Record { conflict },
            instead: None,
        }
    }

    /// The standing of a reply read from a record, for a case that writes a reply by itself.
    #[cfg(test)]
    pub(crate) const fn for_a_record_case(footing: Footing, conflict: bool) -> Self {
        Self::of_a_record(footing, conflict)
    }

    /// The standing of a mutation's own reply, for a case that writes a reply by itself.
    #[cfg(test)]
    pub(crate) const fn for_an_own_effect_case(footing: Footing, taken_effect: bool) -> Self {
        Self::of_an_own_effect(footing, taken_effect)
    }

    /// This standing for a list that `instead` replaces where the lease it was decided under has
    /// ended.
    pub(crate) fn listing(mut self, instead: Option<Instead>) -> Self {
        self.instead = instead;
        self
    }

    /// The frame that replaces the list where the lease ended.
    pub(crate) fn instead(&self) -> Option<&ControlFrame> {
        self.instead.as_ref().map(|instead| &instead.frame)
    }

    /// The question, for a lease whose reading found `bound`: no lock is taken, nothing is awaited
    /// and nothing is written ([`Footing::ask`]). What it was asked with is returned, and the
    /// writer lets it go after the transport's write: the bound's last reference can free memory.
    ///
    /// # Errors
    ///
    /// Returns the member that refuses, and a bound that moved as itself.
    pub(crate) fn asked_holding(
        &self,
        bound: Option<HeldBound>,
    ) -> Result<LeaseAsked, LeasedLapse> {
        // A list decided under a lease is asked with the bound it was decided under where the
        // writer's own reading of the lease found none.
        let carried = bound.is_none();
        let bound = bound.or_else(|| self.instead.as_ref().map(|instead| instead.bound.clone()));
        match bound {
            Some(bound) => {
                let leased = self.footing.clone().holding(bound);
                match leased.ask(self.ask) {
                    Ok(()) => Ok(LeaseAsked::with(leased)),
                    // The lease was presented again: the list was decided under a lease that is
                    // not the one that stands, which is an ended lease's.
                    Err(LeasedLapse::BoundMoved) if carried => {
                        Err(LeasedLapse::Lapse(Lapse::LeaseEnded))
                    }
                    Err(lapse) => Err(lapse),
                }
            }
            None => {
                self.footing.ask(self.ask)?;
                Ok(LeaseAsked::default())
            }
        }
    }

    /// What is written in place of a frame that the last question stopped, for the member `lapse`
    /// that refused it.
    ///
    /// `lease_ended` is the reply of a lease that ended. Whether the frame stands for an effect is
    /// what the door found when it made this standing, never read again from the frame.
    pub(crate) fn withheld(
        &self,
        lapse: Lapse,
        request_id: RequestId,
        lease_ended: impl FnOnce() -> ControlFrame,
    ) -> ControlFrame {
        if lapse == Lapse::LeaseEnded {
            return lease_ended();
        }
        let not_shown = || respond(request_id, Err(ControllerError::outcome_not_shown()));
        match self.words {
            Words::Record { conflict: false } | Words::OwnEffect { taken_effect: true } => {
                not_shown()
            }
            Words::Record { conflict: true }
            | Words::OwnEffect {
                taken_effect: false,
            }
            | Words::Read => {
                refused_with(request_id, &refusal_of(&self.footing, self.words, lapse))
            }
        }
    }
}

/// The refusal of the member `lapse` that refused, in the words of the door's own check for that
/// condition. A registration that has gone is refused in the words of the registration check that
/// the door asks, which is the reply's own except for a reply read from a record, whose check is
/// the kept answer's.
fn refusal_of(footing: &Footing, words: Words, lapse: Lapse) -> ControllerError {
    let registration_gone = || Lapse::Withdrawn.refusal();
    match lapse {
        Lapse::Admission(AdmissionLapse::Deregistered)
            if !matches!(words, Words::Record { .. }) || footing.connection_id().is_none() =>
        {
            registration_gone()
        }
        Lapse::Admission(AdmissionLapse::Revoked | AdmissionLapse::Expired)
            if footing.connection_id().is_none() =>
        {
            registration_gone()
        }
        lapse => lapse.refusal(),
    }
}

impl DoorReply {
    /// The frame, whichever it is, for a case that reads what the door answered.
    #[cfg(test)]
    pub(crate) fn into_frame(self) -> ControlFrame {
        self.frame
    }
}

/// A refusal that names no record and was made before any effect. One variant for each exit; each
/// payload is a type that only its own gate can make: a private field in the gate's own module,
/// and no conversion from a [`ControllerError`].
pub(crate) enum Declined {
    /// The connection's registration was withdrawn (made by `Controller::authorised`).
    Unauthorised(Unauthorised),
    /// The method is not in the registry.
    NotInRegistry,
    /// The local owner's membership lease is not live (made by `Controller::local_hold`).
    Lease(LeaseNotLive),
    /// The envelope, or the window it carries, refuses the mutation (made by
    /// `Controller::check_envelope`).
    Envelope(EnvelopeRefused),
    /// The identifier could not be looked for (made by `Controller::spend_the_identifier`).
    Spend(SpendFailed),
    /// A mutation arrived on a stream of the wrong kind.
    WrongEndpoint,
}

/// The reply to a request that is declined: nothing is withheld, and the refusal is written as it
/// is.
#[cfg_attr(not(feature = "testing"), allow(unused_variables))]
pub(crate) fn declined(
    controller: &Controller,
    declined: Declined,
    request_id: RequestId,
) -> DoorReply {
    let frame = match declined {
        Declined::Unauthorised(refusal) => {
            error_reply(request_id, ErrorCode::PermissionDenied, refusal.to_string())
        }
        Declined::NotInRegistry => error_reply(
            request_id,
            ErrorCode::PermissionDenied,
            "the method is not in the registry",
        ),
        Declined::Lease(refusal) => refused_with(request_id, &ControllerError::from(refusal)),
        Declined::Envelope(refusal) => ControlFrame::Response(Response {
            request_id,
            outcome: Outcome::Error(ControllerError::from(refusal).to_protocol_error()),
        }),
        Declined::Spend(refusal) => refused_with(request_id, &ControllerError::from(refusal)),
        Declined::WrongEndpoint => error_reply(
            request_id,
            ErrorCode::PermissionDenied,
            crate::transfer::WRONG_ENDPOINT,
        ),
    };
    #[cfg(feature = "testing")]
    controller.note_a_reply_made(request_id, false, &frame);
    DoorReply {
        frame,
        request_id,
        written_under: None,
        stops_the_daemon: false,
    }
}

fn refused_with(request_id: RequestId, error: &ControllerError) -> ControlFrame {
    error_reply(request_id, error.code(), error.to_string())
}

/// What a request stands on when its reply is told: the footing it was admitted under, made once at
/// the door in the same read as the revision of the authority it was admitted under, and the
/// request it answers.
pub(crate) struct Standing<'a> {
    controller: &'a Controller,
    footing: Footing,
    request_id: RequestId,
}

impl<'a> Standing<'a> {
    pub(crate) const fn new(
        controller: &'a Controller,
        footing: Footing,
        request_id: RequestId,
    ) -> Self {
        Self {
            controller,
            footing,
            request_id,
        }
    }
}

/// The reply to a mutation whose outcome the host holds: what a write came to, as the caller may be
/// shown it under the authority it still has. Each ask below is the footing's one question, which
/// reads no lock; the writer asks it again after its last wait ([`WrittenUnder`]), and that ask is
/// not this one made twice: it is the one that decides what reaches the transport.
///
/// - A copy the service withheld is not shown.
/// - A copy, which states what an earlier request or attempt did, is given only while the kept
///   answer's question holds ([`Ask::KEPT_ANSWER`]: the fence, the revision the request was
///   admitted under and the registration, no deadline); otherwise it is not shown.
/// - An answer that says another request spent the identifier is given only under the same
///   question; otherwise the refusal of the member that refused, which is true: this request was
///   not performed.
/// - Any other answer carries only this request's own effect. It is given while the connection's
///   registration stands and no fence is owed ([`Ask::FRESH_REPLY`]); otherwise it is not shown
///   when it may have taken effect, and the refusal of the member that refused when it says nothing
///   was done. A refusal made after the request had changed something does not say that: it is
///   not shown whatever its code is, here and where the writer's last question stops it.
/// - The same, when the request's own effect raised the barrier that withdrew every connection of
///   the host, its own included ([`HostWithdrawal`]): the registration is then gone by the
///   request's own doing, so the answer is given while no fence is owed and no later barrier has
///   moved the revision that withdrawal set.
///
/// "Not shown" is `OUTCOME_UNKNOWN`. Every reply made here may be a result, so it is written under
/// the local owner's lease.
pub(crate) async fn told(settled: Settled<ControlFrame>, standing: &Standing<'_>) -> DoorReply {
    #[cfg(feature = "testing")]
    standing.controller.stop_before_a_reply_is_told().await;
    let Settled {
        given,
        withdrew,
        stops_after_the_answer,
    } = settled;
    let origin = given.origin();
    let answer = given.into_answer();
    let Standing {
        controller,
        footing,
        request_id,
    } = standing;
    let request_id = *request_id;
    let not_shown = || respond(request_id, Err(ControllerError::outcome_not_shown()));
    // Whether the request took effect, or may have: the writer is handed this verdict and does not
    // make it again from the frame, whose code can say that nothing was done of a request that
    // first changed something.
    let taken_effect = match origin {
        Origin::Withheld | Origin::Copied | Origin::AfterAnEffect => true,
        Origin::Fresh => may_have_taken_effect(&answer),
    };
    // What the frame is written under: a reply read from a record that passes the kept answer's
    // question is written under that question again, and any other under the request's own.
    let mut written_under = match &withdrew {
        Some(withdrew) => {
            WrittenUnder::of_an_own_withdrawal(footing.clone(), withdrew, taken_effect)
        }
        None => WrittenUnder::of_an_own_effect(footing.clone(), taken_effect),
    };
    let frame = match origin {
        Origin::Withheld => not_shown(),
        Origin::Copied => match footing.ask(Ask::KEPT_ANSWER) {
            Ok(()) => {
                written_under = WrittenUnder::of_a_record(footing.clone(), false);
                answer
            }
            Err(_) => not_shown(),
        },
        Origin::Fresh if names_a_reused_identifier(&answer) => {
            match footing.ask(Ask::KEPT_ANSWER) {
                Ok(()) => {
                    written_under = WrittenUnder::of_a_record(footing.clone(), true);
                    answer
                }
                Err(lapse) => refused_with(
                    request_id,
                    &refusal_of(footing, Words::Record { conflict: true }, lapse),
                ),
            }
        }
        // The refusal says what was done before it, and under authority that no longer stands
        // that is not shown, whatever the check's own refusal would say of nothing having been done.
        Origin::AfterAnEffect => {
            match own_withdrawal_or_standing(controller, footing, withdrew.as_ref()) {
                Ok(()) => answer,
                Err(_) => not_shown(),
            }
        }
        Origin::Fresh => {
            match own_withdrawal_or_standing(controller, footing, withdrew.as_ref()) {
                Ok(()) => answer,
                // The check's refusal says nothing was done, which is true of a refusal and false of a
                // result, or of any word that does not say so.
                Err(_) if taken_effect => not_shown(),
                Err(refusal) => refused_with(request_id, &refusal),
            }
        }
    };
    #[cfg(feature = "testing")]
    controller.note_a_reply_made(request_id, true, &frame);
    DoorReply {
        frame,
        request_id,
        written_under: Some(written_under),
        stops_the_daemon: stops_after_the_answer,
    }
}

/// What a fresh answer that is not a conflict stands on: the connection's registration and no
/// fence owed, or, for a request whose own barrier withdrew the host, no fence owed and the
/// revision that barrier set still in force.
fn own_withdrawal_or_standing(
    controller: &Controller,
    footing: &Footing,
    withdrew: Option<&HostWithdrawal>,
) -> Result<(), ControllerError> {
    match withdrew {
        Some(withdrew) => controller.withdrawal_stands(withdrew),
        None => footing.ask(Ask::FRESH_REPLY).map_err(|lapse| {
            refusal_of(
                footing,
                Words::OwnEffect {
                    taken_effect: false,
                },
                lapse,
            )
        }),
    }
}

/// The one way a mutation's reply is written to a local connection.
///
/// It holds the connection's writer privately and has one writing operation, which consumes the
/// reply: a connection's loop that serves a mutation holds no writer of its own to write another
/// frame with.
pub(crate) struct ReplySink<'a> {
    writer: &'a mut FrameWriter,
    kind: StreamKind,
}

impl<'a> ReplySink<'a> {
    pub(crate) fn new(writer: &'a mut FrameWriter, kind: StreamKind) -> Self {
        Self { writer, kind }
    }

    /// The kind of stream the connection is, for a mutation that arrived on the wrong one.
    pub(crate) const fn kind(&self) -> StreamKind {
        self.kind
    }

    /// Writes `reply` as the answer to a request for `method`, and says whether the connection goes
    /// on.
    ///
    /// A reply that carries a result is written under the local owner's lease and the footing of
    /// its request, which are asked again before every transport write
    /// ([`Controller::write_answer`]); a refusal that carries none is written as it is. The reply
    /// to a stop request whose wait has ended is written under a bound
    /// instead, and the daemon is told to stop after it
    /// ([`Controller::write_the_answer_of_a_stop`]).
    pub(crate) async fn write(
        self,
        controller: &Controller,
        reply: DoorReply,
        method: Option<Method>,
    ) -> bool {
        let DoorReply {
            frame,
            request_id,
            written_under,
            stops_the_daemon,
        } = reply;
        #[cfg(feature = "testing")]
        controller.note_a_reply_written(request_id, &frame);
        if stops_the_daemon {
            return controller
                .write_the_answer_of_a_stop(self.writer, self.kind, &frame)
                .await;
        }
        if let Some(written_under) = written_under {
            controller
                .write_answer(
                    self.writer,
                    self.kind,
                    &frame,
                    method,
                    request_id,
                    &written_under,
                )
                .await
        } else {
            self.writer.write_message(&frame).await.is_ok()
        }
    }
}
