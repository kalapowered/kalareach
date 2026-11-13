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
use kr_protocol::ids::{AuthorityRevision, ConnectionId, RequestId};
use kr_protocol::method::Method;

use super::{Origin, Settled, may_have_taken_effect, names_a_reused_identifier};
use crate::error::ControllerError;
use crate::service::{
    Controller, EnvelopeRefused, HostWithdrawal, LeaseNotLive, SpendFailed, Unauthorised,
    error_reply, respond,
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
    /// Whether the frame is a result, or an answer that may derive from a record. A result of a
    /// method held to the local owner's lease is written only while the lease holds; a refusal
    /// that carries none is written as it is.
    carries_a_result: bool,
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
pub(crate) fn declined(declined: Declined, request_id: RequestId) -> DoorReply {
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
    DoorReply {
        frame,
        request_id,
        carries_a_result: false,
    }
}

fn refused_with(request_id: RequestId, error: &ControllerError) -> ControlFrame {
    error_reply(request_id, error.code(), error.to_string())
}

/// What a request stands on when its reply is told: the connection it arrived on, the revision of
/// the authority it was admitted under, and the request it answers.
pub(crate) struct Standing<'a> {
    controller: &'a Controller,
    connection_id: ConnectionId,
    admitted: Option<AuthorityRevision>,
    request_id: RequestId,
}

impl<'a> Standing<'a> {
    pub(crate) const fn new(
        controller: &'a Controller,
        connection_id: ConnectionId,
        admitted: Option<AuthorityRevision>,
        request_id: RequestId,
    ) -> Self {
        Self {
            controller,
            connection_id,
            admitted,
            request_id,
        }
    }
}

/// The reply to a mutation whose outcome the host holds: what a write came to, as the caller may be
/// shown it under the authority it still has.
///
/// - A copy the service withheld is not shown.
/// - A copy, which states what an earlier request or attempt did, is given only under the strict
///   check ([`Controller::check_retained_answer`]: the fence, the registration and its exact
///   revision, no deadline); otherwise it is not shown.
/// - An answer that says another request spent the identifier is given only under the strict
///   check; otherwise the check's own refusal, which is true: this request was not performed.
/// - Any other answer carries only this request's own effect. It is given while the connection's
///   registration stands and no fence is owed; otherwise it is not shown when it may have taken
///   effect, and the check's refusal when it says nothing was done.
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
    let Settled { given, withdrew } = settled;
    let origin = given.origin();
    let answer = given.into_answer();
    let Standing {
        controller,
        connection_id,
        admitted,
        request_id,
    } = *standing;
    let not_shown = || respond(request_id, Err(ControllerError::outcome_not_shown()));
    let frame = match origin {
        Origin::Withheld => not_shown(),
        Origin::Copied => match controller.check_retained_answer(connection_id, admitted) {
            Ok(()) => answer,
            Err(_) => not_shown(),
        },
        Origin::Fresh if names_a_reused_identifier(&answer) => {
            match controller.check_retained_answer(connection_id, admitted) {
                Ok(()) => answer,
                Err(refusal) => refused_with(request_id, &refusal),
            }
        }
        Origin::Fresh => {
            match own_withdrawal_or_standing(controller, connection_id, withdrew).await {
                Ok(()) => answer,
                // The check's refusal says nothing was done, which is true of a refusal and false of a
                // result, or of any word that does not say so.
                Err(_) if may_have_taken_effect(&answer) => not_shown(),
                Err(refusal) => refused_with(request_id, &refusal),
            }
        }
    };
    DoorReply {
        frame,
        request_id,
        carries_a_result: true,
    }
}

/// What a fresh answer that is not a conflict stands on: the connection's registration and no
/// fence owed, or, for a request whose own barrier withdrew the host, no fence owed and the
/// revision that barrier set still in force.
async fn own_withdrawal_or_standing(
    controller: &Controller,
    connection_id: ConnectionId,
    withdrew: Option<HostWithdrawal>,
) -> Result<(), ControllerError> {
    match withdrew {
        Some(withdrew) => {
            controller.check_fence()?;
            if controller.withdrawal_stands(&withdrew).await {
                Ok(())
            } else {
                Err(ControllerError::PermissionDenied {
                    detail: "the authority this connection was admitted under has been \
                             withdrawn; open a new connection"
                        .to_owned(),
                })
            }
        }
        None => controller
            .authorised(connection_id)
            .map_err(ControllerError::from)
            .and_then(|_| controller.check_fence()),
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
    /// A reply that carries a result is written under the local owner's lease, which is asked again
    /// before every transport write ([`Controller::write_answer`]); a refusal that carries none is
    /// written as it is.
    pub(crate) async fn write(
        self,
        controller: &Controller,
        reply: DoorReply,
        method: Option<Method>,
    ) -> bool {
        let DoorReply {
            frame,
            request_id,
            carries_a_result,
        } = reply;
        #[cfg(feature = "testing")]
        controller.note_a_reply_written(request_id, &frame);
        if carries_a_result {
            controller
                .write_answer(self.writer, self.kind, &frame, method, request_id)
                .await
        } else {
            self.writer.write_message(&frame).await.is_ok()
        }
    }
}
