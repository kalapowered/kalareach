//! The position that a request's barrier names, read before the request is forwarded.
//!
//! A release, a detach or a launch may carry the count of frames it must follow: the typing that
//! its sender wrote on the stream before it, which the worker's input domain checks again in the
//! same hold as the action. The host reads the barrier against its own record of the stream
//! ([`super::InputStreams::position_not_reached`]) and forwards the request unless that record
//! shows the position is not reached.
//!
//! The barrier and the request for the fenced count are members that only a worker which serves
//! typing on a lane of its own reads ([`params_for_worker`]).
//!
//! The host reads the parameters of these three requests whole, or refuses the request itself: it
//! never takes a member out of parameters that it could not read, and never judges a position from
//! parameters that it could not read.

use kr_protocol::attachment::SessionDetachParams;
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::input::{InputBarrier, InputReleaseParams};
use kr_protocol::method::Method;
use kr_protocol::root::ShellLaunchParams;

/// Reads the parameters of a request of the three methods whole, or refuses the request as an
/// argument. The refusal carries what the decoder said.
fn read_whole<T: kr_protocol::wire::WireMessage>(params: &ParamsValue) -> Result<T, ProtocolError> {
    params
        .to_typed()
        .map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
}

/// The barrier that `mutation` carries, when it is one of the three requests that can carry one and
/// it carries one.
///
/// A release's or a detach's barrier names the request's own attachment: the request orders itself
/// after its own typing. A launch's names the holder of the lease, which only the worker knows. A
/// detach that names no attachment has no subject here, and the worker, which resolves it, judges
/// the barrier against the attachment it finds.
///
/// # Errors
///
/// Refuses a request of the three methods whose parameters do not decode whole, whatever worker it
/// is for: the host cannot say what position it names, and it takes nothing out of it. Refuses a
/// release or a detach whose barrier names another attachment than its own, as an argument, with
/// nothing forwarded and no outcome left uncertain.
pub(in crate::service::net) fn barrier_of(
    mutation: &MutationRequest,
) -> Result<Option<InputBarrier>, ProtocolError> {
    let (barrier, subject) = match mutation.method.method() {
        Some(Method::InputRelease) => {
            let params = read_whole::<InputReleaseParams>(&mutation.params)?;
            (params.after_input, Some(params.attachment_id))
        }
        Some(Method::SessionDetach) => {
            let params = read_whole::<SessionDetachParams>(&mutation.params)?;
            (params.after_input, params.attachment_id.0)
        }
        Some(Method::ShellLaunch) => (
            read_whole::<ShellLaunchParams>(&mutation.params)?.after_input,
            None,
        ),
        _ => (None, None),
    };
    if let (Some(barrier), Some(subject)) = (&barrier, subject)
        && barrier.attachment_id != subject
    {
        return Err(ProtocolError::new(
            ErrorCode::InvalidArgument,
            kr_worker::input_domain::POSITION_NAMES_ANOTHER,
        ));
    }
    Ok(barrier)
}

/// What a request is told when the typing its barrier names has not all been accepted, or can no
/// longer be: the frames behind a frame that the worker refused are not sent. The request was not
/// forwarded and nothing was applied, so the sender may send it again, and a release or a detach
/// that must end is sent again with no position.
pub(in crate::service::net) fn not_reached() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::DraftConflict,
        "the typing before this request has not all arrived",
    )
}

/// The parameters of a release, a detach or a launch as the worker that will be sent them reads
/// them.
///
/// A worker that serves typing on a lane of its own (`serves_lane`) reads the barrier, and is asked
/// to report the bytes that the end of the lease discarded, on a release and on a detach, so the
/// device learns the count from the answer. Any other worker refuses a member it does not know, so
/// the members are taken out for it, and the host's own check of the position is the only one. The
/// choice is the worker's stated capability and never its level.
///
/// # Errors
///
/// The parameters are read whole before anything is set or taken out, and parameters that do not
/// decode are refused as an argument, so nothing is taken out of a request that was not read.
pub(in crate::service::net) fn params_for_worker(
    serves_lane: bool,
    method: Method,
    params: &ParamsValue,
) -> Result<ParamsValue, ProtocolError> {
    let asked_for_the_count = match method {
        Method::InputRelease => Some(ParamsValue::from_typed(&InputReleaseParams {
            fenced_report: true,
            ..read_whole(params)?
        })),
        Method::SessionDetach => Some(ParamsValue::from_typed(&SessionDetachParams {
            fenced_report: true,
            ..read_whole(params)?
        })),
        Method::ShellLaunch => {
            read_whole::<ShellLaunchParams>(params)?;
            None
        }
        _ => None,
    };
    if !serves_lane {
        return Ok(kr_protocol::retained::strip_input_lane_members(
            method, params,
        ));
    }
    match asked_for_the_count {
        Some(asked) => {
            asked.map_err(|error| ProtocolError::new(ErrorCode::InvalidArgument, error.to_string()))
        }
        None => Ok(params.clone()),
    }
}
