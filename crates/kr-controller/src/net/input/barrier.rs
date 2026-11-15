//! The position that a request's barrier names, read before the request is forwarded.
//!
//! A release, a detach or a launch may carry the count of frames it must follow: the typing that
//! its sender wrote on the stream before it, which the worker's input domain checks again in the
//! same hold as the action. The host reads the barrier against its own record of the stream
//! ([`super::InputStreams::position_not_reached`]) and forwards the request unless that record
//! shows the position is not reached.

use kr_protocol::attachment::SessionDetachParams;
use kr_protocol::envelope::MutationRequest;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::input::{InputBarrier, InputReleaseParams};
use kr_protocol::method::Method;
use kr_protocol::root::ShellLaunchParams;

/// The barrier that `mutation` carries, when it is one of the three requests that can carry one and
/// it carries one. Parameters that cannot be read name no barrier: the worker refuses them.
pub(in crate::service::net) fn barrier_of(mutation: &MutationRequest) -> Option<InputBarrier> {
    match mutation.method.method()? {
        Method::InputRelease => {
            mutation
                .params
                .to_typed::<InputReleaseParams>()
                .ok()?
                .after_input
        }
        Method::SessionDetach => {
            mutation
                .params
                .to_typed::<SessionDetachParams>()
                .ok()?
                .after_input
        }
        Method::ShellLaunch => {
            mutation
                .params
                .to_typed::<ShellLaunchParams>()
                .ok()?
                .after_input
        }
        _ => None,
    }
}

/// What a request is told when the typing its barrier names has not all been accepted. The request
/// was not forwarded and nothing was applied, so the sender may send it again.
pub(in crate::service::net) fn not_reached() -> ProtocolError {
    ProtocolError::new(
        ErrorCode::DraftConflict,
        "the typing before this request has not all arrived",
    )
}
