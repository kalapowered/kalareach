//! The bounded pre-authorisation pairing surface.
//!
//! Section 23: an unpaired connection has only the bounded pre-authorisation pairing surface
//! explicitly listed in section 10. It negotiates framing and version but cannot pass ordinary
//! device authorisation or reach session streams until pairing commits. This exception is not an
//! unauthenticated ordinary control channel, so everything about the surface is narrow on purpose:
//!
//! * three methods, `pair.redeem`, `pair.finish` and `pair.status`, and the registry refuses every
//!   other name at this ingress;
//! * frames far below the control limit, because a pairing message is small and an unpaired peer
//!   should not be able to make the host reserve a megabyte;
//! * a request budget per connection and a rate limit inside it, so an endpoint cannot grind
//!   through attempts by reconnecting or by flooding one connection;
//! * no mutation in 0-RTT, which [`crate::actor::ConnectionActor`] enforces, leaving only
//!   `pair.status` reachable as early data.
//!
//! Pairing's own budgets, phase rules and proofs are not here. They belong to the pairing crate,
//! which implements [`PairingSurface`]; this module is the door, not the ceremony behind it.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::envelope::{Outcome, ParamsValue, Request, Response};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration};
use kr_protocol::method::Method;
use kr_protocol::scalars::EndpointKey;

use crate::actor::ConnectionActor;
use crate::clock::{ContinuousClock, ContinuousInstant};
use crate::error::Result;
use crate::handshake::UnpairedConnection;

/// The largest pre-authorisation frame, in bytes.
///
/// A pairing message carries a bundle, a transcript and a signature or two. Eight kibibytes is
/// generous for that and two orders of magnitude below the control limit an authorised connection
/// gets.
pub const MAX_PREAUTH_FRAME_LEN: usize = 8 * 1024;

/// What an unpaired connection is allowed to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreAuthLimits {
    /// Total requests one unpaired connection may make.
    pub max_requests: usize,
    /// Requests allowed inside one rate window.
    pub max_requests_per_window: usize,
    /// The rate window.
    pub window: Duration,
    /// The largest request frame accepted.
    pub max_frame_len: usize,
}

impl Default for PreAuthLimits {
    fn default() -> Self {
        Self {
            // A pairing exchange is redeem, finish and a handful of status polls. Sixteen leaves
            // room for a retry without leaving room for a campaign.
            max_requests: 16,
            max_requests_per_window: 4,
            window: Duration::from_secs(10),
            max_frame_len: MAX_PREAUTH_FRAME_LEN,
        }
    }
}

/// The three methods an unpaired connection may call.
///
/// The set is closed here as well as in the registry, so a future registry entry cannot widen this
/// surface by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingMethod {
    /// `pair.redeem`.
    Redeem,
    /// `pair.finish`.
    Finish,
    /// `pair.status`, answered only for the candidate endpoint of the attempt.
    Status,
}

impl PairingMethod {
    fn from_name(name: &str) -> Option<Self> {
        match Method::from_wire(name)? {
            Method::PairRedeem => Some(Self::Redeem),
            Method::PairFinish => Some(Self::Finish),
            Method::PairStatus => Some(Self::Status),
            _ => None,
        }
    }
}

/// What the host's pairing implementation answers.
///
/// The candidate is identified by the endpoint identity iroh authenticated, which is what makes
/// `pair.status` candidate-authenticated rather than open: the answer is about the attempt that
/// endpoint is party to, and the caller cannot name another.
pub trait PairingSurface: Send + Sync + std::fmt::Debug {
    /// Handles one call on the pre-authorisation surface.
    ///
    /// # Errors
    ///
    /// Returns the protocol error to send back.
    fn call(
        &self,
        method: PairingMethod,
        candidate_endpoint_id: &EndpointKey,
        connection_id: ConnectionId,
        params: &ParamsValue,
    ) -> std::result::Result<ParamsValue, ProtocolError>;
}

/// A sliding-window request budget for one unpaired connection.
#[derive(Debug)]
struct RequestBudget {
    limits: PreAuthLimits,
    state: Mutex<BudgetState>,
}

#[derive(Debug, Default)]
struct BudgetState {
    total: usize,
    recent: VecDeque<ContinuousInstant>,
}

impl RequestBudget {
    fn new(limits: PreAuthLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(BudgetState::default()),
        }
    }

    /// Charges one request, or returns the refusal to send back.
    fn charge(&self, now: ContinuousInstant) -> Charge {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.total >= self.limits.max_requests {
            return Charge::Exhausted(ProtocolError::new(
                ErrorCode::RateLimited,
                "this connection has used its pairing request budget",
            ));
        }
        while let Some(oldest) = state.recent.front().copied() {
            if now.saturating_duration_since(oldest) >= self.limits.window {
                state.recent.pop_front();
            } else {
                break;
            }
        }
        if state.recent.len() >= self.limits.max_requests_per_window {
            return Charge::RateLimited(ProtocolError::new(
                ErrorCode::RateLimited,
                "too many pairing requests in a short interval",
            ));
        }
        state.total += 1;
        state.recent.push_back(now);
        Charge::Accepted
    }
}

/// What charging one request to a connection's budget decided.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Charge {
    /// The request is inside the budget.
    Accepted,
    /// Too many requests in a short interval. The connection stays open.
    RateLimited(ProtocolError),
    /// The connection has used its whole budget. It is answered once and then ends.
    Exhausted(ProtocolError),
}

/// Serves the pre-authorisation surface on one unpaired connection until the peer stops.
///
/// The loop ends when the peer closes the stream, when the budget is exhausted or when a frame is
/// refused. It never returns an authorised connection: pairing commits through the host's own
/// records, and the device reconnects.
///
/// # Errors
///
/// Returns a transport failure. A refused request is answered and the loop continues; only a
/// broken or abusive stream ends it.
pub async fn serve(
    connection: &mut UnpairedConnection,
    surface: &dyn PairingSurface,
    limits: PreAuthLimits,
    clock: &dyn ContinuousClock,
    controller_generation: ControllerGeneration,
) -> Result<()> {
    let actor = ConnectionActor::unpaired_peer(
        candidate_principal(&connection.peer_endpoint_id),
        controller_generation,
        connection.connection_id,
    )
    .in_early_data(connection.early_data);
    let budget = RequestBudget::new(limits);

    loop {
        let request: Request = match connection
            .control_reader
            .read_message_within(limits.max_frame_len)
            .await?
        {
            Some(request) => request,
            None => return Ok(()),
        };
        let (response, exhausted) = answer(&request, &actor, surface, &budget, clock, connection);
        connection.control_writer.write_message(&response).await?;
        if exhausted {
            // The connection has used its whole budget. Reading further requests only to refuse
            // them costs the host work for nothing, so the exchange ends here.
            let _ = connection.control_writer.finish();
            return Ok(());
        }
    }
}

fn answer(
    request: &Request,
    actor: &ConnectionActor,
    surface: &dyn PairingSurface,
    budget: &RequestBudget,
    clock: &dyn ContinuousClock,
    connection: &UnpairedConnection,
) -> (Response, bool) {
    let charged = budget.charge(clock.now());
    let exhausted = matches!(charged, Charge::Exhausted(_));
    let admitted = match charged {
        Charge::Accepted => Ok(()),
        Charge::RateLimited(error) | Charge::Exhausted(error) => Err(error),
    };
    let outcome = admitted
        .and_then(|()| {
            actor.admit(request.method.as_str(), request.method_version)?;
            PairingMethod::from_name(request.method.as_str()).ok_or_else(|| {
                ProtocolError::new(ErrorCode::PermissionDenied, "the method is not available")
            })
        })
        .and_then(|method| {
            surface.call(
                method,
                &connection.peer_endpoint_id,
                connection.connection_id,
                &request.params,
            )
        });
    (
        Response {
            request_id: request.request_id,
            outcome: match outcome {
                Ok(result) => Outcome::Ok(result),
                Err(error) => Outcome::Error(error),
            },
        },
        exhausted,
    )
}

/// Returns the principal a candidate endpoint acts under before it has a device record.
///
/// It is derived from the authenticated endpoint identity, so it names exactly one endpoint and
/// the candidate cannot choose it. It is not a device identity: the host assigns one of those only
/// when it commits the device record.
#[must_use]
pub fn candidate_principal(endpoint_id: &EndpointKey) -> ActorId {
    let text = format!(
        "candidate:{}",
        kr_protocol::scalars::to_base64url(endpoint_id.as_bytes())
    );
    ActorId::new(text).expect("a base64url endpoint identity is a valid opaque identifier")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;

    #[test]
    fn only_the_three_pairing_methods_resolve() {
        assert_eq!(
            PairingMethod::from_name("pair.redeem"),
            Some(PairingMethod::Redeem)
        );
        assert_eq!(
            PairingMethod::from_name("pair.finish"),
            Some(PairingMethod::Finish)
        );
        assert_eq!(
            PairingMethod::from_name("pair.status"),
            Some(PairingMethod::Status)
        );
        for other in ["pair.invite", "pair.confirm", "session.list", "host.info"] {
            assert_eq!(PairingMethod::from_name(other), None, "{other}");
        }
    }

    #[test]
    fn the_registry_refuses_everything_else_at_this_ingress() {
        let actor = ConnectionActor::unpaired_peer(
            ActorId::new("candidate:test").expect("a principal"),
            ControllerGeneration::new(1),
            ConnectionId::new(kr_protocol::scalars::Uuid::from_bytes([1; 16])),
        );
        for method in ["session.list", "input.write", "pair.invite", "pair.confirm"] {
            assert!(
                actor
                    .admit(method, kr_protocol::method::MethodVersion::V1)
                    .is_err(),
                "{method}"
            );
        }
        for method in ["pair.redeem", "pair.finish", "pair.status"] {
            assert!(
                actor
                    .admit(method, kr_protocol::method::MethodVersion::V1)
                    .is_ok(),
                "{method}"
            );
        }
    }

    #[test]
    fn a_connection_cannot_exceed_its_request_budget() {
        let clock = ManualClock::new();
        let limits = PreAuthLimits {
            max_requests: 3,
            max_requests_per_window: 3,
            window: Duration::from_secs(10),
            max_frame_len: MAX_PREAUTH_FRAME_LEN,
        };
        let budget = RequestBudget::new(limits);
        for _ in 0..3 {
            assert_eq!(budget.charge(clock.now()), Charge::Accepted);
        }
        let Charge::Exhausted(error) = budget.charge(clock.now()) else {
            panic!("the fourth request is past the budget");
        };
        assert_eq!(error.code, ErrorCode::RateLimited);
        // Waiting does not restore a spent total budget.
        clock.advance(Duration::from_secs(60));
        assert!(matches!(budget.charge(clock.now()), Charge::Exhausted(_)));
    }

    #[test]
    fn the_rate_window_slides() {
        let clock = ManualClock::new();
        let limits = PreAuthLimits {
            max_requests: 100,
            max_requests_per_window: 2,
            window: Duration::from_secs(10),
            max_frame_len: MAX_PREAUTH_FRAME_LEN,
        };
        let budget = RequestBudget::new(limits);
        assert_eq!(budget.charge(clock.now()), Charge::Accepted);
        assert_eq!(budget.charge(clock.now()), Charge::Accepted);
        assert!(matches!(budget.charge(clock.now()), Charge::RateLimited(_)));
        clock.advance(Duration::from_secs(11));
        assert_eq!(
            budget.charge(clock.now()),
            Charge::Accepted,
            "the window has slid"
        );
    }

    #[test]
    fn a_candidate_principal_names_one_endpoint() {
        let first = candidate_principal(&EndpointKey::from_bytes([1; 32]));
        let second = candidate_principal(&EndpointKey::from_bytes([2; 32]));
        assert_ne!(first, second);
        assert!(first.as_str().starts_with("candidate:"));
    }

    #[test]
    fn the_frame_bound_is_far_below_the_control_limit() {
        const {
            assert!(MAX_PREAUTH_FRAME_LEN < kr_protocol::limits::MAX_CONTROL_FRAME_LEN / 100);
        }
    }
}
