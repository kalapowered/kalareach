//! The account that pays for this host's relay leases, taken from the host's own sign-in.
//!
//! A host key draws on no allowance of its own, so every lease is billed to an account, under an
//! authorisation that account gave this host's key. The sign-in the host holds is that
//! authorisation: the host presents its credential and the account token of its sign-in to the
//! relay service, which opens one authorisation for the sign-in, binds it to this host's key and
//! makes it the host's default payer. Nobody copies an identifier between screens, and a host that
//! is signed out asks for no new lease.
//!
//! # What the authorisation is
//!
//! It lasts an hour from each time it is asked for again once fewer than
//! [`RELAY_PAYER_RENEW_BELOW_SECONDS`] seconds remain, and no lease outlasts it, so a host that
//! stops asking, because it signed out or its sign-in ended, has its leases end within the hour.
//! The keeper asks before a lease is asked for, so a request for a lease never names an
//! authorisation that has lapsed.
//!
//! A new sign-in opens another authorisation, and a lease keeps the one it was asked for under for
//! as long as it lives. The keeper names the new authorisation for the leases it asks for from then
//! on and goes on naming the previous one for a lease issued under it; it stops asking for the
//! previous sign-in, so that authorisation and its leases end within the hour.
//!
//! # When the person is asked
//!
//! The service answers `REAUTHENTICATION_REQUIRED` when the person has to sign the host in again:
//! there is no sign-in, it was issued without the scope or has ended, it belongs to another key, or
//! the account withdrew the authorisation it opened. A token that ended in transit gets the same
//! answer, so the host takes a fresh one once and asks again before it gives the question to the
//! person. An answer it is given again stands for as long as the sign-in does, and is asked again
//! after [`STANDING_RETRY`]: the same sign-in is refused for ever once the account withdrew it, and
//! only a new sign-in, which the person starts with `kr account sign-in`, opens another.

use std::sync::Arc;
use std::time::Instant;

use kr_client::ClientError;
use kr_client::services::RelayLeaseService;
use kr_client::services::relay::RELAY_PAYER_RENEW_BELOW_SECONDS;
use kr_client::shown::Shown;
use kr_protocol::error::ErrorCode;

use super::STANDING_RETRY;
use crate::account::{GrantMark, HostAccount};

/// The service's code for a sign-in that only the person can mend.
const SIGN_IN_REQUIRED: &str = "REAUTHENTICATION_REQUIRED";

/// The authorisation the host leases under, as a request names it.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Authorised {
    /// The account that is billed.
    pub(super) account_id: String,
    /// The authorisation record the sign-in opened.
    pub(super) authorisation_id: String,
    /// When it stops being in force, in UTC milliseconds on the service's clock.
    valid_until_ms: u64,
}

impl std::fmt::Debug for Authorised {
    /// Nothing: the account's identifier is the sign-in's, and a rendering does not repeat it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Authorised").finish_non_exhaustive()
    }
}

impl Authorised {
    /// The text a row keeps the payer it was asked for under as.
    pub(super) fn key(&self) -> String {
        format!("{}/{}", self.account_id, self.authorisation_id)
    }
}

/// What the host can lease under now.
pub(super) enum Current {
    /// The authorisation this host's sign-in opened.
    Authorised(Authorised),
    /// The person has to sign this host in again.
    SignIn,
    /// The relay lease service is not the account service this host signs in at, so there is no
    /// account whose token it may be given.
    Misconfigured,
    /// The host could not renew the authorisation it holds, which is still in force: the service
    /// could not be reached for the question. The leases are asked for under what the host holds,
    /// and the question is asked again after [`RENEW_RETRY`].
    Holding(Authorised, ClientError),
    /// The host holds no authorisation and the question about one failed for a reason that passes:
    /// the service could not be reached. The leases the host holds are refilled under the
    /// authorisation their rows name, no new lease is asked for, and the question is asked again
    /// after [`RENEW_RETRY`].
    Unknown(ClientError),
    /// The question about the authorisation failed a moment ago and is not asked again yet.
    Pending,
    /// The host could not find out: the service refused for a reason the person cannot mend by
    /// signing in.
    Failed(ClientError),
}

/// Why no authorisation was obtained.
enum Fault {
    SignIn,
    Failed(ClientError),
}

/// What the host remembers between two looks.
#[derive(Default)]
struct State {
    /// The authorisation the sign-in opened, and the grant it was opened for.
    held: Option<(GrantMark, Authorised)>,
    /// The grant the service refused as one only the person can mend, and when it did.
    refused: Option<(GrantMark, Instant)>,
    /// The service turned the held authorisation back, so it is asked for again whatever time it
    /// says it has left.
    stale: bool,
    /// A question that failed is not asked again before this, while the held authorisation stands.
    not_before: Option<Instant>,
    /// A question that failed while the host held no authorisation it could use, for the grant it
    /// was asked for, is not asked again before this; a new sign-in is a new grant.
    unknown_until: Option<(GrantMark, Instant)>,
}

/// How long a failed question about the authorisation waits while the one the host holds stands.
const RENEW_RETRY: std::time::Duration = super::MIN_ASK_GAP;

/// The host's payer: its sign-in at the relay lease service's account system.
pub(super) struct HostPayer {
    account: Arc<HostAccount>,
    /// The relay lease service's origin, which is also the account service's.
    origin: String,
    state: tokio::sync::Mutex<State>,
}

impl HostPayer {
    pub(super) fn new(account: Arc<HostAccount>, origin: &str) -> Self {
        Self {
            account,
            origin: origin.to_owned(),
            state: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// The authorisation to lease under now, asking the service for it when the host holds none,
    /// when it has fewer than [`RELAY_PAYER_RENEW_BELOW_SECONDS`] seconds left, when the host was
    /// signed in again since, or when a request under it was turned back.
    pub(super) async fn current(
        &self,
        service: &dyn RelayLeaseService,
        now_ms: u64,
        timer_now: Instant,
    ) -> Current {
        // A token is a bearer credential for the service that issued it, so a host whose lease
        // service is not its account service names no account to pay.
        if self.account.report().service.as_ref().map(String::as_str) != Some(self.origin.as_str())
        {
            return Current::Misconfigured;
        }
        let mut state = self.state.lock().await;
        let grant = self.account.grant_mark();
        let renew_below_ms = RELAY_PAYER_RENEW_BELOW_SECONDS.saturating_mul(1000);
        if let Some((held_for, authorised)) = &state.held
            && *held_for == grant
            && !state.stale
            && (authorised.valid_until_ms > now_ms.saturating_add(renew_below_ms)
                || (authorised.valid_until_ms > now_ms
                    && state.not_before.is_some_and(|until| timer_now < until)))
        {
            return Current::Authorised(authorised.clone());
        }
        if let Some((refused_for, at)) = &state.refused
            && *refused_for == grant
            && timer_now.saturating_duration_since(*at) < STANDING_RETRY
        {
            return Current::SignIn;
        }
        if let Some((unknown_for, until)) = &state.unknown_until
            && *unknown_for == grant
            && timer_now < *until
        {
            return Current::Pending;
        }
        match self.sign_in(service).await {
            Ok(authorised) => {
                state.held = Some((grant, authorised.clone()));
                state.refused = None;
                state.stale = false;
                state.not_before = None;
                state.unknown_until = None;
                Current::Authorised(authorised)
            }
            Err(Fault::SignIn) => {
                state.held = None;
                state.refused = Some((grant, timer_now));
                Current::SignIn
            }
            Err(Fault::Failed(error)) => {
                // A question the service did not answer, about an authorisation that still stands,
                // does not stop the leases the host holds from being refilled under it.
                let transient = !matches!(
                    error.code(),
                    ErrorCode::PermissionDenied
                        | ErrorCode::HostNotConfigured
                        | ErrorCode::InvalidArgument
                );
                match &state.held {
                    Some((held_for, authorised))
                        if transient
                            && *held_for == grant
                            && !state.stale
                            && authorised.valid_until_ms > now_ms =>
                    {
                        let held = authorised.clone();
                        state.not_before = timer_now.checked_add(RENEW_RETRY);
                        Current::Holding(held, error)
                    }
                    // A question that failed for a reason that passes, with nothing held, as after a
                    // restart: the leases the host holds are still refilled under the authorisation
                    // their rows name.
                    _ if transient => {
                        state.unknown_until = timer_now
                            .checked_add(RENEW_RETRY)
                            .map(|until| (grant, until));
                        Current::Unknown(error)
                    }
                    _ => Current::Failed(error),
                }
            }
        }
    }

    /// The service turned a request under the authorisation `key` back as one that is not in
    /// force: it is asked for again at the next look, which renews a lapsed one.
    pub(super) async fn turned_back(&self, key: &str) {
        let mut state = self.state.lock().await;
        if state
            .held
            .as_ref()
            .is_some_and(|(_, authorised)| authorised.key() == key)
        {
            state.stale = true;
        }
    }

    /// Asks the service for the authorisation of the host's sign-in: with the token it holds, and
    /// once more with a fresh one when the service says the person must sign in.
    async fn sign_in(
        &self,
        service: &dyn RelayLeaseService,
    ) -> std::result::Result<Authorised, Fault> {
        let mut renew = false;
        loop {
            let signed_in = match self.account.relay_payer_token(&self.origin, renew).await {
                Ok(signed_in) => signed_in,
                // No account is signed in, the sign-in was not given the scope, or it has ended.
                Err(error)
                    if matches!(
                        error.code(),
                        ErrorCode::HostNotConfigured | ErrorCode::PermissionDenied
                    ) =>
                {
                    return Err(Fault::SignIn);
                }
                Err(error) => return Err(Fault::Failed(error)),
            };
            match service
                .sign_in_payer(&signed_in.account_id, &signed_in.token)
                .await
            {
                Ok(authorisation) => {
                    let Some(valid_until_ms) = authorisation.valid_until_ms() else {
                        return Err(Fault::Failed(ClientError::refusal(
                            ErrorCode::UpstreamUnavailable,
                            Shown::said(
                                "the service named an end for the authorisation that this host \
                                 cannot read",
                            ),
                        )));
                    };
                    return Ok(Authorised {
                        account_id: authorisation.account_id,
                        authorisation_id: authorisation.authorisation_id,
                        valid_until_ms,
                    });
                }
                Err(error) if error.service_code() == Some(SIGN_IN_REQUIRED) => {
                    if renew {
                        return Err(Fault::SignIn);
                    }
                    renew = true;
                }
                Err(error) => return Err(Fault::Failed(error)),
            }
        }
    }
}
