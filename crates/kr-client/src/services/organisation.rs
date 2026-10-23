//! The organisation's service, as a member's device asks it for the lease that proves its
//! membership.
//!
//! A host answers for a member's device only while the device holds a membership lease its
//! organisation signed, and a lease lasts at most fifteen minutes. The organisation's service
//! signs one for the account that is signed in and for the device key it is asked about, and says
//! when to ask again. It also publishes the chain of keys that signs its leases, which a host needs
//! when a lease is signed by a key it has not yet followed.
//!
//! Both calls present the account's token for [`LEASE_SCOPE`] and nothing else: the service does
//! not ask for proof that the device holds the key it names, because a host accepts a lease only
//! on a connection that proves the key, so a lease for a key the caller does not hold is one only
//! the holder can use.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::OrganisationId;
use kr_protocol::scalars::{AuthorisationKey, to_base64url};
use serde::Deserialize;

use super::account::{LEASE_SCOPE, SignedInAccount};
use super::relay::ServiceHttp;
use super::signed::{Repeat, data_or_refusal, unreadable_answer};
use super::{ServiceFuture, unconfigured};
use crate::error::{ClientError, Result};
use crate::retry::UserAction;
use crate::shown::Shown;

/// What the organisation's service signed for a device, and when to ask again.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedLease {
    /// The lease, as a host verifies it.
    pub lease: MembershipLease,
    /// How long after this answer the service advises asking for the next lease.
    ///
    /// Advice to the holder, kept beside the lease and not inside it: it is no part of the
    /// statement the organisation signed.
    pub refresh_after: Duration,
}

impl fmt::Debug for IssuedLease {
    /// That a lease was issued and when to ask again. Never the lease, which names an account.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedLease")
            .field("refresh_after", &self.refresh_after)
            .finish_non_exhaustive()
    }
}

/// Where a member's device gets the lease its organisation signed for it.
pub trait MembershipLeaseService: Send + Sync + fmt::Debug {
    /// Asks for a lease for the account signed in, naming `device_key` as the device it is for.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, such as that the account is not a member of the
    /// organisation, or why no account token could be had.
    fn lease<'a>(
        &'a self,
        organisation: OrganisationId,
        device_key: AuthorisationKey,
    ) -> ServiceFuture<'a, IssuedLease>;

    /// Reads the chain of keys that signs the organisation's leases, which a host follows from the
    /// key it pinned to the one signing now.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, or why no account token could be had.
    fn authority<'a>(&'a self, organisation: OrganisationId) -> ServiceFuture<'a, PolicyAuthority>;
}

impl MembershipLeaseService for super::NullService {
    fn lease<'a>(
        &'a self,
        _organisation: OrganisationId,
        _device_key: AuthorisationKey,
    ) -> ServiceFuture<'a, IssuedLease> {
        unconfigured(super::ManagedService::AccountLogin.as_str())
    }

    fn authority<'a>(
        &'a self,
        _organisation: OrganisationId,
    ) -> ServiceFuture<'a, PolicyAuthority> {
        unconfigured(super::ManagedService::AccountLogin.as_str())
    }
}

/// The managed organisation service.
#[derive(Clone)]
pub struct ManagedMembershipLeaseService {
    origin: String,
    http: Arc<dyn ServiceHttp>,
    account: Arc<SignedInAccount>,
}

impl fmt::Debug for ManagedMembershipLeaseService {
    /// The origin as a diagnostic names one: an address may carry a user name and a password in
    /// front of its host.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedMembershipLeaseService")
            .field("origin", &Shown::address(&self.origin))
            .finish_non_exhaustive()
    }
}

impl ManagedMembershipLeaseService {
    /// Builds a client against one origin, presenting the token `account` holds for
    /// [`LEASE_SCOPE`].
    #[must_use]
    pub fn new(
        origin: &kr_protocol::service::GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        account: Arc<SignedInAccount>,
    ) -> Self {
        Self {
            origin: origin.as_str().to_owned(),
            http,
            account,
        }
    }

    /// The origin this client addresses.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The `authorization` header value a request carries, from the token the account holds or,
    /// with `renew`, from one it replaces whatever the old one's age.
    ///
    /// An account that is not signed in, whose sign-in has ended, or whose sign-in was not granted
    /// the lease scope has no token to ask with, and asking for the sign-in again is what mends
    /// each. The account says so as a failure of this device's own, which this turns into the
    /// refusal that names the action; a failure to read or renew a token stays as it was.
    async fn authorisation(&self, renew: bool) -> Result<String> {
        let token = match self.account.token_of_account(LEASE_SCOPE, renew).await {
            Ok(held) => held.token,
            Err(ClientError::Host(refusal))
                if matches!(
                    refusal.code,
                    ErrorCode::HostNotConfigured | ErrorCode::PermissionDenied
                ) =>
            {
                return Err(ClientError::Refused {
                    error: refusal,
                    retry_after_seconds: None,
                    action: UserAction::SignIn,
                    service_code: None,
                });
            }
            Err(other) => return Err(other),
        };
        // The one place the token is read. It goes into a header value and nowhere else.
        Ok(format!("Bearer {}", token.expose()))
    }

    /// Makes a request with the account's token, and once more with a renewed one when the service
    /// rejects the first as `UNAUTHENTICATED`: a token can end in transit, or on a clock that runs
    /// behind the service's, and nothing a person does mends that. A second rejection is the
    /// service's last word.
    ///
    /// Sound for a request that is safe to send again, as both of this client's are: a request the
    /// service rejected for its token did nothing.
    async fn with_token<T, F, Fut>(&self, mut request: F) -> Result<T>
    where
        F: FnMut(String) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut renew = false;
        loop {
            let authorisation = self.authorisation(renew).await?;
            match request(authorisation).await {
                Err(ClientError::Refused {
                    service_code: Some("UNAUTHENTICATED"),
                    ..
                }) if !renew => renew = true,
                other => return other,
            }
        }
    }

    fn path(&self, organisation: OrganisationId, tail: &str) -> String {
        format!(
            "{}/api/account/organisations/{organisation}/{tail}",
            self.origin
        )
    }
}

/// The members of a lease answer. The service writes them in camel case, as its envelope does.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseAnswer {
    lease: MembershipLease,
    #[serde(rename = "refreshAfterSeconds")]
    refresh_after_seconds: u64,
}

impl MembershipLeaseService for ManagedMembershipLeaseService {
    fn lease<'a>(
        &'a self,
        organisation: OrganisationId,
        device_key: AuthorisationKey,
    ) -> ServiceFuture<'a, IssuedLease> {
        Box::pin(async move {
            let body = serde_json::to_vec(&serde_json::json!({
                "device_key": to_base64url(device_key.as_bytes()),
            }))
            .map_err(|error| {
                ClientError::refusal(
                    kr_protocol::error::ErrorCode::InvalidArgument,
                    crate::shown!(
                        "a lease request could not be written: {}",
                        Shown::json(&error)
                    ),
                )
            })?;
            let path = self.path(organisation, "lease");
            let answered: LeaseAnswer = self
                .with_token(|authorisation| {
                    let (body, path) = (&body, &path);
                    async move {
                        let answer = self
                            .http
                            .post_json(path, body, &[("authorization", authorisation.as_str())])
                            .await?;
                        serde_json::from_value(data_or_refusal(&answer, Repeat::Safe)?)
                            .map_err(|error| unreadable_answer("a lease", &error))
                    }
                })
                .await?;
            Ok(IssuedLease {
                lease: answered.lease,
                refresh_after: Duration::from_secs(answered.refresh_after_seconds),
            })
        })
    }

    fn authority<'a>(&'a self, organisation: OrganisationId) -> ServiceFuture<'a, PolicyAuthority> {
        Box::pin(async move {
            let path = self.path(organisation, "policy-authority");
            self.with_token(|authorisation| {
                let path = &path;
                async move {
                    let answer = self
                        .http
                        .get_json(path, &[("authorization", authorisation.as_str())])
                        .await?;
                    serde_json::from_value(data_or_refusal(&answer, Repeat::Safe)?)
                        .map_err(|error| unreadable_answer("a policy authority", &error))
                }
            })
            .await
        })
    }
}
