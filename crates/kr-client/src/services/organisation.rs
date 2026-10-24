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
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::OrganisationId;
use kr_protocol::scalars::{AuthorisationKey, to_base64url};
use serde::Deserialize;

use super::account::{AccountMark, LEASE_SCOPE, SignedInAccount};
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

/// Which token a request to the service carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    /// The one the account holds, refreshed first when it is near its end.
    Held,
    /// One the account replaces first, whatever the held token's age: the service turned the held
    /// one back, and a token can end in transit or on a clock that runs behind the service's.
    Renewed,
}

/// Whether the account signed in is the one a lease client asks as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccountNow {
    /// The account the client was made for.
    Same,
    /// Another account: the one the client was made for signed out and someone signed in.
    Replaced,
    /// No account is signed in.
    SignedOut,
}

/// Where a member's device gets the lease its organisation signed for it.
///
/// A client asks as one account, the one signed in when it was made, and never as another: a lease
/// is signed for an account, and the host binds a device to the first account that presents one.
pub trait MembershipLeaseService: Send + Sync + fmt::Debug {
    /// Whether the account signed in now is the one this client asks as. Asked before a lease is
    /// presented and before a lease is asked for, so that work begun for an account that has since
    /// signed out ends and is not carried on for the account that signed in after it.
    ///
    /// # Errors
    ///
    /// Returns why the account could not be read.
    fn account_now(&self) -> Result<AccountNow>;

    /// Asks for a lease for the account signed in, naming `device_key` as the device it is for,
    /// under `token`. A service that rejects the token is answered with its refusal as it is: the
    /// caller decides whether to ask again under a renewed one, so that the second request meets
    /// the same pacing as the first.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, such as that the account is not a member of the
    /// organisation, or why no account token could be had.
    fn lease<'a>(
        &'a self,
        organisation: OrganisationId,
        device_key: AuthorisationKey,
        token: Token,
    ) -> ServiceFuture<'a, IssuedLease>;

    /// Reads the chain of keys that signs the organisation's leases, which a host follows from the
    /// key it pinned to the one signing now.
    ///
    /// # Errors
    ///
    /// Returns the service's refusal, or why no account token could be had.
    fn authority<'a>(
        &'a self,
        organisation: OrganisationId,
        token: Token,
    ) -> ServiceFuture<'a, PolicyAuthority>;
}

impl MembershipLeaseService for super::NullService {
    fn account_now(&self) -> Result<AccountNow> {
        Ok(AccountNow::Same)
    }

    fn lease<'a>(
        &'a self,
        _organisation: OrganisationId,
        _device_key: AuthorisationKey,
        _token: Token,
    ) -> ServiceFuture<'a, IssuedLease> {
        unconfigured(super::ManagedService::AccountLogin.as_str())
    }

    fn authority<'a>(
        &'a self,
        _organisation: OrganisationId,
        _token: Token,
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
    /// The account this client asks as, at `origin`.
    asks_as: AccountMark,
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
    /// [`LEASE_SCOPE`], and only while the account signed in is the one `asks_as` marks: a request
    /// is never made under another account's token.
    #[must_use]
    pub fn new(
        origin: &kr_protocol::service::GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        account: Arc<SignedInAccount>,
        asks_as: AccountMark,
    ) -> Self {
        Self {
            origin: origin.as_str().to_owned(),
            http,
            account,
            asks_as,
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
    /// refusal that names the action; a failure to read or renew a token stays as it was. A token of
    /// another account than the one this client asks as is never presented.
    async fn authorisation(&self, renew: bool) -> Result<String> {
        let (token, mark) = match self
            .account
            .token_marked(LEASE_SCOPE, &self.origin, renew)
            .await
        {
            Ok(held) => held,
            Err(ClientError::Host(refusal))
                if matches!(
                    refusal.code,
                    ErrorCode::HostNotConfigured | ErrorCode::PermissionDenied
                ) =>
            {
                return Err(sign_in_again(refusal));
            }
            Err(other) => return Err(other),
        };
        if mark != self.asks_as {
            return Err(sign_in_again(crate::error::refusal(
                ErrorCode::PermissionDenied,
                Shown::said("another account is signed in than the one this request is for"),
            )));
        }
        // The one place the token is read. It goes into a header value and nowhere else.
        Ok(format!("Bearer {}", token.expose()))
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

/// The refusal for a request there is no token to make: the sign-in is what mends it.
fn sign_in_again(refusal: kr_protocol::error::ProtocolError) -> ClientError {
    ClientError::Refused {
        error: refusal,
        retry_after_seconds: None,
        action: UserAction::SignIn,
        service_code: None,
    }
}

impl MembershipLeaseService for ManagedMembershipLeaseService {
    fn account_now(&self) -> Result<AccountNow> {
        Ok(match self.account.mark(&self.origin)? {
            Some(mark) if mark == self.asks_as => AccountNow::Same,
            Some(_) => AccountNow::Replaced,
            None => AccountNow::SignedOut,
        })
    }

    fn lease<'a>(
        &'a self,
        organisation: OrganisationId,
        device_key: AuthorisationKey,
        token: Token,
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
            let authorisation = self.authorisation(token == Token::Renewed).await?;
            let answer = self
                .http
                .post_json(&path, &body, &[("authorization", authorisation.as_str())])
                .await?;
            let answered: LeaseAnswer =
                serde_json::from_value(data_or_refusal(&answer, Repeat::Safe)?)
                    .map_err(|error| unreadable_answer("a lease", &error))?;
            Ok(IssuedLease {
                lease: answered.lease,
                refresh_after: Duration::from_secs(answered.refresh_after_seconds),
            })
        })
    }

    fn authority<'a>(
        &'a self,
        organisation: OrganisationId,
        token: Token,
    ) -> ServiceFuture<'a, PolicyAuthority> {
        Box::pin(async move {
            let path = self.path(organisation, "policy-authority");
            let authorisation = self.authorisation(token == Token::Renewed).await?;
            let answer = self
                .http
                .get_json(&path, &[("authorization", authorisation.as_str())])
                .await?;
            serde_json::from_value(data_or_refusal(&answer, Repeat::Safe)?)
                .map_err(|error| unreadable_answer("a policy authority", &error))
        })
    }
}
