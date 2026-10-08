//! The host's own sign-in to the managed account service: its two methods and the account the
//! daemon builds at start.

use std::sync::Arc;

use kr_protocol::envelope::ParamsValue;
use kr_protocol::host_account::{AccountSignInParams, AccountSignOutParams, AccountStatusParams};
use kr_protocol::service::GatewayOrigin;

use crate::error::{ControllerError, Result};

use super::{Controller, parse};

/// The account service's origin: the one the browser signs in at, which the issuer every answer is
/// checked against belongs to.
#[cfg(not(any(test, feature = "testing")))]
fn account_origin() -> String {
    kr_client::services::account::ACCOUNT_ORIGIN.to_owned()
}

/// The account service's origin, or the one a suite stands its own service at.
#[cfg(any(test, feature = "testing"))]
fn account_origin() -> String {
    crate::testing::account_origin()
        .unwrap_or_else(|| kr_client::services::account::ACCOUNT_ORIGIN.to_owned())
}

impl Controller {
    /// The host's own sign-in to the managed account service, through the proxy the configuration
    /// document selects.
    ///
    /// The account service is the one the browser signs in at, and a code is redeemable only
    /// there, so every request of the sign-in goes there and the voice broker is presented a token
    /// only when it is that service. A host whose broker is another service, or none, signs in and
    /// presents nowhere, but still reaches the account service for what it holds: the grant it was
    /// signed in with while its broker was the managed one can be seen, revoked and signed out.
    /// What stands in the way is said on standard error, as for the voice broker.
    pub(super) fn build_host_account(
        started: &crate::config::Started,
        store: Arc<dyn kr_crypto::store::SecretStore>,
        environment_id: kr_protocol::ids::EnvironmentId,
        runtime_root: &std::path::Path,
    ) -> crate::account::HostAccount {
        use kr_protocol::host_account::SignInUnavailable;

        let unusable = |reason: &dyn std::fmt::Display| {
            eprintln!("kr-controller: no host sign-in: {reason}");
            SignInUnavailable::NotUsable
        };
        let origin = account_origin();
        let refused = match started.voice.broker_origin() {
            None => Some(SignInUnavailable::NoBroker),
            Some(broker) if broker == origin => None,
            Some(_) => Some(SignInUnavailable::BrokerIsAnotherService),
        };
        let service = GatewayOrigin::new(&origin)
            .map_err(|error| unusable(&format_args!("the account service: {error}")))
            .and_then(|gateway| {
                let proxy = Self::proxy_of(started).map_err(|error| unusable(&error))?;
                let transport = Arc::new(crate::managed_transport::ManagedTransport::new(
                    gateway,
                    proxy,
                    kr_client::services::HttpDeadlines::default(),
                ));
                Ok(crate::account::Service {
                    account: Arc::new(kr_client::services::ManagedAccountService::at_origin(
                        origin.clone(),
                        transport,
                        kr_client::services::account::Client::Desktop,
                    )),
                    origin: origin.clone(),
                })
            });
        crate::account::HostAccount::new(store, environment_id, runtime_root, service, refused)
    }

    /// This host's own sign-in to the managed account service.
    #[must_use]
    pub fn host_account(&self) -> &Arc<crate::account::HostAccount> {
        &self.account
    }

    /// Answers `account.sign_in`: starts the sign-in and says when the daemon stops waiting for
    /// the browser.
    ///
    /// # Errors
    ///
    /// Returns why no sign-in can start, as [`crate::account::HostAccount::sign_in`] does.
    pub(super) async fn account_sign_in(
        &self,
        mutation: &kr_protocol::envelope::MutationRequest,
    ) -> Result<ParamsValue> {
        let _: AccountSignInParams = parse(&mutation.params)?;
        let started = self.account.sign_in().await?;
        ParamsValue::from_typed(&started)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `account.sign_out`: removes the grant and asks the service to end it.
    ///
    /// # Errors
    ///
    /// Returns why the host cannot sign out, as [`crate::account::HostAccount::sign_out`] does.
    pub(super) async fn account_sign_out(
        &self,
        mutation: &kr_protocol::envelope::MutationRequest,
    ) -> Result<ParamsValue> {
        let _: AccountSignOutParams = parse(&mutation.params)?;
        let done = self.account.sign_out().await?;
        ParamsValue::from_typed(&done)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `account.status`: where the host's sign-in stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for parameters that are not empty.
    pub(super) fn account_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _: AccountStatusParams = parse(params)?;
        ParamsValue::from_typed(&self.account.report())
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}
