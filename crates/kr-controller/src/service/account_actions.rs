//! The host's own sign-in to the managed account service: its two methods and the account the
//! daemon builds at start.

use std::sync::Arc;

use kr_protocol::envelope::ParamsValue;
use kr_protocol::host_account::{AccountSignInParams, AccountStatusParams};
use kr_protocol::service::GatewayOrigin;

use crate::error::{ControllerError, Result};

use super::{Controller, parse};

impl Controller {
    /// The host's own sign-in to the managed account service, at the broker origin the
    /// configuration document names, through the proxy it selects.
    ///
    /// A host that names no broker, or one this daemon cannot reach a service at, signs in
    /// nowhere; what stands in the way is said on standard error, as for the voice broker.
    pub(super) fn build_host_account(
        started: &crate::config::Started,
        store: Arc<dyn kr_crypto::store::SecretStore>,
        environment_id: kr_protocol::ids::EnvironmentId,
        runtime_root: &std::path::Path,
    ) -> crate::account::HostAccount {
        let service = started.voice.broker_origin().and_then(|origin| {
            let unavailable = |reason: &dyn std::fmt::Display| {
                eprintln!("kr-controller: no host sign-in: {reason}");
            };
            let gateway = GatewayOrigin::new(origin)
                .inspect_err(|error| unavailable(&format_args!("voice.broker_origin: {error}")))
                .ok()?;
            let proxy = Self::proxy_of(started)
                .inspect_err(|error| unavailable(error))
                .ok()?;
            let transport = Arc::new(crate::managed_transport::ManagedTransport::new(
                gateway,
                proxy,
                kr_client::services::HttpDeadlines::default(),
            ));
            Some(crate::account::Service {
                origin: origin.to_owned(),
                account: Arc::new(kr_client::services::ManagedAccountService::at_origin(
                    origin,
                    transport,
                    kr_client::services::account::Client::Desktop,
                )),
            })
        });
        crate::account::HostAccount::new(store, environment_id, runtime_root, service)
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
