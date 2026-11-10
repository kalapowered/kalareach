//! The host's own sign-ins to account services: the methods that sign the managed account in, out
//! and read it, the same three for the account at a storage service the owner runs, and the
//! accounts the daemon builds at start.

use std::sync::Arc;

use kr_protocol::envelope::ParamsValue;
use kr_protocol::host_account::{AccountSignInParams, AccountSignOutParams, AccountStatusParams};
use kr_protocol::service::GatewayOrigin;

use crate::account::{HostAccount, Service};
use crate::config::Outbound;
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

/// Whether a plain-HTTP origin may hold an account: only in a build for tests, whose suites stand
/// the services they run against at a loopback origin. No shipped build presents an account token
/// over plain HTTP.
const PLAIN_HTTP_PERMITTED: bool = cfg!(any(test, feature = "testing"));

/// Refuses a storage origin that would be sent an account token over plain HTTP, unless
/// `plain_http_permitted`.
///
/// A proxy carries every request in absolute form, loopback ones included, so a plain-HTTP origin
/// with `network.proxy_url` would send the sign-in code, the verifier, the refresh token and each
/// bearer token across the proxy in clear text; with no proxy, another local user can take a
/// loopback port while the person's own service is down.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] naming `storage.origin`.
fn refuse_plain_http(origin: &GatewayOrigin, plain_http_permitted: bool) -> Result<()> {
    if origin.as_str().starts_with("http://") && !plain_http_permitted {
        return Err(ControllerError::NotConfigured(format!(
            "{} in this host's configuration document ({}) names {origin}, which is not served \
             over https: this host presents its account token to a storage service it does not \
             run itself only over https",
            kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
            kr_protocol::hostinfo::configuration::FILE_NAME,
        )));
    }
    Ok(())
}

impl Controller {
    /// The host's managed account, through the proxy the configuration document selects.
    ///
    /// The account service is the one the browser signs in at, and a code is redeemable only
    /// there, so every request of the sign-in goes there and the voice broker and the storage
    /// service are each presented a token only when they are that service. A host whose broker is
    /// another service, or none, and that selects no storage service of the managed origin signs in
    /// and presents nowhere, but still reaches the account service for what it holds: the grant it
    /// was signed in with while its broker was the managed one can be seen, revoked and signed
    /// out. What stands in the way is said on standard error, as for the voice broker.
    ///
    /// The sign-in asks for the scope of each service the host presents it to: voice where the
    /// broker is the account service, backup storage where the document selects the managed
    /// storage service, and the right to bill relay traffic where the relay lease service is the
    /// account service. The account that pays for the leases is the one the host is signed in as.
    /// A storage service the person runs is reached with an account of its own
    /// ([`Self::build_storage_account`]).
    pub(super) fn build_host_account(
        started: &crate::config::Started,
        store: Arc<dyn kr_crypto::store::SecretStore>,
        environment_id: kr_protocol::ids::EnvironmentId,
        runtime_root: &std::path::Path,
    ) -> HostAccount {
        use kr_protocol::host_account::SignInUnavailable;

        let unusable = |reason: &dyn std::fmt::Display| {
            eprintln!("kr-controller: no host sign-in: {reason}");
            SignInUnavailable::NotUsable
        };
        let origin = account_origin();
        let broker = started.voice.broker_origin();
        let managed_storage = started.storage.origin() == Some(origin.as_str());
        let relay_is_account_service = started.relay.origin() == Some(origin.as_str());
        let mut scopes = Vec::new();
        if broker == Some(origin.as_str()) {
            scopes.push(kr_client::services::voice::VOICE_SCOPE);
        }
        if managed_storage {
            scopes.push(kr_client::services::account::BACKUP_WRITE_SCOPE);
        }
        if relay_is_account_service {
            scopes.push(kr_client::services::account::RELAY_LEASE_SCOPE);
        }
        let route = Self::outbound_of(started);
        let closed = matches!(&route, Ok(Outbound::Closed(_)));
        // A host over a document it cannot use selects nothing, so it would read as naming no
        // service; it is the document that stands in the way, and the refusals say so.
        let refused = if closed {
            Some(SignInUnavailable::NotUsable)
        } else {
            match (broker, managed_storage) {
                (_, true) => None,
                (_, false) if relay_is_account_service => None,
                (None, false) => Some(SignInUnavailable::NoManagedService),
                (Some(broker), false) if broker == origin => None,
                (Some(_), false) => Some(SignInUnavailable::BrokerIsAnotherService),
            }
        };
        let service = GatewayOrigin::new(&origin)
            .map_err(|error| unusable(&format_args!("the account service: {error}")))
            .and_then(|gateway| match route {
                Ok(route) => {
                    // Over a closed route the account the host keeps is still read and ended here,
                    // and nothing is sent: what is owed to the service waits for the route.
                    if let Outbound::Closed(refusal) = &route {
                        eprintln!("kr-controller: no request to the account service: {refusal}");
                    }
                    Ok(Service::at_origin(&gateway, scopes, route))
                }
                Err(error) => Err(unusable(&error)),
            });
        HostAccount::new(store, environment_id, runtime_root, service, refused)
    }

    /// The account of the storage service the person runs, when the host's `storage.origin` names
    /// a service that is not the managed one, and none when it names the managed one or none.
    ///
    /// The account asks for `backup.write` and hands out that scope and no other. It is built
    /// after the two rules that keep it from sending an account token where none should go: the
    /// storage origin is served over https in a shipped build, which is checked here, and its scope
    /// in the secret store has a name of its own, which the account's constructor checks before it
    /// exists, because building it starts settling what that scope holds.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] naming `storage.origin` when it is not usable or
    /// breaks one of the two rules.
    pub(super) fn build_storage_account(
        started: &crate::config::Started,
        managed: &HostAccount,
        store: Arc<dyn kr_crypto::store::SecretStore>,
        environment_id: kr_protocol::ids::EnvironmentId,
    ) -> Result<Option<HostAccount>> {
        use kr_protocol::host_account::SignInUnavailable;

        let managed_origin = account_origin();
        let Some(storage) = started
            .storage
            .origin()
            .filter(|storage| *storage != managed_origin)
        else {
            return Ok(None);
        };
        let storage = super::clients::selected_origin(
            &kr_protocol::hostinfo::configuration::STORAGE_ORIGIN,
            storage,
        )?;
        refuse_plain_http(&storage, PLAIN_HTTP_PERMITTED)?;
        let route = Self::outbound_of(started)?;
        let refused = matches!(&route, Outbound::Closed(_)).then_some(SignInUnavailable::NotUsable);
        let service = Service::at_origin(
            &storage,
            vec![kr_client::services::account::BACKUP_WRITE_SCOPE],
            route,
        );
        HostAccount::for_storage(managed, store, environment_id, Ok(service), refused).map(Some)
    }

    /// This host's own sign-in to the managed account service.
    #[must_use]
    pub fn host_account(&self) -> &Arc<crate::account::HostAccount> {
        &self.account
    }

    /// The account that serves this host's storage service: the managed account when the storage
    /// service is the managed one, and the account of the service the person runs otherwise.
    #[must_use]
    pub fn storage_account(&self) -> &Arc<crate::account::HostAccount> {
        self.storage_account.as_ref().unwrap_or(&self.account)
    }

    /// The account of the storage service the person runs, or the refusal a host with none is
    /// given. Over a configuration document the daemon cannot use nothing is selected, and the
    /// refusal says that; otherwise its `storage.origin` is unset or names the managed account
    /// service, so it holds no account of its own for storage.
    fn own_storage_account(&self) -> Result<&Arc<HostAccount>> {
        self.storage_account.as_ref().ok_or_else(|| {
            let key = kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key;
            let file = kr_protocol::hostinfo::configuration::FILE_NAME;
            ControllerError::NotConfigured(if self.started.unusable.is_some() {
                format!(
                    "this host's configuration document ({file}) cannot be used, so its {key} \
                     selects no storage service and this host holds no account for one you run; \
                     `kr doctor` says how to put the document right"
                )
            } else {
                format!(
                    "{key} in this host's configuration document ({file}) is unset or names the \
                     managed account service, so this host holds no account for a storage \
                     service you run; `kr account sign-in` signs in the managed account"
                )
            })
        })
    }

    /// Answers `account.storage_sign_in`: starts the sign-in at the storage service the person
    /// runs and says when the daemon stops waiting for the browser.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] naming `storage.origin` for a host that holds no
    /// storage account, and otherwise why no sign-in can start, as
    /// [`crate::account::HostAccount::sign_in`] does.
    pub(super) async fn account_storage_sign_in(
        &self,
        mutation: &kr_protocol::envelope::MutationRequest,
    ) -> Result<ParamsValue> {
        let _: AccountSignInParams = parse(&mutation.params)?;
        let started = self.own_storage_account()?.sign_in().await?;
        ParamsValue::from_typed(&started)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `account.storage_sign_out`: removes the storage account's grant and asks the storage
    /// service to end it. The managed account is not touched.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] naming `storage.origin` for a host that holds no
    /// storage account, and otherwise why the host cannot sign out, as
    /// [`crate::account::HostAccount::sign_out`] does.
    pub(super) async fn account_storage_sign_out(
        &self,
        mutation: &kr_protocol::envelope::MutationRequest,
    ) -> Result<ParamsValue> {
        let _: AccountSignOutParams = parse(&mutation.params)?;
        let done = self.own_storage_account()?.sign_out().await?;
        ParamsValue::from_typed(&done)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `account.storage_status`: where the storage account's sign-in stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for parameters that are not empty, and
    /// [`ControllerError::NotConfigured`] naming `storage.origin` for a host that holds no storage
    /// account.
    pub(super) fn account_storage_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _: AccountStatusParams = parse(params)?;
        ParamsValue::from_typed(&self.own_storage_account()?.report())
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
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

#[cfg(test)]
mod tests {
    use kr_protocol::service::GatewayOrigin;

    use super::refuse_plain_http;

    fn origin(text: &str) -> GatewayOrigin {
        GatewayOrigin::new(text).expect("an origin")
    }

    /// A storage origin that is served over plain HTTP is refused where plain HTTP is not
    /// permitted, whether or not the document names a proxy, and the refusal names the key. The
    /// rule takes the permission as an argument because this crate's own tests always run with it:
    /// the program a person runs is shown to refuse by the shipped-build case of the daemon's
    /// storage account suite.
    #[test]
    fn a_plain_http_storage_origin_is_refused_where_plain_http_is_not_permitted() {
        let loopback = origin("http://127.0.0.1:8787");
        let refusal = refuse_plain_http(&loopback, false).expect_err("a refusal");
        assert!(refusal.to_string().contains("storage.origin"), "{refusal}");
        assert!(refuse_plain_http(&loopback, true).is_ok());
    }

    /// The same origin over https is the one a shipped build presents an account token to.
    #[test]
    fn an_https_storage_origin_is_admitted_whether_or_not_plain_http_is_permitted() {
        let owner = origin("https://owner.example");
        assert!(refuse_plain_http(&owner, false).is_ok());
        assert!(refuse_plain_http(&owner, true).is_ok());
    }
}
