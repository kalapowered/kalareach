//! A member's lease on the host this device is paired with.
//!
//! A device whose grant answers to an organisation is refused every method but the presentation of
//! a lease until the host holds one, `pair.status` and `host.info` included, and no lease survives
//! a host's restart. So the lease is presented as the first thing on every connection this device
//! makes to such a host, before anything is read of it ([`LeaseDesk`] is the link's
//! [`MembershipPresenter`]), and kept on the interval the organisation's service advises for as
//! long as the application's own connection to the host lasts ([`LeaseDesk::keep`]).
//!
//! The lease is the device's own: the organisation signs it for the account signed in and for this
//! device's authorisation key, and the host accepts it only on a connection that proves that key.
//! Which organisation is the one the host's grant names, kept with the pairing. The host holds one
//! lease for the device, not one for each connection, so a connection made beside the one that
//! keeps the lease presents nothing.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::organisation::{
    LONGEST_REFRESH, LeaseEvent, LeaseKeeper, LeaseStop, LeaseTimer, RealTimer,
};
use kr_client::pairing::BoxFuture;
use kr_client::pairing::link::{LinkError, MembershipPresenter};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::{
    HttpDeadlines, HttpService, ManagedMembershipLeaseService, managed_response_limits,
};
use kr_client::session::Session;
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{DeviceId, EnvironmentId};
use kr_protocol::scalars::AuthorisationKey;
use tauri::{AppHandle, Manager as _, Runtime};

use crate::account::{Account, AccountSlot};

/// Where the desk finds the account on this device, when it has one.
pub type AccountSource =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Arc<Account>>> + Send>> + Send + Sync>;

/// What the desk keeps of one host.
struct Kept {
    keeper: Arc<LeaseKeeper>,
    /// The interval the organisation's service advised with the lease the host holds.
    advised: Duration,
    /// Whether this application's own connection to the host is keeping the lease, in which case a
    /// connection made beside it needs to present nothing.
    refreshing: bool,
}

struct Inner {
    account: AccountSource,
    timer: Arc<dyn LeaseTimer>,
    hosts: Mutex<BTreeMap<DeviceId, Kept>>,
}

/// What gets a member's lease for the connections of a device.
#[derive(Clone)]
pub struct LeaseDesk {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for LeaseDesk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LeaseDesk")
    }
}

/// Clears the mark that a connection is keeping a host's lease, however that connection ends.
struct Refreshing<'a> {
    desk: &'a LeaseDesk,
    host: DeviceId,
}

impl Drop for Refreshing<'_> {
    fn drop(&mut self) {
        if let Some(kept) = self.desk.hosts().get_mut(&self.host) {
            kept.refreshing = false;
        }
    }
}

/// The refusal a lease that cannot be got is reported as, which the connection says to the person.
fn refused(stop: &LeaseStop) -> LinkError {
    LinkError::Refused(ProtocolError::new(stop.code(), stop.to_string()))
}

impl LeaseDesk {
    /// A desk that finds the account with `account` and waits by `timer`.
    #[must_use]
    pub fn new(account: AccountSource, timer: Arc<dyn LeaseTimer>) -> Self {
        Self {
            inner: Arc::new(Inner {
                account,
                timer,
                hosts: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    /// The desk this application uses: it finds the account in the application's own slot and
    /// waits in real time.
    #[must_use]
    pub fn for_app<R: Runtime>(app: &AppHandle<R>) -> Self {
        let app = app.clone();
        Self::new(
            Arc::new(move || {
                let app = app.clone();
                Box::pin(async move {
                    let slot = app.try_state::<AccountSlot>()?;
                    slot.get().await.ok().cloned()
                })
            }),
            Arc::new(RealTimer),
        )
    }

    fn hosts(&self) -> MutexGuard<'_, BTreeMap<DeviceId, Kept>> {
        self.inner
            .hosts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The keeper of `host`'s lease, made the first time it is asked for, or none for a host whose
    /// grant answers to no organisation.
    async fn keeper_of(
        &self,
        host: &PairedHost,
        key: AuthorisationKey,
    ) -> Result<Option<Arc<LeaseKeeper>>, LeaseStop> {
        let Some(requirement) = host.proposed_grant.organisation.as_ref() else {
            return Ok(None);
        };
        if let Some(kept) = self.hosts().get(&host.host_device_id) {
            return Ok(Some(Arc::clone(&kept.keeper)));
        }
        let Some(account) = (self.inner.account)().await else {
            return Err(LeaseStop::SignIn);
        };
        let http = HttpService::with(
            account.origin().clone(),
            HttpDeadlines::default(),
            managed_response_limits(),
        )
        .map_err(|error| {
            tracing::warn!(%error, "this device cannot reach its organisation's service");
            LeaseStop::Unreachable
        })?;
        let leases =
            ManagedMembershipLeaseService::new(account.origin(), Arc::new(http), account.tokens());
        let keeper = Arc::new(
            LeaseKeeper::new(
                Arc::new(leases),
                Arc::clone(&self.inner.timer),
                requirement.organisation_id,
                EnvironmentId::new(host.host_device_id.get()),
                key,
            )
            .reporting(|event| match event {
                LeaseEvent::Held { .. } => {}
                LeaseEvent::Retrying => {
                    tracing::debug!("the organisation's lease was not got this time");
                }
                LeaseEvent::Stopped(why) => {
                    tracing::warn!(%why, "this device holds no lease from its organisation");
                }
            }),
        );
        let mut hosts = self.hosts();
        let kept = hosts.entry(host.host_device_id).or_insert_with(|| Kept {
            keeper,
            advised: LONGEST_REFRESH,
            refreshing: false,
        });
        Ok(Some(Arc::clone(&kept.keeper)))
    }

    /// Keeps the lease the host holds for this device for as long as `session` lasts, and says why
    /// it stopped. Returns at once, with nothing to say, when the host's grant answers to no
    /// organisation.
    pub async fn keep(
        &self,
        session: &Session,
        host: &PairedHost,
        key: AuthorisationKey,
    ) -> Option<LeaseStop> {
        let keeper = self.keeper_of(host, key).await.ok().flatten()?;
        let advised = {
            let mut hosts = self.hosts();
            let kept = hosts.get_mut(&host.host_device_id)?;
            kept.refreshing = true;
            kept.advised
        };
        let _marked = Refreshing {
            desk: self,
            host: host.host_device_id,
        };
        Some(keeper.keep(session, advised).await)
    }
}

impl MembershipPresenter for LeaseDesk {
    fn present<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        key: AuthorisationKey,
    ) -> BoxFuture<'a, Result<(), LinkError>> {
        Box::pin(async move {
            let Some(keeper) = self
                .keeper_of(host, key)
                .await
                .map_err(|stop| refused(&stop))?
            else {
                return Ok(());
            };
            // The host holds one lease for the device, and the connection that keeps it fresh has
            // it there already.
            if self
                .hosts()
                .get(&host.host_device_id)
                .is_some_and(|kept| kept.refreshing)
            {
                return Ok(());
            }
            let advised = keeper
                .present_first(session)
                .await
                .map_err(|stop| refused(&stop))?;
            if let Some(kept) = self.hosts().get_mut(&host.host_device_id) {
                kept.advised = advised;
            }
            Ok(())
        })
    }
}
