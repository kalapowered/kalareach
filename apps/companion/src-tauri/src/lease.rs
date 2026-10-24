//! A member's lease on the host this device is paired with.
//!
//! A device whose grant answers to an organisation is refused every method but the presentation of
//! a lease until the host holds one, `pair.status` and `host.info` included, and no lease survives
//! a host's restart. So the lease is presented as the first thing on every connection this device
//! makes to such a host as a paired device, before anything is read of it ([`LeaseDesk`] is the
//! link's [`MembershipPresenter`]), and kept on the interval the organisation's service advises for
//! as long as the application's own connection to the host lasts ([`LeaseDesk::keep`]). The
//! application's standing links to a host's sessions open a transport of their own and present
//! nothing: they rely on the lease the application's own connection keeps.
//!
//! The lease is the device's own: the organisation signs it for the account signed in and for this
//! device's authorisation key, and the host accepts it only on a connection that proves that key.
//! Which organisation is the one the host's grant names, kept with the pairing. The host holds one
//! lease for the device, not one for each connection, so the desk keeps one keeper for each host
//! and every connection to it presents the lease that keeper holds again while it lasts, asking the
//! organisation's service for another only when none is held or the host refuses the one that is.
//!
//! A keeper belongs to the account signed in when it was made, and to that sign-in: when another
//! account signs in, or the account signs out, the keeper of a connection that keeps a lease ends
//! it at once, and no lease or request of the first is presented for the second. A person who signs
//! in again as the same account gets a keeper with nothing held against it.
//!
//! Every connection to such a host is bound to the sign-in in force when it is opened
//! ([`LeaseDesk::bind`], called by the link for each one it makes): the main connection, a visit, a
//! session link, a terminal view, the owner watcher's session and a push run's line end the moment
//! that sign-in is not the one in force ([`crate::bound`]), and a connection is not opened at all
//! while no account is signed in. A connection that presents no lease of its own serves the person
//! only while the keeper of its sign-in holds a lease the host took.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kr_client::organisation::{LeaseEvent, LeaseKeeper, LeaseStop, LeaseTimer, RealTimer};
use kr_client::pairing::BoxFuture;
use kr_client::pairing::link::{LinkError, MembershipPresenter, Presentation};
use kr_client::pairing::paired::PairedHost;
use kr_client::services::account::AccountStatus;
use kr_client::services::{
    AccountMark, HttpDeadlines, HttpService, ManagedMembershipLeaseService, managed_response_limits,
};
use kr_client::session::Session;
use kr_client::transport::ControlTransport;
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{DeviceId, EnvironmentId, OrganisationId};
use kr_protocol::scalars::AuthorisationKey;
use kr_transport::handshake::LocalIdentity;
use tauri::{AppHandle, Manager as _, Runtime};

use crate::account::{Account, AccountSlot};
use crate::bound::{BoundTransport, LeaseGate};

/// Where the desk finds the account on this device, when it has one.
pub type AccountSource =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Option<Arc<Account>>> + Send>> + Send + Sync>;

/// What the desk keeps of one host: the keeper, and what it was made for.
struct Kept {
    keeper: Arc<LeaseKeeper>,
    organisation: OrganisationId,
    key: AuthorisationKey,
    /// Which account, at which service, the keeper asks as. A keeper holds a lease signed for one
    /// account, and the application keeps one `Account` whoever is signed in to it, so another
    /// account gets a keeper of its own.
    account: AccountMark,
    /// Which sign-in the keeper was made under, the same through a grant's refreshes and another
    /// for any later sign-in, even of the same account: what the keeper has held against the
    /// account is not held against a sign-in made since.
    sign_in: String,
}

impl Kept {
    fn is_for(
        &self,
        organisation: OrganisationId,
        key: AuthorisationKey,
        account: AccountMark,
        sign_in: &str,
    ) -> bool {
        self.organisation == organisation
            && self.key == key
            && self.account == account
            && self.sign_in == sign_in
    }
}

/// The account signed in, which sign-in it is, and which account it marks.
struct SignedIn {
    account: Arc<Account>,
    sign_in: String,
    mark: AccountMark,
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

/// The failure a lease that cannot be got is reported as, which the connection says to the person.
/// It is not the host's word about what it was asked: a stop can be the organisation's service, this
/// device's account, or the host's refusal of the lease it was given. A connection that ended under
/// the presentation is the one thing it says of the host: it was lost.
fn failed(stop: &LeaseStop) -> LinkError {
    match stop {
        LeaseStop::ConnectionEnded => LinkError::Lost(stop.to_string()),
        other => LinkError::Membership(ProtocolError::new(other.code(), other.to_string())),
    }
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

    /// Lets go of what is kept for `host`: a host this computer forgets takes its lease with it.
    pub fn forget(&self, host: DeviceId) {
        self.hosts().remove(&host);
    }

    /// The account signed in on this device, which sign-in it is and which account it marks.
    async fn signed_in(&self) -> Result<SignedIn, LeaseStop> {
        let Some(account) = (self.inner.account)().await else {
            return Err(LeaseStop::SignIn);
        };
        Self::read(account)
    }

    /// Which sign-in is in force on `account` and which account it marks.
    fn read(account: Arc<Account>) -> Result<SignedIn, LeaseStop> {
        let tokens = account.tokens();
        let unreadable = |error: &dyn std::fmt::Display| {
            tracing::warn!(%error, "this device cannot read which account is signed in");
            LeaseStop::Unreachable
        };
        let sign_in = match tokens.status() {
            Ok(AccountStatus::SignedIn { generation, .. }) => generation,
            Ok(_) => return Err(LeaseStop::SignIn),
            Err(error) => return Err(unreadable(&error)),
        };
        let mark = match tokens.mark(account.origin().as_str()) {
            Ok(Some(mark)) => mark,
            Ok(None) => return Err(LeaseStop::SignIn),
            Err(error) => return Err(unreadable(&error)),
        };
        Ok(SignedIn {
            account,
            sign_in,
            mark,
        })
    }

    /// Whether the keeper of `host`'s lease for this sign-in holds a lease the host took, and
    /// otherwise the stop that says why not.
    fn holds_a_lease(
        &self,
        host: DeviceId,
        organisation: OrganisationId,
        key: AuthorisationKey,
        mark: AccountMark,
        sign_in: &str,
    ) -> Result<(), LeaseStop> {
        match self.hosts().get(&host) {
            Some(kept) if kept.is_for(organisation, key, mark, sign_in) => {
                if kept.keeper.took_a_lease() {
                    Ok(())
                } else {
                    Err(kept.keeper.why_no_lease())
                }
            }
            _ => Err(LeaseStop::Unreachable),
        }
    }

    /// The keeper of `host`'s lease, made the first time it is asked for and again when the
    /// organisation, this device's key or the account signed in is not the one it was made for, or
    /// when the person has signed in since; none for a host whose grant answers to no organisation.
    async fn keeper_of(
        &self,
        host: &PairedHost,
        key: AuthorisationKey,
    ) -> Result<Option<Arc<LeaseKeeper>>, LeaseStop> {
        let Some(requirement) = host.proposed_grant.organisation.as_ref() else {
            return Ok(None);
        };
        let organisation = requirement.organisation_id;
        let SignedIn {
            account,
            sign_in,
            mark,
        } = match self.signed_in().await {
            Ok(signed) => signed,
            Err(stop) => {
                if stop == LeaseStop::SignIn {
                    self.forget(host.host_device_id);
                }
                return Err(stop);
            }
        };
        if let Some(kept) = self.hosts().get(&host.host_device_id)
            && kept.is_for(organisation, key, mark, &sign_in)
        {
            return Ok(Some(Arc::clone(&kept.keeper)));
        }
        // A first presentation is waited for by a person and by callers that allow ten seconds, so
        // one request is not given the twenty seconds a background request is.
        let http = HttpService::with(
            account.origin().clone(),
            HttpDeadlines {
                connect: Duration::from_secs(3),
                read: Duration::from_secs(5),
                total: Duration::from_secs(5),
            },
            managed_response_limits(),
        )
        .map_err(|error| {
            tracing::warn!(%error, "this device cannot reach its organisation's service");
            LeaseStop::Unreachable
        })?;
        let leases = ManagedMembershipLeaseService::new(
            account.origin(),
            Arc::new(http),
            account.tokens(),
            mark,
        );
        let made = Arc::new(
            LeaseKeeper::new(
                Arc::new(leases),
                Arc::clone(&self.inner.timer),
                organisation,
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
        // Two connections that both found none made one each: the one that is kept first is the
        // one both use, so they share the lease it holds and the stop it remembers.
        let mut hosts = self.hosts();
        if let Some(kept) = hosts.get(&host.host_device_id)
            && kept.is_for(organisation, key, mark, &sign_in)
        {
            return Ok(Some(Arc::clone(&kept.keeper)));
        }
        hosts.insert(
            host.host_device_id,
            Kept {
                keeper: Arc::clone(&made),
                organisation,
                key,
                account: mark,
                sign_in,
            },
        );
        Ok(Some(made))
    }

    /// Keeps the lease the host holds for this device for as long as `session` lasts, and says why
    /// it stopped, among them that no account can ask for it. Returns at once, with nothing to say,
    /// when the host's grant answers to no organisation. The connection itself ends with the
    /// account it was opened under, whatever the keeper is doing ([`Self::bind`]).
    pub async fn keep(
        &self,
        session: &Session,
        host: &PairedHost,
        key: AuthorisationKey,
    ) -> Option<LeaseStop> {
        match self.keeper_of(host, key).await {
            Ok(Some(keeper)) => Some(keeper.keep(session).await),
            Ok(None) => None,
            Err(stop) => Some(stop),
        }
    }
}

/// The failure a lease stop is when the session the stop happened on says this device ended it for
/// the account's sake: the account's words, not that the connection was lost.
fn failed_on(session: &Session, stop: &LeaseStop) -> LinkError {
    if *stop == LeaseStop::ConnectionEnded
        && let Some(error) = session.transport().ended_by_this_device()
    {
        return LinkError::Membership(error);
    }
    failed(stop)
}

impl MembershipPresenter for LeaseDesk {
    fn bind<'a>(
        &'a self,
        host: &'a PairedHost,
        identity: &'a LocalIdentity,
        dial: BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>>,
    ) -> BoxFuture<'a, Result<Arc<dyn ControlTransport>, LinkError>> {
        Box::pin(async move {
            let Some(requirement) = host.proposed_grant.organisation.as_ref() else {
                return dial.await;
            };
            let organisation = requirement.organisation_id;
            let Some(account) = (self.inner.account)().await else {
                self.forget(host.host_device_id);
                return Err(failed(&LeaseStop::SignIn));
            };
            // Subscribed before the sign-in is read, so a change between the two is heard.
            let tokens = account.tokens();
            let (gate_changes, task_changes) = (tokens.subscribe(), tokens.subscribe());
            let signed = Self::read(account).map_err(|stop| {
                if stop == LeaseStop::SignIn {
                    self.forget(host.host_device_id);
                }
                failed(&stop)
            })?;
            let key = *identity.authorisation.public();
            let transport = dial.await?;
            let lease: LeaseGate = {
                let desk = self.clone();
                let (host_id, mark, sign_in) =
                    (host.host_device_id, signed.mark, signed.sign_in.clone());
                Arc::new(move || desk.holds_a_lease(host_id, organisation, key, mark, &sign_in))
            };
            let bound =
                BoundTransport::over(transport, signed.sign_in, gate_changes, task_changes, lease);
            // The account may have left while the connection was dialled: nothing is opened.
            match bound.ended_by_this_device() {
                Some(error) => Err(LinkError::Membership(error)),
                None => Ok(bound),
            }
        })
    }

    fn present<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        key: AuthorisationKey,
        presentation: Presentation,
    ) -> BoxFuture<'a, Result<(), LinkError>> {
        Box::pin(async move {
            let Some(keeper) = self
                .keeper_of(host, key)
                .await
                .map_err(|stop| failed(&stop))?
            else {
                return Ok(());
            };
            match presentation {
                Presentation::First => keeper.present_first(session).await,
                Presentation::IfDue => keeper.present_if_due(session).await,
            }
            .map_err(|stop| failed_on(session, &stop))
        })
    }
}
