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
//! A connection is bound to the account it was opened under, which is read before it is dialled
//! ([`LeaseDesk::account_of`]) and not when its keeper starts: an account that signs in between
//! the connection's presentation and its keeper ends the connection when the keeper starts
//! ([`LeaseDesk::keep`]), and whoever uses a connection for more than its opening asks whether the
//! account is still the one ([`LeaseDesk::still_under`]).

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
use kr_protocol::error::ProtocolError;
use kr_protocol::ids::{DeviceId, EnvironmentId, OrganisationId};
use kr_protocol::scalars::AuthorisationKey;
use tauri::{AppHandle, Manager as _, Runtime};

use crate::account::{Account, AccountSlot};

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

/// A keeper and the account it asks as.
struct Keeping {
    keeper: Arc<LeaseKeeper>,
    account: Arc<Account>,
    mark: AccountMark,
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

    /// Lets go of what is kept for `host` when it was kept for the account `mark`: that account
    /// signed out, or another signed in.
    fn forget_account(&self, host: DeviceId, mark: AccountMark) {
        let mut hosts = self.hosts();
        if hosts.get(&host).is_some_and(|kept| kept.account == mark) {
            hosts.remove(&host);
        }
    }

    /// The account signed in on this device, which sign-in it is and which account it marks.
    async fn signed_in(&self) -> Result<SignedIn, LeaseStop> {
        let Some(account) = (self.inner.account)().await else {
            return Err(LeaseStop::SignIn);
        };
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

    /// The account a connection to `host` is opened under, read before the connection is dialled:
    /// none when the host's grant answers to no organisation, or no account is signed in.
    pub async fn account_of(&self, host: &PairedHost) -> Option<AccountMark> {
        host.proposed_grant.organisation.as_ref()?;
        self.signed_in().await.ok().map(|signed| signed.mark)
    }

    /// Whether the account signed in is still the one `under` marks, the account a connection to
    /// `host` was opened under. Nothing to ask of a host whose grant answers to no organisation.
    ///
    /// # Errors
    ///
    /// Returns why the connection is no longer the account's: it signed out, or another account is
    /// signed in, or none was when the connection was opened.
    pub async fn still_under(
        &self,
        host: &PairedHost,
        under: Option<AccountMark>,
    ) -> Result<(), LeaseStop> {
        if host.proposed_grant.organisation.as_ref().is_none() {
            return Ok(());
        }
        let signed = self.signed_in().await?;
        match under {
            Some(under) if under == signed.mark => Ok(()),
            _ => Err(LeaseStop::AccountChanged),
        }
    }

    /// The keeper of `host`'s lease, made the first time it is asked for and again when the
    /// organisation, this device's key or the account signed in is not the one it was made for, or
    /// when the person has signed in since; none for a host whose grant answers to no organisation.
    async fn keeper_of(
        &self,
        host: &PairedHost,
        key: AuthorisationKey,
    ) -> Result<Option<Keeping>, LeaseStop> {
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
            return Ok(Some(Keeping {
                keeper: Arc::clone(&kept.keeper),
                account,
                mark,
            }));
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
            return Ok(Some(Keeping {
                keeper: Arc::clone(&kept.keeper),
                account,
                mark,
            }));
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
        Ok(Some(Keeping {
            keeper: made,
            account,
            mark,
        }))
    }

    /// Keeps the lease the host holds for this device for as long as `session` lasts, and says why it
    /// stopped, among them that no account can ask for it, or that the account the connection was
    /// opened under (`under`, from [`Self::account_of`]) signed out or was replaced by another, which
    /// ends it at once, though the replacement came before the keeper did. Returns at once, with
    /// nothing to say, when the host's grant answers to no organisation.
    pub async fn keep(
        &self,
        session: &Session,
        host: &PairedHost,
        key: AuthorisationKey,
        under: Option<AccountMark>,
    ) -> Option<LeaseStop> {
        let keeping = match self.keeper_of(host, key).await {
            Ok(Some(keeping)) => keeping,
            Ok(None) => return None,
            Err(stop) => return Some(stop),
        };
        let Keeping {
            keeper,
            account,
            mark,
        } = keeping;
        // The lease the connection presented was the account's that was signed in when it was
        // opened: if another is signed in now, the keeper that is made for it is not the one that
        // presented.
        let Some(under) = under.filter(|under| *under == mark) else {
            return Some(LeaseStop::AccountChanged);
        };
        let stop = tokio::select! {
            stop = keeper.keep(session) => stop,
            stop = account_left(&account, under) => {
                self.forget_account(host.host_device_id, under);
                stop
            }
        };
        Some(stop)
    }
}

/// Returns when the account signed in is no longer the one `mark` marks: it signed out, or another
/// signed in. Never returns while it is, and never returns if the account is not read.
async fn account_left(account: &Account, mark: AccountMark) -> LeaseStop {
    let tokens = account.tokens();
    let mut changes = tokens.subscribe();
    loop {
        match tokens.mark(account.origin().as_str()) {
            Ok(Some(signed_in)) if signed_in == mark => {}
            Ok(Some(_)) => return LeaseStop::AccountChanged,
            Ok(None) => return LeaseStop::SignIn,
            // Unreadable now: the keeper's own requests find out when they are made.
            Err(_) => {}
        }
        if changes.changed().await.is_err() {
            return std::future::pending().await;
        }
    }
}

impl MembershipPresenter for LeaseDesk {
    fn present<'a>(
        &'a self,
        session: &'a Session,
        host: &'a PairedHost,
        key: AuthorisationKey,
        presentation: Presentation,
    ) -> BoxFuture<'a, Result<(), LinkError>> {
        Box::pin(async move {
            let Some(keeping) = self
                .keeper_of(host, key)
                .await
                .map_err(|stop| failed(&stop))?
            else {
                return Ok(());
            };
            match presentation {
                Presentation::First => keeping.keeper.present_first(session).await,
                Presentation::IfDue => keeping.keeper.present_if_due(session).await,
            }
            .map_err(|stop| failed(&stop))
        })
    }
}
