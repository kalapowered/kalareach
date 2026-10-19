//! What drafts sync can learn of a host: which sessions it holds, and where its privacy mode
//! stands, through the connection this application holds to it.
//!
//! Only the host the application is connected to can be asked. It is asked whether it holds a
//! session, which is how a draft comes to be known as that host's, and it is asked for its privacy
//! mode, which `privacy.status` gives only a device the host gave the right to manage it.
//! Everything else is a host this device cannot read, and its drafts stay on this device
//! ([`HostPrivacy::Unreadable`], [`Holds::Unknown`]).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_client::pairing::link::LinkError;
use kr_client::{ClientError, Session};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::rights::ActionRight;
use kr_protocol::session::{SessionReadParams, SessionReadResult};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult};
use tauri::{AppHandle, Manager as _, Runtime};

use super::drafts::{Holds, HostLists, HostPrivacy, Hosts};
use crate::connection::{Connection, Replacer, Standing};
use crate::drafts::DraftHost;
use crate::error::CommandError;
use crate::state::AppState;

/// How long the host is given to say where privacy mode stands.
pub(crate) const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// One connection to one host: a reconnection to the same host is another. The session is held
/// weakly, so its address is not given to another while the cache names it.
type Link = (EnvironmentId, Weak<Session>);

/// The hosts this application is connected to.
pub struct ConnectedHosts<R: Runtime> {
    app: AppHandle<R>,
    /// The sessions the host of one connection said it does not hold, so that a draft of another
    /// host is not asked about again for as long as this application keeps that connection.
    not_held: Mutex<(Option<Link>, BTreeSet<SessionId>)>,
}

impl<R: Runtime> ConnectedHosts<R> {
    /// The hosts of `app`.
    #[must_use]
    pub fn new(app: AppHandle<R>) -> Self {
        Self {
            app,
            not_held: Mutex::new((None, BTreeSet::new())),
        }
    }

    fn remember_not_held(
        &self,
        environment: EnvironmentId,
        over: &Arc<Session>,
        session: SessionId,
    ) {
        let mut held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !is_link(held.0.as_ref(), environment, over) {
            *held = (Some((environment, Arc::downgrade(over))), BTreeSet::new());
        }
        held.1.insert(session);
    }

    fn known_not_held(
        &self,
        environment: EnvironmentId,
        over: &Arc<Session>,
        session: SessionId,
    ) -> bool {
        let held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        is_link(held.0.as_ref(), environment, over) && held.1.contains(&session)
    }
}

/// Whether a refusal says the host will answer no question now, and not only this one.
fn refuses_everything(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::RateLimited
            | ErrorCode::EnvironmentUnavailable
            | ErrorCode::UpstreamUnavailable
            | ErrorCode::StorageUnavailable
    )
}

/// Whether `link` is the connection `over` makes to the host of `environment`.
fn is_link(link: Option<&Link>, environment: EnvironmentId, over: &Arc<Session>) -> bool {
    link.is_some_and(|(held, session)| {
        *held == environment
            && session
                .upgrade()
                .is_some_and(|open| Arc::ptr_eq(&open, over))
    })
}

/// The host a connection is to: the environment its sessions live in, and what it is called.
fn host_of(connection: &Connection) -> DraftHost {
    let name = match connection.standing() {
        Standing::Owner => Some("this computer".to_owned()),
        Standing::Paired { host, .. } => host.name.clone(),
    };
    DraftHost {
        environment: connection.environment_id(),
        name,
    }
}

fn unreadable(reason: impl Into<String>) -> HostPrivacy {
    HostPrivacy::Unreadable {
        reason: reason.into(),
    }
}

/// What a host said when asked for its devices.
pub(crate) enum Listing {
    /// Its list.
    Listed(DeviceListResult),
    /// It answered that this device may not list its devices, as a host does once the grant that
    /// gave the right has run out or been revoked. Such a host is not this computer's to ask, and
    /// is not one that failed to answer.
    Refused,
    /// It did not answer in time, could not be reached, or refused for a reason that says nothing
    /// of its devices.
    Silent,
    /// The connection it was asked over has ended, which says nothing of the host: a connection
    /// that was replaced while a caller still held a copy of it.
    Ended,
}

impl Listing {
    /// What a refusal with `code` says. Only the refusal to list the host's devices to this
    /// computer is an answer about them. A host that refuses for another reason, such as a protocol
    /// this computer does not speak or a limit it has reached, may be the one that lists a device,
    /// so it counts as one that did not answer.
    fn of_refusal(code: ErrorCode) -> Self {
        if code == ErrorCode::PermissionDenied {
            Self::Refused
        } else {
            Self::Silent
        }
    }

    /// What a failed connection to a host says. A host that does not find this computer paired
    /// answers the hello as it would an unpaired peer, which this computer ends itself, so it
    /// reads as a connection lost, as a host that is asleep does.
    pub(crate) fn of_link(error: &LinkError) -> Self {
        match error {
            LinkError::Refused(refusal) => Self::of_refusal(refusal.code),
            _ => Self::Silent,
        }
    }
}

/// What a host lists as its devices, asked over `session`.
pub(crate) async fn listed(session: &Arc<Session>) -> Listing {
    let asked = tokio::time::timeout(
        ANSWER_WITHIN,
        session.read::<_, DeviceListResult>(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        ),
    )
    .await;
    match asked {
        Ok(Ok(list)) => Listing::Listed(list),
        Ok(Err(ClientError::Host(refused))) => Listing::of_refusal(refused.code),
        Ok(Err(ClientError::ConnectionEnded)) => Listing::Ended,
        Ok(Err(_)) | Err(_) => Listing::Silent,
    }
}

/// What the host on this computer lists of its devices, asked over the connection this application
/// holds to it.
///
/// A revocation withdraws the connections the host admitted before it, and the host answers every
/// request on one with a refusal that says to open a new connection. It does not close it, so a
/// connection that is held and not asked for what it is refused goes on being refused. When the
/// host refuses this connection, it is asked again over another; when that lists, the refused
/// connection was withdrawn, and `replace` puts the other in its place and ends it. A connection
/// that has ended, because a caller held a copy of one that was replaced, is asked about the same
/// way. What a fresh connection is answered is the host's word; one that cannot be opened says
/// nothing of the host.
pub(crate) async fn listed_replacing(connection: &Connection, replace: &Replacer) -> Listing {
    if !matches!(connection.standing(), Standing::Owner) {
        return listed(&connection.session()).await;
    }
    let listing = listed(&connection.session()).await;
    if !matches!(listing, Listing::Refused | Listing::Ended) {
        return listing;
    }
    match tokio::time::timeout(ANSWER_WITHIN, connection.another()).await {
        Ok(Ok(fresh)) => {
            let listing = listed(&fresh.session()).await;
            if matches!(listing, Listing::Listed(_)) {
                replace(&connection.session(), fresh);
            }
            listing
        }
        _ => Listing::Silent,
    }
}

impl<R: Runtime> Hosts for ConnectedHosts<R> {
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let mut found = HostLists::default();
            let mut asked = None;
            if let Ok(connection) = state.connection() {
                // The connection this application holds to a host is asked over, when the right
                // to list the host's devices is the one it holds. A host that is not this
                // computer's to manage lists nothing to it, and its silence means nothing.
                let owns = match connection.standing() {
                    Standing::Owner => true,
                    Standing::Paired { rights, .. } => rights.contains(&ActionRight::HostManage),
                };
                if owns {
                    match listed_replacing(&connection, &state.replacer()).await {
                        Listing::Listed(list) => found.lists.push(list),
                        Listing::Refused => found.refused = true,
                        Listing::Silent | Listing::Ended => found.silent = true,
                    }
                }
                if let Standing::Paired { host, .. } = connection.standing() {
                    asked = Some(host.host_device_id);
                }
            }
            // The other hosts this computer owns, each on a connection made for the question and
            // let go after it. They are asked at the same time, so that a host that is asleep
            // keeps the others waiting for one wait and not for each.
            // A computer whose pairing records cannot be opened knows of no other host to ask.
            let Ok(device) = state.device() else {
                return found;
            };
            let visits: Vec<_> = device
                .owner_hosts()
                .into_iter()
                .filter(|host| asked != Some(host.host_device_id))
                .map(|host| {
                    let device = Arc::clone(&device);
                    tauri::async_runtime::spawn(async move {
                        let pairing = device.pairing();
                        let identity = pairing.candidate.paired_identity(host.device_id);
                        let visit = async {
                            match pairing.link.connect_paired(&host, &identity).await {
                                Ok(session) => listed(&Arc::new(session)).await,
                                Err(error) => Listing::of_link(&error),
                            }
                        };
                        tokio::time::timeout(ANSWER_WITHIN, visit)
                            .await
                            .unwrap_or(Listing::Silent)
                    })
                })
                .collect();
            for visit in visits {
                match visit.await {
                    Ok(Listing::Listed(list)) => found.lists.push(list),
                    Ok(Listing::Refused) => found.refused = true,
                    Ok(Listing::Silent | Listing::Ended) | Err(_) => found.silent = true,
                }
            }
            found
        })
    }

    fn holds(
        &self,
        session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let Ok(connection) = state.connection() else {
                return Holds::Unknown;
            };
            let host = host_of(&connection);
            let over = connection.session();
            if self.known_not_held(host.environment, &over, session) {
                return Holds::NotHere;
            }
            let asked = tokio::time::timeout(
                ANSWER_WITHIN,
                over.read::<_, SessionReadResult>(
                    Method::SessionRead,
                    &SessionReadParams {
                        session_id: session,
                    },
                ),
            )
            .await;
            match asked {
                // A session that has closed is still the host's: the draft was written for it.
                Ok(Ok(_)) => Holds::Here(host),
                Ok(Err(ClientError::Host(refused))) => match refused.code {
                    ErrorCode::SessionClosed => Holds::Here(host),
                    ErrorCode::UnknownSession => {
                        self.remember_not_held(host.environment, &over, session);
                        Holds::NotHere
                    }
                    // A host too busy or unavailable to say asks for no more questions; one that
                    // refuses to say about this session, or cannot reach that session's worker,
                    // may still say about another.
                    code if refuses_everything(code) => Holds::Unknown,
                    _ => Holds::Refused,
                },
                Ok(Err(_)) | Err(_) => Holds::Unknown,
            }
        })
    }

    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let Ok(connection) = state.connection() else {
                return unreadable("this computer is not connected to a host");
            };
            if connection.environment_id() != environment {
                return unreadable("this computer is not connected to that host");
            }
            // The host checks the right again. Asking without it only fills the log with a refusal.
            if let Standing::Paired { rights, .. } = connection.standing()
                && !rights.contains(&ActionRight::HostManage)
            {
                return unreadable("this device holds no right to read the host's privacy mode");
            }
            let asked = tokio::time::timeout(
                ANSWER_WITHIN,
                connection
                    .session()
                    .read::<_, PrivacyReport>(Method::PrivacyStatus, &PrivacyStatusParams {}),
            )
            .await;
            match asked {
                Err(_) => unreadable("the host did not say where privacy mode stands in time"),
                Ok(Err(error)) => {
                    let error = CommandError::from(error);
                    if error.code == ErrorCode::PermissionDenied {
                        unreadable("the host does not let this device read its privacy mode")
                    } else {
                        unreadable(error.message)
                    }
                }
                Ok(Ok(report)) if report.enabled => HostPrivacy::On {
                    generation: report.generation.get(),
                },
                Ok(Ok(report)) => HostPrivacy::Off {
                    generation: report.generation.get(),
                },
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A session whose worker cannot be reached is refused as unavailable, and that says nothing of
    /// the host's other sessions; a host that is rate limited answers none.
    #[test]
    fn a_session_that_cannot_be_reached_does_not_end_the_questions_about_the_others() {
        assert!(!refuses_everything(ErrorCode::ResourceUnavailable));
        assert!(!refuses_everything(ErrorCode::PermissionDenied));
        assert!(refuses_everything(ErrorCode::RateLimited));
        assert!(refuses_everything(ErrorCode::EnvironmentUnavailable));
    }

    /// A host that refuses to list its devices to this computer has answered. One that refuses for
    /// another reason, or whose connection ends, has not: it may be the host that lists a device.
    #[test]
    fn only_a_refusal_to_list_the_hosts_devices_is_an_answer() {
        let refused = |code| LinkError::Refused(kr_protocol::error::ProtocolError::new(code, "no"));
        assert!(matches!(
            Listing::of_link(&refused(ErrorCode::PermissionDenied)),
            Listing::Refused
        ));
        for code in [
            ErrorCode::UnsupportedSchema,
            ErrorCode::RateLimited,
            ErrorCode::EnvironmentUnavailable,
        ] {
            assert!(
                matches!(Listing::of_link(&refused(code)), Listing::Silent),
                "{code} says nothing of the host's devices"
            );
        }
        assert!(matches!(
            Listing::of_link(&LinkError::Lost("gone".to_owned())),
            Listing::Silent
        ));
    }
}
