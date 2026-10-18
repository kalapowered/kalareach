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
use crate::connection::{Connection, Standing};
use crate::drafts::DraftHost;
use crate::error::CommandError;
use crate::state::AppState;

/// How long the host is given to say where privacy mode stands.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

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

/// What a host lists as its devices, asked over `session`, or nothing when it does not say in time
/// or does not let this device ask (listing devices needs the right to manage the host).
async fn listed(session: &Arc<Session>) -> Option<DeviceListResult> {
    tokio::time::timeout(
        ANSWER_WITHIN,
        session.read::<_, DeviceListResult>(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: true,
            },
        ),
    )
    .await
    .ok()?
    .ok()
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
                    match listed(&connection.session()).await {
                        Some(list) => found.lists.push(list),
                        None => found.silent = true,
                    }
                }
                if let Standing::Paired { host, .. } = connection.standing() {
                    asked = Some(host.host_device_id);
                }
            }
            // The other hosts this computer owns, each on a connection made for the question and
            // let go after it. They are asked at the same time, so that a host that is asleep
            // keeps the others waiting for one wait and not for each.
            let Ok(device) = state.device() else {
                found.silent = true;
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
                            let session =
                                pairing.link.connect_paired(&host, &identity).await.ok()?;
                            listed(&Arc::new(session)).await
                        };
                        tokio::time::timeout(ANSWER_WITHIN, visit)
                            .await
                            .ok()
                            .flatten()
                    })
                })
                .collect();
            for visit in visits {
                match visit.await {
                    Ok(Some(list)) => found.lists.push(list),
                    Ok(None) | Err(_) => found.silent = true,
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
}
