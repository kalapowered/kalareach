//! What drafts sync can learn of a host: which sessions it holds, and where its privacy mode
//! stands, through the connection this application holds to it.
//!
//! Only the host the application is connected to can be asked. It is asked whether it holds a
//! session, which is how a draft comes to be known as that host's, and it is asked for its privacy
//! mode, which `privacy.status` gives only a device the host gave the right to manage it. Everything
//! else is a host this device cannot read, and its drafts stay on this device
//! ([`HostPrivacy::Unreadable`], [`Holds::Unknown`]).

use std::collections::BTreeSet;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::rights::ActionRight;
use kr_protocol::session::{SessionReadParams, SessionReadResult};
use tauri::{AppHandle, Manager as _, Runtime};

use super::drafts::{DraftHosts, Holds, HostPrivacy};
use crate::connection::{Connection, Standing};
use crate::drafts::DraftHost;
use crate::error::CommandError;
use crate::state::AppState;

/// How long the host is given to say where privacy mode stands.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The hosts this application is connected to.
pub struct ConnectedHosts<R: Runtime> {
    app: AppHandle<R>,
    /// The sessions the host of one environment said it does not hold, so that a draft of another
    /// host is not asked about again for as long as this application is connected to the same host.
    not_held: Mutex<(Option<EnvironmentId>, BTreeSet<SessionId>)>,
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

    fn remember_not_held(&self, environment: EnvironmentId, session: SessionId) {
        let mut held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.0 != Some(environment) {
            *held = (Some(environment), BTreeSet::new());
        }
        held.1.insert(session);
    }

    fn known_not_held(&self, environment: EnvironmentId, session: SessionId) -> bool {
        let held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.0 == Some(environment) && held.1.contains(&session)
    }
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

impl<R: Runtime> DraftHosts for ConnectedHosts<R> {
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
            if self.known_not_held(host.environment, session) {
                return Holds::NotHere;
            }
            let asked = tokio::time::timeout(
                ANSWER_WITHIN,
                connection.session().read::<_, SessionReadResult>(
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
                Ok(Err(error)) => match CommandError::from(error).code {
                    ErrorCode::SessionClosed => Holds::Here(host),
                    ErrorCode::UnknownSession => {
                        self.remember_not_held(host.environment, session);
                        Holds::NotHere
                    }
                    _ => Holds::Unknown,
                },
                Err(_) => Holds::Unknown,
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
