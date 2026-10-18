//! What drafts sync can read of a host's privacy mode: through the connection this application holds
//! to it.
//!
//! Only the host the application is connected to can be asked, and only by a device the host gave the
//! right to manage it, which is what `privacy.status` requires. Everything else is a host this
//! device cannot read, and its drafts stay on this device ([`HostPrivacy::Unreadable`]).

use std::time::Duration;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::rights::ActionRight;
use tauri::{AppHandle, Manager as _, Runtime};

use super::drafts::{DraftHosts, HostPrivacy};
use crate::connection::Standing;
use crate::error::CommandError;
use crate::state::AppState;

/// How long the host is given to say where privacy mode stands.
const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// The hosts this application is connected to.
pub struct ConnectedHosts<R: Runtime> {
    app: AppHandle<R>,
}

impl<R: Runtime> ConnectedHosts<R> {
    /// The hosts of `app`.
    #[must_use]
    pub const fn new(app: AppHandle<R>) -> Self {
        Self { app }
    }
}

fn unreadable(reason: impl Into<String>) -> HostPrivacy {
    HostPrivacy::Unreadable {
        reason: reason.into(),
    }
}

impl<R: Runtime> DraftHosts for ConnectedHosts<R> {
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
