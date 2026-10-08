//! Reaching the host on this machine, and publishing what it says.
//!
//! The desktop application connects to the controller on its own machine over local IPC. That is
//! the only connection it makes on its own: pairing another host is an explicit act with its own
//! screen, and a client that dialled out at startup would be making a decision the person has not
//! made.
//!
//! When the connection cannot be made the application stays unconnected and says so. That is a
//! state the interface has to have anyway, because a host that stops answering produces it, and it
//! is the state section 13 is most specific about: a host that cannot be contacted is
//! disconnected, and nothing about elapsed time makes its processes failed.

use std::sync::Arc;

use kr_client::pairing::paired::PairedHost;
use kr_client::{Said as _, Session};
use kr_protocol::ids::{BuildId, DeviceId, EnvironmentId};
use kr_protocol::rights::ActionRight;
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Manager as _, Runtime};

use crate::device::Device;
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// How long a connection to a paired host, and the question that follows it, may take.
const CONNECT_WITHIN: std::time::Duration = std::time::Duration::from_secs(20);

/// The event the backend publishes each host notification on.
pub const HOST_EVENT: &str = "kr://event";

/// The event the backend publishes a change of connection state on.
pub const CONNECTION_EVENT: &str = "kr://connection";

/// The build this client declares in its handshake.
///
/// The host records it, and refuses a connection whose protocol major it does not share.
///
/// # Errors
///
/// Returns the failure when the compiled version is not a valid build identity, which is a
/// packaging mistake rather than a runtime condition.
pub fn build_id() -> Result<BuildId> {
    BuildId::new(concat!("kalareach-companion/", env!("CARGO_PKG_VERSION")))
        .map_err(|error| CommandError::local_failure(error.to_string()))
}

/// Who this application is on the host it reached, and what the host lets it do there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// The owner at this machine, over its own socket: every right.
    Owner,
    /// A device the host paired with: the rights its grant carries, as this device recorded them
    /// when it paired, under the identity the host gave it.
    Paired {
        /// The device identity the host gave this application.
        device_id: DeviceId,
        /// What its grant carries. The host checks each action against its own record again.
        rights: Vec<ActionRight>,
    },
}

/// A live connection to a host: the one on this machine, or one this device is paired with.
#[derive(Debug)]
pub struct Connection {
    session: Arc<Session>,
    environment_id: EnvironmentId,
    standing: Standing,
}

impl Connection {
    /// A connection over a local transport, belonging to the environment the host stamped on the
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns the client library's refusal to start a session on the transport.
    pub fn over(transport: kr_client::ipc::IpcTransport) -> Result<Self> {
        let environment_id = transport.context().environment_id;
        let session = Session::start(transport.shared())?;
        Ok(Self {
            session: Arc::new(session),
            environment_id,
            standing: Standing::Owner,
        })
    }

    /// A connection to a host this device is paired with, as the device the host made it.
    ///
    /// The environment is the one the host says it is, read over the connection: a paired
    /// connection carries no environment on its handshake.
    ///
    /// # Errors
    ///
    /// Returns the failure when the host cannot be reached or cannot say which environment it is.
    pub async fn paired(device: &Device, host: &PairedHost) -> Result<Self> {
        let pairing = device.pairing();
        let identity = pairing.candidate.paired_identity(host.device_id);
        let session =
            tokio::time::timeout(CONNECT_WITHIN, pairing.link.connect_paired(host, &identity))
                .await
                .map_err(|_| CommandError::unavailable("the host did not answer in time"))?
                .map_err(|error| CommandError::unavailable(error.said().into_string()))?;
        let info: kr_protocol::hostinfo::HostInfoResult = tokio::time::timeout(
            CONNECT_WITHIN,
            session.read(
                kr_protocol::method::Method::HostInfo,
                &crate::commands::NoParams {},
            ),
        )
        .await
        .map_err(|_| CommandError::unavailable("the host did not say which environment it is"))?
        .map_err(CommandError::from)?;
        Ok(Self {
            session: Arc::new(session),
            environment_id: info.environment_id,
            standing: Standing::Paired {
                device_id: host.device_id,
                rights: host.proposed_grant.actions.iter().copied().collect(),
            },
        })
    }

    /// Who this application is on the host, and what that lets it do.
    #[must_use]
    pub const fn standing(&self) -> &Standing {
        &self.standing
    }

    /// The session every command goes through.
    #[must_use]
    pub fn session(&self) -> Arc<Session> {
        Arc::clone(&self.session)
    }

    /// The environment this connection belongs to, as the host stamped it.
    ///
    /// It comes from the handshake rather than from the page: an environment the WebView named
    /// would be a value the WebView chose.
    #[must_use]
    pub const fn environment_id(&self) -> EnvironmentId {
        self.environment_id
    }
}

/// What the interface is told about the connection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConnectionState {
    /// True while a session is live.
    pub connected: bool,
    /// The environment the connection belongs to, when there is one.
    pub environment_id: Option<String>,
    /// Why there is no connection, in plain words, when there is none.
    pub reason: Option<String>,
    /// What this connection may do, when it is live.
    ///
    /// The connection is to the host on this machine, over its own socket, which authenticated the
    /// operating-system user this application runs as: the host's owner, whose authority is every
    /// action. A control whose visibility turns on a right is shown from this, and the host checks
    /// the right again when the action arrives.
    pub rights: Option<Vec<kr_protocol::rights::ActionRight>>,
}

impl ConnectionState {
    /// The state of an application that has not reached a host.
    #[must_use]
    pub fn unreachable(reason: impl Into<String>) -> Self {
        Self {
            connected: false,
            environment_id: None,
            reason: Some(reason.into()),
            rights: None,
        }
    }

    /// The state of a live connection to the host on this machine, in `environment_id`.
    #[must_use]
    pub fn owner(environment_id: EnvironmentId) -> Self {
        Self {
            connected: true,
            environment_id: Some(environment_id.to_string()),
            reason: None,
            rights: Some(kr_protocol::rights::ActionRight::ALL.to_vec()),
        }
    }

    /// The state of a live connection, with the rights its standing gives.
    #[must_use]
    pub fn of(connection: &Connection) -> Self {
        match &connection.standing {
            Standing::Owner => Self::owner(connection.environment_id),
            Standing::Paired { rights, .. } => Self {
                connected: true,
                environment_id: Some(connection.environment_id.to_string()),
                reason: None,
                rights: Some(rights.clone()),
            },
        }
    }
}

/// Connects to the controller on this machine.
///
/// # Errors
///
/// Returns the failure when there is no controller to reach, when its endpoint belongs to another
/// user, or when the two builds share no protocol major.
pub async fn connect_local() -> Result<Connection> {
    let paths = kr_ipc::paths::HostPaths::discover()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let environment_id = paths
        .open_environment_id()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let endpoint = paths
        .environment(environment_id)
        .controller_endpoint()
        .map_err(|error| CommandError::unavailable(format!("no host on this machine: {error}")))?;
    let transport = kr_client::ipc::IpcTransport::connect_app(&endpoint, build_id()?)
        .await
        .map_err(absent_host)?;
    Connection::over(transport)
}

/// Names the ordinary case of no host running before it reaches the window.
///
/// A socket that is not there, or that nothing is listening on, is not a fault in either build: it
/// is what this machine looks like before the host is started. The window has to say something,
/// and "no such file or directory" is the operating system talking about a path the person never
/// chose. Every other failure keeps its own words, because they describe something that did go
/// wrong.
fn absent_host(error: kr_client::error::ClientError) -> CommandError {
    if let kr_client::error::ClientError::Ipc(kr_ipc::IpcError::Socket { source, .. }) = &error
        && matches!(
            source.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        )
    {
        return CommandError::unavailable("no host on this machine");
    }
    CommandError::from(error)
}

/// One host notification, in the shape the interface reads.
#[derive(Clone, Debug, Serialize)]
pub struct PublishedEvent {
    /// The stream it belongs to.
    pub stream_id: String,
    /// Its position in that stream.
    pub sequence: String,
    /// What happened.
    pub event_type: String,
    /// The payload, as JSON.
    pub payload: serde_json::Value,
}

/// Reads an event payload into the shape the page reads.
///
/// The payload of an event is the canonical value the host sent, and its shape depends on the
/// event type. What crosses to the page is its JSON representation, which is the same form every
/// other answer arrives in. A payload that has no JSON representation is published as null beside
/// its event type, so the view still learns that the event happened and asks for a snapshot rather
/// than being handed something it cannot read.
fn read_payload(payload: &kr_protocol::envelope::ParamsValue) -> serde_json::Value {
    payload
        .to_typed::<serde_json::Value>()
        .unwrap_or(serde_json::Value::Null)
}

/// Publishes the session's events to the window until the connection ends, and then says so.
///
/// Every event carries the stream it came from, so a view that is showing one session can ignore
/// another's. A client that published events without their stream would leave each view guessing
/// whether an event was its own. When the connection ends the application is told it is not
/// connected, and its state says so, so a command made afterwards is refused as unconnected rather
/// than sent down a connection that is gone.
pub async fn forward_events<R: Runtime>(app: AppHandle<R>, session: Arc<Session>) {
    let mut events = session.events();
    loop {
        let heard = tokio::select! {
            heard = events.recv() => heard,
            () = session.closed() => {
                let state = app.state::<AppState>();
                state.disconnected_from(&session, "the connection to this host ended");
                let _ = app.emit(CONNECTION_EVENT, state.connection_state());
                return;
            }
        };
        match heard {
            Ok(notification) => {
                let published = PublishedEvent {
                    payload: read_payload(&notification.payload),
                    stream_id: notification.stream_id.to_string(),
                    sequence: notification.sequence.to_string(),
                    event_type: notification.event_type.to_string(),
                };
                if app.emit(HOST_EVENT, published).is_err() {
                    return;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                // The interface fell behind the host. Section 8 makes that a resynchronisation
                // rather than a gap to paper over, so the view is told to take a snapshot again
                // instead of receiving a stream with a hole in it.
                if app
                    .emit(
                        HOST_EVENT,
                        PublishedEvent {
                            stream_id: String::new(),
                            sequence: String::new(),
                            event_type: "resync_required".to_owned(),
                            payload: serde_json::Value::Null,
                        },
                    )
                    .is_err()
                {
                    return;
                }
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
        }
    }
}

/// Publishes the session's events to the window in a task of their own.
pub fn publish_events<R: Runtime>(app: AppHandle<R>, session: Arc<Session>) {
    tauri::async_runtime::spawn(forward_events(app, session));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_declared_build_identity_is_valid() {
        let build = build_id().expect("a valid build identity");
        assert!(build.as_str().starts_with("kalareach-companion/"));
    }

    /// KR-REQ-11.48: a live connection to the host on this machine says what it may do, in the
    /// protocol's own names, so a control whose visibility turns on a right is decided from a fact
    /// rather than a guess; a lost connection says nothing about rights at all.
    #[test]
    fn a_live_local_connection_carries_every_right_and_a_lost_one_none() {
        let environment: EnvironmentId = "3f1a2c40-11aa-4b2c-9d3e-000000000001"
            .parse()
            .expect("an environment identity");
        let live = serde_json::to_value(ConnectionState::owner(environment)).expect("encodes");
        let rights: Vec<String> = serde_json::from_value(live["rights"].clone()).expect("a list");
        let every: Vec<String> = kr_protocol::rights::ActionRight::ALL
            .iter()
            .map(|right| {
                serde_json::to_value(right)
                    .expect("encodes")
                    .as_str()
                    .expect("a name")
                    .to_owned()
            })
            .collect();
        assert_eq!(rights, every);
        assert!(rights.contains(&"agent.prompt".to_owned()));
        assert_eq!(live["connected"], serde_json::Value::Bool(true));
        assert_eq!(
            live["environment_id"],
            serde_json::json!(environment.to_string())
        );

        let lost = serde_json::to_value(ConnectionState::unreachable("no host")).expect("encodes");
        assert_eq!(lost["rights"], serde_json::Value::Null);
    }

    /// KR-REQ-10.01: what crosses to the WebView is a host event's payload as the native client
    /// validated and decoded it: a payload with a JSON form arrives as that JSON, and one without
    /// arrives as null beside its event type rather than as something the page cannot read.
    #[test]
    fn an_event_payload_reaches_the_page_as_json_or_as_null() {
        let published = serde_json::json!({
            "session_id": "0f1e2d3c",
            "state": "live",
            "cursor": 42,
            "changed": [true, null],
        });
        let payload = kr_protocol::envelope::ParamsValue::from_typed(&published)
            .expect("a canonical payload");
        assert_eq!(read_payload(&payload), published);

        let opaque =
            kr_protocol::envelope::ParamsValue::new(kr_cbor::CanonicalValue::Bytes(vec![1, 2, 3]));
        assert_eq!(read_payload(&opaque), serde_json::Value::Null);
    }

    #[test]
    fn an_unreachable_host_carries_a_reason_and_no_environment() {
        let state = ConnectionState::unreachable("no host on this machine");
        assert!(!state.connected);
        assert_eq!(state.environment_id, None);
        assert_eq!(state.reason.as_deref(), Some("no host on this machine"));
    }
}
