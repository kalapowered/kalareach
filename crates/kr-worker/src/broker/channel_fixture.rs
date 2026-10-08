//! A launched application's channel, served over a connection a test holds the far end of.
//!
//! This is the harness the worker's own tests and the control daemon's use to relay a real tool
//! approval into a broker: the channel the command backend would hand over once it has admitted
//! one (a launched instance, the connector read from a package laid out as the store extracts it,
//! and the channel's own connection), and the channel server's end of that connection, which
//! writes the frames the forwarder relays and reads what this host writes back. It is compiled
//! only with the `testing` feature.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
use kr_protocol::gateway::NativeFraming;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PublisherId, SessionId};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

use crate::broker::bridge::{AdmittedBridge, BridgeProcess, BridgeStream, BridgeSurface};
use crate::broker::channels::{ChannelEnd, ChannelLaunch, serve};
use crate::broker::connectors::{InstalledConnector, decoding_trust, fixture};
use crate::broker::{
    Broker, BrokerTransport, Credential, Framing, ManagedProcess, TransportHandle,
};

/// How long a test waits for a channel to say something or to end.
const DEADLINE: Duration = Duration::from_secs(120);

/// The Claude Code method a relayed tool approval arrives as.
pub const PERMISSION_REQUEST: &str = "notifications/claude/channel/permission_request";

/// The session the harness's brokers are for.
pub fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// The application instance a harness registers under `number`.
pub fn instance(number: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([number; 16]))
}

/// The application the launch registered for one instance.
pub fn launched(number: u8) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        1_000 + u64::from(number),
        ProcessStartSource::MacosProcBsdInfo,
        900,
    )
}

/// A channel server's own process.
pub fn channel_process(number: u8) -> ProcessStartIdentity {
    ProcessStartIdentity::new(
        2_000 + u64::from(number),
        ProcessStartSource::MacosProcBsdInfo,
        901,
    )
}

/// The binding a harness gives the connector's package for instance `number`.
pub fn binding(number: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([100 + number; 16]))
}

/// Registers one launched instance on a broker, as the command backend's launch does.
pub fn register(broker: &Broker, number: u8) {
    let managed = ManagedProcess::new(
        instance(number),
        launched(number),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance(number),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: launched(number),
        },
        Credential::from_bytes([9; 32]),
        false,
        TimestampMs::new(1),
    );
    broker
        .register_instance(
            instance(number),
            IntegrationMode::NativeBridge,
            None,
            Some(managed),
        )
        .expect("the launched instance is registered");
}

/// The Claude Code connector, read from a package laid out as the store extracts one.
pub struct Package {
    /// The directory the package was laid out in, which goes when the package does.
    pub root: PathBuf,
    /// The connector read from it.
    pub connector: Arc<InstalledConnector>,
}

impl Package {
    /// Lays the package out on the internal disk and reads it.
    ///
    /// # Panics
    ///
    /// Panics when the package cannot be written or read, which in a test means the environment
    /// is unusable.
    #[must_use]
    pub fn laid_out() -> Self {
        let root = std::env::temp_dir().join(format!("kr-channels-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("the store's directory");
        let source = fixture::claude_code_package(&root, Path::new(fixture::FORWARDER))
            .expect("the package is written");
        let connector =
            Arc::new(InstalledConnector::read(source).expect("the installed package reads"));
        Self { root, connector }
    }

    /// What a channel of one instance is served with.
    pub fn launch(&self, broker: &Arc<Broker>, number: u8, version: Option<&str>) -> ChannelLaunch {
        ChannelLaunch {
            broker: Arc::clone(broker),
            application_instance_id: instance(number),
            connector: Arc::clone(&self.connector),
            version: version.map(str::to_owned),
            site: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16])),
            os_user: "person".to_owned(),
            views: None,
        }
    }

    /// Binds the connector's package to one instance the way the installation's binder will: the
    /// approval interpreter, with the trust its grants give.
    pub fn bind(&self, broker: &Broker, number: u8) {
        broker
            .bind_descriptor(
                binding(number),
                instance(number),
                self.connector.plugin_id(),
                PublisherId::new("kalareach").expect("valid"),
                self.connector.package_digest(),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                decoding_trust(&self.connector, TimestampMs::new(1)),
                TimestampMs::new(1),
            )
            .expect("the package is bound");
    }
}

impl Drop for Package {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One channel being served, and the channel server's end of its connection.
pub struct Channel {
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    writes: Option<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
    served: tokio::task::JoinHandle<ChannelEnd>,
    /// Ends the channel as the backend's retirement does, when sent or dropped.
    retire: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Channel {
    /// Hands one admitted channel, started by `starter`, to the consumer.
    pub fn open(launch: ChannelLaunch, number: u8, starter: ProcessStartIdentity) -> Self {
        Self::open_with(launch, number, starter, 64 * 1024)
    }

    /// The same, over a connection that holds at most `buffer` bytes each way unread.
    pub fn open_with(
        launch: ChannelLaunch,
        number: u8,
        starter: ProcessStartIdentity,
        buffer: usize,
    ) -> Self {
        let (ours, theirs) = tokio::io::duplex(buffer);
        let (reader, writer) = tokio::io::split(theirs);
        let admitted = AdmittedBridge {
            surface: BridgeSurface::Channel,
            process: BridgeProcess {
                identity: channel_process(number),
                starter: Some(starter),
                started: None,
            },
            stream: BridgeStream::new(
                Box::new(reader),
                Box::new(writer),
                Vec::new(),
                Framing::new(NativeFraming::JsonLines),
            ),
        };
        let (retire, retired) = tokio::sync::oneshot::channel::<()>();
        let served = tokio::spawn(serve(launch, admitted, async move {
            let _ = retired.await;
        }));
        let (ours_reader, ours_writer) = tokio::io::split(ours);
        Self {
            lines: tokio::io::BufReader::new(ours_reader).lines(),
            writes: Some(ours_writer),
            served,
            retire: Some(retire),
        }
    }

    /// Relays one tool approval, as the forwarder does.
    pub async fn relay(&mut self, request_id: &str) {
        let frame = serde_json::json!({
            "jsonrpc": "2.0",
            "method": PERMISSION_REQUEST,
            "params": {
                "request_id": request_id,
                "tool_name": "Bash",
                "description": "List the files here",
                "input_preview": "ls -la",
            },
        });
        self.send(&frame).await;
    }

    /// Sends one frame as the channel server would.
    pub async fn send(&mut self, frame: &serde_json::Value) {
        let writes = self.writes.as_mut().expect("the channel's end is open");
        writes
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("the frame is written");
        writes.flush().await.expect("the frame is flushed");
    }

    /// Closes the channel server's end, as the forwarder does when Claude Code closes it.
    pub async fn close(&mut self) {
        if let Some(mut writes) = self.writes.take() {
            let _ = writes.shutdown().await;
        }
    }

    /// Reads the next line this host wrote, or `None` when it closed its direction.
    pub async fn next(&mut self) -> Option<serde_json::Value> {
        let line = tokio::time::timeout(DEADLINE, self.lines.next_line())
            .await
            .expect("the channel says something or closes in time")
            .expect("the channel reads")?;
        Some(serde_json::from_str(&line).expect("a frame is JSON"))
    }

    /// Waits for the consumer to end while the channel server's end stays open, and says how it
    /// did.
    pub async fn ended_while_open(&mut self) -> ChannelEnd {
        tokio::time::timeout(DEADLINE, &mut self.served)
            .await
            .expect("the consumer ends in time")
            .expect("the consumer's task joins")
    }

    /// Waits for the consumer to end, and says how it did.
    pub async fn ended(self) -> ChannelEnd {
        let _retire = self.retire;
        tokio::time::timeout(DEADLINE, self.served)
            .await
            .expect("the consumer ends in time")
            .expect("the consumer's task joins")
    }
}
