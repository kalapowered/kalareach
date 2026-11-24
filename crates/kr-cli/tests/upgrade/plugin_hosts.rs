//! The plugin host an environment publishes, seen from outside.
//!
//! One host serves the sessions of every release: it speaks `kr-plugin-host/3` and publishes
//! `plugin-host-3.json`, whichever release's program started it. It is read from that file and
//! spoken to with the three requests every protocol has (`Hello`, `Verify`, `Health`), over raw
//! frames, so the same helper asks a host started by the release before and one started by this
//! release, and no client of this build is opened at it.
//!
//! A host this release starts also speaks `kr-plugin-host/4` and publishes `plugin-host-4.json`.
//! Which protocol a worker's next session runs cannot be seen from outside its process, so a case
//! that needs it connects a client of this build as a worker does and asks it
//! ([`Host::observed_protocol`]). What the host says of a binding over `/4` is read over a
//! connection that speaks the frames itself ([`FourConnection`]).

use std::path::PathBuf;
use std::time::Duration;

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::{FrameReader, FrameWriter, split};
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::Endpoint;
use kr_plugin_sdk::digest::PayloadDigest;
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{
    BindingRegistration, ComponentSource, Frame, HostDescriptor, HostHealth, HostProtocol, Request,
    RequestBody, ResponseBody, WireFacts,
};
use kr_plugin_service::protocol4::{
    BindingRegistration4, CallValue4, Checkpointed, Frame4, HostDescriptor4, RecordState, Request4,
    RequestBody4, ResponseBody4, Through,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{PluginId, RepositoryGeneration};
use kr_protocol::scalars::Uuid;

use super::{Host, command_of, until};

/// How long one exchange with a host is given.
const EXCHANGE: Duration = Duration::from_secs(5);

/// How long a registration or a call over `/4` is given: the first registration of a component in
/// a host compiles it.
const CALL: Duration = Duration::from_secs(60);

/// Sends `bodies` to the host `descriptor` names, in order on one connection, and returns each
/// answer; none when the host cannot be reached or stops answering.
async fn speak(descriptor: &HostDescriptor, bodies: Vec<RequestBody>) -> Option<Vec<ResponseBody>> {
    let exchange = async {
        let endpoint = Endpoint::from_path(&descriptor.endpoint).ok()?;
        let connection = Connection::connect(&endpoint).await.ok()?;
        let (mut reader, mut writer) = split(connection, StreamKind::Control);
        let mut answers = Vec::new();
        for (index, body) in bodies.into_iter().enumerate() {
            let request_id = u64::try_from(index).ok()? + 1;
            writer
                .write_message(&Request { request_id, body })
                .await
                .ok()?;
            loop {
                let frame: Frame = reader.read_message_without_schema().await.ok()?;
                match frame {
                    Frame::Response { reply_to, body } if reply_to == request_id => {
                        answers.push(body);
                        break;
                    }
                    // News the host sends unasked is not an answer to anything here.
                    Frame::Response { .. } | Frame::Notice(_) => {}
                }
            }
        }
        Some(answers)
    };
    tokio::time::timeout(EXCHANGE, exchange)
        .await
        .ok()
        .flatten()
}

impl Host {
    /// The descriptor the environment's plugin host is published with, when one is.
    ///
    /// The file is read for what it says and not held to a protocol: a case asks what it holds.
    pub fn plugin_descriptor(&self) -> Option<HostDescriptor> {
        let path = self
            .tree
            .environment()
            .runtime_dir()
            .join(HostProtocol::V3.descriptor);
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The process of the plugin host, when one is published.
    pub fn plugin_host(&self) -> Option<ProcessStartIdentity> {
        self.plugin_descriptor()
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// What the plugin host says it holds, after it proved it is the process its descriptor names.
    pub async fn plugin_health(&self) -> Option<HostHealth> {
        let descriptor = self.plugin_descriptor()?;
        let nonce = launcher::fresh_challenge().ok()?;
        let answers = speak(
            &descriptor,
            vec![
                RequestBody::Hello {
                    protocol: descriptor.protocol.clone(),
                },
                RequestBody::Verify { nonce },
                RequestBody::Health,
            ],
        )
        .await?;
        let [
            ResponseBody::Hello { protocol, .. },
            ResponseBody::Verified(proof),
            ResponseBody::Health(health),
        ] = <[ResponseBody; 3]>::try_from(answers).ok()?
        else {
            return None;
        };
        (protocol == HostProtocol::V3.name
            && descriptor.protocol == HostProtocol::V3.name
            && launcher::check_proof(&descriptor, &nonce, &proof).is_ok())
        .then_some(*health)
    }

    /// Waits until the plugin host holds `bindings` bindings, and returns what it reports.
    pub async fn plugin_holding(&self, bindings: u64) -> HostHealth {
        until(
            &format!("the plugin host to answer a proved Health with {bindings} bindings"),
            || async {
                self.plugin_health()
                    .await
                    .filter(|health| health.live_bindings == bindings)
            },
        )
        .await
    }

    /// Ends the plugin host, by the process recorded for it, and waits for it to end.
    pub async fn end_the_plugin_host(&self) {
        let runtime = self.plugin_host().expect("a plugin host is published");
        let ended = std::process::Command::new("kill")
            .arg(runtime.pid.get().to_string())
            .status()
            .expect("kill runs");
        assert!(ended.success(), "the recorded plugin host is ended");
        until("the plugin host to end", || async {
            matches!(
                kr_ipc::identity::process_state(&runtime),
                ProcessState::Ended
            )
            .then_some(())
        })
        .await;
    }

    /// Waits until a plugin host is published that is not `not`, and returns its process.
    pub async fn another_plugin_host(&self, not: &ProcessStartIdentity) -> ProcessStartIdentity {
        until("another plugin host to be published", || async {
            self.plugin_host().filter(|published| published != not)
        })
        .await
    }
}

/// A connection that speaks the frames of `/4` itself, with no client between it and the host.
///
/// It registers one instance of a component under a binding of its own and asks for what the host
/// says of it. The host owns the connection's bindings and ends them with it.
pub struct FourConnection {
    reader: FrameReader,
    writer: FrameWriter,
    next: u64,
}

impl FourConnection {
    /// Connects to the host a `/4` descriptor names and opens the connection with `Hello`.
    pub async fn open(descriptor: &HostDescriptor4) -> Self {
        let endpoint = Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let connection = Connection::connect(&endpoint)
            .await
            .expect("connects to the plugin host of the fourth protocol");
        let (reader, writer) = split(connection, StreamKind::Control);
        let mut opened = Self {
            reader,
            writer,
            next: 0,
        };
        let answer = opened
            .ask(RequestBody4::Hello {
                protocol: HostProtocol::V4.name.to_owned(),
            })
            .await;
        assert!(
            matches!(&answer, ResponseBody4::Hello { protocol, .. } if protocol == HostProtocol::V4.name),
            "the fourth endpoint answered Hello with {answer:?}"
        );
        opened
    }

    /// Writes one request and reads until its answer; a notice read on the way is not an answer.
    async fn ask(&mut self, body: RequestBody4) -> ResponseBody4 {
        self.next += 1;
        let request_id = self.next;
        self.writer
            .write_message(&Request4 { request_id, body })
            .await
            .expect("the request is written");
        tokio::time::timeout(CALL, async {
            loop {
                let frame: Frame4 = self
                    .reader
                    .read_message_without_schema()
                    .await
                    .expect("the host's frame reads as a frame of the fourth protocol");
                if let Frame4::Response { reply_to, body } = frame
                    && reply_to == request_id
                {
                    return body;
                }
            }
        })
        .await
        .expect("the host answered")
    }

    /// Registers the instance of `component` that `binding` names, as attempt `registration`.
    pub async fn register(&mut self, binding: u8, registration: u64, component: &ComponentSource) {
        let plugin = "kalareach/well-behaved";
        let answer = self
            .ask(RequestBody4::RegisterBinding(Box::new(
                BindingRegistration4 {
                    registration,
                    binding: BindingRegistration {
                        binding_id: Uuid::from_bytes([binding; 16]),
                        identity: PluginIdentity::new(
                            PluginId::new(plugin).expect("a bounded identifier"),
                            PackageVersion::parse("1.0.0").expect("a semantic version"),
                            PayloadDigest::of(plugin.as_bytes()),
                            RepositoryGeneration::new(1),
                        ),
                        facts: WireFacts {
                            plugin_id: plugin.to_owned(),
                            binding_revision: 1,
                            activity: "running".to_owned(),
                            thread_id: None,
                            turn_id: None,
                            updated_at_ms: 1_700_000_000_000,
                            held_rights: Vec::new(),
                        },
                        executable: "/usr/local/bin/example-agent".to_owned(),
                        component: component.clone(),
                    },
                },
            )))
            .await;
        assert!(
            matches!(&answer, ResponseBody4::Registered { registration: echoed, .. } if *echoed == registration),
            "the registration was answered with {answer:?}"
        );
    }

    /// The component's resumable state and what the host says the instance has consumed.
    pub async fn checkpoint(&mut self, binding: u8) -> Checkpointed {
        let answer = self
            .ask(RequestBody4::Checkpoint {
                binding_id: Uuid::from_bytes([binding; 16]),
                deadline_ms: u64::try_from(CALL.as_millis()).expect("milliseconds"),
            })
            .await;
        let ResponseBody4::Called {
            value: Some(CallValue4::Checkpointed(checkpointed)),
            ..
        } = answer
        else {
            panic!("a checkpoint was answered with {answer:?}");
        };
        *checkpointed
    }

    /// Restores `state` into the instance of `registration`, with the position it covers, and
    /// returns whether the host set its record from the position.
    pub async fn restore(
        &mut self,
        binding: u8,
        registration: u64,
        state: Vec<u8>,
        through: Option<Through>,
    ) -> Option<RecordState> {
        let answer = self
            .ask(RequestBody4::Restore {
                binding_id: Uuid::from_bytes([binding; 16]),
                registration,
                state,
                through,
                deadline_ms: u64::try_from(CALL.as_millis()).expect("milliseconds"),
            })
            .await;
        let ResponseBody4::Called { record, .. } = answer else {
            panic!("a restore was answered with {answer:?}");
        };
        record
    }
}

impl Host {
    /// The descriptor the environment's plugin host of `/4` is published with, when one is.
    ///
    /// Read as the launcher and the daemon read it: a file that is there and is not a descriptor of
    /// this environment's `/4` host fails the case, and an absent one is none.
    pub fn plugin_descriptor4(&self) -> Option<HostDescriptor4> {
        launcher::read_descriptor4(&self.tree.environment())
            .expect("a `/4` descriptor file, when there is one, is one this build reads")
    }

    /// The bytes of the published `/3` descriptor and of the `/4` one, as they are on disk.
    pub fn plugin_descriptor_files(&self) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        let environment = self.tree.environment();
        let runtime = environment.runtime_dir();
        (
            std::fs::read(runtime.join(HostProtocol::V3.descriptor)).ok(),
            std::fs::read(runtime.join(HostProtocol::V4.descriptor)).ok(),
        )
    }

    /// The protocol a client of this build speaks to the plugin host, connecting as a worker does:
    /// the answer is the protocol, or the failure to connect.
    pub async fn observed_protocol(&self) -> Result<HostProtocol, String> {
        let environment = self.tree.environment();
        tokio::time::timeout(CALL, PluginClient::connect(&environment))
            .await
            .map_err(|_| "the client did not connect in time".to_owned())?
            .map(|client| client.protocol())
            .map_err(|error| error.to_string())
    }

    /// Waits until a plugin host is published, by either protocol's descriptor, and returns its
    /// process.
    pub async fn plugin_host_published(&self) -> ProcessStartIdentity {
        until("a plugin host to be published", || async {
            self.plugin_host()
        })
        .await
    }

    /// Waits until the host `process` is published under both protocols, and returns the two
    /// descriptors. The host's launcher publishes the third protocol's first, so the first of the
    /// two is the one a client of the third protocol reads.
    pub async fn descriptors_of(
        &self,
        process: &ProcessStartIdentity,
    ) -> (HostDescriptor, HostDescriptor4) {
        let four = self.plugin_descriptor4_of(process).await;
        let three = self
            .plugin_descriptor()
            .expect("the descriptor of the third protocol is published before the fourth's");
        (three, four)
    }

    /// Waits until the `/4` descriptor names `process`, and returns it.
    pub async fn plugin_descriptor4_of(&self, process: &ProcessStartIdentity) -> HostDescriptor4 {
        until(
            "the descriptor of the fourth protocol to name the host",
            || async {
                self.plugin_descriptor4()
                    .filter(|descriptor| &descriptor.process_start_identity == process)
            },
        )
        .await
    }

    /// A copy of the test component the host `process` can read, in the packages directory its
    /// command line names, and how a registration names it.
    pub fn component_for(&self, process: &ProcessStartIdentity) -> ComponentSource {
        let command = command_of(process);
        let mut words = command.split_whitespace();
        let packages = loop {
            match words.next() {
                Some("--packages-dir") => {
                    break PathBuf::from(words.next().expect("a packages directory"));
                }
                Some(_) => {}
                None => panic!("the plugin host's command names no packages directory: {command}"),
            }
        };
        let built = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/plugins/components/build/well-behaved.wasm");
        let bytes = std::fs::read(&built).unwrap_or_else(|error| {
            panic!(
                "the test component is not built ({error}); run scripts/build-plugin-fixtures.sh"
            )
        });
        let placed = packages.join("upgrade-observer.wasm");
        std::fs::write(&placed, &bytes).expect("the component is placed beside the host's own");
        ComponentSource {
            path: placed.display().to_string(),
            digest: PayloadDigest::of(&bytes),
            bytes: bytes.len() as u64,
        }
    }
}
