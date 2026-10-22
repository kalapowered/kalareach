//! The plugin hosts a host's environment publishes, one for each protocol, seen from outside.
//!
//! A host of the release before speaks `kr-plugin-host/2` and publishes `plugin-host.json`; a host
//! of this release speaks `kr-plugin-host/3` and publishes `plugin-host-3.json`. Each is read from
//! the file its protocol names and spoken to with the three requests every protocol has (`Hello`,
//! `Verify`, `Health`), over raw frames, so the same helper asks either one and no client of this
//! build is ever opened at the other protocol.
//!
//! These helpers, and the cases that use them, assume the release before speaks
//! `kr-plugin-host/2` and this release `/3`. The cut that retains a release of this release's
//! protocol rewrites them with the rule that cut puts in its place.

use std::time::Duration;

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::split;
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::Endpoint;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{
    Frame, HostDescriptor, HostHealth, Request, RequestBody, ResponseBody,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::ProcessStartIdentity;

use super::{Host, until};

/// The protocol a plugin host speaks, named by what it publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wire {
    /// `kr-plugin-host/2`, the release before's.
    Two,
    /// `kr-plugin-host/3`, this release's.
    Three,
}

impl Wire {
    /// The protocol's name, as a host's `Hello` answers it.
    pub const fn protocol(self) -> &'static str {
        match self {
            Self::Two => "kr-plugin-host/2",
            Self::Three => "kr-plugin-host/3",
        }
    }

    /// The file in the runtime directory a host of this protocol is published in.
    pub const fn descriptor_file(self) -> &'static str {
        match self {
            Self::Two => "plugin-host.json",
            Self::Three => "plugin-host-3.json",
        }
    }
}

/// How long one exchange with a host is given.
const EXCHANGE: Duration = Duration::from_secs(5);

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
    /// The descriptor a plugin host of `wire` is published with, when one is.
    ///
    /// The file is read for what it says and not held to a protocol: a case asks what each file
    /// holds.
    pub fn plugin_descriptor(&self, wire: Wire) -> Option<HostDescriptor> {
        let path = self
            .tree
            .environment()
            .runtime_dir()
            .join(wire.descriptor_file());
        let bytes = std::fs::read(path).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// The process of the plugin host of `wire`, when one is published.
    pub fn plugin_host_of(&self, wire: Wire) -> Option<ProcessStartIdentity> {
        self.plugin_descriptor(wire)
            .map(|descriptor| descriptor.process_start_identity)
    }

    /// What the plugin host of `wire` says it holds, after it proved it is the process its
    /// descriptor names.
    pub async fn plugin_health_of(&self, wire: Wire) -> Option<HostHealth> {
        let descriptor = self.plugin_descriptor(wire)?;
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
        (protocol == wire.protocol()
            && descriptor.protocol == wire.protocol()
            && launcher::check_proof(&descriptor, &nonce, &proof).is_ok())
        .then_some(*health)
    }

    /// Waits until the plugin host of `wire` holds `bindings` bindings, and returns what it
    /// reports.
    pub async fn plugin_holding_at(&self, wire: Wire, bindings: u64) -> HostHealth {
        until(
            &format!(
                "the {} plugin host to answer a proved Health with {bindings} bindings",
                wire.protocol()
            ),
            || async {
                self.plugin_health_of(wire)
                    .await
                    .filter(|health| health.live_bindings == bindings)
            },
        )
        .await
    }

    /// Whether the plugin host of `wire` refuses a `Hello` that offers `offered`, which is what a
    /// host does with a protocol it does not speak.
    pub async fn plugin_host_refuses(&self, wire: Wire, offered: &str) -> bool {
        let Some(descriptor) = self.plugin_descriptor(wire) else {
            return false;
        };
        let answers = speak(
            &descriptor,
            vec![RequestBody::Hello {
                protocol: offered.to_owned(),
            }],
        )
        .await;
        matches!(
            answers.as_deref(),
            Some([ResponseBody::Refused { request, .. }]) if request == "hello"
        )
    }

    /// Ends the plugin host of `wire`, by the process recorded for it, and waits for it to end.
    pub async fn end_the_plugin_host_at(&self, wire: Wire) {
        let runtime = self
            .plugin_host_of(wire)
            .unwrap_or_else(|| panic!("no plugin host of {} is published", wire.protocol()));
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

    /// Waits until a plugin host of `wire` is published that is not `not`, and returns its process.
    pub async fn another_plugin_host_of(
        &self,
        wire: Wire,
        not: &ProcessStartIdentity,
    ) -> ProcessStartIdentity {
        until("another plugin host to be published", || async {
            self.plugin_host_of(wire)
                .filter(|published| published != not)
        })
        .await
    }
}
