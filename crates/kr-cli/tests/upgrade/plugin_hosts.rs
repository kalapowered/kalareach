//! The plugin host an environment publishes, seen from outside.
//!
//! One host serves the sessions of every release: it speaks `kr-plugin-host/3` and publishes
//! `plugin-host-3.json`, whichever release's program started it. It is read from that file and
//! spoken to with the three requests every protocol has (`Hello`, `Verify`, `Health`), over raw
//! frames, so the same helper asks a host started by the release before and one started by this
//! release, and no client of this build is opened at it.

use std::time::Duration;

use kr_ipc::endpoint::Connection;
use kr_ipc::framed::split;
use kr_ipc::identity::ProcessState;
use kr_ipc::paths::Endpoint;
use kr_plugin_service::launcher;
use kr_plugin_service::protocol::{
    Frame, HostDescriptor, HostHealth, HostProtocol, Request, RequestBody, ResponseBody,
};
use kr_protocol::frame::StreamKind;
use kr_protocol::identity::ProcessStartIdentity;

use super::{Host, until};

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
    /// The descriptor the environment's plugin host is published with, when one is.
    ///
    /// The file is read for what it says and not held to a protocol: a case asks what it holds.
    pub fn plugin_descriptor(&self) -> Option<HostDescriptor> {
        let path = self
            .tree
            .environment()
            .runtime_dir()
            .join(HostProtocol::THIS.descriptor);
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
        (protocol == HostProtocol::THIS.name
            && descriptor.protocol == HostProtocol::THIS.name
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
