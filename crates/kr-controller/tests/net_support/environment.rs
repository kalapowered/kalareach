//! A daemon on the network with one worker it adopts, and the paired devices that act on it.
//!
//! The worker is the product's own, run in this process; the daemon is started the way a host
//! starts one, over a tree the worker was recorded on, so it adopts the worker at its start.

use std::time::Duration;

use kr_controller::service::net::devices::DeviceRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::question::{
    Question, QuestionAnswer, QuestionAnswerParams, QuestionResolveResult,
};
use kr_protocol::receipt::ActionReadParams;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, TimestampMs};

use super::worker::Worker;
use super::{Device, Host, RawDevice, pair_with, proposal};

/// How long a test waits for the daemon to reach the worker.
pub const PATIENCE: Duration = Duration::from_secs(60);

/// A daemon on the network with one adopted worker, and the keys of the environment's owner.
pub struct Environment {
    pub host: Host,
    pub owner: DeviceKeys,
    pub worker: Worker,
}

impl Environment {
    /// Starts a daemon on a fresh environment, bootstraps its owner, stops it, starts a worker on
    /// the tree, and starts the daemon again, which adopts the worker.
    pub async fn start() -> Self {
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start(&owner).await;
        let stopped = host.shut_down().await;
        let worker = Worker::start(stopped.tree(), 1).await;
        let settings = stopped.settings().clone();
        let host = stopped.start(settings).await;
        let environment = Self {
            host,
            owner,
            worker,
        };
        environment.until_adopted().await;
        environment
    }

    pub async fn stop(self) {
        self.host.stop().await;
    }

    pub fn environment_id(&self) -> EnvironmentId {
        self.host.environment_id
    }

    pub fn target(&self) -> ActionTarget {
        self.worker.target(self.environment_id())
    }

    /// Waits until the daemon serves the worker's session.
    pub async fn until_adopted(&self) {
        let deadline = tokio::time::Instant::now() + PATIENCE;
        loop {
            let mut client = self.host.client().await;
            let read = client
                .request(
                    Method::SessionRead,
                    &kr_protocol::session::SessionReadParams {
                        session_id: self.worker.session_id,
                    },
                )
                .await
                .expect("the call reaches the daemon");
            if read.is_ok() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the daemon never reached the worker: {read:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Pairs a device under `proposal` and connects it as one that submits the action identifiers
    /// it is given.
    pub async fn device(&self, proposal: kr_protocol::pairing::ProposedGrant) -> Paired {
        let device = Device::create().await;
        let record = pair_with(&self.host, &device, &self.owner, proposal).await;
        let connection = RawDevice::connect(&self.host, &device, &record).await;
        Paired {
            _device: device,
            _record: record,
            connection,
        }
    }
}

pub struct Paired {
    pub _device: Device,
    pub _record: DeviceRecord,
    pub connection: RawDevice,
}

/// A grant carrying exactly the rights named, whose history reaches back to `bound_ms`.
pub fn from(actions: &[ActionRight], bound_ms: u64) -> kr_protocol::pairing::ProposedGrant {
    let mut proposal = proposal(actions);
    proposal.history.lower_bound_ms = Nullable::some(TimestampMs::new(bound_ms));
    proposal
}

pub fn yes(environment: &Environment, question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: environment.worker.session_id,
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

pub fn resolved(value: ParamsValue) -> QuestionResolveResult {
    value.to_typed().expect("a resolution result")
}

pub fn read_by_id(action_id: ActionId) -> ActionReadParams {
    ActionReadParams {
        action_id,
        session_id: None,
    }
}
