//! What a paired device is told when it repeats a create that failed.
//!
//! One real daemon on the loopback network and one real paired device over the transport. The
//! directory the sessions' directories lie in is a file, so the create is refused after the host
//! has reserved the session under the action. A repeat of the action is answered from that
//! reservation, as a repeat of a create that succeeded is, and a device is told it as it is told any
//! answer read from a record: as the record has it when the device may read the session the
//! reservation holds, and as an outcome that is unknown when it may not, whatever the record held.
//! The refusal of the first attempt is the host's word on that attempt and is told as ever.
#![cfg(unix)]

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCreateParams, ShellMode};

use net_support::{Device, Host, RawDevice, on_the_host, pair_with, proposal};

/// A host whose sessions cannot be given a directory, and a device paired with the rights given.
struct World {
    host: Host,
    device: RawDevice,
    _paired: Device,
    // Declared last: the directory is removed after every field above has let go of its files.
    _scratch: kr_ipc::testing::PrivateTempDir,
}

impl World {
    async fn start(rights: &[ActionRight]) -> Self {
        let scratch = kr_ipc::testing::PrivateTempDir::create();
        let home = scratch.path().join("marge");
        std::fs::create_dir_all(&home).expect("a home directory");
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_under(&owner, &home).await;
        let paired = Device::create().await;
        let record = pair_with(&host, &paired, &owner, proposal(rights)).await;
        let device = RawDevice::connect(&host, &paired, &record).await;
        let workers = host.workers_dir();
        std::fs::remove_dir_all(&workers).expect("the directory is there to remove");
        std::fs::write(&workers, b"not a directory").expect("a file in its place");
        Self {
            host,
            device,
            _scratch: scratch,
            _paired: paired,
        }
    }

    /// The request a create carries, naming `cwd` as the session's working directory.
    fn params(&self, cwd: &std::path::Path) -> SessionCreateParams {
        SessionCreateParams {
            environment_id: self.host.environment_id,
            presentation: Presentation::Attach,
            shell: Nullable::some(kr_worker::testing::posix_shell()),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some(cwd.display().to_string()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            palette: Nullable::null(),
            environment_snapshot: Vec::new(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        }
    }

    /// Submits the create under `action`, as the device does each time it asks.
    async fn create(&self, action: ActionId) -> ProtocolError {
        self.create_with(action, self.host.work()).await
    }

    /// Submits the create under `action` with the working directory `cwd`.
    async fn create_with(&self, action: ActionId, cwd: &std::path::Path) -> ProtocolError {
        net_support::refusal(
            self.device
                .mutate(
                    Method::SessionCreate,
                    action,
                    on_the_host(&self.host),
                    &self.params(cwd),
                )
                .await,
        )
    }

    async fn stop(self) {
        self.device.close();
        self.host.stop().await;
    }
}

/// A device that may create a session and may not view it is told, when it repeats a create that
/// failed, that the outcome is unknown: that the create was refused, and why, is not for a device
/// that may not read the session the host reserved for it. The first attempt was refused as ever.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_failed_create_is_told_the_outcome_is_unknown_to_a_device_that_may_not_view_it()
 {
    let world = World::start(&[ActionRight::SessionCreate, ActionRight::SessionClose]).await;
    let action = ActionId::new(kr_ipc::new_uuid());

    let first = world.create(action).await;
    assert_eq!(first.code, ErrorCode::ResourceUnavailable, "{first:?}");
    let again = world.create(action).await;
    assert_eq!(again.code, ErrorCode::OutcomeUnknown, "{again:?}");
    assert!(
        !again.message.contains("failed"),
        "the recorded phase is not told: {again:?}"
    );

    world.stop().await;
}

/// The control: a device that may view the session is told the record as it is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_failed_create_is_told_what_the_record_holds_to_a_device_that_may_view_it() {
    let world = World::start(&[ActionRight::SessionCreate, ActionRight::SessionView]).await;
    let action = ActionId::new(kr_ipc::new_uuid());

    let first = world.create(action).await;
    assert_eq!(first.code, ErrorCode::ResourceUnavailable, "{first:?}");
    let again = world.create(action).await;
    assert_eq!(again.code, ErrorCode::ResourceUnavailable, "{again:?}");
    assert!(
        again.message.contains("failed"),
        "the recorded phase is told: {again:?}"
    );

    world.stop().await;
}

/// A create that reuses the identifier of one that failed, with another request, is refused for
/// the reuse, as ever: that is this host's word about the identifier, names no result, and is not
/// the record's answer, so a device that may not view the session the reservation holds is told
/// it as it is told it anywhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_that_reuses_the_identifier_of_a_failed_one_is_refused_for_the_reuse() {
    let world = World::start(&[ActionRight::SessionCreate, ActionRight::SessionClose]).await;
    let action = ActionId::new(kr_ipc::new_uuid());

    let first = world.create(action).await;
    assert_eq!(first.code, ErrorCode::ResourceUnavailable, "{first:?}");
    let other = world
        .create_with(action, &world.host.work().join("elsewhere"))
        .await;
    assert_eq!(other.code, ErrorCode::IdConflict, "{other:?}");

    world.stop().await;
}
