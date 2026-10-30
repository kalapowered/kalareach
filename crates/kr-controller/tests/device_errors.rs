//! What a paired device is told when the host cannot do what it asked, and what the owner is told.
//!
//! One real daemon on the loopback network whose directories lie under a home directory named for
//! an account, one real paired device over the transport, and the owner's own client on the local
//! socket. A device is told what kind of thing failed and nothing of this host's files or
//! accounts; the owner is told the whole of it.
#![cfg(unix)]

mod net_support;

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{Presentation, SessionCreateParams, ShellMode};

use net_support::{Device, Host, RawDevice, on_the_host, pair_with, proposal};

/// The name of an account on the machine the host runs on, and so of the home directory the host's
/// directories are under.
const ACCOUNT: &str = "marguerite";

/// What a device is told when the host could not make the directory a session works in. It says
/// what failed, and that the rest stays on the host.
const THE_DIRECTORY_SENTENCE: &str = "the host could not make the session's directory; the detail names the host and is not sent to a paired device";

/// A host whose directories lie under `<scratch>/home/<account>`, as they do under a person's home
/// on the default layout, and a device paired with the right to create sessions.
struct World {
    host: Host,
    device: RawDevice,
    home: PathBuf,
    _scratch: kr_ipc::testing::PrivateTempDir,
    _paired: Device,
}

impl World {
    async fn start() -> Self {
        let scratch = kr_ipc::testing::PrivateTempDir::create();
        let home = scratch.path().join("home").join(ACCOUNT);
        std::fs::create_dir_all(&home).expect("a home directory");
        let owner = DeviceKeys::generate().expect("owner keys");
        let host = Host::start_under(&owner, &home).await;
        let paired = Device::create().await;
        let record = pair_with(
            &host,
            &paired,
            &owner,
            proposal(&[ActionRight::SessionCreate, ActionRight::SessionClose]),
        )
        .await;
        let device = RawDevice::connect(&host, &paired, &record).await;
        Self {
            host,
            device,
            home,
            _scratch: scratch,
            _paired: paired,
        }
    }

    /// Asks for a session as the device does.
    async fn device_creates(&self) -> ProtocolError {
        let refused = self
            .device
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                on_the_host(&self.host),
                &create_params(self.host.environment_id, self.host.work()),
            )
            .await;
        net_support::refusal(refused)
    }

    /// Asks for a session as the owner does, on the local socket.
    async fn owner_creates(&self) -> ProtocolError {
        let mut local = self.host.client().await;
        let answered = local
            .mutate(
                Method::SessionCreate,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(self.host.environment_id),
                &create_params(self.host.environment_id, self.host.work()),
            )
            .await
            .expect("the call reaches the daemon");
        net_support::refusal(answered)
    }

    /// What no device is told of the host's directories: the path of one, the home directory they
    /// are under, the account that home belongs to, and the pieces of the host's own layout.
    fn assert_names_nothing_of_the_host(&self, told: &ProtocolError) {
        let message = &told.message;
        for local in [
            ACCOUNT,
            self.home.to_str().expect("a path of text"),
            self.host.workers_dir().to_str().expect("a path of text"),
        ] {
            assert!(!message.contains(local), "{local} in: {message}");
        }
        assert!(
            !message.contains('/') && !message.contains('\\'),
            "a path in: {message}"
        );
        assert!(!message.contains("chmod"), "a command in: {message}");
    }
}

fn create_params(environment_id: EnvironmentId, cwd: &Path) -> SessionCreateParams {
    SessionCreateParams {
        environment_id,
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

/// A device that asks for a session on a host that cannot make the session's directory is told
/// what failed, under the code the owner is given, and is not told where or whose.
///
/// The directory the sessions' directories lie in is a file, which no account's permissions mend.
/// The owner's own client, on the same host and the same failure, is told the path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_not_told_the_path_of_a_directory_the_host_could_not_make() {
    let world = World::start().await;
    let workers = world.host.workers_dir();
    std::fs::remove_dir_all(&workers).expect("the directory is there to remove");
    std::fs::write(&workers, b"not a directory").expect("a file in its place");

    let told = world.device_creates().await;
    assert_eq!(told.code, ErrorCode::ResourceUnavailable, "{told:?}");
    assert_eq!(told.message, THE_DIRECTORY_SENTENCE);
    world.assert_names_nothing_of_the_host(&told);

    let owner = world.owner_creates().await;
    assert_eq!(owner.code, told.code, "{owner:?}");
    assert!(
        owner.message.contains(workers.to_str().expect("text")),
        "the owner is told which path: {owner:?}"
    );
    assert!(owner.message.contains(ACCOUNT), "{owner:?}");

    world.device.close();
    world.host.stop().await;
}

/// A device that asks for a session on a host whose directory is open to other accounts is told
/// neither the account numbers nor the command that mends it; the owner is told both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_is_not_told_the_account_numbers_or_the_command_of_a_directory_that_is_too_open() {
    let world = World::start().await;
    let workers = world.host.workers_dir();
    std::fs::set_permissions(&workers, std::fs::Permissions::from_mode(0o755))
        .expect("the directory is opened to others");

    let told = world.device_creates().await;
    assert_eq!(told.code, ErrorCode::PermissionDenied, "{told:?}");
    assert_eq!(told.message, THE_DIRECTORY_SENTENCE);
    world.assert_names_nothing_of_the_host(&told);

    let owner = world.owner_creates().await;
    assert_eq!(owner.code, told.code, "{owner:?}");
    assert!(
        owner.message.contains("chmod 700"),
        "the owner is told the command that mends it: {owner:?}"
    );
    assert!(owner.message.contains("must be owned by user"), "{owner:?}");

    world.device.close();
    world.host.stop().await;
}

/// What names nothing of the host is told to a device as the owner is told it.
///
/// The control of the two cases above: an error is not made vague because it passes a device's
/// connection, only when it names the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refusal_that_names_nothing_of_the_host_reaches_a_device_whole() {
    let world = World::start().await;
    let unknown = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    let close = kr_protocol::session::SessionCloseParams {
        session_id: unknown,
    };
    let told = net_support::refusal(
        world
            .device
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_session(&world.host, unknown),
                &close,
            )
            .await,
    );
    let mut local = world.host.client().await;
    let owner = net_support::refusal(
        local
            .mutate(
                Method::SessionClose,
                ActionId::new(kr_ipc::new_uuid()),
                net_support::on_the_session(&world.host, unknown),
                &close,
            )
            .await
            .expect("the call reaches the daemon"),
    );
    assert_eq!(told.code, owner.code, "{told:?} {owner:?}");
    assert_eq!(told.message, owner.message);
    assert!(told.message.contains(&unknown.to_string()), "{told:?}");

    world.device.close();
    world.host.stop().await;
}
