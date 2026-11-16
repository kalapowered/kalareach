//! A host's network keys are kept in the store its own device keys are kept in.
//!
//! One state directory has one store for the keys of its host. The selection that opens the
//! daemon's device keys is the one the network's keys come from, so two starts of one directory
//! (from a desktop session where the Secret Service opens, and from a shell where it does not, or
//! with `--secret-store file` and without) read the same keys, the host's endpoint identity is the
//! one its paired devices pinned, and a start whose store cannot be opened makes no key.
//!
//! The platform store is a stand-in the suite puts in its place: no case here opens this machine's
//! own credential store.

mod net_support;

use std::sync::Arc;

use kr_controller::service::net::device_key_scope;
use kr_controller::service::{Controller, ControllerSetup};
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{KeyOwner, SecretStore, StoreSelection, load_device_keys, stand_in};
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_pairing::host::HostIdentity;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::EnvironmentId;
use kr_protocol::scalars::Nullable;

/// The address the host's endpoint binds, so that nothing leaves this machine.
const LOOPBACK: &str = "127.0.0.1:0";

/// KR-REQ-10.47: a host whose keys are in files, where the platform store opens, has the same
/// network identity as before, and its keys are the ones in files: the platform's store holds no
/// key afterwards. This is the state a `--secret-store file` start leaves, taken up by a plain
/// start from a session that reaches the Secret Service.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_whose_keys_are_in_files_keeps_its_network_identity_where_the_platform_store_opens()
{
    let switch = stand_in::Switch::take(CONTROLLER_SECRET_SERVICE);
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    put_on_the_network(&environment);

    let first = start(&environment, host.environment_id(), StoreSelection::File)
        .await
        .expect("the daemon starts over files");
    let before = identity_of(&first);
    drop(first);

    let platform = switch.opens();
    let second = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens");
    let after = identity_of(&second);
    drop(second);

    assert_eq!(after, before, "the host keeps the identity it had");
    assert_the_identity_is_the_keys_in(&environment, host.environment_id(), &after);
    assert!(
        platform.is_empty(),
        "no key is made in the platform's store while the host's keys are in files"
    );
}

/// KR-REQ-10.47: a host that started where the platform store did not open, and so keeps its keys
/// in files, has the same network identity at a start where it does, and its platform's store
/// holds no key afterwards. This is the same host started from an SSH shell and then from a
/// desktop session.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_that_started_without_the_platform_store_keeps_its_network_identity_where_it_opens()
{
    let switch = stand_in::Switch::take(CONTROLLER_SECRET_SERVICE);
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    put_on_the_network(&environment);

    switch.closes();
    let first = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts over files");
    let before = identity_of(&first);
    drop(first);

    let platform = switch.opens();
    let second = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens");
    let after = identity_of(&second);
    drop(second);

    assert_eq!(after, before, "the host keeps the identity it had");
    assert_the_identity_is_the_keys_in(&environment, host.environment_id(), &after);
    assert!(
        platform.is_empty(),
        "no key is made in the platform's store while the host's keys are in files"
    );
}

/// KR-REQ-10.47: a host whose keys are in the platform store is not started where that store does
/// not open: the start is refused, no key is made or moved in either store, and the host has its
/// identity again where the store opens.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_where_the_platform_store_does_not_open_is_refused_and_makes_no_key() {
    let switch = stand_in::Switch::take(CONTROLLER_SECRET_SERVICE);
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    put_on_the_network(&environment);

    let platform = switch.opens();
    let first = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens");
    let before = identity_of(&first);
    drop(first);
    assert!(
        kept_in_files(&environment).is_empty(),
        "the host's keys are in the platform's store alone"
    );

    switch.closes();
    let refused = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await;
    assert!(
        refused.is_err(),
        "a host whose keys are in the platform store does not start without it"
    );
    assert!(
        kept_in_files(&environment).is_empty(),
        "the refused start made no key in files"
    );
    let kept = device_keys_in(&*platform, host.environment_id());
    assert_eq!(
        kept.public_keys(),
        before.keys,
        "the platform's keys are as they were"
    );

    switch.opens_with(&platform);
    let again = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens again");
    assert_eq!(
        identity_of(&again),
        before,
        "the host has the identity it had"
    );
}

/// KR-REQ-10.47: a host whose keys are in the platform store is not started with the file store:
/// the start is refused, no key is made in files or in the platform's store, and the host has its
/// identity at the next start that does not name the file store.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_start_with_the_file_store_over_a_platform_record_is_refused_and_makes_no_key() {
    let switch = stand_in::Switch::take(CONTROLLER_SECRET_SERVICE);
    let host = kr_ipc::testing::TempHost::create();
    let environment = host.environment();
    put_on_the_network(&environment);

    let platform = switch.opens();
    let first = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens");
    let before = identity_of(&first);
    drop(first);

    let refused = start(&environment, host.environment_id(), StoreSelection::File).await;
    assert!(
        refused.is_err(),
        "the file store is not the store of a host whose keys are in the platform's"
    );
    assert!(
        kept_in_files(&environment).is_empty(),
        "the refused start made no key in files"
    );
    let kept = device_keys_in(&*platform, host.environment_id());
    assert_eq!(
        kept.public_keys(),
        before.keys,
        "the platform's keys are as they were"
    );

    let again = start(
        &environment,
        host.environment_id(),
        StoreSelection::Platform,
    )
    .await
    .expect("the daemon starts where the platform store opens");
    assert_eq!(
        identity_of(&again),
        before,
        "the host has the identity it had"
    );
}

/// Writes the document that puts the host on the network, on loopback alone.
fn put_on_the_network(environment: &kr_ipc::paths::EnvironmentPaths) {
    let mut document = ConfigurationDocument::empty();
    document.revision = 1;
    document.network.enabled = Nullable::some(true);
    document.network.bind_address = Nullable::some(LOOPBACK.to_owned());
    let path = kr_worker::config::document_path(environment);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("the state directory");
    }
    kr_ipc::paths::write_owner_only_file(
        &path,
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("the document");
}

/// Starts a daemon in-process over `environment` with the store `selection` names, launching no
/// worker. The controller's own identity is opened through the same selection, as the daemon's
/// program opens it, so the directory and the record are in the state the program leaves them in.
async fn start(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    selection: StoreSelection,
) -> kr_controller::Result<Arc<Controller>> {
    kr_controller::testing::taken_over(|| start_once(environment, environment_id, selection)).await
}

async fn start_once(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    selection: StoreSelection,
) -> kr_controller::Result<Arc<Controller>> {
    let secrets = environment.secrets_dir();
    Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = selection
                .open(CONTROLLER_SECRET_SERVICE, &secrets, KeyOwner::Host)
                .map_err(|error| {
                    kr_controller::ControllerError::NotConfigured(error.to_string())
                })?;
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: selection,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(net_support::RefusingSupervisor),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: net_support::build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
}

/// What the daemon declares of itself on the network: the identity and the keys a paired device
/// pins, without the addresses it happens to be reachable at.
fn identity_of(controller: &Controller) -> HostIdentity {
    let mut identity = controller
        .network_guard()
        .expect("the host is on the network")
        .pairing()
        .identity()
        .clone();
    identity.network_config = kr_protocol::pairing::NetworkConfig::empty();
    identity
}

/// The host's network device keys as the store keeps them.
fn device_keys_in(store: &dyn SecretStore, environment_id: EnvironmentId) -> DeviceKeys {
    load_device_keys(store, &device_key_scope(environment_id))
        .expect("the store reads")
        .expect("the store holds the host's device keys")
}

/// The host's keys in the directory store are the identity it presents on the network.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
fn assert_the_identity_is_the_keys_in(
    environment: &kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    identity: &HostIdentity,
) {
    let files = kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("the files");
    let kept = device_keys_in(&*files.store, environment_id);
    assert_eq!(identity.endpoint_id, *kept.transport.public());
    assert_eq!(identity.keys, kept.public_keys());
}

/// What the directory store holds, apart from its own dotted records.
fn kept_in_files(environment: &kr_ipc::paths::EnvironmentPaths) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(environment.secrets_dir()) else {
        return Vec::new();
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.starts_with('.'))
        .collect()
}
