//! The host's own method groups at both of its doors: the environment's owner on the local socket,
//! and a paired device on an authorised iroh connection, asking the same daemon.
//!
//! Two groups are here. The host diagnostics are served at both doors, and what leaves for a
//! device is the owner's own answer with every name and path held to its class and its length.
//! The skill setup group is served at the local door alone: a device whose grant manages the host
//! is refused each of its methods, and nothing is written for it.
//!
//! The daemon starts no worker, so every answer here is one it gives itself. Everything a test
//! writes is in its own temporary host tree on the internal disk.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostDoctorResult;
use kr_protocol::hostinfo::configuration::{ConfigurationDocument, SecretReference};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};
use net_support::{Device, Host, RawDevice};

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// A name an owner gave a secure-store reference, and wrote the secret itself into.
const CREDENTIAL: &str = "relay-token-7d1f0c9a52e84b36";

/// KR-REQ-23.25: `host.doctor` is served at both doors, to a paired device and to the owner, and
/// its diagnostics carry no credential out of the host. The device reads the same checks as the
/// owner, in the same order, with the same titles, statuses and remedies; a credential the owner
/// put in the configuration, and the paths of this host's directories and document, are in the
/// owner's answer and nowhere in the device's, where each stands as its class and its length.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_diagnostics_answer_both_doors_and_carry_no_credential_to_a_device() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let environment = host.tree().environment();
    let mut document = ConfigurationDocument::empty();
    document.secrets.push(SecretReference {
        name: CREDENTIAL.to_owned(),
        store: "login_keychain".to_owned(),
        item: "kalareach/relay".to_owned(),
    });
    kr_ipc::paths::write_owner_only_file(
        &kr_worker::config::document_path(&environment),
        kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
    )
    .expect("writes the document");
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let mut local = host.client().await;

    let owners: HostDoctorResult = typed(
        &local
            .request(Method::HostDoctor, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.doctor is served on the local socket"),
    );
    let devices: HostDoctorResult = typed(
        &session
            .read(Method::HostDoctor, &())
            .await
            .expect("host.doctor is served to the device"),
    );

    // The same diagnostics, check by check: the same checks in the same order, each with the
    // same title, status and remedy, and the same verdict.
    let checks = |result: &HostDoctorResult| {
        result
            .checks
            .iter()
            .map(|check| {
                (
                    check.id().to_owned(),
                    check.title().to_owned(),
                    check.status,
                    check.remedy().map(str::to_owned),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(checks(&devices), checks(&owners));
    assert_eq!(devices.healthy, owners.healthy);
    assert_eq!(
        devices.configuration.secrets.len(),
        owners.configuration.secrets.len()
    );

    // What the owner wrote and where this host keeps its files reach the owner's own answer, and
    // leave for the device as their class and their length: the credential, the environment's
    // directories and the document's path.
    assert_eq!(owners.configuration.secrets[0].name, CREDENTIAL);
    assert_eq!(
        devices.configuration.secrets[0].name,
        format!("[name withheld, {} bytes]", CREDENTIAL.len())
    );
    let withheld = [
        CREDENTIAL.to_owned(),
        environment.runtime_dir().display().to_string(),
        environment.state_dir().display().to_string(),
        kr_worker::config::document_path(&environment)
            .display()
            .to_string(),
    ];
    let owners_text = serde_json::to_string(&owners).expect("the answer serialises");
    let devices_text = serde_json::to_string(&devices).expect("the answer serialises");
    for value in &withheld {
        // As the answer spells it: a backslash in a Windows path is written as two.
        let spelled = serde_json::to_string(value).expect("the value serialises");
        let spelled = &spelled[1..spelled.len() - 1];
        assert!(
            owners_text.contains(spelled),
            "the owner's own report names {value}: {owners_text}"
        );
        assert!(
            !devices_text.contains(spelled),
            "{value} reached a paired device: {devices_text}"
        );
    }

    session.close();
    host.stop().await;
}

/// KR-REQ-23.33: the skill setup group needs the host owner at the machine. A paired device whose
/// grant manages the host is refused `agent_tools.install`, `agent_tools.status` and
/// `agent_tools.remove` through the daemon, and the refused installation writes nothing: no action
/// record and no file in the project it named. The control: the owner's own install of the same
/// target at the same scope is served, and reported installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_is_refused_the_skill_setup_and_nothing_is_written_for_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let project = host.tree().root().join("project");
    std::fs::create_dir_all(project.join(".codex")).expect("a project directory");
    let params = AgentToolsParams {
        agent: AgentTarget::Codex,
        scope: InstallScope::Project,
        project_dir: Nullable::some(project.display().to_string()),
    };
    let files = |directory: &std::path::Path| {
        walk(directory)
            .into_iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
    };
    let before = files(&project);
    let actions = host
        .tree()
        .environment()
        .state_dir()
        .join("agent-tools/actions");

    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::HostManage, ActionRight::SessionView]),
    )
    .await;
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    for method in [Method::AgentToolsInstall, Method::AgentToolsRemove] {
        let refused = net_support::refusal(
            raw.mutate(
                method,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await,
        );
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{} reached a paired device: {refused:?}",
            method.as_str()
        );
    }
    let refused = net_support::refusal(raw.read(Method::AgentToolsStatus, &params).await);
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    raw.close();
    assert_eq!(
        files(&project),
        before,
        "a refused installation wrote nothing"
    );
    assert!(
        walk(&actions).is_empty(),
        "and recorded no action it would have to answer for"
    );

    // The owner at the machine is served the same installation.
    let mut local = host.client().await;
    let installed: kr_protocol::skill::AgentToolsInstallResult = typed(
        &local
            .mutate(
                Method::AgentToolsInstall,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(host.environment_id),
                &params,
            )
            .await
            .expect("the call reaches the daemon")
            .expect("the owner installs the skill"),
    );
    assert!(!installed.already_installed);
    assert_ne!(
        files(&project),
        before,
        "the owner's installation wrote files"
    );
    let status: kr_protocol::skill::AgentToolsStatusResult = typed(
        &local
            .request(Method::AgentToolsStatus, &params)
            .await
            .expect("the call reaches the daemon")
            .expect("the owner reads the status"),
    );
    assert!(status.installed, "{status:?}");
    host.stop().await;
}

/// Every file under `directory`, in a stable order; nothing when it does not exist.
fn walk(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found.sort();
    found
}
