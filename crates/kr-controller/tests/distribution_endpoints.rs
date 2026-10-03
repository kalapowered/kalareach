//! The paired endpoint of one distribution of a machine, from inside that distribution.
//!
//! Each installation has its own paired endpoint and its own grants, and a machine group grants
//! nothing by itself. These cases are the parts of that check that can only run inside a
//! distribution, against the control daemon the distribution already runs, over the network that
//! distribution has. `scripts/e2e-wsl.sh` runs them in each of two distributions in turn and hands
//! one distribution's endpoint to the other, so every case is ignored here and does nothing in an
//! ordinary test run: it needs a daemon this run did not start.
//!
//! * `prepare_the_network` selects the loopback network in this installation's configuration
//!   document, and refuses a document that already names a relay or a discovery service. The
//!   daemon reads it when it starts, so the script restarts the daemon after it.
//! * `pair_a_viewer_with_this_distribution` pairs a device that may view sessions with this
//!   installation's own endpoint. The installation's first owner is established the way a person
//!   establishes it, through the initial bootstrap on the daemon's own socket, and every later
//!   pairing is confirmed by that owner device. The first owner is established once, so its keys
//!   are kept between runs, with the viewer's, in a directory of this account's own state
//!   (`KR_ACC_DIR` names another).
//! * `a_viewer_reaches_only_the_distribution_it_was_paired_with` connects that viewer to this
//!   distribution, and then to the endpoint of another distribution that `KR_ACC_OTHER` describes.
//!   The other one is first reached as any device may reach it, which shows the address leads to
//!   the endpoint it names, and then as the viewer, which it must end with the close a host gives a
//!   device it holds no record of.
//! * `report_the_devices_and_grants` prints what this installation holds of both, which the script
//!   compares across a change of machine group.
//!
//! Each case prints the facts the script needs on lines that start with `KR-ACC`.

#![cfg(unix)]

mod net_support;

use std::path::PathBuf;
use std::sync::Arc;

use iroh::EndpointAddr;
use kr_client::session::Session;
use kr_client::transport::NetworkTransport;
use kr_crypto::connect::PairedPeer;
use kr_crypto::keys::DeviceKeys;
use kr_crypto::store::{load_device_keys, open_store_in, store_device_keys};
use kr_ipc::client::LocalClient;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::hostinfo::configuration::{ConfigurationDocument, contents};
use kr_protocol::ids::{DeviceId, DeviceKeyRevision, EnvironmentId, InvitationId};
use kr_protocol::invitation::InviteGrantKind;
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::pairing::PairStatus;
use kr_protocol::preauth::{
    PairRedeemParams, PairRedeemResult, PairStatusParams, PairStatusResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Uuid};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult, GrantListParams, GrantListResult};
use kr_transport::TransportError;
use kr_transport::handshake;
use kr_transport::scheduler::SendLimits;
use net_support::{Device, build, pairing, proposal};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Where the keys and records this suite keeps between runs are, below this account's home,
/// unless `KR_ACC_DIR` says. It is in the account's own state area rather than a temporary
/// directory, which a system may empty, because the first owner it holds the keys of is made once.
const DEFAULT_DIRECTORY: &str = ".local/state/kr-acc-pairing";

/// The address the network endpoint binds to: loopback, a free port, no relay, no discovery.
const BIND_ADDRESS: &str = "127.0.0.1:0";

/// The scope the device keys of this suite are kept under in a store.
const KEY_SCOPE: &str = "acceptance-device";

/// How long a connection or an answer is given.
const DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

/// An endpoint as a device that was paired with it holds it, and as it is handed to another
/// distribution: the identity the endpoint proves, and the addresses it listens on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct EndpointRecord {
    environment_id: String,
    host_device_id: String,
    host_key_revision: u64,
    host_authorisation: String,
    endpoint_id: String,
    addresses: Vec<String>,
}

impl EndpointRecord {
    fn peer(&self) -> PairedPeer {
        PairedPeer {
            device_id: self.host_device_id.parse().expect("a device identity"),
            device_key_revision: DeviceKeyRevision::new(self.host_key_revision),
            authorisation: AuthorisationKey::from_bytes(unhex(&self.host_authorisation)),
            endpoint_id: EndpointKey::from_bytes(unhex(&self.endpoint_id)),
        }
    }

    fn address(&self) -> EndpointAddr {
        let key = iroh::PublicKey::from_bytes(&unhex(&self.endpoint_id))
            .expect("a usable endpoint identity");
        let mut address = EndpointAddr::new(key);
        for text in &self.addresses {
            address = address.with_ip_addr(text.parse().expect("a socket address"));
        }
        address
    }
}

/// The device this suite paired with this distribution, and the endpoint it paired with.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Viewer {
    device_id: String,
    grant_id: String,
    endpoint: EndpointRecord,
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "a key is 64 hexadecimal digits: {text}");
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).expect("hexadecimal digits");
    }
    bytes
}

/// One line the script reads.
fn report(kind: &str, value: &serde_json::Value) {
    println!("KR-ACC {kind} {value}");
}

/// The directory this suite keeps its keys and records in: owner-only, and this account's own.
fn directory() -> PathBuf {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    let directory = std::env::var_os("KR_ACC_DIR").map_or_else(
        || {
            PathBuf::from(std::env::var_os("HOME").expect("this account has a home"))
                .join(DEFAULT_DIRECTORY)
        },
        PathBuf::from,
    );
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .expect("the directory this suite keeps its state in");
    let metadata = std::fs::symlink_metadata(&directory).expect("the directory is readable");
    assert!(
        metadata.is_dir()
            && metadata.uid() == kr_ipc::paths::current_uid()
            && metadata.mode() & 0o077 == 0,
        "{} is not a directory of this account that no other account can open",
        directory.display()
    );
    directory
}

/// This installation: the environment its own daemon serves, found the way `kr` finds it.
struct Own {
    environment: EnvironmentPaths,
    environment_id: EnvironmentId,
}

fn own() -> Own {
    let paths = HostPaths::discover().expect("this account's runtime and state directories");
    let environment_id = paths
        .open_environment_id()
        .expect("this installation's environment identity");
    Own {
        environment: paths.environment(environment_id),
        environment_id,
    }
}

impl Own {
    /// Connects to the daemon this distribution runs.
    async fn daemon(&self) -> LocalClient {
        let endpoint = self
            .environment
            .controller_endpoint()
            .expect("the daemon's endpoint");
        tokio::time::timeout(
            DEADLINE,
            LocalClient::connect(&endpoint, LocalClientKind::Cli, build()),
        )
        .await
        .expect("the daemon answers in time")
        .expect("this distribution's control daemon is running")
    }
}

/// Keeps `keys` in a store of their own under `name`, replacing what was there.
fn keep_keys(name: &str, keys: &DeviceKeys) {
    let place = directory().join(name);
    // This suite's own directory, made by an earlier run of it.
    let _ = std::fs::remove_dir_all(&place);
    let store = open_store_in(&place).expect("a store for the keys");
    store_device_keys(store.store.as_ref(), KEY_SCOPE, keys).expect("the keys are stored");
}

/// Reads the keys kept under `name`.
fn kept_keys(name: &str) -> Option<DeviceKeys> {
    let place = directory().join(name);
    if !place.exists() {
        return None;
    }
    let store = open_store_in(&place).expect("the store of the keys");
    load_device_keys(store.store.as_ref(), KEY_SCOPE).expect("the keys are readable")
}

/// Selects the loopback network in this installation's configuration document.
///
/// The daemon builds its endpoint when it starts, so the one running now keeps what it has until
/// it is started again. A document that already names a relay or a discovery service is not edited:
/// this acceptance is about endpoints reached on loopback, and it does not choose a person's
/// services for them.
#[tokio::test]
#[ignore = "runs inside a distribution against its own control daemon: scripts/e2e-wsl.sh"]
async fn prepare_the_network() {
    let own = own();
    // One writer edits at a time, the way every other writer of the document does. The lock is in
    // the installation's state directory, which its daemon makes when it first starts.
    let _lock = kr_worker::config::lock(&own.environment)
        .expect("the configuration lock, which needs a daemon that has started once");
    let path = kr_worker::config::document_path(&own.environment);
    let loaded = kr_worker::config::load(&own.environment);
    let mut document = match loaded.document {
        Some(document) => document,
        None => {
            assert!(
                !path.exists(),
                "the configuration document at {} is one this suite cannot edit",
                path.display()
            );
            ConfigurationDocument::empty()
        }
    };
    let network = &document.network;
    assert!(
        network.relay_urls().is_empty()
            && network.pkarr_publisher_url().is_none()
            && network.pkarr_resolver_url().is_none()
            && network.dns_origin.0.is_none()
            && network.relay_only.0 != Some(true)
            && network.local_discovery.0 != Some(true)
            && network.mainline_dht.0 != Some(true),
        "the configuration document at {} selects a relay or a discovery service, and this \
         acceptance reaches endpoints on loopback alone",
        path.display()
    );
    let changed = !(network.joins() && network.bind_address() == Some(BIND_ADDRESS));
    if changed {
        document.revision += 1;
        document.network.enabled = kr_protocol::scalars::Nullable::some(true);
        document.network.bind_address =
            kr_protocol::scalars::Nullable::some(BIND_ADDRESS.to_owned());
        // Owner-only, as the daemon requires of every directory it keeps below its own roots.
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path.parent().expect("the document has a directory"))
                .expect("the configuration directory");
        }
        kr_ipc::paths::write_owner_only_file(&path, contents(&document).as_bytes())
            .expect("the configuration document");
    }
    report(
        "prepared",
        &json!({ "environment_id": own.environment_id.to_string(), "changed": changed }),
    );
}

/// What this installation's devices list says, revoked devices included.
async fn owner_devices(client: &mut LocalClient) -> DeviceListResult {
    pairing::read(
        client,
        Method::DeviceList,
        &DeviceListParams {
            include_revoked: true,
        },
    )
    .await
    .expect("the owner reads the devices")
}

/// Establishes this installation's first owner, or finds the one an earlier run established, and
/// returns the owner device's keys.
async fn the_owner(own: &Own, client: &mut LocalClient) -> DeviceKeys {
    let listed = owner_devices(client).await;
    // A revoked owner counts: the initial bootstrap closes for good once an installation has had
    // an owner, whatever became of it.
    let owners: Vec<_> = listed
        .devices
        .iter()
        .filter(|device| device.manages_host)
        .collect();
    if let Some(keys) = kept_keys("owner") {
        let wanted = keys.public_keys();
        if owners
            .iter()
            .any(|device| device.keys.0.as_ref() == Some(&wanted) && !device.revoked)
        {
            return keys;
        }
    }
    assert!(
        owners.is_empty(),
        "this installation has an owner device whose keys this suite does not hold (it did not \
         make it, its keys were not kept where this suite looks, or it was revoked), and the \
         initial bootstrap is closed for good once an installation has had an owner: run the \
         acceptance where the installation has no owner"
    );
    let keys = DeviceKeys::generate().expect("owner keys");
    // Kept before the confirmation that commits the pairing, so an owner this run makes is never
    // one whose keys it lost. Keys kept for a pairing that did not commit match no owner, and the
    // next run makes new ones.
    keep_keys("owner", &keys);
    let device = Device::with_keys(keys.clone()).await;
    let ceremony = DeviceKeys::generate().expect("a ceremony key");
    let signer = pairing::Signer::Bootstrap(&ceremony.authorisation);
    let proposal = kr_pairing::grants::personal_owner_grant();
    let invited = pairing::invite_direct(
        own.environment_id,
        client,
        InviteGrantKind::PersonalOwner,
        &proposal,
        &signer,
    )
    .await
    .expect("the daemon issues its first owner's invitation");
    let (connection, _candidate, _record) = redeem(&device, &invited).await;
    let confirmed =
        pairing::confirm_candidate(own.environment_id, client, invited.invitation_id, &signer)
            .await
            .expect("the first owner is confirmed");
    assert!(
        confirmed.event.first_owner,
        "the initial bootstrap establishes the first owner"
    );
    connection.close(0_u32.into(), b"paired");
    keys
}

/// Redeems a direct invitation as `device`, and returns the candidate's connection, the candidate
/// it asks about its pairing on, and what it learned of the endpoint it reached from what that
/// endpoint proved.
async fn redeem(
    device: &Device,
    invited: &kr_protocol::invitation::PairInviteResult,
) -> (
    iroh::endpoint::Connection,
    handshake::CandidateConnection,
    EndpointRecord,
) {
    let payload = pairing::direct_payload(invited);
    let candidate = device.candidate();
    let connection = tokio::time::timeout(
        DEADLINE,
        candidate
            .endpoint
            .connect(pairing::host_addr(&payload), kr_protocol::hello::ALPN),
    )
    .await
    .expect("the candidate reaches the endpoint in time")
    .expect("the candidate reaches the endpoint the invitation names");
    let mut unpaired = handshake::connect_unpaired(&connection, candidate.identity)
        .await
        .expect("an unpaired connection");
    let challenge: PairRedeemResult = unpaired
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Challenge {
                invitation_id: payload.invitation_id,
            },
        )
        .await
        .expect("the endpoint issues a challenge");
    let PairRedeemResult::Challenge(challenge) = challenge else {
        panic!("the first redemption step answers with a challenge");
    };
    let (proof, _transcript) = kr_pairing::direct::redeem_proof(
        &payload,
        &challenge,
        &candidate.keys.authorisation,
        &candidate.declared,
        &pairing::HostPeer(*challenge.endpoint_id.as_bytes()),
    )
    .expect("a redemption proof");
    let locked: PairRedeemResult = unpaired
        .call(
            Method::PairRedeem,
            &PairRedeemParams::Direct(Box::new(proof)),
        )
        .await
        .expect("the endpoint accepts the redemption");
    let PairRedeemResult::Locked { .. } = locked else {
        panic!("a redemption locks the invitation");
    };
    let record = EndpointRecord {
        environment_id: String::new(),
        host_device_id: unpaired.selection.device_id.to_string(),
        host_key_revision: challenge.device_key_revision.get(),
        host_authorisation: hex(challenge.host_keys.authorisation.as_bytes()),
        endpoint_id: hex(challenge.endpoint_id.as_bytes()),
        addresses: payload
            .network_config
            .direct_addresses
            .iter()
            .map(|hint| hint.as_str().to_owned())
            .collect(),
    };
    (connection, unpaired, record)
}

/// Pairs a device that may view sessions with this installation's own endpoint.
#[tokio::test]
#[ignore = "runs inside a distribution against its own control daemon: scripts/e2e-wsl.sh"]
async fn pair_a_viewer_with_this_distribution() {
    let own = own();
    let mut client = own.daemon().await;
    let info: HostInfoResult = pairing::read(&mut client, Method::HostInfo, &())
        .await
        .expect("the daemon answers host.info");
    assert_eq!(
        info.environment_id, own.environment_id,
        "the daemon this distribution runs serves the installation's own environment"
    );
    let owner = the_owner(&own, &mut client).await;

    let keys = DeviceKeys::generate().expect("viewer keys");
    let viewer = Device::with_keys(keys.clone()).await;
    let signer = pairing::Signer::OwnerDevice(&owner);
    let invited = pairing::invite_direct(
        own.environment_id,
        &mut client,
        InviteGrantKind::SessionInvitation,
        &proposal(&[ActionRight::SessionView]),
        &signer,
    )
    .await
    .expect("the owner device confirms the invitation and the daemon issues it");
    let (connection, mut candidate, mut record) = redeem(&viewer, &invited).await;
    record.environment_id = own.environment_id.to_string();
    let status = pairing::owner_status(&mut client, invited.invitation_id)
        .await
        .expect("the owner's view");
    assert!(
        status.owner.0.and_then(|view| view.candidate.0).is_some(),
        "the owner is shown the candidate that redeemed"
    );
    let confirmed = pairing::confirm_candidate(
        own.environment_id,
        &mut client,
        invited.invitation_id,
        &signer,
    )
    .await
    .expect("the owner device confirms the viewer");
    assert!(
        !confirmed.event.first_owner,
        "the viewer is not the first owner"
    );
    // And the candidate learns which device it became on the connection it is already on.
    let told: PairStatusResult = candidate
        .call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: invited.invitation_id,
            },
        )
        .await
        .expect("the endpoint answers the candidate");
    assert!(
        matches!(
            told.status,
            PairStatus::Committed { device_id, .. } if device_id == confirmed.device_id
        ),
        "the candidate is told which device it became: {:?}",
        told.status
    );
    connection.close(0_u32.into(), b"paired");
    keep_keys("viewer", &keys);
    let kept = Viewer {
        device_id: confirmed.device_id.to_string(),
        grant_id: confirmed.grant_id.to_string(),
        endpoint: record.clone(),
    };
    std::fs::write(
        directory().join("viewer.json"),
        serde_json::to_vec(&kept).expect("the viewer record"),
    )
    .expect("the viewer record is kept");
    report(
        "endpoint",
        &serde_json::to_value(&record).expect("a record"),
    );
    report(
        "viewer",
        &json!({
            "device_id": kept.device_id,
            "grant_id": kept.grant_id,
            "keys": keys.public_keys(),
        }),
    );
}

/// Reads the viewer this suite paired with this distribution, and its keys.
fn the_viewer() -> (Viewer, DeviceKeys) {
    let text = std::fs::read(directory().join("viewer.json"))
        .expect("a viewer was paired with this distribution before");
    let viewer: Viewer = serde_json::from_slice(&text).expect("the viewer record");
    let keys = kept_keys("viewer").expect("the viewer's keys were kept");
    (viewer, keys)
}

/// KR-REQ-03.11: each installation has its own paired endpoint and its own grants. A viewer is
/// let into the distribution it was paired with and refused by every other one.
#[tokio::test]
#[ignore = "runs inside a distribution against its own control daemon: scripts/e2e-wsl.sh"]
async fn a_viewer_reaches_only_the_distribution_it_was_paired_with() {
    let (viewer, keys) = the_viewer();
    let device = Device::with_keys(keys).await;
    let device_id: DeviceId = viewer.device_id.parse().expect("a device identity");

    // Its own endpoint lets it in, and answers as the environment it was paired with.
    let transport = tokio::time::timeout(
        DEADLINE,
        NetworkTransport::connect(
            device.endpoint(),
            viewer.endpoint.address(),
            &device.paired_identity(device_id),
            &viewer.endpoint.peer(),
            SendLimits::default(),
        ),
    )
    .await
    .expect("the paired connection is made in time")
    .expect("the viewer is let into the distribution it was paired with");
    let session = Session::start(Arc::new(transport)).expect("a session");
    let info: HostInfoResult = tokio::time::timeout(DEADLINE, session.read(Method::HostInfo, &()))
        .await
        .expect("host.info is answered in time")
        .expect("the viewer reads host.info where it is paired");
    assert_eq!(
        info.environment_id.to_string(),
        viewer.endpoint.environment_id,
        "the endpoint the viewer was paired with answers as that environment"
    );
    drop(session);

    // Another distribution's endpoint, which the script describes.
    let other: EndpointRecord = serde_json::from_str(
        &std::env::var("KR_ACC_OTHER").expect("KR_ACC_OTHER describes the other endpoint"),
    )
    .expect("the other endpoint's record");
    assert_ne!(
        other.endpoint_id, viewer.endpoint.endpoint_id,
        "two distributions have two endpoint identities"
    );
    assert_ne!(
        other.environment_id, viewer.endpoint.environment_id,
        "two distributions are two environments"
    );

    // Anyone can reach the other endpoint, and what answers there is the endpoint it names: the
    // address leads to it, so a refusal below is its decision and not a failed connection.
    let candidate = device.candidate();
    let connection = tokio::time::timeout(
        DEADLINE,
        candidate
            .endpoint
            .connect(other.address(), kr_protocol::hello::ALPN),
    )
    .await
    .expect("the other endpoint is reached in time")
    .expect("the other endpoint is reachable from this distribution");
    let mut unpaired = handshake::connect_unpaired(&connection, candidate.identity)
        .await
        .expect("the other endpoint serves an unpaired device");
    let asked: Result<PairStatusResult, TransportError> = unpaired
        .call(
            Method::PairStatus,
            &PairStatusParams {
                invitation_id: InvitationId::new(Uuid::from_bytes([0x7e; 16])),
            },
        )
        .await;
    match &asked {
        Ok(result) => assert!(
            !matches!(result.status, PairStatus::Committed { .. }),
            "no invitation of the other endpoint is the viewer's"
        ),
        Err(TransportError::Refused(_)) => {}
        Err(error) => panic!("the other endpoint did not answer an unpaired device: {error}"),
    }
    connection.close(0_u32.into(), b"reached");

    // The viewer is refused there. The other endpoint holds no record of the viewer's endpoint
    // key, so it answers the viewer's offer as it answers any unpaired peer, finds no pairing
    // exchange in what the viewer sends next, and ends the connection with the close it gives an
    // unpaired peer. That close is the endpoint's own decision, read as a code: a connection that
    // timed out, was reset or could not be made carries none, and a viewer let in has no such
    // close.
    let connection = tokio::time::timeout(
        DEADLINE,
        kr_transport::endpoint::connect(
            device.endpoint(),
            other.address(),
            kr_protocol::hello::ALPN,
        ),
    )
    .await
    .expect("the other endpoint is reached in time")
    .expect("the other endpoint is reachable from this distribution");
    let attempt = tokio::time::timeout(
        DEADLINE,
        handshake::connect(
            &connection,
            &device.paired_identity(device_id),
            &other.peer(),
        ),
    )
    .await
    .expect("the other endpoint answers the viewer in time");
    assert!(
        attempt.is_err(),
        "the viewer was let into a distribution it was not paired with"
    );
    let closed = tokio::time::timeout(DEADLINE, connection.closed())
        .await
        .expect("the other endpoint closes the viewer's connection in time");
    let iroh::endpoint::ConnectionError::ApplicationClosed(close) = closed else {
        panic!(
            "the other endpoint did not end the viewer's connection by its own close: {closed:?}"
        );
    };
    let code = u64::from(close.error_code);
    assert_eq!(
        code,
        u64::from(kr_transport::listener::REFUSED_UNPAIRED),
        "the other endpoint ends the viewer's connection as it ends an unpaired peer's"
    );
    report(
        "reach",
        &json!({
            "own": viewer.endpoint.environment_id,
            "other": other.environment_id,
            "other_closed_the_viewer_with_code": code,
            "reason": String::from_utf8_lossy(&close.reason),
        }),
    );
}

/// What this installation holds of devices and grants, as one value that two reads compare.
///
/// What a device acknowledged of the authority revision is left out: it is bookkeeping a
/// connection updates, and not a grant.
#[tokio::test]
#[ignore = "runs inside a distribution against its own control daemon: scripts/e2e-wsl.sh"]
async fn report_the_devices_and_grants() {
    let own = own();
    let mut client = own.daemon().await;
    let devices = owner_devices(&mut client).await;
    let grants: GrantListResult = pairing::read(
        &mut client,
        Method::GrantList,
        &GrantListParams {
            session_id: kr_protocol::scalars::Nullable::null(),
            include_resolved: true,
        },
    )
    .await
    .expect("the owner reads the grants");
    let held = json!({
        "environment_id": own.environment_id.to_string(),
        "authority_revision": devices.authority_revision,
        "devices": devices.devices.iter().map(|device| json!({
            "device_id": device.device_id,
            "display_name": device.display_name,
            "grant_id": device.grant_id,
            "paired_at_ms": device.paired_at_ms,
            "revoked": device.revoked,
            "manages_host": device.manages_host,
            "keys": device.keys,
        })).collect::<Vec<_>>(),
        // What each grant is and whether it was revoked, and not where it stands now: a grant
        // that expires between two reads has not been changed by anything.
        "grants": grants.grants.iter().map(|summary| json!({
            "grant": summary.grant,
            "revoked_at_ms": summary.revoked_at_ms,
            "revoked_by_parent": summary.revoked_by_parent,
        })).collect::<Vec<_>>(),
    });
    report("held", &held);
}
