//! A paired device's four public keys on the host: kept at pairing, reported by `device.list` to an
//! owner's device, and declared once by a device paired before the host kept them all.
//!
//! Another device seals to a device's stored-envelope key only when a host reports it, because the
//! pairing the owner approved is what binds that key to the device. These tests hold the host to
//! that: every key a pairing bound is on record, the report is served to an owner's device over its
//! own connection and to nobody without `host.manage`, and a device whose record lacks two keys can
//! supply them once, signed by the authorisation key its pairing recorded, without losing its host
//! access meanwhile.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::DurationMs;
use kr_protocol::sharing::{
    DEVICE_KEYS_DOMAIN, DeviceKeysCompleteParams, DeviceKeysCompleteResult, DeviceKeysDeclaration,
    DeviceListParams, DeviceListResult, DeviceSummary,
};
use net_support::{Device, Host, RawDevice};

/// What an owner's device holds on a host.
const OWNER: &[ActionRight] = &[ActionRight::HostManage, ActionRight::SessionView];

/// What a viewer's device holds.
const VIEWER: &[ActionRight] = &[ActionRight::SessionView];

const LIFETIME: DurationMs = DurationMs::new(60_000);

async fn listed(session: &kr_client::session::Session) -> DeviceListResult {
    session
        .read(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: false,
            },
        )
        .await
        .expect("device.list is served to an owner's device")
}

fn entry(list: &DeviceListResult, device_id: kr_protocol::ids::DeviceId) -> &DeviceSummary {
    list.devices
        .iter()
        .find(|device| device.device_id == device_id)
        .expect("the device is listed")
}

/// Signs a declaration of `keys` as `signer`, for the device `device_id`.
fn declaration(
    device_id: kr_protocol::ids::DeviceId,
    keys: kr_protocol::pairing::DevicePublicKeys,
    signer: &DeviceKeys,
) -> DeviceKeysCompleteParams {
    let signature = kr_crypto::sign::sign_object(
        &signer.authorisation,
        DEVICE_KEYS_DOMAIN,
        &DeviceKeysDeclaration { device_id, keys },
    )
    .expect("a signature");
    DeviceKeysCompleteParams { keys, signature }
}

async fn complete(
    host: &Host,
    session: &kr_client::session::Session,
    params: &DeviceKeysCompleteParams,
) -> std::result::Result<DeviceKeysCompleteResult, kr_client::error::ClientError> {
    session
        .mutate(
            Method::DeviceKeysComplete,
            ActionTarget::environment(host.environment_id),
            None,
            &ParamsValue::empty(),
            params,
            LIFETIME,
        )
        .await
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a completion answers with its result")
                .to_typed()
                .expect("a completion result")
        })
}

/// Holds a device's row as a host that kept two of its keys wrote it.
fn as_an_earlier_host_wrote_it(host: &Host, device_id: kr_protocol::ids::DeviceId) {
    let connection = rusqlite::Connection::open(host.registry_database()).expect("the registry");
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .expect("a timeout");
    let changed = connection
        .execute(
            "UPDATE network_devices
                SET stored_envelope_key = NULL, notification_preview = NULL
              WHERE device_id = ?1",
            rusqlite::params![device_id.get().as_bytes().as_slice()],
        )
        .expect("the row is written");
    assert_eq!(changed, 1, "the device has a row");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pairing_keeps_all_four_keys_and_an_owner_device_reads_them() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner, net_support::proposal(OWNER)).await;
    assert_eq!(record.public_keys(), Some(device.keys().public_keys()));
    let session = net_support::connect(&host, &device, &record).await;

    // An owner's device reads the list over its own connection, with every key the pairing bound
    // and the fact that its grant manages this host.
    let list = listed(&session).await;
    let own = entry(&list, record.device_id);
    assert_eq!(own.keys.0, Some(device.keys().public_keys()));
    assert!(own.manages_host);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_without_host_manage_is_listed_as_such_and_is_not_served_the_list() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let viewer = Device::create().await;
    let record =
        net_support::pair_with(&host, &viewer, &owner, net_support::proposal(VIEWER)).await;
    let session = net_support::connect(&host, &viewer, &record).await;

    // The owner's own socket lists it, with its keys and without the right to manage this host.
    let mut control = host.client().await;
    let answer = control
        .request(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: false,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("device.list succeeds for the owner");
    let list: DeviceListResult = answer.to_typed().expect("a device list");
    let listed_viewer = entry(&list, record.device_id);
    assert_eq!(listed_viewer.keys.0, Some(viewer.keys().public_keys()));
    assert!(!listed_viewer.manages_host);

    // Over its own connection, a device that does not manage this host is not served the list.
    let refused = session
        .read::<_, DeviceListResult>(
            Method::DeviceList,
            &DeviceListParams {
                include_revoked: false,
            },
        )
        .await
        .expect_err("a device without host.manage is not served the list");
    assert_eq!(refused.code(), ErrorCode::PermissionDenied);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_paired_before_the_host_kept_its_keys_declares_them_once() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner, net_support::proposal(OWNER)).await;
    as_an_earlier_host_wrote_it(&host, record.device_id);
    let session = net_support::connect(&host, &device, &record).await;

    // Until it declares them, its keys are reported as incomplete, and its host access is intact.
    assert_eq!(
        entry(&listed(&session).await, record.device_id).keys.0,
        None
    );
    let _: HostInfoResult = session
        .read(Method::HostInfo, &())
        .await
        .expect("a device with two keys on record keeps its host access");

    let keys = device.keys().public_keys();

    // A declaration not signed by the authorisation key the pairing recorded is refused.
    let stranger = DeviceKeys::generate().expect("other keys");
    let forged = complete(
        &host,
        &session,
        &declaration(record.device_id, keys, &stranger),
    )
    .await
    .expect_err("another key's signature");
    assert_eq!(forged.code(), ErrorCode::PermissionDenied);
    // So is one whose transport or authorisation key is not the recorded one.
    let mut moved = keys;
    moved.transport = stranger.public_keys().transport;
    let wrong_keys = complete(
        &host,
        &session,
        &declaration(record.device_id, moved, device.keys()),
    )
    .await
    .expect_err("a transport key the pairing did not bind");
    assert_eq!(wrong_keys.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        entry(&listed(&session).await, record.device_id).keys.0,
        None
    );

    // The device's own signed declaration completes the record.
    let completed = complete(
        &host,
        &session,
        &declaration(record.device_id, keys, device.keys()),
    )
    .await
    .expect("the device declares its own keys");
    assert_eq!(completed.device_id, record.device_id);
    assert_eq!(completed.keys, keys);
    assert_eq!(
        entry(&listed(&session).await, record.device_id).keys.0,
        Some(keys)
    );

    // Declaring the same keys again is answered with the same record; declaring others is refused,
    // because a declaration completes a record and never replaces a key.
    let again = complete(
        &host,
        &session,
        &declaration(record.device_id, keys, device.keys()),
    )
    .await
    .expect("the same declaration");
    assert_eq!(again.keys, keys);
    let mut replaced = keys;
    replaced.stored_envelope = stranger.public_keys().stored_envelope;
    let replacement = complete(
        &host,
        &session,
        &declaration(record.device_id, replaced, device.keys()),
    )
    .await
    .expect_err("a second declaration of other keys");
    assert_eq!(replacement.code(), ErrorCode::PermissionDenied);
    assert_eq!(
        entry(&listed(&session).await, record.device_id).keys.0,
        Some(keys)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exact_retry_of_a_completion_is_answered_from_its_record_after_a_reconnect() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(&host, &device, &owner, net_support::proposal(OWNER)).await;
    as_an_earlier_host_wrote_it(&host, record.device_id);

    let params = declaration(record.device_id, device.keys().public_keys(), device.keys());
    let action = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget::environment(host.environment_id);

    let first_connection = RawDevice::connect(&host, &device, &record).await;
    first_connection.claim();
    let first = first_connection
        .mutate(Method::DeviceKeysComplete, action, target.clone(), &params)
        .await
        .expect("the declaration completes the record");
    let window = first_connection.action_window_id();
    first_connection.close();

    // The reply is taken to be lost. On a later connection, with a window of its own, the device
    // presents the same action in the window it was first sent in, and is answered from the
    // record of what it did rather than told the window has gone.
    let later_connection = RawDevice::connect(&host, &device, &record).await;
    later_connection.claim();
    let replayed = later_connection
        .mutate_in(
            window,
            Method::DeviceKeysComplete,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("an exact retry is answered from its record");
    assert_eq!(replayed, first);

    // The same identity presented in the later connection's own window is another request, and
    // is refused rather than performed again.
    let reused = later_connection
        .mutate(Method::DeviceKeysComplete, action, target, &params)
        .await
        .expect_err("a reused action identity");
    assert_eq!(reused.code, ErrorCode::IdConflict);
}
