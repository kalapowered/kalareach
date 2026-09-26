//! The reads a paired device makes that the daemon decides itself, over a real paired connection.
//!
//! What these demonstrate, for the paired-device ingress: KR-REQ-23.49 for `grant.list`, and
//! KR-REQ-23.34 and KR-REQ-23.41 for the reads this host refuses a device. The method table admits
//! a paired device to `grant.list`, `session.describe`, `upload.status`, `download.begin` and
//! `download.chunk`.
//!
//! A device lists the grants it issued and everything delegated from them, which is what the
//! sharing service shows any issuer other than this host itself, and it needs `session.share` to
//! ask. The other four are refused by name, each with the reason this host does not serve it to a
//! device: a refusal a device can act on rather than one that names no reason. Before either, a
//! device whose grant does not reach what it asks about is refused as it always was.
//!
//! No worker is started here: every answer below is the daemon's own.

mod net_support;

use std::collections::BTreeSet;

use kr_client::session::Session;
use kr_controller::grants::GrantRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::describe::{SessionDescribeParams, SessionDescribeResult};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::{Grant, GrantExpiry, SessionSelector};
use kr_protocol::ids::{DeviceId, GrantId, SessionId, TransferId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::sharing::{GrantListParams, GrantListResult};
use kr_protocol::transfer::{
    DownloadBeginParams, DownloadBeginResult, DownloadChunkParams, DownloadChunkResult,
    DownloadSource, UploadStatusParams, UploadStatusResult,
};
use net_support::{Device, Host, connect, pair_with, proposal};

/// Runs one read over the network and returns the host's refusal of it.
async fn refused<P, R>(session: &Session, method: Method, params: &P) -> ProtocolError
where
    P: serde::Serialize + ?Sized,
    R: kr_protocol::wire::WireMessage + std::fmt::Debug,
{
    match session.read::<P, R>(method, params).await {
        Ok(answer) => panic!("{} was answered: {answer:?}", method.as_str()),
        Err(kr_client::error::ClientError::Host(error)) => error,
        Err(other) => panic!(
            "{} failed before the host answered: {other:?}",
            method.as_str()
        ),
    }
}

/// Writes one grant into the host's own store, from `issuer` to `recipient`, delegated from
/// `parent` when it names one.
fn issued(host: &Host, issuer: DeviceId, recipient: DeviceId, parent: Option<GrantId>) -> Grant {
    let grant = Grant {
        grant_id: GrantId::new(kr_ipc::new_uuid()),
        parent_grant_id: Nullable(parent),
        issuer_device_id: issuer,
        recipient_device_id: recipient,
        authority_revision: host.controller().policy().authority_revision(),
        environment_selector: kr_protocol::grant::EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: kr_protocol::grant::HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: kr_protocol::scalars::CanonicalSet::new(),
            named_approvals: kr_protocol::scalars::CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    host.controller()
        .sharing()
        .grants()
        .issue(
            &GrantRecord {
                grant: grant.clone(),
                session_id: None,
                issued_at_ms: 1_000,
                activated_at_ms: Some(1_000),
                revoked_at_ms: None,
                revoked_by_parent: None,
            },
            || Ok(()),
        )
        .expect("the grant is written");
    grant
}

/// A device lists the grants it issued and everything delegated from them, and nothing this host
/// issued or another device issued outside that line. A device without `session.share` is refused,
/// and so is one whose grant does not admit the session its listing names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_lists_the_grants_it_issued_and_what_was_delegated_from_them() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let sharer = Device::create().await;
    let sharer_record = pair_with(
        &host,
        &sharer,
        &owner,
        proposal(&[ActionRight::SessionView, ActionRight::SessionShare]),
    )
    .await;
    let viewer = Device::create().await;
    let viewer_record = pair_with(
        &host,
        &viewer,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;

    // What the sharer issued to the viewer, what the viewer delegated from that, and what this host
    // issued to the viewer itself.
    let shared = issued(
        &host,
        sharer_record.device_id,
        viewer_record.device_id,
        None,
    );
    let delegated = issued(
        &host,
        viewer_record.device_id,
        sharer_record.device_id,
        Some(shared.grant_id),
    );
    let hosts = issued(
        &host,
        host.controller().sharing().host_device_id(),
        viewer_record.device_id,
        None,
    );

    let session = connect(&host, &sharer, &sharer_record).await;
    let listed: GrantListResult = session
        .read(
            Method::GrantList,
            &GrantListParams {
                session_id: Nullable::null(),
                include_resolved: true,
            },
        )
        .await
        .expect("a device lists the grants it issued");
    let grants: BTreeSet<GrantId> = listed
        .grants
        .iter()
        .map(|summary| summary.grant.grant_id)
        .collect();
    assert_eq!(
        grants,
        BTreeSet::from([shared.grant_id, delegated.grant_id]),
        "the grant this device issued and the one delegated from it, and not this host's {}",
        hosts.grant_id
    );
    session.close();

    // Without `session.share`, the listing is refused, as it always was.
    let viewing = connect(&host, &viewer, &viewer_record).await;
    let refusal = refused::<_, GrantListResult>(
        &viewing,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::null(),
            include_resolved: true,
        },
    )
    .await;
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    viewing.close();

    // A listing that names a session the grant does not admit is refused before anything is read.
    let narrow = Device::create().await;
    let mut narrow_grant = proposal(&[ActionRight::SessionView, ActionRight::SessionShare]);
    narrow_grant.session_selector = SessionSelector::These {
        session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
    };
    let narrow_record = pair_with(&host, &narrow, &owner, narrow_grant).await;
    let narrowed = connect(&host, &narrow, &narrow_record).await;
    let refusal = refused::<_, GrantListResult>(
        &narrowed,
        Method::GrantList,
        &GrantListParams {
            session_id: Nullable::some(SessionId::new(kr_ipc::new_uuid())),
            include_resolved: true,
        },
    )
    .await;
    assert_eq!(refusal.code, ErrorCode::PermissionDenied, "{refusal:?}");
    narrowed.close();
    host.stop().await;
}

/// The four reads the method table admits for a paired device that this host does not serve one
/// are each refused by name, as `UNSUPPORTED_CAPABILITY` with the method and the reason in the
/// message. A device whose grant does not reach the subject or carry the right is refused first,
/// as it always was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_this_host_does_not_serve_a_device_is_refused_by_name() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = pair_with(
        &host,
        &device,
        &owner,
        proposal(&[
            ActionRight::SessionView,
            ActionRight::FilesUpload,
            ActionRight::FilesRead,
        ]),
    )
    .await;
    let session = connect(&host, &device, &record).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let transfer_id = TransferId::new(kr_ipc::new_uuid());
    let begin = DownloadBeginParams {
        environment_id: host.environment_id,
        resume_transfer_id: Nullable::null(),
        source: Nullable::some(DownloadSource::Attachment { transfer_id }),
        device_id: Nullable::some(record.device_id),
    };

    let refusals = [
        refused::<_, SessionDescribeResult>(
            &session,
            Method::SessionDescribe,
            &SessionDescribeParams { session_id },
        )
        .await,
        refused::<_, UploadStatusResult>(
            &session,
            Method::UploadStatus,
            &UploadStatusParams { transfer_id },
        )
        .await,
        refused::<_, DownloadBeginResult>(&session, Method::DownloadBegin, &begin).await,
        refused::<_, DownloadChunkResult>(
            &session,
            Method::DownloadChunk,
            &DownloadChunkParams {
                transfer_id,
                index: U64::ZERO,
            },
        )
        .await,
    ];
    for (method, refusal) in [
        Method::SessionDescribe,
        Method::UploadStatus,
        Method::DownloadBegin,
        Method::DownloadChunk,
    ]
    .into_iter()
    .zip(refusals)
    {
        assert_eq!(
            refusal.code,
            ErrorCode::UnsupportedCapability,
            "{}: {refusal:?}",
            method.as_str()
        );
        assert!(
            refusal.message.starts_with(method.as_str()),
            "the refusal names the read it refuses: {refusal:?}"
        );
    }
    session.close();

    // A device whose grant sees another session is refused the description of this one, and one
    // without `files.read` is refused a download, each as it always was.
    let elsewhere = Device::create().await;
    let mut elsewhere_grant = proposal(&[ActionRight::SessionView, ActionRight::FilesUpload]);
    elsewhere_grant.session_selector = SessionSelector::These {
        session_ids: [SessionId::new(kr_ipc::new_uuid())].into_iter().collect(),
    };
    let elsewhere_record = pair_with(&host, &elsewhere, &owner, elsewhere_grant).await;
    let elsewhere_session = connect(&host, &elsewhere, &elsewhere_record).await;
    let outside = refused::<_, SessionDescribeResult>(
        &elsewhere_session,
        Method::SessionDescribe,
        &SessionDescribeParams { session_id },
    )
    .await;
    assert_eq!(outside.code, ErrorCode::PermissionDenied, "{outside:?}");
    let unread = refused::<_, DownloadBeginResult>(
        &elsewhere_session,
        Method::DownloadBegin,
        &DownloadBeginParams {
            device_id: Nullable::some(elsewhere_record.device_id),
            ..begin
        },
    )
    .await;
    assert_eq!(unread.code, ErrorCode::PermissionDenied, "{unread:?}");
    elsewhere_session.close();
    host.stop().await;
}
