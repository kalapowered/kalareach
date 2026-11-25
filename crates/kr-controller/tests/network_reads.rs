//! The reads a paired device makes that the daemon decides itself, over a real paired connection.
//!
//! What these demonstrate, for the paired-device ingress: `grant.list`, and the reads this host
//! refuses a device. The method table admits a paired device to `grant.list`, `download.begin` and
//! `download.chunk`, among others.
//!
//! A device lists the grants it issued and everything delegated from them, which is what the
//! sharing service shows any issuer other than this host itself, and it needs `session.share` to
//! ask. The downloads are refused by name, each with the reason this host does not serve them to a
//! device: a refusal a device can act on rather than one that names no reason. Before either, a
//! device whose grant does not reach what it asks about is refused as it always was, and so is a
//! description of a session its grant does not reach.
//!
//! No worker is started here: every answer below is the daemon's own.

#[path = "support/backup_seed.rs"]
mod backup_seed;
mod net_support;

use std::collections::BTreeSet;

use backup_seed::SeededBackups;
use kr_client::session::Session;
use kr_controller::grants::GrantRecord;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::backup_checkpoint::{
    BackupCheckpointParams, BackupCheckpointResult, HostCheckpoint,
};
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
    DownloadSource,
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
///
/// KR-REQ-23.49, the part about `grant.list` as a sharing method: a device lists the grants it
/// issued and everything delegated from them and no other, needs `session.share`, and is refused a
/// listing for a session its grant does not admit. Not shown here: expiry, owner confirmation,
/// parent rights and the barrier of the other grant methods.
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

/// The two reads the method table admits for a paired device that this host does not serve one
/// are each refused by name, as `UNSUPPORTED_CAPABILITY` with the method and the reason in the
/// message. A device whose grant does not reach the subject or carry the right is refused first,
/// as it always was.
///
/// KR-REQ-23.41, the part about file grants: a device without `files.read` is refused
/// `download.begin` with a permission error. Not shown here: the draft methods, owner revision,
/// environment handles and the upload methods' own rights; that the two download reads this host
/// does not serve a device are refused by name is not a clause of the row. The refused device's
/// grant also sees only one other session, and the case does not read the refusal's message, so
/// it does not tie the refusal to `files.read` alone.
///
/// KR-REQ-23.34, the part about describe as a rights-bound read: a device whose grant sees another
/// session is refused the description of this one with a permission error. Not shown here: the
/// other session methods, and describe as a filtered read.
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
    for (method, refusal) in [Method::DownloadBegin, Method::DownloadChunk]
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

/// KR-REQ-10.50, the part about file and attachment bytes needing a file grant of their own: a
/// device that holds `session.view`, the live screen and a history that reaches every moment is
/// refused the two methods that serve file bytes, and the one difference between it and a device
/// that is not refused for its rights is `files.read`.
///
/// The first device is refused `PERMISSION_DENIED`, before the route. The second holds the right
/// and is refused by name as every device is, since this host opens no chunk stream on a network
/// connection, so no byte reaches either. That refusal is the control, and a host that serves a
/// device a chunk stream turns it into a served read. Not shown here: a served byte, since none
/// is, and the other rights of the transfer methods.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_50_a_device_that_holds_the_screen_and_history_but_not_files_read_is_refused_a_download()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let transfer_id = TransferId::new(kr_ipc::new_uuid());
    let mut reached = Vec::new();
    for rights in [
        &[ActionRight::SessionView][..],
        &[ActionRight::SessionView, ActionRight::FilesRead][..],
    ] {
        let device = Device::create().await;
        let mut grant = proposal(rights);
        grant.history.lower_bound_ms = Nullable::some(kr_protocol::scalars::TimestampMs::new(0));
        assert!(grant.history.include_live_screen, "the live screen is held");
        let record = pair_with(&host, &device, &owner, grant).await;
        let session = connect(&host, &device, &record).await;
        let begin = refused::<_, DownloadBeginResult>(
            &session,
            Method::DownloadBegin,
            &DownloadBeginParams {
                environment_id: host.environment_id,
                resume_transfer_id: Nullable::null(),
                source: Nullable::some(DownloadSource::Attachment { transfer_id }),
                device_id: Nullable::some(record.device_id),
            },
        )
        .await;
        let chunk = refused::<_, DownloadChunkResult>(
            &session,
            Method::DownloadChunk,
            &DownloadChunkParams {
                transfer_id,
                index: U64::ZERO,
            },
        )
        .await;
        reached.push((begin.code, chunk.code));
        session.close();
    }
    assert_eq!(
        reached,
        [
            (ErrorCode::PermissionDenied, ErrorCode::PermissionDenied),
            (
                ErrorCode::UnsupportedCapability,
                ErrorCode::UnsupportedCapability
            ),
        ],
        "without files.read the read is refused for it; with it, by name"
    );
    host.stop().await;
}

/// What a device reads of the host's backups with `backup.checkpoint`: the checkpoint the host
/// answered, or the words of what came back in its place. A case asserts on the whole, so a read
/// the host does not serve fails the case's own assertion.
async fn read_checkpoint(session: &Session) -> Result<Nullable<HostCheckpoint>, String> {
    session
        .read(Method::BackupCheckpoint, &BackupCheckpointParams {})
        .await
        .map(|answer: BackupCheckpointResult| answer.checkpoint)
        .map_err(|error| format!("{error:?}"))
}

/// An owner device, over a real paired connection, is told the newest generation the host's
/// service accepted: nothing before the host has a setup or a generation, and each newer
/// generation the host publishes after. A device that does not manage the host and the owner's
/// own local socket are refused, and a host whose record of its newest generation is damaged
/// answers `STORAGE_UNAVAILABLE`, never null and never the generation before it. The answer
/// carries the archive, the service, the generation and the manifest hash, and nothing else.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_owner_device_is_told_the_newest_generation_the_host_published_and_no_one_else_is() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = pair_with(&host, &device, &owner, proposal(&[ActionRight::HostManage])).await;
    let session = connect(&host, &device, &record).await;

    assert_eq!(
        read_checkpoint(&session).await,
        Ok(Nullable::null()),
        "a host with no setup"
    );
    let service = host.controller().backup();
    let seeded = SeededBackups::set_up(service);
    assert_eq!(
        read_checkpoint(&session).await,
        Ok(Nullable::null()),
        "a setup and no generation"
    );
    let first = seeded.publish(service, 1);
    assert_eq!(
        read_checkpoint(&session).await,
        Ok(Nullable::some(first)),
        "the first generation the service accepted"
    );
    let second = seeded.publish(service, 2);
    assert_eq!(
        read_checkpoint(&session).await,
        Ok(Nullable::some(second)),
        "a newer generation, read from a host already running"
    );

    // A device that does not manage the host is refused, as it always was.
    let viewer = Device::create().await;
    let viewer_record = pair_with(
        &host,
        &viewer,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let viewing = connect(&host, &viewer, &viewer_record).await;
    let refusal = viewing
        .read::<_, BackupCheckpointResult>(Method::BackupCheckpoint, &BackupCheckpointParams {})
        .await;
    assert!(
        matches!(
            &refusal,
            Err(kr_client::error::ClientError::Host(error))
                if error.code == ErrorCode::PermissionDenied
        ),
        "a device that does not manage the host is refused: {refusal:?}"
    );
    viewing.close();

    // The local socket does not serve it: the method's ingress is the paired device.
    let mut local = host.client().await;
    let answered = local
        .request(Method::BackupCheckpoint, &BackupCheckpointParams {})
        .await;
    assert!(
        matches!(
            &answered,
            Ok(Err(error))
                if error.code == ErrorCode::PermissionDenied
                    && error.message
                        == "the backup checkpoint is read by a paired device, and the local \
                            socket does not serve it"
        ),
        "the local socket is refused with the checkpoint's own words: {answered:?}"
    );

    // A newest row the host cannot read back is a refusal the device can tell from none.
    let backups = host.registry_database().with_file_name("backup.sqlite");
    rusqlite::Connection::open(backups)
        .expect("the backup store")
        .execute(
            "UPDATE generations SET descriptor = NULL WHERE backup_generation = 2",
            [],
        )
        .expect("the row is damaged");
    let damaged = session
        .read::<_, BackupCheckpointResult>(Method::BackupCheckpoint, &BackupCheckpointParams {})
        .await;
    assert!(
        matches!(
            &damaged,
            Err(kr_client::error::ClientError::Host(error))
                if error.code == ErrorCode::StorageUnavailable
        ),
        "a newest row the host cannot read back is a refusal, never null: {damaged:?}"
    );
    session.close();
    host.stop().await;
}
