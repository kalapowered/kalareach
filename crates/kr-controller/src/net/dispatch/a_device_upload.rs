//! What the door does with a paired device's uploads: `upload.begin`, `upload.finish`,
//! `upload.cancel` and `upload.status`, and the chunk that travels on a stream of its own.
//!
//! The transfer service performs each under the device's own principal. The chunk is served on an
//! attachment-chunk stream and refused by name on the control stream, and every other upload method
//! is served on the control stream.

use std::sync::Arc;

use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request, Response,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActorId, RequestId, SessionEpoch, TransferId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, U64};
use kr_protocol::transfer::{
    ChunkDescriptor, UploadBeginParams, UploadChunkParams, UploadStatusParams, UploadStatusResult,
};

use super::a_copy_from_a_services_record::{mutation_of, written};
use super::routes::DeviceRead;
use super::write_boundary::paired_connection;
use super::writes::DeviceWrite;
use crate::service::a_close_a_worker_never_answers as fake;
use crate::service::the_fence_at_every_effect::refused_for_a_fence;
use crate::transfer::TransferAdmission;

/// How long a case waits for a read to reach the place it is stopped at.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// An upload of `bytes` begun for `actor` in the transfer service directly.
fn begun_for(world: &fake::Silent, actor: &ActorId, bytes: &[u8]) -> TransferId {
    world
        .controller
        .transfer()
        .service()
        .upload_begin(
            actor,
            &UploadBeginParams {
                environment_id: world.environment_id,
                session_id: Nullable::null(),
                device_id: Nullable::null(),
                declared_byte_len: U64::new(bytes.len() as u64),
                declared_digest: Digest256::from_bytes(kr_cbor::sha256(bytes)),
                declared_media_type: "application/octet-stream".to_owned(),
                original_file_name: "notes.bin".to_owned(),
            },
            None,
            None,
        )
        .expect("the upload begins")
        .transfer_id
}

fn status_request(transfer_id: TransferId) -> Request {
    Request {
        request_id: RequestId::new(1),
        method: Method::UploadStatus.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&UploadStatusParams { transfer_id }).expect("encodes"),
    }
}

/// The refusal an answer carries, or the result of `UploadStatusResult` it holds.
fn status_of(answer: &ControlFrame) -> Result<UploadStatusResult, ProtocolError> {
    let ControlFrame::Response(Response { outcome, .. }) = answer else {
        panic!("a response was expected: {answer:?}");
    };
    match outcome {
        Outcome::Ok(value) => Ok(value.to_typed().expect("a status")),
        Outcome::Error(error) => Err(error.clone()),
    }
}

/// KR-REQ-23.21 and KR-REQ-23.41: the routing of the walk lists every upload method as served. The
/// four methods of an upload and the read that tells a device which streams the host takes each
/// have a route that performs them, and the chunk is served only through the stream door. None is
/// refused by name for lack of a part of the host.
#[test]
fn the_walk_serves_the_upload_methods_and_the_reads_that_go_with_them() {
    for method in [
        Method::UploadBegin,
        Method::UploadFinish,
        Method::UploadCancel,
    ] {
        let route = DeviceWrite::of(method);
        assert!(
            matches!(route, Some(route) if !matches!(route, DeviceWrite::Refused(_))),
            "{method:?} is served to a paired device: {route:?}"
        );
    }
    assert_eq!(
        DeviceWrite::of(Method::UploadChunk),
        Some(DeviceWrite::Chunk),
        "a chunk is served on a stream"
    );
    for method in [Method::UploadStatus, Method::TransferStreams] {
        let route = DeviceRead::of(method);
        assert!(
            matches!(route, Some(route) if !matches!(route, DeviceRead::Refused(_))),
            "{method:?} is served to a paired device: {route:?}"
        );
    }
}

/// KR-REQ-23.21 and KR-REQ-09.09: a chunk another attempt recorded, which the service finds after
/// the door's own look for a record, is told as the copy it is and is not given back while this
/// host owes a fence it could not raise: the end check the serial path makes decides, and the
/// answer that goes back is withheld. Once the fence is gone the chunk is answered from its record
/// again, and it was staged all along. The control is the same attempt with nothing owed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_another_attempt_recorded_is_not_given_back_while_a_fence_is_owed() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 40, &[ActionRight::FilesUpload]);
    let actor = connection.device.principal();
    let bytes = [7_u8; 96];
    let transfer_id = begun_for(&world, &actor, &bytes);
    let mutation = mutation_of(
        &world,
        &connection,
        Method::UploadChunk,
        1,
        ParamsValue::from_typed(&UploadChunkParams {
            transfer_id,
            chunk: ChunkDescriptor {
                index: U64::ZERO,
                byte_len: U64::new(bytes.len() as u64),
                digest: Digest256::from_bytes(kr_cbor::sha256(&bytes)),
            },
            bytes: Bytes::new(bytes.to_vec()),
        })
        .expect("encodes"),
    );
    let admission = fake::admission(controller, world.accepted).await;
    let attempt = || {
        controller.transfer().write(
            &actor,
            &mutation,
            Method::UploadChunk,
            TransferAdmission::new(Arc::clone(controller), admission),
            None,
        )
    };

    let first = attempt().await;
    assert!(
        !first.is_copied(),
        "the attempt that stages the chunk is not told as a copy of an answer it recorded itself"
    );
    first
        .into_answer()
        .expect("the first attempt stages the chunk");
    let late = attempt().await;
    assert!(late.is_copied(), "the late attempt is given the record");
    late.into_answer()
        .expect("with nothing owed the late attempt is answered from the record");

    controller.hold_fence(true);
    let refused = attempt()
        .await
        .into_withheld()
        .expect_err("a fence this host owes stops the retained answer");
    controller.hold_fence(false);
    refused_for_a_fence(&refused);
    attempt()
        .await
        .into_answer()
        .expect("once the fence is gone it is answered again");
    let status = controller
        .transfer()
        .service()
        .upload_status(&actor, &UploadStatusParams { transfer_id })
        .expect("the upload's status");
    assert_eq!(
        status.received_byte_len.get(),
        bytes.len() as u64,
        "the chunk is staged"
    );
    world.serving.abort();
}

/// KR-REQ-23.21 and KR-REQ-09.09: an `upload.status` is a read of recorded state, and it goes
/// through the end check a recorded answer is owed. A fence this host comes to owe after the
/// service has read the chunks and before the answer goes back withholds it: the device is told the
/// answer is not shown, and is not shown which chunks the host holds. The control is the same read
/// with nothing owed, which is answered with the bitmap. Another principal's upload is unknown to
/// the device, under the same code as an upload that never existed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_upload_status_is_withheld_while_a_fence_is_owed_before_its_end_check() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 41, &[ActionRight::FilesUpload]);
    let actor = connection.device.principal();
    let transfer_id = begun_for(&world, &actor, &[7_u8; 96]);

    let shown = status_of(&connection.read(&status_request(transfer_id)).await)
        .expect("with nothing owed the status is answered");
    assert_eq!(shown.transfer_id, transfer_id);

    let (arrived, go) = controller.pause_retained_lookup();
    let request = status_request(transfer_id);
    let reading = connection.read(&request);
    tokio::pin!(reading);
    tokio::select! {
        arrived = tokio::time::timeout(WAIT_BOUND, arrived) => {
            arrived
                .expect("the read reaches its end check")
                .expect("the pause is armed");
        }
        early = &mut reading => panic!("the read was answered before its end check: {early:?}"),
    }
    controller.hold_fence(true);
    go.send(()).expect("the read goes on");
    let answered = reading.await;
    controller.hold_fence(false);
    let told = status_of(&answered).expect_err("the status is withheld");
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(told.message, super::outcome_not_shown().message);

    let owners = ActorId::new("local:test").expect("a principal");
    let theirs = begun_for(&world, &owners, &[7_u8; 96]);
    let unknown = status_of(&connection.read(&status_request(theirs)).await)
        .expect_err("another principal's upload is unknown");
    let never = status_of(
        &connection
            .read(&status_request(TransferId::new(kr_ipc::new_uuid())))
            .await,
    )
    .expect_err("an upload that never existed is unknown");
    assert_eq!(
        unknown.code, never.code,
        "another principal's upload is refused as an upload that never existed is"
    );
    world.serving.abort();
}

/// Serves `mutation` twice at once, the first copy stopped inside the transfer service once it has
/// passed the door's check and before it takes the service's lock, and returns what each copy was
/// answered with.
async fn two_copies_stopped_in_the_service(
    controller: &Arc<crate::service::Controller>,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> (super::Answered, super::Answered) {
    let (arrived, release) = controller.transfer().pause_after_the_outer_check();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(first);
    let waiting = tokio::task::spawn_blocking(move || arrived.recv_timeout(WAIT_BOUND));
    tokio::pin!(waiting);
    tokio::select! {
        arrived = &mut waiting => {
            arrived
                .expect("the waiting thread finishes")
                .expect("the first copy reaches the service");
        }
        early = &mut first => panic!("the first copy was answered before the service: {early:?}"),
    }
    let (copied, fresh) = tokio::join!(first, async {
        let fresh = connection
            .answer_now(ControlFrame::Mutation(Box::new(mutation.clone())))
            .await;
        release.send(()).expect("the first copy goes on");
        fresh
    });
    (
        copied.expect("the first copy is answered"),
        fresh.expect("the second copy is answered"),
    )
}

/// KR-REQ-23.21 and KR-REQ-09.09: a reservation for a session that another copy of the action
/// performed while this one was on its way to the service is told as the copy it is, and the copy
/// that performed is a fresh answer: a device that may upload to the session and not view it is
/// given its own first answer, and told the outcome is unknown for the copy, whose record it may not
/// read. The control is a device that may view the session, which is given the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_begin_a_service_copied_after_the_door_looked_is_told_as_a_copy_and_the_first_is_not() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let session = world.session_id;
    let params = UploadBeginParams {
        environment_id: world.environment_id,
        session_id: Nullable::some(session),
        device_id: Nullable::null(),
        declared_byte_len: U64::ZERO,
        declared_digest: Digest256::from_bytes(kr_cbor::sha256(&[])),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: "notes.bin".to_owned(),
    };
    let on_the_session = |connection: &super::RemoteConnection, request_id: u64| {
        let mut mutation = mutation_of(
            &world,
            connection,
            Method::UploadBegin,
            request_id,
            ParamsValue::from_typed(&params).expect("encodes"),
        );
        mutation.target = ActionTarget {
            environment_id: world.environment_id,
            session_id: Nullable::some(session),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        mutation
    };

    let (blind, recording) = paired_connection(controller, 42, &[ActionRight::FilesUpload]);
    let mutation = on_the_session(&blind, 91);
    let (copied, fresh) = two_copies_stopped_in_the_service(controller, &blind, &mutation).await;
    assert!(
        copied
            .asked
            .as_ref()
            .is_some_and(super::decision::Asked::is_kept),
        "the copy that read the record is held as a kept answer"
    );
    assert!(
        fresh.asked.as_ref().is_some_and(|asked| !asked.is_kept()),
        "the copy that performed is a fresh answer"
    );
    let told = written(&blind, &recording, copied).await;
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert!(
        blind.write_answer(blind.output(), fresh).await,
        "the connection stands"
    );
    assert!(
        matches!(
            recording.frames().last(),
            Some(ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            }))
        ),
        "the device is given its own first answer: {:?}",
        recording.frames()
    );

    let (sighted, recording) = paired_connection(
        controller,
        43,
        &[ActionRight::FilesUpload, ActionRight::SessionView],
    );
    let mutation = on_the_session(&sighted, 92);
    let (copied, _fresh) = two_copies_stopped_in_the_service(controller, &sighted, &mutation).await;
    assert!(
        sighted.write_answer(sighted.output(), copied).await,
        "the connection stands"
    );
    assert!(
        matches!(
            recording.frames().last(),
            Some(ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            }))
        ),
        "a device that may view the session is given the record: {:?}",
        recording.frames()
    );
    world.serving.abort();
}
