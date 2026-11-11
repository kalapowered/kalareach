//! A paired device's transfer writes over real paired connections.
//!
//! A device's three draft writes are performed by the transfer service under the device's own
//! principal, and a device that lost the reply to one asks again on a replacement connection and is
//! answered from the service's record. The four upload writes are refused by name, since a device's
//! chunks have no stream to travel on here, as are the two writes this host performs for no device:
//! a palette change, and raw input sent as a mutation. Each refusal comes after the device's rights
//! are asked and before anything is recorded or staged.
//!
//! The one worker these cases need is none: a session this host's registry holds as open is enough
//! to name, and every answer is the daemon's own.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::transfer::{DraftCreateParams, DraftCreateResult, UploadBeginParams};
use net_support::{Device, Host, RawDevice, an_open_session, on_the_host, on_the_session};

/// Parameters the host has no reason to read: each refusal comes before any are.
#[derive(serde::Serialize)]
struct Anything {}

fn begin_params(host: &Host) -> UploadBeginParams {
    UploadBeginParams {
        environment_id: host.environment_id,
        session_id: Nullable::null(),
        device_id: Nullable::null(),
        declared_byte_len: U64::new(4096),
        declared_digest: kr_protocol::scalars::Digest256::from_bytes([0xd1; 32]),
        declared_media_type: "application/octet-stream".to_owned(),
        original_file_name: "notes.bin".to_owned(),
    }
}

fn draft_params(host: &Host, text: &str) -> DraftCreateParams {
    DraftCreateParams {
        environment_id: host.environment_id,
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: text.to_owned(),
    }
}

/// A device paired with exactly `rights`, connected, and holding its window.
async fn paired_with(
    host: &Host,
    owner: &DeviceKeys,
    rights: &[ActionRight],
) -> (Device, RawDevice) {
    let device = Device::create().await;
    let record = net_support::pair_with(host, &device, owner, net_support::proposal(rights)).await;
    let raw = RawDevice::connect(host, &device, &record).await;
    raw.claim();
    (device, raw)
}

/// KR-REQ-23.41 and KR-REQ-23.21: a chunk sent on the control stream, a palette change and raw input
/// sent as a mutation are each refused by name, with a reason a device can act on, and nothing is
/// recorded or staged for them: a repeat of the same action is refused as the first was, where an
/// action the host had claimed would be told apart. A chunk's refusal names the stream it belongs
/// on. The control is a device that does not hold the right to upload: it is told so first, because
/// the device's rights are asked before the refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_on_the_control_stream_a_palette_change_and_raw_input_are_refused_by_name_and_record_nothing()
 {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session_id, _) = an_open_session(&host);
    let (_device, raw) = paired_with(
        &host,
        &owner,
        &[
            ActionRight::FilesUpload,
            ActionRight::TerminalPalette,
            ActionRight::TerminalInput,
            ActionRight::SessionView,
        ],
    )
    .await;

    let on_host = on_the_host(&host);
    let on_session = on_the_session(&host, session_id);
    let writes: Vec<(Method, ActionTarget)> = vec![
        (Method::UploadChunk, on_host),
        (Method::TerminalPaletteSet, on_session.clone()),
        (Method::InputWrite, on_session),
    ];
    for (method, target) in writes {
        let action = ActionId::new(kr_ipc::new_uuid());
        let send = || async {
            raw.mutate(method, action, target.clone(), &Anything {})
                .await
        };
        let refused = send().await.expect_err("refused by name");
        let name = method.as_str();
        assert!(
            refused.message.starts_with(name),
            "{name}: the refusal names the method: {refused:?}"
        );
        let expected = if method == Method::InputWrite {
            ErrorCode::InvalidArgument
        } else {
            ErrorCode::UnsupportedCapability
        };
        assert_eq!(refused.code, expected, "{name}: {refused:?}");
        if method == Method::UploadChunk {
            assert!(
                refused.message.contains("attachment-chunk stream"),
                "a chunk is refused for the stream it belongs on: {refused:?}"
            );
        }
        let again = send().await.expect_err("refused again");
        assert_eq!(
            again.code, refused.code,
            "{name}: nothing was claimed for the first attempt, so the repeat is refused as it was"
        );
    }
    assert_eq!(
        host.controller()
            .transfer()
            .service()
            .staged_byte_len()
            .expect("the journal reads"),
        0,
        "nothing was staged for a write that was refused"
    );

    // The control: a device without the right is told so, not that the method is unserved.
    let (_plain, plain) = paired_with(&host, &owner, &[ActionRight::SessionView]).await;
    let told: ProtocolError = plain
        .mutate(
            Method::UploadBegin,
            ActionId::new(kr_ipc::new_uuid()),
            on_the_host(&host),
            &begin_params(&host),
        )
        .await
        .expect_err("a device without the right");
    assert_eq!(told.code, ErrorCode::PermissionDenied, "{told:?}");
    plain.close();
    raw.close();
    host.stop().await;
}

/// KR-REQ-23.41, KR-REQ-14.07 and section 9: a device that lost the reply to a `draft.create` asks
/// again on a replacement connection, carrying the window its first attempt was admitted under, and
/// is answered with the draft its first attempt made, with nothing made twice. The control is a new
/// action under that same window, which the replacement connection refuses for the window, and a
/// new action under its own window, which makes a second draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_draft_create_on_a_replacement_connection_is_answered_from_its_record() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let target = on_the_host(&host);
    let params = draft_params(&host, "made once");

    let first = RawDevice::connect(&host, &device, &record).await;
    first.claim();
    let window = first.action_window_id();
    let action = ActionId::new(kr_ipc::new_uuid());
    let made: DraftCreateResult = first
        .mutate_in(
            window.clone(),
            Method::DraftCreate,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("the device makes a draft")
        .to_typed()
        .expect("a result of the declared shape");
    first.close();

    let again = RawDevice::connect(&host, &device, &record).await;
    again.claim();
    let stale = again
        .mutate_in(
            window.clone(),
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &params,
        )
        .await
        .expect_err("a new action under the window of another connection");
    assert_eq!(stale.code, ErrorCode::PermissionDenied, "{stale:?}");

    let repeated: DraftCreateResult = again
        .mutate_in(window, Method::DraftCreate, action, target.clone(), &params)
        .await
        .expect("the repeat is answered from the service's record")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(repeated, made, "the draft was not made twice");

    let second: DraftCreateResult = again
        .mutate(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &params,
        )
        .await
        .expect("a new action makes a new draft")
        .to_typed()
        .expect("a result of the declared shape");
    assert_ne!(second.draft.draft_id, made.draft.draft_id);
    let session: Option<SessionId> = second.draft.session_id.0;
    assert_eq!(session, None, "a draft that names no session is the host's");
    again.close();
    host.stop().await;
}
