//! A paired device ends a draft of its own over real paired connections.
//!
//! `draft.discard` is an ordinary action write: a device that lost the reply to one asks again on a
//! replacement connection, carrying the window its first attempt was admitted under, and is answered
//! from the transfer service's record, though the draft it ended is gone. The same device's update at
//! a stale revision is refused with the draft's own conflict, in the words a client reads the current
//! revision from.

mod net_support;

use kr_crypto::keys::DeviceKeys;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, DraftRevision, SessionId,
};
use kr_protocol::method::Method;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::transfer::{
    DraftCreateParams, DraftCreateResult, DraftDiscardParams, DraftDiscardResult,
    DraftUpdateParams, DraftUpdateResult,
};
use net_support::{Device, Host, RawDevice, an_open_session, on_the_session};

/// The parameters of a draft written for `session`, which is what a paired device makes: a device's
/// draft names the session it is for.
fn draft_params(host: &Host, session: SessionId, text: &str) -> DraftCreateParams {
    DraftCreateParams {
        environment_id: host.environment_id,
        device_id: Nullable::null(),
        session_id: Nullable::some(session),
        application_instance_id: Nullable::null(),
        text: text.to_owned(),
    }
}

/// KR-REQ-23.41 and section 9: a device that lost the reply to a `draft.discard` asks again on a
/// replacement connection and is answered with what the first attempt answered, and nothing is ended
/// twice. A new action under the window of the first connection is refused for the window, and a new
/// action under the replacement's own window, for a draft that is gone, is refused as unknown: the
/// refusal a client reads as already ended. The control is the first attempt, which ends the draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_a_discard_on_a_replacement_connection_is_answered_from_its_record() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session_id, _) = an_open_session(&host);
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let target = on_the_session(&host, session_id);

    let first = RawDevice::connect(&host, &device, &record).await;
    first.claim();
    let made: DraftCreateResult = first
        .mutate(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &draft_params(&host, session_id, "to be ended"),
        )
        .await
        .expect("the device makes a draft")
        .to_typed()
        .expect("a result of the declared shape");
    let params = DraftDiscardParams {
        draft_id: made.draft.draft_id,
    };
    let window = first.action_window_id();
    let action = ActionId::new(kr_ipc::new_uuid());
    let ended: DraftDiscardResult = first
        .mutate_in(
            window.clone(),
            Method::DraftDiscard,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("the device ends its draft")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(ended.draft_id, made.draft.draft_id);
    first.close();

    let again = RawDevice::connect(&host, &device, &record).await;
    again.claim();
    let repeated: DraftDiscardResult = again
        .mutate_in(
            window.clone(),
            Method::DraftDiscard,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("the repeat is answered from the service's record")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(repeated, ended, "nothing was ended twice");

    let stale = again
        .mutate_in(
            window,
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &params,
        )
        .await
        .expect_err("a new action under the window of another connection");
    assert_eq!(stale.code, ErrorCode::PermissionDenied, "{stale:?}");

    let gone = again
        .mutate(
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &params,
        )
        .await
        .expect_err("a new action for a draft that is gone");
    assert_eq!(gone.code, ErrorCode::InvalidArgument, "{gone:?}");
    again.close();
    host.stop().await;
}

/// KR-REQ-23.41: an update at a stale revision reaches the device as the draft's own conflict, in the
/// words the service wrote, so that a client can read the current revision from them and go on
/// instead of ending the draft. The control is the update at the current revision, which is served.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_update_tells_the_device_the_current_revision_as_the_service_wrote_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session_id, _) = an_open_session(&host);
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let target = on_the_session(&host, session_id);
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let made: DraftCreateResult = raw
        .mutate(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &draft_params(&host, session_id, "first"),
        )
        .await
        .expect("the device makes a draft")
        .to_typed()
        .expect("a result of the declared shape");
    let update = |expected: u64, text: &str| DraftUpdateParams {
        draft_id: made.draft.draft_id,
        expected_revision: DraftRevision::new(expected),
        text: text.to_owned(),
    };
    let updated: DraftUpdateResult = raw
        .mutate(
            Method::DraftUpdate,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &update(1, "second"),
        )
        .await
        .expect("the update at the current revision is served")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(updated.draft.revision, DraftRevision::new(2));

    let stale = raw
        .mutate(
            Method::DraftUpdate,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &update(1, "stale"),
        )
        .await
        .expect_err("the revision moved");
    assert_eq!(stale.code, ErrorCode::DraftConflict, "{stale:?}");
    assert_eq!(
        stale.message, "this draft is at revision 2 and the update expects 1",
        "the sentence a client reads the revision from reaches the device as written"
    );
    raw.close();
    host.stop().await;
}

/// KR-REQ-23.41: a draft written for an application is ended by a request that names that
/// application, as the host asks of a request that acts on the draft, and a request that names none is
/// refused and leaves the draft.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_draft_written_for_an_application_is_ended_by_a_request_that_names_it() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (session_id, _) = an_open_session(&host);
    let device = Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(&[ActionRight::SessionView]),
    )
    .await;
    let target = on_the_session(&host, session_id);
    let raw = RawDevice::connect(&host, &device, &record).await;
    raw.claim();

    let application = ApplicationInstanceId::new(kr_ipc::new_uuid());
    let mut params = draft_params(&host, session_id, "for an application");
    params.application_instance_id = Nullable::some(application);
    let mut naming = target.clone();
    naming.application_instance_id = Nullable::some(application);
    naming.agent_binding_revision = Nullable::some(AgentBindingRevision::new(1));
    let made: DraftCreateResult = raw
        .mutate(
            Method::DraftCreate,
            ActionId::new(kr_ipc::new_uuid()),
            naming.clone(),
            &params,
        )
        .await
        .expect("the device makes a draft for an application")
        .to_typed()
        .expect("a result of the declared shape");
    let ending = DraftDiscardParams {
        draft_id: made.draft.draft_id,
    };

    let naming_none = raw
        .mutate(
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &ending,
        )
        .await
        .expect_err("a request that names no application");
    assert_eq!(
        naming_none.code,
        ErrorCode::InvalidArgument,
        "{naming_none:?}"
    );

    let ended: DraftDiscardResult = raw
        .mutate(
            Method::DraftDiscard,
            ActionId::new(kr_ipc::new_uuid()),
            naming,
            &ending,
        )
        .await
        .expect("the request that names the application ends the draft")
        .to_typed()
        .expect("a result of the declared shape");
    assert_eq!(ended.draft_id, made.draft.draft_id);
    raw.close();
    host.stop().await;
}
