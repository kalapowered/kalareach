//! A read of a session's description that is held while privacy mode is enabled.
//!
//! What a model wrote of a session is removed when privacy mode is enabled, and no answer that was
//! decided before may carry it out afterwards, however long the reader took to take it.

use kr_protocol::describe::{LabelSource, SessionDescribeParams, SessionDescribeResult};
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::RequestId;
use kr_protocol::method::{Method, MethodVersion};
use kr_worker::privacy::PrivacyGeneration;

use super::a_close_a_worker_never_answers as fake;
use crate::attention::tests::owner_connection;
use crate::privacy::Published;

/// What `session.describe` answered, as the reader of a connection finds it.
async fn described_by(reader: &mut kr_ipc::framed::FrameReader) -> SessionDescribeResult {
    let ControlFrame::Response(response) = reader
        .read_message::<ControlFrame>()
        .await
        .expect("the reader is answered")
    else {
        panic!("a response");
    };
    let Outcome::Ok(value) = response.outcome else {
        panic!("the read was refused");
    };
    value.to_typed().expect("decodes")
}

/// KR-REQ-22.17 and KR-REQ-24.11: an answer to `session.describe` that carries what a model wrote
/// is written only while the privacy state it was read under holds. The same answer held while
/// privacy mode is enabled is taken back and written without it, as the pin or the title from
/// metadata; the control is the same answer written while nothing has changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_held_while_privacy_mode_is_enabled_carries_no_description() {
    // A worker that records what it is sent answers the daemon's own `session.read`.
    let world = fake::fake_worker(Some(std::sync::Arc::default())).await;
    let controller = &world.controller;
    fake::acknowledged(controller, world.session_id);
    controller
        .descriptions
        .store()
        .publish(
            &world.session_id,
            &crate::describe::tests::generated("Pairing check", PrivacyGeneration::new(0)),
            900,
        )
        .expect("a description");
    let request = Request {
        request_id: RequestId::new(7),
        method: Method::SessionDescribe.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&SessionDescribeParams {
            session_id: world.session_id,
        })
        .expect("encodes"),
    };
    let actor = world.actor.actor_id.clone();
    let (mut writer, mut reader) = owner_connection(&world._temp, 2).await;

    // The control: nothing changes between the read and the write.
    let released = controller.read_released(&actor, &request).await;
    controller
        .attention()
        .write_released(&mut writer, StreamKind::Control, released)
        .await
        .expect("the answer is written");
    let shown = described_by(&mut reader).await;
    assert_eq!(shown.source, LabelSource::Generated);
    assert_eq!(shown.title, "Pairing check");
    assert!(shown.activity_text.0.is_some());

    // The answer is held, and privacy mode is enabled before it is written.
    let held = controller.read_released(&actor, &request).await;
    controller.privacy.state().set(Published {
        generation: PrivacyGeneration::new(1),
        private: true,
    });
    controller
        .attention()
        .write_released(&mut writer, StreamKind::Control, held)
        .await
        .expect("the answer without the description is written");
    let withheld = described_by(&mut reader).await;
    assert_eq!(withheld.source, LabelSource::Metadata);
    assert_ne!(withheld.title, "Pairing check");
    assert!(withheld.activity_text.0.is_none());
    assert!(withheld.provenance.0.is_none());
}
