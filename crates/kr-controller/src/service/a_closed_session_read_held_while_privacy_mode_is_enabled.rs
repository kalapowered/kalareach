//! A read of a closed session's output that is held while privacy mode is enabled.
//!
//! What a closed session retained is removed when privacy mode is enabled, and no answer that was
//! read before may carry it out afterwards, however long the reader took to take it.

use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{RequestId, SessionId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::recovery::{HistoryPageParams, HistoryPageResult};
use kr_protocol::scalars::U64;
use kr_worker::privacy::PrivacyGeneration;

use super::a_close_a_worker_never_answers as fake;
use crate::attention::tests::owner_connection;
use crate::privacy::Published;

/// The output the closed session retained.
const OUTPUT: &[u8] = b"0123456789abcdef";

/// A closed session as its worker left it: sixteen bytes of retained output in a spool.
fn closed_session(temp: &kr_ipc::testing::TempHost) -> SessionId {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut history = kr_worker::history::OutputHistory::with_spool(
        8,
        temp.environment().session_spool(session_id),
        kr_worker::history::SpoolLayout::new(8, 1 << 20),
    )
    .expect("a spool");
    history.append(OUTPUT);
    session_id
}

/// The page the reader of a connection finds.
async fn paged_by(reader: &mut kr_ipc::framed::FrameReader) -> HistoryPageResult {
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

/// KR-REQ-24.27 and KR-REQ-24.28: a page of a closed session's output is written only while the
/// privacy state it was read under holds. The same page held while privacy mode is enabled is
/// taken back and written without its bytes, as a range that is gone; the control is the same page
/// written while nothing has changed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_page_held_while_privacy_mode_is_enabled_carries_no_output() {
    let world = fake::fake_worker(Some(std::sync::Arc::default())).await;
    let controller = &world.controller;
    let session_id = closed_session(&world._temp);
    let request = Request {
        request_id: RequestId::new(7),
        method: Method::HistoryPage.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(&HistoryPageParams {
            session_id,
            from_cursor: U64::new(0),
            max_bytes: U64::new(1 << 20),
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
        .expect("the page is written");
    let shown = paged_by(&mut reader).await;
    assert_eq!(shown.bytes.as_slice(), OUTPUT);
    assert!(shown.gap.0.is_none());

    // The page is held, and privacy mode is enabled before it is written.
    let held = controller.read_released(&actor, &request).await;
    controller.privacy.state().set(Published {
        generation: PrivacyGeneration::new(1),
        private: true,
    });
    controller
        .attention()
        .write_released(&mut writer, StreamKind::Control, held)
        .await
        .expect("the page without its bytes is written");
    let withheld = paged_by(&mut reader).await;
    assert!(withheld.bytes.as_slice().is_empty());
    assert_eq!(withheld.next_cursor.get(), OUTPUT.len() as u64);
    let gap = withheld.gap.0.expect("and the range is said to be gone");
    assert_eq!(gap.from_cursor.get(), 0);
    assert_eq!(gap.to_cursor.get(), OUTPUT.len() as u64);
}
