//! What a paired device's declared frame does to the answers its worker gives it.
//!
//! One real daemon on the loopback network and the worker it adopts, run in this process. A device
//! says in its hello how large a control frame it can receive, and the link the daemon opens to the
//! worker for that device says the same, so the worker cuts or refuses what it would answer past
//! it. The daemon has no frame to relay that the device would have to discard, and the device's
//! connection stays up.

mod net_support;

use kr_protocol::error::ErrorCode;
use kr_protocol::hello::ReceiveLimits;
use kr_protocol::method::Method;
use kr_protocol::question::{QuestionReadParams, QuestionReadResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Nullable, U64};

use net_support::environment::{Environment, from};

/// KR-REQ-23.48: a device that declared the smallest control frame is refused an answer larger than
/// it, and the refusal names the frame; the same read by a device that declared the usual frame
/// is answered whole, and the first device's connection reads on.
///
/// Three questions with the most context a source may give each are larger together than the
/// smallest frame, and each one alone is smaller: the read of all of them is the answer that does
/// not fit, and the read of one is the one that does.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_48_a_worker_does_not_answer_a_device_with_a_frame_it_declared_it_cannot_receive()
{
    let environment = Environment::start().await;
    let context = "c".repeat(kr_protocol::question::MAX_CONTEXT_BYTES);
    let asked: Vec<_> = (0..3)
        .map(|index| {
            environment
                .worker
                .ask_with_context(&format!("large-{index}"), &context)
        })
        .collect();
    let rights = [ActionRight::SessionView];
    let all = QuestionReadParams {
        session_id: environment.worker.session_id,
        question_id: Nullable::null(),
        include_resolved: true,
    };
    let one = QuestionReadParams {
        question_id: Nullable::some(asked[0].question_id),
        ..all.clone()
    };

    // The control: the usual frame holds the answer, so the cut below is the frame's doing.
    let usual = environment.device(from(&rights, 1)).await;
    let whole: QuestionReadResult = usual
        .connection
        .read(Method::QuestionRead, &all)
        .await
        .expect("a device that declared the usual frame reads every question")
        .to_typed()
        .expect("decodes");
    assert_eq!(whole.questions.len(), asked.len());

    let smallest = ReceiveLimits {
        max_control_frame_len: U64::new(kr_transport::scheduler::MIN_CONTROL_FRAME_LEN as u64),
        ..ReceiveLimits::default()
    };
    let small = environment
        .device_receiving(from(&rights, 1), smallest)
        .await;
    let refused = small
        .connection
        .read(Method::QuestionRead, &all)
        .await
        .expect_err("an answer larger than the device's frame is refused, not relayed");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused}");
    let room =
        kr_transport::scheduler::MIN_CONTROL_FRAME_LEN - kr_protocol::limits::MAX_STREAM_HEADER_LEN;
    assert!(
        refused.message.contains(&room.to_string()),
        "the refusal names the room the device's frame leaves: {refused}"
    );
    let single: QuestionReadResult = small
        .connection
        .read(Method::QuestionRead, &one)
        .await
        .expect("the same connection reads an answer that fits")
        .to_typed()
        .expect("decodes");
    assert_eq!(single.questions.len(), 1);
    small.connection.close();
    usual.connection.close();
    environment.stop().await;
}
