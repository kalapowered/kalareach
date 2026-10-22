//! The worker offers the components of its bindings what they observe, and holds them to the
//! runtime's budgets without ever holding the terminal or a query's answer.
//!
//! A real daemon, this test process as the worker it started (with its own journal, broker and
//! pseudo-terminal session), a real plugin host started by the daemon on the worker's request, and
//! real components. The upstream is the one thing played: a scripted peer behind the production
//! gateway transport that sends the frames a case asks it to; the native terminal on the other end
//! reads everything the worker forwards to it. Everything between them is the product: the broker,
//! the observation lane, the link and its pump, the plugin service protocol, and the engine that
//! runs the component. A case reads what a component was offered from the component itself, through
//! its checkpoint, since nothing in the worker presents a component's document.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-06.07 | an upstream frame the worker offers reaches the binding's component with its bytes, its provenance and the request identifier it carried, once and in order, and the handle is the broker's own for a request the upstream is waiting on |
//! | KR-REQ-11.01 | the same run, through a vendor component that needed no core release; the binding's other bindings, a binding without the stream, another package's binding and a rich-disabled binding are offered nothing, a frame the table does not list and one it lists as a credential are offered to nobody |

#![cfg(unix)]

mod plugin_world;

use plugin_world::observing::{
    Observing, Options, Spec, credential, digest, notification, request, unlisted,
};

/// KR-REQ-06.07 and KR-REQ-11.01: what the worker offers a binding's component arrives as the
/// worker offered it, and only a binding that may be offered it is.
///
/// Four bindings share the instance. The first is granted the connector's own frames and is the
/// positive case; the second runs another package, the third holds the grant and no stream, and the
/// fourth is rich-disabled before anything is offered. The upstream sends a run of notifications and
/// requests, a frame the table lists as a credential and one it does not list at all; the last
/// notification is a marker, so that "nothing arrived" is decided by a frame that did.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_06_07_a_frame_the_worker_offers_reaches_the_components_that_may_be_offered_it() {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::semantic_only(2).of_another_package(),
        Spec::observer(3).without_a_stream(),
        Spec::semantic_only(4),
    ]))
    .await
    else {
        return;
    };
    world.broker().disable_rich(
        plugin_world::observing::binding(4),
        "disabled before the run",
    );
    for number in [1, 2, 3] {
        world.until_ready(number).await;
    }

    let frames = [
        notification("one"),
        request(7),
        credential(8),
        unlisted(),
        notification("two"),
        request(9),
        notification("three"),
    ];
    for frame in &frames {
        world.send(frame);
    }

    // Offered, in the order the upstream sent them: the five a component may be offered, and not the
    // credential or the frame nothing lists.
    let account = world
        .until_account(1, "the first binding to have observed the run", |account| {
            account.observes >= 5
        })
        .await;
    assert_eq!(account.observes, 5, "{account:?}");
    let offered: Vec<String> = [0, 1, 4, 5, 6]
        .into_iter()
        .map(|index| frames[index].to_string())
        .collect();
    let expected: Vec<(&str, &str, usize, u64)> = offered
        .iter()
        .zip(["-", "7", "-", "9", "-"])
        .map(|(frame, request)| {
            (
                "native_protocol",
                request,
                frame.len(),
                digest(frame.as_bytes()),
            )
        })
        .collect();
    let seen: Vec<(&str, &str, usize, u64)> = account
        .seen
        .iter()
        .map(|seen| {
            (
                seen.provenance.as_str(),
                seen.request.as_str(),
                seen.len,
                seen.digest,
            )
        })
        .collect();
    assert_eq!(
        seen, expected,
        "what the component read is what was offered"
    );
    assert_eq!(account.requests, ["7", "9"]);

    // Offered to nobody else. The marker was the last frame, so a binding that was going to be
    // offered something has been by now.
    for number in [2, 3] {
        let other = world
            .account(number)
            .await
            .expect("the component answers its checkpoint");
        assert_eq!(other.observes, 0, "binding {number} was offered {other:?}");
    }

    // And the terminal got every frame, whatever the components were offered.
    plugin_world::until("the terminal to be forwarded every frame", || async {
        (world.terminal.lines().len() == frames.len()).then_some(())
    })
    .await;
    let forwarded = world.terminal.lines();
    for (line, frame) in forwarded.iter().zip(&frames) {
        assert_eq!(line, &frame.to_string());
    }
}
