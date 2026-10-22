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
//! | KR-REQ-11.38 | a lane that is full loses the oldest observations it holds, counts them, takes a fresh snapshot of the component, and never loses the request the upstream is waiting on; an observation that never returns is stopped by its bound and named; three faults in a minute disable the binding while the native terminal goes on; a snapshot that never returns is stopped by its bound and named |
//! | KR-REQ-11.39 | the terminal drains and its questions are answered while the worker's observation pump is held, and while the plugin runtime is stopped and refuses what is handed to it |
//! | KR-REQ-11.40 | an observation the component never returns from is stopped by fuel when its deadline cannot fire, and named so |
//! | KR-REQ-11.41 | a component that was compiled when it was registered is observed without a fault, the compile outside the observation's deadline |

#![cfg(unix)]

mod plugin_world;

use plugin_world::observing::{
    Observing, Options, Spec, answered, binding, credential, digest, highest_line, notification,
    request, unlisted,
};
use plugin_world::{Epoch, until};

/// A shell that asks the terminal a question every time round and stops until it is answered.
///
/// `ESC [ c` is a device-attributes query, which the worker answers into the application's own
/// input, and a shell that stops until it is answered is a shell whose output continuing is proof
/// the answer arrived. The line discipline is put in raw mode first, because a reply with no
/// newline in it would otherwise sit in the terminal's line buffer unread.
const ASKING_SHELL: &str = "stty -icanon -echo min 1 time 0 2>/dev/null; i=0; \
     while [ $i -lt 900 ]; do echo kalareach-$i; printf '\\033[c'; \
     answer=$(dd bs=1 count=9 2>/dev/null | tr -d '\\033'); echo \"answered-$i-$answer\"; \
     i=$((i+1)); sleep 0.02; done";

/// A frame whose payload is large enough that a few dozen of them are more than the lane holds.
fn large_notification() -> serde_json::Value {
    notification(&"x".repeat(128 * 1024))
}

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

    // Offered to nobody else. The marker was the last frame, and the pump offers each frame to every
    // binding that may be offered it before it takes the next, so once it has finished with the
    // marker a binding that was going to be offered something has been.
    let lane = world.broker().observation();
    until("the pump to have finished with every frame", || async {
        (lane.waiting() == 0 && lane.in_flight() == 0).then_some(())
    })
    .await;
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

/// KR-REQ-11.38 and KR-REQ-11.39: a lane that is full loses the oldest observations it holds, counts
/// what it lost, and takes the component through a fresh snapshot, and it never loses the request
/// the upstream is waiting on; and the terminal, which pushes onto the same lane, is neither slowed
/// nor left unanswered while nothing at all is taking what is on it.
///
/// The worker's pump is held, which is every observation callback stalled at once and the worker's
/// side of them with it. The upstream sends one request and then more than four mebibytes of
/// notifications. While the pump is held the shell goes on: it prints a line and asks the terminal a
/// question each time round and stops until it is answered, so a higher line number and another
/// answer are the terminal draining and being answered. The request is kept in the lane and in the
/// broker's ledger, and when the pump is let go the component is offered it exactly once, after a
/// snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_a_full_lane_loses_the_oldest_observations_and_never_the_request() {
    let Some(world) = Observing::start(Options {
        shell: ASKING_SHELL.to_owned(),
        ..Options::with(vec![Spec::observer(1)])
    })
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;

    // Where the terminal had got to when nothing was taking what it pushes.
    let (high_water, answers) = until("the shell to be asking", || async {
        let text = world.output();
        highest_line(&text).map(|line| (line, answered(&text)))
    })
    .await;

    world.send(&request(9));
    for _ in 0..40 {
        world.send(&large_notification());
    }
    until("the lane to have lost what did not fit", || async {
        (lane.account().evicted.events > 0).then_some(())
    })
    .await;
    assert_eq!(
        lane.account().refused.events,
        0,
        "the request the upstream is waiting on is never refused for room"
    );
    assert!(
        lane.held_bytes() <= kr_plugin_sdk::limits::OBSERVATION_QUEUE_BYTES,
        "the lane holds {} bytes",
        lane.held_bytes()
    );

    // The terminal goes on beside it: more lines, and more questions answered.
    until(
        "the shell to go on and be answered while the pump is held",
        || async {
            let text = world.output();
            (highest_line(&text) > Some(high_water) && answered(&text) > answers).then_some(())
        },
    )
    .await;

    // The request is held in the lane and in the broker's ledger, as it arrived.
    assert!(lane.waiting() >= 1);
    let pending = world.broker().pending_resources();
    let held = pending
        .iter()
        .filter(|resource| resource.request.upstream.as_str() == "9")
        .count();
    assert_eq!(held, 1, "the ledger holds the request: {pending:?}");

    hold.release();
    let account = world
        .until_account(
            1,
            "the component to have been offered the request",
            |account| account.requests == ["9"] && account.snapshots >= 1,
        )
        .await;
    assert_eq!(account.requests, ["9"], "offered exactly once");
    let reason = world.until_reason(1, "a fresh snapshot was taken").await;
    assert!(reason.contains("were dropped"), "{reason}");
    assert!(world.broker().rich_disabled(binding(1)).is_none());
}

/// KR-REQ-11.39: the terminal goes on draining, and its questions go on being answered, while the
/// plugin runtime is stopped and refuses what the worker hands it; and when the runtime goes on,
/// the connection has not ended and the component is taken through a snapshot.
///
/// The runtime is stopped (`SIGSTOP`), and the shell then prints eight megabytes, which the worker
/// offers the component as terminal output until the hand-off to the runtime refuses it. The shell
/// finishes, and asks and is answered after it, with the runtime still stopped.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_39_the_terminal_drains_and_is_answered_while_the_runtime_refuses_what_it_is_handed()
 {
    let gate = std::env::temp_dir().join(format!("kr-observe-gate-{}", kr_ipc::new_uuid()));
    let ask = "printf '\\033[c'; answer=$(dd bs=1 count=9 2>/dev/null | tr -d '\\033')";
    let shell = format!(
        "stty -icanon -echo min 1 time 0 2>/dev/null; echo kalareach-0; {ask}; echo \"answered-0-$answer\"; \
         while [ ! -e '{gate}' ]; do sleep 0.05; done; yes x | head -c 8000000; echo kalareach-1; \
         {ask}; echo \"answered-1-$answer\"; echo kalareach-done",
        gate = gate.display()
    );
    let Some(world) = Observing::start(Options {
        shell,
        ..Options::with(vec![Spec::terminal_only(1)])
    })
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    until(
        "the shell to ask its first question and be answered",
        || async { world.output().contains("answered-0-").then_some(()) },
    )
    .await;

    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::acting::signal(&host, rustix::process::Signal::STOP);
    std::fs::write(&gate, b"").expect("the gate opens");
    let lane = world.broker().observation();
    until("the hand-off to the stopped runtime to refuse", || async {
        lane.view(binding(1))
            .is_some_and(|view| view.lost_seq > 0)
            .then_some(())
    })
    .await;

    // The terminal finished printing and was answered, and the runtime is still stopped.
    until("the terminal to drain and be answered", || async {
        world.output().contains("kalareach-done").then_some(())
    })
    .await;
    plugin_world::acting::signal(&host, rustix::process::Signal::CONT);

    // The connection did not end, the binding is still ready, and the component was taken through a
    // snapshot for what it missed.
    let client = world
        .broker()
        .component_calls()
        .client()
        .expect("the connection to the runtime is still held");
    client.health().await.expect("the runtime answers");
    world
        .until_account(
            1,
            "the component to have been taken through a snapshot",
            |account| account.snapshots >= 1,
        )
        .await;
    assert!(lane.is_ready(binding(1)));
    assert!(world.broker().rich_disabled(binding(1)).is_none());
    let _ = std::fs::remove_file(&gate);
}

/// KR-REQ-11.38: an observation the component never returns from is stopped by its bound, which the
/// report names, and the binding goes on: the next frame is observed.
///
/// With the plugin host's epoch running, the 10 ms deadline is what stops it; the library's own case
/// holds the epoch and shows the deadline alone (`kr_req_11_40_fuel_and_deadlines_are_separate_bounds`).
/// A loaded machine can let fuel end a call first, so the report is read for either bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_an_observation_that_never_returns_is_stopped_by_its_bound_and_the_binding_goes_on()
 {
    let mut options = Options::with(vec![Spec::semantic_only(1)]);
    options.epoch = Epoch::Running;
    let Some(world) = Observing::start(options).await else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("!spin-observe"));
    let reason = world.until_reason(1, "last fault, in observe").await;
    assert!(
        reason.contains("deadline") || reason.contains("fuel"),
        "the report names the bound that stopped it: {reason}"
    );
    assert!(world.broker().rich_disabled(binding(1)).is_none());

    // And the binding goes on: the replacement instance is offered what comes next.
    world.send(&notification("after"));
    let account = world
        .until_account(
            1,
            "the replacement instance to observe the next frame",
            |account| account.observes >= 1,
        )
        .await;
    assert_eq!(account.observes, 1, "{account:?}");
}

/// KR-REQ-11.40: instructions are bounded with fuel and elapsed execution with deadlines, and the
/// report says which ended the call. With the plugin host's epoch held, no deadline can fire, so
/// what stops an observation that never returns is its fuel.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_40_with_no_deadline_to_fire_fuel_stops_an_observation_that_never_returns() {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("!spin-observe"));
    let reason = world.until_reason(1, "last fault, in observe").await;
    assert!(reason.contains("fuel"), "{reason}");
    assert!(
        !reason.contains("deadline"),
        "fuel is not reported as a deadline: {reason}"
    );
}

/// KR-REQ-11.38 and KR-ACC-016: three faults in a minute disable the binding, with the last fault's
/// own words, and the native terminal's traffic goes on before, between and after: the component's
/// fault costs the binding its rich capabilities and the terminal nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_three_observations_that_fault_disable_the_binding_and_the_terminal_goes_on() {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    world.terminal.round_trip(1).await;
    for (round, count) in [
        (2_u64, "(1 in the last minute)"),
        (3, "(2 in the last minute)"),
    ] {
        world.send(&notification("!spin-observe"));
        world.until_reason(1, count).await;
        world.terminal.round_trip(round).await;
    }
    world.send(&notification("!trap"));
    let disabled = until("the binding to be disabled", || async {
        world.broker().rich_disabled(binding(1))
    })
    .await;
    assert!(disabled.contains("3 faults within 60 s"), "{disabled}");
    assert!(
        world
            .report(1)
            .is_some_and(|report| report.state == kr_protocol::admission::ComponentState::Disabled)
    );

    // After the disabling the terminal's traffic is untouched, and the component is offered nothing.
    world.terminal.round_trip(4).await;
    world.send(&notification("after"));
    until(
        "the terminal to be forwarded the frame sent after the disabling",
        || async {
            world
                .terminal
                .lines()
                .iter()
                .any(|line| line.contains("\"after\""))
                .then_some(())
        },
    )
    .await;
}

/// KR-REQ-11.38: a snapshot that never returns is stopped by its bound and named. The component is
/// told to spin in its next snapshot, the pump is held while more than the lane holds is sent, and
/// when the pump goes on the snapshot it owes the component for what the lane lost is the one that
/// spins.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_a_snapshot_that_never_returns_is_stopped_by_its_bound_and_named() {
    let mut options = Options::with(vec![Spec::semantic_only(1)]);
    options.epoch = Epoch::Running;
    let Some(world) = Observing::start(options).await else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("!spin-snapshot"));
    world
        .until_account(1, "the component to have observed the frame", |account| {
            account.observes >= 1
        })
        .await;
    let lane = world.broker().observation();
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    for _ in 0..40 {
        world.send(&large_notification());
    }
    until("the lane to have lost what did not fit", || async {
        (lane.account().evicted.events > 0).then_some(())
    })
    .await;
    hold.release();
    let reason = world.until_reason(1, "last fault, in snapshot").await;
    assert!(
        reason.contains("deadline") || reason.contains("fuel"),
        "{reason}"
    );
}

/// KR-REQ-11.41: a component is compiled when it is registered, outside any observation's deadline,
/// and the first observation after it is finished inside its own, with no fault and the binding
/// still enabled.
///
/// The component is one whose module is slow to compile and quick to run. The plugin host's epoch
/// runs, so a call is stopped at its deadline if it takes past it. The registration is compiled, not
/// loaded from the cache, and an observation after it finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_41_a_component_compiled_at_registration_is_observed_inside_its_own_deadline() {
    let mut options = Options::with(vec![Spec::semantic_only(1).shipping("slow-compile")]);
    options.epoch = Epoch::Running;
    let Some(world) = Observing::start(options).await else {
        return;
    };
    world.until_ready(1).await;
    let reason = world.reason(1);
    assert!(
        reason.contains("compiled in"),
        "the registration compiled the component: {reason}"
    );
    let client = world
        .broker()
        .component_calls()
        .client()
        .expect("the connection to the runtime is held");
    let before = client
        .health()
        .await
        .expect("a health report")
        .component_calls;
    world.send(&notification("one"));
    until("the observation to have finished", || async {
        let now = client.health().await.ok()?.component_calls;
        (now > before).then_some(())
    })
    .await;
    assert!(
        !world.reason(1).contains("fault"),
        "an observation after a cold compile faulted: {}",
        world.reason(1)
    );
    assert!(world.broker().rich_disabled(binding(1)).is_none());
}
