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
//! | KR-REQ-06.07 | an upstream frame the worker offers reaches the binding's component with its bytes, its provenance and the request identifier it carried, once and in order |
//! | KR-REQ-11.01 | the same run, through a vendor component that needed no core release; the binding's other bindings, a binding without the stream, another package's binding and a rich-disabled binding are offered nothing, a frame the table does not list and one it lists as a credential are offered to nobody |
//! | KR-REQ-11.38 | a lane that is full loses observations it holds, counts them, takes a fresh snapshot of the component, and never loses the request the upstream is waiting on; an observation that never returns is stopped by its bound and named; an observation that asks for more memory or produces more output than a call may is refused and the binding's record names the bound; three faults in a minute disable the binding while the native terminal goes on; a snapshot that never returns is stopped by its bound and named |
//! | KR-REQ-11.39 | the terminal drains and its questions are answered while the worker's observation pump is held, and while the plugin runtime has stopped reading what is handed to it; the worker lets go of that runtime and takes the component up again when it reads |
//! | KR-REQ-11.40 | an observation the component never returns from is stopped by fuel when its deadline cannot fire, and named so |
//! | KR-REQ-11.41 | a component that was compiled when it was registered is observed without a fault, the compile outside the observation's deadline |
//! | KR-REQ-24.06 | a plugin runtime killed with a receipt, a question and an approval live leaves all three as they were and answerable, and its component is registered again in the replacement and restored to the state the worker held |
//! | KR-REQ-24.27 | turning privacy mode on drops the state held for a component and none is taken or held while it is on, observation for live use goes on, a component offered anything made in it has no state taken until it starts again, and then state is taken again |

#![cfg(unix)]

mod plugin_world;

use kr_protocol::gateway::{PendingKind, PendingState};
use kr_protocol::local::ControllerConnectionRole;
use kr_worker::broker::observation::Audience;
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
/// fourth is rich-disabled after it is ready and before anything is offered. The upstream sends a
/// run of notifications and requests, a frame the table lists as a credential and one it does not
/// list at all; the last notification is a marker, so that "nothing arrived" is decided by a frame
/// that did.
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
    for number in [1, 2, 3, 4] {
        world.until_ready(number).await;
    }
    // The fourth binding is registered and ready, and then loses its rich capabilities: the runtime
    // has not unbound it yet, and it is offered nothing from here on.
    world
        .broker()
        .disable_rich(binding(4), "disabled before the run");
    // Of the four bindings only the first may be offered the connector's frames: the second runs
    // another package, the third holds the grant and no stream, and the fourth is rich-disabled.
    assert_eq!(
        world.broker().observing(Audience::Native {
            instance: plugin_world::observing::instance(),
            package: Some(&plugin_world::acting::installed()),
        }),
        [binding(1)]
    );

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

/// KR-REQ-11.38 and KR-REQ-11.39: a lane that is full loses observations it holds, counts
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
/// plugin runtime has stopped reading what the worker hands it; the worker lets go of a runtime that
/// does not read, and takes the component up again when the runtime does.
///
/// The runtime is stopped (`SIGSTOP`), and the shell then prints eight megabytes, which the worker
/// offers the component as terminal output. The shell finishes, and asks and is answered after it,
/// with the runtime still stopped. A runtime that does not take an event it is handed within ten
/// seconds, or does not answer the link's health question twice running, has stopped reading, and
/// the link lets the connection go: the component is no longer ready. When the runtime goes on, the
/// link reaches it again and the component is ready, and enabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_39_the_terminal_drains_and_is_answered_while_the_runtime_has_stopped_reading() {
    let gate = std::env::temp_dir().join(format!("kr-observe-gate-{}", kr_ipc::new_uuid()));
    let begun = std::env::temp_dir().join(format!("kr-observe-begun-{}", kr_ipc::new_uuid()));
    let ask = "printf '\\033[c'; answer=$(dd bs=1 count=9 2>/dev/null | tr -d '\\033')";
    // The shell says nothing until it is told the component is ready: what was printed before that
    // predates the component's view.
    let shell = format!(
        "stty -icanon -echo min 1 time 0 2>/dev/null; while [ ! -e '{begun}' ]; do sleep 0.05; done; \
         echo kalareach-0; {ask}; echo \"answered-0-$answer\"; \
         while [ ! -e '{gate}' ]; do sleep 0.05; done; yes x | head -c 8000000; echo kalareach-1; \
         {ask}; echo \"answered-1-$answer\"; echo kalareach-done",
        begun = begun.display(),
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
    std::fs::write(&begun, b"").expect("the shell may begin");
    until(
        "the shell to ask its first question and be answered",
        || async { world.output().contains("answered-0-").then_some(()) },
    )
    .await;
    // The component is offered the terminal's output, as the owner's terminal receives it.
    world
        .until_account(
            1,
            "the component to have observed the terminal's output",
            |account| {
                account
                    .seen
                    .iter()
                    .any(|seen| seen.provenance == "terminal_scrape")
            },
        )
        .await;

    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::acting::signal(&host, rustix::process::Signal::STOP);
    std::fs::write(&gate, b"").expect("the gate opens");

    // The terminal finishes printing and is answered, and the runtime is still stopped.
    let drained = tokio::time::timeout(plugin_world::PATIENCE, async {
        while !world.output().contains("kalareach-done") {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "the terminal did not drain while the runtime was stopped: {}",
        world.diagnostics(1)
    );
    assert!(world.output().contains("answered-1-"));

    // The worker lets go of a runtime that does not read.
    let lane = world.broker().observation();
    let let_go = tokio::time::timeout(plugin_world::PATIENCE, async {
        while lane.is_ready(binding(1)) {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        let_go.is_ok(),
        "the worker kept a runtime that does not read: {}",
        world.diagnostics(1)
    );
    plugin_world::acting::signal(&host, rustix::process::Signal::CONT);

    // And takes the component up again when the runtime reads.
    world.until_ready(1).await;
    assert!(world.broker().rich_disabled(binding(1)).is_none());
    let _ = std::fs::remove_file(&gate);
    let _ = std::fs::remove_file(&begun);
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

/// KR-REQ-11.38: an observation that asks for more linear memory than a call may is refused, and
/// the binding's record names the memory as what ran out.
///
/// The component allocates without end in every export, so the observation's refusal is followed by
/// the snapshot the runtime then owes it, which is refused the same way. Three faults in a minute
/// disable the binding, and the reason it is disabled for is the last fault's own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_an_observation_that_asks_for_more_memory_than_its_bound_is_refused_and_named()
{
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1).shipping("memory-hog"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("one"));
    let disabled = until("the binding to be disabled", || async {
        world.broker().rich_disabled(binding(1))
    })
    .await;
    assert!(disabled.contains("linear memory"), "{disabled}");
}

/// KR-REQ-11.38: an observation that produces more output than one call may is refused, and the
/// binding's record names the output budget as what ran out. The component floods in every export,
/// so the faults that follow the observation's disable the binding, as in the memory case.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_an_observation_that_produces_more_than_its_output_budget_is_refused_and_named()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1).shipping("oversized-output"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("one"));
    let disabled = until("the binding to be disabled", || async {
        world.broker().rich_disabled(binding(1))
    })
    .await;
    assert!(disabled.contains("output budget"), "{disabled}");
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
    // The component counts the observations it finished, and a call that faulted is not one.
    world.send(&notification("one"));
    world
        .until_account(
            1,
            "the component to have finished an observation",
            |account| account.observes >= 1,
        )
        .await;
    assert!(
        !world.reason(1).contains("fault"),
        "an observation after a cold compile faulted: {}",
        world.reason(1)
    );
    assert!(world.broker().rich_disabled(binding(1)).is_none());
}

/// KR-REQ-24.06: a plugin runtime that is killed while the worker holds a receipt, a question and an
/// approval takes none of them with it, and the component that ran in it is registered again in the
/// replacement and restored to the state the worker held.
///
/// The worker holds all three: the receipt of an owner's attach is in its journal, the agent's
/// question is in its ledger, and the upstream's permission request was read into an approval, by
/// the connector table's own decision response, for a binding trusted to decode it, and is in its
/// broker with the decoder's record. Neither the runtime nor its component holds any of them. (The
/// component does not decode the request: that call waits for the plugin host's decode request.) The runtime is killed with `SIGKILL` after the worker has taken its component's
/// state, and the daemon starts another on the worker's asking. The three are read again, and are
/// equal; the person's answer to the approval goes to the upstream once, through the native
/// terminal, and the person's answer to the question is taken. The component in the replacement
/// has been restored, so it has the count it had and not a new one.
///
/// What is not claimed: a plugin that reconnects and answers on a restored connection. No entry
/// reopens a gateway connection that has closed, and the runtime's end does not close one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_06_a_plugin_runtime_that_is_killed_leaves_the_receipt_the_approval_and_the_question_and_its_component_is_restored()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::interpreter(2),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;

    let mut window = world.owner().await;
    let action_id = world.attach(&mut window).await;
    let (question_id, caller_token) = world.ask();
    world.send(&notification("before"));
    world.send(&request(7));
    let approval = until("the request to be read into an approval", || async {
        world
            .broker()
            .pending_resources()
            .into_iter()
            .find(|resource| {
                resource.request.upstream.as_str() == "7"
                    && resource.kind == PendingKind::Approval
                    && resource.interpretation_verified
            })
            .map(|resource| resource.resource_id)
    })
    .await;
    world.send(&notification("after"));

    // The component has observed all three frames, and the worker holds its state as of the last.
    world
        .until_account(
            1,
            "the component to have observed the three frames",
            |account| account.observes >= 3,
        )
        .await;
    world.until_held(1, "observe=3;").await;
    let before = world
        .live(&mut window, action_id, question_id, approval)
        .await;
    assert_eq!(
        before.question.state,
        kr_protocol::question::QuestionState::Pending
    );
    assert_eq!(
        before.approval.as_ref().map(|approval| approval.state),
        Some(PendingState::Pending),
        "{before:?}"
    );
    let decoded = world
        .broker()
        .decoding(approval)
        .expect("the ledger reads")
        .expect("the interpretation is recorded with its decoder");

    // The runtime is killed, and the daemon starts another on the worker's asking.
    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::kill(&host);
    until("the runtime to have ended", || async {
        (kr_ipc::identity::process_state(&host) == kr_ipc::identity::ProcessState::Ended)
            .then_some(())
    })
    .await;
    let replacement = until("a replacement runtime to be published", || async {
        world
            .hosted
            .published()
            .filter(|published| *published != host)
    })
    .await;
    assert_ne!(replacement, host);
    assert_eq!(
        world.hosted.started(),
        2,
        "the daemon started one replacement"
    );

    // The component is registered in it again and restored to what the worker held.
    let account = world
        .until_account(1, "the component to have been restored", |account| {
            account.restores >= 1
        })
        .await;
    assert_eq!(account.restores, 1, "{account:?}");
    assert_eq!(
        account.observes, 3,
        "it resumed from the state the worker held and not from nothing: {account:?}"
    );
    assert_eq!(account.requests, ["7"]);
    world.until_ready(1).await;
    let reason = world.reason(1);
    assert!(
        reason.contains("were not replayed"),
        "the report says what the restore did not replay: {reason}"
    );

    // What the worker held is where the runtime's end left it.
    let after = world
        .live(&mut window, action_id, question_id, approval)
        .await;
    assert_eq!(
        after, before,
        "the receipt, the question and the approval are unchanged"
    );
    assert_eq!(
        world
            .broker()
            .decoding(approval)
            .expect("the ledger reads")
            .as_ref(),
        Some(&decoded),
        "and so is the record of who read the request and what they offered"
    );

    // And is live. The person answers the approval through the native terminal, and the upstream
    // is given the answer once; the person answers the question, and the agent reads the answer.
    world
        .terminal
        .write(&serde_json::json!({ "id": 7, "result": { "outcome": "allow" } }))
        .await;
    let answers = || {
        world
            .written
            .lock()
            .expect("not poisoned")
            .iter()
            .filter(|line| {
                serde_json::from_str::<serde_json::Value>(line).is_ok_and(|frame| {
                    frame.get("id") == Some(&serde_json::json!(7)) && frame.get("result").is_some()
                })
            })
            .count()
    };
    until("the upstream to have been given the answer", || async {
        (answers() == 1).then_some(())
    })
    .await;
    let settled = until("the approval to settle", || async {
        world
            .broker()
            .recorded(approval)
            .ok()
            .flatten()
            .filter(|resource| resource.state != PendingState::Pending)
    })
    .await;
    assert_eq!(settled.state, PendingState::Resolved);
    assert_eq!(answers(), 1, "the answer went once");
    let resolved = world.answer_yes(&mut window, &after.question).await;
    assert_eq!(
        resolved.state,
        kr_protocol::question::QuestionState::Answered
    );
    assert!(
        world
            .read_back(question_id, caller_token)
            .answer
            .is_present(),
        "the agent is told the answer"
    );

    // The component goes on observing from where it was restored.
    world.send(&notification("again"));
    world
        .until_account(
            1,
            "the component to have observed the next frame",
            |account| account.observes >= 4,
        )
        .await;
}

/// KR-REQ-24.27: turning privacy mode on drops the state the worker holds for a component, and while
/// it is on no state is taken or held; observation for live use goes on; a component that was offered
/// something while it was on is not asked for its state again, since what it holds may be what it
/// was offered; and a component that starts again has its state taken from then on.
///
/// The state is what a component returns when it is asked for a checkpoint: a record of what it was
/// offered, held in the worker so that a component started again after its runtime ended can be
/// restored. Privacy mode removes the caches derived from what a session produced, so a component
/// that is started again after it starts from the live point and not from a restored state.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_privacy_mode_drops_the_state_held_for_a_component_and_none_is_taken_of_what_it_was_offered_in_it()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    // Far enough on that every time rule has passed, so that what the lane would ask for is decided
    // by what it is owed and not by how long it has been since.
    let later = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);

    world.send(&notification("one"));
    world.until_held(1, "observe=1;").await;
    assert_eq!(lane.held_checkpoints().0, 1);

    // Privacy mode on: what is held is dropped.
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    world.tell_privacy(&mut authority, 1, true).await;
    assert!(lane.is_private());
    assert_eq!(
        lane.held_checkpoints(),
        (0, 0),
        "the state held was dropped"
    );

    // Observation for live use goes on. The component is owed a checkpoint it is not asked for.
    world.send(&notification("two"));
    world
        .until_account(
            1,
            "the component to observe a frame sent while private",
            |account| account.observes >= 2,
        )
        .await;
    world.until_offered(1).await;
    assert!(lane.checkpoint_due(later).is_empty());
    assert_eq!(lane.held_checkpoints(), (0, 0));

    // Privacy mode off: what the component was offered while it was on is still in it, so it is
    // still not asked.
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());
    assert!(lane.checkpoint_due(later).is_empty());
    assert_eq!(lane.held_checkpoints(), (0, 0));

    // A runtime that ends is replaced, and the component in it starts from the live point: nothing
    // is restored. Its state is taken from then on.
    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::kill(&host);
    until("a replacement runtime to be published", || async {
        world
            .hosted
            .published()
            .filter(|published| *published != host)
    })
    .await;
    let account = world
        .until_account(1, "the component to be registered again", |account| {
            account.binds >= 1
        })
        .await;
    assert_eq!(account.restores, 0, "{account:?}");
    assert_eq!(account.observes, 0, "{account:?}");
    world.until_ready(1).await;
    world.send(&notification("three"));
    world.until_held(1, "observe=1;").await;
}

/// KR-REQ-24.27: what the worker had while privacy mode was on is made in it however long it waits
/// to be offered. A frame that reached the worker in privacy mode and is offered to the component
/// after privacy mode ended leaves the component holding something made in privacy mode, so no
/// state is taken from it afterwards.
///
/// The worker's pump is held while privacy mode is turned on, a frame arrives, and privacy mode is
/// turned off again; then the pump goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_an_observation_made_in_privacy_mode_and_offered_after_it_leaves_no_state_taken()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    let later = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;

    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    world.tell_privacy(&mut authority, 1, true).await;
    world.send(&notification("made in privacy mode"));
    until("the lane to hold the frame", || async {
        (lane.waiting() == 1).then_some(())
    })
    .await;
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());

    hold.release();
    world
        .until_account(
            1,
            "the component to be offered the frame after privacy mode ended",
            |account| account.observes >= 1,
        )
        .await;
    world.until_offered(1).await;
    assert!(lane.checkpoint_due(later).is_empty());
    assert_eq!(lane.held_checkpoints(), (0, 0));
}
