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

mod plugin_world;

use kr_protocol::gateway::{PendingKind, PendingState};
use kr_protocol::local::ControllerConnectionRole;
use kr_worker::broker::decoding::{NotDecoded, Verdict};
use kr_worker::broker::observation::{Audience, Pause, Source};
use plugin_world::observing::{
    Observing, Options, Spec, answered, binding, credential, digest, highest_line, instance,
    notification, request, request_noting, unlisted,
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
    // The fourth binding is registered and ready, and then loses its rich capabilities: it is
    // offered nothing from here on.
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
/// broker's ledger, and when the pump is let go the component is offered it exactly once and has
/// been taken through a snapshot. (The lane's own test shows that what it lost is older than what it
/// hands over.)
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_38_a_full_lane_loses_observations_counts_them_and_never_the_request() {
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

    world.send_and_wait_for_the_terminal(&request(9)).await;
    for _ in 0..40 {
        world
            .send_and_wait_for_the_terminal(&large_notification())
            .await;
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
// The runtime is stopped and resumed by a signal, which Windows has no counterpart of.
#[cfg(unix)]
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

    // The terminal finishes printing and is answered, and the runtime is still stopped. Eight
    // megabytes take as long as the machine takes to work through them, so the wait gives up when
    // the output stops growing and not when a fixed time has passed.
    let drained = plugin_world::until_the_work_stops(|| {
        let output = world.output();
        (
            output.contains("kalareach-done").then_some(()),
            output.len(),
        )
    })
    .await;
    assert!(
        drained.is_some(),
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
        let reason = world.until_reason(1, count).await;
        // Outside privacy mode the report carries the runtime's own words, which is what the
        // privacy case below holds back.
        assert!(reason.contains("last fault, in observe: "), "{reason}");
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
        world
            .send_and_wait_for_the_terminal(&large_notification())
            .await;
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
/// and the first observation after it is finished with no fault and the binding still enabled.
///
/// The component is one whose module is slow to compile and quick to run. The plugin host's epoch
/// is held, so no call is stopped by a deadline however long the machine takes over it. What this
/// case reads is that the registration compiled the component and did not load it from the cache,
/// that the component then observed, and that nothing faulted. That the clock of an observation's
/// deadline starts with the call and not before the compile is held, with the epoch moved by
/// several deadlines between the compile and the call, in the plugin runtime's own suite
/// (`kr_req_11_41_a_cold_compile_is_not_inside_an_observation_deadline`).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_41_a_component_compiled_at_registration_is_observed_inside_its_own_deadline() {
    let options = Options::with(vec![Spec::semantic_only(1).shipping("slow-compile")]);
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

/// KR-REQ-11.41: a compile that is queued and not done never stops the terminal draining or its
/// questions being answered, and does not fault the binding.
///
/// The plugin host queues the compile of the binding's component behind a hold on its compile pool,
/// so the component cannot be compiled whatever the machine does, and the host says when the compile
/// is queued. While it is held the binding is not ready (the control: the registration is waiting
/// for the compile and nothing else), and the shell goes on: it prints a line and asks the terminal
/// a question each time round and stops until it is answered, so a higher line number and another
/// answer are the terminal draining and being answered. When the compile is let go the binding
/// becomes ready, its component was compiled and not loaded, and nothing faulted.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_41_a_compile_that_is_queued_and_not_done_leaves_the_terminal_draining_and_answered()
 {
    let Some(world) = Observing::start(Options {
        shell: ASKING_SHELL.to_owned(),
        holding_compiles: true,
        ..Options::with(vec![Spec::semantic_only(1)])
    })
    .await
    else {
        return;
    };
    until("the plugin host to have queued the compile", || async {
        world.a_compile_is_held().then_some(())
    })
    .await;
    let lane = world.broker().observation();
    assert!(
        !lane.is_ready(binding(1)),
        "the binding was ready with its compile held"
    );

    // Where the terminal had got to with the compile held.
    let (high_water, answers) = until("the shell to be asking", || async {
        let text = world.output();
        highest_line(&text).map(|line| (line, answered(&text)))
    })
    .await;
    until(
        "the shell to go on and be answered while the compile is held",
        || async {
            let text = world.output();
            (highest_line(&text) > Some(high_water) && answered(&text) > answers).then_some(())
        },
    )
    .await;
    assert!(
        !lane.is_ready(binding(1)),
        "the compile was done although it was held"
    );

    world.let_the_compiles_go();
    world.until_ready(1).await;
    let reason = world.reason(1);
    assert!(
        reason.contains("compiled in"),
        "the registration compiled the component: {reason}"
    );
    assert!(world.broker().rich_disabled(binding(1)).is_none());
    assert!(
        !reason.contains("fault"),
        "a compile that waited faulted the binding: {reason}"
    );
}

/// KR-REQ-24.24: a request frame the lane holds carries the place the broker recorded the request
/// in, which is the order of the broker's records and not the order of the request's identifier.
///
/// A producer pushes a frame after the broker's lock is dropped, so the order of pushes does not
/// say which of two requests the broker recorded first. The place is what a rebuilt component's
/// baseline and the lane's live entries are ordered by. A frame that is not a request carries none.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_frame_in_the_lane_carries_the_place_the_broker_recorded_it_in() {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    world.send(&request(9));
    world.send(&notification("between"));
    world.send(&request(7));
    until("the lane to hold the three frames", || async {
        (lane.waiting() == 3).then_some(())
    })
    .await;
    let mut taken = Vec::new();
    for _ in 0..3 {
        let entry = lane.take().entry.expect("an entry waits");
        let Source::Native(frame) = &entry.source else {
            panic!("an upstream frame: {entry:?}");
        };
        taken.push((
            frame.request_id.clone(),
            frame.recorded.map(|recorded| recorded.place),
        ));
        lane.finish(&entry);
    }
    hold.release();
    assert_eq!(
        taken
            .iter()
            .map(|(id, _)| id.as_deref())
            .collect::<Vec<_>>(),
        [Some("9"), None, Some("7")]
    );
    assert_eq!(taken[1].1, None, "a notification is no record");
    let nine = taken[0]
        .1
        .expect("a request carries the place it was recorded in");
    let seven = taken[2]
        .1
        .expect("a request carries the place it was recorded in");
    assert!(nine < seven, "9 was recorded before 7: {taken:?}");
}

/// KR-REQ-24.06: a plugin runtime that is killed while the worker holds a receipt, a question and an
/// approval takes none of them with it, and the component that ran in it is registered again in the
/// replacement and given the approval, which the broker still holds as pending.
///
/// The worker holds all three: the receipt of an owner's attach is in its journal, the agent's
/// question is in its ledger, and the upstream's permission request was read into an approval, by
/// the connector table's own decision response, for a binding trusted to decode it, and is in its
/// broker with the decoder's record. Neither the runtime nor its component holds any of them. (The
/// binding that decodes ships no component, so the connector's table reads the request, as it does
/// for every package whose bindings ship none.) The runtime is killed with `SIGKILL`, and the daemon
/// starts another on the worker's asking. The three are read again, and are equal; the person's answer to the approval goes to the upstream once, through the native
/// terminal, and the person's answer to the question is taken. The component in the replacement
/// is a new one with no state, so it has seen the approval and nothing before it.
///
/// What is not claimed: a plugin that reconnects and answers on a restored connection. No entry
/// reopens a gateway connection that has closed, and the runtime's end does not close one.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_06_a_plugin_runtime_that_is_killed_leaves_the_receipt_the_approval_and_the_question_and_its_component_starts_again()
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
    world.send(&request(8));
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

    // The component has observed all three frames.
    world
        .until_account(
            1,
            "the component to have observed the four frames",
            |account| account.observes >= 4,
        )
        .await;
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

    // The runtime is killed, and the daemon starts another on the worker's asking. The pump is
    // stopped once the component that starts again has been given the first request.
    let hold = world
        .broker()
        .observation()
        .pause_at(Pause::BaselineGiven(1));
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

    // A person answers the other request through the native terminal while the baseline waits: the
    // upstream is given the answer once, and the component is never given the request.
    until(
        "the baseline to be held after its first request",
        || async { hold.parked().then_some(()) },
    )
    .await;
    answer_natively(&world, 8).await;
    hold.release();

    // The component is registered in it again, with no state, and given what the broker holds: the
    // approval, and not the two notifications nor the request answered meanwhile.
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(
        account.restores, 0,
        "nothing was restored into it: {account:?}"
    );
    assert_eq!(account.binds, 1, "{account:?}");
    assert_eq!(
        account.observes, 1,
        "it was given the pending request and nothing else: {account:?}"
    );
    assert_eq!(account.requests, ["7"]);
    assert_eq!(answers_to(&world, 8), 1, "the answer to 8 went once");
    let reason = world.reason(1);
    assert!(
        reason.contains(
            "started again after the plugin runtime was lost, with no state or history from \
             before the loss; the worker gave it 1 pending request from its own records, oldest first, \
             already read as an approval"
        ),
        "the report says what the component was given: {reason}"
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

    // The component goes on observing from where it was started again.
    world.send(&notification("again"));
    world
        .until_account(
            1,
            "the component to have observed the next frame",
            |account| account.observes >= 2,
        )
        .await;
}

/// Closes the plugin host's compile gate and kills the plugin runtime: the component is not
/// registered in the replacement until the case lets the compiles go, so that what the worker does
/// while the runtime is away can be done with the runtime away. Waits until the replacement's
/// registration is queued behind the gate.
async fn lose_the_runtime(world: &Observing) {
    world.hold_the_compiles();
    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::kill(&host);
    until("the runtime to have ended", || async {
        (kr_ipc::identity::process_state(&host) == kr_ipc::identity::ProcessState::Ended)
            .then_some(())
    })
    .await;
    until(
        "the replacement's registration to wait at the gate",
        || async { world.a_compile_is_held().then_some(()) },
    )
    .await;
}

/// Waits until the component of binding `number` has been registered again and the worker has given
/// it what it holds for it.
async fn until_started_again(world: &Observing, number: u8) {
    let lane = world.broker().observation();
    until("the component to have started again", || async {
        lane.view(binding(number))
            .is_some_and(|view| view.ready && !view.rebuild_owed)
            .then_some(())
    })
    .await;
}

/// Waits until binding `number` is registered again and owed what the broker holds for it.
async fn until_owed_its_baseline(world: &Observing, number: u8) {
    let lane = world.broker().observation();
    until(
        "the component to be registered again, owed its baseline",
        || async {
            lane.view(binding(number))
                .is_some_and(|view| view.ready && view.rebuild_owed)
                .then_some(())
        },
    )
    .await;
}

/// Waits until the broker holds the request the upstream gave `id`, and returns it.
async fn until_recorded(world: &Observing, id: u64) -> kr_protocol::gateway::PendingResource {
    let wanted = id.to_string();
    until("the request to be recorded", || async {
        world
            .broker()
            .pending_resources()
            .into_iter()
            .find(|resource| resource.request.upstream.as_str() == wanted)
    })
    .await
}

/// How many times the upstream was written the answer to request `id`.
fn answers_to(world: &Observing, id: u64) -> usize {
    world
        .written
        .lock()
        .expect("not poisoned")
        .iter()
        .filter(|line| {
            serde_json::from_str::<serde_json::Value>(line).is_ok_and(|frame| {
                frame.get("id") == Some(&serde_json::json!(id)) && frame.get("result").is_some()
            })
        })
        .count()
}

/// The person answers request `id` through the native terminal, and the worker writes it to the
/// upstream once.
async fn answer_natively(world: &Observing, id: u64) {
    world
        .terminal
        .write(&serde_json::json!({ "id": id, "result": { "outcome": "allow" } }))
        .await;
    until("the upstream to have been given the answer", || async {
        (answers_to(world, id) == 1).then_some(())
    })
    .await;
    until("the request to be settled", || async {
        world
            .broker()
            .pending_resources()
            .into_iter()
            .all(|resource| {
                resource.request.upstream.as_str() != id.to_string()
                    || resource.state != PendingState::Pending
            })
            .then_some(())
    })
    .await;
}

/// KR-REQ-24.24: a component that starts again after its runtime was lost is given the requests the
/// broker still holds as pending, once each, in the order the broker recorded them; what was
/// answered while the runtime was away is not among them, and nothing a component saved is restored
/// into it.
///
/// Ten requests are sent in an order no sort of their identifiers or of the broker's own keys gives,
/// and each is read into an approval. The runtime is lost, one request is answered through the
/// native terminal while it is away, and the component that starts again in the replacement is
/// given the other nine in the order they were sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_component_that_starts_again_is_given_the_pending_requests_once_each_in_the_order_they_were_recorded()
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
    let sent = [5_u64, 2, 9, 1, 7, 3, 10, 4, 8, 6];
    for id in sent {
        world.send(&request(id));
    }
    until("every request to be read into an approval", || async {
        (world
            .broker()
            .pending_resources()
            .iter()
            .filter(|resource| {
                resource.kind == PendingKind::Approval && resource.interpretation_verified
            })
            .count()
            == sent.len())
        .then_some(())
    })
    .await;
    world
        .until_account(1, "the component to have observed them all", |account| {
            account.requests.len() == sent.len()
        })
        .await;

    lose_the_runtime(&world).await;
    answer_natively(&world, 9).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;

    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.restores, 0, "{account:?}");
    assert_eq!(account.binds, 1, "{account:?}");
    let expected: Vec<String> = sent
        .iter()
        .filter(|id| **id != 9)
        .map(ToString::to_string)
        .collect();
    assert_eq!(
        account.requests, expected,
        "the pending requests, once each, in the order they were recorded"
    );
    assert_eq!(account.observes, 9, "{account:?}");
    let reason = world.reason(1);
    assert!(
        reason.contains(
            "started again after the plugin runtime was lost, with no state or history from \
             before the loss; the worker gave it 9 pending requests from its own records, oldest first, 9 \
             of them already read as approvals"
        ),
        "{reason}"
    );
    assert!(
        world.report(2).is_none(),
        "the binding that ships no component has no report"
    );
}

/// KR-REQ-24.24: a request recorded after the baseline was read and answered before the pump takes
/// its frame is not given to the component.
///
/// The component starts again with nothing pending. The pump is held, a request arrives and is
/// answered through the native terminal, and a notification arrives after it. When the pump goes on,
/// the component observes the notification, which the lane holds after the request, and was never
/// given the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_answered_after_the_baseline_was_read_is_not_given_to_the_component()
{
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;

    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    world.send(&request(5));
    until_recorded(&world, 5).await;
    answer_natively(&world, 5).await;
    world.send(&notification("after"));
    until(
        "the lane to hold the request and the notification",
        || async { (lane.waiting() == 2).then_some(()) },
    )
    .await;
    hold.release();
    let account = world
        .until_account(
            1,
            "the component to have observed the notification",
            |account| account.observes >= 1,
        )
        .await;
    assert!(
        account.requests.is_empty(),
        "the component was given a request answered before it was offered: {account:?}"
    );
    assert_eq!(account.observes, 1, "{account:?}");
}

/// KR-REQ-24.24: a frame that a binding was not offered because the plugin runtime was lost while an
/// earlier binding was handed it is counted as passed over for that binding.
///
/// Two bindings observe. The pump is stopped once it has handed a notification to the first, the
/// runtime is lost, and the pump goes on: the second binding's component is away, and the frame is
/// counted for it and for no other. Both components are then registered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_frame_not_offered_because_the_runtime_was_lost_during_an_earlier_hand_over_is_counted()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::semantic_only(2),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;
    let lane = world.broker().observation();
    let frame = notification("counted");
    let each = frame.to_string().len() as u64;
    let pause = lane.pause_at(Pause::OfferedTo(binding(1)));
    world.send(&frame);
    until("the pump to stop after the first hand-over", || async {
        pause.parked().then_some(())
    })
    .await;

    lose_the_runtime(&world).await;
    pause.release();
    until("the pump to have finished with the frame", || async {
        (lane.waiting() == 0 && lane.in_flight() == 0).then_some(())
    })
    .await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until_started_again(&world, 2).await;

    let second = world.reason(2);
    assert!(
        second.contains(&format!(
            "while the plugin runtime was away the worker passed over 1 upstream frame ({each} \
             bytes), which the component was never given"
        )),
        "the frame the second binding was not offered is not counted: {second}"
    );
    let first = world.reason(1);
    assert!(
        !first.contains("passed over"),
        "the first binding was handed the frame: {first}"
    );
}

/// Starts a world whose binding 1 reads requests into approvals and whose binding 2 observes, and
/// sends three requests that binding 1 reads and binding 2 has observed.
///
/// The binding that reads the requests is the first of its package, since that is the one the
/// worker asks whether the package may answer.
async fn three_approvals_read_by_the_first_binding() -> Option<Observing> {
    let world = Observing::start(Options::with(vec![
        Spec::interpreter(1),
        Spec::semantic_only(2),
    ]))
    .await?;
    world.until_ready(2).await;
    for id in 1..=3_u64 {
        world.send(&request(id));
    }
    until("every request to be read into an approval", || async {
        (world
            .broker()
            .pending_resources()
            .iter()
            .filter(|resource| {
                resource.kind == PendingKind::Approval && resource.interpretation_verified
            })
            .count()
            == 3)
            .then_some(())
    })
    .await;
    world
        .until_account(2, "the component to have observed them all", |account| {
            account.requests.len() == 3
        })
        .await;
    Some(world)
}

/// Admits an answer to the request the upstream gave `id`, which claims it and leaves the answer
/// unwritten until [`Broker::abandon`] gives the claim back.
async fn admit_an_answer_to(world: &Observing, id: u64) -> kr_worker::broker::MutationAdmission {
    let request = until_recorded(world, id).await;
    let revision = world
        .broker()
        .binding_state(instance())
        .expect("the instance is bound")
        .binding_revision;
    let caller = kr_worker::broker::Caller {
        actor_id: kr_protocol::ids::ActorId::new("device-1").expect("an actor"),
        grant_id: None,
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        device_id: None,
    };
    let admitted = world
        .broker()
        .admit_approval(
            &caller,
            &kr_protocol::agent::AgentApprovalRespondParams {
                target: kr_protocol::agent::AgentMutationTarget {
                    subject: kr_worker::broker::subject(world.hosted.session_id, instance()),
                    binding_revision: revision,
                },
                resource_id: request.resource_id,
                option_id: "allow".to_owned(),
            },
            kr_ipc::now_ms(),
        )
        .expect("the answer is admitted");
    assert_eq!(
        until_recorded(world, id).await.state,
        PendingState::Claimed,
        "the admitted answer claims the request"
    );
    admitted
}

/// KR-REQ-24.24: a request claimed for a rich answer that is not yet marked as sent is given to a
/// component that starts again, and is not given a second time when the claim goes back.
///
/// Three requests are read into approvals. The runtime is lost and an answer to the second is
/// admitted, which claims it; the answer is not written. The component that starts again is given
/// all three, in the order they were recorded. The answer is then given up, which makes the second
/// request pending again, and a notification that the component observes after it shows that the
/// pump has gone past: the component was not given the request again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_claimed_for_an_answer_is_given_to_a_component_that_starts_again_and_once_when_the_claim_goes_back()
 {
    let Some(world) = three_approvals_read_by_the_first_binding().await else {
        return;
    };
    lose_the_runtime(&world).await;
    let answer = admit_an_answer_to(&world, 2).await;
    world.let_the_compiles_go();
    until_started_again(&world, 2).await;

    let account = world.account(2).await.expect("the component answers");
    assert_eq!(
        account.requests,
        ["1", "2", "3"],
        "the claimed request was left out, or another was: {account:?}"
    );
    let reason = world.reason(2);
    assert!(
        reason.contains("the worker gave it 3 pending requests from its own records"),
        "{reason}"
    );

    world.broker().abandon(&answer);
    assert_eq!(
        until_recorded(&world, 2).await.state,
        PendingState::Pending,
        "the claim went back"
    );
    world.send(&notification("after"));
    let account = world
        .until_account(
            2,
            "the component to have observed the notification",
            |account| account.observes >= 4,
        )
        .await;
    assert_eq!(
        account.requests,
        ["1", "2", "3"],
        "the request whose claim went back was given again: {account:?}"
    );
}

/// KR-REQ-24.24: a request that is claimed for a rich answer while an earlier request is handed over
/// is still given: the claim can go back, and the request is then pending.
///
/// Three requests are read into approvals, and the baseline is held once it has given the first.
/// An answer to the second is admitted, and the baseline goes on: the component is given the second
/// and the third.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_claimed_while_an_earlier_hand_over_waits_is_still_given() {
    let Some(world) = three_approvals_read_by_the_first_binding().await else {
        return;
    };
    let lane = world.broker().observation();
    let hold = lane.pause_at(Pause::BaselineGiven(1));
    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until(
        "the baseline to be held after its first request",
        || async { hold.parked().then_some(()) },
    )
    .await;
    let answer = admit_an_answer_to(&world, 2).await;
    hold.release();
    until_started_again(&world, 2).await;

    let account = world.account(2).await.expect("the component answers");
    assert_eq!(
        account.requests,
        ["1", "2", "3"],
        "the request claimed while the first was handed over was left out: {account:?}"
    );
    world.broker().abandon(&answer);
}

/// KR-REQ-24.24: a request that is answered while an earlier request is handed over is not given.
///
/// Three requests are read into approvals, and the baseline is held once it has given the first.
/// The second is answered through the native terminal and the baseline goes on: the component is
/// given the first and the third, and the upstream is written one answer to the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_answered_while_an_earlier_hand_over_waits_is_not_given() {
    let Some(world) = three_requests_read_into_approvals().await else {
        return;
    };
    let lane = world.broker().observation();
    let hold = lane.pause_at(Pause::BaselineGiven(1));
    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until(
        "the baseline to be held after its first request",
        || async { hold.parked().then_some(()) },
    )
    .await;
    answer_natively(&world, 2).await;
    hold.release();
    until_started_again(&world, 1).await;

    let account = world.account(1).await.expect("the component answers");
    assert_eq!(
        account.requests,
        ["1", "3"],
        "the request answered while the first was handed over was given: {account:?}"
    );
    assert_eq!(account.observes, 2, "{account:?}");
    assert_eq!(
        answers_to(&world, 2),
        1,
        "the upstream was written one answer"
    );
    let reason = world.reason(1);
    assert!(
        reason.contains("the worker gave it 2 pending requests from its own records"),
        "{reason}"
    );
}

/// Starts a world whose binding 1 observes and whose binding 2 reads requests, and sends three
/// requests that binding 2 reads into approvals and binding 1 has observed.
async fn three_requests_read_into_approvals() -> Option<Observing> {
    let world = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::interpreter(2),
    ]))
    .await?;
    world.until_ready(1).await;
    for id in 1..=3_u64 {
        world.send(&request(id));
    }
    until("every request to be read into an approval", || async {
        (world
            .broker()
            .pending_resources()
            .iter()
            .filter(|resource| {
                resource.kind == PendingKind::Approval && resource.interpretation_verified
            })
            .count()
            == 3)
            .then_some(())
    })
    .await;
    world
        .until_account(1, "the component to have observed them all", |account| {
            account.requests.len() == 3
        })
        .await;
    Some(world)
}

/// Waits until binding `number` is registered on a later connection to the plugin runtime than
/// `than`, and is owed its baseline.
async fn until_registered_on_a_later_connection(world: &Observing, number: u8, than: u64) {
    let lane = world.broker().observation();
    until(
        "the component to be registered on the next runtime, owed its baseline",
        || async {
            lane.view(binding(number))
                .is_some_and(|view| view.ready && view.rebuild_owed && view.connection > than)
                .then_some(())
        },
    )
    .await;
}

/// KR-REQ-24.24: a baseline that began on one registration is never given to the next one. The plugin
/// runtime is lost a second time between two hand-overs of the baseline, and the component that
/// starts the second time is given every pending request, once each.
///
/// Three requests are read into approvals and the runtime is lost. The baseline is held once it has
/// given the first request, the runtime is lost again, and the component is registered in the third
/// runtime, owed its baseline, before the first baseline goes on. That baseline gives the third
/// runtime's component nothing; the baseline of the second registration gives it all three.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_second_loss_between_two_hand_overs_leaves_the_replacement_every_pending_request_once()
 {
    let Some(world) = three_requests_read_into_approvals().await else {
        return;
    };
    let lane = world.broker().observation();
    let hold = lane.pause_at(Pause::BaselineGiven(1));

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until(
        "the baseline to be held after its first request",
        || async { hold.parked().then_some(()) },
    )
    .await;
    let first = lane.view(binding(1)).expect("a view").connection;

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_registered_on_a_later_connection(&world, 1, first).await;
    hold.release();
    until_started_again(&world, 1).await;

    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.restores, 0, "{account:?}");
    assert_eq!(account.binds, 1, "{account:?}");
    assert_eq!(
        account.requests,
        ["1", "2", "3"],
        "the component of the second registration was given the first baseline's rest, or not every \
         request: {account:?}"
    );
    assert_eq!(account.observes, 3, "{account:?}");
    let reason = world.reason(1);
    assert!(
        reason.contains("the worker gave it 3 pending requests from its own records"),
        "{reason}"
    );
}

/// KR-REQ-24.24: a baseline that has given every request ends only for the registration it began on.
/// The plugin runtime is lost a second time after the last hand-over and before the baseline ends,
/// and the component that starts the second time is given every pending request, once each.
///
/// The baseline is held once it has given the third of three requests. The runtime is lost again and
/// the component is registered in the third runtime, owed its baseline, before the first baseline
/// ends. It does not end the owed baseline of the second registration.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_second_loss_before_a_baseline_ends_leaves_the_replacement_every_pending_request_once()
 {
    let Some(world) = three_requests_read_into_approvals().await else {
        return;
    };
    let lane = world.broker().observation();
    let hold = lane.pause_at(Pause::BaselineGiven(3));

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until("the baseline to be held after its last request", || async {
        hold.parked().then_some(())
    })
    .await;
    let first = lane.view(binding(1)).expect("a view").connection;

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_registered_on_a_later_connection(&world, 1, first).await;
    hold.release();
    until_started_again(&world, 1).await;

    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.binds, 1, "{account:?}");
    assert_eq!(
        account.requests,
        ["1", "2", "3"],
        "the first baseline ended the second registration's baseline: {account:?}"
    );
    assert_eq!(account.observes, 3, "{account:?}");
}

/// KR-REQ-24.24: what the worker passed over while the plugin runtime was away is counted, whether
/// the pump took it while the runtime was away or after the component was registered again, and told
/// in the component's report with its bytes.
///
/// Three notifications arrive while the runtime is away and the pump runs. The pump is then held,
/// two more notifications and two spans of terminal output arrive, and the component is registered
/// again before the pump takes them: all of them are older than the component's view.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_what_the_worker_passed_over_while_the_runtime_was_away_is_counted_and_told() {
    let Some(world) = Observing::start(Options::with(vec![Spec::observer(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    let frame = notification("passed over");
    let each = frame.to_string().len() as u64;

    lose_the_runtime(&world).await;
    for _ in 0..3 {
        world.send_and_wait_for_the_terminal(&frame).await;
    }
    until("the pump to have finished with the first three", || async {
        (lane.waiting() == 0 && lane.in_flight() == 0).then_some(())
    })
    .await;

    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    for _ in 0..2 {
        world.send(&frame);
    }
    for _ in 0..2 {
        lane.push_terminal(&std::sync::Arc::new(vec![b'x'; 500]), 1);
    }
    until("the lane to hold the four", || async {
        (lane.waiting() == 4).then_some(())
    })
    .await;
    world.let_the_compiles_go();
    until_owed_its_baseline(&world, 1).await;
    hold.release();
    until_started_again(&world, 1).await;

    let reason = world.reason(1);
    assert!(
        reason.contains(&format!(
            "while the plugin runtime was away the worker passed over 5 upstream frames ({} bytes) \
             and 2 terminal spans (1000 bytes), which the component was never given",
            5 * each
        )),
        "{reason}"
    );
    assert!(
        !world.report(1).expect("a report").reason_cut,
        "the report was cut: {reason}"
    );
}

/// KR-REQ-24.24: observations the worker's queue dropped while the plugin runtime was away are told
/// as dropped, and owe the component that starts again no snapshot: it holds nothing of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_observations_dropped_while_the_runtime_was_away_are_told_and_owe_no_snapshot()
{
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();

    lose_the_runtime(&world).await;
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    for _ in 0..40 {
        world
            .send_and_wait_for_the_terminal(&large_notification())
            .await;
    }
    let dropped = lane.account().evicted.events;
    assert!(
        dropped > 0,
        "the lane dropped nothing: {:?}",
        lane.account()
    );
    world.let_the_compiles_go();
    until_owed_its_baseline(&world, 1).await;
    hold.release();
    until_started_again(&world, 1).await;

    let reason = world.reason(1);
    assert!(
        reason.contains(&format!(
            "{dropped} observations ("
        )) && reason.contains(
            " were dropped because the worker's queue was full while the plugin runtime was away"
        ),
        "{reason}"
    );
    assert!(!reason.contains("fresh snapshot"), "{reason}");
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.snapshots, 0, "a snapshot was taken: {account:?}");
}

/// Says that `dropped` observations were told as dropped for want of room while the runtime was
/// away, and that no snapshot was owed for them.
fn told_as_dropped_while_the_runtime_was_away(world: &Observing, dropped: u64) {
    let reason = world.reason(1);
    assert!(
        reason.contains(&format!("{dropped} observations (")) && reason.contains(
            " were dropped because the worker's queue was full while the plugin runtime was away"
        ),
        "{dropped} were dropped: {reason}"
    );
    assert!(!reason.contains("fresh snapshot"), "{reason}");
}

/// KR-REQ-24.24: the frames the worker's queue dropped while the plugin runtime was away are counted
/// when the pump takes them with the runtime still away, and not only once the component is
/// registered again.
///
/// The lane is filled past its bound while the pump is held. The pump is released with the runtime
/// away and finishes with the lane before the component is registered again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_frames_dropped_while_the_runtime_was_away_are_counted_when_the_pump_takes_them_then()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();

    lose_the_runtime(&world).await;
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    for _ in 0..40 {
        world
            .send_and_wait_for_the_terminal(&large_notification())
            .await;
    }
    let dropped = lane.account().evicted.events;
    assert!(
        dropped > 0,
        "the lane dropped nothing: {:?}",
        lane.account()
    );
    hold.release();
    until("the pump to have finished with the lane", || async {
        (lane.waiting() == 0 && lane.in_flight() == 0).then_some(())
    })
    .await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;

    told_as_dropped_while_the_runtime_was_away(&world, dropped);
}

/// KR-REQ-24.24: the terminal output the worker's queue dropped while the plugin runtime was away is
/// counted when the pump takes it with the runtime still away.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_terminal_output_dropped_while_the_runtime_was_away_is_counted_when_the_pump_takes_it_then()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::terminal_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();

    lose_the_runtime(&world).await;
    let hold = lane.hold_pump();
    until("the pump to stop at the hold", || async {
        hold.parked().then_some(())
    })
    .await;
    for _ in 0..20 {
        lane.push_terminal(&std::sync::Arc::new(vec![b'x'; 256 * 1024]), 1);
    }
    let dropped = lane.account().evicted.events;
    assert!(
        dropped > 0,
        "the lane dropped nothing: {:?}",
        lane.account()
    );
    hold.release();
    until("the pump to have finished with the lane", || async {
        (lane.waiting() == 0 && lane.in_flight() == 0).then_some(())
    })
    .await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;

    told_as_dropped_while_the_runtime_was_away(&world, dropped);
}

/// KR-REQ-24.24: a request is given to the component once when the producer pushes it to the lane
/// after the broker has read what it holds.
///
/// The runtime is lost and the producers' pushes are held. A request arrives and is recorded, and its
/// push waits. The component is registered again and is given the request from the broker's records.
/// The push is then made, and a notification follows: the component observes the notification and
/// is not given the request a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_recorded_before_the_baseline_was_read_and_pushed_after_it_is_given_once()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    lose_the_runtime(&world).await;
    let pushes = lane.hold_pushes();
    world.send(&request(9));
    until_recorded(&world, 9).await;
    until("the push of the request to be held", || async {
        (pushes.held() == 1).then_some(())
    })
    .await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(
        account.requests,
        ["9"],
        "the baseline did not give the request: {account:?}"
    );

    pushes.release();
    world.send(&notification("after"));
    let account = world
        .until_account(
            1,
            "the component to have observed the notification",
            |account| account.observes >= 2,
        )
        .await;
    assert_eq!(
        account.requests,
        ["9"],
        "the request was given again when the lane offered it: {account:?}"
    );
    assert_eq!(account.observes, 2, "{account:?}");
}

/// KR-REQ-24.24: a request that was answered before the baseline was read is not given when the
/// producer pushes it to the lane after.
///
/// The runtime is lost and the producers' pushes are held. A request arrives, is recorded, and is
/// answered through the native terminal. The component is registered again and is given nothing; the
/// push is then made and a notification follows: the component observes the notification and was
/// never given the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_answered_before_the_baseline_was_read_and_pushed_after_it_is_never_given()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    lose_the_runtime(&world).await;
    let pushes = lane.hold_pushes();
    world.send(&request(11));
    until_recorded(&world, 11).await;
    until("the push of the request to be held", || async {
        (pushes.held() == 1).then_some(())
    })
    .await;
    answer_natively(&world, 11).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert!(account.requests.is_empty(), "{account:?}");

    pushes.release();
    world.send(&notification("after"));
    let account = world
        .until_account(
            1,
            "the component to have observed the notification",
            |account| account.observes >= 1,
        )
        .await;
    assert!(
        account.requests.is_empty(),
        "the component was given a request answered before the baseline was read: {account:?}"
    );
    assert_eq!(account.observes, 1, "{account:?}");
    assert_eq!(
        answers_to(&world, 11),
        1,
        "the upstream was written one answer"
    );
}

/// KR-REQ-24.27 and KR-REQ-24.24: a request made in privacy mode is still one when the component
/// that starts again is given it, and a request that arrives while the runtime is away is decoded
/// again after it.
///
/// A request is recorded in privacy mode and decoded, and privacy mode ends. The runtime is lost, and
/// the component of the binding that observes is marked as handed it again when it is given the
/// request. A request that arrives while the runtime is away, with the decoder's component down, is
/// decoded by the component that starts again.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_made_in_privacy_mode_is_given_as_one_and_a_request_sent_while_the_runtime_was_away_is_decoded_again()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::decoder(2, "hostile-decoder"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;
    let lane = world.broker().observation();
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    world.tell_privacy(&mut authority, 1, true).await;
    world.send(&request_noting(61, "!answer"));
    until("the request to be decoded", || async {
        until_decoded(&world, 61).then_some(())
    })
    .await;
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());

    lose_the_runtime(&world).await;
    world.send(&request_noting(62, "!answer"));
    until_recorded(&world, 62).await;
    // The decode queue holds it for a decoder that is away; the queue the component finds when it
    // starts again is empty, as it is once the queue passes the request over, so only the worker's
    // own queueing when the component is registered can bring the request back.
    let queue = world.broker().decode_queue();
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    let (taken, dropped) = queue.take(|_| Verdict::Drop(NotDecoded::NotRegistered));
    assert!(taken.is_none() && dropped.len() == 1, "{dropped:?}");
    assert!(
        !until_decoded(&world, 62),
        "a request nobody can decode is read by nobody while its decoder is away"
    );
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    assert!(
        lane.is_marked(binding(1)),
        "the component was given a request made in privacy mode and is not marked"
    );
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.requests.iter().filter(|id| *id == "61").count(), 1);
    until(
        "the request sent while the runtime was away to be decoded again",
        || async { until_decoded(&world, 62).then_some(()) },
    )
    .await;
    let decoding = world.reason(2);
    assert!(
        decoding.contains("1 pending request was queued to be decoded again"),
        "{decoding}"
    );
}

/// KR-REQ-24.27 and KR-REQ-24.24: a request made in privacy mode while the runtime was away is still
/// one after it was decoded again and the runtime is lost a second time.
///
/// The runtime is lost, privacy mode is turned on, a request arrives for a decoder that is away, its
/// queued decode is dropped, and privacy mode is turned off. The component that starts again is
/// given the request and the decoder reads it. The runtime is lost again, and the component that
/// starts the second time is given the approval as a request made in privacy mode: it is marked as
/// handed it, as the first was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_made_in_privacy_mode_while_the_runtime_was_away_is_still_one_when_the_runtime_is_lost_again()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::decoder(2, "hostile-decoder"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;
    let lane = world.broker().observation();
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;

    lose_the_runtime(&world).await;
    world.tell_privacy(&mut authority, 1, true).await;
    world.send(&request_noting(63, "!answer"));
    until_recorded(&world, 63).await;
    let queue = world.broker().decode_queue();
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    let (taken, dropped) = queue.take(|_| Verdict::Drop(NotDecoded::NotRegistered));
    assert!(taken.is_none() && dropped.len() == 1, "{dropped:?}");
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());

    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until(
        "the request sent while the runtime was away to be decoded again",
        || async { until_decoded(&world, 63).then_some(()) },
    )
    .await;
    assert!(
        lane.is_marked(binding(1)),
        "the component that started again was given a request made in privacy mode and is not marked"
    );

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(
        account.requests,
        ["63"],
        "the component that started the second time was not given the request: {account:?}"
    );
    assert!(
        lane.is_marked(binding(1)),
        "the component that started the second time was given a request made in privacy mode and \
         is not marked"
    );
}

/// Holds the decode queue, records a request in privacy mode (`authority` tells privacy mode on with
/// the number `first` and off with the next) and passes its queued decode over, as a decode is when
/// the plugin runtime is away. Privacy mode is off again when this returns, and the request is
/// recorded and not decoded.
async fn record_in_privacy_mode_and_pass_its_decode_over(
    world: &Observing,
    authority: &mut kr_ipc::client::BoundLink,
    id: u64,
) {
    let lane = world.broker().observation();
    let queue = world.broker().decode_queue();
    let hold = queue.hold();
    world.tell_privacy(authority, 1, true).await;
    world.send(&request_noting(id, "!answer"));
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    let (taken, dropped) = queue.take(|_| Verdict::Drop(NotDecoded::NotRegistered));
    assert!(taken.is_none() && dropped.len() == 1, "{dropped:?}");
    world.tell_privacy(authority, 2, false).await;
    assert!(!lane.is_private());
    hold.release();
    assert!(
        !until_decoded(world, id),
        "a request nobody can decode is read by nobody"
    );
}

/// KR-REQ-24.27 and KR-REQ-24.24: the runtime's words stay withheld once a component has decoded
/// again a request made in privacy mode, when that decode is all the component was handed.
///
/// Only a decoder is bound. A request is recorded in privacy mode and its decode is passed over;
/// privacy mode ends. The runtime is then lost, and the connection the link makes has not stood
/// under privacy mode. The component that starts again decodes the request, and is handed something
/// made in privacy mode on that connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_made_in_privacy_mode_withholds_the_runtimes_words_when_it_is_decoded_again()
 {
    let Some(world) =
        Observing::start(Options::with(vec![Spec::decoder(1, "hostile-decoder")])).await
    else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    record_in_privacy_mode_and_pass_its_decode_over(&world, &mut authority, 64).await;

    lose_the_runtime(&world).await;
    assert!(
        !lane.words_withheld(),
        "the connection the link made has stood under privacy mode"
    );
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until("the request to be decoded again", || async {
        until_decoded(&world, 64).then_some(())
    })
    .await;
    assert!(
        lane.words_withheld(),
        "the component decoded again a request made in privacy mode, and the words are not withheld"
    );
}

/// KR-REQ-24.27 and KR-REQ-24.24: a request made outside privacy mode and decoded again while it
/// stands is one made in it from then on: the component that starts again after a second loss is
/// handed it as such.
///
/// A request is recorded outside privacy mode while the runtime is away and its queued decode is
/// passed over. Privacy mode is turned on before the component starts again, and the request is
/// decoded again under it. Privacy mode ends and the runtime is lost a second time; the connection
/// the link makes has not stood under privacy mode, and the component that starts again is given
/// the approval and is handed something made in privacy mode.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_request_decoded_again_in_privacy_mode_is_one_made_in_it_when_the_runtime_is_lost_again()
 {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::decoder(2, "hostile-decoder"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;
    let lane = world.broker().observation();
    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;

    lose_the_runtime(&world).await;
    world.send(&request_noting(65, "!answer"));
    until_recorded(&world, 65).await;
    let queue = world.broker().decode_queue();
    until("the request to be queued for its decode", || async {
        (queue.len() == 1).then_some(())
    })
    .await;
    let (taken, dropped) = queue.take(|_| Verdict::Drop(NotDecoded::NotRegistered));
    assert!(taken.is_none() && dropped.len() == 1, "{dropped:?}");
    world.tell_privacy(&mut authority, 1, true).await;

    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until(
        "the request to be decoded again under privacy mode",
        || async { until_decoded(&world, 65).then_some(()) },
    )
    .await;
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());

    lose_the_runtime(&world).await;
    assert!(
        !lane.words_withheld(),
        "the connection the link made has stood under privacy mode"
    );
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.requests, ["65"], "{account:?}");
    assert!(
        lane.words_withheld(),
        "the component was given a request decoded again under privacy mode, and the words are not \
         withheld"
    );
}

/// KR-REQ-24.24: a component is given the requests of its own instance and none of another instance
/// of its package, whether the broker holds them as interpretations or not.
///
/// Two instances run the package. A request is sent to each and read into an approval. The runtime
/// is lost, and the component of each instance that starts again is given the request of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_component_is_given_no_request_of_another_instance_of_its_package() {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::interpreter(2),
        Spec::semantic_only(3).on_the_second_instance(),
        Spec::interpreter(4).on_the_second_instance(),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(3).await;
    world.send(&request(1));
    world.send_to_the_second_instance(&request(5));
    until("both requests to be read into approvals", || async {
        (world
            .broker()
            .pending_resources()
            .iter()
            .filter(|resource| {
                resource.kind == PendingKind::Approval && resource.interpretation_verified
            })
            .count()
            == 2)
            .then_some(())
    })
    .await;
    world
        .until_account(
            1,
            "the first component to have its own request",
            |account| account.requests == ["1"],
        )
        .await;
    world
        .until_account(
            3,
            "the second component to have its own request",
            |account| account.requests == ["5"],
        )
        .await;

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until_started_again(&world, 3).await;
    let first = world.account(1).await.expect("the component answers");
    assert_eq!(
        first.requests,
        ["1"],
        "the component was given the request of another instance: {first:?}"
    );
    assert_eq!(first.observes, 1, "{first:?}");
    let second = world.account(3).await.expect("the component answers");
    assert_eq!(
        second.requests,
        ["5"],
        "the component was given the request of another instance: {second:?}"
    );
    assert_eq!(second.observes, 1, "{second:?}");
}

/// Returns true once the request the upstream gave `id` is an approval.
fn until_decoded(world: &Observing, id: u64) -> bool {
    let wanted = id.to_string();
    world
        .broker()
        .pending_resources()
        .into_iter()
        .any(|resource| {
            resource.request.upstream.as_str() == wanted && resource.interpretation_verified
        })
}

/// KR-REQ-24.24: the worker gives a component that starts again at most what it holds, and says what
/// it could not give.
///
/// Seventy requests arrive while the runtime is away and the decoder is down. The worker retains
/// sixty-four of the frames, so six requests cannot be given; the decode queue takes eight of the
/// sixty-four it is asked to queue again. One of the six is answered through the native terminal
/// while the runtime is away, and is not counted: five cannot be given. A request the worker cannot
/// give can still be answered through the native terminal, once.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_the_worker_gives_at_most_what_it_holds_and_says_what_it_could_not_give() {
    let Some(world) = Observing::start(Options::with(vec![
        Spec::semantic_only(1),
        Spec::decoder(2, "hostile-decoder"),
    ]))
    .await
    else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;

    lose_the_runtime(&world).await;
    for id in 1..=70_u64 {
        world.send_and_wait_for_the_terminal(&request(id)).await;
    }
    until_recorded(&world, 70).await;
    // The decode queue holds the first eight of them for a decoder that is away; the queue the
    // component finds when it starts again is empty, as it is once those are passed over.
    let (taken, dropped) = world
        .broker()
        .decode_queue()
        .take(|_| Verdict::Drop(NotDecoded::NotRegistered));
    assert!(taken.is_none() && dropped.len() == 8, "{dropped:?}");
    answer_natively(&world, 2).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until_started_again(&world, 2).await;

    let reason = world.reason(1);
    for clause in [
        "the worker gave it 64 pending requests from its own records, oldest first",
        "5 pending requests could not be given because the worker could not use their bytes",
    ] {
        assert!(reason.contains(clause), "{clause}: {reason}");
    }
    let decoding = world.reason(2);
    for clause in [
        "8 pending requests were queued to be decoded again",
        "56 pending requests could not be queued to be decoded again because the decode queue was full",
    ] {
        assert!(decoding.contains(clause), "{clause}: {decoding}");
    }
    assert!(
        !decoding.contains("gave it"),
        "a decoder that observes nothing is given nothing: {decoding}"
    );
    answer_natively(&world, 1).await;
    assert_eq!(answers_to(&world, 1), 1);
}

/// KR-REQ-24.24: a component of another package is given nothing of a request that is not its
/// package's, whether the broker holds the request as an interpretation or as a frame.
async fn another_package_is_given_nothing(specs: Vec<Spec>) {
    let Some(world) = Observing::start(Options::with(specs)).await else {
        return;
    };
    world.until_ready(1).await;
    world.until_ready(2).await;
    for id in [1_u64, 2, 3] {
        world.send(&request(id));
    }
    world
        .until_account(1, "the component to have observed them", |account| {
            account.requests.len() == 3
        })
        .await;

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    until_started_again(&world, 2).await;
    let own = world.account(1).await.expect("the component answers");
    assert_eq!(own.requests, ["1", "2", "3"], "{own:?}");
    let other = world.account(2).await.expect("the component answers");
    assert_eq!(other.binds, 1, "{other:?}");
    assert_eq!(
        other.observes, 0,
        "a component of another package was given a request that is not its package's: {other:?}"
    );
    assert!(other.requests.is_empty(), "{other:?}");
}

/// KR-REQ-24.24: the requests the connector's table read into approvals belong to the package that
/// read them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_component_of_another_package_is_given_no_interpreted_request() {
    another_package_is_given_nothing(vec![
        Spec::semantic_only(1),
        Spec::semantic_only(2).of_another_package(),
        Spec::interpreter(3),
    ])
    .await;
}

/// KR-REQ-24.24: the requests nothing interpreted belong to the package whose table recorded them.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_component_of_another_package_is_given_no_uninterpreted_request() {
    another_package_is_given_nothing(vec![
        Spec::semantic_only(1),
        Spec::semantic_only(2).of_another_package(),
    ])
    .await;
}

/// KR-REQ-24.24: a component registered for the first time is given nothing and has no word of a
/// restart, and what reads like a request in a span of terminal output is not one.
///
/// The component is registered after a request arrives (its compile is held), so it starts from the
/// live point. The terminal prints a line that reads like a request. The runtime is then lost; the
/// component that starts again is given the one request the broker holds and not the line.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_24_a_first_registration_is_given_nothing_and_terminal_text_is_no_request() {
    let mut options = Options::with(vec![Spec::observer(1)]);
    options.holding_compiles = true;
    options.shell = "printf '%s\\n' '{\"id\":99,\"method\":\"session/request_permission\",\"params\":{}}'; exec cat"
        .to_owned();
    let Some(world) = Observing::start(options).await else {
        return;
    };
    world.send(&request(5));
    until_recorded(&world, 5).await;
    world.let_the_compiles_go();
    world.until_ready(1).await;
    let account = world.account(1).await.expect("the component answers");
    assert!(
        account.requests.is_empty(),
        "a first registration was given a request: {account:?}"
    );
    assert!(
        !world.reason(1).contains("started again"),
        "{}",
        world.reason(1)
    );

    lose_the_runtime(&world).await;
    world.let_the_compiles_go();
    until_started_again(&world, 1).await;
    let account = world.account(1).await.expect("the component answers");
    assert_eq!(account.requests, ["5"], "{account:?}");
    assert!(
        world
            .broker()
            .pending_resources()
            .iter()
            .all(|resource| resource.request.upstream.as_str() == "5"),
        "text in a span of terminal output became a request"
    );
}

/// KR-REQ-24.27: the worker takes no state of a component, however long the component has been quiet
/// since it was offered something: what a component holds is opaque to the worker, and nothing the
/// worker could keep of it is derived from what it was offered.
///
/// A component observes a frame. Its account is read until it says so, and once more after a wait
/// longer than the time a component was once left quiet before its state was asked for. Each read of
/// the account is a checkpoint, and the case counts its own: the component has taken no others.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_a_component_is_asked_for_no_state_however_long_it_has_been_quiet() {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    world.send(&notification("one"));
    let mut reads = 0_u64;
    loop {
        if let Some(account) = world.account(1).await {
            reads += 1;
            if account.observes >= 1 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let account = world.account(1).await.expect("the component answers");
    reads += 1;
    assert_eq!(
        account.checkpoints, reads,
        "the link took the component's state while it was quiet: {account:?}"
    );
}

/// KR-REQ-24.27: what the runtime says about a fault of a component is made in part of what the
/// component was handed, so the words are not kept once privacy mode has stood on the connection
/// that carries them, however many notices wait and however late the link reads them. Two frames
/// are made in privacy mode and offered after it ended: both faults are read after the change, the
/// second as well as the first, and so is the disabling the third fault brings.
///
/// The worker's pump is held while privacy mode is turned on, two frames that fault the component
/// arrive, and privacy mode is turned off; then the pump goes on. The control is the three-fault
/// case above, where a fault outside privacy mode carries the runtime's words.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_the_runtimes_words_are_never_kept_once_privacy_mode_has_stood_on_the_connection_that_carries_them()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
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
    world.send(&notification("!trap"));
    world.send(&notification("!trap again"));
    until("the lane to hold both frames", || async {
        (lane.waiting() == 2).then_some(())
    })
    .await;
    world.tell_privacy(&mut authority, 2, false).await;
    assert!(!lane.is_private());

    // Both faults are read with privacy mode off, the second after the first.
    hold.release();
    let reason = world.until_reason(1, "(2 in the last minute)").await;
    assert!(
        reason.contains("the runtime's words are withheld for privacy mode"),
        "{reason}"
    );
    assert!(!reason.contains("last fault, in observe: "), "{reason}");

    // The third fault disables the binding, and the reason the runtime gives is words too.
    world.send(&notification("!trap once more"));
    let disabled = until("the binding to be disabled", || async {
        world.broker().rich_disabled(binding(1))
    })
    .await;
    assert!(disabled.contains("withheld for privacy mode"), "{disabled}");
    assert!(!disabled.contains("3 faults within 60 s"), "{disabled}");
}

/// KR-REQ-24.27: the plugin runtime is told whether privacy mode stands, each time it changes, and
/// from the moment it has said it holds that, no document of the worker's connection reaches the
/// worker: the worker reads documents and drops them, so what stops them is the runtime's.
///
/// The `recording` component draws a document in every call. Privacy mode is turned on; the runtime
/// acknowledges it; the component is then made to draw and, after it, to fault, which is a notice
/// that is not a document and comes after every document the runtime wrote before it on the one
/// stream. When the worker has read the fault, no document it read is one drawn after the
/// acknowledgement. The control is the document the worker read before privacy mode. A runtime that
/// replaces the one that was killed is told before the first component is registered on it: its
/// first document, the one `bind` draws, is never read.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_24_27_the_runtime_is_told_privacy_mode_and_no_document_reaches_the_worker_once_it_has_said_it_holds_it()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let lane = world.broker().observation();
    world.until_runtime_told(false).await;
    until("the worker to have read the document bind drew", || async {
        lane.highest_document_read(binding(1)).map(|_| ())
    })
    .await;

    let mut authority = world
        .hosted
        .daemon_connection(ControllerConnectionRole::Authority)
        .await;
    world.tell_privacy(&mut authority, 1, true).await;
    world.until_runtime_told(true).await;
    // Every call the component has made so far drew one document; what it has drawn when the
    // runtime says it holds privacy mode is the most that can have been written before.
    let account = world.raw_account(1).await.expect("the component answers");
    let drawn = |text: &str| -> u64 {
        ["bind=", "observe=", "snapshot="]
            .iter()
            .map(|key| {
                text.split(';')
                    .find_map(|part| part.strip_prefix(key))
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0)
            })
            .sum()
    };
    let at_acknowledgement = drawn(&account);

    // The component draws, and then faults; the fault is read after everything before it.
    world.send(&notification("drawn while the runtime holds privacy mode"));
    world
        .until_account(1, "the component to draw it", |account| {
            account.observes >= 1
        })
        .await;
    world.send(&notification("!trap"));
    world.until_reason(1, "last fault, in observe").await;
    let read = lane
        .highest_document_read(binding(1))
        .expect("the worker read a document before");
    assert!(
        read <= at_acknowledgement,
        "the worker read document {read}, drawn after the runtime said it held privacy mode (it had \
         drawn {at_acknowledgement})"
    );

    // The runtime that replaces a killed one is told before anything is registered on it: nothing
    // the first component draws is read, and what the control read before is not carried over.
    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::kill(&host);
    until("a replacement runtime to be published", || async {
        world
            .hosted
            .published()
            .filter(|published| *published != host)
    })
    .await;
    world
        .until_account(1, "the component to be registered again", |account| {
            account.binds >= 1
        })
        .await;
    world.until_ready(1).await;
    world.until_runtime_told(true).await;
    world.send(&notification("!trap"));
    world.until_reason(1, "last fault, in observe").await;
    assert_eq!(
        lane.highest_document_read(binding(1)),
        None,
        "a document drawn by the component on the replacement reached the worker"
    );

    // Privacy mode off: the runtime is told, and documents arrive again.
    world.tell_privacy(&mut authority, 2, false).await;
    world.until_runtime_told(false).await;
    world.send(&notification("drawn once privacy mode has ended"));
    until("the worker to read a document again", || async {
        lane.highest_document_read(binding(1)).map(|_| ())
    })
    .await;
}

/// KR-REQ-11.01: a component reads the execution its binding is bound to as the broker holds it, and
/// reads each change of it in its next call.
///
/// The instance is at revision 1 with no conversation and no turn when the component is registered.
/// The broker then moves the instance to a conversation, which is revision 2, starts a turn, and
/// ends it. The component's own account says what it read each time. A runtime that replaces a
/// killed one registers the component with the execution as it is by then, and not as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_11_01_a_component_reads_the_execution_its_binding_is_bound_to_and_each_change_of_it()
 {
    let Some(world) = Observing::start(Options::with(vec![Spec::semantic_only(1)])).await else {
        return;
    };
    world.until_ready(1).await;
    let reads = async |part: &str| {
        until("the component to read the execution", || async {
            world
                .raw_account(1)
                .await
                .filter(|account| account.contains(part))
        })
        .await
    };
    reads("facts=1/idle/-/-/").await;

    let broker = world.broker();
    broker
        .advance_binding(
            instance(),
            Some(kr_protocol::ids::AgentThreadId::new("thread-5").expect("a thread")),
            kr_protocol::scalars::TimestampMs::new(5),
        )
        .expect("the instance moves to a conversation");
    reads("facts=2/idle/thread-5/-/").await;
    broker
        .set_turn(
            instance(),
            Some(kr_protocol::ids::AgentTurnId::new("turn-9").expect("a turn")),
        )
        .expect("a turn starts");
    reads("facts=2/running/thread-5/turn-9/").await;
    broker.set_turn(instance(), None).expect("the turn ends");
    reads("facts=2/idle/thread-5/-/").await;

    // The replacement for a runtime that was killed is told what the execution is by then.
    let host = world.hosted.published().expect("the runtime is published");
    plugin_world::kill(&host);
    until("a replacement runtime to be published", || async {
        world
            .hosted
            .published()
            .filter(|published| *published != host)
    })
    .await;
    world
        .until_account(1, "the component to be registered again", |account| {
            account.binds >= 1
        })
        .await;
    reads("facts=2/idle/thread-5/-/").await;
}
