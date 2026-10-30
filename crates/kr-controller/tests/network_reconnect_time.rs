//! What a paired device waits for when it comes back to a real daemon.
//!
//! KR-PERF-006 gives a reconnect two seconds from the moment the transport is available to a
//! usable 120x40 screen, leaving out pairing, an outage of discovery and the operating system's
//! suspension. The client library's own case times its half against a host that answers at once,
//! and the transport's times a frame carried. This case times the whole of what lies between: one
//! real daemon on the loopback network, a real worker it adopts, and a paired device that has been
//! attached and subscribed before and has gone, and that comes back the way the client library
//! comes back: with the cursors the ended session carried, subscribing from the position it held.
//! The clock starts as the device dials, which on the loopback network with direct addresses is
//! the moment the transport is available, and it stops when the restoration has installed the
//! screen the host projects and the client has painted it. The connection and its handshake, the
//! attach that comes before the subscription, the host's answer to each, and the projection it
//! builds and publishes are all inside the figure.
//!
//! The two seconds are the row's figure for the reference host, so they are asserted only where no
//! condition of the reference host that a run can read is shown to fall short: an optimised build,
//! at least four processors, 8 GiB of memory, durable writes on the host's disk in at most 25 ms in
//! the slowest tenth of a reading, and at most one part in a hundred of the time taken by a
//! hypervisor, where the platform accounts for them. "Nothing else running" is not among them, so
//! a figure with no shortfall is a figure with no measured shortfall and not a certified
//! reference-host run. Where a shortfall is shown, which is every debug build, the figure is
//! recorded with the shortfall named and the target cannot fail the case. A run that gets as far as
//! the timed span's end records the figure beside the host it was taken on, in the form the other
//! performance records take, before the target is asserted. The case has no other limit on time
//! than a liveness bound of 120 seconds on each wait, including the wait for the screen inside the
//! timed span, so a host that never publishes one fails the case whatever it lacks.

#![cfg(unix)]

mod net_support;

#[path = "../../../tests/perf/src/record.rs"]
mod record;

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::projection::paint::{Keyboard, Window};
use kr_client::projection::{Applied, Projection};
use kr_client::reconnect::ClientState;
use kr_client::session::Session;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::ids::{EnvironmentId, SessionId, StreamId};
use kr_protocol::method::Method;
use kr_protocol::recovery::EventStream;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, U64};
use kr_protocol::session::Dimensions;

use net_support::worker::Worker;
use net_support::{Device, Host, pair_with, paired_dial, proposal};

/// How long a case waits for something the host does without being asked again: a liveness bound,
/// and not the figure under test.
const LIVENESS: Duration = Duration::from_secs(120);

/// The file this case keeps its record in when a run keeps its evidence.
const RECORD: &str = "kr-controller-reconnect.md";

/// The screen section 27 names.
const COLUMNS: u64 = 120;
const ROWS: u64 = 40;

/// The last line the application writes, which is on the screen the device is restored to.
const LAST_LINE: &str = "kr-row-45";

/// The application: it writes more lines than a screen holds, says it is ready, and keeps the
/// session open.
fn application(kept: &std::path::Path) -> String {
    format!(
        "i=1; while [ $i -le 45 ]; do echo kr-row-$i; i=$((i+1)); done; touch '{}'; exec cat",
        kept.join("ready").display()
    )
}

fn output_stream() -> StreamId {
    StreamId::new("session.output").expect("a stream identifier")
}

/// Attaches as a terminal of the session's size that draws a rendering of its grid, without
/// claiming the geometry, subscribes from the client's cursors, and returns the time until the
/// host's screen is installed and painted, with the painted text.
///
/// Everything a reconnecting client does after the transport returns is in here, in the order it
/// does it: the attach, the subscription named by the cursors, the projection's snapshot and rows,
/// and the paint. The step the restoration began at is returned, so a caller can say whether the
/// subscription resumed from a position or began at the start. The position the installed screen
/// describes is recorded as applied, which is what a later reconnect carries.
async fn restored(
    session: &Session,
    environment_id: EnvironmentId,
    session_id: SessionId,
    started: Instant,
) -> (Duration, String, RestorationStep) {
    // The events are read from before the subscription, so nothing it queues is missed.
    let mut events = session.events();
    let attached: SessionAttachResult = session
        .mutate(
            Method::SessionAttach,
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            None,
            &ParamsValue::empty(),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(COLUMNS, ROWS)),
                terminal_profile_id: Nullable::null(),
                requested: [AttachmentCapability::ObserveTerminal]
                    .into_iter()
                    .collect(),
            },
            DurationMs::new(120_000),
        )
        .await
        .expect("the attach is settled")
        .to_typed()
        .expect("an attachment");

    let mut restoration = Restoration::start(output_stream(), &session.cursors().await);
    let began = restoration.step();
    let params = restoration
        .subscribe_params(
            session_id,
            attached.attachment.attachment_id,
            &[EventStream::Output],
        )
        .expect("the stream is waiting to subscribe");
    session
        .subscribe_events(&params)
        .await
        .expect("the subscription succeeds");
    restoration.subscribed().expect("the order is kept");

    let mut projection = Projection::new();
    let deadline = tokio::time::Instant::now() + LIVENESS;
    loop {
        let notification = tokio::time::timeout_at(deadline, events.recv())
            .await
            .expect("the host projected a screen")
            .expect("the channel is open");
        let Some(event) =
            kr_client::projection::decode(notification.event_type.as_str(), &notification.payload)
        else {
            continue;
        };
        if matches!(projection.apply(event), Applied::Installed) {
            break;
        }
    }
    restoration.installed().expect("the snapshot is installed");

    let screen = projection.screen().expect("a screen");
    assert_eq!(
        (
            screen.dimensions.columns.get(),
            screen.dimensions.rows.get()
        ),
        (COLUMNS, ROWS),
        "the screen the host restored is the size section 27 names"
    );
    let painted =
        kr_client::projection::paint::install(screen, Window::of(screen), Keyboard::EVERYTHING);
    let elapsed = started.elapsed();
    let base = projection.base().expect("the installed screen has a base");
    session
        .applied_content(&output_stream(), U64::new(base.cursor))
        .await;
    (
        elapsed,
        String::from_utf8(painted.bytes).expect("the paint is text and escapes"),
        began,
    )
}

/// KR-PERF-006: a paired device that comes back to a real daemon has a painted 120x40 screen of
/// the session within two seconds of dialling again, on a host that is not shown to fall short of
/// the reference host.
///
/// The device is attached and subscribed once and goes, and the host has recorded that its
/// connection ended. It then dials again, resuming the cursors the ended session carried, and the
/// clock starts as it dials. The two seconds are the row's figure for the reference host: they
/// are asserted where no condition the record reads falls short, and the reading is recorded with
/// the host it was taken on in every run. A host that is shown to fall short of the reference host
/// (a debug build, fewer processors, a slow disk) records its figure and fails nothing on time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_that_comes_back_has_a_painted_screen_inside_the_reconnect_budget() {
    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let stopped = host.shut_down().await;
    let worker = Worker::start_running_sized(
        stopped.tree(),
        1,
        &application(kept.path()),
        Dimensions::new(COLUMNS, ROWS),
    )
    .await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    until("the daemon to serve the worker's session", || async {
        let mut client = host.client().await;
        client
            .request(
                Method::SessionRead,
                &kr_protocol::session::SessionReadParams {
                    session_id: worker.session_id,
                },
            )
            .await
            .expect("the call reaches the daemon")
            .is_ok()
            .then_some(())
    })
    .await;
    until("the application to write its screen", || async {
        kept.path().join("ready").exists().then_some(())
    })
    .await;

    let device = Device::create().await;
    let record = pair_with(
        &host,
        &device,
        &owner,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let dial = paired_dial(&host, &device, &record);

    // The first connection: attached, subscribed and restored, then gone. What it applied is what
    // the client library carries to the next one.
    let first_started = Instant::now();
    let first_transport = dial.dial().await;
    let session = Session::start(Arc::new(first_transport)).expect("a session");
    let (first, painted, began) = restored(
        &session,
        host.environment_id,
        worker.session_id,
        first_started,
    )
    .await;
    assert_eq!(
        began,
        RestorationStep::SubscribeFromStart,
        "a device with nothing applied subscribes from the start"
    );
    assert!(
        painted.contains(LAST_LINE),
        "the screen carries the session's text"
    );
    let carried = ClientState::from_session(&session, None).await;
    session.close();
    until("the host to record that the connection ended", || async {
        (host.connections_of(&record) == 0).then_some(())
    })
    .await;

    // The host is read before the clock starts and again after it stops, so that neither reading
    // is inside the figure. The disk is read in the tree that holds the worker's journal, since the
    // attach inside the figure waits on a durable write.
    let window = record::Window::open_with_disk(host.tree().environment().state_root());

    // The return: the clock starts as the device dials, and nothing has been asked of the host.
    let started = Instant::now();
    let transport = dial.dial().await;
    let session = Session::resume(Arc::new(transport), carried.cursors).expect("a resumed session");
    let (elapsed, painted, began) =
        restored(&session, host.environment_id, worker.session_id, started).await;
    assert!(
        matches!(began, RestorationStep::SubscribeFrom(_)),
        "a reconnect subscribes from the position it carried: {began:?}"
    );
    assert!(
        painted.contains(LAST_LINE),
        "every row of the session's screen is in what a terminal would be sent"
    );
    let conditions = window.close();
    let shortfalls = conditions.shortfalls();
    let budget = kr_client::retry::RECONNECT_BUDGET;
    let mut lines = conditions.lines();
    lines.push(format!(
        "  reconnect         {elapsed:?} from the dial to a painted {COLUMNS}x{ROWS} screen, against \
         a {budget:?} target (the first connection took {first:?})"
    ));
    if shortfalls.is_empty() {
        lines.push(format!(
            "  verdict           no measured shortfall, and the target is {} on this host",
            if elapsed < budget { "met" } else { "not met" }
        ));
        lines.push(
            "  conditions        no measured shortfall, so the target is asserted here; what the \
             lines above call unverified stays unverified"
                .to_owned(),
        );
    } else {
        lines.push(format!(
            "  verdict           {} the target, with a condition missing, so it is recorded and \
             not asserted here",
            if elapsed < budget {
                "inside"
            } else {
                "outside"
            }
        ));
        for shortfall in &shortfalls {
            lines.push(format!("  condition missing {shortfall}"));
        }
        lines.push(
            "  conditions        not met, so the figure above is recorded and the target is not \
             asserted here; the target's evidence is a run of this case in a release build on a \
             reference host"
                .to_owned(),
        );
    }
    // Before the assertion, so a run the target failed on keeps the figure and the verdict.
    record::report(RECORD, "KR-PERF-006 reconnect to a real daemon", &lines);
    if shortfalls.is_empty() {
        assert!(
            elapsed < budget,
            "a reconnect to a real daemon took {elapsed:?}, over the {budget:?} budget"
        );
    }

    session.close();
    worker
        .runtime()
        .close(kr_protocol::session::ClosureReason::CloseRequested)
        .1
        .release();
    host.stop().await;
}

/// Asks `check` until it answers, or the liveness bound runs out.
async fn until<T, Fut>(what: &str, mut check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + LIVENESS;
    loop {
        if let Some(found) = check().await {
            return found;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited {LIVENESS:?} for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
