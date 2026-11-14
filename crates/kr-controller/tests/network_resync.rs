//! A paired device that is behind a session's bounded history, over a real connection.
//!
//! One real daemon on the loopback network, the worker's own session service over a real
//! pseudo-terminal that the daemon adopts, and a paired device that dials it over iroh. The device
//! has installed the session's screen and gone; the session then writes more output than its
//! history keeps; and the device comes back with the position it held. What it is told and what
//! it is then sent are read on the device, from what arrives on its own connection.
//!
//! The session keeps no spool and retains a few kilobytes, which is what the case configures. A
//! session on a host keeps a spool that holds up to 128 MiB of one session's output, and a case
//! that reached that bound would write more output than it can write quickly. So the window here
//! is smaller than a host's, and the case runs the layout that keeps only the resident window: the
//! gap it is told carries no cause, where a spool's eviction records one. The decision that a
//! position lies behind what is kept is the worker's own line, which takes the oldest cursor of
//! the session's history whichever layers hold it, so the decision made about this window is the
//! one made about a host's.
//!
//! The application follows a file from its start, so the output is written when the case writes
//! the file, and the case waits for the worker to have retained the last line it wrote, as the
//! owner reads the retained output, never by a length of time.

#![cfg(unix)]

mod net_support;

use std::sync::Arc;
use std::time::Duration;

use kr_client::cursors::{Restoration, RestorationStep};
use kr_client::projection::{Applied, Projection, Screen};
use kr_client::reconnect::ClientState;
use kr_client::session::Session;
use kr_crypto::keys::DeviceKeys;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, Notification, ParamsValue};
use kr_protocol::ids::{EnvironmentId, SessionId, StreamId};
use kr_protocol::method::Method;
use kr_protocol::projection::ProjectionEvent;
use kr_protocol::recovery::{
    EventStream, EventsSubscribeResult, HistoryGap, HistoryPageParams, HistoryPageResult,
    MAX_HISTORY_PAGE_BYTES,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, U64};
use kr_protocol::session::{ClosureReason, Dimensions};
use tokio::sync::broadcast::Receiver;

use net_support::worker::Worker;
use net_support::{Device, Host, pair_with, paired_dial, proposal};

/// How long a case waits for something the host does without being asked again. It is a bound on
/// a wait that ends by a condition, and no measure of anything the case asserts.
const LIVENESS: Duration = Duration::from_secs(120);

/// How much of its output the session retains.
const WINDOW: usize = 16 * 1024;

/// The screen the device draws.
const COLUMNS: u64 = 80;
const ROWS: u64 = 24;

/// What the application prints before anything is written to it.
const READY: &str = "kr-ready.";

/// The last line written while the device is away.
const LAST_AWAY: &str = "kr-away-last";

/// The application: it says it is ready and then prints what is appended to a file.
///
/// The file is empty when the application starts and is followed from its first byte, so what is
/// written before the reader has opened it is read as well.
fn application(output: &std::path::Path) -> String {
    format!(
        "printf '{READY}'; exec tail -f -n +1 '{}'",
        output.display()
    )
}

fn output_stream() -> StreamId {
    StreamId::new("session.output").expect("a stream identifier")
}

/// What a device holds after it has subscribed and installed the screen the host sent.
struct Joined {
    /// The events of the connection, read from before the subscription was made.
    events: Receiver<Notification>,
    /// The step the restoration began at.
    began: RestorationStep,
    /// What the subscription's answer said.
    subscribed: EventsSubscribeResult,
    /// The screen the host's projection installed.
    projection: Projection,
    /// The notice of a gap the stream opened with, when it opened with one.
    gap_notice: Option<HistoryGap>,
}

/// Attaches as a terminal that draws a rendering of the session's grid, subscribes from the
/// cursors the client holds, and applies what arrives until the host's screen is installed.
///
/// The position the installed screen describes is recorded as applied, which is what a later
/// reconnect carries.
async fn join(session: &Session, environment_id: EnvironmentId, session_id: SessionId) -> Joined {
    // The events are read from before the subscription, so nothing it queues is missed.
    let mut events = session.events();
    let attached: SessionAttachResult = within_liveness(
        "the host to answer the attach",
        session.mutate(
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
        ),
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
    let subscribed = within_liveness(
        "the host to answer the subscription",
        session.subscribe_events(&params),
    )
    .await
    .expect("the subscription succeeds");
    restoration.subscribed().expect("the order is kept");

    let mut projection = Projection::new();
    let mut gap_notice = None;
    let mut screen_begun = false;
    within_liveness("the host to send its screen", async {
        loop {
            let notification = events.recv().await.expect("the connection is open");
            let Some(event) = kr_client::projection::decode(
                notification.event_type.as_str(),
                &notification.payload,
            ) else {
                if notification.event_type.as_str() == "session.gap" {
                    assert!(
                        !screen_begun,
                        "the notice of a gap comes before the screen the stream opens with"
                    );
                    gap_notice = Some(notification.payload.to_typed().expect("a gap"));
                }
                continue;
            };
            screen_begun = true;
            if matches!(projection.apply(event), Applied::Installed) {
                break;
            }
        }
    })
    .await;
    restoration.installed().expect("the snapshot is installed");
    let base = projection.base().expect("the installed screen has a base");
    session
        .applied_content(&output_stream(), U64::new(base.cursor))
        .await;
    Joined {
        events,
        began,
        subscribed,
        projection,
        gap_notice,
    }
}

/// The text of the rows the screen shows, top to bottom, one line each.
fn shown(screen: &Screen) -> String {
    screen
        .visible_rows()
        .into_iter()
        .filter_map(|row| screen.row(row))
        .map(|row| {
            row.runs
                .iter()
                .map(|run| run.text.as_str())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Applies what the device is sent until its screen shows `wanted`, and returns the cursor each
/// update continued from and the cursor it reached. Every event must be an update that the screen
/// takes: a reset, a refusal or a second snapshot is the host saying that what the device holds is
/// not the session.
async fn follow(
    projection: &mut Projection,
    events: &mut Receiver<Notification>,
    wanted: &str,
) -> Vec<(u64, u64, u64)> {
    let mut updates = Vec::new();
    within_liveness(&format!("the screen to show {wanted:?}"), async {
        loop {
            let screen = projection.screen().expect("a screen is installed");
            if shown(screen).contains(wanted) {
                return;
            }
            let notification = events.recv().await.expect("the connection is open");
            let Some(event) = kr_client::projection::decode(
                notification.event_type.as_str(),
                &notification.payload,
            ) else {
                continue;
            };
            let held = projection.base().expect("a held screen has a base").cursor;
            let ProjectionEvent::Delta(delta) = &event else {
                panic!("after the snapshot the host sends updates and nothing else: {event:?}");
            };
            let (base, next) = (delta.base_cursor.get(), delta.next_cursor.get());
            let applied = projection.apply(event);
            assert!(
                matches!(applied, Applied::Updated(_)),
                "an update continuing from {base} was not taken by a screen at {held}: {applied:?}"
            );
            updates.push((held, base, next));
        }
    })
    .await;
    updates
}

/// Appends `text` to the file the application follows.
fn write(output: &std::path::Path, text: &str) {
    use std::io::Write as _;
    std::fs::OpenOptions::new()
        .append(true)
        .open(output)
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .expect("the output is added to");
}

/// What the owner reads of the worker's retained output, on the worker's own socket: the page from
/// the oldest cursor it keeps, whole. The case uses it to know when the worker holds what the
/// application printed, and asserts nothing about what it reads.
async fn retained(worker: &Worker) -> HistoryPageResult {
    let page: HistoryPageResult = worker
        .client()
        .await
        .request(
            Method::HistoryPage,
            &HistoryPageParams {
                session_id: worker.session_id,
                from_cursor: U64::new(0),
                max_bytes: U64::new(MAX_HISTORY_PAGE_BYTES),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the owner is served the page")
        .to_typed()
        .expect("decodes");
    page
}

/// The bytes of a page without the carriage returns the terminal adds to each line end.
fn without_returns(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .copied()
        .filter(|&byte| byte != b'\r')
        .collect()
}

/// Asks `check` until it answers, or the liveness bound runs out.
async fn until<T, Fut>(what: &str, mut check: impl FnMut() -> Fut) -> T
where
    Fut: std::future::Future<Output = Option<T>>,
{
    within_liveness(what, async {
        loop {
            if let Some(found) = check().await {
                return found;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
}

/// Runs one whole wait inside the liveness bound, and fails the case when the bound runs out.
async fn within_liveness<T>(what: &str, wait: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, wait)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS:?} for {what}"))
}

/// KR-REQ-08.80: a paired device that is behind the session's bounded history is told so over its
/// connection, is sent a fresh snapshot, and goes on from it with no hole.
///
/// The device installs the session's screen and goes, carrying the position it reached. The
/// session writes more than its history retains, so the position is behind what the worker keeps.
/// The device dials again and subscribes from that position. The answer names the gap, the
/// range from the position it held to the oldest cursor the worker still retains. The host does
/// not replay what is gone: it sends the screen as it stands, which carries the last of what was
/// written while the device was away, and the device installs it at the cursor the subscription
/// named, past the gap. The output written after that arrives as updates, each continuing from
/// the cursor the screen before it was at, the first from the snapshot's own.
///
/// The host sends a projected attachment a fresh screen with every subscription, so the case shows
/// that the device is told of the gap and installs the screen as it stands past it, not that the
/// screen is sent because of the gap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_device_behind_the_bounded_history_is_told_of_the_gap_and_sent_a_fresh_snapshot() {
    let kept = tempfile::tempdir().expect("a directory for what the application follows");
    let output = kept.path().join("output");
    std::fs::write(&output, b"").expect("the file the application follows");
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let stopped = host.shut_down().await;
    let worker =
        Worker::start_running_with_a_window(stopped.tree(), 1, &application(&output), WINDOW).await;
    let settings = stopped.settings().clone();
    let host = stopped.start(settings).await;
    until("the daemon to serve the worker's session", || async {
        host.client()
            .await
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
    until("the application's first output", || async {
        let page = retained(&worker).await;
        (page.oldest_retained_cursor.get() == 0
            && page.bytes.as_slice().ends_with(READY.as_bytes()))
        .then_some(())
    })
    .await;

    let device = Device::create().await;
    let record = within_liveness(
        "the host to pair the device",
        pair_with(
            &host,
            &device,
            &owner,
            proposal(&[ActionRight::SessionView]),
        ),
    )
    .await;
    let dial = paired_dial(&host, &device, &record);

    // The first connection: attached, subscribed and given the screen, and then gone. What it
    // applied is what the client library carries to the next one.
    let session = Session::start(Arc::new(dial.dial().await)).expect("a session");
    let first = join(&session, host.environment_id, worker.session_id).await;
    assert_eq!(
        first.began,
        RestorationStep::SubscribeFromStart,
        "a device with nothing applied subscribes from the start"
    );
    assert!(
        first.subscribed.gap.0.is_none(),
        "a device that holds no position is behind nothing: {:?}",
        first.subscribed.gap
    );
    assert!(
        shown(first.projection.screen().expect("a screen")).contains(READY),
        "the first screen carries what the application printed"
    );
    let carried = ClientState::from_session(&session, None).await;
    let held = carried
        .cursors
        .applied_cursor(&output_stream())
        .expect("the device holds a position")
        .get();
    session.close();
    until("the host to record that the connection ended", || async {
        (host.connections_of(&record) == 0).then_some(())
    })
    .await;

    // While the device is away the session writes more than it keeps, and the case waits until
    // the oldest cursor the worker retains has passed the position the device holds.
    let padding = "x".repeat(70);
    let mut away = String::new();
    for line in 0..300 {
        away.push_str(&format!("kr-away-{line:04} {padding}\n"));
    }
    away.push_str(&format!("{LAST_AWAY}\n"));
    write(&output, &away);
    until(
        "the worker to hold the last line and have lost the device's position",
        || async {
            let page = retained(&worker).await;
            (page.oldest_retained_cursor.get() > held
                && without_returns(page.bytes.as_slice())
                    .ends_with(format!("{LAST_AWAY}\n").as_bytes()))
            .then_some(())
        },
    )
    .await;

    // The return, with the position the ended connection carried.
    let session =
        Session::resume(Arc::new(dial.dial().await), carried.cursors).expect("a resumed session");
    let mut second = join(&session, host.environment_id, worker.session_id).await;
    assert_eq!(
        second.began,
        RestorationStep::SubscribeFrom(U64::new(held)),
        "the device subscribes from the position it carried"
    );

    // The host tells the device what is gone, in the protocol's own words: the range from the
    // position the device held to the oldest cursor retained, which is where the answer says the
    // history begins.
    let gap: HistoryGap = second
        .subscribed
        .gap
        .0
        .expect("a device behind the history is told of the gap");
    assert_eq!(
        gap.from_cursor.get(),
        held,
        "the gap begins at the position held"
    );
    assert_eq!(
        gap.to_cursor, second.subscribed.oldest_retained_cursor,
        "the gap ends where the history that remains begins"
    );
    assert!(
        gap.to_cursor.get() > held,
        "the history that remains begins past the position held"
    );
    assert!(
        gap.to_cursor.get() < second.subscribed.from_cursor.get(),
        "some of the history remains after the gap, up to the cursor the screen is at"
    );

    // The stream the device is sent opens with the same notice, before the screen, and the first
    // connection, which held no position, was sent none.
    assert_eq!(
        second.gap_notice,
        Some(gap),
        "the stream opens with a notice of the gap the answer named"
    );
    assert_eq!(
        first.gap_notice, None,
        "a device that held no position was sent no notice of a gap"
    );

    // And it is sent the screen as it stands, past the gap, rather than the bytes that are gone.
    let base = second
        .projection
        .base()
        .expect("the installed screen has a base");
    assert_eq!(
        base.cursor,
        second.subscribed.from_cursor.get(),
        "the screen is the one at the cursor the subscription named"
    );
    assert!(
        base.cursor >= gap.to_cursor.get(),
        "the screen is at a cursor past the gap"
    );
    let text = shown(second.projection.screen().expect("a screen"));
    assert!(
        text.contains(LAST_AWAY),
        "the screen carries the last of what was written while the device was away: {text:?}"
    );

    // What is written from here on arrives in order, and each update continues from where the
    // screen before it was, the first from the snapshot's own cursor.
    let installed_at = base.cursor;
    let mut updates = Vec::new();
    for line in ["kr-live-1", "kr-live-2", "kr-live-3"] {
        write(&output, &format!("{line}\n"));
        updates.extend(follow(&mut second.projection, &mut second.events, line).await);
    }
    assert_eq!(
        updates.first().map(|&(_, base, _)| base),
        Some(installed_at),
        "the first update continues from the snapshot's cursor: {updates:?}"
    );
    for &(held, base, next) in &updates {
        assert_eq!(
            base, held,
            "each update continues from the screen before it"
        );
        assert!(next > base, "each update moves the screen on: {updates:?}");
    }
    let text = shown(second.projection.screen().expect("a screen"));
    let place = |line: &str| {
        text.find(line)
            .unwrap_or_else(|| panic!("{line} on {text:?}"))
    };
    assert!(
        place("kr-live-1") < place("kr-live-2") && place("kr-live-2") < place("kr-live-3"),
        "what was written after the snapshot is shown in the order it was written: {text:?}"
    );

    session.close();
    worker
        .runtime()
        .close(ClosureReason::CloseRequested)
        .1
        .release();
    host.stop().await;
}
