//! What the host adds to a keystroke, and how long it holds an ambiguous one.
//!
//! These are measurements rather than unit tests, so they are ignored by default and
//! `scripts/performance.sh` runs them in a release build. Each one prints the conditions it was
//! taken under, because a latency figure without them is not evidence.
//!
//! # What is being measured, and what is deliberately not
//!
//! The path is the one `kr attach` uses: a client writes `input.write` on the session's own local
//! socket. What the measurement waits for is the byte arriving at the *application*, which the root
//! program reports by echoing it, and then reaching the client again as output.
//!
//! That is deliberately **more** than section 27 asks for. The section excludes the application's
//! own work and the terminal's render; this includes the application's read and echo and the host's
//! whole output path. It is measured that way because the host's acknowledgement is not proof that
//! the byte was written: the write is handed to the session's writer and the answer does not wait
//! for it, so a figure that stopped at the answer would pass while a slow writer missed the bound.
//! An upper bound that meets the target establishes the target; a figure that measures less than
//! the target does not.
//!
//! The terminal's own render is still outside it, because no application here draws anything.
//!
//! The recogniser measurement runs the same way, and has to. What it measures is a *wait* the host
//! imposes deliberately, so it runs to the point where the held byte reaches the application. Its
//! own bound is checked twice: the deadline the host is built with is asserted against section 27's
//! twenty-five milliseconds directly, and the observed arrival is bounded separately with a stated
//! allowance for everything around it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionDetachParams,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputWriteParams, InputWriteResult};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};
use kr_worker::trace::Site;

#[path = "../../../tests/perf/src/record.rs"]
mod record;

#[path = "input_latency/recorded.rs"]
mod recorded;

/// The record these measurements' figures are kept in, under `KR_TEST_ARTIFACTS_DIR`.
const RECORD: &str = "kr-worker-input.md";

/// The bound section 27 puts on the ninety-fifth percentile.
const P95_BOUND: Duration = Duration::from_millis(5);

/// The bound section 27 puts on the ninety-ninth percentile.
const P99_BOUND: Duration = Duration::from_millis(15);

/// The recogniser's deadline.
const RECOGNISER_DEADLINE: Duration = Duration::from_millis(25);

/// How much longer than the deadline a held byte may take to arrive.
///
/// The deadline is the host's; this covers the timer's own wake-up, the write, the application's
/// echo and this measurement's polling interval. A figure beyond it is a wait the requirement does
/// not allow, whatever caused it.
///
/// An allowance cannot tell a twenty-five millisecond deadline from a thirty-five millisecond one,
/// so the deadline itself is asserted against section 27's figure separately. This bounds the path
/// around it.
const RECOGNISER_TOLERANCE: Duration = Duration::from_millis(15);

/// How many keystrokes the latency measurement sends.
const SAMPLES: usize = 1_000;

/// How many live shells section 27 puts on the host while a measurement runs.
const BACKGROUND_SESSIONS: usize = 20;

/// How many attached views it puts on them.
const BACKGROUND_VIEWS: usize = 32;

/// What each background session runs.
///
/// It has to still be there when the measurement starts, and building this background is itself
/// slow on a busy machine: nineteen sessions, each with a pseudo-terminal, a shell, a session key
/// and a secret store. A shell on a ten-minute clock took its session with it while the background
/// was still being built - measured at 802 s to build on a machine at load 9 - and the measurement
/// then failed attaching to a session that had closed exactly as it was told to, reporting
/// `SessionClosed` for what was really its own setup time. A day is not a bound this can reach; it
/// is the absence of one.
const BACKGROUND_SHELL: &str = "sleep 86400";

/// How often the recogniser measurement looks for the held byte.
const POLL: Duration = Duration::from_micros(250);

/// How long an attachment's opening output is given to stop before the latency measurement starts.
///
/// What arrives is a drawn screen and the root program's few bytes, which stop within a moment
/// even on a busy machine. Output still arriving after this long comes from something other than
/// the root program the measurement started, and the measurement says so rather than waiting on it.
const OPENING_OUTPUT_BOUND: Duration = Duration::from_secs(30);

/// A root program that echoes what it reads, with the terminal in raw mode.
const ECHOES: &str = "stty raw -echo; printf 'kr-ready.'; exec cat";

/// The same, with canonical bracketed paste enabled by the application.
const ECHOES_BRACKETED: &str = "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat";

fn build() -> BuildId {
    BuildId::new("kr-perf/0").expect("a build identifier")
}

struct Hosted {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
}

impl Hosted {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }
}

async fn hosted(script: &str) -> Hosted {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = ControllerIdentity::initialise(store.store.as_ref(), environment_id)
        .expect("a controller identity");

    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script.to_owned()],
            cwd: "/".to_owned(),
            environment: vec![
                ("TERM".to_owned(), "xterm-256color".to_owned()),
                ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
                ("PS1".to_owned(), String::new()),
            ],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );

    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                build_id: build(),
                journal_path: None,
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Hosted {
        _temp: temp,
        _service: service,
        runtime,
        session_id,
        environment_id,
        endpoint,
    }
}

/// Says what a session did, for an attachment that was refused.
///
/// A refusal names the rule, not the history: `SessionClosed` says the session is closed and
/// nothing about whether its shell exited, was signalled, or was told to stop. The record is where
/// that is, so a measurement that cannot attach reports it rather than leaving the next reader to
/// guess.
fn why(hosted: &Hosted) -> String {
    let state = hosted.runtime.state();
    let session = hosted.runtime.session();
    match session.closure() {
        Some(record) => format!(
            ", and the session is {state:?}: closed for {:?}, root exit {:?}, root signal {:?}, \
             coverage {:?}, terminated {:?}, surviving {:?}",
            record.reason,
            record.root_exit_code,
            record.root_signal,
            record.ownership_coverage,
            record.terminated,
            record.surviving
        ),
        None => format!(", and the session is {state:?} with no record written"),
    }
}

/// Attaches a terminal that may type, and returns its client, identifier and lease epoch.
async fn controlling(
    hosted: &Hosted,
) -> (LocalClient, AttachmentId, kr_protocol::ids::InputLeaseEpoch) {
    let mut client = LocalClient::connect(&hosted.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            hosted.target(),
            &SessionAttachParams {
                session_id: hosted.session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .unwrap_or_else(|refusal| panic!("attaches: {refusal:?}{}", why(hosted)))
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: hosted.session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("subscribes");
    let lease: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            hosted.target(),
            &InputAcquireParams {
                session_id: hosted.session_id,
                attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("acquires")
        .to_typed()
        .expect("decodes");
    (client, attachment_id, lease.lease.epoch)
}

/// Brings the host up to the load section 27 states: twenty live shells and thirty-two views.
///
/// The sessions are idle, which is what the section says, and the views hold live connections to
/// them. They are returned so they outlive the measurement.
async fn background() -> (Vec<Hosted>, Vec<LocalClient>) {
    let started = Instant::now();
    let mut sessions = Vec::new();
    for _ in 1..BACKGROUND_SESSIONS {
        sessions.push(hosted(BACKGROUND_SHELL).await);
    }
    let mut views = Vec::new();
    for index in 0..BACKGROUND_VIEWS {
        let Some(session) = sessions.get(index % sessions.len().max(1)) else {
            break;
        };
        let mut client = LocalClient::connect(&session.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                session.target(),
                &SessionAttachParams {
                    session_id: session.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(80, 24)),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("reaches the worker")
            .unwrap_or_else(|refusal| {
                panic!(
                    "attaches, {:?} after this background began{}: {refusal:?}",
                    started.elapsed(),
                    why(session)
                )
            })
            .to_typed()
            .expect("decodes");
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        client
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: session.session_id,
                    attachment_id: attached.attachment.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("reaches the worker")
            .expect("subscribes");
        views.push(client);
    }
    (sessions, views)
}

/// Closes a session and waits for it to stop running.
///
/// Closure is a sequence - a grace period, a forced stop and a drain - so a session on its way out
/// is given time to finish going rather than reported as one this measurement left behind.
async fn close(hosted: &Hosted) -> Result<(), String> {
    let (_, gate) = hosted.runtime.close(ClosureReason::CloseRequested);
    gate.release();
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if !hosted.runtime.session().state().is_running() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("a session this measurement created is still running".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Reads everything the session has retained, which is what the application produced.
fn retained(runtime: &SessionRuntime) -> Vec<u8> {
    retained_in(&runtime.session())
}

/// Reads everything a session that is already held has retained.
fn retained_in(session: &Session) -> Vec<u8> {
    let mut seen = Vec::new();
    let mut cursor = 0_u64;
    loop {
        let page = session
            .history_page(cursor, 1024 * 1024)
            .expect("reads the retained output");
        if page.bytes.as_slice().is_empty() {
            break;
        }
        seen.extend_from_slice(page.bytes.as_slice());
        cursor = page.next_cursor.get();
    }
    seen
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Waits for `marker` in the retained output, and returns how long it took to appear.
///
/// `None` means it never did within `within`, which for a held prefix is a failure of the
/// requirement rather than of the measurement.
async fn arrival(
    runtime: &SessionRuntime,
    marker: &[u8],
    from: Instant,
    within: Duration,
) -> Option<Duration> {
    let deadline = from + within;
    loop {
        if contains(&retained(runtime), marker) {
            return Some(from.elapsed());
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The percentile of a sorted sample set, by nearest rank.
///
/// The rank is `ceil(fraction * n)`, counted from one, which is the definition that puts the
/// ninety-fifth percentile of a hundred samples on the ninety-fifth of them. Nothing is
/// interpolated: every sample here is a real measurement and an average of two of them is a figure
/// nothing recorded.
fn percentile(sorted: &[Duration], fraction: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    #[expect(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "a rank inside a sample set of a thousand is exact in both directions"
    )]
    let rank = (sorted.len() as f64 * fraction).ceil() as usize;
    sorted[rank.max(1).min(sorted.len()) - 1]
}

/// KR-PERF-001: added local ordinary-input forwarding latency.
#[test]
#[ignore = "a measurement rather than a test; scripts/performance.sh runs it"]
fn added_input_forwarding_latency() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let outcome = runtime.block_on(measure_latency());
    let (samples, closed) = outcome;
    // The measurement first, because a failure in it is the interesting one and the closure has
    // already been performed by the time either is looked at. The figure is kept before the
    // closure's outcome is, so a completed measurement is recorded whatever the closure did.
    let (samples, conditions) =
        samples.unwrap_or_else(|failure| panic!("the measurement: {failure}"));

    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    let mut lines = conditions.lines();
    lines.push(format!(
        "  measurement       {SAMPLES} single-byte writes from a client on the session's own \
         local socket, each timed to the byte arriving back at that client after the application \
         echoed it, with {BACKGROUND_SESSIONS} live shells and {BACKGROUND_VIEWS} attached views on \
         the host. That is more than section 27 asks for - it includes the application's read and \
         echo and the host's whole output path, where the section excludes the application - so it \
         is an upper bound on the added forwarding latency rather than the figure itself. The \
         terminal's render is outside it: nothing here draws."
    ));
    lines.push(format!(
        "  samples           {}: median {}, p95 {}, p99 {}, worst {}",
        samples.len(),
        milliseconds(percentile(&samples, 0.5)),
        milliseconds(p95),
        milliseconds(p99),
        milliseconds(samples.last().copied().unwrap_or_default())
    ));
    lines.push(format!(
        "  target            p95 below {} and p99 below {}",
        milliseconds(P95_BOUND),
        milliseconds(P99_BOUND)
    ));
    lines.push(format!(
        "  verdict           {}",
        if p95 < P95_BOUND && p99 < P99_BOUND {
            "the target is met on this host"
        } else {
            "the target is not met on this host"
        }
    ));
    // Before anything is asserted, so a run whose target failed keeps the figure.
    record::report(
        RECORD,
        "KR-PERF-001 added local input forwarding latency",
        &lines,
    );
    closed.unwrap_or_else(|failure| panic!("the sessions this measurement created: {failure}"));
    assert!(
        p95 < P95_BOUND,
        "the ninety-fifth percentile is within {P95_BOUND:?}: {p95:?}"
    );
    assert!(
        p99 < P99_BOUND,
        "the ninety-ninth percentile is within {P99_BOUND:?}: {p99:?}"
    );
}

/// A duration as a record gives it, in milliseconds to the microsecond.
fn milliseconds(duration: Duration) -> String {
    format!("{:.3} ms", duration.as_secs_f64() * 1000.0)
}

/// Sends the keystrokes and returns the sorted samples and the host's conditions while they were
/// taken, plus what closing the sessions did.
async fn measure_latency() -> (
    Result<(Vec<Duration>, record::Conditions), String>,
    Result<(), String>,
) {
    let (sessions, views) = background().await;
    let measured = hosted(ECHOES).await;
    let samples = latency_samples(&measured).await;
    // Everything this measurement started is closed before its figures are looked at, so a
    // failure never leaves a shell running.
    drop(views);
    let mut closed = Ok(());
    for session in std::iter::once(&measured).chain(sessions.iter()) {
        if let Err(failure) = close(session).await {
            closed = Err(failure);
        }
    }
    (samples, closed)
}

async fn latency_samples(hosted: &Hosted) -> Result<(Vec<Duration>, record::Conditions), String> {
    if arrival(
        &hosted.runtime,
        b"kr-ready.",
        Instant::now(),
        Duration::from_secs(20),
    )
    .await
    .is_none()
    {
        return Err("the root program never started reading".to_owned());
    }
    let (mut client, attachment_id, epoch) = controlling(hosted).await;
    // Everything the attachment was sent while it was joining: the screen it was drawn, and the
    // application's own opening output. The measurement starts once that has stopped arriving.
    drain(
        &mut client,
        Duration::from_millis(500),
        OPENING_OUTPUT_BOUND,
    )
    .await?;

    let window = record::Window::open();
    let mut samples = Vec::with_capacity(SAMPLES);
    for sequence in 0..SAMPLES {
        let params = InputWriteParams {
            session_id: hosted.session_id,
            attachment_id,
            epoch,
            sequence: kr_protocol::ids::InputSequence::new(sequence as u64),
            bytes: Bytes::new(b"x".to_vec()),
        };
        let encoded = kr_protocol::envelope::ParamsValue::from_typed(&params)
            .map_err(|error| format!("the request did not encode: {error}"))?;
        let request_id = kr_protocol::ids::RequestId::new(sequence as u64 + 1);
        // Written rather than asked, because the answer and the echo arrive on the same connection
        // and a call that waited for the answer would read the echo as part of waiting for it.
        let started = Instant::now();
        client
            .writer()
            .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
                request_id,
                method: Method::InputWrite.into(),
                method_version: kr_protocol::method::MethodVersion::V1,
                params: encoded,
            }))
            .await
            .map_err(|error| format!("the write did not reach the worker: {error}"))?;
        let mut keystroke = Keystroke::new(request_id);
        let (elapsed, accepted) = loop {
            if let Some(arrived) = keystroke.arrived() {
                break arrived;
            }
            let frame = tokio::time::timeout(Duration::from_secs(10), client.recv())
                .await
                .map_err(|_| keystroke.missing())?
                .map_err(|error| format!("the connection ended: {error}"))?;
            keystroke.take(frame, started.elapsed())?;
        };
        if accepted.forwarded_bytes.get() != 1 {
            return Err(format!(
                "a single ordinary byte was forwarded whole: {} forwarded, {} held",
                accepted.forwarded_bytes.get(),
                accepted.held_prefix_bytes.get()
            ));
        }
        samples.push(elapsed);
    }
    drop(client);
    let conditions = window.close();
    samples.sort_unstable();
    Ok((samples, conditions))
}

/// One keystroke's two arrivals at the client: the host's answer to the write, and the
/// application's echo of the byte as output.
///
/// The host promises no order between them. It answers `input.write` once the bytes are handed to
/// the session's writer, without waiting for them to reach the application, while the echo goes
/// through the terminal, the application and the whole output path, and the two frames are
/// written to the connection by different tasks. The answer usually wins; on a busy machine the
/// echo can be written first. Either order completes the keystroke, and the figure is the time to
/// the echo whichever came first, because the echo is what says the byte reached the application
/// and came back.
#[derive(Debug)]
struct Keystroke {
    /// The write this keystroke went as, which its answer names.
    request_id: kr_protocol::ids::RequestId,
    /// The host's answer, once it has arrived.
    answer: Option<InputWriteResult>,
    /// How long after the write the echo arrived, once it has.
    echo: Option<Duration>,
}

impl Keystroke {
    fn new(request_id: kr_protocol::ids::RequestId) -> Self {
        Self {
            request_id,
            answer: None,
            echo: None,
        }
    }

    /// Takes one frame that arrived `elapsed` after the write was sent.
    ///
    /// A refusal is a failure, and so is an answer to any other request: one keystroke is in
    /// flight at a time, so an answer that is not this write's is an answer the measurement cannot
    /// place.
    fn take(&mut self, frame: ControlFrame, elapsed: Duration) -> Result<(), String> {
        match frame {
            ControlFrame::Response(response) => {
                if response.request_id != self.request_id {
                    return Err(format!(
                        "an answer to request {} arrived while the write of request {} was in \
                         flight",
                        response.request_id, self.request_id
                    ));
                }
                let value = match response.outcome {
                    kr_protocol::envelope::Outcome::Ok(value) => value,
                    kr_protocol::envelope::Outcome::Error(error) => {
                        return Err(format!("the write was refused: {}", error.message));
                    }
                };
                self.answer = Some(
                    value
                        .to_typed::<InputWriteResult>()
                        .map_err(|error| format!("the answer did not decode: {error}"))?,
                );
            }
            ControlFrame::Notification(notification)
                if notification.event_type.as_str() == "session.output" =>
            {
                let event = notification
                    .payload
                    .to_typed::<kr_protocol::recovery::OutputEvent>()
                    .map_err(|error| format!("the output did not decode: {error}"))?;
                if self.echo.is_none() && !event.bytes.as_slice().is_empty() {
                    self.echo = Some(elapsed);
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The time to the echo and the host's answer, once both have arrived.
    fn arrived(&self) -> Option<(Duration, InputWriteResult)> {
        Some((self.echo?, self.answer.clone()?))
    }

    /// What had not arrived when the wait for it ran out.
    fn missing(&self) -> String {
        match (&self.answer, self.echo) {
            (None, None) => "neither the answer to a keystroke nor its echo arrived",
            (None, Some(_)) => "a keystroke was echoed and its write was never answered",
            (Some(_), None) => "a keystroke was answered and its echo never arrived",
            (Some(_), Some(_)) => "a keystroke that had arrived was waited for again",
        }
        .to_owned()
    }
}

/// Reads whatever this client has waiting until nothing arrives for `quiet`.
///
/// It ends with the reason in two other cases. A connection the host has closed answers every read
/// at once, with an error rather than a frame, so an error is the end of the drain rather than one
/// more thing that arrived. And frames that are still arriving after `within` are output that is
/// not going to stop, which a measurement that starts once it has stopped cannot wait out. So a
/// drain takes at most `within` and `quiet`, whatever the host does.
async fn drain(client: &mut LocalClient, quiet: Duration, within: Duration) -> Result<(), String> {
    let deadline = Instant::now() + within;
    loop {
        match tokio::time::timeout(quiet, client.recv()).await {
            Err(_) => return Ok(()),
            Ok(Err(error)) => {
                return Err(format!(
                    "the connection ended while what it had waiting was being read: {error}"
                ));
            }
            Ok(Ok(_)) if Instant::now() >= deadline => {
                return Err(format!(
                    "frames were still arriving {within:?} after the drain began, with no quiet \
                     spell of {quiet:?} between them"
                ));
            }
            Ok(Ok(_)) => {}
        }
    }
}

/// KR-PERF-002: the recogniser's deadline, per prefix length, and a split delimiter.
#[test]
#[ignore = "a measurement rather than a test; scripts/performance.sh runs it"]
fn paste_prefix_recogniser_deadline() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("a runtime");
    let (report, closed) = runtime.block_on(measure_recogniser());
    // The figure is kept before the closure's outcome is, as above.
    let report = report.unwrap_or_else(|failure| panic!("the measurement: {failure}"));

    let allowed = RECOGNISER_DEADLINE + RECOGNISER_TOLERANCE;
    let mut lines = report.conditions.lines();
    lines.push(format!(
        "  measurement       canonical bracketed paste enabled by the application, and one lone \
         prefix per measurement with no keystroke behind it. Each figure runs from the write to \
         the byte reaching the application, which the root program reports by echoing it, so it \
         includes the host's deadline, the timer's wake-up, the write, that echo and this \
         measurement's {} polling interval.",
        milliseconds(POLL)
    ));
    lines.push(format!(
        "  deadline          {}, the one this host is built with, against section 27's {}",
        milliseconds(kr_worker::input::RECOGNISER_DEADLINE),
        milliseconds(RECOGNISER_DEADLINE)
    ));
    for (what, held) in &report.holds {
        lines.push(format!(
            "  held              {}: {what}",
            milliseconds(*held)
        ));
    }
    lines.push(format!(
        "  split delimiter   recognised once, in {}, with its payload kept{}",
        milliseconds(report.split),
        if report.paste_open_after_split {
            ""
        } else {
            ", and the framer did not record the paste it opened"
        }
    ));
    lines.push(format!(
        "  bound             at least the deadline and at most {} for each hold, which allows {} \
         for the path around the deadline",
        milliseconds(allowed),
        milliseconds(RECOGNISER_TOLERANCE)
    ));
    let met = kr_worker::input::RECOGNISER_DEADLINE == RECOGNISER_DEADLINE
        && report
            .holds
            .iter()
            .all(|(_, held)| *held >= RECOGNISER_DEADLINE && *held <= allowed)
        && report.split <= allowed
        && report.paste_open_after_split;
    lines.push(format!(
        "  verdict           {}",
        if met {
            "the target is met on this host"
        } else {
            "the target is not met on this host"
        }
    ));
    // Rounds that are recorded and not asserted: where the time of a hold went, for the one that
    // takes longer than the allowance.
    lines.extend(report.recorded.lines());
    // Before anything is asserted, so a run whose target failed keeps the figure.
    record::report(
        RECORD,
        "KR-PERF-002 recogniser deadline for a held prefix",
        &lines,
    );
    // After the idle figure is kept, so that a failure to set up either measurement beside
    // journalled mutations cannot lose it. Each keeps its own figure when it succeeds, and fails
    // below.
    let beside_mutations = runtime.block_on(measure_recogniser_beside_mutations(false));
    let beside_a_disk_writer = runtime.block_on(measure_recogniser_beside_mutations(true));
    let on_its_own_connection = runtime.block_on(measure_recogniser_on_its_own_connection(false));
    let on_its_own_connection_beside_a_disk_writer =
        runtime.block_on(measure_recogniser_on_its_own_connection(true));
    closed.unwrap_or_else(|failure| panic!("the session this measurement created: {failure}"));
    // The requirement's own bound, on the deadline this host is built with. It is asserted here
    // rather than inferred from a figure, because a measurement with an allowance around it cannot
    // tell a twenty-five millisecond deadline from a thirty-five millisecond one.
    assert_eq!(
        kr_worker::input::RECOGNISER_DEADLINE,
        Duration::from_millis(25),
        "the recogniser's deadline is section 27's"
    );
    for (what, held) in &report.holds {
        assert!(
            *held <= allowed,
            "{what} was held for {held:?}, beyond the {RECOGNISER_DEADLINE:?} deadline and the \
             stated allowance around it"
        );
        assert!(
            *held >= RECOGNISER_DEADLINE,
            "{what} was forwarded in {held:?}, before its deadline: the hold is what makes a split \
             delimiter recognisable at all"
        );
    }
    assert!(
        report.split <= allowed,
        "the split delimiter took {:?} to be recognised",
        report.split
    );
    assert!(
        report.paste_open_after_split,
        "and the framer recorded the paste the delimiter opened, rather than passing its bytes \
         through without recognising them"
    );
    beside_mutations
        .unwrap_or_else(|failure| panic!("the measurement beside mutations: {failure}"))
        .assert_met(allowed);
    beside_a_disk_writer
        .unwrap_or_else(|failure| {
            panic!("the measurement beside mutations and a disk writer: {failure}")
        })
        .assert_met(allowed);
    on_its_own_connection
        .unwrap_or_else(|failure| {
            panic!("the measurement behind a mutation on its own connection: {failure}")
        })
        .assert_met(allowed);
    on_its_own_connection_beside_a_disk_writer
        .unwrap_or_else(|failure| {
            panic!(
                "the measurement behind a mutation on its own connection and a disk writer: \
                 {failure}"
            )
        })
        .assert_met(allowed);
}

/// The recogniser's holds taken while journalled mutations run beside them.
///
/// A journalled mutation commits three times to a store that makes each commit durable, and a
/// keystroke that arrives during one is held no longer than the recogniser's deadline from its
/// arrival all the same: aggregate figures cannot hide a wait for the next key. This is the
/// measurement that shows it, and it is asserted to the same bound as the holds taken alone.
struct BesideMutations {
    /// One entry per prefix of each delimiter, as in [`Recogniser`].
    holds: Vec<MutatedHold>,
    /// How long the split delimiter took to be recognised once its second half arrived.
    split: Duration,
    /// The host while the holds were taken, and how many mutations were completed beside them.
    conditions: record::Conditions,
    /// How many mutations were completed while the holds were taken.
    mutations: u64,
}

/// Where an instant on a keystroke's path fell in a mutation's hold of the session, as the worker
/// recorded the hold: how far into it, and how long the hold was.
#[derive(Clone, Copy)]
struct Within {
    into: Duration,
    of: Duration,
}

impl Within {
    fn describe(place: Option<Self>, what: &str) -> String {
        match place {
            Some(Self { into, of }) => format!(
                "{what} {} into a mutation's {} hold of the session",
                milliseconds(into),
                milliseconds(of)
            ),
            None => format!("{what} between the mutations' holds of the session"),
        }
    }
}

/// One hold taken with journalled mutations running, and where the worker's own record puts the
/// keystroke in relation to the session a mutation was holding.
struct MutatedHold {
    what: String,
    held: Duration,
    /// Where the worker took the write into its input domain.
    accepted: Option<Within>,
    /// Where the recogniser's timer took the prefix to forward it.
    forwarded: Option<Within>,
}

impl MutatedHold {
    /// Whether the keystroke met a journalled mutation holding the session, on its way in or when
    /// the timer forwarded it.
    const fn met_a_mutation(&self) -> bool {
        self.accepted.is_some() || self.forwarded.is_some()
    }
}

impl BesideMutations {
    /// Asserts the holds against the bound, after the figure has been kept.
    fn assert_met(&self, allowed: Duration) {
        assert!(
            self.mutations >= self.holds.len() as u64,
            "journalled mutations did not run beside the holds: {} completed for {} holds, so the \
             figure says nothing about a keystroke behind a mutation",
            self.mutations,
            self.holds.len()
        );
        assert!(
            self.holds.iter().any(MutatedHold::met_a_mutation),
            "no keystroke met a mutation holding the session, on its way in or at its forward, so \
             the figure says nothing about a keystroke behind a mutation"
        );
        for hold in &self.holds {
            let (what, held) = (&hold.what, &hold.held);
            assert!(
                *held <= allowed,
                "{what} was held for {held:?} with journalled mutations running beside it, beyond \
                 the {RECOGNISER_DEADLINE:?} deadline and the stated allowance around it"
            );
            assert!(
                *held >= RECOGNISER_DEADLINE,
                "{what} was forwarded in {held:?}, before its deadline"
            );
        }
        assert!(
            self.split <= allowed,
            "the split delimiter took {:?} to be recognised with journalled mutations running \
             beside it",
            self.split
        );
    }
}

/// Something that writes to the disk the measurement runs on for as long as it lives, the way a
/// process beside the worker does.
struct DiskWriter {
    stop: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

impl DiskWriter {
    fn beside(directory: &std::path::Path) -> Self {
        use std::io::Write as _;

        let stop = Arc::new(AtomicBool::new(false));
        let path = directory.join("disk-writer");
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let block = vec![0x5a_u8; 4 * 1024 * 1024];
                while !stop.load(Ordering::Acquire) {
                    if let Ok(mut file) = std::fs::File::create(&path) {
                        let _ = file.write_all(&block);
                        let _ = file.sync_all();
                    }
                }
                let _ = std::fs::remove_file(&path);
            })
        };
        Self { stop, thread }
    }

    fn stop(self) {
        self.stop.store(true, Ordering::Release);
        self.thread.join().expect("the disk writer ends");
    }
}

/// A client that attaches a terminal and detaches it again, over and over, until it is told to
/// stop. Each is a journalled mutation: accepted, marked and settled in three commits.
struct Mutating {
    stop: Arc<AtomicBool>,
    made: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

impl Mutating {
    async fn begin(hosted: &Hosted) -> Self {
        let mut client = LocalClient::connect(&hosted.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let (stop, made) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicU64::new(0)),
        );
        let (target, session_id) = (hosted.target(), hosted.session_id);
        let task = {
            let (stop, made) = (Arc::clone(&stop), Arc::clone(&made));
            tokio::spawn(async move {
                let mut requested = CanonicalSet::new();
                requested.insert(AttachmentCapability::ObserveTerminal);
                while !stop.load(Ordering::Acquire) {
                    let attached: kr_protocol::attachment::SessionAttachResult = client
                        .mutate(
                            Method::SessionAttach,
                            ActionId::new(kr_ipc::new_uuid()),
                            target.clone(),
                            &SessionAttachParams {
                                session_id,
                                mode: AttachMode::Terminal,
                                claim_geometry: false,
                                dimensions: Nullable::some(Dimensions::new(80, 24)),
                                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                                requested: requested.clone(),
                            },
                        )
                        .await
                        .map_err(|error| format!("the attach did not reach the worker: {error}"))?
                        .map_err(|refusal| format!("the attach was refused: {refusal:?}"))?
                        .to_typed()
                        .map_err(|error| format!("the attach's answer did not decode: {error}"))?;
                    made.fetch_add(1, Ordering::AcqRel);
                    client
                        .mutate(
                            Method::SessionDetach,
                            ActionId::new(kr_ipc::new_uuid()),
                            target.clone(),
                            &SessionDetachParams {
                                attachment_id: Nullable::some(attached.attachment.attachment_id),
                                line_token: Nullable::null(),
                            },
                        )
                        .await
                        .map_err(|error| format!("the detach did not reach the worker: {error}"))?
                        .map_err(|refusal| format!("the detach was refused: {refusal:?}"))?;
                    made.fetch_add(1, Ordering::AcqRel);
                }
                Ok(())
            })
        };
        Self { stop, made, task }
    }

    /// Waits until a mutation has completed, so that the next is the one under way when the caller
    /// writes: each mutation is accepted, marked and settled in turn, and the next begins as soon
    /// as the last is answered.
    async fn until_the_next_one_is_under_way(&self) -> Result<(), String> {
        let seen = self.made.load(Ordering::Acquire);
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.made.load(Ordering::Acquire) == seen {
            if Instant::now() >= deadline || self.task.is_finished() {
                return Err("the mutations beside the holds stopped".to_owned());
            }
            tokio::time::sleep(POLL).await;
        }
        Ok(())
    }

    /// Stops the mutations and returns how many were completed.
    async fn end(self) -> Result<u64, String> {
        self.stop.store(true, Ordering::Release);
        self.task
            .await
            .map_err(|error| format!("the mutations ended abnormally: {error}"))??;
        Ok(self.made.load(Ordering::Acquire))
    }
}

/// A root program that passes what it reads to a named pipe, with bracketed paste enabled.
///
/// What reached the application is read from the pipe, which touches nothing of the worker's and
/// no file system: an observation that polled the session would wait behind the mutations it is
/// measuring beside, and a file the application wrote would wait behind their syncs.
fn keeping(pipe: &std::path::Path) -> String {
    format!(
        "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat > '{}'",
        pipe.display()
    )
}

/// One read of the pipe: the instant it returned, and what it returned.
type PipeRead = (Instant, Vec<u8>);

/// What the pipe has delivered, each read with the instant it returned.
struct Receipt {
    reads: Arc<std::sync::Mutex<Vec<PipeRead>>>,
}

impl Receipt {
    /// Starts reading the pipe on a thread of its own. The root program blocks opening it until
    /// this has.
    fn start(pipe: &std::path::Path) -> Self {
        use std::io::Read as _;

        let reads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (path, kept) = (pipe.to_path_buf(), Arc::clone(&reads));
        std::thread::spawn(move || {
            let Ok(mut pipe) = std::fs::File::open(path) else {
                return;
            };
            let mut buffer = [0_u8; 4096];
            while let Ok(taken) = pipe.read(&mut buffer) {
                if taken == 0 {
                    return;
                }
                kept.lock()
                    .expect("the receipt is not poisoned")
                    .push((Instant::now(), buffer[..taken].to_vec()));
            }
        });
        Self { reads }
    }

    /// Waits until the pipe has delivered exactly `expected`, and returns how long after `from` the
    /// read that completed it returned.
    async fn arrival(&self, expected: &[u8], from: Instant, within: Duration) -> Option<Duration> {
        let deadline = from + within;
        loop {
            {
                let reads = self.reads.lock().expect("the receipt is not poisoned");
                let mut kept = Vec::new();
                for (at, bytes) in reads.iter() {
                    kept.extend_from_slice(bytes);
                    if kept == expected {
                        return Some(at.saturating_duration_since(from));
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

async fn measure_recogniser_beside_mutations(
    beside_a_disk_writer: bool,
) -> Result<BesideMutations, String> {
    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let pipe = kept.path().join("received");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "the pipe is made");
    let receipt = Receipt::start(&pipe);
    let writer = beside_a_disk_writer.then(|| DiskWriter::beside(kept.path()));
    let hosted = hosted(&keeping(&pipe)).await;
    let figures = recogniser_beside_mutations(&hosted, &receipt).await;
    let closed = close(&hosted).await;
    if let Some(writer) = writer {
        writer.stop();
    }
    // The figure is kept before anything is asserted, as the holds taken alone are, and a failure
    // is the caller's to raise once the figures of the measurements before it are kept too.
    let beside = figures?;
    let mut lines = beside.conditions.lines();
    lines.push(format!(
        "  measurement       the same holds as the section above, taken with an attach and a \
         detach looping on a second connection for the whole window, each a journalled mutation \
         that holds the session across three commits{}. A figure runs from the write to the byte \
         reaching the application, which the root program passes to a pipe the test reads, so \
         the observation waits behind nothing the mutations hold or sync. Where the write was \
         taken and where the timer forwarded it are the worker's own instants, set against the \
         spans in which a mutation held the session.",
        if beside_a_disk_writer {
            ", and a writer that writes four megabytes to the same disk and syncs them, over and over"
        } else {
            ""
        }
    ));
    for hold in &beside.holds {
        lines.push(format!(
            "  held              {}: {}; {}; {}",
            milliseconds(hold.held),
            hold.what,
            Within::describe(hold.accepted, "the write was taken"),
            Within::describe(hold.forwarded, "the timer forwarded it")
        ));
    }
    lines.push(format!(
        "  split delimiter   recognised once, in {}, and the framer recorded the paste it opened",
        milliseconds(beside.split)
    ));
    lines.push(format!(
        "  mutations         {} completed beside the {} holds; {} of them met a mutation holding \
         the session",
        beside.mutations,
        beside.holds.len(),
        beside
            .holds
            .iter()
            .filter(|hold| hold.met_a_mutation())
            .count()
    ));
    record::report(
        RECORD,
        if beside_a_disk_writer {
            "KR-PERF-002 recogniser deadline for a held prefix with journalled mutations and a disk writer running"
        } else {
            "KR-PERF-002 recogniser deadline for a held prefix with journalled mutations running"
        },
        &lines,
    );
    closed.map_err(|failure| format!("the session this measurement created: {failure}"))?;
    Ok(beside)
}

/// The place of an instant, in nanoseconds on the recorder's clock, among the spans in which a
/// mutation held the session.
fn place(spans: &[(u64, u64)], at: u64) -> Option<Within> {
    spans
        .iter()
        .find(|(from, to)| *from <= at && at <= *to)
        .map(|(from, to)| Within {
            into: Duration::from_nanos(at - from),
            of: Duration::from_nanos(to - from),
        })
}

async fn recogniser_beside_mutations(
    hosted: &Hosted,
    receipt: &Receipt,
) -> Result<BesideMutations, String> {
    if arrival(
        &hosted.runtime,
        b"kr-ready.",
        Instant::now(),
        Duration::from_secs(20),
    )
    .await
    .is_none()
    {
        return Err("the root program never started reading".to_owned());
    }
    let (mut client, attachment_id, epoch) = controlling(hosted).await;
    let trace = hosted.runtime.trace();
    trace.arm();
    let mutating = Mutating::begin(hosted).await;
    let window = record::Window::open().beside(
        "journalled mutations (an attach or a detach each)",
        Arc::clone(&mutating.made),
    );
    let mut sequence = 0_u64;
    // What was measured, and when each write began on the recorder's clock.
    let mut measured = Vec::new();
    let mut expected = Vec::new();
    for (name, delimiter) in [("start", &b"\x1b[200~"[..]), ("end", &b"\x1b[201~"[..])] {
        for length in 1..delimiter.len() {
            let prefix = &delimiter[..length];
            expected.extend_from_slice(prefix);
            mutating.until_the_next_one_is_under_way().await?;
            let started = Instant::now();
            let accepted = write(
                hosted,
                &mut client,
                attachment_id,
                epoch,
                &mut sequence,
                prefix,
            )
            .await?;
            if accepted.held_prefix_bytes.get() != length as u64 {
                return Err(format!(
                    "a prefix of {length} bytes of the {name} delimiter was not held: {} held, {} \
                     forwarded",
                    accepted.held_prefix_bytes.get(),
                    accepted.forwarded_bytes.get()
                ));
            }
            let held = receipt
                .arrival(&expected, started, RECOGNISER_DEADLINE * 8)
                .await
                .ok_or_else(|| {
                    format!(
                        "a prefix of {length} bytes of the {name} delimiter never reached the \
                         application on its own"
                    )
                })?;
            let what = if length == 1 {
                format!(
                    "a lone Escape, with journalled mutations running (the {name} delimiter's pass)"
                )
            } else {
                format!(
                    "the {name} delimiter's prefix of {length} bytes, with journalled mutations running"
                )
            };
            measured.push((what, held, trace.offset(started)));
        }
    }
    // A delimiter split across two frames, recognised once.
    write(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"\x1b[20",
    )
    .await?;
    expected.extend_from_slice(b"\x1b[20");
    let started = Instant::now();
    write(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"0~kr-payload",
    )
    .await?;
    expected.extend_from_slice(b"0~kr-payload");
    let split = receipt
        .arrival(&expected, started, RECOGNISER_DEADLINE * 8)
        .await
        .ok_or_else(|| "the split delimiter never completed".to_owned())?;
    // A prefix that had expired and was forwarded with the bytes behind it would also arrive whole,
    // and opens no paste: the framer says whether the delimiter was recognised.
    if !hosted.runtime.input().lock().paste_open() {
        return Err("the split delimiter reached the application but opened no paste".to_owned());
    }
    let conditions = window.close();
    let mutations = mutating.end().await?;
    drop(client);
    trace.disarm();
    let recording = trace.recording();
    if recording.overflowed {
        return Err("the worker's recorder filled before the measurement ended".to_owned());
    }
    // The spans in which a mutation held the session, and the instants the keystrokes were taken
    // and forwarded at, are the worker's own.
    let spans: Vec<(u64, u64)> = recording
        .events
        .iter()
        .filter(|event| event.site == Site::Mutation)
        .map(|event| (event.held, event.released))
        .collect();
    let holds = measured
        .into_iter()
        .map(|(what, held, began)| {
            let taken = recording
                .events
                .iter()
                .filter(|event| event.site == Site::InputAcceptance && event.held >= began)
                .map(|event| event.held)
                .min();
            let forwarded = taken.and_then(|taken| {
                recording
                    .events
                    .iter()
                    .filter(|event| event.site == Site::TimerForward && event.held >= taken)
                    .map(|event| event.held)
                    .min()
            });
            MutatedHold {
                what,
                held,
                accepted: taken.and_then(|at| place(&spans, at)),
                forwarded: forwarded.and_then(|at| place(&spans, at)),
            }
        })
        .collect();
    Ok(BesideMutations {
        holds,
        split,
        conditions,
        mutations,
    })
}

/// The holds taken again with the journalled mutation on the keystroke's own connection.
///
/// A client sends its keys and its viewport reports and resizes on one connection, so a key can
/// follow a mutation of its own. Before each hold the connection sends a viewport report, a
/// journalled mutation, and writes the prefix right behind it without waiting for the answer. What
/// the worker did with the key is read from the order the two answers came back in, and from where
/// its own record puts the key's acceptance against the hold of the session of the report it
/// followed.
struct OnItsOwnConnection {
    holds: Vec<OwnHold>,
    /// How long the split delimiter took to be recognised once its second half arrived.
    split: Duration,
    conditions: record::Conditions,
    /// How many viewport reports the connection sent and had answered.
    viewports: u64,
}

/// One hold taken behind a viewport report on the same connection.
struct OwnHold {
    what: String,
    held: Duration,
    /// The key was answered before the viewport report it followed.
    answered_first: bool,
    /// Where the worker took the write into its input domain, against the report's own hold of the
    /// session.
    accepted: AgainstReport,
}

/// Where an instant on a key's path fell against the session hold of the report sent just ahead of
/// it on the same connection.
#[derive(Clone, Copy)]
enum AgainstReport {
    /// Before the report took the session: the key did not wait for the report's commits to begin.
    Before,
    /// While the report held the session.
    During(Within),
    /// After the report had released the session.
    After(Duration),
    /// The report's hold was not recorded.
    Unrecorded,
}

impl AgainstReport {
    /// Places `at`, in nanoseconds on the recorder's clock, against the first hold of the session
    /// that began after `sent_at`, which is the report's: nothing else mutates in this measurement,
    /// and the caller has checked that each report left one hold.
    fn of(spans: &[(u64, u64)], sent_at: u64, at: Option<u64>) -> Self {
        let Some(at) = at else {
            return Self::Unrecorded;
        };
        let Some((from, to)) = spans
            .iter()
            .filter(|(from, _)| *from >= sent_at)
            .min_by_key(|(from, _)| *from)
            .copied()
        else {
            return Self::Unrecorded;
        };
        if at < from {
            Self::Before
        } else if at <= to {
            Self::During(Within {
                into: Duration::from_nanos(at - from),
                of: Duration::from_nanos(to - from),
            })
        } else {
            Self::After(Duration::from_nanos(at - to))
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Before => "the write was taken before its report took the session".to_owned(),
            Self::During(Within { into, of }) => format!(
                "the write was taken {} into its report's {} hold of the session",
                milliseconds(into),
                milliseconds(of)
            ),
            Self::After(after) => format!(
                "the write was taken {} after its report released the session",
                milliseconds(after)
            ),
            Self::Unrecorded => {
                "the write's acceptance or its report's hold of the session was not recorded"
                    .to_owned()
            }
        }
    }
}

impl OnItsOwnConnection {
    /// Asserts the holds against the bound, after the figure has been kept.
    fn assert_met(&self, allowed: Duration) {
        assert!(
            self.holds.iter().any(|hold| hold.answered_first),
            "no key was answered before the mutation sent just ahead of it on its connection, so \
             the figure says nothing about a key behind a mutation of its own connection"
        );
        for hold in &self.holds {
            let (what, held) = (&hold.what, &hold.held);
            assert!(
                *held <= allowed,
                "{what} was held for {held:?} behind a mutation on its own connection, beyond the \
                 {RECOGNISER_DEADLINE:?} deadline and the stated allowance around it"
            );
            assert!(
                *held >= RECOGNISER_DEADLINE,
                "{what} was forwarded in {held:?}, before its deadline"
            );
        }
        assert!(
            self.split <= allowed,
            "the split delimiter took {:?} to be recognised behind a mutation on its own connection",
            self.split
        );
    }
}

/// What a connection has been answered, by request identifier, and in which order.
#[derive(Default)]
struct Answers {
    outcomes:
        std::collections::BTreeMap<kr_protocol::ids::RequestId, kr_protocol::envelope::Outcome>,
    order: Vec<kr_protocol::ids::RequestId>,
}

impl Answers {
    /// Reads `client` until `id` has been answered.
    async fn until(
        &mut self,
        client: &mut LocalClient,
        id: kr_protocol::ids::RequestId,
    ) -> Result<kr_protocol::envelope::Outcome, String> {
        while !self.outcomes.contains_key(&id) {
            let frame = tokio::time::timeout(Duration::from_secs(30), client.recv())
                .await
                .map_err(|_| "an answer never came".to_owned())?
                .map_err(|error| format!("the connection could not be read: {error}"))?;
            if let ControlFrame::Response(response) = frame {
                self.order.push(response.request_id);
                self.outcomes.insert(response.request_id, response.outcome);
            }
        }
        Ok(self.outcomes[&id].clone())
    }
}

/// Where this measurement's own raw requests begin numbering, apart from the identifiers the
/// client gives the calls it makes itself.
const OWN_REQUESTS: u64 = 1_000_000;

/// Sends a viewport report at the attachment's own size, which changes nothing and is journalled
/// like any mutation, without waiting for its answer.
async fn send_viewport(
    hosted: &Hosted,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
) -> Result<kr_protocol::ids::RequestId, String> {
    let mutation = client
        .compose(
            Method::AttachmentViewport,
            ActionId::new(kr_ipc::new_uuid()),
            hosted.target(),
            &kr_protocol::attachment::AttachmentViewportParams {
                attachment_id,
                dimensions: Dimensions::new(80, 24),
                position: Nullable::null(),
                column: kr_protocol::scalars::U64::new(0),
            },
        )
        .await
        .map_err(|error| format!("the viewport report could not be built: {error}"))?;
    let id = mutation.request_id;
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .map_err(|error| format!("the viewport report did not reach the worker: {error}"))?;
    Ok(id)
}

/// Sends one `input.write` without waiting for its answer.
async fn send_key(
    hosted: &Hosted,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: &mut u64,
    bytes: &[u8],
) -> Result<kr_protocol::ids::RequestId, String> {
    let id = kr_protocol::ids::RequestId::new(OWN_REQUESTS + *sequence);
    let params = kr_protocol::envelope::ParamsValue::from_typed(&InputWriteParams {
        session_id: hosted.session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(*sequence),
        bytes: Bytes::new(bytes.to_vec()),
    })
    .map_err(|error| format!("the write could not be encoded: {error}"))?;
    *sequence += 1;
    client
        .writer()
        .write_message(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: id,
            method: Method::InputWrite.into(),
            method_version: kr_protocol::method::MethodVersion::V1,
            params,
        }))
        .await
        .map_err(|error| format!("the write did not reach the worker: {error}"))?;
    Ok(id)
}

/// Reads the answers to a viewport report and the key sent behind it, and returns the key's result
/// and whether it was answered first.
async fn both_answered(
    client: &mut LocalClient,
    answers: &mut Answers,
    viewport: kr_protocol::ids::RequestId,
    key: kr_protocol::ids::RequestId,
) -> Result<(InputWriteResult, bool), String> {
    let viewed = answers.until(client, viewport).await?;
    let typed = answers.until(client, key).await?;
    if let kr_protocol::envelope::Outcome::Error(error) = viewed {
        return Err(format!(
            "the viewport report was refused: {}",
            error.message
        ));
    }
    let kr_protocol::envelope::Outcome::Ok(value) = typed else {
        return Err("the key was refused".to_owned());
    };
    let result = value
        .to_typed()
        .map_err(|error| format!("the answer did not decode: {error}"))?;
    let position = |id| answers.order.iter().position(|seen| *seen == id);
    Ok((result, position(key) < position(viewport)))
}

async fn measure_recogniser_on_its_own_connection(
    beside_a_disk_writer: bool,
) -> Result<OnItsOwnConnection, String> {
    let kept = tempfile::tempdir().expect("a directory for what the application keeps");
    let pipe = kept.path().join("received");
    let made = std::process::Command::new("mkfifo")
        .arg(&pipe)
        .status()
        .expect("mkfifo runs");
    assert!(made.success(), "the pipe is made");
    let receipt = Receipt::start(&pipe);
    let writer = beside_a_disk_writer.then(|| DiskWriter::beside(kept.path()));
    let hosted = hosted(&keeping(&pipe)).await;
    let figures = recogniser_on_its_own_connection(&hosted, &receipt).await;
    let closed = close(&hosted).await;
    if let Some(writer) = writer {
        writer.stop();
    }
    // The figure is kept before anything is asserted, as the others are.
    let own = figures?;
    let mut lines = own.conditions.lines();
    lines.push(format!(
        "  measurement       the same holds as the section above, each taken right behind a \
         viewport report, a journalled mutation that holds the session across three commits, sent \
         on the same connection and not waited for{}. A figure runs from the write to the byte \
         reaching the application, which the root program passes to a pipe the test reads. \
         Whether the key was answered before the report it followed is read from the order the two \
         answers came back in; where the worker took the write is its own instant, set against the \
         hold of the session of the report sent just ahead of the key.",
        if beside_a_disk_writer {
            ", and a writer that writes four megabytes to the same disk and syncs them, over and over"
        } else {
            ""
        }
    ));
    for hold in &own.holds {
        lines.push(format!(
            "  held              {}: {}; the key was answered {} the report; {}",
            milliseconds(hold.held),
            hold.what,
            if hold.answered_first {
                "before"
            } else {
                "after"
            },
            hold.accepted.describe()
        ));
    }
    lines.push(format!(
        "  split delimiter   recognised once, in {}, and the framer recorded the paste it opened",
        milliseconds(own.split)
    ));
    lines.push(format!(
        "  viewport reports  {} sent and answered beside the {} holds; the key was answered \
         before the report in {} of them, and taken before the report took the session in {}, \
         while it held it in {} and after it released it in {}",
        own.viewports,
        own.holds.len(),
        own.holds.iter().filter(|hold| hold.answered_first).count(),
        own.holds
            .iter()
            .filter(|hold| matches!(hold.accepted, AgainstReport::Before))
            .count(),
        own.holds
            .iter()
            .filter(|hold| matches!(hold.accepted, AgainstReport::During(_)))
            .count(),
        own.holds
            .iter()
            .filter(|hold| matches!(hold.accepted, AgainstReport::After(_)))
            .count()
    ));
    record::report(
        RECORD,
        if beside_a_disk_writer {
            "KR-PERF-002 recogniser deadline for a held prefix behind a mutation on its own connection and a disk writer running"
        } else {
            "KR-PERF-002 recogniser deadline for a held prefix behind a mutation on its own connection"
        },
        &lines,
    );
    closed.map_err(|failure| format!("the session this measurement created: {failure}"))?;
    Ok(own)
}

async fn recogniser_on_its_own_connection(
    hosted: &Hosted,
    receipt: &Receipt,
) -> Result<OnItsOwnConnection, String> {
    if arrival(
        &hosted.runtime,
        b"kr-ready.",
        Instant::now(),
        Duration::from_secs(20),
    )
    .await
    .is_none()
    {
        return Err("the root program never started reading".to_owned());
    }
    let (mut client, attachment_id, epoch) = controlling(hosted).await;
    let trace = hosted.runtime.trace();
    trace.arm();
    let viewports = Arc::new(AtomicU64::new(0));
    let window = record::Window::open().beside(
        "viewport reports (a journalled mutation each) on the keystroke's own connection",
        Arc::clone(&viewports),
    );
    let mut sequence = 0_u64;
    let mut answers = Answers::default();
    let mut measured = Vec::new();
    let mut expected = Vec::new();
    for (name, delimiter) in [("start", &b"\x1b[200~"[..]), ("end", &b"\x1b[201~"[..])] {
        for length in 1..delimiter.len() {
            let prefix = &delimiter[..length];
            expected.extend_from_slice(prefix);
            let before_report = Instant::now();
            let viewport = send_viewport(hosted, &mut client, attachment_id).await?;
            let started = Instant::now();
            let key = send_key(
                hosted,
                &mut client,
                attachment_id,
                epoch,
                &mut sequence,
                prefix,
            )
            .await?;
            let held = receipt
                .arrival(&expected, started, RECOGNISER_DEADLINE * 8)
                .await
                .ok_or_else(|| {
                    format!(
                        "a prefix of {length} bytes of the {name} delimiter never reached the \
                         application on its own"
                    )
                })?;
            let (accepted, answered_first) =
                both_answered(&mut client, &mut answers, viewport, key).await?;
            viewports.fetch_add(1, Ordering::AcqRel);
            if accepted.held_prefix_bytes.get() != length as u64 {
                return Err(format!(
                    "a prefix of {length} bytes of the {name} delimiter was not held: {} held, {} \
                     forwarded",
                    accepted.held_prefix_bytes.get(),
                    accepted.forwarded_bytes.get()
                ));
            }
            let what = if length == 1 {
                format!("a lone Escape, behind a viewport report (the {name} delimiter's pass)")
            } else {
                format!("the {name} delimiter's prefix of {length} bytes, behind a viewport report")
            };
            measured.push((
                what,
                held,
                answered_first,
                trace.offset(before_report),
                trace.offset(started),
            ));
        }
    }
    // A delimiter split across two frames, recognised once, the second half behind a report too.
    let first = send_key(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"\x1b[20",
    )
    .await?;
    answers.until(&mut client, first).await?;
    expected.extend_from_slice(b"\x1b[20");
    let viewport = send_viewport(hosted, &mut client, attachment_id).await?;
    let started = Instant::now();
    let second = send_key(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"0~kr-payload",
    )
    .await?;
    expected.extend_from_slice(b"0~kr-payload");
    let split = receipt
        .arrival(&expected, started, RECOGNISER_DEADLINE * 8)
        .await
        .ok_or_else(|| "the split delimiter never completed".to_owned())?;
    both_answered(&mut client, &mut answers, viewport, second).await?;
    viewports.fetch_add(1, Ordering::AcqRel);
    if !hosted.runtime.input().lock().paste_open() {
        return Err("the split delimiter reached the application but opened no paste".to_owned());
    }
    let conditions = window.close();
    let reports = viewports.load(Ordering::Acquire);
    drop(client);
    trace.disarm();
    let recording = trace.recording();
    if recording.overflowed {
        return Err("the worker's recorder filled before the measurement ended".to_owned());
    }
    let spans: Vec<(u64, u64)> = recording
        .events
        .iter()
        .filter(|event| event.site == Site::Mutation)
        .map(|event| (event.held, event.released))
        .collect();
    // Each report leaves one hold of the session, which is what places a key against its own.
    if spans.len() as u64 != reports {
        return Err(format!(
            "the worker recorded {} holds of the session by a mutation for {reports} viewport \
             reports",
            spans.len()
        ));
    }
    let holds = measured
        .into_iter()
        .map(|(what, held, answered_first, sent_at, began)| {
            let taken = recording
                .events
                .iter()
                .filter(|event| event.site == Site::InputAcceptance && event.held >= began)
                .map(|event| event.held)
                .min();
            OwnHold {
                what,
                held,
                answered_first,
                accepted: AgainstReport::of(&spans, sent_at, taken),
            }
        })
        .collect();
    Ok(OnItsOwnConnection {
        holds,
        split,
        conditions,
        viewports: reports,
    })
}

struct Recogniser {
    /// One entry per prefix of each delimiter, plus the lone Escape, each measured on its own.
    holds: Vec<(String, Duration)>,
    /// How long the split delimiter took to be recognised once its second half arrived.
    split: Duration,
    /// Whether the framer recorded the paste that delimiter opened.
    paste_open_after_split: bool,
    /// The host while the prefixes were measured.
    conditions: record::Conditions,
    /// The rounds taken after them, which are recorded and not asserted.
    recorded: recorded::Recorded,
}

async fn measure_recogniser() -> (Result<Recogniser, String>, Result<(), String>) {
    let hosted = hosted(ECHOES_BRACKETED).await;
    let report = recogniser_samples(&hosted).await;
    let closed = close(&hosted).await;
    (report, closed)
}

async fn recogniser_samples(hosted: &Hosted) -> Result<Recogniser, String> {
    if arrival(
        &hosted.runtime,
        b"kr-ready.",
        Instant::now(),
        Duration::from_secs(20),
    )
    .await
    .is_none()
    {
        return Err("the root program never started reading".to_owned());
    }
    let (mut client, attachment_id, epoch) = controlling(hosted).await;
    let window = record::Window::open();
    let mut sequence = 0_u64;
    let mut holds = Vec::new();

    // Every proper prefix of both delimiters, each one alone, and each one measured to the moment
    // it reaches the application. A lone Escape is the shortest of them, and it is the case the
    // requirement names outright: it must never wait for another keystroke. The two delimiters
    // share their first four bytes and differ at the fifth, so the end delimiter's own prefixes are
    // measured rather than assumed to behave like the start's.
    for (name, delimiter) in [("start", &b"\x1b[200~"[..]), ("end", &b"\x1b[201~"[..])] {
        for length in 1..delimiter.len() {
            let prefix = &delimiter[..length];
            // A marker before the prefix, so what is waited for is this prefix rather than an
            // earlier one. It is an ordinary byte and is forwarded at once.
            let marker = format!("<{name}{length}>");
            write(
                hosted,
                &mut client,
                attachment_id,
                epoch,
                &mut sequence,
                marker.as_bytes(),
            )
            .await?;
            let mut expected = marker.clone().into_bytes();
            expected.extend_from_slice(prefix);
            let started = Instant::now();
            let accepted = write(
                hosted,
                &mut client,
                attachment_id,
                epoch,
                &mut sequence,
                prefix,
            )
            .await?;
            if accepted.held_prefix_bytes.get() != length as u64 {
                return Err(format!(
                    "a prefix of {length} bytes of the {name} delimiter was held: {} held, {} \
                     forwarded",
                    accepted.held_prefix_bytes.get(),
                    accepted.forwarded_bytes.get()
                ));
            }
            let held = arrival(&hosted.runtime, &expected, started, RECOGNISER_DEADLINE * 8)
                .await
                .ok_or_else(|| {
                    format!(
                        "a prefix of {length} bytes of the {name} delimiter never reached the \
                         application on its own"
                    )
                })?;
            let what = if length == 1 {
                format!("a lone Escape, with no keystroke behind it (the {name} delimiter's pass)")
            } else {
                format!(
                    "the {name} delimiter's prefix of {length} bytes, with no keystroke behind it"
                )
            };
            holds.push((what, held));
        }
    }

    // A delimiter split across two frames: recognised once, with the payload behind it kept.
    let marker = b"<split>";
    write(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        marker,
    )
    .await?;
    write(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"\x1b[20",
    )
    .await?;
    let started = Instant::now();
    write(
        hosted,
        &mut client,
        attachment_id,
        epoch,
        &mut sequence,
        b"0~kr-payload",
    )
    .await?;
    let split = arrival(
        &hosted.runtime,
        b"\x1b[200~kr-payload",
        started,
        RECOGNISER_DEADLINE * 8,
    )
    .await
    .ok_or_else(|| "the split delimiter never completed".to_owned())?;
    let seen = retained(&hosted.runtime);
    if count(&seen, b"\x1b[200~") != 1 {
        return Err(format!(
            "the completed delimiter was emitted exactly once: {} times",
            count(&seen, b"\x1b[200~")
        ));
    }
    // What the framer made of it, rather than only what the application received: a path that
    // forwarded the same bytes without recognising them would look identical in the output.
    let paste_open_after_split = hosted.runtime.session().paste_open();
    let conditions = window.close();
    let recorded =
        recorded::record_rounds(hosted, &mut client, attachment_id, epoch, &mut sequence).await;
    drop(client);
    Ok(Recogniser {
        holds,
        split,
        paste_open_after_split,
        conditions,
        recorded,
    })
}

async fn write(
    hosted: &Hosted,
    client: &mut LocalClient,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: &mut u64,
    bytes: &[u8],
) -> Result<InputWriteResult, String> {
    let params = InputWriteParams {
        session_id: hosted.session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(*sequence),
        bytes: Bytes::new(bytes.to_vec()),
    };
    *sequence += 1;
    let outcome = client
        .request(Method::InputWrite, &params)
        .await
        .map_err(|error| format!("the write did not reach the worker: {error}"))?;
    outcome
        .map_err(|error| format!("the write was refused: {}", error.message))?
        .to_typed()
        .map_err(|error| format!("the answer did not decode: {error}"))
}

/// The percentile helper, checked against a set whose answers are known by hand.
#[test]
fn a_percentile_is_the_rank_it_claims_to_be() {
    let sorted: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();
    assert_eq!(percentile(&sorted, 0.5), Duration::from_millis(50));
    assert_eq!(percentile(&sorted, 0.95), Duration::from_millis(95));
    assert_eq!(percentile(&sorted, 0.99), Duration::from_millis(99));
    assert_eq!(
        percentile(&sorted, 0.0),
        Duration::from_millis(1),
        "and a fraction of zero is the smallest sample rather than nothing"
    );
    assert_eq!(percentile(&sorted, 1.0), Duration::from_millis(100));
    assert_eq!(percentile(&[], 0.95), Duration::ZERO);
    assert_eq!(
        percentile(&[Duration::from_millis(7)], 0.99),
        Duration::from_millis(7)
    );
}

/// The host's answer to the write of request `request`, which forwarded one byte.
fn answer_to(request: u64) -> ControlFrame {
    ControlFrame::Response(kr_protocol::envelope::Response {
        request_id: kr_protocol::ids::RequestId::new(request),
        outcome: kr_protocol::envelope::Outcome::Ok(
            kr_protocol::envelope::ParamsValue::from_typed(&InputWriteResult {
                sequence: kr_protocol::ids::InputSequence::new(request - 1),
                forwarded_bytes: kr_protocol::scalars::U64::new(1),
                held_prefix_bytes: kr_protocol::scalars::U64::new(0),
            })
            .expect("the answer encodes"),
        ),
    })
}

/// The output the application's echo reaches the client as.
fn output_of(bytes: &[u8]) -> ControlFrame {
    ControlFrame::Notification(kr_protocol::envelope::Notification {
        stream_id: kr_protocol::ids::StreamId::new("output").expect("a stream name"),
        sequence: kr_protocol::ids::EventSequence::new(1),
        event_type: kr_protocol::ids::EventType::new("session.output").expect("an event type"),
        payload: kr_protocol::envelope::ParamsValue::from_typed(
            &kr_protocol::recovery::OutputEvent {
                cursor: kr_protocol::scalars::U64::new(0),
                bytes: Bytes::new(bytes.to_vec()),
            },
        )
        .expect("the output encodes"),
    })
}

/// A keystroke is complete once both its answer and its echo have arrived, in either order, and
/// its figure is the time to the echo.
///
/// The host answers a write without waiting for the byte to reach the application, and the echo
/// travels the output path on its own, so on a busy machine the echo can reach the client first.
/// That is a keystroke like any other rather than a sample that failed.
#[test]
fn a_keystroke_is_its_answer_and_its_echo_in_either_order() {
    let millis = Duration::from_millis;
    let request = kr_protocol::ids::RequestId::new(7);

    let mut keystroke = Keystroke::new(request);
    keystroke
        .take(answer_to(7), millis(1))
        .expect("the answer is taken");
    assert_eq!(keystroke.arrived(), None, "the echo is still owed");
    keystroke
        .take(output_of(b"x"), millis(2))
        .expect("the echo is taken");
    let (elapsed, accepted) = keystroke.arrived().expect("both have arrived");
    assert_eq!(elapsed, millis(2));
    assert_eq!(accepted.forwarded_bytes.get(), 1);

    let mut keystroke = Keystroke::new(request);
    keystroke
        .take(output_of(b"x"), millis(1))
        .expect("an echo that arrives before the answer is taken");
    assert_eq!(keystroke.arrived(), None, "the answer is still owed");
    keystroke
        .take(answer_to(7), millis(3))
        .expect("the answer is taken");
    let (elapsed, accepted) = keystroke.arrived().expect("both have arrived");
    assert_eq!(
        elapsed,
        millis(1),
        "the figure is the time to the echo, not to the answer after it"
    );
    assert_eq!(accepted.forwarded_bytes.get(), 1);
}

/// What does not complete a keystroke: an empty batch of output is not its echo, and an answer to
/// another write or a refusal fails the sample.
#[test]
fn a_keystroke_is_not_completed_by_an_empty_batch_or_by_another_writes_answer() {
    let millis = Duration::from_millis;
    let request = kr_protocol::ids::RequestId::new(7);

    let mut keystroke = Keystroke::new(request);
    keystroke
        .take(output_of(b""), millis(1))
        .expect("an empty batch is taken");
    keystroke
        .take(answer_to(7), millis(2))
        .expect("the answer is taken");
    assert_eq!(keystroke.arrived(), None, "an empty batch is not the echo");
    assert_eq!(
        keystroke.missing(),
        "a keystroke was answered and its echo never arrived"
    );

    let failure = Keystroke::new(request)
        .take(answer_to(6), millis(1))
        .expect_err("an answer to another write is not this one's");
    assert!(failure.contains("request 6"), "{failure}");

    let refused = ControlFrame::Response(kr_protocol::envelope::Response {
        request_id: request,
        outcome: kr_protocol::envelope::Outcome::Error(kr_protocol::error::ProtocolError::new(
            kr_protocol::error::ErrorCode::LeaseLost,
            "the lease moved",
        )),
    });
    let failure = Keystroke::new(request)
        .take(refused, millis(1))
        .expect_err("a refused write fails the sample");
    assert_eq!(failure, "the write was refused: the lease moved");
}

/// Both measurements need a root program that echoes, because the echo is what says the byte
/// reached the application, and they need the terminal in raw mode with its own echo off, because
/// otherwise the line discipline answers first and the figure is the kernel's rather than the
/// host's. The recogniser measurement additionally needs the application to have enabled canonical
/// bracketed paste, which is the only thing that makes the host track framing at all.
#[test]
fn both_measurements_use_a_root_program_that_reports_what_it_received() {
    for program in [ECHOES, ECHOES_BRACKETED] {
        assert!(program.contains("stty raw -echo"), "{program}");
        assert!(program.contains("exec cat"), "{program}");
    }
    assert!(ECHOES_BRACKETED.contains("2004h"));
    assert!(!ECHOES.contains("2004h"));
}

/// What a scripted host does once it has answered a client's opening frame.
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
enum Afterwards {
    /// It closes the connection, as a worker that is going away does.
    Closes,
    /// It sends a frame every few milliseconds for as long as the connection lasts.
    NeverGoesQuiet,
}

/// A client on a real local endpoint whose host answers the opening frame and then does
/// `afterwards`, with the tree the endpoint lives in and the task that serves it.
#[cfg(unix)]
async fn scripted(
    afterwards: Afterwards,
) -> (
    kr_ipc::testing::TempHost,
    tokio::task::JoinHandle<()>,
    LocalClient,
) {
    use kr_protocol::hello::{ActionWindow, ReceiveLimits};
    use kr_protocol::ids::{ActionWindowId, BootEpoch, ConnectionId};
    use kr_protocol::local::{LocalHelloAck, LocalPeer, LocalRole};
    use kr_protocol::scalars::{DurationMs, TimestampMs, U64};

    let tree = kr_ipc::testing::TempHost::create();
    let endpoint = tree
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let environment_id = tree.environment_id();
    let serving = tokio::spawn(async move {
        let Ok((connection, peer)) = listener.accept().await else {
            return;
        };
        let (mut reader, mut writer) =
            kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
        let Ok(ControlFrame::Hello(_)) = reader.read_message::<ControlFrame>().await else {
            return;
        };
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        let acknowledgement = LocalHelloAck {
            selected_version: PROTOCOL_VERSION,
            role: LocalRole::Worker,
            connection_id,
            environment_id,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            peer: LocalPeer {
                uid: U64::new(u64::from(peer.uid)),
                gid: U64::new(u64::from(peer.gid)),
                pid: Nullable::null(),
            },
            action_window: ActionWindow {
                action_window_id: ActionWindowId::new("window-1").expect("a window identifier"),
                connection_id,
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(0),
                valid_for_ms: DurationMs::new(60_000),
            },
            capabilities: CanonicalSet::new(),
            max_receive: ReceiveLimits::default(),
            build: None,
        };
        if writer
            .write_message(&ControlFrame::HelloAck(Box::new(acknowledgement)))
            .await
            .is_err()
        {
            return;
        }
        match afterwards {
            // Both halves go when this task ends, and the connection with them.
            Afterwards::Closes => {}
            Afterwards::NeverGoesQuiet => loop {
                if writer.write_message(&output_of(b"x")).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            },
        }
    });
    let client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("the host answers the opening frame");
    (tree, serving, client)
}

/// Drains a client of a scripted host on a thread of its own, and returns what the drain came to
/// and how long it took, or `None` when it had not ended within `bound`.
///
/// A drain that never ends never gives its thread back either, so it is not run on the thread
/// that is waiting for it.
#[cfg(unix)]
fn drained_within(
    bound: Duration,
    afterwards: Afterwards,
    quiet: Duration,
    within: Duration,
) -> Option<(Result<(), String>, Duration)> {
    let (finished, outcome) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        let drained = runtime.block_on(async {
            let (_tree, serving, mut client) = scripted(afterwards).await;
            let started = Instant::now();
            let drained = drain(&mut client, quiet, within).await;
            let took = started.elapsed();
            serving.abort();
            (drained, took)
        });
        let _ = finished.send(drained);
    });
    outcome.recv_timeout(bound).ok()
}

/// A drain of a connection the host has closed ends, and says the connection ended, rather than
/// reading the closed connection's error as one more frame for ever.
#[cfg(unix)]
#[test]
fn draining_a_connection_the_host_closed_ends_and_says_so() {
    let (drained, _) = drained_within(
        Duration::from_secs(10),
        Afterwards::Closes,
        Duration::from_millis(200),
        Duration::from_secs(5),
    )
    .expect("the drain of a closed connection ends");
    let failure = drained.expect_err("a closed connection is not a quiet one");
    assert!(
        failure.starts_with("the connection ended"),
        "the drain says why it ended: {failure}"
    );
}

/// A drain of a connection whose frames never stop ends at its bound, and says so.
#[cfg(unix)]
#[test]
fn draining_a_connection_that_never_goes_quiet_ends_at_its_bound() {
    let within = Duration::from_millis(600);
    let quiet = Duration::from_millis(200);
    // What the drain may take past its own bound: the last wait for a frame, which is at most
    // `quiet`, and the scheduler's delay in waking it, which is allowed a generous second here.
    let allowance = quiet + Duration::from_secs(1);
    let (drained, took) = drained_within(
        Duration::from_secs(10),
        Afterwards::NeverGoesQuiet,
        quiet,
        within,
    )
    .expect("the drain of a connection that never goes quiet ends");
    let failure = drained.expect_err("output that never stops is not a quiet connection");
    assert!(
        failure.starts_with("frames were still arriving"),
        "the drain says why it ended: {failure}"
    );
    assert!(
        took >= within,
        "the drain gave up after {took:?}, before its bound of {within:?}"
    );
    assert!(
        took <= within + allowance,
        "the drain took {took:?}, past its bound of {within:?} and the {allowance:?} allowed \
         around it"
    );
}
