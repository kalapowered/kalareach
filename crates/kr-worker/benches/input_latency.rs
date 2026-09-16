//! What the host adds to a keystroke, and how long it holds an ambiguous one.
//!
//! These are measurements rather than unit tests, so they are ignored by default and
//! `scripts/performance.sh` runs them in a release build. Each one prints the conditions it was
//! taken under, because a latency figure without them is not evidence.
//!
//! # What is being measured, and what is deliberately not
//!
//! The path is the one `kr attach` uses: a client writes `input.write` on the session's own local
//! socket, and the host answers after the bytes have been written into the pseudo-terminal. The
//! response is the end of the measurement because the host encodes it only once the write has
//! happened, so the figure is the host's own added latency.
//!
//! What is outside it is what section 27 puts outside it: the application's own read and whatever
//! it then does, and the physical terminal's render. Waiting for the application to answer would
//! measure the application.
//!
//! The recogniser measurement is the other way round, and has to be. What it measures is a *wait*
//! the host imposes deliberately, so it runs to the point where the held byte reaches the
//! application, which the root program reports by echoing it back.

use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
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
const RECOGNISER_TOLERANCE: Duration = Duration::from_millis(15);

/// How many keystrokes the latency measurement sends.
const SAMPLES: usize = 1_000;

/// How many live shells section 27 puts on the host while a measurement runs.
const BACKGROUND_SESSIONS: usize = 20;

/// How many attached views it puts on them.
const BACKGROUND_VIEWS: usize = 32;

/// How often the recogniser measurement looks for the held byte.
const POLL: Duration = Duration::from_micros(250);

/// A root program that echoes what it reads, with the terminal in raw mode.
const ECHOES: &str = "stty raw -echo; printf 'kr-ready.'; exec cat";

/// The same, with canonical bracketed paste enabled by the application.
const ECHOES_BRACKETED: &str = "stty raw -echo; printf '\\033[?2004hkr-ready.'; exec cat";

/// A root program that reads its input and keeps nothing, so the terminal never fills.
const DRAINS: &str = "stty raw -echo; printf 'kr-ready.'; exec cat > /dev/null";

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
    let store = kr_crypto::store::open_store("KalaReachInputLatency", &environment.secrets_dir())
        .expect("a secret store");
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
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
    };
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(SessionRuntime::start(session).expect("starts the runtime"));

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
        .expect("attaches")
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
    let mut sessions = Vec::new();
    for _ in 1..BACKGROUND_SESSIONS {
        sessions.push(hosted("sleep 600").await);
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
            .expect("attaches")
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
    let session = runtime.session();
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

fn load_average() -> String {
    std::process::Command::new("sh")
        .args([
            "-c",
            "sysctl -n vm.loadavg 2>/dev/null | tr -d '{}' || cut -d' ' -f1-3 /proc/loadavg",
        ])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|text| text.trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn processors() -> String {
    std::thread::available_parallelism()
        .map(|count| count.to_string())
        .unwrap_or_else(|_| "unknown".to_owned())
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
    // already been performed by the time either is looked at.
    let samples = samples.unwrap_or_else(|failure| panic!("the measurement: {failure}"));
    closed.unwrap_or_else(|failure| panic!("the sessions this measurement created: {failure}"));

    let p95 = percentile(&samples, 0.95);
    let p99 = percentile(&samples, 0.99);
    println!("KR-PERF-001 measurement");
    println!(
        "  conditions: a release build on a host of {} logical processors, with \
         {BACKGROUND_SESSIONS} live shells and {BACKGROUND_VIEWS} attached views; {SAMPLES} \
         single-byte writes from a client on the session's own local socket, each measured to the \
         host's answer, which it sends only after the byte has been written into the \
         pseudo-terminal. The application's own read and the terminal's render are excluded, as \
         section 27 excludes them.",
        processors()
    );
    println!(
        "  load average at the end: {}. Section 27 asks for a quiet reference host; this figure \
         says what else the machine was doing while it was taken.",
        load_average()
    );
    println!(
        "  samples: {}, median {:?}, p95 {p95:?} (bound {P95_BOUND:?}), p99 {p99:?} (bound \
         {P99_BOUND:?}), worst {:?}",
        samples.len(),
        percentile(&samples, 0.5),
        samples.last().copied().unwrap_or_default()
    );
    assert!(
        p95 < P95_BOUND,
        "the ninety-fifth percentile is within {P95_BOUND:?}: {p95:?}"
    );
    assert!(
        p99 < P99_BOUND,
        "the ninety-ninth percentile is within {P99_BOUND:?}: {p99:?}"
    );
}

/// Sends the keystrokes and returns the sorted samples, plus what closing the sessions did.
async fn measure_latency() -> (Result<Vec<Duration>, String>, Result<(), String>) {
    let (sessions, views) = background().await;
    let measured = hosted(DRAINS).await;
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

async fn latency_samples(hosted: &Hosted) -> Result<Vec<Duration>, String> {
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
    let mut samples = Vec::with_capacity(SAMPLES);
    for sequence in 0..SAMPLES {
        let params = InputWriteParams {
            session_id: hosted.session_id,
            attachment_id,
            epoch,
            sequence: kr_protocol::ids::InputSequence::new(sequence as u64),
            bytes: Bytes::new(b"x".to_vec()),
        };
        let started = Instant::now();
        let outcome = client
            .request(Method::InputWrite, &params)
            .await
            .map_err(|error| format!("the write did not reach the worker: {error}"))?;
        let elapsed = started.elapsed();
        let accepted: InputWriteResult = outcome
            .map_err(|error| format!("the write was refused: {}", error.message))?
            .to_typed()
            .map_err(|error| format!("the answer did not decode: {error}"))?;
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
    samples.sort_unstable();
    Ok(samples)
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
    let report = report.unwrap_or_else(|failure| panic!("the measurement: {failure}"));
    closed.unwrap_or_else(|failure| panic!("the session this measurement created: {failure}"));

    println!("KR-PERF-002 measurement");
    println!(
        "  conditions: a release build, canonical bracketed paste enabled by the application, and \
         one lone prefix per measurement with no keystroke behind it. Each figure runs from the \
         write to the byte reaching the application, which the root program reports by echoing it, \
         so it includes the host's deadline, the timer's wake-up, the write, that echo and this \
         measurement's {POLL:?} polling interval. The bound is the deadline plus \
         {RECOGNISER_TOLERANCE:?} for those."
    );
    println!(
        "  load average at the end: {}. Section 27 asks for a quiet reference host; this figure \
         says what else the machine was doing while it was taken.",
        load_average()
    );
    for (what, held) in &report.holds {
        println!("  {what}: held for {held:?} (deadline {RECOGNISER_DEADLINE:?})");
    }
    println!(
        "  a delimiter split across two frames: recognised once, in {:?}, with its payload kept",
        report.split
    );
    let allowed = RECOGNISER_DEADLINE + RECOGNISER_TOLERANCE;
    for (what, held) in &report.holds {
        assert!(
            *held <= allowed,
            "{what} was held for {held:?}, beyond the {RECOGNISER_DEADLINE:?} deadline"
        );
    }
    assert!(
        report.split <= allowed,
        "the split delimiter took {:?} to be recognised",
        report.split
    );
}

struct Recogniser {
    /// One entry per prefix length, plus the lone Escape, each measured on its own.
    holds: Vec<(String, Duration)>,
    /// How long the split delimiter took to be recognised once its second half arrived.
    split: Duration,
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
    let mut sequence = 0_u64;
    let mut holds = Vec::new();

    // Every proper prefix of the start delimiter, each one alone, and each one measured to the
    // moment it reaches the application. A lone Escape is the shortest of them, and it is the case
    // the requirement names outright: it must never wait for another keystroke.
    let delimiter = b"\x1b[200~";
    for length in 1..delimiter.len() {
        let prefix = &delimiter[..length];
        // A marker before the prefix, so what is waited for is this prefix rather than an earlier
        // one. It is an ordinary byte and is forwarded at once.
        let marker = format!("<{length}>");
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
                "a prefix of {length} bytes was held: {} held, {} forwarded",
                accepted.held_prefix_bytes.get(),
                accepted.forwarded_bytes.get()
            ));
        }
        let held = arrival(&hosted.runtime, &expected, started, RECOGNISER_DEADLINE * 8)
            .await
            .ok_or_else(|| {
                format!("a prefix of {length} bytes never reached the application on its own")
            })?;
        let what = if length == 1 {
            "a lone Escape, with no keystroke behind it".to_owned()
        } else {
            format!("a prefix of {length} bytes, with no keystroke behind it")
        };
        holds.push((what, held));
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
    drop(client);
    Ok(Recogniser { holds, split })
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

/// The echoing program is the one the recogniser measurement needs, and the draining one is the
/// one the latency measurement needs. Naming them apart keeps a change to one from moving the
/// other.
#[test]
fn each_measurement_uses_the_root_program_it_needs() {
    assert!(ECHOES.contains("exec cat"));
    assert!(ECHOES_BRACKETED.contains("2004h"));
    assert!(DRAINS.contains("/dev/null"));
}
