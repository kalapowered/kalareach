//! A real session for one application, and what the test can see of it.
//!
//! The application is the session's root program, started by a worker's own session in a real
//! pseudo-terminal. Two attachments watch it over the worker's own endpoint, with the product's own
//! client:
//!
//! * the terminal: attached at the session's own size, so it is served the byte stream directly,
//!   holding the input lease, and typing through the session's input path exactly as a keystroke
//!   from a socket is handled. Everything it is sent is kept, because what it must never be sent is
//!   a query the application asked. Its capture is only read once it provably holds the whole
//!   stream up to the application's last query: see [`Session::received`];
//! * a snapshot: a terminal of another size, attached for the moment it is needed and projected, so
//!   what it is sent is the worker's own snapshot of the canonical grid rather than bytes. That is
//!   what every case compares with the screen the application should be showing.
//!
//! The application waits for the terminal to be attached before it starts: the session's program
//! is a shell that reads one line and then replaces itself with the application. So every query the
//! application asks at startup is asked while an attachment is there to be sent it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    TerminalPresentationMode,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, EnvironmentId, InputLeaseEpoch,
    RequestId, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::projection::{
    PROJECTION_DELTA_EVENT, PROJECTION_RESET_EVENT, PROJECTION_ROWS_EVENT,
    PROJECTION_SNAPSHOT_EVENT, ProjectedBuffer, ProjectedRow, ProjectionDelta, ProjectionReset,
    ProjectionRowPage, ProjectionSnapshot,
};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams, OutputEvent};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{MAX_OUTPUT_EVENT_BYTES, ServiceBinding, WorkerService};
use kr_worker::session::{Session as WorkerSession, SessionConfig};

/// How long a wait for something to happen is given. It is a liveness bound, not a measurement:
/// a wait that succeeds costs what it takes, and one that never can fails here, saying what it saw.
pub const LIVENESS: Duration = Duration::from_secs(120);

/// The variable that names the cache `scripts/run-conformance.sh` fetched the applications into.
pub const APPLICATIONS: &str = "KR_CONFORMANCE_APPLICATIONS";

/// The terminal the typing attachment says it is. The session lets an attachment type only in
/// the keyboard protocols its terminal is credited with, and this one is credited with both an
/// application may ask for: `modifyOtherKeys` and the Kitty protocol.
const TYPING_TERMINAL: &str = "ghostty";

/// Records a known difference between an application and the profile, for the report: what the
/// case is about, how the application reads it, how the grid does, and what the grid showed.
///
/// A case records one when the difference is a documented property of the profile rather than a
/// fault, and it asserts what the profile defines. The report shows it as a known difference, in
/// a section of its own, never as a pass. Where `KR_TEST_ARTIFACTS_DIR` is not set the record is
/// printed and kept nowhere.
///
/// # Panics
///
/// Panics when the directory is set and the record cannot be written there, because a run that
/// asked for its evidence and could not keep it has no evidence.
pub fn known_difference(test: &str, subject: &str, application: &str, grid: &str, observed: &str) {
    let record = serde_json::json!({
        "package": "kr-conformance",
        "target": "applications",
        "test": test,
        "subject": subject,
        "application": application,
        "grid": grid,
        "observed": observed,
    });
    println!("known difference: {record}");
    let Some(directory) = std::env::var_os("KR_TEST_ARTIFACTS_DIR") else {
        return;
    };
    let path = Path::new(&directory).join("known-differences.jsonl");
    let write = || -> std::io::Result<()> {
        use std::io::Write;
        std::fs::create_dir_all(&directory)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        writeln!(file, "{record}")
    };
    if let Err(error) = write() {
        panic!(
            "this run could not keep its evidence at {}: {error}",
            path.display()
        );
    }
}

/// One application as the fetch step installed it.
#[derive(Clone, Debug)]
pub struct Application {
    /// The program to run.
    pub executable: PathBuf,
}

/// Looks up an application in the index the fetch step wrote.
///
/// # Panics
///
/// Panics, saying how to fetch it, when the cache or the application is not there. A case that
/// passed without the program it is about would be a pass it never earned.
#[must_use]
pub fn application(id: &str) -> Application {
    let Some(cache) = std::env::var_os(APPLICATIONS) else {
        panic!(
            "{APPLICATIONS} is not set. The application matrix runs the pinned applications \
             `scripts/run-conformance.sh --group applications` fetches and names in that variable."
        );
    };
    let index_path = Path::new(&cache).join("index.json");
    let text = std::fs::read_to_string(&index_path).unwrap_or_else(|error| {
        panic!(
            "{} could not be read ({error}); `scripts/run-conformance.sh --group applications` \
             writes it",
            index_path.display()
        )
    });
    let index: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not JSON: {error}", index_path.display()));
    let entry = index["applications"]
        .as_array()
        .and_then(|entries| entries.iter().find(|entry| entry["id"] == id))
        .unwrap_or_else(|| panic!("{} names no application {id}", index_path.display()));
    let executable = entry["executable"].as_str().unwrap_or_else(|| {
        panic!(
            "{id} is not installed here: {}",
            entry["reason"]
                .as_str()
                .unwrap_or("the index gives no reason")
        )
    });
    Application {
        executable: PathBuf::from(executable),
    }
}

/// The locale every application is started in: UTF-8, which every case with text beyond ASCII needs.
#[must_use]
pub fn utf8_locale() -> &'static str {
    if cfg!(target_os = "macos") {
        "en_US.UTF-8"
    } else {
        "C.UTF-8"
    }
}

/// What a session is started with.
pub struct Launch {
    /// The application.
    pub program: PathBuf,
    /// Its arguments.
    pub arguments: Vec<String>,
    /// Variables beyond `TERM`, `HOME`, `PATH` and the locale.
    pub environment: Vec<(String, String)>,
    /// The session's size.
    pub size: (u16, u16),
    /// Shell commands to run after the application exits, which keep the session open for the
    /// case to look at what the application left behind.
    pub after: Option<String>,
}

impl Launch {
    /// An 80 by 24 session.
    #[must_use]
    pub fn new(program: &Path) -> Self {
        Self {
            program: program.to_owned(),
            arguments: Vec::new(),
            environment: Vec::new(),
            size: (80, 24),
            after: None,
        }
    }

    /// Runs `commands` in the session's shell once the application has exited.
    #[must_use]
    pub fn after(mut self, commands: &str) -> Self {
        self.after = Some(commands.to_owned());
        self
    }

    /// Adds arguments.
    #[must_use]
    pub fn arguments<I: IntoIterator<Item = S>, S: Into<String>>(mut self, arguments: I) -> Self {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    /// Adds a variable.
    #[must_use]
    pub fn variable(mut self, name: &str, value: impl Into<String>) -> Self {
        self.environment.push((name.to_owned(), value.into()));
        self
    }
}

/// The session, its worker and the typing terminal.
pub struct Session {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The application's home and working directory, kept for as long as the session is.
    _home: tempfile::TempDir,
    size: (u16, u16),
    keys: Keys,
    capture: Arc<Mutex<Capture>>,
    reader: tokio::task::JoinHandle<()>,
}

/// What the typing terminal has been sent, and what stopped it being sent the whole stream.
#[derive(Default)]
struct Capture {
    /// The bytes, in the order they came.
    bytes: Vec<u8>,
    /// The greatest stream position a whole delivery it was sent names: where an output span
    /// starts, the position a screen describes, or the position of a projected screen, a change to
    /// it or its reset. A delivery that takes several events, a large span or screen in chunks or a
    /// projected screen in pages, counts only once its last event has arrived. One connection
    /// delivers in order, so everything sent before it has arrived as well.
    settled: Option<u64>,
    /// How many events of each type it was sent, which a failure reports.
    seen: std::collections::BTreeMap<String, u64>,
    /// How many times the worker told the terminal its view was no longer continuous, which the
    /// terminal answers as the product's own client does: by subscribing again, for a fresh screen.
    resynchronised: u64,
    /// Why the capture stopped being everything the terminal was sent, once it did: the connection
    /// ended, an event could not be decoded, a new subscription was refused, or the terminal was
    /// detached.
    broken: Option<String>,
}

impl Capture {
    /// Takes note of an event at `position`, which ends its delivery when `last` says so.
    fn took(&mut self, position: u64, last: bool) {
        if last {
            self.settled = Some(
                self.settled
                    .map_or(position, |settled| settled.max(position)),
            );
        }
    }
}

struct Keys {
    attachment_id: AttachmentId,
    epoch: InputLeaseEpoch,
    sequence: u64,
}

impl Drop for Session {
    /// Stops the application however the case ended. The host's own forced stop signals through
    /// the handle the session holds, and a session whose lock an earlier panic poisoned is left
    /// alone rather than taking the whole test binary down with a second panic.
    fn drop(&mut self) {
        self.reader.abort();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = self.runtime.session().force_close();
        }));
    }
}

fn build() -> BuildId {
    BuildId::new("kr-conformance/0").expect("a build identifier")
}

fn target(session_id: SessionId, environment_id: EnvironmentId) -> ActionTarget {
    ActionTarget {
        environment_id,
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

impl Session {
    /// Starts `launch` as the root of a real session, attaches the typing terminal, and then lets
    /// the application start.
    ///
    /// # Panics
    ///
    /// Panics when any step of that fails, naming it.
    pub async fn start(launch: Launch) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let home = tempfile::Builder::new()
            .prefix("kr-conformance-home.")
            .tempdir()
            .expect("a home directory for the application");
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
        let process =
            kr_ipc::identity::current_process_start_identity().expect("a process identity");
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
        let controller =
            kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
                .expect("a controller identity");

        // The application starts once the typing terminal is attached: a shell reads one line and
        // then runs it, replacing itself with it unless the case looks at what follows.
        let mut command = vec![quote(&launch.program.to_string_lossy())];
        command.extend(launch.arguments.iter().map(|argument| quote(argument)));
        let script = match &launch.after {
            Some(after) => format!("read -r _ && {}; {after}", command.join(" ")),
            None => format!("read -r _ && exec {}", command.join(" ")),
        };
        let mut variables = vec![
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            (
                "HOME".to_owned(),
                home.path().to_string_lossy().into_owned(),
            ),
            ("PATH".to_owned(), "/usr/bin:/bin".to_owned()),
            ("LANG".to_owned(), utf8_locale().to_owned()),
            ("LC_ALL".to_owned(), utf8_locale().to_owned()),
        ];
        variables.extend(launch.environment.iter().cloned());
        let shell = ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), script],
            cwd: home.path().to_string_lossy().into_owned(),
            environment: variables,
        };
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell,
            shell_mode: ShellMode::NativeCompat,
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(u64::from(launch.size.0), u64::from(launch.size.1)),
            journal_path: Some(environment.journal_database(session_id)),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 4 * 1024 * 1024,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut session = WorkerSession::open(config).expect("opens the session");
        session.launch().expect("launches the root program");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
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

        // The typing terminal: the session's own size, so it is served the stream directly. The
        // lease is taken before the subscription, and everything it is sent from then on is kept.
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let (attachment_id, presentation) = attach(
            &mut client,
            session_id,
            environment_id,
            launch.size,
            Some(TYPING_TERMINAL),
        )
        .await;
        assert_eq!(
            presentation,
            Some(TerminalPresentationMode::Direct),
            "a terminal of the session's own size is served the stream"
        );
        let acquired: InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target(session_id, environment_id),
                &InputAcquireParams {
                    session_id,
                    attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the lease is granted")
            .to_typed()
            .expect("decodes");
        subscribe(&mut client, session_id, attachment_id).await;
        let capture = Arc::new(Mutex::new(Capture::default()));
        let reader = tokio::spawn(keep_output(
            client,
            Arc::clone(&capture),
            session_id,
            attachment_id,
        ));
        let mut started = Self {
            _temp: temp,
            _service: service,
            runtime,
            session_id,
            environment_id,
            endpoint,
            _home: home,
            size: launch.size,
            keys: Keys {
                attachment_id,
                epoch: acquired.lease.epoch,
                sequence: 0,
            },
            capture,
            reader,
        };
        started.type_bytes(b"\n");
        started
    }

    /// Types `bytes` through the input lease the typing terminal holds.
    ///
    /// # Panics
    ///
    /// Panics when the session does not take every byte.
    pub fn type_bytes(&mut self, bytes: &[u8]) {
        let accepted = {
            let mut session = self.runtime.session();
            session
                .write_input(
                    self.keys.attachment_id,
                    self.keys.epoch.get(),
                    self.keys.sequence,
                    bytes,
                    None,
                    Instant::now(),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "the session refused {}: {error}",
                        String::from_utf8_lossy(bytes).escape_debug()
                    )
                })
        };
        assert_eq!(
            accepted.forwarded_bytes,
            bytes.len() as u64,
            "the session took every byte of {}",
            String::from_utf8_lossy(bytes).escape_debug()
        );
        self.keys.sequence += 1;
        self.runtime.flush_input();
    }

    /// Types `text` as a bracketed paste, the way a terminal wraps what a person pastes.
    pub fn paste(&mut self, text: &str) {
        let mut bytes = b"\x1b[200~".to_vec();
        bytes.extend_from_slice(text.as_bytes());
        bytes.extend_from_slice(b"\x1b[201~");
        self.type_bytes(&bytes);
    }

    /// Clicks the first button at `column` and `row` (from 1), in the encoding the application
    /// asked for: the SGR form where it turned that on, and the original form otherwise.
    pub fn click(&mut self, screen: &Screen, column: u16, row: u16) {
        if screen.mode(1006) {
            self.type_bytes(format!("\x1b[<0;{column};{row}M\x1b[<0;{column};{row}m").as_bytes());
        } else {
            let at = |value: u16| {
                u8::try_from(value + 32).expect("a position the original form can carry")
            };
            self.type_bytes(&[0x1b, b'[', b'M', 32, at(column), at(row)]);
            self.type_bytes(&[0x1b, b'[', b'M', 35, at(column), at(row)]);
        }
    }

    /// Everything the typing terminal has been sent, once it holds the whole stream up to where the
    /// application's last query ends.
    ///
    /// The worker keeps what the application wrote, queries included, and delivers the typing
    /// terminal what it may be sent, each span with the cursor it starts at, in order over one
    /// connection. Once a span that starts at or past the end of the last query has arrived, every
    /// span before it has too, so a query that reached this terminal is in what this returns. A
    /// terminal told to resynchronise is sent a fresh screen at the session's cursor and nothing
    /// in between, so what it was never sent cannot have reached it either. A query already in the
    /// capture is returned at once, for the case to report.
    ///
    /// # Panics
    ///
    /// Panics when the capture broke (the connection ended, an event could not be decoded, a new
    /// subscription was refused, or the terminal was detached), or when no such span arrives in
    /// time.
    pub async fn received(&self) -> Vec<u8> {
        let boundary = crate::queries::find(&self.written())
            .last()
            .map_or(0, |query| (query.at + query.bytes.len()) as u64);
        let started = tokio::time::Instant::now();
        loop {
            let resynchronised = {
                let capture = self.capture.lock().expect("the reader's capture");
                if let Some(broken) = &capture.broken {
                    panic!("the typing terminal's capture is not the whole stream: {broken}");
                }
                if capture.settled.is_some_and(|settled| settled >= boundary)
                    || !crate::queries::find(&capture.bytes).is_empty()
                {
                    return capture.bytes.clone();
                }
                (capture.resynchronised, capture.seen.clone())
            };
            assert!(
                started.elapsed() < LIVENESS,
                "the typing terminal was never sent output past {boundary}, where the \
                 application's last query ends (it was resynchronised {} times, and sent {:?})",
                resynchronised.0,
                resynchronised.1
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Everything the application has written, as the session retained it from its first byte.
    ///
    /// # Panics
    ///
    /// Panics when the history cannot be read, or no longer starts at the first byte.
    #[must_use]
    pub fn written(&self) -> Vec<u8> {
        let session = self.runtime.session();
        let mut seen = Vec::new();
        let mut cursor = 0_u64;
        loop {
            let page = session
                .history_page(cursor, 1024 * 1024)
                .expect("reads the retained output");
            assert!(
                !page.gap.is_present(),
                "the session no longer retains all the application wrote: {:?}",
                page.gap
            );
            if page.bytes.as_slice().is_empty() {
                break;
            }
            seen.extend_from_slice(page.bytes.as_slice());
            cursor = page.next_cursor.get();
        }
        seen
    }

    /// The worker's snapshot of the canonical grid, as a projected terminal is sent it now.
    ///
    /// # Panics
    ///
    /// Panics when the snapshot does not arrive.
    pub async fn snapshot(&self) -> Screen {
        let mut client = LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        // Any other size is projected; one more row keeps every row of the screen in view.
        let size = (self.size.0, self.size.1 + 1);
        let (attachment_id, presentation) = attach(
            &mut client,
            self.session_id,
            self.environment_id,
            size,
            Some("xterm-256color"),
        )
        .await;
        assert_eq!(presentation, Some(TerminalPresentationMode::Viewport));
        subscribe(&mut client, self.session_id, attachment_id).await;
        let screen = read_snapshot(&mut client).await;
        let _ = self.runtime.session().detach(attachment_id);
        screen
    }

    /// Takes snapshots until `until` holds of one, and returns it.
    ///
    /// # Panics
    ///
    /// Panics, with the last snapshot, when it never does.
    pub async fn wait_for(&self, what: &str, until: impl Fn(&Screen) -> bool) -> Screen {
        let started = tokio::time::Instant::now();
        loop {
            let screen = self.snapshot().await;
            if until(&screen) {
                return screen;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "waited {:?} for {what}; the worker's snapshot was:\n{screen}",
                started.elapsed()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Quotes one word for `/bin/sh`.
fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\\''"))
}

async fn attach(
    client: &mut LocalClient,
    session_id: SessionId,
    environment_id: EnvironmentId,
    size: (u16, u16),
    profile: Option<&str>,
) -> (AttachmentId, Option<TerminalPresentationMode>) {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    let attached: SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target(session_id, environment_id),
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(u64::from(size.0), u64::from(size.1))),
                terminal_profile_id: Nullable(profile.map(str::to_owned)),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    (
        attached.attachment.attachment_id,
        attached.attachment.presentation.as_ref().copied(),
    )
}

async fn subscribe(client: &mut LocalClient, session_id: SessionId, attachment_id: AttachmentId) {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds");
}

/// Keeps every byte the typing terminal is sent until the session ends, and records what stopped
/// the capture being everything it was sent, if anything did.
///
/// A resynchronisation is answered as the product's own client answers it: by subscribing again,
/// on this connection, so the worker sends a fresh screen and the stream from there.
async fn keep_output(
    mut client: LocalClient,
    capture: Arc<Mutex<Capture>>,
    session_id: SessionId,
    attachment_id: AttachmentId,
) {
    // Far above the identifiers the client numbers its own calls with, so the two never meet.
    let mut next_request = 1_u64 << 48;
    let mut asked: Vec<RequestId> = Vec::new();
    let broken = loop {
        let frame = match client.recv().await {
            Ok(frame) => frame,
            Err(error) => break format!("its connection ended: {error}"),
        };
        let ControlFrame::Notification(notification) = frame else {
            if let ControlFrame::Response(response) = frame
                && asked.contains(&response.request_id)
                && let Outcome::Error(error) = response.outcome
            {
                break format!("a new subscription was refused: {error:?}");
            }
            continue;
        };
        let kind = notification.event_type.as_str().to_owned();
        if let Ok(mut kept) = capture.lock() {
            *kept.seen.entry(kind.clone()).or_default() += 1;
        }
        // Where in the stream the event is, and whether it ends its delivery: an output span's
        // start or a screen's position, whose last chunk is the one shorter than a full chunk; a
        // projected screen, whose last page says there is no more; a change to one, or its reset.
        // A terminal the worker has moved to a projection is sent no bytes until it is moved back.
        let position = match kind.as_str() {
            "session.output" => notification
                .payload
                .to_typed::<OutputEvent>()
                .map(|event| {
                    if let Ok(mut kept) = capture.lock() {
                        kept.bytes.extend_from_slice(event.bytes.as_slice());
                    }
                    Some((
                        event.cursor.get(),
                        event.bytes.as_slice().len() < MAX_OUTPUT_EVENT_BYTES,
                    ))
                })
                .map_err(|error| error.to_string()),
            PROJECTION_SNAPSHOT_EVENT => notification
                .payload
                .to_typed::<ProjectionSnapshot>()
                .map(|snapshot| Some((snapshot.output_cursor.get(), false)))
                .map_err(|error| error.to_string()),
            PROJECTION_ROWS_EVENT => notification
                .payload
                .to_typed::<ProjectionRowPage>()
                .map(|page| Some((page.output_cursor.get(), !page.more)))
                .map_err(|error| error.to_string()),
            PROJECTION_DELTA_EVENT => notification
                .payload
                .to_typed::<ProjectionDelta>()
                .map(|delta| Some((delta.next_cursor.get(), true)))
                .map_err(|error| error.to_string()),
            PROJECTION_RESET_EVENT => notification
                .payload
                .to_typed::<ProjectionReset>()
                .map(|reset| Some((reset.cursor.get(), true)))
                .map_err(|error| error.to_string()),
            _ => Ok(None),
        };
        match position {
            Ok(Some((position, last))) => {
                if let Ok(mut kept) = capture.lock() {
                    kept.took(position, last);
                }
            }
            Ok(None) => {}
            Err(error) => break format!("a {kind} event could not be decoded: {error}"),
        }
        match kind.as_str() {
            "session.resync" => {
                let mut streams = CanonicalSet::new();
                streams.insert(EventStream::Output);
                let Ok(params) = ParamsValue::from_typed(&EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                }) else {
                    break "a new subscription could not be encoded".to_owned();
                };
                let request_id = RequestId::new(next_request);
                next_request += 1;
                let request = Request {
                    request_id,
                    method: Method::EventsSubscribe.into(),
                    method_version: MethodVersion::V1,
                    params,
                };
                if let Err(error) = client
                    .writer()
                    .write_message(&ControlFrame::Request(request))
                    .await
                {
                    break format!("a new subscription could not be sent: {error}");
                }
                asked.push(request_id);
                if let Ok(mut kept) = capture.lock() {
                    kept.resynchronised += 1;
                }
            }
            "session.detached" => break "the worker detached it".to_owned(),
            _ => {}
        }
    };
    if let Ok(mut kept) = capture.lock() {
        kept.broken.get_or_insert(broken);
    }
}

async fn read_snapshot(client: &mut LocalClient) -> Screen {
    let started = tokio::time::Instant::now();
    let mut header: Option<ProjectionSnapshot> = None;
    let mut rows: Vec<ProjectedRow> = Vec::new();
    loop {
        let remaining = LIVENESS.saturating_sub(started.elapsed());
        let frame = match tokio::time::timeout(remaining, client.recv()).await {
            Ok(Ok(frame)) => frame,
            Ok(Err(error)) => panic!("the snapshot's connection ended: {error}"),
            Err(_) => panic!("waited {:?} for the worker's snapshot", started.elapsed()),
        };
        let ControlFrame::Notification(notification) = frame else {
            continue;
        };
        match notification.event_type.as_str() {
            "session.projection.snapshot" => {
                header = notification.payload.to_typed().ok();
                rows.clear();
            }
            "session.projection.rows" => {
                let page: ProjectionRowPage = notification.payload.to_typed().expect("a row page");
                // Both buffers are sent, each with its own rows; the screen is the active one's.
                if header
                    .as_ref()
                    .is_some_and(|header| header.active_buffer == page.buffer)
                {
                    rows.extend(page.rows);
                }
                if !page.more {
                    let header = header.take().expect("the snapshot's header came first");
                    return Screen::from_projection(&header, &rows);
                }
            }
            _ => {}
        }
    }
}

/// One run of a row: where it starts, how many columns it takes and what it shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// The column of its first cell, from zero.
    pub column: u64,
    /// How many columns it takes, a wide character counting two.
    pub cells: u64,
    /// Its text.
    pub text: String,
}

/// The worker's snapshot of the screen.
#[derive(Clone, Debug)]
pub struct Screen {
    /// Which buffer is showing.
    pub buffer: ProjectedBuffer,
    /// The visible rows, as the runs the worker sent for each.
    pub rows: Vec<Vec<Run>>,
    /// The cursor: column and row, from zero.
    pub cursor: (u64, u64),
    /// Whether the cursor is shown.
    pub cursor_visible: bool,
    /// The modes the snapshot says are set.
    pub modes: String,
    /// The keyboard state the snapshot carries.
    pub keyboard: String,
}

impl Screen {
    fn from_projection(header: &ProjectionSnapshot, rows: &[ProjectedRow]) -> Self {
        let top = header.viewport.screen_top_row.get();
        let count = header.dimensions.rows.get();
        let visible = (0..count)
            .map(|index| {
                rows.iter()
                    .find(|row| row.row.get() == top + index)
                    .map(|row| {
                        row.runs
                            .iter()
                            .map(|run| Run {
                                column: run.column.get(),
                                cells: run.cells.get(),
                                text: run.text.clone(),
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect();
        Self {
            buffer: header.active_buffer,
            rows: visible,
            cursor: (header.cursor.column.get(), header.cursor.row.get()),
            cursor_visible: header.cursor.visible,
            modes: format!("{:?}", header.modes),
            keyboard: format!("{:?}", header.keyboard),
        }
    }

    /// One row's text: each run at its column, the columns between runs shown as spaces, and the
    /// trailing blanks removed.
    #[must_use]
    pub fn line(&self, row: usize) -> String {
        let mut text = String::new();
        let mut column = 0_u64;
        for run in self.rows.get(row).into_iter().flatten() {
            while column < run.column {
                text.push(' ');
                column += 1;
            }
            text.push_str(&run.text);
            column = run.column + run.cells;
        }
        text.trim_end().to_owned()
    }

    /// The row a text is on, when a row shows it.
    #[must_use]
    pub fn row_of(&self, text: &str) -> Option<usize> {
        (0..self.rows.len()).find(|row| self.line(*row).contains(text))
    }

    /// Whether any row shows `text`.
    #[must_use]
    pub fn shows(&self, text: &str) -> bool {
        self.row_of(text).is_some()
    }

    /// Whether the snapshot says DEC private mode `mode` is set.
    #[must_use]
    pub fn mode(&self, mode: u16) -> bool {
        self.modes
            .contains(&format!("kind: Dec, mode: U64({mode}), enabled: true"))
    }
}

impl std::fmt::Display for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "buffer {:?}, cursor {:?}{}",
            self.buffer,
            self.cursor,
            if self.cursor_visible { "" } else { " (hidden)" }
        )?;
        for row in 0..self.rows.len() {
            writeln!(f, "{row:>3}|{}", self.line(row))?;
        }
        Ok(())
    }
}

/// The column at which `suffix` starts on `row`, counted back from the end of the run that holds
/// it. Everything from `suffix` to the end of that run has to be ASCII, a cell each, so where it
/// starts is known whatever the widths of what comes before it; `None` when it is not so.
#[must_use]
pub fn ascii_suffix_column(screen: &Screen, row: usize, suffix: &str) -> Option<u64> {
    let run = screen
        .rows
        .get(row)?
        .iter()
        .find(|run| run.text.contains(suffix))?;
    let at = run.text.rfind(suffix)?;
    let tail = &run.text[at..];
    tail.is_ascii()
        .then(|| run.column + run.cells - tail.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::Capture;

    #[test]
    fn a_delivery_in_several_events_settles_only_with_its_last() {
        let mut capture = Capture::default();
        // A screen in two chunks at one position: the first is not the whole screen.
        capture.took(40, false);
        assert_eq!(capture.settled, None);
        capture.took(40, true);
        assert_eq!(capture.settled, Some(40));
        // A projected screen's header and a page with more to come settle nothing further.
        capture.took(90, false);
        capture.took(90, false);
        assert_eq!(capture.settled, Some(40));
        capture.took(90, true);
        assert_eq!(capture.settled, Some(90));
        // An earlier position never takes a settled one back.
        capture.took(60, true);
        assert_eq!(capture.settled, Some(90));
    }
}
