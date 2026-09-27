//! A session's screen restored in a real session: the worker's runtime reads a program's output
//! from a real pseudo-terminal, and clients attach over the worker's own endpoint with the
//! product's client.
//!
//! The program writes each piece of a corpus when the test releases it through a named pipe, and
//! the test waits for the session to have read a piece before it acts, so a client attaches at an
//! exact point (inside a sequence, at a buffer switch, after a clipboard write) and nothing depends
//! on how fast anything runs. Each client is checked against the session's own screen, read by a
//! client installed at the end. The in-process suite (`tests/restore.rs`) checks every point of
//! each corpus; this one shows the same properties through the runtime, the endpoint and the wire.
//!
//! Unix only: the program waits on a named pipe.

#![cfg(unix)]

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use kr_cli::render::ProjectedDisplay;
use kr_client::projection::{Applied, Projection};
use kr_faults::corpus::{self, Corpus};
use kr_faults::screen::{Line, Parts, View};
use kr_faults::terminal::Terminal;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, AttachmentId, BuildId, ControllerGeneration, EnvironmentId, SessionEpoch, SessionId,
};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::projection::{AgentResourceSnapshot, ProjectionEvent};
use kr_protocol::recovery::{EventStream, EventsSubscribeParams, OutputEvent};
use kr_protocol::scalars::{CanonicalSet, Nullable, U64};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_term::sideeffect::SideEffectKind;
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a wait for something to happen is given: a liveness bound, never a measurement.
const LIVENESS: Duration = Duration::from_secs(120);

/// How long a wait sleeps between two looks at what it waits for.
const LOOK_AGAIN: Duration = Duration::from_millis(10);

/// What the program writes after the corpus: a line a client shows only once it has read
/// everything the session sent before it, so a client that shows it has missed nothing.
const BARRIER: &[u8] = b"\r\nkr-end-of-output";

fn build() -> BuildId {
    BuildId::new("kr-faults/0").expect("a build identifier")
}

fn corpus(name: &str) -> Corpus {
    Corpus::load(&corpus::directory().join(format!("{name}.json")))
        .unwrap_or_else(|error| panic!("{error}"))
}

/// A session whose program writes a corpus a piece at a time.
struct Live {
    _temp: kr_ipc::testing::TempHost,
    _service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    endpoint: kr_ipc::paths::Endpoint,
    session_id: SessionId,
    environment_id: EnvironmentId,
    gate: std::fs::File,
    ends: Vec<usize>,
    released: usize,
    columns: u16,
    rows: u16,
}

impl Live {
    /// Starts a session whose program writes `corpus` in pieces that end at `ends`, and then the
    /// barrier.
    async fn start(corpus: &Corpus, mut ends: Vec<usize>) -> Self {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let pieces = temp.root().join("pieces");
        std::fs::create_dir(&pieces).expect("a directory for the pieces");
        let bytes = corpus.bytes();
        let mut start = 0;
        for (index, end) in ends.iter().enumerate() {
            std::fs::write(pieces.join(index.to_string()), &bytes[start..*end])
                .expect("writes a piece");
            start = *end;
        }
        assert_eq!(start, bytes.len(), "the pieces cover the corpus");
        std::fs::write(pieces.join(ends.len().to_string()), BARRIER).expect("writes the barrier");
        ends.push(start + BARRIER.len());
        let gate = temp.root().join("gate");
        let made = std::process::Command::new("mkfifo")
            .arg(&gate)
            .status()
            .expect("mkfifo runs");
        assert!(made.success(), "the gate is made");
        // Raw output, so every byte the program writes is read as it was written; the gate is
        // held open for reading and writing, so it never reaches its end between two releases.
        let script = format!(
            "stty raw -echo -opost; exec 3<>'{gate}'; \
             while IFS= read -r piece <&3; do cat '{pieces}'/\"$piece\"; done",
            gate = gate.display(),
            pieces = pieces.display()
        );
        let config = SessionConfig {
            session_id,
            session_epoch: SessionEpoch::V1,
            environment_id,
            display_number: DisplayNumber::new(1),
            shell: ShellCommand {
                program: "/bin/sh".to_owned(),
                arguments: vec!["-c".to_owned(), script],
                cwd: temp.root().to_string_lossy().into_owned(),
                environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
            },
            shell_mode: ShellMode::NativeCompat,
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            worker_profile: WorkerProfile::HeadlessUser,
            desktop: DesktopBinding::none(),
            dimensions: Dimensions::new(u64::from(corpus.columns), u64::from(corpus.rows)),
            journal_path: Some(environment.journal_database(session_id)),
            spool_directory: Some(environment.session_spool(session_id)),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 4 * 1024 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
        };
        let mut session = Session::open(config).expect("opens the session");
        session.launch().expect("launches the program");
        let runtime = Arc::new(
            SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
                .expect("starts the runtime"),
        );
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
        // Held open for reading as well as writing, which never waits for the program: what is
        // written waits in the pipe until the program reads it.
        let gate = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&gate)
            .expect("opens the gate");
        Self {
            _temp: temp,
            _service: service,
            runtime,
            endpoint,
            session_id,
            environment_id,
            gate,
            ends,
            released: 0,
            columns: corpus.columns,
            rows: corpus.rows,
        }
    }

    /// Releases the next piece and waits until the session has read all of it.
    async fn release(&mut self) {
        let index = self.released;
        writeln!(self.gate, "{index}").expect("releases a piece");
        self.released += 1;
        let end = u64::try_from(self.ends[index]).expect("an offset");
        within("the session reads the piece", async {
            loop {
                let read = self
                    .runtime
                    .session()
                    .snapshot(AgentResourceSnapshot {
                        snapshot_id: U64::new(0),
                        stream_generation: U64::new(0),
                        cursor: U64::new(0),
                        resources: Vec::new(),
                        continue_after: Nullable::null(),
                    })
                    .cursor
                    .get();
                if read >= end {
                    return;
                }
                tokio::time::sleep(LOOK_AGAIN).await;
            }
        })
        .await;
    }

    /// Releases every piece still held.
    async fn release_all(&mut self) {
        while self.released < self.ends.len() {
            self.release().await;
        }
    }

    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A client attached and subscribed: a terminal of the session's size holding the lease, or a
    /// narrower one, or the probe the session's screen is read with.
    async fn client(&self, form: Form) -> Client {
        let mut client = LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects");
        let (columns, profile) = match form {
            Form::Direct => (self.columns, Some("xterm-256color")),
            Form::Projected => (
                self.columns.saturating_sub(4).max(1),
                Some("xterm-256color"),
            ),
            Form::Probe => (self.columns, None),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        if form == Form::Direct {
            requested.insert(AttachmentCapability::Input);
        }
        let attached: SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &SessionAttachParams {
                    session_id: self.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(Dimensions::new(
                        u64::from(columns),
                        u64::from(self.rows),
                    )),
                    terminal_profile_id: Nullable(profile.map(ToOwned::to_owned)),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("attaches")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        if form == Form::Direct {
            let _: InputAcquireResult = client
                .mutate(
                    Method::InputAcquire,
                    ActionId::new(kr_ipc::new_uuid()),
                    self.target(),
                    &InputAcquireParams {
                        session_id: self.session_id,
                        attachment_id,
                        expected_epoch: Nullable::null(),
                    },
                )
                .await
                .expect("the call reaches the worker")
                .expect("takes the lease")
                .to_typed()
                .expect("decodes");
        }
        let mut client = Client {
            client,
            session_id: self.session_id,
            attachment_id,
            form,
            terminal: Terminal::new(self.columns, self.rows).expect("a terminal"),
            display: ProjectedDisplay::new(),
            projection: Projection::new(),
            performed: Vec::new(),
            replies: 0,
        };
        client.subscribe().await;
        client
    }

    /// The session's screen, as a client installed now holds it.
    async fn canonical(&self) -> View {
        let mut probe = self.client(Form::Probe).await;
        probe
            .read_until("the probe holds a whole screen", |client| {
                client.projection.screen().is_some()
            })
            .await;
        let view = View::of(probe.projection.screen().expect("a screen"));
        let _: kr_protocol::attachment::SessionDetachResult = probe
            .client
            .mutate(
                Method::SessionDetach,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &kr_protocol::attachment::SessionDetachParams {
                    attachment_id: Nullable::some(probe.attachment_id),
                    line_token: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the probe leaves")
            .to_typed()
            .expect("decodes");
        view
    }

    /// Releases every piece still held, and after each one waits for `client` to show the
    /// session's screen, as a client that reads its output as it comes does.
    async fn release_all_read_by(&mut self, client: &mut Client) {
        while self.released < self.ends.len() {
            self.release().await;
            let expected = self.canonical().await;
            client
                .read_until("the client keeps up with the session", |client| {
                    client.shows(&expected, Parts::Painted)
                })
                .await;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Form {
    Direct,
    Projected,
    Probe,
}

/// A client on the wire, with the model of what it draws.
struct Client {
    client: LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    form: Form,
    /// The terminal a client of the session's size draws into.
    terminal: Terminal,
    /// The command's painter, for a screen it is shown as a projection.
    display: ProjectedDisplay,
    /// The projection it holds.
    projection: Projection,
    /// Every side effect its terminal performed.
    performed: Vec<SideEffectKind>,
    /// How many questions its terminal answered.
    replies: usize,
}

impl Client {
    async fn subscribe(&mut self) {
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        self.client
            .request(
                Method::EventsSubscribe,
                &EventsSubscribeParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("subscribes");
    }

    fn feed(&mut self, bytes: &[u8]) {
        let performed = self.terminal.feed(bytes);
        self.replies += performed.replies;
        self.performed.extend(performed.effects);
    }

    /// Reads what the session sends until `done` holds, drawing it as the client would.
    async fn read_until(&mut self, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = tokio::time::Instant::now() + LIVENESS;
        while !done(self) {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            let frame = tokio::time::timeout(left, self.client.recv())
                .await
                .unwrap_or_else(|_| panic!("waited {LIVENESS:?} for {what}"))
                .unwrap_or_else(|error| panic!("the connection ended waiting for {what}: {error}"));
            let ControlFrame::Notification(notification) = frame else {
                continue;
            };
            let kind = notification.event_type.as_str().to_owned();
            if kind == "session.output" {
                let event: OutputEvent = notification.payload.to_typed().expect("decodes");
                self.feed(event.bytes.as_slice());
            } else if kind == "session.resync" {
                self.projection.discard();
                self.subscribe().await;
            } else if let Some(event) = kr_client::projection::decode(&kind, &notification.payload)
            {
                self.projected(event).await;
            }
        }
    }

    async fn projected(&mut self, event: ProjectionEvent) {
        let refused = matches!(self.projection.apply(event.clone()), Applied::Refused(_));
        let mut again = refused;
        if self.form == Form::Direct {
            let drawn = self.display.apply(event);
            again |= drawn.resubscribe;
            if !drawn.bytes.is_empty() {
                self.feed(&drawn.bytes);
            }
        }
        if again {
            self.projection.discard();
            self.subscribe().await;
        }
    }

    /// What the terminal shows.
    fn terminal_view(&mut self) -> View {
        self.terminal.view().expect("a view")
    }

    /// Whether the terminal shows `expected` in the parts named.
    fn shows(&mut self, expected: &View, parts: Parts) -> bool {
        self.terminal_view().differences(expected, parts).is_empty()
    }
}

async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS, work)
        .await
        .unwrap_or_else(|_| panic!("waited {LIVENESS:?} for {what}"))
}

/// The pieces a corpus is written in: its own writes, and a split at `inside` where a case wants a
/// client to arrive part way through one.
fn pieces(corpus: &Corpus, inside: Option<usize>) -> Vec<usize> {
    let mut ends = corpus.write_ends();
    if let Some(point) = inside {
        ends.push(point);
        ends.sort_unstable();
        ends.dedup();
    }
    ends
}

/// KR-REQ-27.06: in a real session, a client that attaches inside a long link the program has
/// half written, while the output is still coming, is drawn the session's screen and continues
/// with it once the program writes the rest: a terminal of the session's size shows what the
/// session shows, and a projection holds it, and neither was asked a question the session answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_arriving_inside_a_sequence_of_a_live_session_holds_its_screen() {
    let corpus = corpus("sequences");
    // Inside the link's target: the eighth write starts after the first seven.
    let link = corpus.write_ends()[6];
    let mut live = Live::start(&corpus, pieces(&corpus, Some(link + 30))).await;
    let arrival = live
        .ends
        .iter()
        .position(|end| *end == link + 30)
        .expect("the split");
    for _ in 0..=arrival {
        live.release().await;
    }
    let mut direct = live.client(Form::Direct).await;
    let mut projected = live.client(Form::Projected).await;
    live.release_all().await;
    let expected = live.canonical().await;
    assert!(
        expected
            .lines
            .iter()
            .any(|line| line.text() == "kr-end-of-output"),
        "the barrier is on the screen the clients are compared with"
    );
    direct
        .read_until("the terminal shows the session's screen", |client| {
            client.shows(&expected, Parts::Painted)
        })
        .await;
    projected
        .read_until("the projection holds the session's screen", |client| {
            client.projection.screen().is_some_and(|screen| {
                View::of(screen)
                    .differences(&expected, Parts::Whole)
                    .is_empty()
            })
        })
        .await;
    assert_eq!(direct.replies, 0, "no query reached the terminal");
    assert!(
        direct.performed.is_empty(),
        "nothing happened to the terminal: {:?}",
        direct.performed
    );
}

/// KR-REQ-27.06: in a real session, a client that attaches while a full-screen application is
/// showing its own buffer is sent a restoration that draws that buffer and the shell's lines
/// beneath it; after a soft reset returns the session to the shell's buffer, the client shows it.
///
/// The buffer that is not showing holds a saved cursor here (entering mode 1049 saves one), which
/// no restoration can put in a terminal, so the session draws this client's screen as a projection
/// once the restoration is in: what is checked of the restoration is what every restoration
/// carries, both buffers' rows and which one shows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_arriving_while_the_alternate_buffer_shows_holds_both_buffers() {
    let corpus = corpus("alternate-resets");
    let mut live = Live::start(&corpus, pieces(&corpus, None)).await;
    // The shell's line, then the full-screen application's buffer with its text.
    live.release().await;
    live.release().await;
    let mut direct = live.client(Form::Direct).await;
    let expected = live.canonical().await;
    assert_eq!(
        expected.other.first().map(Line::text).as_deref(),
        Some("shell line"),
        "the shell's line is beneath the application's buffer"
    );
    direct
        .read_until("the restoration draws both buffers", |client| {
            client.shows(&expected, Parts::Buffers)
        })
        .await;
    live.release_all_read_by(&mut direct).await;
    assert!(direct.performed.is_empty(), "{:?}", direct.performed);
    assert_eq!(direct.replies, 0, "no query reached the terminal");
}

/// KR-REQ-27.06: in a real session, a clipboard write, a bell and notifications the program made
/// before a client arrived never happen to that client; the clipboard writes and the bell it makes
/// afterwards happen to the client holding the input lease, once each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_arriving_after_a_clipboard_write_is_never_made_to_perform_it() {
    let corpus = corpus("side-effects");
    let mut live = Live::start(&corpus, pieces(&corpus, None)).await;
    // The clipboard write, the bell and both notifications, then the client.
    for _ in 0..4 {
        live.release().await;
    }
    let mut direct = live.client(Form::Direct).await;
    live.release_all_read_by(&mut direct).await;
    let performed: Vec<String> = direct
        .performed
        .iter()
        .map(|effect| match effect {
            SideEffectKind::ClipboardWrite { content, .. } => {
                format!("clipboard {}", String::from_utf8_lossy(content))
            }
            SideEffectKind::Bell => "bell".to_owned(),
            other => format!("{other:?}"),
        })
        .collect();
    assert_eq!(
        performed,
        vec!["clipboard primary", "bell", "clipboard live"],
        "the terminal performed what came after it arrived, once each, and nothing from before"
    );
    assert_eq!(direct.replies, 0, "no query reached the terminal");
}
