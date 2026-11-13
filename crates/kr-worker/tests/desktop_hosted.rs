//! A desktop-bound worker's disclosed checks, performed on the desktop of a hosted macOS runner.
//!
//! The screen image, the accessible element and the application launch are asked of a worker only
//! when it is bound to a desktop, and this build performs them only on macOS. Performed, they take
//! an image of the screen, read the front application's accessibility tree through System Events and
//! start an application, so on a person's own machine they would raise the system's permission
//! prompts, whose answers are decisions written into its privacy database, and act on the desktop
//! the person is using. The one case here therefore runs
//! only where a desktop belongs to the run: a GitHub-hosted runner, where continuous integration's
//! step for it names it. It is ignored in every ordinary run, and it refuses to run anywhere else
//! before it does anything, so that it fails with a reason beginning "not run" and never reads as
//! passed.
//!
//! What a hosted runner does about the system's permission prompts: nothing. Its image grants
//! Accessibility, and the Automation grant for System Events, to the scripting tool and the shell,
//! and Screen Recording to the shell, the scripting tool and the hosted agent, which is the process
//! the system holds responsible for what a job runs. So no prompt should be raised, and the case
//! answers none. A check that a prompt holds comes back as not answered, and one the system refuses
//! as permission required; either fails the case naming the capability.

#[cfg(target_os = "macos")]
mod common;

/// Whether this run is on a GitHub-hosted runner, whose desktop belongs to the run.
///
/// Anywhere else the desktop is somebody's own, and the checks would act on it. The guard reads the
/// two variables a hosted runner sets, and the one a local runner such as `act` adds to them. It
/// cannot tell a runner from a shell that sets them by hand.
fn on_a_hosted_runner() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok_and(|value| value == "true")
        && std::env::var("RUNNER_ENVIRONMENT").is_ok_and(|value| value == "github-hosted")
        && std::env::var_os("ACT").is_none()
}

/// KR-REQ-03.30, for the three desktop checks that only a desktop-bound worker performs: on a
/// hosted macOS runner, a run of the disclosed checks sends no input to the application in front
/// of the desktop, which is an application of the run's own and holds the focus throughout; writes
/// nothing to the session's terminal; and leaves the file the person nominated and its directory
/// as they were, and no instance of the application the launch check starts running.
///
/// A real session's worker is bound to the runner's desktop, and the control daemon's checks
/// connection asks it for the checks. The request names no check: the worker performs those its
/// own context allows, which are now the file read, the accessible element, the application launch
/// and the screen image, and each of the four answers is held to have been established by the
/// operation itself, so the watchers below had something to watch. The watchers are
///
/// - an application of the run's own, a window with a text field that holds some given text and has
///   the focus, which records every key and mouse button that reaches it, the field's text, and
///   each time it gains or loses the focus: it does not lose the focus from before the checks
///   begin until the person's sentinel has reached it, so whatever a check typed into the
///   application in front was typed into it, and it holds the given text and nothing else, so no
///   check typed into it or changed what it holds;
/// - the session's terminal, whose root program records every byte it reads: it reads the
///   person's sentinel and nothing else;
/// - the file the person nominates, with a file beside it: the names in the directory and each
///   one's bytes, modification time and mode bits are, when the checks have answered, as they
///   were;
/// - the processes of the launch check: none that carries its own mark is left running.
///
/// The person's sentinels are typed after the checks, which is how a recording is known to be
/// complete and the window known to take what is typed: one is typed into the window with System
/// Events, as a person would, and the other through the session's own input path. What a check
/// wrote to the window or the terminal would have come before them.
///
/// Not shown here: input to an application that is not in front, or sent after the checks have
/// answered, which the sentinels cannot show; that nothing else the person owns is changed, which
/// would take the system's privacy database and the runner's other files, and only the nominated
/// tree is compared, and not what was changed in it and put back; that no accessibility action,
/// pointer movement or menu choice reached the window, of which it records the keys, the mouse
/// buttons and the scroll wheel and the text its field holds; the check that sends input, which
/// this build withholds on every platform and which has no record here; a keystroke delivered
/// inside an isolated test context, which no check delivers; and anything on a person's own
/// machine, where the case does not run.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "drives the desktop of the machine it runs on, and refuses to run anywhere but on a GitHub-hosted runner, where continuous integration's step for it runs it with --ignored"]
async fn a_desktop_bound_workers_checks_leave_the_other_application_the_terminal_and_the_files_as_they_were()
 {
    assert!(
        on_a_hosted_runner(),
        "not run: this case drives the desktop of the machine it runs on, and runs only on a \
         GitHub-hosted runner (GITHUB_ACTIONS is true and RUNNER_ENVIRONMENT is github-hosted \
         there, and ACT is not set)"
    );
    #[cfg(target_os = "macos")]
    hosted::run().await;
    #[cfg(not(target_os = "macos"))]
    panic!(
        "not run: this build performs the desktop checks on macOS, and this case drives a macOS \
         desktop"
    );
}

#[cfg(target_os = "macos")]
mod hosted {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Stdio;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use kr_ipc::client::{BoundLink, LocalClient};
    use kr_ipc::endpoint::Listener;
    use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
    use kr_protocol::attachment::{
        AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
    };
    use kr_protocol::desktop::{
        CapabilityEvidenceSource, CapabilityState, DesktopChecksAnswer, DesktopChecksRequest,
        capabilities,
    };
    use kr_protocol::envelope::{ActionTarget, ControlFrame};
    use kr_protocol::hello::PROTOCOL_VERSION;
    use kr_protocol::identity::WorkerProfile;
    use kr_protocol::ids::{
        ActionId, AttachmentId, BuildId, ControllerGeneration, EnvironmentId, RequestId,
        SessionEpoch, SessionId,
    };
    use kr_protocol::local::{ControllerConnectionRole, LocalClientKind};
    use kr_protocol::method::Method;
    use kr_protocol::scalars::{CanonicalSet, Nullable};
    use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, ShellMode};
    use kr_worker::runtime::SessionRuntime;
    use kr_worker::service::{ServiceBinding, WorkerService};
    use kr_worker::session::{Session, SessionConfig};
    use tokio::process::Command;

    use super::common;

    /// How long a wait for something to happen is given. It is what a step that never reaches its
    /// condition fails at, and it decides nothing.
    const LIVENESS: Duration = common::LIVENESS_DEADLINE;

    /// How long building the window program is given: a compile on a hosted runner that is a
    /// quarter of the way through a long job is slow, and the bound only ends a hung one.
    const BUILD_LIVENESS: Duration = Duration::from_secs(600);

    /// How long the answer to the checks request is given. The four checks bound themselves at
    /// 20, 30, 5 and 20 seconds, and the launch waits again for the instance to end; this only
    /// ends a request that never answers.
    const CHECKS_LIVENESS: Duration = Duration::from_secs(300);

    /// The text the window's field holds before anything is typed.
    const GIVEN: &str = "the person's own text: ";

    /// What the person types into the window afterwards. Lower case, digits and a hyphen, so that
    /// each character is one key press on the runner's input source.
    const WINDOW_SENTINEL: &str = "typed-by-the-person-4417";

    /// What the person types into the session's terminal afterwards.
    const TERMINAL_SENTINEL: &[u8] = b"typed-by-the-person-6208";

    fn build() -> BuildId {
        BuildId::new("kr-test/0").expect("a build identifier")
    }

    /// Waits for `future`, and fails naming `what` when it has not finished by the liveness bound.
    /// The bound decides nothing: it ends a step that is hung.
    async fn within<T>(what: &str, future: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(LIVENESS, future)
            .await
            .unwrap_or_else(|_| panic!("{what} did not finish in {LIVENESS:?}"))
    }

    /// One statement for System Events, and what it printed, or what it said when it failed.
    ///
    /// The scripting tool is ended when the wait for it is, so a prompt that holds it never holds
    /// the case.
    async fn system_events(statement: &str) -> Result<String, String> {
        let mut command = Command::new("/usr/bin/osascript");
        command
            .arg("-e")
            .arg(format!("tell application \"System Events\" to {statement}"))
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(LIVENESS, command.output())
            .await
            .map_err(|_| format!("System Events did not answer `{statement}` in {LIVENESS:?}"))?
            .map_err(|error| format!("the scripting tool did not start: {error}"))?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).trim().to_owned())
        }
    }

    /// The application in front, by name and process identifier, for the run's log.
    async fn in_front() -> String {
        system_events("get (name of first process whose frontmost is true) & \", process \" & (unix id of first process whose frontmost is true)")
            .await
            .unwrap_or_else(|error| format!("not read: {error}"))
    }

    /// One thing the window said, read back from its log.
    #[derive(Debug, PartialEq, Eq)]
    enum Said {
        /// The field's whole text.
        Text(String),
        /// A key pressed in the window, as the characters it produced.
        Key(String),
        /// A mouse button pressed in the window.
        Mouse,
        /// The scroll wheel turned over the window.
        Scroll,
        /// Whether typing would land in the field.
        Focus(bool),
    }

    fn unhex(text: &str) -> String {
        let bytes: Vec<u8> = (0..text.len() / 2)
            .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hexadecimal"))
            .collect();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// The lines of a window log that were written whole.
    fn said(log: &Path) -> Vec<Said> {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        text.split_inclusive('\n')
            .filter_map(|line| line.strip_suffix('\n'))
            .map(|line| {
                let parts: Vec<&str> = line.split(' ').collect();
                match parts[..] {
                    ["text", hex] => Said::Text(unhex(hex)),
                    ["key", hex, _code] => Said::Key(unhex(hex)),
                    ["mouse", _kind] => Said::Mouse,
                    ["scroll"] => Said::Scroll,
                    ["focus", flag] => Said::Focus(flag == "1"),
                    _ => panic!("the window wrote a line that is not one of its own: {line:?}"),
                }
            })
            .collect()
    }

    /// An application of the run's own: a window with a text field, in front of the desktop.
    struct Window {
        child: tokio::process::Child,
        pid: u32,
        log: PathBuf,
        errors: PathBuf,
    }

    impl Window {
        /// Builds the window program from its source and starts it.
        async fn start(directory: &Path) -> Self {
            let source = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("desktop_window.swift");
            let program = directory.join("desktop_window");
            let mut compile = Command::new("/usr/bin/xcrun");
            compile
                .args(["swiftc", "-swift-version", "5", "-O", "-o"])
                .arg(&program)
                .arg(&source)
                .stdin(Stdio::null())
                .kill_on_drop(true);
            let built = tokio::time::timeout(BUILD_LIVENESS, compile.output())
                .await
                .expect("the window program is built in time")
                .expect("the compiler starts");
            assert!(
                built.status.success(),
                "the window program was not built: {}",
                String::from_utf8_lossy(&built.stderr)
            );

            let log = directory.join("window.log");
            let errors = directory.join("window.errors");
            let child = Command::new(&program)
                .arg(&log)
                .arg(GIVEN)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(
                    std::fs::File::create(&errors).expect("a file for what the window says"),
                ))
                .kill_on_drop(true)
                .spawn()
                .expect("the window program starts");
            let pid = child.id().expect("a process identifier");
            Self {
                child,
                pid,
                log,
                errors,
            }
        }

        fn said(&self) -> Vec<Said> {
            said(&self.log)
        }

        /// Holds that the window program is still running, and says what it printed when it is not.
        fn assert_running(&mut self) {
            assert!(
                self.child.try_wait().expect("the window's state").is_none(),
                "the window program ended: {}",
                std::fs::read_to_string(&self.errors).unwrap_or_default()
            );
        }

        /// Brings the window to the front, as the person would, and waits until it says typing
        /// would land in its field.
        ///
        /// System Events does not know the process until the window has been shown, so asking it
        /// to bring the window forward is repeated until the window itself says it has the focus.
        async fn take_the_focus(&mut self) {
            let started = Instant::now();
            loop {
                self.assert_running();
                let _ = system_events(&format!(
                    "set frontmost of (first process whose unix id is {}) to true",
                    self.pid
                ))
                .await;
                let focus = self.said().into_iter().rev().find_map(|line| match line {
                    Said::Focus(focus) => Some(focus),
                    _ => None,
                });
                if focus == Some(true) {
                    return;
                }
                assert!(
                    started.elapsed() < LIVENESS,
                    "waited {LIVENESS:?} for the window to have the focus; it said {:?} and \
                     the application in front is {}",
                    self.said(),
                    in_front().await
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    /// One path as the person left it: its modification time and its permission bits.
    #[derive(Debug, PartialEq, Eq)]
    struct Left {
        modified: std::time::SystemTime,
        mode: u32,
    }

    fn left(path: &Path) -> Left {
        let metadata = std::fs::metadata(path).expect("the path's metadata");
        Left {
            modified: metadata.modified().expect("a modification time"),
            mode: metadata.permissions().mode(),
        }
    }

    /// What is around one nominated file: the directory as the person left it, which moves its
    /// modification time when a name is added, removed or renamed, and every name in it with its
    /// bytes, its modification time and its mode bits.
    fn directory_state(directory: &Path) -> (Left, Vec<(String, Vec<u8>, Left)>) {
        let mut names: Vec<_> = std::fs::read_dir(directory)
            .expect("lists the directory")
            .map(|entry| {
                let path = entry.expect("an entry").path();
                (
                    path.file_name()
                        .expect("a name")
                        .to_string_lossy()
                        .into_owned(),
                    std::fs::read(&path).expect("reads the file"),
                    left(&path),
                )
            })
            .collect();
        names.sort_by(|first, second| first.0.cmp(&second.0));
        (left(directory), names)
    }

    /// The processes that carry the launch check's own mark, which no run of it may leave behind.
    ///
    /// The mark names the process that made it, and the worker is this one.
    async fn instances_the_launch_left() -> String {
        let mut lister = Command::new("/usr/bin/pgrep");
        lister
            .arg("-f")
            .arg(format!(
                "kalareach-capability-check-{}-",
                std::process::id()
            ))
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = within("the process lister", lister.output())
            .await
            .expect("the process lister runs");
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "the process lister failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A worker for a desktop-bound session, serving its endpoint in this process, and the session's
    /// terminal: a program that keeps every byte it reads.
    struct Worker {
        _service: Arc<WorkerService>,
        runtime: Arc<SessionRuntime>,
        session_id: SessionId,
        environment_id: EnvironmentId,
        endpoint: kr_ipc::paths::Endpoint,
        controller: Arc<ControllerIdentity>,
        boot: kr_protocol::identity::BootIdentity,
        // Declared last: the directory is removed after every field above has let go of its files.
        _temp: kr_ipc::testing::TempHost,
    }

    impl Worker {
        async fn start(received: &Path) -> Self {
            let temp = kr_ipc::testing::TempHost::create();
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
            let store = kr_crypto::store::open_store_in(&environment.secrets_dir())
                .expect("a secret store");
            let controller = Arc::new(
                ControllerIdentity::initialise(store.store.as_ref(), environment_id)
                    .expect("a controller identity"),
            );
            let journal_path = environment.journal_database(session_id);
            if let Some(parent) = journal_path.parent() {
                std::fs::create_dir_all(parent).expect("the journal directory");
            }

            // Bound to the desktop this runner's login session gives it, as a worker is that the
            // host starts for a session that asked for one.
            let desktop = kr_worker::desktop::context(WorkerProfile::DesktopBound, boot.clone());
            println!(
                "the desktop this worker is bound to: graphic access {}, {:?}, {:?}, {:?}",
                desktop.graphic_access, desktop.availability, desktop.display_server, desktop.kind
            );
            assert!(
                desktop.graphic_access,
                "this runner gave the worker no desktop to be bound to, so none of the three \
                 desktop checks would be asked of it: {desktop:?}"
            );
            let script = format!(
                "stty raw -echo; printf 'kr-ready.'; exec {} {}",
                common::KEEPS_WHAT_IT_READS,
                kr_worker::testing::shell_quoted(received)
            );
            let config = SessionConfig {
                session_id,
                session_epoch: SessionEpoch::V1,
                environment_id,
                display_number: DisplayNumber::new(1),
                shell: kr_worker::testing::posix_script(&script),
                shell_mode: ShellMode::NativeCompat,
                worker_profile: WorkerProfile::DesktopBound,
                desktop: kr_worker::desktop::binding(&desktop),
                dimensions: Dimensions::new(80, 24),
                journal_path: Some(journal_path.clone()),
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
                        boot_identity: boot.clone(),
                        controller_public_key: *controller.public_key(),
                        controller_generation: ControllerGeneration::new(1),
                        journal_path: Some(journal_path),
                        build_id: build(),
                    },
                )
                .expect("a worker service"),
            );
            tokio::spawn(Arc::clone(&service).serve(listener));
            Self {
                _temp: temp,
                _service: service,
                runtime,
                session_id,
                environment_id,
                endpoint,
                controller,
                boot,
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

        /// The person at the terminal: a client that holds the input lease.
        async fn person(&self) -> (LocalClient, common::Keys) {
            common::retained_carrying(&self.runtime, b"kr-ready.", 1, LIVENESS).await;
            let mut client = within(
                "the person's connection to the worker",
                LocalClient::connect(&self.endpoint, LocalClientKind::Cli, build()),
            )
            .await
            .expect("connects");
            let mut requested = CanonicalSet::new();
            requested.insert(AttachmentCapability::ObserveTerminal);
            requested.insert(AttachmentCapability::Input);
            let attached: SessionAttachResult = within(
                "the person's attachment to the session",
                client.mutate(
                    Method::SessionAttach,
                    ActionId::new(kr_ipc::new_uuid()),
                    self.target(),
                    &SessionAttachParams {
                        session_id: self.session_id,
                        mode: AttachMode::Terminal,
                        claim_geometry: false,
                        dimensions: Nullable::some(Dimensions::new(80, 24)),
                        terminal_profile_id: Nullable(Some("xterm-256color".to_owned())),
                        requested,
                    },
                ),
            )
            .await
            .expect("reaches the worker")
            .expect("attaches")
            .to_typed()
            .expect("decodes");
            let attachment: AttachmentId = attached.attachment.attachment_id;
            let keys = within(
                "the person's input lease",
                common::take_the_keys(
                    &mut client,
                    self.environment_id,
                    self.session_id,
                    attachment,
                ),
            )
            .await;
            (client, keys)
        }

        /// The control daemon's checks connection, speaking for generation one.
        async fn daemon(&self) -> BoundLink {
            let mut link = BoundLink::connect(&self.endpoint, build())
                .await
                .expect("connects");
            let role = ControllerConnectionRole::Checks;
            link.send(&ControlFrame::ControllerRole(role))
                .await
                .expect("declares the role");
            match link.recv().await.expect("the worker answers") {
                ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
                other => panic!("the worker answered {other:?}"),
            }
            let identity = Arc::clone(&self.controller);
            let boot = self.boot.clone();
            link.present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(1), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            })
            .await
            .expect("the worker accepts the generation");
            link
        }
    }

    /// Holds that the window had the focus when the checks began, `from` lines into its log, and
    /// has not lost it since.
    ///
    /// A check that moved the focus would send whatever it typed next to another application,
    /// which this window could not have seen, so a run in which the window lost the focus shows
    /// nothing about what a check typed. What the window did while it was first being shown is
    /// not held to this: the case begins to watch once the window says it has the focus.
    fn kept_the_focus(said: &[Said], from: usize, until: &str) {
        let had = said[..from].iter().rev().find_map(|line| match line {
            Said::Focus(focus) => Some(*focus),
            _ => None,
        });
        assert_eq!(
            had,
            Some(true),
            "the window did not have the focus when the checks began: {said:?}"
        );
        assert!(
            !said[from..].contains(&Said::Focus(false)),
            "the window lost the focus before {until}, so what was typed after that may have gone \
             to another application, and nothing in this window shows what a check sent: {said:?}"
        );
    }

    /// Asks the worker for the checks, naming `file` for the read, and waits for the answer.
    async fn ask(link: &mut BoundLink, worker: &Worker, file: &str) -> DesktopChecksAnswer {
        within(
            "the checks request being written",
            link.send(&ControlFrame::DesktopChecks(DesktopChecksRequest {
                request_id: RequestId::new(1),
                environment_id: worker.environment_id,
                authorised_file: Nullable(Some(file.to_owned())),
            })),
        )
        .await
        .expect("writes the request");
        let answer = tokio::time::timeout(CHECKS_LIVENESS, async {
            loop {
                match link.recv().await.expect("the worker answers") {
                    ControlFrame::DesktopChecksAnswer(found) => return found,
                    ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                    other => panic!("the worker answered {other:?}"),
                }
            }
        })
        .await
        .expect("the worker answers in time");
        *answer
    }

    pub async fn run() {
        let scratch = tempfile::tempdir().expect("a directory of this run's own");
        let received = scratch.path().join("received");

        // The person's application, in front, before anything is asked of the worker.
        let mut window = Window::start(scratch.path()).await;
        window.take_the_focus().await;
        println!("in front before the checks: {}", in_front().await);
        assert_eq!(
            window.said().first(),
            Some(&Said::Text(GIVEN.to_owned())),
            "the field starts with the given text"
        );
        // What the window says from here on is what the checks did to it: it has the focus now.
        let from = window.said().len();

        // The person's file and the file beside it, in a directory of their own.
        let tree = tempfile::tempdir().expect("a directory of this run's own");
        let file = tree.path().join("authorised.txt");
        std::fs::write(&file, b"the person nominated this").expect("the nominated file");
        std::fs::write(tree.path().join("beside.txt"), b"not nominated").expect("another file");
        // A mode the process's umask would not give a new file, so that a check that set the mode
        // to the usual one, or to the owner's alone, changes it whatever the umask is.
        for name in ["authorised.txt", "beside.txt"] {
            std::fs::set_permissions(tree.path().join(name), PermissionsExt::from_mode(0o640))
                .expect("a mode of the run's choosing");
        }
        let before = directory_state(tree.path());
        assert_eq!(
            instances_the_launch_left().await,
            "",
            "no launch is under way yet"
        );

        let worker = Worker::start(&received).await;
        let (client, mut keys) = worker.person().await;
        let mut daemon = within("the daemon's checks connection", worker.daemon()).await;

        let answer = ask(
            &mut daemon,
            &worker,
            file.to_str().expect("a path that is text"),
        )
        .await;
        println!("in front after the checks: {}", in_front().await);

        // The checks were performed: each record is the operation having been performed and
        // answered, and none names synthetic input.
        let mut found: Vec<&str> = answer
            .records
            .iter()
            .map(|record| record.capability.as_str())
            .collect();
        found.sort_unstable();
        assert_eq!(
            found,
            [
                capabilities::ACCESSIBILITY,
                capabilities::APPLICATION_LAUNCH,
                capabilities::AUTHORISED_FILE_READ,
                capabilities::SCREEN_CAPTURE,
            ],
            "a desktop-bound worker is asked for the file read and the three desktop checks, and \
             never for the one that sends input: {:?}",
            answer.records
        );
        for record in &answer.records {
            println!(
                "{}: {:?}, {:?}: {:?}",
                record.capability.as_str(),
                record.state,
                record.evidence_source,
                record.disabled_reason
            );
            assert_eq!(
                record.evidence_source,
                CapabilityEvidenceSource::DisclosedProbe,
                "{record:?}"
            );
            assert_eq!(
                record.state,
                CapabilityState::QualifiedAvailable,
                "{} was not established, so what it did to the desktop was not watched: {:?}",
                record.capability.as_str(),
                record.disabled_reason
            );
        }

        // The person's file and the directory around it.
        assert_eq!(
            directory_state(tree.path()),
            before,
            "the person's files are as they were after the checks"
        );
        // The application the launch check started.
        assert_eq!(
            instances_the_launch_left().await,
            "",
            "the launch check left an application it started running"
        );
        // The window has the focus still: it has not lost it since the checks began.
        kept_the_focus(&window.said(), from, "the checks had answered");

        // The person types into the window, which has the focus, and the window is read once it
        // holds that: what a check typed would have come before it.
        window.assert_running();
        let typed = system_events(&format!("keystroke \"{WINDOW_SENTINEL}\"")).await;
        assert!(
            typed.is_ok(),
            "the person's keystrokes were refused: {typed:?}"
        );
        let expected = format!("{GIVEN}{WINDOW_SENTINEL}");
        let started = Instant::now();
        loop {
            window.assert_running();
            let said = window.said();
            // A window that lost the focus never receives the sentinel, so the wait ends here
            // with the reason rather than at its bound.
            kept_the_focus(&said, from, "the person's sentinel had reached the window");
            let last_text = said.into_iter().rev().find_map(|line| match line {
                Said::Text(text) => Some(text),
                _ => None,
            });
            if last_text.is_some_and(|text| text.ends_with(WINDOW_SENTINEL)) {
                break;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "waited {LIVENESS:?} for what the person typed to reach the window; it said \
                 {:?} and the application in front is {}",
                window.said(),
                in_front().await
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let said = window.said();
        kept_the_focus(&said, from, "the person's sentinel had been typed");
        let pressed: Vec<&str> = said
            .iter()
            .filter_map(|line| match line {
                Said::Key(characters) => Some(characters.as_str()),
                _ => None,
            })
            .collect();
        let sentinel: Vec<String> = WINDOW_SENTINEL.chars().map(String::from).collect();
        assert_eq!(
            pressed, sentinel,
            "the keys that reached the window are those the person typed and no key a check sent: {said:?}"
        );
        assert!(
            !said
                .iter()
                .any(|line| matches!(line, Said::Mouse | Said::Scroll)),
            "a mouse button or the wheel reached the window: {said:?}"
        );
        for line in &said {
            if let Said::Text(text) = line {
                assert!(
                    text.starts_with(GIVEN) && expected.starts_with(text.as_str()),
                    "the field held {text:?}, which is the given text with some of what the \
                     person typed and nothing else: {said:?}"
                );
            }
        }
        assert_eq!(
            said.iter().rev().find_map(|line| match line {
                Said::Text(text) => Some(text.as_str()),
                _ => None,
            }),
            Some(expected.as_str()),
            "the window holds the given text and what the person typed"
        );

        // The person types into the session's terminal, and the recording is read once it holds
        // that: what a check wrote to the terminal would have come before it.
        keys.type_bytes(&worker.runtime, TERMINAL_SENTINEL);
        let started = Instant::now();
        loop {
            if std::fs::read(&received).is_ok_and(|seen| common::carries(&seen, TERMINAL_SENTINEL))
            {
                break;
            }
            assert!(
                started.elapsed() < LIVENESS,
                "waited {LIVENESS:?} for what the person typed to reach the terminal's program"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            std::fs::read(&received).expect("the recording"),
            TERMINAL_SENTINEL,
            "what reached the terminal's program is what the person typed and nothing a check wrote"
        );

        drop(daemon);
        drop(client);
        worker
            .runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
        within("ending the window program", window.child.kill())
            .await
            .expect("the window program is ended");
    }
}
