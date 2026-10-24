//! A real daemon and a real worker on Windows, in a tree of a test's own, and a terminal attached
//! to a session of the worker's.
//!
//! The daemon runs in this process and starts each worker through the environment's scheduled
//! task, so a session's worker is a process of its own outside the test's job, as it is in an
//! installation. A test types into the session's root shell through the terminal it attaches, and
//! reads what the session writes.

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::BuildId;
use kr_protocol::local::LocalClientKind;
use kr_protocol::scalars::Nullable;

use crate::support::kr;
use crate::teardown;

/// How long a wait for the daemon or the session is given before the test calls it a failure.
pub const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// The build identity `kr` and a test present to the daemon.
pub fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A terminal attached to a real worker's session, holding its keys: what it types reaches the
/// session's root shell, and what the session writes reaches it.
pub struct WorkerTerminal {
    client: LocalClient,
    session_id: kr_protocol::ids::SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    seen: String,
}

impl WorkerTerminal {
    /// Attaches to the session's worker through its own descriptor and endpoint, at the session's
    /// own size, takes the keys and subscribes to what the session writes.
    ///
    /// At the session's size the worker streams the session's output as it is written. A terminal
    /// of another size that holds no geometry of its own is drawn a projection of the screen
    /// instead, which carries none of the session's output events.
    pub async fn attach(
        environment: &kr_ipc::paths::EnvironmentPaths,
        session_id: kr_protocol::ids::SessionId,
        dimensions: kr_protocol::session::Dimensions,
    ) -> Self {
        use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
        use kr_protocol::envelope::ActionTarget;
        use kr_protocol::ids::ActionId;
        use kr_protocol::method::Method;
        use kr_protocol::scalars::CanonicalSet;

        let descriptor = kr_ipc::descriptor::read_all(environment)
            .expect("reads the runtime directory")
            .into_iter()
            .filter_map(|entry| entry.descriptor.ok())
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("the session's descriptor is published");
        let endpoint =
            kr_ipc::paths::Endpoint::from_path(&descriptor.endpoint).expect("an endpoint");
        let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
            .await
            .expect("reaches the worker");
        client
            .verify_worker(&descriptor)
            .await
            .expect("the worker answers the descriptor's challenge");
        let target = ActionTarget {
            environment_id: descriptor.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                target.clone(),
                &SessionAttachParams {
                    session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker attaches the terminal")
            .to_typed()
            .expect("decodes");
        let attachment_id = attached.attachment.attachment_id;
        let lease: kr_protocol::input::InputAcquireResult = client
            .mutate(
                Method::InputAcquire,
                ActionId::new(kr_ipc::new_uuid()),
                target,
                &kr_protocol::input::InputAcquireParams {
                    session_id,
                    attachment_id,
                    expected_epoch: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker hands this terminal the keys")
            .to_typed()
            .expect("decodes");
        let mut streams = CanonicalSet::new();
        streams.insert(kr_protocol::recovery::EventStream::Output);
        // The subscription is the last call: a client drops what arrives while it waits for an
        // answer of its own, and the screen it is drawn is queued the moment it subscribes.
        client
            .request(
                Method::EventsSubscribe,
                &kr_protocol::recovery::EventsSubscribeParams {
                    session_id,
                    attachment_id,
                    streams,
                    from_cursor: Nullable::null(),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker subscribes the terminal");
        Self {
            client,
            session_id,
            attachment_id,
            epoch: lease.lease.epoch,
            sequence: 0,
            seen: String::new(),
        }
    }

    /// Types one line into the session's root shell, ending it with the carriage return the Enter
    /// key sends, which is what the pseudo-console takes as the end of a line.
    pub async fn type_line(&mut self, line: &str) {
        let _: kr_protocol::input::InputWriteResult = self
            .client
            .request(
                kr_protocol::method::Method::InputWrite,
                &kr_protocol::input::InputWriteParams {
                    session_id: self.session_id,
                    attachment_id: self.attachment_id,
                    epoch: self.epoch,
                    sequence: kr_protocol::ids::InputSequence::new(self.sequence),
                    bytes: kr_protocol::scalars::Bytes::new(format!("{line}\r").into_bytes()),
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the worker takes the line")
            .to_typed()
            .expect("decodes");
        self.sequence += 1;
    }

    /// What the session has written so far, with its control sequences and line breaks taken out,
    /// so text the console wrapped or redrew reads as one run.
    pub fn text(&self) -> String {
        let mut plain = String::new();
        let mut characters = self.seen.chars().peekable();
        while let Some(character) = characters.next() {
            match character {
                '\u{1b}' => {
                    // A control sequence: ESC, then `[` and parameters up to a final letter, or `]`
                    // up to BEL or ST, or one character.
                    match characters.next() {
                        Some('[') => {
                            for next in characters.by_ref() {
                                if next.is_ascii_alphabetic() || next == '~' {
                                    break;
                                }
                            }
                        }
                        Some(']') => {
                            while let Some(next) = characters.next() {
                                if next == '\u{7}' {
                                    break;
                                }
                                if next == '\u{1b}' && characters.peek() == Some(&'\\') {
                                    characters.next();
                                    break;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                '\r' | '\n' => {}
                other if other.is_control() => {}
                other => plain.push(other),
            }
        }
        plain
    }

    /// Waits until the session has written `pattern`, as [`Self::text`] reads it, and returns it all.
    pub async fn shown(&mut self, pattern: &str, what: &str) -> String {
        let started = tokio::time::Instant::now();
        let deadline = started + LIVENESS_DEADLINE;
        while !self.text().contains(pattern) {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.client.recv()).await {
                Ok(Ok(kr_protocol::envelope::ControlFrame::Notification(notification)))
                    if notification.event_type.as_str() == "session.output" =>
                {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        self.seen
                            .push_str(&String::from_utf8_lossy(event.bytes.as_slice()));
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!(
                    "{what}: waited {:?} for {pattern:?} and the connection ended ({error}): {}",
                    started.elapsed(),
                    self.text()
                ),
                Err(_) => panic!(
                    "{what}: waited {:?} for {pattern:?}; the session wrote {} bytes: {:?}",
                    started.elapsed(),
                    self.seen.len(),
                    self.seen
                ),
            }
        }
        self.text()
    }
}

/// A daemon this test hosts for its own tree, on loopback as [`Host`]'s is, starting each worker
/// through the environment's scheduled task: the task's starter creates the worker, so a session's
/// worker is a process of its own outside this test's job.
pub struct WorkerHost {
    pub tree: teardown::Tree,
    _task: kr_controller::supervision::windows::testing::TestTask,
    controller: Option<std::sync::Arc<kr_controller::service::Controller>>,
    serving: Vec<tokio::task::JoinHandle<kr_controller::Result<()>>>,
}

/// A tree with the environment's task registered and the programs a session needs placed on it,
/// and no daemon yet: a test puts what the daemon reads on first start there, and then starts it.
pub struct Prepared {
    pub tree: teardown::Tree,
    task: kr_controller::supervision::windows::testing::TestTask,
    worker: PathBuf,
}

impl Prepared {
    /// Places the tree: its configuration, the environment's task, and beside the worker the
    /// programs it starts (the forwarder a launch goes through and the plugin host), each when the
    /// workspace has built it.
    pub fn new() -> Self {
        use kr_controller::supervision::windows::testing::{TestTask, built_binary};

        let tree = teardown::Tree::create();
        let environment = tree.environment();
        let mut document = ConfigurationDocument::empty();
        document.revision = 1;
        document.network.enabled = Nullable::some(true);
        document.network.bind_address = Nullable::some("127.0.0.1:0".to_owned());
        let path = kr_worker::config::document_path(&environment);
        std::fs::create_dir_all(path.parent().expect("the document has a directory"))
            .expect("the state directory");
        kr_ipc::paths::write_owner_only_file(
            &path,
            kr_protocol::hostinfo::configuration::contents(&document).as_bytes(),
        )
        .expect("the configuration document");
        let starter = built_binary("kr-controller").unwrap_or_else(|missing| panic!("{missing}"));
        let task = TestTask::register(&environment, &starter)
            .unwrap_or_else(|failure| panic!("the environment's task: {failure}"));
        let worker = tree.root().join("kr-worker.exe");
        kr_ipc::testing::place_and_start_once(
            &built_binary("kr-worker").unwrap_or_else(|missing| panic!("{missing}")),
            &worker,
            &["--version"],
        );
        for beside in ["kr-hook", "kr-plugin-host"] {
            if let Ok(built) = built_binary(beside) {
                kr_ipc::testing::place_and_start_once(
                    &built,
                    &tree.root().join(format!("{beside}.exe")),
                    &["--version"],
                );
            }
        }
        Self { tree, task, worker }
    }

    /// Starts the daemon on this tree, reading shell packages from `packages` when it is given.
    pub async fn start(self, packages: Option<PathBuf>) -> WorkerHost {
        use kr_controller::service::{Controller, ControllerSetup};

        let Self { tree, task, worker } = self;
        let environment = tree.environment();
        let environment_id = environment.environment_id();
        let secrets = environment.secrets_dir();
        let controller = Controller::start(ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store = kr_crypto::store::open_store_in(&secrets).expect("a secret store");
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    store.store.as_ref(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: kr_crypto::store::StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: tree.supervisor(Box::new(task.supervisor(&environment))),
            worker_program: worker,
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: packages,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        })
        .await
        .expect("the daemon starts");
        let rendezvous = kr_ipc::endpoint::Listener::bind(
            &environment.rendezvous_endpoint().expect("an endpoint"),
        )
        .expect("binds the rendezvous");
        let clients = kr_ipc::endpoint::Listener::bind(
            &environment.controller_endpoint().expect("an endpoint"),
        )
        .expect("binds the client endpoint");
        let serving = vec![
            tokio::spawn(std::sync::Arc::clone(&controller).serve_rendezvous(rendezvous)),
            tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(clients)),
        ];
        WorkerHost {
            tree,
            _task: task,
            controller: Some(controller),
            serving,
        }
    }
}

impl WorkerHost {
    pub async fn start() -> Self {
        Prepared::new().start(None).await
    }

    /// The daemon this host runs.
    ///
    /// # Panics
    ///
    /// Panics when the daemon has been dropped.
    pub fn controller(&self) -> std::sync::Arc<kr_controller::service::Controller> {
        std::sync::Arc::clone(self.controller.as_ref().expect("the daemon is running"))
    }

    /// Seeds the catalogue from the generation compiled into this build, as the shipped daemon does
    /// at every start: the bundled agents' packages are installed and admitted.
    ///
    /// # Panics
    ///
    /// Panics when the bundle is not whole.
    pub async fn seed_bundled_agents(&self) {
        let bundle = kr_plugin_catalogue::SeedBundle::embedded().expect("a whole bundle");
        let outcome = self
            .controller
            .as_ref()
            .expect("the daemon is running")
            .seed_catalogue(&bundle)
            .await;
        eprintln!("the bundled catalogue: {}", outcome.report());
        assert!(outcome.failure.is_none(), "{}", outcome.report());
    }

    /// Runs `kr` against this host's directories, on plain pipes, with `extra` set over the
    /// account's own environment, and returns what it printed and how it ended.
    pub async fn kr(&self, arguments: &[&str], extra: &[(&str, &str)]) -> std::process::Output {
        let runtime_root = self.tree.paths().runtime_root().to_path_buf();
        let state_root = self.tree.paths().state_root().to_path_buf();
        let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
        let extra: Vec<(String, String)> = extra
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        tokio::task::spawn_blocking(move || {
            let mut command = std::process::Command::new(kr());
            command
                .args(&arguments)
                .env("KR_RUNTIME_DIR", runtime_root)
                .env("KR_STATE_DIR", state_root)
                .stdin(std::process::Stdio::null());
            for (name, value) in extra {
                command.env(name, value);
            }
            command.output().expect("kr runs")
        })
        .await
        .expect("kr is waited for")
    }

    /// Runs `kr new --invisible --headless` in this host's directory with `arguments` after it,
    /// through this host's daemon, and returns what it printed.
    ///
    /// The session has no desktop of its own: the account these tests run as may have none, and a
    /// session that is not a window is what they read.
    pub async fn kr_new(&self, arguments: &[&str]) -> Created {
        let cwd = self.tree.root().display().to_string();
        let mut words = vec!["--json", "new", "--invisible", "--headless", "--cwd", &cwd];
        words.extend_from_slice(arguments);
        let output = self.kr(&words, &[]).await;
        let document = serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
        Created { output, document }
    }
}

/// What `kr new` printed and how it ended.
pub struct Created {
    pub output: std::process::Output,
    pub document: serde_json::Value,
}

impl Created {
    /// Whether the session was created.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.output.status.success()
    }

    /// What `kr` said when it did not create one, as the person reads it.
    #[must_use]
    pub fn said(&self) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&self.output.stdout),
            String::from_utf8_lossy(&self.output.stderr)
        )
    }

    /// The session that was created, with its size.
    ///
    /// # Panics
    ///
    /// Panics when no session was created.
    #[must_use]
    pub fn session(
        &self,
    ) -> (
        kr_protocol::ids::SessionId,
        kr_protocol::session::Dimensions,
    ) {
        assert!(self.succeeded(), "kr new: {}", self.said());
        let size = |axis: &str| {
            self.document["dimensions"][axis]
                .as_u64()
                .unwrap_or_else(|| panic!("the session's {axis}: {}", self.document))
        };
        (
            self.document["session_id"]
                .as_str()
                .expect("a session identifier")
                .parse()
                .expect("parses"),
            kr_protocol::session::Dimensions::new(size("columns"), size("rows")),
        )
    }
}

impl Drop for WorkerHost {
    fn drop(&mut self) {
        for task in &self.serving {
            task.abort();
        }
        drop(self.controller.take());
    }
}
