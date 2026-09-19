//! The qualification corpus under `tests/shells/`, and the sessions each case drives.
//!
//! Section 7 says the managed packages are qualified against the startup customisations people
//! actually run: zsh-autosuggestions, zsh-syntax-highlighting, Powerlevel10k with its instant
//! prompt, starship, oh-my-zsh, fzf's widgets, atuin and ordinary distribution customisations. The
//! corpus is that list as data: one directory per shell and stack, holding the startup files the
//! case installs and the checks it claims, and one list per shell of the combinations that do not
//! exist, each with its reason.
//!
//! The stacks themselves are pinned in `fixtures/shells/stacks.lock` and fetched once by
//! `scripts/fetch-shell-stacks.sh`. Nothing here reaches the network: a case reads the index that
//! script wrote, and a stack that index calls unreachable is a stack this run did not qualify.
//!
//! Nothing a launched process touches is inside the workspace. The shell's executable is the
//! installed package and the case's home, runtime directory and endpoint are on the internal disk,
//! which is what keeps a rebuilt binary from asking the person at the machine for permission.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hmac::{Hmac, KeyInit, Mac};
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::Uuid;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::contract::transport::{
    BOOTSTRAP_SECRET_LEN, BridgeEndpoint, BridgeFrame, HandshakeOutcome, ObservedPeer,
    ProofVerdict, WorkerExpectation, bootstrap_transcript, decide_handshake,
};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::Deserialize;

use super::*;

/// The token a case's startup file puts where the package's own marked entry belongs.
///
/// A case that names it says where in its own startup the integration is activated, which is what
/// makes "the normal profile order is preserved" something the corpus states rather than assumes.
pub const ENTRY_TOKEN: &str = "# {kalareach-entry}";

/// What the person's binding writes into the line when the key they bound is pressed.
pub const USER_BINDING_TEXT: &str = "kr-user-binding-ran";

/// The key the person's own binding is on, in every case: `ESC q` on the three Unix readers and
/// `Alt+q` on the editor that reads a chord, which is the same two bytes at the terminal.
pub const USER_BINDING_KEY: &[u8] = &[0x1b, b'q'];

/// One stack, as `scripts/fetch-shell-stacks.sh` left it.
#[derive(Clone, Debug, Deserialize)]
pub struct InstalledStack {
    pub id: String,
    pub version: String,
    /// `installed`, `unreachable` or `unsupported_platform`.
    pub status: String,
    pub root: Option<String>,
    pub executable: Option<String>,
    pub url: Option<String>,
    pub sha256: Option<String>,
    pub reason: Option<String>,
}

impl InstalledStack {
    #[must_use]
    pub fn installed(&self) -> bool {
        self.status == "installed"
    }
}

/// The index that script writes beside the trees it unpacked.
#[derive(Clone, Debug, Deserialize)]
pub struct StackIndex {
    pub platform: String,
    pub lock_sha256: String,
    pub stacks: Vec<InstalledStack>,
}

impl StackIndex {
    /// Reads the index, or says why there is none.
    ///
    /// # Errors
    ///
    /// Returns the reason a run has no stacks: the fetcher has not run on this host.
    pub fn read() -> Result<Self, String> {
        let path = stack_cache().join("index.json");
        let body = std::fs::read_to_string(&path).map_err(|error| {
            format!(
                "{} is not here ({error}); run scripts/fetch-shell-stacks.sh",
                path.display()
            )
        })?;
        serde_json::from_str(&body)
            .map_err(|error| format!("{} does not decode: {error}", path.display()))
    }

    #[must_use]
    pub fn get(&self, id: &str) -> Option<&InstalledStack> {
        self.stacks.iter().find(|stack| stack.id == id)
    }
}

/// One pinned stack in `fixtures/shells/stacks.lock`.
#[derive(Clone, Debug, Deserialize)]
pub struct LockedStack {
    pub id: String,
    pub name: String,
    pub version: String,
    /// `source` for a tree the startup file reads, `program` for one it runs.
    pub role: String,
    pub program: Option<String>,
    pub shells: Vec<String>,
    pub entry: Option<String>,
    pub sources: Vec<LockedSource>,
}

/// One platform's archive for a pinned stack.
#[derive(Clone, Debug, Deserialize)]
pub struct LockedSource {
    pub platform: String,
    pub url: String,
    pub sha256: String,
    #[serde(default)]
    pub strip_components: u32,
}

/// The pinned set.
#[derive(Clone, Debug, Deserialize)]
pub struct StackLock {
    pub lock_version: u32,
    pub description: String,
    pub stacks: Vec<LockedStack>,
}

impl StackLock {
    /// Reads the pinned set.
    ///
    /// # Panics
    ///
    /// Panics when the lock is missing or does not decode: it is committed beside the corpus, so
    /// either is a corpus that has been taken apart rather than a run-time condition.
    #[must_use]
    pub fn read() -> Self {
        let path = repository_root().join("fixtures/shells/stacks.lock");
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        serde_json::from_str(&body)
            .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display()))
    }
}

/// One file a case installs under its own home.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HomeFile {
    /// The file in the case's `home/` directory.
    pub file: String,
    /// Where it goes, relative to the session's home directory.
    pub path: String,
}

/// A native module a case installs that the shell cannot load.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeModuleCase {
    pub name: String,
    /// The word the startup file records when the load was refused.
    pub marker: String,
    /// What this case can and cannot prove, stated in the corpus rather than in a comment.
    pub note: String,
}

/// One combination of a shell and a startup customisation.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationCase {
    pub id: String,
    pub shell: ShellKind,
    /// The customisation this case runs, by the identifier the pinned set uses, or `none`,
    /// `distribution` or `native-module` for the three that are not pinned archives.
    pub stack: String,
    pub title: String,
    pub supported: bool,
    #[serde(default)]
    pub reason: Option<String>,
    /// The pinned stacks this case needs installed.
    pub requires: Vec<String>,
    /// The markers the case's startup writes, in the order it writes them.
    pub order: Vec<String>,
    /// What the person's own binding is called.
    pub binding: String,
    /// What this case claims to prove.
    pub checks: Vec<String>,
    #[serde(default)]
    pub native_module: Option<NativeModuleCase>,
    pub covers: Vec<String>,
    pub home: Vec<HomeFile>,
    /// Where the case was read from. Not part of the file.
    #[serde(skip)]
    pub directory: PathBuf,
}

/// A combination that does not exist, with the reason it does not.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedStack {
    pub stack: String,
    pub reason: String,
}

/// Every combination one shell does not have.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedList {
    pub shell: ShellKind,
    pub unsupported: Vec<UnsupportedStack>,
}

/// The workspace root, from this crate's own manifest.
#[must_use]
pub fn repository_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.push("..");
    root.push("..");
    root
}

/// Where the corpus lives.
#[must_use]
pub fn corpus_root() -> PathBuf {
    repository_root().join("tests").join("shells")
}

/// Where `scripts/fetch-shell-stacks.sh` installs what it fetched.
#[must_use]
pub fn stack_cache() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KR_SHELL_STACKS") {
        return PathBuf::from(explicit);
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach/shell-stacks")
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("kalareach/shell-stacks")
    } else {
        home.join(".cache/kalareach/shell-stacks")
    }
}

/// Reads every case, in a stable order.
///
/// # Panics
///
/// Panics when a case does not decode, which is a corpus that cannot be read rather than a
/// package that failed.
#[must_use]
pub fn cases() -> Vec<QualificationCase> {
    let mut found = Vec::new();
    for shell in read_directory(&corpus_root()) {
        if !shell.is_dir() {
            continue;
        }
        for entry in read_directory(&shell) {
            let path = entry.join("case.json");
            if !path.is_file() {
                continue;
            }
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            let mut case: QualificationCase = serde_json::from_str(&body)
                .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display()));
            case.directory = entry;
            found.push(case);
        }
    }
    found.sort_by(|left, right| left.id.cmp(&right.id));
    found
}

/// Reads each shell's list of combinations that do not exist.
///
/// # Panics
///
/// Panics when a list does not decode.
#[must_use]
pub fn unsupported() -> Vec<UnsupportedList> {
    let mut found = Vec::new();
    for shell in read_directory(&corpus_root()) {
        let path = shell.join("unsupported.json");
        if !path.is_file() {
            continue;
        }
        let body = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        found.push(
            serde_json::from_str(&body)
                .unwrap_or_else(|error| panic!("{} does not decode: {error}", path.display())),
        );
    }
    found.sort_by_key(|list: &UnsupportedList| list.shell.as_str());
    found
}

fn read_directory(root: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{}: {error}", root.display()))
        .map(|entry| entry.expect("a directory entry is readable").path())
        .collect();
    entries.sort();
    entries
}

/// The environment variable a case's startup file reads a stack's own directory from.
#[must_use]
pub fn stack_variable(id: &str) -> String {
    format!("KR_STACK_{}", id.to_uppercase().replace('-', "_"))
}

/// Everything one case needs on disk before its shell starts.
///
/// The home outlives the session that reads it, so a case can start a second shell over the same
/// home — which is what a theme that draws from a cache of the last run needs — and so the order
/// the startup wrote can be read after the shell has gone.
pub struct CaseSetup {
    pub home: PathBuf,
    pub runtime: PathBuf,
    /// Where the startup files append the markers that say what ran and in what order.
    pub order: PathBuf,
    pub environment: Vec<(String, String)>,
    directory: tempfile::TempDir,
}

impl CaseSetup {
    /// Writes the case's startup files, with the package's own marked entry where the case put it.
    ///
    /// # Panics
    ///
    /// Panics when a file the case names is missing or its path climbs out of the home, which is a
    /// corpus fault rather than a package one.
    #[must_use]
    pub fn prepare(case: &QualificationCase, package: &Package, stacks: &StackIndex) -> Self {
        let directory = tempfile::Builder::new()
            .prefix("kr-qualification-")
            .tempdir()
            .expect("a case directory on the internal disk");
        let home = directory.path().join("home");
        let runtime = directory.path().join("rt");
        std::fs::create_dir(&home).expect("a home directory");
        std::fs::create_dir(&runtime).expect("a runtime directory");
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700))
            .expect("an owner-only runtime directory");
        let order = directory.path().join("order");
        std::fs::write(&order, "").expect("the order record");

        let entry = package_entry(package);
        let mut entry_written = false;
        for file in &case.home {
            let source = case.directory.join("home").join(&file.file);
            let body = std::fs::read_to_string(&source)
                .unwrap_or_else(|error| panic!("{}: {error}", source.display()));
            let destination = home_path(&home, &file.path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).expect("a directory under the case home");
            }
            let body = if body.contains(ENTRY_TOKEN) {
                entry_written = true;
                body.replace(ENTRY_TOKEN, &entry)
            } else {
                body
            };
            std::fs::write(&destination, body).expect("a startup file");
        }
        if !entry_written {
            // This shell activates the integration from a file of its own rather than from inside
            // the person's, which is what its own configuration layout asks for.
            let destination = home_path(&home, default_entry_path(case.shell));
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("a directory");
            std::fs::write(&destination, entry).expect("the startup entry");
        }

        let mut environment = vec![
            ("HOME".to_owned(), home.display().to_string()),
            ("ZDOTDIR".to_owned(), home.display().to_string()),
            (
                "XDG_CONFIG_HOME".to_owned(),
                home.join(".config").display().to_string(),
            ),
            (
                "XDG_DATA_HOME".to_owned(),
                home.join(".local/share").display().to_string(),
            ),
            (
                "XDG_CACHE_HOME".to_owned(),
                home.join(".cache").display().to_string(),
            ),
            ("KR_TEST_ORDER".to_owned(), order.display().to_string()),
            ("TERM".to_owned(), "xterm-256color".to_owned()),
            ("LANG".to_owned(), "C".to_owned()),
        ];
        for id in &case.requires {
            let stack = stacks
                .get(id)
                .unwrap_or_else(|| panic!("{} needs {id}, which the index does not name", case.id));
            let root = stack
                .root
                .as_ref()
                .unwrap_or_else(|| panic!("{id} is {} and has no directory", stack.status));
            environment.push((stack_variable(id), root.clone()));
        }

        Self {
            home,
            runtime,
            order,
            environment,
            directory,
        }
    }

    /// The markers the startup files recorded, in the order they wrote them.
    #[must_use]
    pub fn recorded_order(&self) -> Vec<String> {
        std::fs::read_to_string(&self.order)
            .unwrap_or_default()
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Empties the order record, so a second start over the same home records only its own run.
    pub fn forget_order(&self) {
        std::fs::write(&self.order, "").expect("the order record");
    }

    /// Where the case's own files live, for evidence a test writes beside them.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
}

/// Joins a path a case named to the home, refusing one that climbs out of it.
fn home_path(home: &Path, relative: &str) -> PathBuf {
    let path = Path::new(relative);
    assert!(path.is_relative(), "{relative} is not relative to the home");
    for part in path.components() {
        assert!(
            matches!(part, std::path::Component::Normal(_)),
            "{relative} climbs out of the home"
        );
    }
    home.join(path)
}

/// Where a shell that activates the integration from its own file keeps that file.
fn default_entry_path(kind: ShellKind) -> &'static str {
    match kind {
        ShellKind::Zsh => ".zshrc",
        ShellKind::Bash => ".bashrc",
        ShellKind::Fish => ".config/fish/conf.d/kr-kalareach.fish",
        ShellKind::PowerShell => ".config/powershell/Microsoft.PowerShell_profile.ps1",
    }
}

/// The marked block the package publishes, exactly as it publishes it.
fn package_entry(package: &Package) -> String {
    std::fs::read_to_string(&package.startup_entry)
        .unwrap_or_else(|error| panic!("{}: {error}", package.startup_entry.display()))
}

impl Session {
    /// Starts the packaged shell over one case's own home and completes the handshake.
    ///
    /// This is beside [`Session::start`] rather than inside it because the two answer different
    /// questions. That one starts a package against the configuration the package tests own; this
    /// one starts it against a person's, which the corpus supplies, and keeps the home after the
    /// shell has gone so what the startup files recorded can be read.
    ///
    /// # Panics
    ///
    /// Panics when the endpoint cannot be created, the shell does not connect, or the worker's own
    /// decision refuses the handshake: each is a failure of the package under test.
    #[must_use]
    pub fn start_for(package: &Package, case: &QualificationCase, setup: &CaseSetup) -> Self {
        let endpoint_path = setup.runtime.join("shell-bridge");
        // A session that starts twice over one home binds a fresh endpoint each time.
        let _ = std::fs::remove_file(&endpoint_path);
        let endpoint = BridgeEndpoint::unix(endpoint_path.to_string_lossy().into_owned());
        endpoint
            .validate()
            .expect("the endpoint path fits a socket address");
        let listener = UnixListener::bind(&endpoint_path).expect("the endpoint binds");
        std::fs::set_permissions(&endpoint_path, std::fs::Permissions::from_mode(0o600))
            .expect("an owner-only endpoint");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");

        let session_id = SessionId::new(Uuid::from_bytes([0x63; 16]));
        let secret: Vec<u8> = (0..BOOTSTRAP_SECRET_LEN)
            .map(|index| (index as u8).wrapping_mul(11))
            .collect();

        let pty = native_pty_system()
            .openpty(PtySize {
                rows: 24,
                cols: 100,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("a pseudo-terminal");

        let mut command = CommandBuilder::new(package.executable.to_string_lossy().into_owned());
        match package.kind {
            ShellKind::PowerShell => {
                command.arg("-NoLogo");
                let mut module_path = package.module_directory.to_string_lossy().into_owned();
                if let Some(existing) = std::env::var_os("PSModulePath") {
                    module_path.push(':');
                    module_path.push_str(&existing.to_string_lossy());
                }
                command.env("PSModulePath", module_path);
                // The host's own image needs its runtime's location, which the qualification
                // recorded from the launcher that started the host it qualified.
                if let Some(environment) = package.record["launch"]["environment"].as_object() {
                    for (name, value) in environment {
                        if let Some(value) = value.as_str() {
                            command.env(name, value);
                        }
                    }
                }
            }
            _ => {
                command.arg("-i");
            }
        }
        command.cwd(&setup.home);
        for (name, value) in &setup.environment {
            command.env(name, value);
        }
        command.env("KR_SESSION", session_id.to_string());
        command.env("KR_SHELL_BRIDGE", &endpoint.path);
        command.env(
            "KR_SHELL_BRIDGE_SECRET",
            kr_protocol::scalars::to_base64url(&secret),
        );
        if let Some(trace) = std::env::var_os("KR_SHELL_BRIDGE_TRACE") {
            command.env("KR_SHELL_BRIDGE_TRACE", trace);
        }

        let child = pty
            .slave
            .spawn_command(command)
            .unwrap_or_else(|error| panic!("{} does not start: {error}", case.id));
        drop(pty.slave);

        let output = Arc::new(Mutex::new(Vec::new()));
        let stopped = Arc::new(AtomicBool::new(false));
        let mut reader = pty.master.try_clone_reader().expect("a terminal reader");
        let collected = Arc::clone(&output);
        let finished = Arc::clone(&stopped);
        let writer: Arc<Mutex<Box<dyn std::io::Write + Send>>> = Arc::new(Mutex::new(
            pty.master.take_writer().expect("a terminal writer"),
        ));
        let answering = Arc::clone(&writer);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while !finished.load(Ordering::Relaxed) {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(taken) => {
                        answer_terminal_queries(&buffer[..taken], &answering);
                        collected
                            .lock()
                            .expect("the output lock")
                            .extend_from_slice(&buffer[..taken]);
                    }
                }
            }
        });

        let stream = accept_within(&listener, REPLY).unwrap_or_else(|| {
            panic!(
                "{} did not connect to the endpoint it was given; the terminal showed:\n{}",
                case.id,
                String::from_utf8_lossy(&output.lock().expect("the output lock"))
            )
        });
        stream
            .set_nonblocking(true)
            .expect("a non-blocking connection");

        // The session's own scratch directory. The case's home is the setup's and outlives this,
        // so what the startup files recorded can be read after the shell has gone.
        let scratch = tempfile::Builder::new()
            .prefix("kr-qualification-session-")
            .tempdir()
            .expect("a session directory on the internal disk");

        let mut session = Self {
            package_kind: package.kind,
            session_id,
            hello: placeholder_hello(session_id),
            accepted: placeholder_accept(session_id),
            prompt: "KR> ".to_owned(),
            mark: 0,
            reading: false,
            stepping: true,
            last_entry: None,
            stream,
            closed: false,
            pending: Vec::new(),
            events: std::collections::VecDeque::new(),
            answers: std::collections::HashMap::new(),
            next_request: 1,
            output,
            stopped,
            writer,
            child,
            _master: pty.master,
            _directory: scratch,
        };

        let hello = match session.read_frame(REPLY) {
            Some(BridgeFrame::Hello(hello)) => hello,
            other => panic!(
                "{} opened with {other:?}; the terminal showed:\n{}",
                case.id,
                session.terminal_output()
            ),
        };
        let transcript = bootstrap_transcript(
            session.session_id,
            &endpoint,
            &hello.shell_process,
            &hello.shell.integration_version,
        )
        .expect("the transcript encodes");
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret).expect("any key length");
        mac.update(&transcript);
        let verdict = if mac.verify_slice(hello.proof.as_slice()).is_ok() {
            ProofVerdict::Verified
        } else {
            ProofVerdict::Failed
        };
        let expectation = WorkerExpectation {
            session_id: session.session_id,
            root_process: hello.shell_process.clone(),
            supported_editor_abis: vec![hello.shell.editor_abi.clone()],
            supported_integration_versions: vec![hello.shell.integration_version.clone()],
            already_registered: false,
            gesture: kr_shell_integration::contract::events::EofGesture::default(),
        };
        let peer = ObservedPeer {
            uid: endpoint_owner(&endpoint_path),
            process: Some(hello.shell_process.clone()),
        };
        let accepted = match decide_handshake(&expectation, &peer, &hello, verdict) {
            HandshakeOutcome::Accepted(accepted) => accepted,
            HandshakeOutcome::Refused(refused) => {
                panic!("{} was refused: {:?}", case.id, refused.reason)
            }
        };
        session.write_frame(&BridgeFrame::Handshake(HandshakeOutcome::Accepted(
            accepted.clone(),
        )));
        session.hello = hello;
        session.accepted = accepted;
        session
    }

    /// Waits until this editor is reading the terminal itself, where one has to be waited for.
    ///
    /// An editor that takes the terminal out of its own line mode reads a key as the key it binds.
    /// One typed before it takes the terminal goes through the terminal's own line discipline
    /// instead, which holds it until a line ends, so a chord sent a moment early is lost. A person
    /// waits for the prompt; against such an editor this session waits for its drawing, which is
    /// the editor rather than the prompt.
    ///
    /// # Panics
    ///
    /// Panics when no prompt or no drawing arrives, which is an editor that never started reading.
    pub fn ensure_reading(&mut self) {
        if !dialect(self.package_kind).types_at_the_prompt {
            return;
        }
        assert!(
            self.wait_for_prompt(),
            "the shell drew no prompt:\n{}",
            self.terminal_output()
        );
        let start = self.terminal_output().len();
        self.type_bytes(b"x");
        assert!(
            self.wait_for_editor(start),
            "the editor drew nothing for a key typed at its prompt:\n{}",
            self.terminal_output()
        );
        self.clear_line();
    }

    /// Presses the key the case's own binding is on and waits for what that binding writes.
    ///
    /// The text comes from the binding rather than from the two bytes that were typed, so seeing
    /// it drawn is the binding having run rather than the terminal having echoed.
    #[must_use]
    pub fn user_binding_ran(&mut self) -> bool {
        self.type_bytes(USER_BINDING_KEY);
        self.wait_for_output(USER_BINDING_TEXT, REPLY)
    }
}

/// What one case's run concluded, for the report the qualification prints.
#[derive(Clone, Debug)]
pub struct CaseOutcome {
    pub id: String,
    pub shell: ShellKind,
    pub stack: String,
    /// `qualified`, or why the case did not run.
    pub verdict: String,
    /// The package identity this case qualified, where it ran.
    pub package_identity: Option<String>,
    /// The stack versions it ran against.
    pub stack_versions: BTreeMap<String, String>,
    pub checks: Vec<String>,
}

impl CaseOutcome {
    #[must_use]
    pub fn skipped(case: &QualificationCase, reason: &str) -> Self {
        Self {
            id: case.id.clone(),
            shell: case.shell,
            stack: case.stack.clone(),
            verdict: reason.to_owned(),
            package_identity: None,
            stack_versions: BTreeMap::new(),
            checks: Vec::new(),
        }
    }
}

/// Flattens a verdict to one line, so the record stays one line per case.
///
/// A failure carries what the terminal showed, which is what makes it readable in the test's own
/// output and unreadable in a table.
fn one_line(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character == '\t' || character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Writes what each case concluded where the run asked for its evidence.
pub fn record_outcomes(name: &str, outcomes: &[CaseOutcome]) {
    let mut report = String::new();
    for outcome in outcomes {
        report.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            outcome.id,
            outcome.shell.as_str(),
            outcome.stack,
            one_line(&outcome.verdict),
            outcome.package_identity.as_deref().unwrap_or("-"),
            outcome
                .stack_versions
                .iter()
                .map(|(id, version)| format!("{id}={version}"))
                .collect::<Vec<_>>()
                .join(","),
        ));
    }
    record(name, &report);
    print!("{report}");
}

/// Waits until the terminal has been quiet for `quiet`, or `within` has passed.
///
/// A prompt some of these stacks draw is several writes long, and a case that typed into the
/// middle of one would be measuring the drawing rather than the reader.
pub fn settle(session: &mut Session, quiet: Duration, within: Duration) {
    let deadline = Instant::now() + within;
    let mut last = session.terminal_output().len();
    let mut since = Instant::now();
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
        let now = session.terminal_output().len();
        if now == last {
            if since.elapsed() >= quiet {
                return;
            }
        } else {
            last = now;
            since = Instant::now();
        }
    }
}
