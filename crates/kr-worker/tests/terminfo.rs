//! The terminfo database a managed session's shell reads.
//!
//! The environment names `xterm-256color`, and a program inside the session asks its terminfo
//! library what that means. These tests run the host's own `tput` and `infocmp` in a real shell in
//! a real pseudo-terminal, started with the environment the worker builds, and check which database
//! answered.

#![cfg(unix)]

use std::time::Duration;

use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, SessionEpoch, SessionId};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber, EnvironmentVariable, ShellMode};
use kr_term::terminfo::Description;
use kr_worker::environment::{
    ExecutionContext, LaunchEnvironment, build, materialise_description, materialise_terminfo,
};
use kr_worker::output::OutputDelivery;
use kr_worker::runtime::SessionRuntime;
use kr_worker::session::{Session, SessionConfig};

/// How long a wait for something to appear is given: it fails a wait that never ends, and is not a
/// measurement.
const LIVENESS_DEADLINE: Duration = Duration::from_secs(120);

/// A scratch directory that removes itself.
struct Scratch(std::path::PathBuf);

impl Scratch {
    /// A directory whose path stays short, because a multiplexer's socket lives inside it and a
    /// socket path has a length limit.
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "krti-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The variables a test shell needs before anything else, as a creator's snapshot.
fn creator(extra: &[(&str, &str)]) -> Vec<EnvironmentVariable> {
    let mut variables: Vec<EnvironmentVariable> = kr_worker::testing::posix_script("")
        .environment
        .into_iter()
        .map(|(name, value)| EnvironmentVariable { name, value })
        .collect();
    variables.extend(extra.iter().map(|(name, value)| EnvironmentVariable {
        name: (*name).to_owned(),
        value: (*value).to_owned(),
    }));
    variables
}

fn launch_environment(
    snapshot: &[EnvironmentVariable],
    private: Option<&std::path::Path>,
) -> LaunchEnvironment {
    let context = ExecutionContext {
        terminfo: private.map(std::path::Path::to_path_buf),
        ..ExecutionContext::default()
    };
    build(
        snapshot,
        kr_protocol::worker::EnvironmentOrigin::CreatorSnapshot,
        &[],
        &context,
        &kr_worker::testing::posix_shell(),
        "0",
        SessionId::new(kr_ipc::new_uuid()),
    )
}

/// What a session's shell printed, and what the terminal engine made of it.
struct Ran {
    /// Everything the shell wrote, up to and including the line `kr-terminfo-done`.
    text: String,
    /// The engine's diagnostic totals, by kind, when the script had finished.
    diagnostics: Vec<(kr_term::diag::DiagnosticKind, u64)>,
    /// Every byte the session's application wrote, before the engine classified any of it.
    raw: Vec<u8>,
}

/// Runs `script` as a session's root shell in `environment`.
async fn run(script: &str, environment: &LaunchEnvironment) -> String {
    run_observed(script, environment, None).await.text
}

/// Everything the session has retained of what its application wrote.
fn retained_output(session: &Session) -> Vec<u8> {
    let mut raw = Vec::new();
    loop {
        let page = session
            .history_page(raw.len() as u64, 1 << 20)
            .expect("the session's output history");
        if page.bytes.is_empty() {
            break;
        }
        raw.extend_from_slice(page.bytes.as_slice());
    }
    raw
}

/// Runs `script` as a session's root shell in `environment` and reports what the engine counted.
///
/// The run is over when the shell has printed its last line or, for a script that draws on the
/// screen and so is not read back from its output, when `finished` exists; and then, in either
/// case, when that last line is in the session's retained output. A script ends before the host
/// has read what its programs wrote last, and the shell's last line follows all of it, so only
/// once the retained output carries that line has everything before it been through the engine.
async fn run_observed(
    script: &str,
    environment: &LaunchEnvironment,
    finished: Option<&std::path::Path>,
) -> Ran {
    let host = kr_ipc::testing::TempHost::create();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let mut shell = kr_worker::testing::posix_script(&format!(
        "{script}\nprintf 'kr-terminfo-done\\n'; exec cat"
    ));
    shell.environment = environment.to_pairs();
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(1),
        shell,
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    session
        .attach(
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested: requested.clone(),
            },
            requested,
            attachment_id,
        )
        .expect("attaches");
    let mut stream = session.subscribe(attachment_id).expect("subscribes");
    let runtime = std::sync::Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    let marker = b"kr-terminfo-done";
    let mut seen = Vec::new();
    let started = tokio::time::Instant::now();
    let deadline = started + LIVENESS_DEADLINE;
    let done = |seen: &[u8]| {
        seen.windows(marker.len()).any(|window| window == marker)
            || finished.is_some_and(std::path::Path::exists)
    };
    while tokio::time::Instant::now() < deadline && !done(&seen) {
        match tokio::time::timeout(Duration::from_secs(5), stream.recv()).await {
            Ok(Some(OutputDelivery::Bytes { bytes, .. })) => seen.extend_from_slice(&bytes),
            Ok(Some(_)) | Err(_) => {}
            Ok(None) => break,
        }
    }
    let text = String::from_utf8_lossy(&seen).into_owned();
    // What the engine counted and what the session retained are read together, under one hold of
    // the session, so that no output is taken in between the two.
    let (diagnostics, raw) = loop {
        let (diagnostics, raw) = {
            let session = runtime.session();
            (session.terminal_diagnostics(), retained_output(&session))
        };
        if raw.windows(marker.len()).any(|window| window == marker)
            || tokio::time::Instant::now() >= deadline
        {
            break (diagnostics, raw);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    // The shell waits on `cat` for a line that never comes; the runtime's owner closes it.
    let _ = runtime.session().force_close();
    assert!(
        done(&seen) && raw.windows(marker.len()).any(|window| window == marker),
        "waited {:?} for the script to finish and its last line to be retained: {text:?}",
        started.elapsed()
    );
    Ran {
        text,
        diagnostics,
        raw,
    }
}

/// The text after `key` up to the end of its line, wherever in the output it appears.
///
/// A program that drew on the screen leaves control sequences in front of the next line it writes,
/// so a line is looked for by its key rather than by its start.
fn value_of(text: &str, key: &str) -> String {
    let start = text
        .find(key)
        .unwrap_or_else(|| panic!("no {key:?} in {text:?}"))
        + key.len();
    text[start..]
        .chars()
        .take_while(|character| *character != '\r' && *character != '\n')
        .collect()
}

fn line_starting<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.lines()
        .map(str::trim_end)
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starts with {prefix:?} in {text:?}"))
}

/// The script every test here runs: what the terminfo library says `xterm-256color` is, and which
/// file it read that from.
const ASKS_THE_LIBRARY: &str = "echo \"colors=$(tput colors)\"\n\
     echo \"truecolor=$(tput -T xterm-256color Tc >/dev/null 2>&1 && echo yes || echo no)\"\n\
     echo \"file=$(infocmp -x xterm-256color | head -n 1)\"\n\
     echo \"creator=$(tput -T kr-creator-term colors 2>&1)\"\n\
     echo \"TERMINFO=$TERMINFO\"\n\
     echo \"TERMINFO_DIRS=$TERMINFO_DIRS\"";

/// A managed session reads the private database: the file the library names is in the worker's
/// state directory, the truecolour flag only that database carries is there, and the environment's
/// diagnostics say which directory was selected.
#[tokio::test(flavor = "multi_thread")]
async fn a_managed_shell_reads_the_private_database() {
    let state = Scratch::new();
    let directory = materialise_terminfo(&state.0).expect("the database is written");
    let environment = launch_environment(&creator(&[]), Some(&directory));
    let shown = run(ASKS_THE_LIBRARY, &environment).await;

    assert_eq!(line_starting(&shown, "colors="), "colors=256");
    assert_eq!(
        line_starting(&shown, "truecolor="),
        "truecolor=yes",
        "the private entry carries the truecolour flag a stock entry lacks: {shown:?}"
    );
    let file = line_starting(&shown, "file=");
    let private = directory.display().to_string();
    assert!(
        file.contains(&format!("from file: {private}/")),
        "infocmp read the entry from the private directory {private}: {file}"
    );
    assert_eq!(
        line_starting(&shown, "TERMINFO="),
        format!("TERMINFO={private}")
    );
    assert_eq!(line_starting(&shown, "TERMINFO_DIRS="), "TERMINFO_DIRS=");
    assert_eq!(
        environment.sources.terminfo.directory.as_deref(),
        Some(private.as_str()),
        "the diagnostics name the selected directory"
    );
    assert!(!environment.sources.terminfo.overridden());
}

/// Control: with no private database a session reads its host's, which has no `Tc`, and infocmp
/// names a file outside the worker's state directory.
#[tokio::test(flavor = "multi_thread")]
async fn without_the_private_database_the_hosts_own_answers() {
    let state = Scratch::new();
    let environment = launch_environment(&creator(&[]), None);
    let shown = run(ASKS_THE_LIBRARY, &environment).await;
    let file = line_starting(&shown, "file=");
    assert!(
        !file.contains(&state.0.display().to_string()),
        "the host's database answered: {file}"
    );
    assert_eq!(line_starting(&shown, "TERMINFO="), "TERMINFO=");
    assert_eq!(environment.sources.terminfo.directory, None);
}

/// A creator's own database directory is not dropped and does not win: the private database still
/// answers `xterm-256color`, the creator's directory still answers the terminal names only it has,
/// and the diagnostics report what the creator had.
#[tokio::test(flavor = "multi_thread")]
async fn a_creators_database_is_kept_behind_the_private_one_and_reported() {
    let state = Scratch::new();
    let directory = materialise_terminfo(&state.0).expect("the database is written");
    let theirs = Scratch::new();
    // A terminal the creator's database has and the private one does not, and a stock-like
    // `xterm-256color` of the creator's that must not be the one the session reads.
    let mut other = Description::pinned();
    other.names = "kr-creator-term|the creator's own terminal".to_owned();
    other.numbers.insert("colors".to_owned(), 8);
    other.install(&theirs.0).expect("the creator's database");
    let mut shadow = Description::pinned();
    shadow.booleans.remove("Tc");
    shadow
        .install(&theirs.0)
        .expect("a competing xterm-256color");

    let theirs_path = theirs.0.display().to_string();
    let environment = launch_environment(
        &creator(&[
            ("TERMINFO", &theirs_path),
            ("TERMINFO_DIRS", "/nonexistent/one"),
        ]),
        Some(&directory),
    );
    let shown = run(ASKS_THE_LIBRARY, &environment).await;

    let private = directory.display().to_string();
    assert!(
        line_starting(&shown, "file=").contains(&format!("from file: {private}/")),
        "the private database answers xterm-256color: {shown:?}"
    );
    assert_eq!(line_starting(&shown, "truecolor="), "truecolor=yes");
    assert_eq!(
        line_starting(&shown, "creator="),
        "creator=8",
        "the creator's directory still answers the terminals only it has: {shown:?}"
    );
    assert_eq!(
        line_starting(&shown, "TERMINFO="),
        format!("TERMINFO={private}")
    );
    assert_eq!(
        line_starting(&shown, "TERMINFO_DIRS="),
        format!("TERMINFO_DIRS={theirs_path}:/nonexistent/one")
    );
    let selection = &environment.sources.terminfo;
    assert!(selection.overridden(), "the override is reported");
    assert_eq!(
        selection.creator_terminfo.as_deref(),
        Some(theirs_path.as_str())
    );
    assert_eq!(
        selection.creator_terminfo_dirs.as_deref(),
        Some("/nonexistent/one")
    );
}

/// A session started by one build keeps the database its own engine answers from while a worker of
/// a build with other data writes its own: both sessions are running, and each reads its own.
#[tokio::test(flavor = "multi_thread")]
async fn two_builds_with_other_data_each_keep_their_own_database() {
    let state = Scratch::new();
    let work = Scratch::new();
    let older = Description::pinned();
    let mut newer = older.clone();
    newer
        .strings
        .insert("cup".to_owned(), "\x1b[%p2%d;%p1%dH".to_owned());
    let older_directory = materialise_description(&state.0, &older).expect("the older database");
    let older_environment = launch_environment(&creator(&[]), Some(&older_directory));
    let asks = "tput -T xterm-256color cup 3 4 | od -An -tx1 | tr -d ' \\n'";
    // The older session waits for the newer build's database to exist before it asks, so it asks
    // while both are there.
    let older_script = format!(
        "while [ ! -f {go} ]; do sleep 0.1; done\necho \"cup=$({asks})\"",
        go = work.0.join("go").display()
    );
    let (older_ran, newer_ran) = tokio::join!(run(&older_script, &older_environment), async {
        let newer_directory =
            materialise_description(&state.0, &newer).expect("the newer database");
        assert_ne!(newer_directory, older_directory);
        let newer_environment = launch_environment(&creator(&[]), Some(&newer_directory));
        let ran = run(&format!("echo \"cup=$({asks})\""), &newer_environment).await;
        std::fs::write(work.0.join("go"), b"").expect("release the older session");
        ran
    });
    // ESC [ 4 ; 5 H, and with the parameters swapped ESC [ 4 ; 3 H.
    assert_eq!(value_of(&older_ran, "cup="), "1b5b343b3548");
    assert_eq!(value_of(&newer_ran, "cup="), "1b5b343b3348");
}

// ------------------------------------------------------------------ nested and remote

/// The program `name` on this host's search path, or `None` with the reason a test gives for
/// standing down. A run that sets `KR_REQUIRE_MULTIPLEXERS` and `KR_REQUIRE_SSHD` treats a missing
/// program as a failure instead, so a host that should have them cannot pass without running.
fn program(name: &str, requirement: &str) -> Option<std::path::PathBuf> {
    let found = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .chain(["/usr/sbin".into(), "/usr/local/sbin".into()])
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file());
    if found.is_none() {
        assert!(
            std::env::var_os(requirement).is_none(),
            "{requirement} is set and this host has no {name}"
        );
        eprintln!("skipped: this host has no {name}, which this test needs");
    }
    found
}

/// The private database a session's environment names, and the database directory its creator
/// gave, as the worker builds them for a session that starts with `TERM` unset in the snapshot.
fn private_environment(state: &Scratch) -> (std::path::PathBuf, LaunchEnvironment) {
    let directory = materialise_terminfo(&state.0).expect("the database is written");
    let environment = launch_environment(&creator(&[]), Some(&directory));
    (directory, environment)
}

/// The value tmux lists for each string capability of the terminal it is attached to.
fn tmux_strings(info: &str) -> std::collections::BTreeMap<String, String> {
    info.lines()
        .filter_map(|line| {
            let (_, rest) = line.trim_start().split_once(": ")?;
            let (name, value) = rest.split_once(": (string) ")?;
            Some((name.to_owned(), value.to_owned()))
        })
        .collect()
}

/// Decodes the escapes tmux prints a string capability with.
fn tmux_unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'\\' || at + 1 >= bytes.len() {
            out.push(bytes[at]);
            at += 1;
            continue;
        }
        let escaped = bytes[at + 1];
        at += 2;
        match escaped {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'0'..=b'7' => {
                let mut value = u32::from(escaped - b'0');
                for _ in 0..2 {
                    match bytes.get(at) {
                        Some(digit @ b'0'..=b'7') => {
                            value = value * 8 + u32::from(digit - b'0');
                            at += 1;
                        }
                        _ => break,
                    }
                }
                out.push(u8::try_from(value).expect("an octal byte"));
            }
            other => out.push(other),
        }
    }
    out
}

/// A multiplexer inside a managed session reads the private database for the outer terminal, and
/// nothing it does changes what the outer session declares.
///
/// `tmux` is asked what it read: it lists every capability of the terminal it is attached to, and
/// each one the private database also has must be the value that database holds. The exception is
/// the cursor-style reset, which `tmux` sets by terminal name whatever the database says.
#[tokio::test(flavor = "multi_thread")]
async fn tmux_inside_a_managed_session_reads_the_private_database() {
    let Some(tmux) = program("tmux", "KR_REQUIRE_MULTIPLEXERS") else {
        return;
    };
    let state = Scratch::new();
    let work = Scratch::new();
    let (directory, environment) = private_environment(&state);
    std::fs::write(
        work.0.join("inner.sh"),
        format!(
            "{{ echo \"inner_term=$TERM\"; echo \"inner_terminfo=$TERMINFO\"; \
             echo \"inner_colors=$(tput colors)\"; \
             echo \"client_term=$({tmux} display-message -p '#{{client_termname}}')\"; }} \
             > {work}/inner.txt\n{tmux} info > {work}/info.txt\n",
            tmux = tmux.display(),
            work = work.0.display()
        ),
    )
    .expect("the script that runs inside tmux");
    let script = format!(
        "export TMUX_TMPDIR={work}\n\
         echo \"outer_file=$(infocmp -x xterm-256color | head -n 1)\" > {work}/outer.txt\n\
         {tmux} -f /dev/null -L kr new-session -x 80 -y 24 \"sh {work}/inner.sh\"\n\
         echo \"outer_term=$TERM\" >> {work}/outer.txt\n\
         echo \"outer_terminfo=$TERMINFO\" >> {work}/outer.txt\n\
         touch {work}/finished",
        tmux = tmux.display(),
        work = work.0.display()
    );
    let ran = run_observed(&script, &environment, Some(&work.0.join("finished"))).await;

    let private = directory.display().to_string();
    let inner = std::fs::read_to_string(work.0.join("inner.txt")).expect("what tmux's pane wrote");
    let info = std::fs::read_to_string(work.0.join("info.txt")).expect("what tmux reported");

    // tmux gives the applications inside it a terminal name of its own, and keeps the database
    // directory the session gave it, so a program in a pane still reads the private database for
    // every name it has.
    let inner_term = value_of(&inner, "inner_term=");
    assert!(
        inner_term.starts_with("tmux") || inner_term.starts_with("screen"),
        "tmux declares its own terminal to its applications: {inner_term}"
    );
    assert_eq!(value_of(&inner, "inner_terminfo="), private);
    assert_eq!(value_of(&inner, "client_term="), "xterm-256color");

    // What tmux read for the outer terminal came from the private database: the truecolour flags a
    // stock database lacks are there, and every string it lists that the database has is the value
    // the database holds.
    assert!(info.contains("xterm-256color for"), "{info}");
    for flag in ["Tc", "RGB"] {
        assert!(
            tmux_strings_and_flags(&info).contains(&format!("{flag}: (flag) true")),
            "tmux read {flag} from the private database: {info}"
        );
    }
    let listed = tmux_strings(&info);
    let mut compared = 0;
    let mut changed = Vec::new();
    for capability in kr_term::terminfo::strings() {
        if let Some(shown) = listed.get(capability.name) {
            compared += 1;
            if tmux_unescape(shown) != capability.value.as_bytes() {
                changed.push(capability.name);
                // Whatever tmux chose to write in its place, the engine has to classify it, or the
                // exemption would let a value the profile does not act on through.
                let value = String::from_utf8_lossy(&tmux_unescape(shown)).into_owned();
                let expansion = kr_term::terminfo::expand(&value, capability.arguments);
                let mut lexer = kr_term::lexer::Lexer::new();
                let mut events = Vec::new();
                lexer.feed(&expansion, &mut events);
                lexer.close(&mut events);
                assert!(
                    !events.is_empty()
                        && events
                            .iter()
                            .all(|event| event.class != kr_term::SequenceClass::Extension),
                    "tmux replaces {} with {value:?}, which the profile does not classify",
                    capability.name
                );
            }
        }
    }
    assert!(
        compared > 100,
        "tmux listed the capabilities it read ({compared}): {info}"
    );
    // tmux replaces a few capabilities by rule whatever the database says: the cursor style, the
    // colour forms and the underline styles, which it sets from the terminal's name and its own
    // version. Every other one it lists is the private database's value.
    let tmux_owns = ["Se", "Ss", "Smulx", "setrgbb", "setrgbf"];
    let unexpected: Vec<_> = changed
        .iter()
        .filter(|name| !tmux_owns.contains(name))
        .collect();
    assert!(
        unexpected.is_empty(),
        "tmux read these from somewhere other than the private database: {unexpected:?}"
    );

    // The outer session is what it was before tmux ran, and everything tmux wrote to it is a
    // sequence the terminal engine classifies.
    let outer =
        std::fs::read_to_string(work.0.join("outer.txt")).expect("what the outer shell wrote");
    assert_eq!(value_of(&outer, "outer_term="), "xterm-256color");
    assert_eq!(value_of(&outer, "outer_terminfo="), private);
    assert!(
        value_of(&outer, "outer_file=").contains(&format!("from file: {private}/")),
        "{outer:?}"
    );
    // Everything tmux wrote is a sequence the engine classifies, or one of the four modes tmux sets
    // for any terminal whose name begins with `xterm` (2031 and 7727, on and off). Anything else
    // the engine does not classify would be a sequence tmux wrote because it read the database, or
    // one this test has not accounted for.
    let unexplained = unexplained_unclassified(&ran.raw);
    assert!(
        unexplained.is_empty(),
        "tmux wrote sequences the profile does not classify and tmux's own rules do not explain: \
         {unexplained:?}"
    );
    let mut lexer = kr_term::lexer::Lexer::new();
    let mut events = Vec::new();
    lexer.feed(&ran.raw, &mut events);
    lexer.close(&mut events);
    let counted = events
        .iter()
        .filter(|event| event.class == kr_term::SequenceClass::Extension)
        .count() as u64;
    assert_eq!(
        counted,
        ran.diagnostics
            .iter()
            .filter(|(kind, _)| *kind == kr_term::diag::DiagnosticKind::UnclassifiedSequence)
            .map(|(_, count)| count)
            .sum::<u64>(),
        "the engine counted the same sequences the raw output holds: {:?}",
        ran.diagnostics
    );
}

/// The DEC private modes tmux sets on a terminal whose name begins with `xterm`, whatever its
/// database says: theme reports and synchronised-update capability queries.
const TMUX_OWN_MODES: [&[u8]; 4] = [
    b"\x1b[?2031h",
    b"\x1b[?2031l",
    b"\x1b[?7727h",
    b"\x1b[?7727l",
];

/// Every sequence in `raw` that the engine does not classify, is not one of [`TMUX_OWN_MODES`], and
/// is not one of the individual sequences the database's own output capabilities expand to.
///
/// The comparison is between single sequences on both sides: a compound capability such as the one
/// that shows the cursor is lexed into the sequences it holds, so an unknown sequence inside one
/// cannot hide in a longer expansion.
fn unexplained_unclassified(raw: &[u8]) -> Vec<String> {
    let lex = |bytes: &[u8]| {
        let mut lexer = kr_term::lexer::Lexer::new();
        let mut events = Vec::new();
        lexer.feed(bytes, &mut events);
        lexer.close(&mut events);
        events
    };
    let named: Vec<Vec<u8>> = kr_term::terminfo::strings()
        .iter()
        .filter(|capability| capability.direction == kr_term::terminfo::Direction::Output)
        .flat_map(|capability| {
            lex(&kr_term::terminfo::expand(
                capability.value,
                capability.arguments,
            ))
            .into_iter()
            .map(|event| AsRef::<[u8]>::as_ref(&event.bytes).to_vec())
        })
        .collect();
    lex(raw)
        .into_iter()
        .filter(|event| event.class == kr_term::SequenceClass::Extension)
        .map(|event| AsRef::<[u8]>::as_ref(&event.bytes).to_vec())
        .filter(|bytes| !TMUX_OWN_MODES.contains(&bytes.as_slice()) && !named.contains(bytes))
        .map(|bytes| String::from_utf8_lossy(&bytes).escape_debug().to_string())
        .collect()
}

/// Control: an unknown sequence is found wherever it sits, including inside a run that also holds
/// sequences the profile classifies, as one would inside a compound capability.
#[test]
fn an_unknown_sequence_inside_a_compound_capability_is_found() {
    assert!(unexplained_unclassified(b"\x1b[?2031h\x1b[?7727l").is_empty());
    let compound = b"\x1b[?12l\x1b[?9999h\x1b[?25h";
    assert_eq!(unexplained_unclassified(compound), ["\\u{1b}[?9999h"]);
    assert_eq!(
        unexplained_unclassified(b"a\x1b[?2031h\x1b[?12l\x1b[?4242l\x1b[?25h"),
        ["\\u{1b}[?4242l"]
    );
}

fn tmux_strings_and_flags(info: &str) -> String {
    info.lines()
        .filter_map(|line| line.trim_start().split_once(": "))
        .map(|(_, rest)| rest.to_owned())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A private `sshd`, run as the current user on a loopback port with a host key and an authorised
/// key made for this test, and stopped when it is dropped. It touches neither the account's
/// `authorized_keys` nor the host's own `sshd`, and it runs none of the account's `~/.ssh/rc`. The
/// remote command still runs under the account's own login shell, which reads that shell's startup
/// files as any login does.
struct Sshd {
    child: std::process::Child,
    port: u16,
    client_key: std::path::PathBuf,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Sshd {
    /// Starts one, or says why this host cannot: no `sshd` to run, or no `ssh-keygen` to make keys
    /// with.
    async fn start(work: &Scratch) -> Option<Self> {
        use std::os::unix::fs::PermissionsExt as _;
        let sshd = program("sshd", "KR_REQUIRE_SSHD")?;
        let keygen = program("ssh-keygen", "KR_REQUIRE_SSHD")?;
        program("ssh", "KR_REQUIRE_SSHD")?;
        let make = |name: &str| {
            let path = work.0.join(name);
            let made = std::process::Command::new(&keygen)
                .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                .arg(&path)
                .status()
                .expect("ssh-keygen runs");
            assert!(made.success(), "ssh-keygen makes a {name}");
            path
        };
        let host_key = make("hostkey");
        let client_key = make("clientkey");
        let authorised = work.0.join("authorized_keys");
        std::fs::copy(client_key.with_extension("pub"), &authorised).expect("an authorised key");
        for path in [&authorised, &host_key, &client_key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only keys");
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("a free loopback port")
            .port();
        let log = std::fs::File::create(work.0.join("sshd.log")).expect("a log");
        let child = std::process::Command::new(sshd)
            .args(["-D", "-e", "-f", "/dev/null", "-h"])
            .arg(&host_key)
            .arg("-p")
            .arg(port.to_string())
            .args(["-o", "ListenAddress=127.0.0.1", "-o", "PidFile=none"])
            .args([
                "-o",
                "UsePAM=no",
                "-o",
                "StrictModes=no",
                "-o",
                "PermitUserRC=no",
            ])
            .arg("-o")
            .arg(format!("AuthorizedKeysFile={}", authorised.display()))
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "KbdInteractiveAuthentication=no"])
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone().expect("a log handle"))
            .stderr(log)
            .spawn()
            .expect("sshd starts");
        let server = Self {
            child,
            port,
            client_key,
        };
        // Ready is a connection that is accepted, not a moment that has passed.
        let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
        while tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            assert!(
                tokio::time::Instant::now() < deadline,
                "sshd never accepted a connection: {}",
                std::fs::read_to_string(work.0.join("sshd.log")).unwrap_or_default()
            );
            tokio::task::yield_now().await;
        }
        Some(server)
    }

    /// The `ssh` command line that runs `command` on this server with a terminal.
    fn command(&self, command: &str) -> String {
        format!(
            "ssh -tt -F /dev/null -i {key} -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR -p {port} \
             127.0.0.1 '{command}'",
            key = self.client_key.display(),
            port = self.port
        )
    }
}

/// An unmanaged shell reached over SSH keeps the stock `xterm-256color`: the terminal name is
/// forwarded, the private database is not, and a remote environment reads its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_remote_shell_over_ssh_keeps_the_stock_database() {
    let work = Scratch::new();
    let Some(server) = Sshd::start(&work).await else {
        return;
    };
    let state = Scratch::new();
    let (directory, environment) = private_environment(&state);
    let remote = "echo \"remote_term=$TERM\"; echo \"remote_terminfo=$TERMINFO\"; \
                  echo \"remote_dirs=$TERMINFO_DIRS\"; \
                  echo \"remote_file=$(infocmp -x xterm-256color | head -n 1)\"; \
                  echo \"remote_colors=$(tput colors)\"";
    let script = format!(
        "echo \"local_file=$(infocmp -x xterm-256color | head -n 1)\" > {work}/seen.txt\n\
         {ssh} >> {work}/seen.txt\n\
         touch {work}/finished",
        ssh = server.command(remote),
        work = work.0.display()
    );
    run_observed(&script, &environment, Some(&work.0.join("finished"))).await;

    let seen = std::fs::read_to_string(work.0.join("seen.txt")).expect("what the shells wrote");
    let private = directory.display().to_string();
    assert!(
        value_of(&seen, "local_file=").contains(&format!("from file: {private}/")),
        "the managed shell reads the private database: {seen:?}"
    );
    assert_eq!(value_of(&seen, "remote_term="), "xterm-256color");
    assert_eq!(
        value_of(&seen, "remote_terminfo="),
        "",
        "the private database's directory is not forwarded: {seen:?}"
    );
    assert_eq!(value_of(&seen, "remote_dirs="), "");
    let remote_file = value_of(&seen, "remote_file=");
    assert!(
        remote_file.contains("xterm-256color") && !remote_file.contains(&private),
        "the remote shell reads a database of its own host: {remote_file}"
    );
    assert_eq!(value_of(&seen, "remote_colors="), "256");
}

/// `tic` writes where `TERMINFO` points, so a `tic` run inside a managed session writes into the
/// private directory, and `tic -o` names another place for an entry that is a person's own. The
/// reference says both, so a change in either has to change the reference.
#[tokio::test(flavor = "multi_thread")]
async fn tic_inside_a_managed_session_writes_where_terminfo_points() {
    let Some(tic) = program("tic", "KR_REQUIRE_MULTIPLEXERS") else {
        return;
    };
    let state = Scratch::new();
    let (directory, environment) = private_environment(&state);
    let own = Scratch::new();
    std::fs::write(
        own.0.join("mine.src"),
        "kr-mine|a terminal of the person's own,\n\tam, cols#80, lines#24,\n",
    )
    .expect("a source entry");
    let script = format!(
        "cd {own}\n\
         {tic} -x mine.src 2>&1\n\
         echo \"private=$(ls {private}/*/kr-mine 2>/dev/null | wc -l | tr -d ' ')\"\n\
         {tic} -x -o {own}/elsewhere mine.src 2>&1\n\
         echo \"elsewhere=$(ls {own}/elsewhere/*/kr-mine 2>/dev/null | wc -l | tr -d ' ')\"",
        own = own.0.display(),
        tic = tic.display(),
        private = directory.display()
    );
    let shown = run(&script, &environment).await;
    assert_eq!(
        line_starting(&shown, "private="),
        "private=1",
        "tic wrote the entry into the private directory: {shown:?}"
    );
    assert_eq!(
        line_starting(&shown, "elsewhere="),
        "elsewhere=1",
        "tic -o wrote it where it was told to: {shown:?}"
    );
}
