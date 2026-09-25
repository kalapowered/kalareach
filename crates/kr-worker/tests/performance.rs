//! What the host costs when nothing is happening, and how long it takes to become usable.
//!
//! These are measurements, not unit tests, so they are ignored by default: one of them runs for
//! five minutes by design, because the requirement it measures is stated as a five-minute average.
//! `scripts/performance.sh` builds a release profile and runs them.
//!
//! Every measurement states its conditions in its own output. A number without the conditions it
//! was taken under is not evidence, and a condition this build cannot yet meet is named rather than
//! quietly left out.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_controller::service::{Controller, ControllerSetup};
use kr_controller::supervision::DetachedSupervisor;
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::ControllerIdentity;
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, BuildId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{
    Dimensions, Presentation, SessionCreateParams, SessionCreateResult, ShellMode,
};

#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;

/// How many idle sessions the memory requirement names.
const IDLE_SESSIONS: usize = 20;

/// How many attached views the memory requirement names.
const ATTACHED_VIEWS: usize = 32;

/// The whole-host resident bound the requirement names, in kibibytes.
const RESIDENT_BOUND_KIB: u64 = 500 * 1024;

/// The processor bound the requirement names: a fraction of one core, averaged.
const IDLE_CORE_FRACTION: f64 = 0.01;

/// How long the processor average is taken over.
const IDLE_WINDOW: Duration = Duration::from_secs(5 * 60);

/// The bound the attach requirement names.
const ATTACH_BOUND: Duration = Duration::from_millis(500);

struct Host {
    /// The host tree, which ends every worker its daemon started before it goes.
    temp: teardown::Tree,
    worker: PathBuf,
    environment_id: EnvironmentId,
    controller: Arc<Controller>,
}

async fn host() -> Host {
    let temp = teardown::Tree::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // On the internal disk, because a process a service manager launches is its own identity to
    // the operating system and one that reaches a removable volume prompts the person at the
    // machine. Started once here, where nothing is measured, so the operating system's check of a
    // new executable is in no timing below.
    let worker = temp.root().join(if cfg!(windows) {
        "kr-worker.exe"
    } else {
        "kr-worker"
    });
    kr_ipc::testing::place_and_start_once(
        std::path::Path::new(env!("CARGO_BIN_EXE_kr-worker")),
        &worker,
        &["--version"],
    );
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: temp.supervisor(Box::new(DetachedSupervisor::new())),
        worker_program: worker.clone(),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let rendezvous = Listener::bind(&environment.rendezvous_endpoint().expect("an endpoint"))
        .expect("binds the rendezvous");
    let clients = Listener::bind(&environment.controller_endpoint().expect("an endpoint"))
        .expect("binds the client endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(rendezvous));
    tokio::spawn(Arc::clone(&controller).serve_clients(clients));
    Host {
        temp,
        worker,
        environment_id,
        controller,
    }
}

fn build() -> BuildId {
    BuildId::new("kr-perf/0").expect("a build identifier")
}

/// What a measurement is responsible for closing.
///
/// A create the daemon answered names a session. A create whose answer was lost names nothing yet,
/// and what it may have made is exactly what nobody else will close, so the request itself stays
/// here until the daemon is asked again and says what it made. The whole request, not the
/// identifier alone: section 23 de-duplicates on the payload, the freshness window included, so
/// only the original request is the exact duplicate the host answers with its recorded outcome.
#[derive(Default)]
struct Owned {
    sessions: Vec<SessionCreateResult>,
    unresolved: Vec<kr_protocol::envelope::MutationRequest>,
}

/// Creates one session, recording what it owns, or says why it could not be created.
///
/// Nothing here panics. A measurement that panicked part way through would leave every session it
/// had already made running, so each step reports its failure and the caller closes what it owns
/// before it reports anything.
async fn create(host: &Host, owned: &mut Owned) -> Result<SessionCreateResult, String> {
    let (mut client, request) = compose(host).await?;
    admit(host, owned, &mut client, request).await
}

/// Opens a connection and composes the create it will send.
///
/// Composed on the connection that sends it, because a first admission quotes the freshness window
/// that connection holds. Every later send of it is a repeat rather than a first admission, which
/// is the only reason it may travel over another connection.
async fn compose(
    host: &Host,
) -> Result<(LocalClient, kr_protocol::envelope::MutationRequest), String> {
    let endpoint = host
        .temp
        .environment()
        .controller_endpoint()
        .map_err(|error| format!("the daemon's endpoint: {error}"))?;
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .map_err(|error| format!("connect to the daemon: {error}"))?;
    let request = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host),
        )
        .await
        .map_err(|error| format!("compose the create: {error}"))?;
    Ok((client, request))
}

/// Sends a create the daemon has not admitted yet, and records what this run then owns.
///
/// The request goes into the record before the call, because the moment it is on the wire is the
/// moment it can have made something, and it comes out again **only** when the daemon names the
/// session it made. Nothing else settles it: an answer that is an error is not proof that nothing
/// was created - the daemon can start a worker, take its readiness and then fail to read its
/// summary - and a run that released the request there would leave that session running.
async fn admit(
    host: &Host,
    owned: &mut Owned,
    client: &mut LocalClient,
    request: kr_protocol::envelope::MutationRequest,
) -> Result<SessionCreateResult, String> {
    let action = request.action_id;
    owned.unresolved.push(request.clone());
    let asked = match client.repeat(&request).await {
        Ok(Ok(value)) => value
            .to_typed()
            .map_err(|error| format!("the create result: {error}")),
        Ok(Err(error)) => Err(format!("the daemon's answer: {error}")),
        // The answer was lost. Whether the session exists is exactly what asking again settles, and
        // asking again is what cleanup does with the request this run is holding.
        Err(error) => ask_create(host, &request, CREATE_ATTEMPTS)
            .await
            .map_err(|failure| format!("the create call: {error}; and asking again: {failure}")),
    };
    match asked {
        Ok(created) => {
            owned.unresolved.retain(|held| held.action_id != action);
            owned.sessions.push(created.clone());
            Ok(created)
        }
        Err(failure) => Err(failure),
    }
}

/// The session every measurement creates.
fn create_params(host: &Host) -> SessionCreateParams {
    SessionCreateParams {
        environment_id: host.environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some(kr_worker::testing::posix_shell()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(host.temp.root().display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        palette: Nullable::null(),
        environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
            name: "PATH".to_owned(),
            value: "/usr/bin:/bin".to_owned(),
        }],
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        terminal: Nullable::null(),
    }
}

/// Sends a request the daemon has already admitted, again, until it answers with what that made.
///
/// The request goes exactly as it was composed, over whichever connection this can open. That is
/// what makes a repeat an exact duplicate rather than a new first admission: the daemon holds the
/// payload digest of what it admitted, the freshness window is part of that payload, and only the
/// original request still matches it.
///
/// **Only an answer that names a session settles anything.** A repeat asks about an action the
/// daemon has already taken, so a refusal says nothing about what that action made: the daemon
/// checks current authority before it looks for a retained action, and the answer it builds for one
/// is read from the live worker, which can be unreachable for a moment. Every other outcome
/// therefore leaves the request owned, and the run reports what it could not account for.
async fn ask_create(
    host: &Host,
    request: &kr_protocol::envelope::MutationRequest,
    attempts: usize,
) -> Result<SessionCreateResult, String> {
    let endpoint = host
        .temp
        .environment()
        .controller_endpoint()
        .map_err(|error| format!("the daemon's endpoint: {error}"))?;
    let mut failure = String::new();
    for _ in 0..attempts {
        let mut client = match LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await
        {
            Ok(client) => client,
            Err(error) => {
                failure = format!("connect to the daemon: {error}");
                continue;
            }
        };
        match client.repeat(request).await {
            Ok(Ok(value)) => {
                return value
                    .to_typed()
                    .map_err(|error| format!("the create result: {error}"));
            }
            Ok(Err(error)) => failure = format!("the daemon's answer: {error}"),
            // The answer was lost. Whether the session exists is exactly what asking again settles.
            Err(error) => failure = format!("the create call: {error}"),
        }
    }
    Err(failure)
}

/// How many times cleanup asks the daemon what this environment holds before it gives up.
const LIST_ATTEMPTS: usize = 5;

/// How many times a measurement asks for the same create before it gives up.
///
/// The identifier does not change between them, so this is one create being asked about rather
/// than several being made.
const CREATE_ATTEMPTS: usize = 3;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_whose_answer_was_lost_is_closed_by_the_run_that_asked_for_it() {
    // A measurement owns a session from the moment it asks for one, not from the moment it is told
    // about it. The daemon's list is not enough on its own: a worker it momentarily cannot read is
    // absent from it, and the session would outlive the run that made it. What the run keeps is the
    // request, because section 23 de-duplicates on the payload and the freshness window is part of
    // it: only the original request is the exact duplicate the daemon answers with what it made.
    let host = host().await;
    let endpoint = host
        .temp
        .environment()
        .controller_endpoint()
        .expect("the daemon's endpoint");
    let mut owned = Owned::default();

    let (mut client, request) = compose(&host).await.expect("composes a create");
    let made = admit(&host, &mut owned, &mut client, request.clone())
        .await
        .expect("the create succeeds");
    assert!(
        !made.deduplicated,
        "the first send is the one that made the session"
    );
    assert!(
        owned.unresolved.is_empty(),
        "a create the daemon named leaves nothing hanging"
    );

    // An answer that is *not* a session leaves the request owned, whichever send it came from. The
    // refusal here is one this test can produce - the same identifier with a different payload -
    // and it stands for the one it cannot: a daemon that started a worker, took its readiness and
    // then failed to read its summary answers with an error about a session that exists.
    let different = client
        .compose(
            Method::SessionCreate,
            request.action_id,
            ActionTarget::environment(host.environment_id),
            &SessionCreateParams {
                cwd: Nullable::some(host.temp.root().join("elsewhere").display().to_string()),
                ..create_params(&host)
            },
        )
        .await
        .expect("composes the same identifier with another payload");
    let refused = admit(&host, &mut owned, &mut client, different)
        .await
        .expect_err("the daemon refuses a reused identifier");
    assert_eq!(
        owned.unresolved.len(),
        1,
        "and the run keeps the request rather than concluding that nothing was made: {refused}"
    );
    owned.unresolved.clear();
    drop(client);

    // From here the run behaves as though the first answer never arrived: it holds the request and
    // nothing else. Sending it again, on another connection, is what cleanup does.
    let again = ask_create(&host, &request, CREATE_ATTEMPTS)
        .await
        .unwrap_or_else(|failure| panic!("the daemon answers the exact duplicate: {failure}"));
    assert_eq!(
        again.session.session_id, made.session.session_id,
        "one request, one session, whichever connection asks about it"
    );
    assert!(
        again.deduplicated,
        "and the daemon says it is the one it recorded rather than a second launch"
    );

    // So a run that holds only the request closes what that request made.
    let mut holding = Owned::default();
    holding.unresolved.push(request);
    close_all(&host, &holding)
        .await
        .expect("closes what the run owns");
    assert!(
        list_sessions(&endpoint, host.environment_id)
            .await
            .expect("the daemon's session list")
            .is_empty(),
        "the run leaves no session of its own running"
    );
    let _ = host.controller;
    let _ = host.worker;
}

/// Returns the resident size of a process, in kibibytes.
///
/// A reading this host could not take is not zero. Treating it as zero would make the total smaller
/// than the truth, and a measurement that can only be wrong downwards is not evidence.
fn resident_kib(pid: u32) -> Result<u64, String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("read the process table: {error}"))?;
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| format!("the kernel reports process {pid}'s resident size"))
}

/// Returns the processor time a process has used, in seconds.
///
/// A reading this host could not take is not zero here either. A process the kernel will not name,
/// or a field it does not write the way this reads it, would otherwise be counted as having used
/// nothing, which is the one direction a resource measurement must never be wrong in.
///
/// Linux keeps the count in clock ticks, the process's `utime` and `stime` in `/proc/<pid>/stat`,
/// and that is what is read there. Its `ps` prints processor time in whole seconds, and every
/// process the idle measurement reads spends well under a second in its window, so two `ps`
/// readings of any of them are the same and their difference is zero whatever the process did.
#[cfg(target_os = "linux")]
fn processor_seconds(pid: u32) -> Result<f64, String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|error| format!("read process {pid}'s status: {error}"))?;
    // The second field is the command name in parentheses, and a name can hold spaces and
    // parentheses of its own, so the fields are counted from after the last parenthesis. The
    // first of them is the line's third field.
    let fields: Vec<&str> = status
        .rsplit_once(')')
        .map(|(_, rest)| rest.split_whitespace().collect())
        .ok_or_else(|| format!("process {pid}'s status names no command: `{status}`"))?;
    let ticks = |field: usize, name: &str| -> Result<u64, String> {
        fields
            .get(field - 3)
            .and_then(|value| value.parse().ok())
            .ok_or_else(|| format!("process {pid}'s status has no {name}: `{status}`"))
    };
    let used = ticks(14, "user time")? + ticks(15, "system time")?;
    Ok(used as f64 / rustix::param::clock_ticks_per_second() as f64)
}

/// Returns the processor time a process has used, in seconds.
///
/// A reading this host could not take is not zero here either. A process the kernel will not name,
/// or a column it does not print the way this reads it, would otherwise be counted as having used
/// nothing, which is the one direction a resource measurement must never be wrong in.
///
/// Outside Linux `ps` prints processor time to a hundredth of a second, and that is what is read.
#[cfg(not(target_os = "linux"))]
fn processor_seconds(pid: u32) -> Result<f64, String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("read the process table: {error}"))?;
    // `ps` prints processor time as `[[dd-]hh:]mm:ss`, with a fraction of a second where the
    // platform's own column carries one.
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Err(format!("the kernel reports process {pid}'s processor time"));
    }
    // A day field is scaled differently from the fields below it, and nothing this measurement
    // starts is a day old, so it is refused rather than read as another sixty of something.
    if text.contains('-') {
        return Err(format!(
            "process {pid} reports a processor time of `{text}`, which this reading does not cover"
        ));
    }
    let mut seconds = 0.0;
    for part in text.split(':') {
        let part: f64 = part
            .trim()
            .parse()
            .map_err(|_| format!("process {pid} reports a processor time of `{text}`"))?;
        seconds = seconds * 60.0 + part;
    }
    Ok(seconds)
}

/// Set in the environment of the process the processor-time regression starts, which makes that
/// process the one that spends the time.
#[cfg(unix)]
const SPENDER: &str = "KR_PERF_SPENDER";

/// How much processor time that process spends before it is read.
///
/// Less than a second on purpose: it is the size of what each process the idle measurement reads
/// spends in its window, and a reading in whole seconds reads it as none.
#[cfg(unix)]
const SPENT: Duration = Duration::from_millis(400);

/// How far a reading may be from what the process spent: the coarsest unit a platform counts
/// processor time in is a clock tick, a hundredth of a second, and this allows several.
#[cfg(unix)]
const READING_TOLERANCE: f64 = 0.05;

/// How long the spending process has from its start to its exit: every wait on it ends by then,
/// and one still running is stopped and the test fails.
#[cfg(unix)]
const SPENDER_LIMIT: Duration = Duration::from_secs(60);

/// A process that spent a fraction of a second of processor time is read as having spent it.
///
/// The idle measurement is the difference of two readings of each process five minutes apart, and
/// each of them spends well under a second in that time. A reading that rounds that away turns
/// every difference into zero, which meets the bound without measuring anything. So this test
/// starts a copy of its own binary that spends [`SPENT`] by its own processor clock, says how much
/// it spent and waits, and reads it the way the measurement does.
#[cfg(unix)]
#[test]
fn a_process_that_spends_processor_time_is_read_as_spending_it() {
    use std::io::BufRead as _;

    if std::env::var_os(SPENDER).is_some() {
        spend_and_wait();
        return;
    }
    let this = std::env::current_exe().expect("this test's own binary");
    let deadline = std::time::Instant::now() + SPENDER_LIMIT;
    let mut spender = std::process::Command::new(this)
        .args([
            "--exact",
            "a_process_that_spends_processor_time_is_read_as_spending_it",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env(SPENDER, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the spending process starts");
    // Its output is read on a thread of its own, to the end, so that nothing it writes on its way
    // out fails. Every wait on it ends at the one deadline: what it says, its exit, and so the
    // reader, which ends with its output.
    let output = spender.stdout.take().expect("its output");
    let (saying, said) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut output = std::io::BufReader::new(output);
        let mut line = String::new();
        while output.read_line(&mut line).unwrap_or(0) > 0 {
            if let Some(nanoseconds) = line
                .trim()
                .strip_prefix("spent ")
                .and_then(|nanoseconds| nanoseconds.parse::<u64>().ok())
            {
                let _ = saying.send(nanoseconds);
            }
            line.clear();
        }
    });
    let said = said.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
    let read = said.is_ok().then(|| processor_seconds(spender.id()));
    // Its input closing is what lets it end; one that has not ended by the deadline is stopped.
    drop(spender.stdin.take());
    let ended = loop {
        match spender.try_wait() {
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => break false,
            Ok(Some(_)) => break true,
        }
    };
    if !ended {
        let _ = spender.kill();
        let _ = spender.wait();
    }
    let _ = reader.join();

    assert!(
        ended,
        "the spending process ends within {SPENDER_LIMIT:?} of its start"
    );
    let said = said.expect("the spending process says what it spent");
    let spent = Duration::from_nanos(said).as_secs_f64();
    let read = read
        .expect("read once it said")
        .expect("the spending process's processor time is read");
    assert!(
        (read - spent).abs() <= READING_TOLERANCE,
        "a process that spent {spent:.3} s of processor time is read as having spent {read:.3} s"
    );
}

/// The spending process's part: spends [`SPENT`] of processor time, says how much it has spent in
/// all, and waits until its input closes, so that it is read while it is still running.
#[cfg(unix)]
fn spend_and_wait() {
    use std::io::{BufRead as _, Write as _};

    let spent = || {
        let clock = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        Duration::new(
            u64::try_from(clock.tv_sec).expect("a processor time"),
            u32::try_from(clock.tv_nsec).expect("a fraction of a second"),
        )
    };
    let mut spinning = 0_u64;
    while spent() < SPENT {
        spinning = std::hint::black_box(spinning.wrapping_add(1));
    }
    // On a line of its own: the harness has already begun a line for this test.
    let mut out = std::io::stdout().lock();
    let _ = write!(out, "\nspent {}\n", spent().as_nanos());
    let _ = out.flush();
    drop(out);
    let _ = std::io::stdin().lock().read_line(&mut String::new());
}

/// Takes one reading for every process, keeping which process it came from.
///
/// The totals are what the bounds are about, and a total that missed a bound says nothing about
/// where the cost is. This keeps the readings apart so the measurement can report both.
fn each<T>(
    pids: &[u32],
    daemon: u32,
    reading: impl Fn(u32) -> Result<T, String>,
) -> Result<Vec<(u32, T)>, String> {
    pids.iter()
        .copied()
        .chain(std::iter::once(daemon))
        .map(|pid| reading(pid).map(|value| (pid, value)))
        .collect()
}

/// Adds up one reading across every process, or says which one could not be taken.
fn total<T: std::iter::Sum>(
    pids: &[u32],
    daemon: u32,
    reading: impl Fn(u32) -> Result<T, String>,
) -> Result<T, String> {
    pids.iter()
        .copied()
        .chain(std::iter::once(daemon))
        .map(reading)
        .sum()
}

/// Returns the one-, five- and fifteen-minute load averages, or says it could not read them.
///
/// A resource figure is about a machine under conditions. The script around this measurement records
/// the load either side of the whole command, setup and cleanup included; this reads it at the two
/// edges of the processor window itself, which is the interval the figure is an average over. It is
/// a condition rather than a reading the figure is made of, so a host that will not report it says
/// so among the conditions instead of losing the measurement.
fn load_average() -> String {
    let reading = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|text| first_three(&text))
        .or_else(|| {
            let output = std::process::Command::new("sysctl")
                .args(["-n", "vm.loadavg"])
                .output()
                .ok()?;
            first_three(&String::from_utf8_lossy(&output.stdout))
        });
    reading.unwrap_or_else(|| "unread".to_owned())
}

/// Returns the first three numbers of a load-average reading, in whichever form the host printed it.
fn first_three(text: &str) -> Option<String> {
    let text = text
        .trim()
        .trim_matches(|character| character == '{' || character == '}');
    let reading: Vec<&str> = text.split_whitespace().take(3).collect();
    (reading.len() == 3).then(|| reading.join(" "))
}

/// What the idle measurement established.
struct Idle {
    cores: f64,
    resident: u64,
}

/// KR-PERF-003: idle local terminal resources, the daemon and twenty idle sessions' workers and root
/// shells together: processor use averaged over five minutes, and resident memory read once at the
/// end of that window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs for five minutes by design; scripts/performance.sh runs it"]
async fn idle_resources_for_twenty_sessions_and_thirty_two_views() {
    let host = host().await;
    // Every session this measurement creates is recorded here as it is created, and every one of
    // them is closed below whatever the measurement itself did. A measurement that ended by
    // panicking would otherwise leave a worker running for each session it had made.
    let mut owned = Owned::default();
    let measured = idle(&host, &mut owned).await;
    let closed = close_all(&host, &owned).await;

    let measured = measured.unwrap_or_else(|failure| panic!("the measurement: {failure}"));
    closed.unwrap_or_else(|failure| panic!("the sessions this measurement created: {failure}"));
    assert!(
        measured.cores < IDLE_CORE_FRACTION,
        "idle processor use is under one per cent of a core: {:.5}",
        measured.cores
    );
    assert!(
        measured.resident < RESIDENT_BOUND_KIB,
        "idle resident memory is under {RESIDENT_BOUND_KIB} KiB: {} KiB",
        measured.resident
    );
    let _ = host.controller;
    let _ = host.worker;
}

/// Takes the idle measurement, reporting a failure rather than ending the process on one.
async fn idle(host: &Host, owned: &mut Owned) -> Result<Idle, String> {
    for _ in 0..IDLE_SESSIONS {
        create(host, owned).await?;
    }
    if owned.sessions.len() != IDLE_SESSIONS {
        return Err(format!("{IDLE_SESSIONS} sessions were created"));
    }

    // Thirty-two views, spread over the sessions, each subscribed to output.
    let mut views = Vec::new();
    for index in 0..ATTACHED_VIEWS {
        let created = &owned.sessions[index % owned.sessions.len()];
        let endpoint = kr_ipc::paths::Endpoint::from_path(
            created
                .endpoint
                .as_ref()
                .ok_or_else(|| "a live session has an endpoint".to_owned())?,
        )
        .map_err(|error| format!("a session's endpoint: {error}"))?;
        views.push(observer(&endpoint, host.environment_id, created.session.session_id).await?);
    }

    // Every process this host is paying for: each session's root shell, and the worker that owns
    // it. The worker is where the canonical grid and the retained output live, so a measurement
    // that counted only the shell would leave out the thing it is meant to be measuring.
    let mut measured: Vec<u32> = Vec::new();
    // Which of them is which, so a figure that misses its bound says whether the cost is in the
    // hosts or in the shells they are holding.
    let mut shells: Vec<u32> = Vec::new();
    for created in &owned.sessions {
        // A session with no root process, or a worker the kernel will not name, is a measurement
        // this host cannot take. Quietly leaving it out would make the answer smaller than the
        // truth, which is the one direction a resource measurement must never be wrong in.
        let root = created
            .session
            .root_process
            .as_ref()
            .ok_or_else(|| "every live session names its root process".to_owned())?;
        let shell = u32::try_from(root.pid.get()).map_err(|_| "a process identifier".to_owned())?;
        measured.push(shell);
        shells.push(shell);
        measured.push(
            parent_of(shell)
                .ok_or_else(|| "the kernel names each root shell's worker".to_owned())?,
        );
    }
    measured.sort_unstable();
    measured.dedup();
    let workers = measured;
    // The daemon is this test process.
    let daemon = std::process::id();

    let started = Instant::now();
    let entering = load_average();
    let before = each(&workers, daemon, processor_seconds)?;
    tokio::time::sleep(IDLE_WINDOW).await;
    let after = each(&workers, daemon, processor_seconds)?;
    let leaving = load_average();
    let elapsed = started.elapsed().as_secs_f64();
    // Per process, because a total that missed its bound does not say what spent the time. A
    // reading that went backwards is an identifier that is no longer the process it was, and a
    // pair of readings that do not line up is not a difference: both are refused rather than
    // subtracted into a smaller answer.
    let mut spent: Vec<(u32, f64)> = Vec::with_capacity(after.len());
    for (&(pid, after), &(same, before)) in after.iter().zip(before.iter()) {
        if pid != same {
            return Err("both readings cover the same processes in the same order".to_owned());
        }
        if after < before {
            return Err(format!("process {pid}'s processor time went backwards"));
        }
        spent.push((pid, after - before));
    }
    let used: f64 = spent.iter().map(|&(_, seconds)| seconds).sum();
    let cores = used / elapsed;
    let kind = |pid: u32| {
        if pid == daemon {
            "the daemon"
        } else if shells.contains(&pid) {
            "a root shell"
        } else {
            "a session host"
        }
    };
    let by_kind = |wanted: &str| -> (usize, f64) {
        let mine = spent.iter().filter(|&&(pid, _)| kind(pid) == wanted);
        (
            mine.clone().count(),
            mine.map(|&(_, seconds)| seconds).sum(),
        )
    };
    let (daemons, in_daemon) = by_kind("the daemon");
    let (hosts, in_hosts) = by_kind("a session host");
    let (roots, in_roots) = by_kind("a root shell");
    let mut largest: Vec<(u32, f64)> = spent.clone();
    largest.sort_by(|left, right| right.1.total_cmp(&left.1));
    let resident = total(&workers, daemon, resident_kib)?;

    println!("KR-PERF-003 measurement");
    let grid = kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS;
    println!(
        "  conditions: {IDLE_SESSIONS} idle sessions, {ATTACHED_VIEWS} attached views, a release \
         build, no application running; each session holds an allocated canonical grid of {}x{} \
         with its scrollback cache",
        grid.columns.get(),
        grid.rows.get()
    );
    println!("  processor: {cores:.5} of one core averaged over {elapsed:.0} seconds");
    println!("  load average at the edges of that window: {entering} entering, {leaving} leaving");
    println!(
        "  processor time: {used:.3} s in all over {elapsed:.1} s: {in_hosts:.3} s across {hosts} \
         session hosts, {in_roots:.3} s across {roots} root shells, and {in_daemon:.3} s in \
         {daemons} daemon, which is this measurement's own process and also holds the \
         {ATTACHED_VIEWS} views' client ends"
    );
    println!(
        "  the processes that spent the most: {}",
        largest
            .iter()
            .take(5)
            .map(|&(pid, seconds)| format!("{} {pid} {seconds:.3} s", kind(pid)))
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "  resident: {resident} KiB across {} processes (each session's worker and its root shell) \
         and the daemon",
        workers.len()
    );
    println!(
        "  not measured: the whole-product figure with adapters and a model active, which belongs \
         to the tasks that add them"
    );
    // The views hold connections to the workers. They go before the sessions are closed.
    drop(views);
    Ok(Idle { cores, resident })
}

/// KR-PERF-004: a local attach to a warm worker, from the connection to the first usable screen of
/// a 120x40 session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement rather than a test; scripts/performance.sh runs it"]
async fn attach_to_a_usable_screen() {
    let host = host().await;
    // As above: what was created is closed whatever the measurement did with it.
    let mut owned = Owned::default();
    let measured = attach(&host, &mut owned).await;
    let closed = close_all(&host, &owned).await;

    let worst = measured.unwrap_or_else(|failure| panic!("the measurement: {failure}"));
    closed.unwrap_or_else(|failure| panic!("the sessions this measurement created: {failure}"));
    assert!(
        worst < ATTACH_BOUND,
        "the slowest attach reached a usable screen within {ATTACH_BOUND:?}: {worst:?}"
    );
    let _ = host.controller;
}

/// Times the attachments and returns the slowest, reporting a failure rather than ending on one.
async fn attach(host: &Host, owned: &mut Owned) -> Result<Duration, String> {
    create(host, owned).await?;
    let created = owned
        .sessions
        .last()
        .ok_or_else(|| "a session".to_owned())?;

    // Both presentations are measured. A terminal of the session's own size is handed the stream
    // directly; one of any other size is drawn a rendering of the canonical grid, and a person
    // waits for the screen either way.
    let direct = attach_samples(host, created, Dimensions::new(120, 40)).await;
    let projected = attach_samples(host, created, Dimensions::new(80, 24)).await;

    println!("KR-PERF-004 measurement");
    println!(
        "  conditions: a local attachment to a live session at 120x40, a release build, measured \
         from the connection to the moment a person could look at the screen: the connection, the \
         worker's proof, the attachment, the subscription, and the screen itself arriving, \
         decoding and being made ready to look at. A terminal of the session's own size reaches \
         that when bytes arrive that place the cursor, which is how a restoration ends; a \
         projected one reaches it when the last row page of its snapshot arrives, the client \
         library installs the screen and paints it, because a client holding part of a screen is \
         holding no screen and a screen nobody has drawn is not one anybody can look at. Writing \
         those bytes to a physical terminal, and that terminal's own render, are outside this \
         figure: there is no terminal here."
    );
    println!(
        "  direct, a terminal of the session's own size: {}",
        report(&direct)
    );
    println!(
        "  projected, a terminal of 80x24 onto the same session: {}",
        report(&projected)
    );
    if direct.len() != 5 {
        return Err("every direct attachment reached a screen".to_owned());
    }
    if projected.len() != 5 {
        return Err("every projected attachment reached a screen".to_owned());
    }
    direct
        .iter()
        .chain(projected.iter())
        .max()
        .copied()
        .ok_or_else(|| "samples".to_owned())
}

/// Closes every session this measurement created and waits for the daemon to record each closure.
///
/// A measurement that simply exited would leave a worker running for every session it made, for as
/// long as the machine stayed up, because a worker is deliberately not ended by whatever created
/// it. Every session a run creates is therefore closed by that run. What is waited for is the
/// daemon's own record of the closure rather than the worker's entry in the process table, because
/// a process that has exited and has not yet been reaped is still an entry and is not a session.
async fn close_all(host: &Host, owned: &Owned) -> Result<(), String> {
    let endpoint = host
        .temp
        .environment()
        .controller_endpoint()
        .map_err(|error| format!("the daemon's endpoint: {error}"))?;
    // The connection is opened again whenever it fails. A transport failure on one close would
    // otherwise leave every session after it in the list unasked, which is the thing this exists
    // to prevent.
    let mut client = None;
    let mut refused = Vec::new();
    // What the daemon says this environment holds, not only what the measurement kept a note of.
    // A create whose answer never arrived is a session all the same, and this host is the
    // measurement's own, so everything in it is the measurement's to close.
    let mut wanted: std::collections::BTreeSet<_> = owned
        .sessions
        .iter()
        .map(|created| created.session.session_id)
        .collect();
    // Asked until it answers. A list that failed once is not an empty environment, and treating it
    // as one is how a live worker outlives the run that made it.
    let mut listing = Err("the daemon's session list was never asked".to_owned());
    for _ in 0..LIST_ATTEMPTS {
        listing = list_sessions(&endpoint, host.environment_id).await;
        if listing.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    match listing {
        Ok(listed) => wanted.extend(listed),
        Err(error) => refused.push(format!("the daemon's session list: {error}")),
    }
    // A create whose answer was lost is asked about again here, under the identifier it was made
    // with. The daemon answers a repeat with the outcome it recorded, so this names the session
    // that create made; if it made none, this makes one, which is then closed with the rest. Either
    // way nothing this measurement started is left behind, which is what the list alone cannot
    // promise: a worker the daemon momentarily cannot read is absent from it.
    for request in &owned.unresolved {
        let action = request.action_id;
        match ask_create(host, request, CREATE_ATTEMPTS).await {
            Ok(created) => {
                wanted.insert(created.session.session_id);
            }
            // The daemon would not name what this request made. Everything live in this environment
            // is closed below whatever that was, and the run says it could not account for the
            // request rather than ending quietly.
            Err(failure) => {
                refused.push(format!("{action}: what it made was never named: {failure}"));
            }
        }
    }
    if wanted.is_empty() {
        return if refused.is_empty() {
            Ok(())
        } else {
            Err(format!("the daemon answered: {refused:?}"))
        };
    }
    for session_id in &wanted {
        let session_id = *session_id;
        let mut attempts = 0;
        loop {
            attempts += 1;
            let connected = match client.take() {
                Some(client) => client,
                None => {
                    match LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
                        Ok(client) => client,
                        Err(error) => {
                            refused.push(format!("{session_id}: connect: {error}"));
                            break;
                        }
                    }
                }
            };
            let mut connected = connected;
            match connected
                .mutate(
                    Method::SessionClose,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget {
                        environment_id: host.environment_id,
                        session_id: Nullable::some(session_id),
                        session_epoch: Nullable::some(SessionEpoch::V1),
                        application_instance_id: Nullable::null(),
                        agent_binding_revision: Nullable::null(),
                    },
                    &kr_protocol::session::SessionCloseParams { session_id },
                )
                .await
            {
                Ok(Ok(_)) => {
                    client = Some(connected);
                    break;
                }
                // The daemon answered and refused. The connection is still good, and the answer is
                // reported at the end rather than stopping the rest of the closes.
                Ok(Err(error)) => {
                    client = Some(connected);
                    refused.push(format!("{session_id}: {error}"));
                    break;
                }
                // The connection failed. It is opened again and this session asked once more,
                // because a session that was never asked is a worker that keeps running.
                Err(error) => {
                    if attempts >= 2 {
                        refused.push(format!("{session_id}: {error}"));
                        break;
                    }
                }
            }
        }
    }

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let mut connected = match client.take() {
            Some(client) => client,
            None => LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
                .await
                .map_err(|error| format!("connect to the daemon: {error}"))?,
        };
        let listed = connected
            .request(
                Method::SessionList,
                &kr_protocol::session::SessionListParams {
                    environment_id: Nullable::null(),
                    include_closed: true,
                },
            )
            .await
            .map_err(|error| format!("the list call: {error}"))
            .and_then(|answer| answer.map_err(|error| format!("the list failed: {error}")))
            .and_then(|value| {
                value
                    .to_typed::<kr_protocol::session::SessionListResult>()
                    .map_err(|error| format!("the list result: {error}"))
            });
        client = Some(connected);
        let listed = listed?;
        let closed: std::collections::BTreeSet<_> = listed
            .sessions
            .iter()
            .filter(|summary| summary.state == kr_protocol::session::SessionState::Closed)
            .map(|summary| summary.session_id)
            .collect();
        let remaining: Vec<_> = wanted.difference(&closed).copied().collect();
        if remaining.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "every session this measurement created finished closing: {remaining:?} did not"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    if refused.is_empty() {
        Ok(())
    } else {
        Err(format!("the daemon accepted every close: {refused:?}"))
    }
}

/// Returns every session the daemon holds for this environment, closed ones aside.
async fn list_sessions(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
) -> Result<Vec<SessionId>, String> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .map_err(|error| format!("connect to the daemon: {error}"))?;
    let listed: kr_protocol::session::SessionListResult = client
        .request(
            Method::SessionList,
            &kr_protocol::session::SessionListParams {
                environment_id: Nullable::some(environment_id),
                include_closed: false,
            },
        )
        .await
        .map_err(|error| format!("the list call: {error}"))?
        .map_err(|error| format!("the list failed: {error}"))?
        .to_typed()
        .map_err(|error| format!("the list result: {error}"))?;
    Ok(listed
        .sessions
        .iter()
        .filter(|summary| summary.state != kr_protocol::session::SessionState::Closed)
        .map(|summary| summary.session_id)
        .collect())
}

/// Returns a process's parent, which for a session's root shell is its worker.
fn parent_of(pid: u32) -> Option<u32> {
    let listing = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&listing.stdout)
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|parent| *parent > 1)
}

/// Renders a set of samples for the measurement's own output.
fn report(samples: &[Duration]) -> String {
    samples
        .iter()
        .map(|sample| format!("{:.3} ms", sample.as_secs_f64() * 1000.0))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Times five attachments of one size, from the connection to a screen somebody could look at.
async fn attach_samples(
    host: &Host,
    created: &SessionCreateResult,
    dimensions: Dimensions,
) -> Vec<Duration> {
    let endpoint =
        kr_ipc::paths::Endpoint::from_path(created.endpoint.as_ref().expect("a live session"))
            .expect("an endpoint");
    let mut samples = Vec::new();
    for _ in 0..5 {
        let started = Instant::now();
        // A usable screen is the whole sequence a person waits for: the connection, the worker's
        // proof, the attachment, the subscription, the screen arriving, and the client making it
        // ready to look at. A measurement that stopped at the first byte would be measuring the
        // transport.
        let Ok(mut client) = LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await
        else {
            // A sample that could not be taken is the absence of one. It is reported that way
            // rather than by panicking, because the caller has sessions to close first.
            return Vec::new();
        };
        let mut requested = CanonicalSet::new();
        requested.insert(AttachmentCapability::ObserveTerminal);
        requested.insert(AttachmentCapability::Input);
        let attached: kr_protocol::attachment::SessionAttachResult = match client
            .mutate(
                Method::SessionAttach,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget {
                    environment_id: host.environment_id,
                    session_id: Nullable::some(created.session.session_id),
                    session_epoch: Nullable::some(SessionEpoch::V1),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                &SessionAttachParams {
                    session_id: created.session.session_id,
                    mode: AttachMode::Terminal,
                    claim_geometry: false,
                    dimensions: Nullable::some(dimensions),
                    terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                    requested,
                },
            )
            .await
        {
            Ok(Ok(value)) => match value.to_typed() {
                Ok(attached) => attached,
                Err(_) => return Vec::new(),
            },
            _ => return Vec::new(),
        };
        let mut streams = CanonicalSet::new();
        streams.insert(EventStream::Output);
        if !matches!(
            client
                .request(
                    Method::EventsSubscribe,
                    &EventsSubscribeParams {
                        session_id: created.session.session_id,
                        attachment_id: attached.attachment.attachment_id,
                        streams,
                        from_cursor: Nullable::null(),
                    },
                )
                .await,
            Ok(Ok(_))
        ) {
            return Vec::new();
        }
        // The screen itself. This is what the person sees, and it is where the clock stops. The
        // two presentations reach it by different routes: a terminal of the session's own size is
        // sent the bytes that put it into the session's state, and a projected client is sent the
        // canonical grid as state and draws it itself. Both are held to the same standard, which
        // is a screen somebody could look at: bytes that place the cursor, or a whole snapshot the
        // client library has installed and painted.
        let mut projection = kr_client::projection::Projection::new();
        let screen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Ok(frame) = client.recv().await else {
                    return false;
                };
                let kr_protocol::envelope::ControlFrame::Notification(notification) = frame else {
                    continue;
                };
                if notification.event_type.as_str() == "session.output" {
                    if let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                    {
                        // A screen a terminal can draw, not merely a frame that arrived: the
                        // payload decodes and it places the cursor, which every restoration ends
                        // by doing.
                        return ends_a_restoration(event.bytes.as_slice());
                    }
                    continue;
                }
                let Some(event) = kr_client::projection::decode(
                    notification.event_type.as_str(),
                    &notification.payload,
                ) else {
                    continue;
                };
                // Applied as the client applies it, which is the only thing that can say whether
                // the client is holding a screen: a page belonging to another snapshot, or an
                // update against a base it does not hold, leaves it holding nothing.
                let applied = projection.apply(event);
                if matches!(applied, kr_client::projection::Applied::Installed) {
                    let Some(held) = projection.screen() else {
                        return false;
                    };
                    // And drawn. A client holding a screen nobody has drawn is not a screen a
                    // person can look at, and drawing it is the client's own work, so it is inside
                    // the figure rather than outside it.
                    let painted = kr_client::projection::paint::install(
                        held,
                        kr_client::projection::paint::Window::of(held),
                        kr_client::projection::paint::Keyboard::NOTHING,
                    );
                    return !painted.bytes.is_empty();
                }
            }
        })
        .await
        .unwrap_or(false);
        // A sample that never reached a screen is not a sample. It is reported as the absence of
        // one rather than panicking here, because the caller has sessions to close first.
        if !screen {
            return Vec::new();
        }
        samples.push(started.elapsed());
    }
    samples
}

/// Whether a restoration's bytes end the way a restoration ends.
///
/// Not "contains an escape sequence": a frame carrying half a screen also does. And not a cursor
/// address alone, because a restoration addresses the cursor for every row it draws. What only the
/// end has is both: the cursor placed where the session's own cursor is, and the cursor's
/// visibility set after it. Finding the two together is finding a screen a terminal can draw.
fn ends_a_restoration(bytes: &[u8]) -> bool {
    places_the_cursor(bytes) && sets_cursor_visibility(bytes)
}

/// Whether the bytes *end* by setting the cursor's visibility, which is how a restoration ends.
///
/// Not "contains": a restoration sets mode 25 among the modes it installs, before it paints a
/// single row. What only its end has is this sequence with nothing after it.
fn sets_cursor_visibility(bytes: &[u8]) -> bool {
    bytes.ends_with(b"\x1b[?25h") || bytes.ends_with(b"\x1b[?25l")
}

/// Whether the bytes address the cursor.
fn places_the_cursor(bytes: &[u8]) -> bool {
    let mut index = 0;
    while let Some(position) = bytes[index..]
        .windows(2)
        .position(|window| window == b"\x1b[")
    {
        let mut at = index + position + 2;
        while bytes
            .get(at)
            .is_some_and(|byte| byte.is_ascii_digit() || *byte == b';')
        {
            at += 1;
        }
        if matches!(bytes.get(at), Some(b'H') | Some(b'f')) {
            return true;
        }
        index = index + position + 2;
        if index >= bytes.len() {
            break;
        }
    }
    false
}

/// Attaches an observing view and subscribes it to output.
async fn observer(
    endpoint: &kr_ipc::paths::Endpoint,
    environment_id: EnvironmentId,
    session_id: SessionId,
) -> Result<LocalClient, String> {
    let mut client = LocalClient::connect(endpoint, LocalClientKind::Cli, build())
        .await
        .map_err(|error| format!("connect to a worker: {error}"))?;
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &SessionAttachParams {
                session_id,
                mode: AttachMode::Terminal,
                claim_geometry: false,
                // The session's own size, with the terminal this client probed declared, so the
                // attachment is served the stream directly. A different size, or no declaration,
                // is served a rendering of the canonical screen instead.
                dimensions: Nullable::some(kr_protocol::session::INVISIBLE_DEFAULT_DIMENSIONS),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .map_err(|error| format!("the attach call: {error}"))?
        .map_err(|error| format!("the attach failed: {error}"))?
        .to_typed()
        .map_err(|error| format!("the attach result: {error}"))?;
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    client
        .request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id,
                attachment_id: attached.attachment.attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .map_err(|error| format!("the subscribe call: {error}"))?
        .map_err(|error| format!("the subscription failed: {error}"))?;
    Ok(client)
}
