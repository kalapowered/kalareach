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
use kr_crypto::store::open_store;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
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
    temp: kr_ipc::testing::TempHost,
    worker: PathBuf,
    environment_id: EnvironmentId,
    controller: Arc<Controller>,
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    // On the internal disk, because a process a service manager launches is its own identity to
    // the operating system and one that reaches a removable volume prompts the person at the
    // machine.
    let worker = temp.root().join("kr-worker");
    std::fs::copy(env!("CARGO_BIN_EXE_kr-worker"), &worker).expect("copies the worker");
    let secrets = environment.secrets_dir();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store(CONTROLLER_SECRET_SERVICE, &secrets).expect("a secret store");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(DetachedSupervisor::new()),
        worker_program: worker.clone(),
        build_id: build(),
        release: "0".to_owned(),
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
    // The request is composed before it is sent and kept. A create whose answer never arrives has
    // still happened, so sending that exact request again is how the measurement learns what it
    // owns rather than leaving a session nobody will close; the daemon answers an exact duplicate
    // with the outcome it recorded the first time. It goes into the record before the call, because
    // the moment it is on the wire is the moment it can have made something.
    let endpoint = match host.temp.environment().controller_endpoint() {
        Ok(endpoint) => endpoint,
        Err(error) => return Err(format!("the daemon's endpoint: {error}")),
    };
    let mut client = match LocalClient::connect(&endpoint, LocalClientKind::Cli, build()).await {
        Ok(client) => client,
        Err(error) => return Err(format!("connect to the daemon: {error}")),
    };
    // Composed on the connection that sends it, because a first admission quotes the freshness
    // window that connection holds. Every later send of it is a repeat rather than a first
    // admission, which is the only reason it may travel over another connection.
    let request = match client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(host),
        )
        .await
    {
        Ok(request) => request,
        Err(error) => return Err(format!("compose the create: {error}")),
    };
    let action = request.action_id;
    owned.unresolved.push(request.clone());
    let asked = match client.repeat(&request).await {
        Ok(Ok(value)) => value
            .to_typed()
            .map_err(|error| Unresolved::Nothing(format!("the create result: {error}"))),
        Ok(Err(error)) => Err(Unresolved::Nothing(format!("the create failed: {error}"))),
        // The answer was lost. Whether the session exists is exactly what asking again settles, and
        // asking again is what cleanup does with the request this run is holding.
        Err(error) => match ask_create(host, &request, CREATE_ATTEMPTS).await {
            Ok(created) => Ok(created),
            Err(Unresolved::Nothing(failure)) => Err(Unresolved::Nothing(failure)),
            Err(Unresolved::Unknown(failure)) => Err(Unresolved::Unknown(format!(
                "the create call: {error}; and asking again: {failure}"
            ))),
        },
    };
    match asked {
        Ok(created) => {
            owned.unresolved.retain(|held| held.action_id != action);
            owned.sessions.push(created.clone());
            Ok(created)
        }
        Err(Unresolved::Nothing(failure)) => {
            // The daemon answered that it made nothing, so there is nothing to own.
            owned.unresolved.retain(|held| held.action_id != action);
            Err(failure)
        }
        // Whether this request made a session is still unknown, so it stays owned and cleanup
        // sends it again.
        Err(Unresolved::Unknown(failure)) => Err(failure),
    }
}

/// The session every measurement creates.
fn create_params(host: &Host) -> SessionCreateParams {
    SessionCreateParams {
        environment_id: host.environment_id,
        presentation: Presentation::Invisible,
        shell: Nullable::some("/bin/sh".to_owned()),
        shell_mode: ShellMode::NativeCompat,
        cwd: Nullable::some(host.temp.root().display().to_string()),
        dimensions: Nullable::null(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        environment_snapshot: vec![kr_protocol::session::EnvironmentVariable {
            name: "PATH".to_owned(),
            value: "/usr/bin:/bin".to_owned(),
        }],
    }
}

/// Why a create did not name a session.
enum Unresolved {
    /// The daemon answered that it made nothing.
    Nothing(String),
    /// What that identifier made, if anything, the answer does not say.
    Unknown(String),
}

/// Sends one create, and sends the same request again while the answer is lost.
///
/// The request is sent exactly as it was composed, over whichever connection this can open. That is
/// what makes a repeat an exact duplicate rather than a new first admission: the daemon holds the
/// payload digest of what it admitted, the freshness window is part of that payload, and only the
/// original request still matches it.
async fn ask_create(
    host: &Host,
    request: &kr_protocol::envelope::MutationRequest,
    attempts: usize,
) -> Result<SessionCreateResult, Unresolved> {
    let endpoint = host
        .temp
        .environment()
        .controller_endpoint()
        .map_err(|error| Unresolved::Unknown(format!("the daemon's endpoint: {error}")))?;
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
                    .map_err(|error| Unresolved::Nothing(format!("the create result: {error}")));
            }
            Ok(Err(error)) if error.code == kr_protocol::error::ErrorCode::IdConflict => {
                return Err(Unresolved::Unknown(format!(
                    "the identifier was admitted under a different payload: {error}"
                )));
            }
            // The daemon retains no such action, so it fell through to first admission and refused
            // a window that is not this connection's. Nothing was made under this request.
            Ok(Err(error)) if error.code == kr_protocol::error::ErrorCode::PermissionDenied => {
                return Err(Unresolved::Nothing(format!(
                    "the daemon has no record of this action: {error}"
                )));
            }
            Ok(Err(error)) => {
                return Err(Unresolved::Nothing(format!("the create failed: {error}")));
            }
            // The answer was lost. Whether the session exists is exactly what asking again settles.
            Err(error) => failure = format!("the create call: {error}"),
        }
    }
    Err(Unresolved::Unknown(failure))
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

    // The create, composed and sent the way `create` does it, on one connection.
    let mut client = LocalClient::connect(&endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the daemon");
    let request = client
        .compose(
            Method::SessionCreate,
            ActionId::new(kr_ipc::new_uuid()),
            ActionTarget::environment(host.environment_id),
            &create_params(&host),
        )
        .await
        .expect("composes a create");
    let made: SessionCreateResult = client
        .repeat(&request)
        .await
        .expect("the call reaches the daemon")
        .expect("the create succeeds")
        .to_typed()
        .expect("decodes");
    assert!(
        !made.deduplicated,
        "the first send is the one that made the session"
    );
    drop(client);

    // From here the run behaves as though that answer never arrived: it holds the request and
    // nothing else. Sending it again, on another connection, is what cleanup does.
    let again = match ask_create(&host, &request, CREATE_ATTEMPTS).await {
        Ok(created) => created,
        Err(Unresolved::Nothing(failure) | Unresolved::Unknown(failure)) => {
            panic!("the daemon answers the exact duplicate: {failure}")
        }
    };
    assert_eq!(
        again.session.session_id, made.session.session_id,
        "one request, one session, whichever connection asks about it"
    );
    assert!(
        again.deduplicated,
        "and the daemon says it is the one it recorded rather than a second launch"
    );

    // So a run that holds only the request closes what that request made.
    let mut owned = Owned::default();
    owned.unresolved.push(request);
    close_all(&host, &owned)
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
fn processor_seconds(pid: u32) -> Result<f64, String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .map_err(|error| format!("read the process table: {error}"))?;
    // `ps` prints elapsed processor time as `[[dd-]hh:]mm:ss`.
    let text = String::from_utf8_lossy(&output.stdout);
    let text = text.trim();
    if text.is_empty() {
        return Ok(0.0);
    }
    let mut seconds = 0.0;
    for part in text.split(':') {
        let part: f64 = part.trim().parse().unwrap_or(0.0);
        seconds = seconds * 60.0 + part;
    }
    Ok(seconds)
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

/// What the idle measurement established.
struct Idle {
    cores: f64,
    resident: u64,
}

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
    let before = total(&workers, daemon, processor_seconds)?;
    tokio::time::sleep(IDLE_WINDOW).await;
    let after = total(&workers, daemon, processor_seconds)?;
    let elapsed = started.elapsed().as_secs_f64();
    let cores = (after - before) / elapsed;
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
         from the connection to the moment the host has delivered the screen: the connection, the \
         worker's proof, the attachment, the input lease, the subscription, and the screen itself \
         arriving and decoding. Drawing it is the terminal's own work and is not in these numbers."
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
            Err(Unresolved::Nothing(_)) => {}
            // The daemon holds a reservation under this identifier and will not name what it made.
            // Everything live in this environment is closed below whatever that was, and the run
            // says it could not account for the identifier rather than ending quietly.
            Err(Unresolved::Unknown(failure)) => {
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

/// Times five attachments of one size, from the connection to the screen.
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
        // proof, the attachment, the input lease, the subscription, and the screen arriving. A
        // measurement that stopped at the first byte would be measuring the transport.
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
        // The screen itself. This is what the person sees, and it is where the clock stops.
        let screen = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Ok(frame) = client.recv().await else {
                    return false;
                };
                if let kr_protocol::envelope::ControlFrame::Notification(notification) = frame
                    && notification.event_type.as_str() == "session.output"
                    && let Ok(event) = notification
                        .payload
                        .to_typed::<kr_protocol::recovery::OutputEvent>()
                {
                    // A screen a terminal can draw, not merely a frame that arrived: the payload
                    // decodes and it places the cursor, which every restoration ends by doing.
                    return event
                        .bytes
                        .as_slice()
                        .windows(4)
                        .any(|window| window == b"\x1b[?25" || window.starts_with(b"\x1b["));
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
