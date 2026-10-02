//! The KalaReach control daemon process.
//!
//! One per OS user and environment. It takes the environment's singleton lock, advances its
//! generation, rebuilds its directory of workers by challenging each one, and then serves two
//! sockets: the owner-only rendezvous socket a starting worker reports itself on, and the client
//! endpoint the `kr` command line reaches.
//!
//! Stopping this process does not stop a session. Workers belong to the platform's service
//! manager, and a replacement daemon finds them again through the registry and their descriptors.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use kr_crypto::store::StoreSelection;
use kr_ipc::endpoint::Listener;
use kr_ipc::install::Running;
use kr_ipc::paths::HostPaths;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::ids::BuildId;
use kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE;

/// The release this build reports.
const RELEASE: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "kr-controller",
    version,
    about = "The KalaReach control daemon. One per OS user and environment."
)]
struct Arguments {
    /// The per-user runtime directory. The platform default is used when this is absent.
    #[arg(long)]
    runtime_dir: Option<PathBuf>,
    /// The per-user state directory. The platform default is used when this is absent.
    #[arg(long)]
    state_dir: Option<PathBuf>,
    /// The worker executable this daemon starts.
    #[arg(long)]
    worker: Option<PathBuf>,
    /// Where this daemon keeps its device keys.
    ///
    /// The default is the platform's own credential store, which is what an installed host uses.
    /// `file` puts them in this environment's `secrets` directory instead, and is for a test, a
    /// bench or a demonstration run, whose keys belong to the run and go with it.
    #[arg(long, value_enum, default_value_t = SecretStoreChoice::Platform)]
    secret_store: SecretStoreChoice,
    /// Start in a session and a process group of its own, with no controlling terminal.
    ///
    /// For a command that starts this daemon on demand, as `kr new` does under the standalone
    /// start: the daemon outlives that command, and nothing the terminal the command ran in does, a
    /// hangup, an interrupt or the end of a login, reaches it. The process it is given must not
    /// already lead a process group, which a process a program starts directly never does.
    #[cfg(unix)]
    #[arg(long)]
    own_session: bool,
    /// Seed the catalogue from the signed generation compiled into this build.
    ///
    /// A shipped build always seeds, and refuses the bundle until the production root exists. A
    /// build with debug assertions trusts the development lineage's root, which anybody can sign
    /// with, so it seeds only when asked: a test that starts this daemon and expects an empty
    /// catalogue is not changed by it.
    #[cfg(debug_assertions)]
    #[arg(long)]
    seed: bool,
    /// Run as the environment's starter rather than as its daemon.
    ///
    /// Windows only, where the environment's scheduled task runs this: it takes the one launch
    /// the daemon has handed over, or a request to start the daemon, creates that process outside
    /// this one's job, and exits. The environment is the one the two roots hold.
    #[arg(long, requires_all = ["runtime_dir", "state_dir"])]
    starter: bool,
}

/// The store a daemon was told to keep its device keys in, as the command line spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SecretStoreChoice {
    /// The operating system's credential store, with the fallback section 10 allows.
    Platform,
    /// This environment's own `secrets` directory, named deliberately.
    File,
}

impl From<SecretStoreChoice> for StoreSelection {
    fn from(choice: SecretStoreChoice) -> Self {
        match choice {
            SecretStoreChoice::Platform => Self::Platform,
            SecretStoreChoice::File => Self::File,
        }
    }
}

fn main() -> ExitCode {
    // First, before anything is read or started: a daemon of an installed release holds that
    // release for as long as it runs, which covers the workers it starts from it until each holds
    // the release itself, and does not start at all once the release is being removed.
    let running = match kr_ipc::install::this_process() {
        Ok(running) => running,
        Err(error) => {
            eprintln!("kr-controller: {error}");
            return ExitCode::FAILURE;
        }
    };
    let arguments = Arguments::parse();
    // Before any thread exists: a session is the calling process's to leave, and nothing the
    // terminal does may reach the daemon from here on.
    #[cfg(unix)]
    if arguments.own_session
        && let Err(error) = rustix::process::setsid()
    {
        eprintln!("kr-controller: could not start a session of its own: {error}");
        return ExitCode::FAILURE;
    }
    if arguments.starter {
        return starter(&arguments);
    }
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("kr-controller: could not start: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(arguments, running)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kr-controller: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(
    arguments: Arguments,
    running: &'static Running,
) -> Result<(), Box<dyn std::error::Error>> {
    // A daemon of an installed release starts its own release's worker with its own release's
    // shell packages, and nothing that names another program or other packages is taken: a session
    // it launched with them would run a release the host's store does not hold for it.
    if running.store().is_some() {
        if arguments.worker.is_some() {
            return Err(
                "a daemon of an installed release starts its own release's worker, and \
                        --worker names another program; start it without --worker"
                    .into(),
            );
        }
        if std::env::var_os(PACKAGE_ROOT_VARIABLE).is_some() {
            return Err(format!(
                "a daemon of an installed release starts sessions with its own release's shell \
                 packages, and {PACKAGE_ROOT_VARIABLE} names others; start it with \
                 {PACKAGE_ROOT_VARIABLE} unset"
            )
            .into());
        }
    }
    let paths = match (arguments.runtime_dir, arguments.state_dir) {
        (Some(runtime), Some(state)) => HostPaths::new(runtime, state)?,
        (runtime, state) => {
            let discovered = HostPaths::discover()?;
            HostPaths::new(
                runtime.unwrap_or_else(|| discovered.runtime_root().to_path_buf()),
                state.unwrap_or_else(|| discovered.state_root().to_path_buf()),
            )?
        }
    };
    let environment_id = paths.open_environment_id()?;
    let environment = paths.environment(environment_id);
    environment.create()?;

    // The identity is created once, on a genuine first start, and loaded every time after that. A
    // missing key on a later start is a recovery condition: every live worker holds the public
    // half, and section C makes rotation something that closes them all, never something that
    // happens because a store was empty.
    //
    // This runs inside `Controller::start`, after the environment's singleton lock is held, so two
    // daemons starting at once cannot both decide they are the first.
    let secrets_dir = environment.secrets_dir();
    let marker = environment.state_dir().join("controller-identity");
    let selection = StoreSelection::from(arguments.secret_store);
    let open_identity = move || -> kr_controller::Result<ControllerIdentity> {
        let store = selection
            .open(CONTROLLER_SECRET_SERVICE, &secrets_dir)
            .map_err(|error| kr_controller::ControllerError::NotConfigured(error.to_string()))?;
        // Named in the daemon's own output, so a run's log says where its keys went rather than
        // leaving it to be worked out from the command line that started it.
        println!("kr-controller: keys in {}", store.store.describe());
        let initialised_before = marker.exists();
        let identity =
            ControllerIdentity::open(store.store.as_ref(), environment_id, initialised_before)
                .map_err(|error| {
                    kr_controller::ControllerError::NotConfigured(error.to_string())
                })?;
        if !initialised_before {
            kr_ipc::paths::write_owner_only_file(
                &marker,
                format!("{:?}\n", store.kind).as_bytes(),
            )?;
        }
        Ok(identity)
    };

    let worker_program = arguments.worker.unwrap_or_else(default_worker_program);
    let release = running.stated_release(RELEASE);
    let build_id = BuildId::new(format!("kr-controller/{release}"))?;
    // Held until the daemon has taken its environment: an update that switches `current` from then
    // on hands the environment over first.
    let controller = {
        #[cfg(unix)]
        let _starting = hold_the_start(running, &paths)?;
        kr_controller::service::Controller::start(kr_controller::service::ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(open_identity),
            secret_store: selection,
            boot_identity: kr_ipc::identity::boot_identity()?,
            supervisor: kr_controller::supervision::detect(),
            worker_program,
            build_id,
            release: release.to_owned(),
            // An installed release's own packages; otherwise the installation's own package
            // directory, or whatever KR_SHELL_PACKAGES names.
            shell_packages: running.shells(),
            // The daemon is this host's local presenter: a session created here or on a paired
            // device can ask for a local tab, and the daemon is the only party that can open one.
            terminal: Box::new(
                kr_controller::supervision::InstalledTerminals::in_environment(
                    environment.state_dir().to_path_buf(),
                ),
            ),
        })
        .await?
    };
    // The catalogue is seeded from the generation compiled into this build, once, before an
    // endpoint a client could reach is bound: a request that came meanwhile would wait for the
    // catalogue, and none can come. A seed that fails or does nothing is reported and the daemon
    // starts all the same.
    #[cfg(debug_assertions)]
    let seeds = arguments.seed;
    #[cfg(not(debug_assertions))]
    let seeds = true;
    if seeds {
        match kr_plugin_catalogue::SeedBundle::embedded() {
            Ok(bundle) => {
                let outcome = controller.seed_catalogue(&bundle).await;
                println!("kr-controller: bundled catalogue: {}", outcome.report());
            }
            Err(error) => {
                eprintln!("kr-controller: the bundled catalogue is not whole: {error}");
            }
        }
    }
    // Every delivery exchange goes to an origin it already knows: a notification, a status
    // question and a renewal to the gateway its credential names, and a webhook message to the
    // address its owner configured. Each goes through the managed transport of that origin, and
    // through the proxy this daemon started with, the one its network endpoint uses.
    controller.attach_delivery_transport(std::sync::Arc::new(
        kr_controller::push::transport::ManagedTransports::new(controller.started_proxy()?),
    ));

    let rendezvous = Listener::bind(&environment.rendezvous_endpoint()?)?;
    let clients = Listener::bind(&environment.controller_endpoint()?)?;
    // A 1 MiB attachment chunk does not fit a control frame, so transfer chunks have their own
    // endpoint, framed at the attachment bound and served by the same admission path.
    let chunks = kr_controller::transfer::bind_chunk_endpoint(&environment)?;
    println!(
        "kr-controller: environment {environment_id} generation {}",
        controller.generation()
    );

    let rendezvous_task =
        tokio::spawn(std::sync::Arc::clone(&controller).serve_rendezvous(rendezvous));
    let client_task = tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(clients));
    let chunk_task = tokio::spawn(kr_controller::transfer::serve_chunks(
        std::sync::Arc::downgrade(&controller),
        chunks,
    ));
    tokio::select! {
        result = rendezvous_task => result??,
        result = client_task => result??,
        result = chunk_task => result?,
        result = tokio::signal::ctrl_c() => result?,
        // An update of this host, which a daemon of the new release replaces this one for. Like
        // any other stop, it stops no session: the workers belong to the service manager.
        () = controller.handed_over() => {
            println!("kr-controller: stopped: an update of this host replaces this daemon");
        }
    }
    Ok(())
}

/// Runs this process as the environment's starter.
#[cfg(windows)]
fn starter(arguments: &Arguments) -> ExitCode {
    let (Some(runtime), Some(state)) = (&arguments.runtime_dir, &arguments.state_dir) else {
        return ExitCode::FAILURE;
    };
    ExitCode::from(kr_controller::supervision::windows::run_starter(runtime, state) as u8)
}

/// A starter exists only where a scheduled task starts each worker.
#[cfg(not(windows))]
fn starter(_arguments: &Arguments) -> ExitCode {
    eprintln!(
        "kr-controller: --starter runs only on Windows, where the environment's scheduled task \
         starts it"
    );
    ExitCode::FAILURE
}

/// Holds the store's start, where this is a daemon of an installed release, until the daemon has
/// taken its environment, and records the roots it serves.
///
/// Held shared, as every starting daemon of the store holds it, and an update takes it exclusively
/// while it switches `current`. So `current` cannot change between this daemon's look at it and its
/// taking the environment: a daemon that finds another release current has been superseded, and
/// exits rather than serving an environment the current release's daemon is about to serve.
#[cfg(unix)]
fn hold_the_start(
    running: &Running,
    paths: &HostPaths,
) -> Result<Option<kr_ipc::install::StoreLock>, Box<dyn std::error::Error>> {
    let (Some(store), Some(release)) = (running.store(), running.release()) else {
        return Ok(None);
    };
    let held = store.lock_start()?;
    match store.current()? {
        Some(current) if current == *release => {}
        Some(current) => {
            return Err(format!(
                "this daemon is of release {release}, and this host's current release is \
                 {current}: that release's daemon serves this host, started through {}",
                store.stable(kr_ipc::install::Program::Controller).display()
            )
            .into());
        }
        None => {
            return Err(format!(
                "this daemon is of release {release}, and the store at {} names no current release",
                store.root().display()
            )
            .into());
        }
    }
    store.record_roots(paths.runtime_root(), paths.state_root())?;
    Ok(Some(held))
}

fn default_worker_program() -> PathBuf {
    // This daemon's own release's worker: it sits beside this executable in every packaged layout,
    // and a daemon of an installed release starts the worker of that release, never the one an
    // update has made current since.
    kr_ipc::install::this_process().map_or_else(
        |_| PathBuf::from("kr-worker"),
        |running| running.own(kr_ipc::install::Program::Worker),
    )
}
