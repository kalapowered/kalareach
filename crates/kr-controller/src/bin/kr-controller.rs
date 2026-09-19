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
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use kr_crypto::store::{SecretStore, open_store, open_store_in};
use kr_ipc::endpoint::Listener;
use kr_ipc::paths::HostPaths;
use kr_ipc::verify::{CONTROLLER_SECRET_SERVICE, ControllerIdentity};
use kr_protocol::ids::BuildId;

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
}

/// The store a daemon was told to keep its device keys in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum SecretStoreChoice {
    /// The operating system's credential store, with the fallback section 10 allows.
    Platform,
    /// This environment's own `secrets` directory, named deliberately.
    File,
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
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
    match runtime.block_on(run(arguments)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kr-controller: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
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
    let choice = arguments.secret_store;
    let open_identity =
        move || -> kr_controller::Result<(ControllerIdentity, Arc<dyn SecretStore>)> {
            let store = match choice {
                SecretStoreChoice::Platform => open_store(CONTROLLER_SECRET_SERVICE, &secrets_dir),
                SecretStoreChoice::File => open_store_in(&secrets_dir),
            }
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
            Ok((identity, Arc::from(store.store)))
        };

    let worker_program = arguments.worker.unwrap_or_else(default_worker_program);
    let build_id = BuildId::new(format!("kr-controller/{RELEASE}"))?;
    let controller =
        kr_controller::service::Controller::start(kr_controller::service::ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(open_identity),
            boot_identity: kr_ipc::identity::boot_identity()?,
            supervisor: kr_controller::supervision::detect(),
            worker_program,
            build_id,
            release: RELEASE.to_owned(),
        })
        .await?;

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
    }
    Ok(())
}

fn default_worker_program() -> PathBuf {
    // The worker sits beside this executable in every packaged layout.
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("kr-worker")))
        .unwrap_or_else(|| PathBuf::from("kr-worker"))
}
