//! The KalaReach plugin-runtime service process.
//!
//! Started by the control daemon through the platform's service manager, as its own job, outside
//! the daemon's kill tree. What the job definition hands it is entirely non-secret: which
//! reservation it was started for, which environment it serves, where the daemon's rendezvous
//! endpoint is, and where the directories are. The signing key it proves itself with is generated
//! here and never leaves this process.

use std::process::ExitCode;

use clap::Parser as _;
use kr_plugin_host::Options;

fn main() -> ExitCode {
    let options = Options::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("kr-plugin-host: the asynchronous runtime could not be started: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(kr_plugin_host::run(options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The one place a host that failed before it had a connection can say why. The daemon
            // routes this to the job's diagnostics file in the owner-only state directory.
            eprintln!("kr-plugin-host: {error}");
            ExitCode::FAILURE
        }
    }
}
