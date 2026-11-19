//! The control daemon, as the test suites start it.
//!
//! The program is the daemon's own source, built with the crate's `testing` feature: on macOS a run
//! that did not ask for the account's own launchd (`KR_ALLOW_ACCOUNT_LAUNCHD=1`) has it choose the
//! detached process for its workers, and refuse any `launchctl` command that would load, start or
//! remove a job. A suite takes this file and places it under the daemon's own name. It is built
//! only with the feature, so a build without it has no daemon of this kind to run, and no release
//! carries it.

#[path = "kr-controller.rs"]
mod daemon;

fn main() -> std::process::ExitCode {
    daemon::main()
}
