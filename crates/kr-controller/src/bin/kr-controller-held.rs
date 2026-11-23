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
    // A suite whose subject is a platform command that outlasts its bound says how long the bound
    // is, so that the case ends in seconds and not in the minute the product allows.
    let _bound = std::env::var("KR_TEST_PLATFORM_LIMIT_MS")
        .ok()
        .and_then(|milliseconds| milliseconds.parse().ok())
        .map(|milliseconds| {
            kr_controller::testing::hold_platform_commands_to(std::time::Duration::from_millis(
                milliseconds,
            ))
        });
    daemon::main()
}
