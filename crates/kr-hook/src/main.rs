//! The `kr-hook` forwarder. See the library for what each invocation does.

use clap::Parser as _;

fn main() -> std::process::ExitCode {
    // First: a forwarder of an installed release holds that release for as long as it runs, and
    // does not start at all once the release is being removed. It says so the way every failure of
    // its own is said, with a code no application reads as a request to block what it observed.
    if let Err(error) = kr_ipc::install::this_process() {
        kr_hook::report_by(
            &error.to_string(),
            std::time::Instant::now() + std::time::Duration::from_millis(100),
        );
        return std::process::ExitCode::from(kr_hook::cli::EXIT_FAILURE);
    }
    match kr_hook::cli::Cli::try_parse() {
        Ok(cli) => kr_hook::run(cli.command),
        Err(error) => {
            // Help and the version are answers, not failures. Everything else the parser refuses is
            // a usage error, answered on standard error with a code no application reads as a
            // request to block what it observed.
            let _ = error.print();
            if error.use_stderr() {
                std::process::ExitCode::from(kr_hook::cli::EXIT_USAGE)
            } else {
                std::process::ExitCode::SUCCESS
            }
        }
    }
}
