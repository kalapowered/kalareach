//! The `kr-hook` forwarder. See the library for what each invocation does.

use clap::Parser as _;

fn main() -> std::process::ExitCode {
    // A hook is timed by its application from its start, so its clock starts here: whatever it
    // waits for before it has anything to answer is part of what it answers within.
    let started = std::time::Instant::now();
    match kr_hook::cli::Cli::try_parse() {
        Ok(cli) => kr_hook::run(cli.command, started),
        // Help and the version are answers, not failures. Everything else the parser refuses is a
        // usage error, answered on standard error with a code no application reads as a request
        // to block what it observed. Either is said only by a program whose release it may run.
        Err(error) => kr_hook::held(|| {
            let _ = error.print();
            if error.use_stderr() {
                std::process::ExitCode::from(kr_hook::cli::EXIT_USAGE)
            } else {
                std::process::ExitCode::SUCCESS
            }
        }),
    }
}
