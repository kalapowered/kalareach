//! The `kr-hook` forwarder. See the library for what each invocation does.

use clap::Parser as _;

fn main() -> std::process::ExitCode {
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
