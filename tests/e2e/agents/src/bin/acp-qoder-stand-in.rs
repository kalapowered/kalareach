//! The stand-in for Qoder CLI in ACP mode: a native program that speaks the Agent Client Protocol
//! on its standard input and output and takes its script from the working directory
//! (`kr_e2e_agents::acp_agent`).

use std::io::BufReader;
use std::process::ExitCode;

use kr_e2e_agents::acp_agent::{Shape, run};

fn main() -> ExitCode {
    let directory = match std::env::current_dir() {
        Ok(directory) => directory,
        Err(why) => {
            eprintln!("acp-qoder-stand-in: no working directory: {why}");
            return ExitCode::from(2);
        }
    };
    match run(
        Shape::Qoder,
        &directory,
        BufReader::new(std::io::stdin()),
        std::io::stdout(),
    ) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(why) => {
            eprintln!("acp-qoder-stand-in: {why}");
            ExitCode::from(2)
        }
    }
}
