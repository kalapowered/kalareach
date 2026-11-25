//! The stand-in for Qoder CLI in ACP mode: a native program that speaks the Agent Client Protocol
//! on its standard input and output and takes its script from the working directory
//! (`kr_e2e_agents::acp_agent`). It takes the one argument `--acp`, as the host starts the real
//! program, and any other argument ends it with the code 2 before it reads or writes a frame.

use std::io::BufReader;
use std::process::ExitCode;

use kr_e2e_agents::acp_agent::{Shape, run};

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments != ["--acp"] {
        eprintln!("acp-qoder-stand-in: expected the one argument `--acp`, got {arguments:?}");
        return ExitCode::from(2);
    }
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
        None,
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
