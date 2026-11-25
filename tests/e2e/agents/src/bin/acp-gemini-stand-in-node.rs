//! The stand-in for the interpreter that runs Gemini CLI in ACP mode. The host starts it as it
//! starts the real one, `<interpreter> <main file> --acp`, and it speaks the Agent Client Protocol
//! on its standard input and output, taking its script from the working directory
//! (`kr_e2e_agents::acp_agent`). It reads the chunks of the script package from the folder of the
//! main file it was started with, so a case shows which folder the host started it from.

use std::io::BufReader;
use std::path::Path;
use std::process::ExitCode;

use kr_e2e_agents::acp_agent::{Shape, run};

/// Says why the program ends before it plays the agent, and returns the exit code that goes with it.
fn refuse(why: &str) -> ExitCode {
    eprintln!("acp-gemini-stand-in-node: {why}");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let [main_file, flag] = arguments.as_slice() else {
        return refuse(&format!(
            "expected the main file and `--acp`, got {} arguments",
            arguments.len()
        ));
    };
    if flag != "--acp" {
        return refuse(&format!(
            "expected `--acp` after the main file, got `{flag}`"
        ));
    }
    if let Err(why) = std::fs::read(main_file) {
        return refuse(&format!("the main file {main_file} cannot be read: {why}"));
    }
    let folder = match Path::new(main_file).parent() {
        Some(folder) if !folder.as_os_str().is_empty() => folder,
        _ => Path::new("."),
    };
    let directory = match std::env::current_dir() {
        Ok(directory) => directory,
        Err(why) => return refuse(&format!("no working directory: {why}")),
    };
    match run(
        Shape::Gemini,
        &directory,
        Some(folder),
        BufReader::new(std::io::stdin()),
        std::io::stdout(),
    ) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(why) => refuse(&why),
    }
}
