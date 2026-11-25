//! A stand-in for a program whose arguments a case reads: placed under the program's name, it says
//! on its terminal, one line each, the arguments it was started with, and ends.
//!
//! `--version` prints a version line and nothing else, as a program placed in a run is started once
//! to show that it starts.

/// The version line the program prints for `--version`.
const VERSION: &str = "2.1.278 (Claude Code)";

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments == ["--version"] {
        println!("{VERSION}");
        return;
    }
    println!("argv-stand-in: started");
    for argument in &arguments {
        println!("argv-stand-in: argument {argument}");
    }
    println!("argv-stand-in: ends");
}
