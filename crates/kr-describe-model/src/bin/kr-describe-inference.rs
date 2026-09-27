//! The description process: the control daemon's own child, one per execution environment, which
//! loads the selected profile's model and answers jobs over its standard input and output.
//!
//! The daemon starts it with the environment's runtime directory, where it takes the environment's
//! lock before its first load. It ends when its input ends, which is the daemon going, and its
//! watchdog ends it when it is stuck; `kr_describe::serve` is the whole of how it serves.

use std::path::PathBuf;

use kr_describe::profile::catalogue::Catalogue;
use kr_describe::serve::{Options, run};
use kr_describe_model::llama::Llama;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let runtime_dir = match arguments.as_slice() {
        [flag, directory] if flag == "--runtime-dir" => PathBuf::from(directory),
        _ => {
            eprintln!("usage: kr-describe-inference --runtime-dir <directory>");
            std::process::exit(64);
        }
    };
    let catalogue = match Catalogue::builtin() {
        Ok(catalogue) => catalogue,
        Err(error) => {
            eprintln!("kr-describe-inference: this build's profiles do not verify: {error}");
            std::process::exit(64);
        }
    };
    let exit = run(
        Options {
            build: format!("kr-describe-inference/{}", env!("CARGO_PKG_VERSION")),
            runtime_dir,
            catalogue,
        },
        Llama::new(),
        std::io::stdin(),
        std::io::stdout(),
    );
    std::process::exit(exit.code());
}
