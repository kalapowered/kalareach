//! The description process: the control daemon's own child, one per execution environment, which
//! loads the selected profile's model and answers jobs over its standard input and output.
//!
//! The daemon starts it with the environment's runtime directory, where it takes the environment's
//! lock before its first load. It ends when its input ends, which is the daemon going, and its
//! watchdog ends it when it is stuck; `kr_describe::serve` is the whole of how it serves.

use kr_describe::profile::catalogue::Catalogue;
use kr_describe::serve::{DAEMON_IDENTITY_ARGUMENT, Options, arguments, run};
use kr_describe_model::llama::Llama;

fn main() {
    let given: Vec<String> = std::env::args().skip(1).collect();
    // What every executable this product installs answers, so a release can start each one where
    // it was built and an installed layout can be checked by asking each for its version.
    if given.as_slice() == ["--version"] {
        println!("kr-describe-inference {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let (runtime_dir, daemon) = match arguments(&given) {
        Ok(read) => read,
        Err(error) => {
            eprintln!(
                "kr-describe-inference: {error}\nusage: kr-describe-inference --runtime-dir \
                 <directory> [{DAEMON_IDENTITY_ARGUMENT} <identity>]"
            );
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
            daemon,
        },
        Llama::new(),
        std::io::stdin(),
        std::io::stdout(),
    );
    std::process::exit(exit.code());
}
