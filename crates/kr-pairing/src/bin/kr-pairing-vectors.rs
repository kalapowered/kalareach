//! Writes the cross-language pairing vectors under `fixtures/pairing/`.
//!
//! ```text
//! kr-pairing-vectors              write the files
//! kr-pairing-vectors --check      fail when the committed files differ
//! kr-pairing-vectors --out-dir P  write to P instead of fixtures/pairing
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_pairing::vectors::generated_files;

fn default_out_dir() -> PathBuf {
    kr_pairing::vectors::fixture_directory(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
}

fn main() -> ExitCode {
    let mut check = false;
    let mut out_dir = default_out_dir();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--check" => check = true,
            "--out-dir" => match arguments.next() {
                Some(value) => out_dir = PathBuf::from(value),
                None => {
                    eprintln!("--out-dir needs a path");
                    return ExitCode::FAILURE;
                }
            },
            "--help" | "-h" => {
                println!("kr-pairing-vectors [--check] [--out-dir <path>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    let files = match generated_files() {
        Ok(files) => files,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::FAILURE;
        }
    };

    if check {
        let mut differences = 0usize;
        for (name, expected) in files {
            let path = out_dir.join(name);
            match std::fs::read_to_string(&path) {
                Ok(actual) if actual == expected => {}
                Ok(_) => {
                    differences += 1;
                    eprintln!("{}: out of date", path.display());
                }
                Err(error) => {
                    differences += 1;
                    eprintln!("{}: {error}", path.display());
                }
            }
        }
        if differences > 0 {
            eprintln!(
                "run `cargo run -p kr-pairing --bin kr-pairing-vectors` and commit the result"
            );
            return ExitCode::FAILURE;
        }
        println!("the pairing vectors are up to date");
        return ExitCode::SUCCESS;
    }

    if let Err(error) = std::fs::create_dir_all(&out_dir) {
        eprintln!("{}: {error}", out_dir.display());
        return ExitCode::FAILURE;
    }
    for (name, contents) in files {
        let path = out_dir.join(name);
        if let Err(error) = std::fs::write(&path, contents) {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }
    ExitCode::SUCCESS
}
