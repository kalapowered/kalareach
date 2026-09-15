//! Writes the generated JSON Schema and method table for the TypeScript package.
//!
//! ```text
//! kr-protocol-gen              write the files
//! kr-protocol-gen --check      fail when the committed files differ
//! kr-protocol-gen --out-dir P  write to P instead of packages/protocol/schema
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_protocol::schema::generated_files;

fn default_out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/protocol/schema")
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
                println!("kr-protocol-gen [--check] [--out-dir <path>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    if check {
        run_check(&out_dir)
    } else {
        run_write(&out_dir)
    }
}

fn run_check(out_dir: &Path) -> ExitCode {
    let mut differences = 0usize;
    for (name, expected) in generated_files() {
        let path = out_dir.join(name);
        match std::fs::read_to_string(&path) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => {
                differences += 1;
                eprintln!(
                    "{}: out of date ({} bytes on disk, {} bytes generated)",
                    path.display(),
                    actual.len(),
                    expected.len()
                );
                report_first_difference(&actual, &expected);
            }
            Err(error) => {
                differences += 1;
                eprintln!("{}: {error}", path.display());
            }
        }
    }
    if differences > 0 {
        eprintln!("run `cargo run -p kr-protocol --bin kr-protocol-gen` and commit the result");
        return ExitCode::FAILURE;
    }
    println!("generated files are up to date");
    ExitCode::SUCCESS
}

fn report_first_difference(actual: &str, expected: &str) {
    for (number, (left, right)) in actual.lines().zip(expected.lines()).enumerate() {
        if left != right {
            eprintln!("  first difference at line {}", number + 1);
            eprintln!("    on disk:   {left}");
            eprintln!("    generated: {right}");
            return;
        }
    }
    eprintln!(
        "  the files share a prefix; on disk has {} lines and generated has {}",
        actual.lines().count(),
        expected.lines().count()
    );
}

fn run_write(out_dir: &Path) -> ExitCode {
    if let Err(error) = std::fs::create_dir_all(out_dir) {
        eprintln!("{}: {error}", out_dir.display());
        return ExitCode::FAILURE;
    }
    for (name, contents) in generated_files() {
        let path = out_dir.join(name);
        if let Err(error) = std::fs::write(&path, contents) {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }
    ExitCode::SUCCESS
}
