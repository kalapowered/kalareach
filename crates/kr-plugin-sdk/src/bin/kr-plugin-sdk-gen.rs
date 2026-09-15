//! Writes the generated schema, contract table and WIT package for the TypeScript package.
//!
//! ```text
//! kr-plugin-sdk-gen                    write the files
//! kr-plugin-sdk-gen --check            fail when the committed files differ
//! kr-plugin-sdk-gen --out-dir P        write the package to P instead of packages/plugin-sdk
//! kr-plugin-sdk-gen --fixtures-dir P   write the fixtures to P instead of fixtures/plugins
//! ```
//!
//! The schema and the contract table go to `schema/`; the WIT package goes to `wit/`; the valid
//! example package goes to the fixtures directory. All of them are checked in continuous
//! integration, so the Rust types, the published schema, the component interface and the example
//! package cannot drift apart. The invalid fixtures beside the example are written by hand: each
//! one is a specific defect, and generating them would mean generating the defect too.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_plugin_sdk::schema::generated_files;
use kr_plugin_sdk::{example, package, wit};

fn default_out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/plugin-sdk")
}

fn default_fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins")
}

/// Every generated file, as an absolute path and its exact contents.
fn outputs(out_dir: &Path, fixtures_dir: &Path) -> Vec<(PathBuf, String)> {
    let mut outputs: Vec<(PathBuf, String)> = generated_files()
        .into_iter()
        .map(|(name, contents)| (out_dir.join("schema").join(name), contents))
        .collect();
    outputs.push((
        out_dir.join("wit").join(wit::PACKAGE_FILE_NAME),
        wit::PACKAGE.to_owned(),
    ));
    let declarative = fixtures_dir.join("valid").join(example::PLUGIN_NAME);
    outputs.push((
        declarative.join(package::MANIFEST_FILE),
        example::example_manifest_json(),
    ));
    outputs.push((
        declarative.join(package::PRESENTATION_FILE),
        example::example_presentation_json(),
    ));
    let connector = fixtures_dir
        .join("valid")
        .join(example::CONNECTOR_PLUGIN_NAME);
    outputs.push((
        connector.join(package::MANIFEST_FILE),
        example::example_connector_manifest_json(),
    ));
    outputs.push((
        connector.join(package::PRESENTATION_FILE),
        example::example_connector_presentation_json(),
    ));
    outputs.push((
        connector.join(package::CONNECTOR_FILE),
        example::example_connector_table_json(),
    ));
    outputs
}

fn main() -> ExitCode {
    let mut check = false;
    let mut out_dir = default_out_dir();
    let mut fixtures_dir = default_fixtures_dir();
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
            "--fixtures-dir" => match arguments.next() {
                Some(value) => fixtures_dir = PathBuf::from(value),
                None => {
                    eprintln!("--fixtures-dir needs a path");
                    return ExitCode::FAILURE;
                }
            },
            "--help" | "-h" => {
                println!("kr-plugin-sdk-gen [--check] [--out-dir <path>] [--fixtures-dir <path>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }
    let outputs = outputs(&out_dir, &fixtures_dir);
    if check {
        run_check(&outputs)
    } else {
        run_write(&outputs)
    }
}

fn run_check(outputs: &[(PathBuf, String)]) -> ExitCode {
    let mut differences = 0usize;
    for (path, expected) in outputs {
        match std::fs::read_to_string(path) {
            Ok(actual) if &actual == expected => {}
            Ok(actual) => {
                differences += 1;
                eprintln!(
                    "{}: out of date ({} bytes on disk, {} bytes generated)",
                    path.display(),
                    actual.len(),
                    expected.len()
                );
                report_first_difference(&actual, expected);
            }
            Err(error) => {
                differences += 1;
                eprintln!("{}: {error}", path.display());
            }
        }
    }
    if differences > 0 {
        eprintln!("run `cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen` and commit the result");
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

fn run_write(outputs: &[(PathBuf, String)]) -> ExitCode {
    for (path, contents) in outputs {
        if let Some(parent) = path.parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            eprintln!("{}: {error}", parent.display());
            return ExitCode::FAILURE;
        }
        if let Err(error) = std::fs::write(path, contents) {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
        println!("wrote {}", path.display());
    }
    ExitCode::SUCCESS
}
