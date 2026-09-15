//! Checks a package directory against the package contract.
//!
//! ```text
//! kr-plugin-sandbox <directory>          report every finding
//! kr-plugin-sandbox <directory> --json   report findings as JSON
//! kr-plugin-sandbox <directory> --quiet  report only the verdict
//! ```
//!
//! The check is offline and executes nothing in the package: no script, no installation step and
//! no Wasm. It reads the directory, rejects links and unsafe names, parses the manifests against
//! the closed schema, and compares every declared digest and length against the bytes on disk.
//! Exit status is 0 when the package is valid and 1 when it is not.

use std::path::PathBuf;
use std::process::ExitCode;

use kr_plugin_sdk::validate::validate_package_directory;

fn main() -> ExitCode {
    let mut directory: Option<PathBuf> = None;
    let mut json = false;
    let mut quiet = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--json" => json = true,
            "--quiet" => quiet = true,
            "--help" | "-h" => {
                println!("kr-plugin-sandbox <directory> [--json] [--quiet]");
                return ExitCode::SUCCESS;
            }
            other if other.starts_with('-') => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
            other => directory = Some(PathBuf::from(other)),
        }
    }
    let Some(directory) = directory else {
        eprintln!("kr-plugin-sandbox needs a package directory");
        return ExitCode::FAILURE;
    };

    let validated = validate_package_directory(&directory);
    let report = &validated.report;

    if json {
        match serde_json::to_string_pretty(report) {
            Ok(text) => println!("{text}"),
            Err(error) => {
                eprintln!("{error}");
                return ExitCode::FAILURE;
            }
        }
    } else if !quiet {
        for finding in &report.findings {
            println!("{finding}");
        }
    }

    if report.is_valid() {
        if !json && !quiet {
            let package = validated.package.as_ref();
            let files = package.map_or(0, |package| package.files.len());
            let bytes = package.map_or(0, kr_plugin_sdk::package::Package::total_size_bytes);
            println!(
                "{}: valid, {files} files, {bytes} bytes",
                directory.display()
            );
        }
        ExitCode::SUCCESS
    } else {
        if !json && !quiet {
            println!(
                "{}: {} finding(s)",
                directory.display(),
                report.findings.len()
            );
        }
        ExitCode::FAILURE
    }
}
