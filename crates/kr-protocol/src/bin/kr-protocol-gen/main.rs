//! Writes the generated JSON Schema, the method table and the cross-language vectors.
//!
//! Three output roots, because the three are consumed differently: the schema and the method table
//! feed the TypeScript build, the vectors are conformance material both languages read, and the
//! method index is documentation. The check also fails when a method in the table is named in no
//! document, or when an index link no longer lands on its section.
//!
//! ```text
//! kr-protocol-gen                   write the files
//! kr-protocol-gen --check           fail when the committed files differ or a method is undocumented
//! kr-protocol-gen --out-dir P       write the schema to P instead of packages/protocol/schema
//! kr-protocol-gen --fixtures-dir P  write the vectors to P instead of fixtures
//! kr-protocol-gen --docs-dir P      write the index to, and read the documentation from, P
//! ```

mod markdown;
mod method_index;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_protocol::schema::generated_files;
use kr_protocol::vectors::{PUSH_FILE_NAME, SERVICE_REQUESTS_FILE_NAME, SERVICES_FILE_NAME};

fn default_out_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/protocol/schema")
}

fn default_fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn default_docs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs")
}

/// Every generated vector file, with the directory it belongs in under the fixtures root.
fn vector_files() -> Vec<(PathBuf, String)> {
    kr_protocol::vectors::generated_files()
        .into_iter()
        .map(|(name, contents)| {
            let area = if name == SERVICE_REQUESTS_FILE_NAME || name == SERVICES_FILE_NAME {
                "service"
            } else if name == PUSH_FILE_NAME {
                "push"
            } else {
                unreachable!("every vector file names its area")
            };
            (PathBuf::from(area).join(name), contents)
        })
        .collect()
}

fn main() -> ExitCode {
    let mut check = false;
    let mut out_dir = default_out_dir();
    let mut fixtures_dir = default_fixtures_dir();
    let mut docs_dir = default_docs_dir();
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
            "--docs-dir" => match arguments.next() {
                Some(value) => docs_dir = PathBuf::from(value),
                None => {
                    eprintln!("--docs-dir needs a path");
                    return ExitCode::FAILURE;
                }
            },
            "--help" | "-h" => {
                println!(
                    "kr-protocol-gen [--check] [--out-dir <path>] [--fixtures-dir <path>] \
                     [--docs-dir <path>]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    let files: Vec<(PathBuf, String)> = generated_files()
        .into_iter()
        .map(|(name, contents)| (out_dir.join(name), contents))
        .chain(
            vector_files()
                .into_iter()
                .map(|(relative, contents)| (fixtures_dir.join(relative), contents)),
        )
        .chain(std::iter::once((
            docs_dir.join(method_index::INDEX_PATH),
            method_index::render(),
        )))
        .collect();

    if check {
        run_check(&files, &docs_dir)
    } else {
        run_write(&files)
    }
}

fn run_check(files: &[(PathBuf, String)], docs_dir: &Path) -> ExitCode {
    let mut differences = 0usize;
    for (path, expected) in files {
        let expected = expected.as_str();
        match std::fs::read_to_string(path) {
            Ok(actual) if actual == expected => {}
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
        eprintln!("run `cargo run -p kr-protocol --bin kr-protocol-gen` and commit the result");
    }
    let undocumented = match method_index::unnamed_methods(docs_dir) {
        Ok(undocumented) => undocumented,
        Err(error) => {
            eprintln!("{}: {error}", docs_dir.display());
            return ExitCode::FAILURE;
        }
    };
    if !undocumented.is_empty() {
        eprintln!(
            "{} registry methods are named in no document under {}:",
            undocumented.len(),
            docs_dir.display()
        );
        for name in &undocumented {
            eprintln!("  {name}");
        }
    }
    let broken = method_index::broken_links(docs_dir);
    if !broken.is_empty() {
        eprintln!(
            "{} method index links do not land on their section:",
            broken.len()
        );
        for description in &broken {
            eprintln!("  {description}");
        }
    }
    if differences > 0 || !undocumented.is_empty() || !broken.is_empty() {
        return ExitCode::FAILURE;
    }
    println!("generated files are up to date and every method is documented");
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

fn run_write(files: &[(PathBuf, String)]) -> ExitCode {
    for (path, contents) in files {
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
