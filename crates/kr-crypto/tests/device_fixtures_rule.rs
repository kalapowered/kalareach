//! A library test of this crate runs on a phone, where there is no checkout to read.
//!
//! `scripts/native-library-tests.sh` builds the library's test program for an Android emulator and
//! an iOS simulator and runs it there. A test that opens a file of the repository by
//! `CARGO_MANIFEST_DIR` or by a relative path stops on the device at "No such file or directory",
//! and the cryptography it was written to check is never reached. A file a case needs is taken into
//! the program when it is built, with `include_str!` or `include_bytes!`.
//!
//! This reads the library's sources and refuses test code that names the manifest directory or a
//! relative path of the repository outside those two macros. It also holds the script to the crates
//! it covers: a crate added there has to be added here.
//!
//! What it cannot see: a path built from another environment variable, from the current directory
//! or from a string put together while the test runs; a file read through a helper that is handed a
//! root; a line that holds a `//` inside a string before the path; test code in a file that no
//! `#[cfg(test)]` line marks, such as a module declared by a macro. The test that is skipped on a
//! device by name is let through for as long as the script skips it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A function of the library's tests that reads the checkout and the case of the script's skipped
/// list that is its only caller: it is let through while the script skips that case.
const SKIPPED_READERS: [(&str, &str, &str); 1] = [(
    "vectors.rs",
    "root_with_a_lease_issued_by",
    "vectors::tests::a_lease_naming_a_key_the_vectors_do_not_sign_with_is_refused",
)];

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The crates whose library tests the script runs: every `-p <crate>` of a `cargo test` line.
fn device_crates(script: &str) -> BTreeSet<String> {
    let mut crates = BTreeSet::new();
    for line in script.lines().map(str::trim) {
        if line.starts_with('#') || !line.contains("cargo test") {
            continue;
        }
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if word == "-p" || word == "--package" {
                crates.extend(words.next().map(str::to_string));
            }
        }
    }
    crates
}

/// The full names in the script's `skipped_cases` list.
fn skipped_cases(script: &str) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let mut inside = false;
    for line in script.lines().map(str::trim) {
        if line.starts_with("skipped_cases=(") {
            inside = true;
        } else if inside && line == ")" {
            break;
        } else if inside && !line.is_empty() && !line.starts_with('#') {
            names.insert(line.to_string());
        }
    }
    names
}

fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("a source directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            // The binaries are tools of the repository, not part of the library's test program.
            if path.file_name().is_none_or(|name| name != "bin") {
                rust_files(&path, found);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

/// The test code of a file: all of it for a module that its parent declares under `#[cfg(test)]`,
/// else everything from the first `#[cfg(test)]` line at the start of a line.
fn test_region(text: &str, declared_for_tests: bool) -> String {
    if declared_for_tests {
        return text.to_string();
    }
    let mut region = String::new();
    let mut inside = false;
    for line in text.lines() {
        inside = inside || line.trim_end() == "#[cfg(test)]";
        if inside {
            region.push_str(line);
        }
        region.push('\n');
    }
    region
}

/// Whether the file that declares the module `stem` marks it `#[cfg(test)]`.
fn declared_for_tests(src: &Path, file: &Path) -> bool {
    let stem = file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .expect("a name");
    let directory = file.parent().expect("a directory");
    if stem == "lib" || stem == "mod" {
        return false;
    }
    let declaring = if directory == src {
        src.join("lib.rs")
    } else if directory.with_extension("rs").exists() {
        directory.with_extension("rs")
    } else {
        directory.join("mod.rs")
    };
    let text = read(&declaring);
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    let module = format!("mod {stem};");
    lines.iter().enumerate().any(|(at, line)| {
        let declaration = line
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub(super) ")
            .trim_start_matches("pub ");
        at > 0 && declaration == module && lines[at - 1] == "#[cfg(test)]"
    })
}

/// The code without its line comments and without the paths of `include_str!` and
/// `include_bytes!`, which are read when the program is built.
fn code_only(text: &str) -> String {
    let mut code: String = text
        .lines()
        .map(|line| format!("{}\n", line.split("//").next().unwrap_or("")))
        .collect();
    for call in ["include_str!(", "include_bytes!("] {
        while let Some(at) = code.find(call) {
            let end = code[at..]
                .find(')')
                .map_or(code.len(), |close| at + close + 1);
            code.replace_range(at..end, "");
        }
    }
    code
}

/// `text` without the function `name` of the tests, which ends at the first line that is a closing
/// brace indented four spaces.
fn without_function(text: &str, name: &str) -> String {
    let marker = format!("fn {name}(");
    let mut kept = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.contains(&marker) {
            inside = true;
        }
        if !inside {
            kept.push_str(line);
        }
        kept.push('\n');
        if inside && line == "    }" {
            inside = false;
        }
    }
    kept
}

/// The lines of `code` that name the manifest directory or a path of the repository.
fn offences(name: &str, code: &str) -> Vec<String> {
    code.lines()
        .map(str::trim)
        .filter(|line| {
            line.contains("CARGO_MANIFEST_DIR")
                || ["\"../", "\"fixtures/", "\"crates/"]
                    .iter()
                    .any(|start| line.contains(start))
        })
        .map(|line| format!("{name}: {line}"))
        .collect()
}

#[test]
fn no_library_test_reads_a_file_of_the_checkout_at_run_time() {
    let script = read(&crate_root().join("../../scripts/native-library-tests.sh"));
    assert_eq!(
        device_crates(&script),
        BTreeSet::from(["kr-crypto".to_string()]),
        "the device script runs the library tests of other crates: this rule has to read their sources too"
    );
    let skipped = skipped_cases(&script);
    let src = crate_root().join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut found = Vec::new();
    let mut tests = 0;
    for file in &files {
        let name = file
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .to_string();
        let mut region = test_region(&read(file), declared_for_tests(&src, file));
        for (path, function, case) in SKIPPED_READERS {
            if name == path && skipped.contains(case) {
                region = without_function(&region, function);
            }
        }
        tests += usize::from(region.contains("#[test]"));
        found.extend(offences(&name, &code_only(&region)));
    }
    assert!(tests > 10, "the rule found test code in only {tests} files");
    assert!(
        found.is_empty(),
        "a library test of this crate reads the checkout at run time, which a device has not: \
         take the file in with include_str! or include_bytes!\n{}",
        found.join("\n")
    );
}

#[test]
fn the_rule_sees_each_way_a_test_reads_the_checkout() {
    let by_manifest = "fn run() {}\n#[cfg(test)]\nmod tests {\n    fn a() {\n        \
        let p = Path::new(env!(\"CARGO_MANIFEST_DIR\")).join(\"x\");\n    }\n}\n";
    let by_relative =
        "#[cfg(test)]\nmod tests {\n    fn a() { std::fs::read(\"../../fixtures/a.json\"); }\n}\n";
    let taken_in = "#[cfg(test)]\nmod tests {\n    const A: &str = include_str!(\n        \
        \"../../../fixtures/a.json\"\n    );\n}\n";
    let outside =
        "fn run(root: &Path) { read(root, \"fixtures/a.json\"); }\n#[cfg(test)]\nmod tests {}\n";
    let whole_file = "fn a() { read(env!(\"CARGO_MANIFEST_DIR\")); }\n";
    let seen =
        |text: &str, whole: bool| offences("m.rs", &code_only(&test_region(text, whole))).len();
    assert_eq!(seen(by_manifest, false), 1);
    assert_eq!(seen(by_relative, false), 1);
    assert_eq!(seen(taken_in, false), 0);
    assert_eq!(seen(outside, false), 0);
    assert_eq!(seen(whole_file, true), 1);
    assert_eq!(seen(whole_file, false), 0);
}
