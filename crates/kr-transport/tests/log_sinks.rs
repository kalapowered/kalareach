//! Who may install a log sink: the sites a review has approved, and no other.
//!
//! Two of the libraries a dial goes through print what they hold at `debug`, and what they print
//! can include a proxy's login. A log sink is where those lines would be read, so a new one must
//! not land unreviewed. This scan reads every Rust source of the workspace, tests included, for
//! the calls that install a `tracing` subscriber or a `log` logger, and for any use of the crates
//! that provide one. The sites it finds must be exactly the approved ones. The scan's own text
//! splits each identifier so that it never finds itself, and a planted fixture of each shows that
//! the scan can fail. It proves that a new sink cannot land unreviewed, not that a filter is right.

use std::fs;
use std::path::{Path, PathBuf};

/// The identifiers that install a sink or name a crate that does, each split in two so that this
/// file's own text holds none whole.
const SINKS: [(&str, &str); 8] = [
    ("set_global", "_default"),
    ("set_", "default"),
    ("with_", "default"),
    ("set_", "logger"),
    ("set_boxed", "_logger"),
    ("tracing_sub", "scriber"),
    ("env_", "logger"),
    ("tauri_plugin", "_log"),
];

/// The dependencies a non-development table must not name, each split in two.
const SINK_CRATES: [(&str, &str); 5] = [
    ("tracing-sub", "scriber"),
    ("env_", "logger"),
    ("tauri-plugin", "-log"),
    ("fe", "rn"),
    ("simple", "log"),
];

/// The sites a review approved: the file, the trimmed line, and how many times it stands.
fn approved() -> Vec<(&'static str, String, usize)> {
    vec![
        (
            "kr-transport/tests/device_endpoint_stall.rs",
            concat!(
                "let _ = tracing::subscriber::set_",
                "global_default(Capture {"
            )
            .to_owned(),
            1,
        ),
        (
            "kr-client/src/services/http.rs",
            concat!(
                "let guard = tracing::subscriber::set_",
                "default(written.clone());"
            )
            .to_owned(),
            2,
        ),
        (
            "kr-client/src/shown/marker.rs",
            concat!(
                "let guard = tracing::subscriber::set_",
                "default(written.clone());"
            )
            .to_owned(),
            1,
        ),
        (
            "kr-controller/tests/proxy_login_logs.rs",
            concat!(
                "let installed = tracing::subscriber::set_",
                "global_default(Capture::default());"
            )
            .to_owned(),
            1,
        ),
        (
            "apps/companion/src-tauri/tests/navigation.rs",
            concat!(
                "tracing::subscriber::set_",
                "global_default(messages.clone())"
            )
            .to_owned(),
            1,
        ),
        (
            "apps/companion/src-tauri/src/voice/owner.rs",
            concat!(
                "tracing::subscriber::with_",
                "default(written.clone(), || {"
            )
            .to_owned(),
            1,
        ),
    ]
}

/// Whether `line` holds `word` as a whole identifier: the characters on each side are not part of
/// one.
fn holds_word(line: &str, word: &str) -> bool {
    let is_identifier = |character: char| character.is_alphanumeric() || character == '_';
    line.match_indices(word).any(|(at, _)| {
        let before = line[..at].chars().next_back();
        let after = line[at + word.len()..].chars().next();
        !before.is_some_and(is_identifier) && !after.is_some_and(is_identifier)
    })
}

/// The trimmed lines of `source` that install a sink or name a crate that provides one, with the
/// comment lines left out.
fn sites(source: &str) -> Vec<String> {
    let words: Vec<String> = SINKS
        .iter()
        .map(|(head, tail)| format!("{head}{tail}"))
        .collect();
    source
        .lines()
        .map(str::trim)
        .filter(|line| !line.starts_with("//"))
        .filter(|line| words.iter().any(|word| holds_word(line, word)))
        .map(str::to_owned)
        .collect()
}

/// The dependency tables of `manifest` that a sink crate appears in outside the development table.
fn sink_dependencies(manifest: &str) -> Vec<String> {
    let crates: Vec<String> = SINK_CRATES
        .iter()
        .map(|(head, tail)| format!("{head}{tail}"))
        .collect();
    let mut table = String::new();
    let mut found = Vec::new();
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            table = line.to_owned();
            continue;
        }
        let name = line.split(['=', ' ']).next().unwrap_or_default();
        if table.contains("dev-dependencies") {
            continue;
        }
        if crates.iter().any(|sink| name == sink) {
            found.push(format!("{table}: {name}"));
        }
    }
    found
}

fn files(directory: &Path, extension: &str, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(&*name, "target" | "node_modules" | ".git" | "gen") {
                files(&path, extension, found);
            }
        } else if name.ends_with(extension) {
            found.push(path);
        }
    }
}

/// No source of the workspace installs a log sink at a site a review has not approved, and no
/// dependency table outside the development tables names a crate that provides one.
///
/// This is a guard: it holds at the base by design, and the planted fixtures show it can fail.
///
/// Covers KR-REQ-10.02.
#[test]
fn no_source_installs_a_log_sink_that_review_has_not_approved() {
    for (head, tail) in SINKS {
        let word = format!("{head}{tail}");
        let planted = format!("fn planted() {{ tracing::subscriber::{word}(x); }}");
        assert_eq!(sites(&planted).len(), 1, "a fixture with {word}");
        assert!(
            sites(&format!("// {word}\nfn quiet() {{}}")).is_empty(),
            "a comment is no site"
        );
        assert!(
            sites(&format!("fn quiet() {{ {word}_validity(x); }}")).is_empty(),
            "a longer identifier is no site"
        );
    }
    for (head, tail) in SINK_CRATES {
        let planted = format!("[dependencies]\n{head}{tail} = \"1\"\n");
        assert_eq!(
            sink_dependencies(&planted).len(),
            1,
            "a fixture of {head}{tail}"
        );
        let development = format!("[dev-dependencies]\n{head}{tail} = \"1\"\n");
        assert!(
            sink_dependencies(&development).is_empty(),
            "a development table is not product"
        );
    }

    let crates_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crates directory");
    let root = crates_dir.parent().expect("the workspace root");
    let mut sources = Vec::new();
    files(&root.join("crates"), ".rs", &mut sources);
    files(&root.join("apps"), ".rs", &mut sources);
    assert!(
        sources.len() > 100,
        "the scan found the workspace's sources"
    );
    let mut found: Vec<(String, String)> = Vec::new();
    for source in sources {
        let relative = source
            .strip_prefix(crates_dir)
            .or_else(|_| source.strip_prefix(root))
            .unwrap_or(&source)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&source).unwrap_or_default();
        for line in sites(&text) {
            found.push((relative.clone(), line));
        }
    }
    found.sort();
    let mut expected: Vec<(String, String)> = Vec::new();
    for (path, line, count) in approved() {
        for _ in 0..count {
            expected.push((path.to_owned(), line.clone()));
        }
    }
    expected.sort();
    assert_eq!(
        found, expected,
        "a log sink stands at a site that no review approved, or an approved one is gone"
    );

    let mut manifests = Vec::new();
    files(&root.join("crates"), "Cargo.toml", &mut manifests);
    files(&root.join("apps"), "Cargo.toml", &mut manifests);
    manifests.push(root.join("Cargo.toml"));
    let mut offenders = Vec::new();
    for manifest in manifests {
        for found in sink_dependencies(&fs::read_to_string(&manifest).unwrap_or_default()) {
            offenders.push(format!("{}: {found}", manifest.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a dependency table names a crate that provides a log sink: {offenders:#?}"
    );
}
