//! Who may write a proxy's login: two files and no other.
//!
//! The login leaves its credential only as the value of a `Proxy-Authorization` header, and only
//! `kr-transport/src/proxy.rs` (which builds it for a client's connector and for a tunnel) and
//! `kr-client/src/tunnel.rs` (the one `CONNECT` writer) may ask for it. This scan reads every
//! non-test Rust source of the workspace for the calls that would build the header some other way,
//! and a planted fixture of each call shows that the scan finds it.

use std::fs;
use std::path::{Path, PathBuf};

/// The calls that build or read a login. Each is a word the scan finds in code, never in a comment.
const WRITERS: [&str; 6] = [
    "custom_http_auth",
    ".authorization()",
    "basic_auth(",
    "set_password(",
    "PROXY_AUTHORIZATION",
    "\"Basic ",
];

/// The files that may use them.
const ALLOWED: [&str; 2] = ["kr-transport/src/proxy.rs", "kr-client/src/tunnel.rs"];

/// The writers a source's non-test code holds: the text before its test module, with the comment
/// lines left out.
fn findings(source: &str) -> Vec<&'static str> {
    let code = source
        .split("#[cfg(test)]")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    WRITERS
        .into_iter()
        .filter(|writer| code.contains(writer))
        .collect()
}

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(&*name, "target" | "tests" | "node_modules" | ".git" | "gen") {
                sources(&path, found);
            }
        } else if name.ends_with(".rs") {
            found.push(path);
        }
    }
}

/// No source of the workspace but the two writers calls anything that builds or reads a login, and
/// the scan finds each call in a planted fixture.
///
/// This is a guard: it holds at the base by design, and the fixtures show it can fail.
///
/// Covers KR-REQ-10.02.
#[test]
fn the_login_is_written_by_two_writers_only() {
    for writer in WRITERS {
        let planted = format!("fn planted() {{ let _ = value{writer}; }}");
        assert_eq!(findings(&planted), vec![writer], "a fixture with {writer}");
        let in_a_comment = format!("// {writer}\nfn quiet() {{}}");
        assert!(findings(&in_a_comment).is_empty(), "a comment is not code");
        let in_a_test =
            format!("fn quiet() {{}}\n#[cfg(test)]\nmod tests {{ fn t() {{ {writer} }} }}");
        assert!(
            findings(&in_a_test).is_empty(),
            "a test module is not product"
        );
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root");
    let mut files = Vec::new();
    sources(&root.join("crates"), &mut files);
    sources(&root.join("apps"), &mut files);
    assert!(files.len() > 100, "the scan found the workspace's sources");
    let mut offenders = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root.join("crates"))
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.iter().any(|allowed| relative.ends_with(allowed)) {
            continue;
        }
        let source = fs::read_to_string(&file).unwrap_or_default();
        for writer in findings(&source) {
            offenders.push(format!("{relative}: {writer}"));
        }
    }
    assert!(
        offenders.is_empty(),
        "a source other than the two writers builds or reads a proxy login: {offenders:#?}"
    );
}
