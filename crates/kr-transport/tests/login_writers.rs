//! Who may write a proxy's login: two files and no other.
//!
//! The login leaves its credential only as the value of a `Proxy-Authorization` header, and only
//! `kr-transport/src/proxy.rs` (which builds it for a client's connector and for a tunnel) and
//! `kr-client/src/tunnel.rs` (the one `CONNECT` writer) may ask for it. This scan reads every
//! non-test Rust source of the workspace for the calls that would build the header some other way,
//! and a planted fixture of each call shows that the scan finds it. The stand-in proxy of the suites
//! is the one test-only file that builds a login's header on purpose, to check what a client wrote:
//! the scan leaves that file out, and checks that the file keeps itself under `#![cfg(test)]`, that
//! every declaration that resolves to it in any source of the workspace, whatever its module name or
//! path, sits under `#[cfg(test)]`, that no source names the file in any other way, and that the
//! declarations are the three known ones.

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

/// The test-only file of the stand-in proxy, which reads the header a client wrote to check it.
const STAND_IN: &str = "kr-client/src/services/http/connect_proxy.rs";

/// The files that may declare it, each once: the library of `kr-client` at the file's standard
/// place, and two other crates' libraries by a path. A fourth declaration, under any module name,
/// is a change to this rule.
const DECLARED_IN: [&str; 3] = [
    "kr-client/src/services/http.rs",
    "kr-controller/src/catalogue/mod.rs",
    "kr-transport/src/pkarr.rs",
];

/// A module declaration of a source: `mod name;`, with the file it names and whether it sits
/// directly under `#[cfg(test)]`.
#[derive(Debug, PartialEq, Eq)]
struct Declaration {
    name: String,
    path: Option<String>,
    under_test: bool,
}

/// The module declarations of `source`, whatever their module name: `mod name;` with any
/// visibility and a trailing comment, with the `#[path]` and `#[cfg(test)]` attributes found among
/// the attribute and comment lines directly above it.
fn declarations(source: &str) -> Vec<Declaration> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        if line.starts_with("//") {
            continue;
        }
        let code = line.split("//").next().unwrap_or_default().trim();
        let mut rest = code;
        if let Some(after) = rest.strip_prefix("pub") {
            rest = match after.strip_prefix('(') {
                Some(inside) => inside.split_once(')').map_or("", |(_, tail)| tail),
                None => after,
            }
            .trim_start();
        }
        let Some(name) = rest
            .strip_prefix("mod ")
            .and_then(|tail| tail.strip_suffix(';'))
        else {
            continue;
        };
        let mut path = None;
        let mut under_test = false;
        for above in lines[..at]
            .iter()
            .rev()
            .take_while(|above| above.starts_with("#[") || above.starts_with("//"))
        {
            under_test |= *above == "#[cfg(test)]";
            if let Some(quoted) = above.strip_prefix("#[path = \"") {
                path = quoted.strip_suffix("\"]").map(str::to_owned);
            }
        }
        found.push(Declaration {
            name: name.trim().to_owned(),
            path,
            under_test,
        });
    }
    found
}

/// The path `components` name, with `.` and `..` taken out.
fn cleaned(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The file a declaration in `file` resolves to: its `#[path]` taken from the folder of `file`, or,
/// with none, the module's own file in the folder the module system gives `file`.
fn resolved(file: &Path, declaration: &Declaration) -> PathBuf {
    let folder = file.parent().unwrap_or(Path::new(""));
    if let Some(path) = &declaration.path {
        return cleaned(&folder.join(path));
    }
    let own_folder = file
        .file_name()
        .is_some_and(|name| matches!(name.to_str(), Some("mod.rs" | "lib.rs" | "main.rs")));
    let base = if own_folder {
        folder.to_path_buf()
    } else {
        folder.join(file.file_stem().unwrap_or_default())
    };
    base.join(format!("{}.rs", declaration.name))
}

/// What a source does with the stand-in's file: the declarations that resolve to it, or whose path
/// ends in its name whatever folder the scan took them from, and the lines that name the file
/// without being such a declaration's path (an `include!`, a path above nothing).
fn uses_of_the_stand_in(file: &Path, source: &str, stand_in: &Path) -> (Vec<Declaration>, usize) {
    let name = stand_in
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let mut declared = Vec::new();
    let mut with_a_path = 0;
    for declaration in declarations(source) {
        let names_it = declaration
            .path
            .as_ref()
            .is_some_and(|path| path.ends_with(name));
        if names_it {
            with_a_path += 1;
        }
        if names_it || resolved(file, &declaration) == stand_in {
            declared.push(declaration);
        }
    }
    let naming_lines = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//") && line.contains(name))
        .count();
    (declared, naming_lines.saturating_sub(with_a_path))
}

/// Whether the file's own inner attribute keeps it out of every build but a test's: `#![cfg(test)]`
/// among the inner attributes above its first `use`.
fn is_test_only(source: &str) -> bool {
    source
        .split("\nuse ")
        .next()
        .unwrap_or_default()
        .lines()
        .any(|line| line.trim() == "#![cfg(test)]")
}

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

    // The stand-in's file is left out only while every declaration of it, under whatever module
    // name and by whatever path, is under `#[cfg(test)]`, and the file keeps itself out of every
    // build but a test's.
    let at = Path::new("/w/crates/a/src/lib.rs");
    let stand_in = Path::new("/w/crates/kr-client/src/services/http/connect_proxy.rs");
    let renamed = "#[cfg(test)]\n#[path = \"../../kr-client/src/services/http/connect_proxy.rs\"]\nmod other;";
    let (found, loose) = uses_of_the_stand_in(at, renamed, stand_in);
    assert_eq!(
        found,
        vec![Declaration {
            name: "other".to_owned(),
            path: Some("../../kr-client/src/services/http/connect_proxy.rs".to_owned()),
            under_test: true,
        }],
        "a renamed module is found by its path"
    );
    assert_eq!(loose, 0);
    let bare = "#[path = \"x/connect_proxy.rs\"]\npub(crate) mod other; // the proxy";
    let (found, _) = uses_of_the_stand_in(at, bare, stand_in);
    assert_eq!(
        found.len(),
        1,
        "a visibility and a trailing comment are read"
    );
    assert!(
        !found[0].under_test,
        "a declaration with no attribute is bare"
    );
    let (found, _) = uses_of_the_stand_in(
        at,
        "#[cfg(test)]\nfn other() {}\n#[path = \"x/connect_proxy.rs\"]\nmod other;",
        stand_in,
    );
    assert!(
        found.len() == 1 && !found[0].under_test,
        "an attribute of another item does not count"
    );
    let (found, loose) = uses_of_the_stand_in(
        Path::new("/w/crates/kr-client/src/services/http.rs"),
        "#[cfg(test)]\nmod connect_proxy;",
        stand_in,
    );
    assert!(
        found.len() == 1 && found[0].under_test && loose == 0,
        "a declaration at the standard place is found by its resolved file"
    );
    let (found, _) = uses_of_the_stand_in(
        Path::new("/w/crates/kr-client/src/services/http.rs"),
        "mod proxy_fixture;",
        Path::new("/w/crates/kr-client/src/services/http/proxy_fixture.rs"),
    );
    assert_eq!(found.len(), 1, "the module's name does not matter");
    let (found, loose) = uses_of_the_stand_in(
        at,
        "const T: &str = include_str!(\"../../x/connect_proxy.rs\");\nmod other;",
        stand_in,
    );
    assert!(found.is_empty());
    assert_eq!(loose, 1, "an include of the file is not a declaration");
    assert!(
        uses_of_the_stand_in(at, "mod connect_proxy;", stand_in)
            .0
            .is_empty()
    );
    assert!(is_test_only("//! docs\n\n#![cfg(test)]\n\nuse std::fs;"));
    assert!(!is_test_only("//! docs\n\nuse std::fs;\n#![cfg(test)]"));
    assert!(!is_test_only("#![allow(dead_code)]\nuse std::fs;"));

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root");
    let stand_in = root.join("crates").join(STAND_IN);
    assert!(
        is_test_only(&fs::read_to_string(&stand_in).expect("the stand-in proxy")),
        "the stand-in proxy's file carries `#![cfg(test)]`"
    );
    let mut files = Vec::new();
    sources(&root.join("crates"), &mut files);
    sources(&root.join("apps"), &mut files);
    assert!(files.len() > 100, "the scan found the workspace's sources");
    let mut offenders = Vec::new();
    let mut declared_in = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(root.join("crates"))
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let source = fs::read_to_string(&file).unwrap_or_default();
        let (declared, loose) = uses_of_the_stand_in(&file, &source, &stand_in);
        for declaration in &declared {
            declared_in.push(relative.clone());
            if !declaration.under_test {
                offenders.push(format!(
                    "{relative}: the stand-in proxy's module `{}` is declared outside `#[cfg(test)]`",
                    declaration.name
                ));
            }
        }
        if loose > 0 {
            offenders.push(format!(
                "{relative}: the stand-in proxy's file is named outside a module declaration"
            ));
        }
        if relative.ends_with(STAND_IN) {
            continue;
        }
        if ALLOWED.iter().any(|allowed| relative.ends_with(allowed)) {
            continue;
        }
        for writer in findings(&source) {
            offenders.push(format!("{relative}: {writer}"));
        }
    }
    declared_in.sort();
    assert_eq!(
        declared_in, DECLARED_IN,
        "the stand-in proxy is declared in these sources and no other"
    );
    assert!(
        offenders.is_empty(),
        "a source other than the two writers builds or reads a proxy login: {offenders:#?}"
    );
}
