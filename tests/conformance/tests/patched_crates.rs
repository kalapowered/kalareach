//! The workspace's `[patch.crates-io]` entries: the lock says by name when cargo found nothing to
//! use one for.

use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// A header or key as TOML reads its text apart from escapes: without the comment, the blanks and
/// the quotes.
fn plain(line: &str) -> String {
    line.split('#')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '"' | '\''))
        .collect()
}

/// How many `[[package]]` tables a lock file holds, and what it holds for a patch: each entry of a
/// `[[patch.unused]]` table as `name version`. Cargo writes that table in one spelling, but
/// `--locked` also accepts a lock whose header has blanks, quotes or a comment that TOML allows
/// there, so the header is read through [`plain`]. Anything else that could define a patch table,
/// or whose escapes the check cannot read, is reported as it stands: the check fails on what it
/// cannot read, and never passes over it.
fn read_lock(lock: &str) -> (usize, Vec<String>) {
    fn render((name, version): (String, String)) -> String {
        let name = if name.is_empty() { "(no name)" } else { &name };
        format!("{name} {version}").trim().to_owned()
    }
    let mut packages = 0;
    let mut found = Vec::new();
    let mut entry: Option<(String, String)> = None;
    let mut in_a_table = false;
    for line in lock.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            found.extend(entry.take().map(render));
            in_a_table = true;
            let header = plain(line);
            if header == "[[package]]" {
                packages += 1;
            } else if header == "[[patch.unused]]" {
                entry = Some((String::new(), String::new()));
            } else if header.starts_with("[patch")
                || header.starts_with("[[patch")
                || line.contains('\\')
            {
                found.push(format!("a table that this check cannot read: {line}"));
            }
        } else if !in_a_table && (plain(line).starts_with("patch") || line.contains('\\')) {
            found.push(format!("a line that this check cannot read: {line}"));
        } else if let (Some(entry), Some((key, value))) = (entry.as_mut(), line.split_once('=')) {
            let value = value
                .split('#')
                .next()
                .unwrap_or_default()
                .trim()
                .trim_matches(['"', '\'']);
            match plain(key).as_str() {
                "name" => entry.0 = value.to_owned(),
                "version" => entry.1 = value.to_owned(),
                _ => {}
            }
        }
    }
    found.extend(entry.take().map(render));
    (packages, found)
}

/// A patch entry that nothing in the dependency graph can use is no error to cargo: it writes the
/// entry into the lock as `[[patch.unused]]`, takes the registry crate in its place and warns, and
/// `--locked` accepts that lock. The workspace's patches carry fixes that no release holds, so a
/// lock that takes the registry crate again has lost them without any build failing.
#[test]
fn the_lock_holds_no_patch_entry_that_nothing_uses() {
    let lock = std::fs::read_to_string(repository().join("Cargo.lock")).expect("the lock");
    let (packages, unused) = read_lock(&lock);
    assert!(packages > 0, "the file read is a lock with packages");
    assert!(
        unused.is_empty(),
        "Cargo.lock holds a patch table that records an entry nothing uses, or that this check \
         cannot read: {unused:?}. When nothing in the graph asks for the version a \
         `[patch.crates-io]` entry of Cargo.toml gives, cargo takes the registry crate instead and \
         only warns"
    );
}

/// A lock that cargo wrote for a patch entry that nothing used: the registry crate in the graph
/// and the table, last in the file, for the entry. The excerpt is that lock's own text.
#[test]
fn a_table_that_cargo_wrote_for_an_unused_patch_is_found_by_the_name_of_its_crate() {
    let lock = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/patched-crates/unused-patch-lock.txt"),
    )
    .expect("the fixture");
    assert_eq!(read_lock(&lock), (1, vec!["noq-proto 0.17.0".to_owned()]));
}

/// Each entry is found wherever its table stands, whether another table follows it or not, and
/// however its header is spelt: with an indent, blanks, quotes or a comment.
#[test]
fn every_unused_entry_is_named_whichever_table_follows_it() {
    let lock = "version = 4\n\n\
        [[patch.unused]]\nname = \"first\"\nversion = \"1.0.0\"\nsource = \"git+https://example.org/a\"\n\n\
        [[package]]\nname = \"other\"\nversion = \"2.0.0\"\n\n\
        [[patch.unused]]\nname = \"second\"\nversion = \"3.0.0\"\n";
    assert_eq!(
        read_lock(lock),
        (1, vec!["first 1.0.0".into(), "second 3.0.0".into()])
    );
    for header in [
        "  [[patch.unused]]",
        "[[patch.unused]] # kept",
        "[[ patch.unused ]]",
        "[[patch.\"unused\"]]",
        "[[patch.'unused']]",
    ] {
        let lock = format!("version = 4\n\n{header}\nname = 'third'\nversion = \"4.0.0\"\n");
        assert_eq!(read_lock(&lock).1, ["third 4.0.0"], "{header}");
    }
}

/// A patch table that is written in a way that this check does not read is reported, never passed
/// over, and a crate whose name holds `patch` is no table.
#[test]
fn what_the_check_cannot_read_fails_it_and_a_crate_named_patch_does_not() {
    for lock in [
        "version = 4\n\n[patch]\nunused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = 4\n\n[patch.unused]\nname = \"x\"\n",
        "version = 4\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = 4\npatch = { unused = [] }\n",
        "version = 4\n\n[[patch.\"un\\u0075sed\"]]\nname = \"x\"\n",
        "version = 4\n\n[[patch.used]]\nname = \"x\"\n",
        "version = 4\n\n[[\"pat\\u0063h\".unused]]\nname = \"x\"\n",
        "version = 4\npat\\u0063h.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
    ] {
        assert!(!read_lock(lock).1.is_empty(), "{lock}");
    }
    let lock = "version = 4\n\n[[package]]\nname = \"json-patch\"\nversion = \"3.0.0\"\n\
        dependencies = [\n \"patch\",\n \"patch 0.1.0\",\n]\n";
    assert_eq!(read_lock(lock), (1, Vec::new()));
}

/// The count of packages does not depend on the line ends or on how the header is quoted.
#[test]
fn the_packages_are_counted_as_toml_reads_their_headers() {
    assert_eq!(
        read_lock("version = 4\r\n\r\n[[package]]\r\nname = \"a\"\r\n").0,
        1
    );
    assert_eq!(
        read_lock("version = 4\n\n[[\"package\"]]\nname = \"a\"\n").0,
        1
    );
}
