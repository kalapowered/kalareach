//! The workspace's `[patch.crates-io]` entries: the lock says by name when cargo found nothing to
//! use one for.

use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// The entries of every `[[patch.unused]]` table in a lock file, each as `name version`. Cargo
/// writes the table in one spelling, but `--locked` also accepts a lock whose header has spaces,
/// quotes or a comment that TOML allows there, so the header is read as TOML reads it.
fn unused_patches(lock: &str) -> Vec<String> {
    fn render((name, version): (String, String)) -> String {
        let name = if name.is_empty() { "(no name)" } else { &name };
        format!("{name} {version}").trim().to_owned()
    }
    let mut found = Vec::new();
    let mut entry: Option<(String, String)> = None;
    for line in lock.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.starts_with('[') {
            found.extend(entry.take().map(render));
            let header: String = line
                .chars()
                .filter(|c| !c.is_whitespace() && !matches!(c, '"' | '\''))
                .collect();
            if header == "[[patch.unused]]" {
                entry = Some((String::new(), String::new()));
            }
        } else if let (Some(entry), Some((key, value))) = (entry.as_mut(), line.split_once('=')) {
            let value = value.trim().trim_matches(['"', '\'']).to_owned();
            match key.trim() {
                "name" => entry.0 = value,
                "version" => entry.1 = value,
                _ => {}
            }
        }
    }
    found.extend(entry.take().map(render));
    found
}

/// A patch entry that nothing in the dependency graph can use is no error to cargo: it writes the
/// entry into the lock as `[[patch.unused]]`, takes the registry crate in its place and warns, and
/// `--locked` accepts that lock. The workspace's patches carry fixes that no release holds, so a
/// lock that takes the registry crate again has lost them without any build failing.
#[test]
fn the_lock_holds_no_patch_entry_that_nothing_uses() {
    let lock = std::fs::read_to_string(repository().join("Cargo.lock")).expect("the lock");
    assert!(
        lock.contains("\n[[package]]\n"),
        "the file read is a lock with packages"
    );
    let unused = unused_patches(&lock);
    assert!(
        unused.is_empty(),
        "Cargo.lock holds a `[[patch.unused]]` table for {unused:?}: nothing in the graph asks for \
         the version a `[patch.crates-io]` entry of Cargo.toml gives, so cargo takes the registry \
         crate instead and only warns"
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
    assert_eq!(unused_patches(&lock), ["noq-proto 0.17.0"]);
}

/// Each entry is found wherever its table stands, whether another table follows it or not, and
/// however TOML lets its header be spelt.
#[test]
fn every_unused_entry_is_named_whichever_table_follows_it() {
    let lock = "version = 4\n\n\
        [[patch.unused]]\nname = \"first\"\nversion = \"1.0.0\"\nsource = \"git+https://example.org/a\"\n\n\
        [[package]]\nname = \"other\"\nversion = \"2.0.0\"\n\n\
        [[patch.unused]]\nname = \"second\"\nversion = \"3.0.0\"\n";
    assert_eq!(unused_patches(lock), ["first 1.0.0", "second 3.0.0"]);
    // The same table with a header that TOML reads alike and cargo does not write.
    for header in [
        "[[patch.unused]] # kept",
        "[[ patch.unused ]]",
        "[[patch.\"unused\"]]",
        "[[patch.'unused']]",
    ] {
        let lock = format!("version = 4\n\n{header}\nname = 'third'\nversion = \"4.0.0\"\n");
        assert_eq!(unused_patches(&lock), ["third 4.0.0"], "{header}");
    }
    assert!(
        unused_patches("version = 4\n\n[[package]]\nname = \"other\"\nversion = \"2.0.0\"\n")
            .is_empty()
    );
}
