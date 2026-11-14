//! The workspace's `[patch.crates-io]` entries and the crates its lock takes from a Git source: the
//! lock says by name when cargo found nothing to use an entry for, and a patched crate has to be
//! replaced whole.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_repository_file(path: &str) -> String {
    std::fs::read_to_string(repository().join(path)).expect(path)
}

/// A header or key without the comment, the blanks and the quotes, which is enough for `patch` and
/// `unused`.
fn plain(line: &str) -> String {
    line.split('#')
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '"' | '\''))
        .collect()
}

/// The text of a string value, without its quotes and without a comment after it.
fn string_value(value: &str) -> String {
    let value = value.trim();
    let Some(quote) = value.chars().next().filter(|q| matches!(q, '"' | '\'')) else {
        return value
            .split('#')
            .next()
            .unwrap_or_default()
            .trim()
            .to_owned();
    };
    let mut text = String::new();
    let mut chars = value[1..].chars();
    while let Some(c) = chars.next() {
        if c == quote {
            break;
        }
        text.push(c);
        if c == '\\' && quote == '"' {
            text.extend(chars.next());
        }
    }
    text
}

/// A package of a lock: its name and, if it has one, its source.
struct Package {
    name: String,
    source: String,
}

/// What this check reads of a lock: the packages, and `found`, each entry of a `[[patch.unused]]`
/// table as `name version` together with each report of something that this check cannot read.
struct Lock {
    packages: Vec<Package>,
    found: Vec<String>,
}

#[derive(PartialEq)]
enum Table {
    Root,
    Package,
    Unused,
    Other,
}

/// The lines cargo writes at the root of a lock, before its first table: none, a comment, or the
/// version.
fn cargo_writes_at_the_root(line: &str) -> bool {
    line.is_empty()
        || line.starts_with('#')
        || plain(line)
            .strip_prefix("version=")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Reads a lock file. A patch entry that nothing used is a `[[patch.unused]]` table, which cargo
/// writes in one spelling; `--locked` also accepts a header with blanks, quotes or a comment that
/// TOML allows there, so a header is read through [`plain`].
///
/// The check reports, with the number of its line, whatever else could hide such a table:
/// - at the root, every line that cargo does not write there. Cargo writes only comments, blank
///   lines and the version before the first table, so a root key, a byte-order mark or the start of
///   a multiline value is reported at its first line, and no multiline value can precede a header
///   that is read as one;
/// - a header that could define a patch table in a spelling that this check does not read, or that
///   holds an escape.
///
/// Inside a table, a line that starts with `[` is read as a header whether or not it is part of a
/// multiline value. That can only add a report, since every real header starts its own line.
fn read_lock(lock: &str) -> Lock {
    fn render((name, version): (String, String)) -> String {
        let name = if name.is_empty() { "(no name)" } else { &name };
        format!("{name} {version}").trim().to_owned()
    }
    let mut read = Lock {
        packages: Vec::new(),
        found: Vec::new(),
    };
    let mut entry: Option<(String, String)> = None;
    let mut table = Table::Root;
    for (index, line) in lock.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.starts_with('[') {
            read.found.extend(entry.take().map(render));
            let header = plain(line);
            table = if header == "[[package]]" {
                read.packages.push(Package {
                    name: String::new(),
                    source: String::new(),
                });
                Table::Package
            } else if header == "[[patch.unused]]" {
                entry = Some((String::new(), String::new()));
                Table::Unused
            } else {
                if header.starts_with("[patch")
                    || header.starts_with("[[patch")
                    || line.contains('\\')
                {
                    read.found.push(format!(
                        "line {number}: a table that this check cannot read: {line}"
                    ));
                }
                Table::Other
            };
        } else if table == Table::Root {
            if !cargo_writes_at_the_root(line) {
                read.found.push(format!(
                    "line {number}: a line at the root that cargo does not write: {line}"
                ));
            }
        } else if let Some((key, value)) = line.split_once('=') {
            let value = string_value(value);
            match (&table, plain(key).as_str()) {
                (Table::Package, "name") => {
                    read.packages.last_mut().expect("a package").name = value;
                }
                (Table::Package, "source") => {
                    read.packages.last_mut().expect("a package").source = value;
                }
                (Table::Unused, "name") => entry.as_mut().expect("an entry").0 = value,
                (Table::Unused, "version") => entry.as_mut().expect("an entry").1 = value,
                _ => {}
            }
        }
    }
    read.found.extend(entry.take().map(render));
    read
}

/// A patch entry that nothing in the dependency graph can use is no error to cargo: it writes the
/// entry into the lock as `[[patch.unused]]`, takes the registry crate in its place and warns, and
/// `--locked` accepts that lock. The workspace's patches carry fixes that no release holds, so a
/// lock that takes the registry crate again has lost them without any build failing.
#[test]
fn the_lock_holds_no_patch_entry_that_nothing_uses() {
    let lock = read_lock(&read_repository_file("Cargo.lock"));
    assert!(
        !lock.packages.is_empty(),
        "the file read is a lock with packages"
    );
    assert!(
        lock.found.is_empty(),
        "Cargo.lock holds a patch table that records an entry nothing uses, or that this check \
         cannot read: {:?}. When nothing in the graph asks for the version a `[patch.crates-io]` \
         entry of Cargo.toml gives, cargo takes the registry crate instead and only warns",
        lock.found
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
    let lock = read_lock(&lock);
    assert_eq!(lock.packages.len(), 1);
    assert_eq!(lock.found, ["noq-proto 0.17.0"]);
}

/// Each entry is found wherever its table stands, whether another table follows it or not, and
/// however its header is spelt: with an indent, blanks, quotes or a comment.
#[test]
fn every_unused_entry_is_named_whichever_table_follows_it() {
    let lock = "version = 4\n\n\
        [[patch.unused]]\nname = \"first\"\nversion = \"1.0.0\"\nsource = \"git+https://example.org/a\"\n\n\
        [[package]]\nname = \"other\"\nversion = \"2.0.0\"\n\n\
        [[patch.unused]]\nname = \"second\"\nversion = \"3.0.0\"\n";
    let lock = read_lock(lock);
    assert_eq!(lock.packages.len(), 1);
    assert_eq!(lock.found, ["first 1.0.0", "second 3.0.0"]);
    for header in [
        "  [[patch.unused]]",
        "[[patch.unused]] # kept",
        "[[ patch.unused ]]",
        "[[patch.\"unused\"]]",
        "[[patch.'unused']]",
    ] {
        let lock = format!("version = 4\n\n{header}\nname = 'third'\nversion = \"4.0.0\"\n");
        assert_eq!(read_lock(&lock).found, ["third 4.0.0"], "{header}");
    }
}

/// A patch table that is written in a way that this check does not read is reported, as is
/// anything at the root that cargo does not write there, and a crate whose name holds `patch` is no
/// table.
#[test]
fn what_the_check_cannot_read_fails_it_and_a_crate_named_patch_does_not() {
    let passed_over = [
        "version = 4\n\n[patch]\nunused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = 4\n\n[patch.unused]\nname = \"x\"\n",
        "version = 4\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = 4\npatch = { unused = [] }\n",
        "version = 4\n\n[[patch.\"un\\u0075sed\"]]\nname = \"x\"\n",
        "version = 4\n\n[[patch.used]]\nname = \"x\"\n",
        "version = 4\n\n[[\"pat\\u0063h\".unused]]\nname = \"x\"\n",
        "version = 4\npat\\u0063h.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = 4\nmetadata.note = '''\n[metadata]\n'''\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
        "version = 4\nx = [\n[],\n]\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "\u{feff}patch.unused = [{ name = \"x\", version = \"1.0.0\" }]\nversion = 4\n",
        "\u{feff}[[patch.unused]]\nname = \"x\"\nversion = \"1.0.0\"\n",
        "version = [\n[],\n]\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
        "version = '''\n[metadata]\n'''\npatch.unused = [{ name = \"x\", version = \"1.0.0\" }]\n",
    ]
    .into_iter()
    .filter(|lock| read_lock(lock).found.is_empty())
    .collect::<Vec<_>>();
    assert!(
        passed_over.is_empty(),
        "the check passes over: {passed_over:?}"
    );
    let lock = "version = 4\n\n[[package]]\nname = \"json-patch\"\nversion = \"3.0.0\"\n\
        dependencies = [\n \"patch\",\n \"patch 0.1.0\",\n]\n";
    let lock = read_lock(lock);
    assert_eq!(lock.packages.len(), 1);
    assert!(lock.found.is_empty());
}

/// What the check reports at the root of a lock is named by the number of its line.
#[test]
fn a_root_line_that_cargo_does_not_write_is_reported_with_its_number() {
    for (lock, number) in [
        (
            "# comment\nversion = 4\n\nmetadata.note = '''\n[metadata]\n'''\n",
            4,
        ),
        ("version = 4\n\u{feff}patch.unused = []\n", 2),
        ("\u{feff}version = 4\n", 1),
    ] {
        let found = read_lock(lock).found;
        assert_eq!(found.len(), 1, "{lock:?}");
        assert!(found[0].contains(&format!("line {number}:")), "{found:?}");
    }
}

/// The count of packages does not depend on the line ends or on how the header is quoted.
#[test]
fn the_packages_are_counted_as_toml_reads_their_headers() {
    assert_eq!(
        read_lock("version = 4\r\n\r\n[[package]]\r\nname = \"a\"\r\n")
            .packages
            .len(),
        1
    );
    assert_eq!(
        read_lock("version = 4\n\n[[\"package\"]]\nname = \"a\"\n")
            .packages
            .len(),
        1
    );
}

/// One entry of the manifest's `[patch.crates-io]` table: the crate that it replaces, and the Git
/// repository and revision that it takes the crate from.
struct Patch {
    name: String,
    git: String,
    rev: String,
}

/// The one spelling of an entry that the manifest uses: `name = { git = "<url>", rev = "<revision>" }`.
fn read_patch(line: &str) -> Option<Patch> {
    let (name, entry) = line.split_once('=')?;
    let (fields, rest) = entry.trim().strip_prefix('{')?.split_once('}')?;
    let rest = rest.trim();
    if !rest.is_empty() && !rest.starts_with('#') {
        return None;
    }
    let (mut git, mut rev) = (None, None);
    for field in fields.split(',') {
        let (key, value) = field.split_once('=')?;
        let value = value
            .trim()
            .strip_prefix('"')?
            .strip_suffix('"')?
            .to_owned();
        match key.trim() {
            "git" => git = Some(value),
            "rev" => rev = Some(value),
            _ => return None,
        }
    }
    Some(Patch {
        name: plain(name),
        git: git?,
        rev: rev?,
    })
}

/// The entries of the manifest's `[patch.crates-io]` table. A line of that table in another
/// spelling, any other patch table, and any line before the manifest's first table that is not a
/// comment are errors that name the line.
fn read_patches(manifest: &str) -> Result<Vec<Patch>, String> {
    let mut patches = Vec::new();
    let mut table = Table::Root;
    for (index, line) in manifest.lines().enumerate() {
        let number = index + 1;
        let line = line.trim();
        if line.starts_with('[') {
            let header = plain(line);
            if header == "[patch.crates-io]" {
                table = Table::Unused;
            } else if header.starts_with("[patch")
                || header.starts_with("[[patch")
                || line.contains('\\')
            {
                return Err(format!(
                    "line {number}: a patch table that this check cannot read: {line}"
                ));
            } else {
                table = Table::Other;
            }
        } else if line.is_empty() || line.starts_with('#') {
        } else if table == Table::Root {
            return Err(format!(
                "line {number}: a line at the root of the manifest that this check cannot read: {line}"
            ));
        } else if table == Table::Unused {
            patches.push(read_patch(line).ok_or_else(|| {
                format!("line {number}: a patch entry that this check cannot read: {line}")
            })?);
        }
    }
    Ok(patches)
}

/// What the lock holds against each patch entry of the manifest: exactly one package of the crate's
/// name, taken from the entry's repository at the entry's revision. A patch replaces a crate whole,
/// so a second package of that name, from the registry or from anywhere else, is a use of the crate
/// that the patch did not reach.
fn patch_problems(manifest: &str, lock: &Lock) -> Vec<String> {
    let patches = match read_patches(manifest) {
        Ok(patches) => patches,
        Err(unread) => return vec![unread],
    };
    let mut problems = Vec::new();
    for Patch { name, git, rev } in patches {
        let held: Vec<&Package> = lock.packages.iter().filter(|p| p.name == name).collect();
        let [package] = held.as_slice() else {
            problems.push(format!(
                "`{name}`: the lock holds {} packages of this name, and a patch replaces a crate \
                 whole, so it has to hold one",
                held.len()
            ));
            continue;
        };
        let from_the_entry = package
            .source
            .strip_prefix(&format!("git+{git}?rev={rev}#"))
            .is_some_and(|commit| commit.starts_with(&rev));
        if !from_the_entry {
            let source = if package.source.is_empty() {
                "no source"
            } else {
                &package.source
            };
            problems.push(format!(
                "`{name}`: the lock takes it from {source}, not from {git} at {rev}"
            ));
        }
    }
    problems
}

/// The entry of the manifest that the fixture lock and the strings below stand against, and the
/// source that cargo gives its crate in a lock.
const GIT_ENTRY: &str = "noq-proto = { git = \"https://github.com/kalapowered/noq\", rev = \
    \"d8d5e9153f22f521bc5768c83fc4a50963d02bf3\" }";
const GIT_SOURCE: &str = "git+https://github.com/kalapowered/noq?rev=\
    d8d5e9153f22f521bc5768c83fc4a50963d02bf3#d8d5e9153f22f521bc5768c83fc4a50963d02bf3";

fn manifest_with(entries: &str) -> String {
    format!("[workspace]\nmembers = []\n\n[patch.crates-io]\n{entries}\n\n[lints]\nx = 1\n")
}

fn lock_with(packages: &[(&str, &str)]) -> Lock {
    let text: String = packages
        .iter()
        .map(|(name, source)| {
            let source = if source.is_empty() {
                String::new()
            } else {
                format!("source = \"{source}\"\n")
            };
            format!("[[package]]\nname = \"{name}\"\nversion = \"1.4.0\"\n{source}\n")
        })
        .collect();
    read_lock(&format!("version = 4\n\n{text}"))
}

#[test]
fn a_patched_crate_is_replaced_whole_in_the_lock() {
    let problems = patch_problems(
        &read_repository_file("Cargo.toml"),
        &read_lock(&read_repository_file("Cargo.lock")),
    );
    assert!(
        problems.is_empty(),
        "Cargo.lock does not take a crate of `[patch.crates-io]` whole from its entry: \
         {problems:?}. A second package of the crate comes from a dependency whose version the \
         patch does not satisfy, and it keeps the crate's registry release in the build"
    );
}

/// A lock that cargo wrote for a crate that two parts of the graph ask for in versions that no one
/// release satisfies: the patch gives the one version from Git, and the registry gives the other.
/// The excerpt is that lock's own text.
#[test]
fn a_second_package_of_a_patched_crate_from_the_registry_fails_the_check() {
    let lock = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/patched-crates/two-packages-lock.txt"),
    )
    .expect("the fixture");
    let lock = read_lock(&lock);
    assert_eq!(lock.packages.len(), 2);
    assert!(lock.found.is_empty(), "cargo wrote no patch table here");
    let problems = patch_problems(&manifest_with(GIT_ENTRY), &lock);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("noq-proto"), "{problems:?}");
}

#[test]
fn a_crate_that_the_lock_takes_whole_from_its_entry_passes_and_any_other_source_fails() {
    let manifest = manifest_with(&format!(
        "# a comment\n  {GIT_ENTRY} # kept\n\"noq-udp\" = {{ git = \"https://example.org/u\", rev = \"ab\" }}"
    ));
    let udp = "git+https://example.org/u?rev=ab#abcdef";
    let whole = [("noq-proto", GIT_SOURCE), ("noq-udp", udp)];
    assert_eq!(
        patch_problems(&manifest, &lock_with(&whole)),
        Vec::<String>::new()
    );
    let registry = "registry+https://github.com/rust-lang/crates.io-index";
    for (name, packages) in [
        (
            "the registry crate only",
            vec![("noq-proto", registry), ("noq-udp", udp)],
        ),
        (
            "both",
            vec![
                ("noq-proto", registry),
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", udp),
            ],
        ),
        (
            "two from the entry",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", udp),
            ],
        ),
        ("one of them missing", vec![("noq-proto", GIT_SOURCE)]),
        ("no source", vec![("noq-proto", ""), ("noq-udp", udp)]),
        (
            "another revision",
            vec![
                (
                    "noq-proto",
                    "git+https://github.com/kalapowered/noq?rev=0000#0000",
                ),
                ("noq-udp", udp),
            ],
        ),
        (
            "another repository",
            vec![
                (
                    "noq-proto",
                    "git+https://github.com/n0-computer/noq?rev=d8d5e9153f22f521bc5768c83fc4a50963d02bf3#d8d5e9153f22f521bc5768c83fc4a50963d02bf3",
                ),
                ("noq-udp", udp),
            ],
        ),
        (
            "another commit",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", "git+https://example.org/u?rev=ab#ffff"),
            ],
        ),
    ] {
        let problems = patch_problems(&manifest, &lock_with(&packages));
        assert_eq!(problems.len(), 1, "{name}: {problems:?}");
    }
    assert!(patch_problems(&manifest_with(""), &lock_with(&[])).is_empty());
    let indented = format!("[workspace]\n  [patch.crates-io]\n  {GIT_ENTRY}\n");
    assert_eq!(patch_problems(&indented, &lock_with(&[])).len(), 1);
}

#[test]
fn a_manifest_that_this_check_cannot_read_fails_it() {
    let lock = lock_with(&[("noq-proto", GIT_SOURCE)]);
    for manifest in [
        manifest_with("noq-proto = { git = \"https://example.org/n\", branch = \"main\" }"),
        manifest_with(
            "noq-proto = { git = \"https://example.org/n\", rev = \"ab\", branch = \"b\" }",
        ),
        manifest_with("noq-proto = { path = \"../noq\" }"),
        manifest_with("noq-proto = \"1.4.0\""),
        manifest_with("noq-proto.git = \"https://example.org/n\""),
        manifest_with(&format!("{GIT_ENTRY} trailing")),
        manifest_with("noq-proto = { git = \"https://example.org/n\", rev = \"ab\", }"),
        format!(
            "{}\n[patch.\"https://example.org/n\"]\nx = 1\n",
            manifest_with(GIT_ENTRY)
        ),
        format!("[[patch.crates-io]]\nx = 1\n{}", manifest_with(GIT_ENTRY)),
        format!(
            "[patch.crates\\u002dio]\nx = 1\n{}",
            manifest_with(GIT_ENTRY)
        ),
        format!(
            "[pat\\u0063h.crates-io]\nx = 1\n{}",
            manifest_with(GIT_ENTRY)
        ),
        format!(
            "patch.crates-io.x = {{ path = \"p\" }}\n{}",
            manifest_with(GIT_ENTRY)
        ),
        format!("note = '''\n[workspace]\n'''\n{}", manifest_with(GIT_ENTRY)),
    ] {
        let problems = patch_problems(&manifest, &lock);
        assert_eq!(problems.len(), 1, "{manifest}: {problems:?}");
        assert!(problems[0].contains("line "), "{problems:?}");
    }
}

/// The sentence of `docs/README.md` that the list of crates taken from Git follows.
const LIST_INTRO: &str = "Core's lock takes these crates from Git:";

/// The crate names that a document lists after [`LIST_INTRO`]: the code spans after the last colon
/// of each bullet of the list that follows the sentence, whether the bullet wraps or not.
fn listed_git_crates(document: &str) -> BTreeSet<String> {
    let list = document
        .lines()
        .skip_while(|line| !line.contains(LIST_INTRO))
        .skip(1)
        .skip_while(|line| line.trim().is_empty())
        .take_while(|line| !line.trim().is_empty());
    let mut items: Vec<String> = Vec::new();
    for line in list {
        match (line.strip_prefix("- "), items.last_mut()) {
            (Some(first), _) => items.push(first.to_owned()),
            (None, Some(last)) => {
                last.push(' ');
                last.push_str(line.trim());
            }
            (None, None) => {}
        }
    }
    items
        .iter()
        .filter_map(|item| item.rsplit_once(": "))
        .flat_map(|(_, names)| names.split('`').skip(1).step_by(2))
        .map(str::to_owned)
        .collect()
}

/// The crates that a lock takes from a Git source, which `cargo audit` does not check.
fn git_crates(lock: &Lock) -> BTreeSet<String> {
    lock.packages
        .iter()
        .filter(|package| package.source.starts_with("git+"))
        .map(|package| package.name.clone())
        .collect()
}

fn list_differences(listed: &BTreeSet<String>, lock: &BTreeSet<String>) -> Vec<String> {
    let missing = lock
        .difference(listed)
        .map(|name| format!("`{name}` is taken from Git by the lock and not listed"));
    let stale = listed
        .difference(lock)
        .map(|name| format!("`{name}` is listed and not taken from Git by the lock"));
    missing.chain(stale).collect()
}

#[test]
fn the_documents_list_the_crates_that_the_lock_takes_from_git() {
    let differences = list_differences(
        &listed_git_crates(&read_repository_file("docs/README.md")),
        &git_crates(&read_lock(&read_repository_file("Cargo.lock"))),
    );
    assert!(
        differences.is_empty(),
        "the list in docs/README.md differs from the packages that Cargo.lock takes from Git, \
         which `cargo audit` does not check: {differences:?}"
    );
}

#[test]
fn a_list_that_differs_from_the_lock_is_reported_in_both_directions() {
    let git = |name| (name, "git+https://example.org/x?rev=1#1");
    let registry = |name| {
        (
            name,
            "registry+https://github.com/rust-lang/crates.io-index",
        )
    };
    let lock = git_crates(&lock_with(&[git("a"), git("c"), registry("b")]));
    let document =
        |list: &str| format!("Text `x`.\n{LIST_INTRO}\n\n{list}\n\nAfter the list: `z`.\n");
    let listed = |list: &str| listed_git_crates(&document(list));
    let wrapped = "- from `x`: a note about `y`: `a`,\n  `c`\n";
    assert_eq!(
        list_differences(&listed(wrapped), &lock),
        Vec::<String>::new()
    );
    let two = "- from one place: `a`, `c`\n- from another: `b`\n";
    assert_eq!(
        list_differences(&listed(two), &lock),
        ["`b` is listed and not taken from Git by the lock"]
    );
    let one = "- from one place: `a`\n";
    assert_eq!(
        list_differences(&listed(one), &lock),
        ["`c` is taken from Git by the lock and not listed"]
    );
    assert_eq!(
        list_differences(&listed_git_crates("`a`, `c`\n"), &lock).len(),
        2
    );
}
