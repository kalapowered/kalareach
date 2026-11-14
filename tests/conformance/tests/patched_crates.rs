//! The workspace's `[patch.crates-io]` entries and the crates its lock takes from a Git source: the
//! lock says by name when cargo found nothing to use an entry for, and a patched crate has to be
//! replaced whole.
//!
//! The lock and the manifest are read as TOML data, and every rule works on the parsed values, so
//! no spelling of the same data can differ from another here. A file that does not parse fails the
//! check with the parser's message.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml::{Table, Value};
use url::Url;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_repository_file(path: &str) -> String {
    std::fs::read_to_string(repository().join(path)).expect(path)
}

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/patched-crates")
            .join(name),
    )
    .expect(name)
}

/// A package of a lock: its name and, if it has one, its source.
struct Package {
    name: String,
    source: Option<String>,
}

/// What this check reads of a lock: the packages, and `found`, each entry of the root's
/// `patch.unused` as `name version` together with each report of something that this check cannot
/// read.
struct Lock {
    packages: Vec<Package>,
    found: Vec<String>,
}

/// An entry of `patch.unused` as `name version`.
fn render(entry: &Value) -> String {
    let field = |key: &str| entry.get(key).and_then(Value::as_str).unwrap_or_default();
    let name = match field("name") {
        "" => "(no name)",
        name => name,
    };
    format!("{name} {}", field("version")).trim().to_owned()
}

/// Reads a lock file. A patch entry that nothing used is an entry of `patch.unused` at the root,
/// which cargo writes as `[[patch.unused]]` tables; any TOML spelling of the same data is found the
/// same way. A `patch` key that holds anything else, a package without a string name, and a source
/// that is not a string are reported, as is a lock that does not parse.
fn read_lock(lock: &str) -> Lock {
    let mut read = Lock {
        packages: Vec::new(),
        found: Vec::new(),
    };
    let root: Table = match lock.parse() {
        Ok(root) => root,
        Err(error) => {
            read.found
                .push(format!("the lock does not parse as TOML: {error}"));
            return read;
        }
    };
    match root.get("package") {
        None => {}
        Some(Value::Array(packages)) => {
            for (index, package) in packages.iter().enumerate() {
                let name = package.get("name").and_then(Value::as_str);
                let source = package.get("source").map(Value::as_str);
                match (name, source) {
                    (Some(name), None | Some(Some(_))) => read.packages.push(Package {
                        name: name.to_owned(),
                        source: source.flatten().map(str::to_owned),
                    }),
                    _ => read.found.push(format!(
                        "package {} of the lock has no string name, or has a source that is not a \
                         string",
                        index + 1
                    )),
                }
            }
        }
        Some(_) => read
            .found
            .push("`package` is not an array of tables".to_owned()),
    }
    match root.get("patch") {
        None => {}
        Some(Value::Table(patch)) => {
            for (key, entries) in patch {
                match (key.as_str(), entries) {
                    ("unused", Value::Array(entries)) => {
                        read.found.extend(entries.iter().map(render));
                    }
                    _ => read.found.push(format!(
                        "`patch.{key}` is not an array of entries, the only form of `patch` that \
                         this check reads"
                    )),
                }
            }
        }
        Some(_) => read.found.push("`patch` is not a table".to_owned()),
    }
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
    let lock = read_lock(&fixture("unused-patch-lock.txt"));
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

/// The entry of the root `patch.unused` that every text below holds, in the spellings that TOML
/// allows for it and that the line readers of the earlier checks read wrongly: the entry is found
/// by its name in each, wherever a multiline string, an escape, a quoted key, a byte-order mark or
/// an array before it would have hidden it from a reader of lines.
#[test]
fn an_unused_entry_is_found_in_every_spelling_that_toml_gives_it() {
    let entry = "{ name = \"x\", version = \"1.0.0\" }";
    let spellings = vec![
        format!("version = 4\n\n[patch]\nunused = [{entry}]\n"),
        format!("version = 4\npatch.unused = [{entry}]\n"),
        format!("version = 4\npatch = {{ unused = [{entry}] }}\n"),
        format!("version = 4\n\n[[patch.\"un\\u0075sed\"]]\nname = \"x\"\nversion = \"1.0.0\"\n"),
        format!("version = 4\n\n[[\"pat\\u0063h\".unused]]\nname = \"x\"\nversion = \"1.0.0\"\n"),
        format!("version = 4\n\"pat\\u0063h\".unused = [{entry}]\n"),
        format!("version = 4\nmetadata.note = '''\n[metadata]\n'''\npatch.unused = [{entry}]\n"),
        format!("version = 4\nx = [\n[],\n]\npatch.unused = [{entry}]\n"),
        format!("version = [\n[],\n]\npatch.unused = [{entry}]\n"),
        format!("version = '''\n[metadata]\n'''\npatch.unused = [{entry}]\n"),
        format!("version = 4\n\"ver sion\" = '''4\n[metadata]\n'''\npatch.unused = [{entry}]\n"),
        format!("version = 4\n\n[[patch.unused]] # edited\nname = \"x\"\nversion = \"1.0.0\"\n"),
        format!("\u{feff}patch.unused = [{entry}]\nversion = 4\n"),
        format!("\u{feff}[[patch.unused]]\nname = \"x\"\nversion = \"1.0.0\"\n"),
        format!("version = 4\r\n\r\n[[patch.unused]]\r\nname = \"x\"\r\nversion = \"1.0.0\"\r\n"),
        "version = 4\n\n[[package]]\nname = \"a\"\nversion = \"1.0.0\"\nnote = '''\n[[package]]\n'''\n\n\
         [[patch.unused]]\nname = \"x\"\nversion = \"1.0.0\"\n"
            .to_owned(),
    ];
    for lock in spellings {
        assert_eq!(read_lock(&lock).found, ["x 1.0.0"], "{lock:?}");
    }
}

/// A patch table in a form that this check does not read, and a lock that does not parse, are
/// reported, and a `patch` table with no entry is not an entry. A crate whose name holds `patch` is
/// no table.
#[test]
fn what_the_check_cannot_read_fails_it_and_what_holds_no_entry_does_not() {
    let not_read = [
        "version = 4\n\n[patch.unused]\nname = \"x\"\n",
        "version = 4\n\n[[patch.used]]\nname = \"x\"\n",
        "version = 4\npatch = \"x\"\n",
        "version = 4\npatch.unused = \"x\"\n",
        "version = 4\n\n[[package]]\nversion = \"1.0.0\"\n",
        "version = 4\n\n[[package]]\nname = \"a\"\nsource = 4\n",
        "version = 4\npackage = \"x\"\n",
    ];
    for lock in not_read {
        assert_eq!(read_lock(lock).found.len(), 1, "{lock:?}");
    }
    let broken = read_lock("version = 4\n\n[[package]\nname = \"a\"\n");
    assert_eq!(broken.found.len(), 1, "{:?}", broken.found);
    assert!(broken.found[0].contains("line 3"), "{:?}", broken.found);
    for lock in [
        "version = 4\npatch = { unused = [] }\n",
        "version = 4\npatch.unused = []\n",
        "version = 4\nsomething.else = 'x'\n\n[metadata]\nnote = 'x'\n",
    ] {
        assert!(read_lock(lock).found.is_empty(), "{lock:?}");
    }
    let lock = "version = 4\n\n[[package]]\nname = \"json-patch\"\nversion = \"3.0.0\"\n\
        dependencies = [\n \"patch\",\n \"patch 0.1.0\",\n]\n";
    let lock = read_lock(lock);
    assert_eq!(lock.packages.len(), 1);
    assert!(lock.found.is_empty());
}

/// The count of packages does not depend on the line ends or on how the header is quoted, and a
/// string that holds a header is no header.
#[test]
fn the_packages_are_counted_as_toml_reads_their_headers() {
    for lock in [
        "version = 4\r\n\r\n[[package]]\r\nname = \"a\"\r\n",
        "version = 4\n\n[[\"package\"]]\nname = \"a\"\n",
        "version = 4\n\n[[package]]\nname = \"a\"\nnote = '''\n[[package]]\nname = \"b\"\n'''\n",
    ] {
        assert_eq!(read_lock(lock).packages.len(), 1, "{lock:?}");
    }
}

/// One entry of the manifest's `[patch.crates-io]` table: the crate that it replaces, and the Git
/// repository and revision that it takes the crate from.
struct Patch {
    name: String,
    git: String,
    rev: String,
}

/// An entry is a table of exactly `git` and `rev`, both strings, in whatever TOML spelling.
fn read_patch(name: &str, entry: &Value) -> Result<Patch, String> {
    let field = |key: &str| entry.get(key).and_then(Value::as_str).map(str::to_owned);
    match (entry.as_table().map(Table::len), field("git"), field("rev")) {
        (Some(2), Some(git), Some(rev)) => Ok(Patch {
            name: name.to_owned(),
            git,
            rev,
        }),
        _ => Err(format!(
            "the entry `{name}` of `[patch.crates-io]` is not a table of exactly a `git` and a \
             `rev`, both strings, the only form that this check reads"
        )),
    }
}

/// The entries of the manifest's `patch.crates-io` table. A manifest that does not parse, a `patch`
/// key that holds another table, and an entry in another form are errors.
fn read_patches(manifest: &str) -> Result<Vec<Patch>, String> {
    let root: Table = manifest
        .parse()
        .map_err(|error| format!("Cargo.toml does not parse as TOML: {error}"))?;
    let Some(patch) = root.get("patch") else {
        return Ok(Vec::new());
    };
    let Some(tables) = patch.as_table() else {
        return Err("`patch` of Cargo.toml is not a table".to_owned());
    };
    let mut patches = Vec::new();
    for (registry, table) in tables {
        let entries = match (registry.as_str(), table.as_table()) {
            ("crates-io", Some(entries)) => entries,
            _ => {
                return Err(format!(
                    "Cargo.toml holds `patch.{registry}`, which is not the table \
                     `[patch.crates-io]`, the only patch table that this check reads"
                ));
            }
        };
        for (name, entry) in entries {
            patches.push(read_patch(name, entry)?);
        }
    }
    Ok(patches)
}

/// What counts as one repository: the same scheme, host, port, user name and path, where the
/// letter case of the scheme and the host does not matter, a port that is the scheme's default is
/// no port, and the path ignores a final `/` and a final `.git`. The rest of the path is compared
/// as it is written.
fn repository_of(url: &Url) -> (String, String, Option<u16>, String, String) {
    let path = url.path().trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    (
        url.scheme().to_ascii_lowercase(),
        url.host_str().unwrap_or_default().to_ascii_lowercase(),
        url.port_or_known_default(),
        url.username().to_owned(),
        path.to_owned(),
    )
}

/// Whether the lock's `source` of a package is the entry's repository at the entry's revision, in
/// the form cargo writes: `git+<url>?rev=<revision>#<commit>`, where the commit starts with the
/// revision. The URLs are compared as [`repository_of`] says; the revision is compared as written.
fn comes_from_the_entry(source: &str, git: &str, rev: &str) -> bool {
    let Some((location, commit)) = source
        .strip_prefix("git+")
        .and_then(|source| source.split_once('#'))
    else {
        return false;
    };
    let (Ok(location), Ok(entry)) = (Url::parse(location), Url::parse(git)) else {
        return false;
    };
    location.query() == Some(format!("rev={rev}").as_str())
        && commit.starts_with(rev)
        && entry.query().is_none()
        && entry.fragment().is_none()
        && repository_of(&location) == repository_of(&entry)
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
        let source = package.source.as_deref();
        if !source.is_some_and(|source| comes_from_the_entry(source, &git, &rev)) {
            problems.push(format!(
                "`{name}`: the lock takes it from {}, not from {git} at {rev}",
                source.unwrap_or("no source")
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
const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

fn manifest_with(entries: &str) -> String {
    format!("[workspace]\nmembers = []\n\n[patch.crates-io]\n{entries}\n\n[lints]\nx = 1\n")
}

/// [`GIT_ENTRY`] with another URL for the repository.
fn entry_at(url: &str) -> String {
    GIT_ENTRY.replacen("https://github.com/kalapowered/noq", url, 1)
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
    let lock = read_lock(&fixture("two-packages-lock.txt"));
    assert_eq!(lock.packages.len(), 2);
    assert!(lock.found.is_empty(), "cargo wrote no patch table here");
    let problems = patch_problems(&manifest_with(GIT_ENTRY), &lock);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("noq-proto"), "{problems:?}");
}

/// A package name that TOML spells with an escape is the name it spells, so the second package is
/// counted, and an assignment inside a multiline string is no assignment of the package.
#[test]
fn a_package_is_read_by_its_data_and_not_by_its_spelling() {
    let lock = fixture("two-packages-lock.txt").replacen(
        "name = \"noq-proto\"",
        "name = \"noq-pr\\u006fto\"",
        1,
    );
    let problems = patch_problems(&manifest_with(GIT_ENTRY), &read_lock(&lock));
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("2 packages"), "{problems:?}");

    let lock = read_lock(&format!(
        "version = 4\n\n[[package]]\nname = \"noq-proto\"\nversion = \"1.4.0\"\n\
         source = \"{REGISTRY}\"\nnote = '''\nsource = \"{GIT_SOURCE}\"\n'''\n"
    ));
    assert!(git_crates(&lock).is_empty());
    let problems = patch_problems(&manifest_with(GIT_ENTRY), &lock);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains(REGISTRY), "{problems:?}");
}

/// Two spellings of a repository's URL are one repository as [`repository_of`] says: the letter
/// case of the scheme and the host, the default port, a final `.git` and a final `/` make no
/// difference, and anything else does.
#[test]
fn a_repository_is_the_same_repository_in_every_spelling_of_its_url() {
    let lock = lock_with(&[("noq-proto", GIT_SOURCE)]);
    for url in [
        "https://github.com/kalapowered/noq",
        "https://GITHUB.COM/kalapowered/noq",
        "HTTPS://github.com/kalapowered/noq",
        "https://github.com/kalapowered/noq.git",
        "https://github.com/kalapowered/noq/",
        "https://github.com:443/kalapowered/noq",
    ] {
        let manifest = manifest_with(&entry_at(url));
        assert_eq!(
            patch_problems(&manifest, &lock),
            Vec::<String>::new(),
            "{url}"
        );
    }
    let with_suffix = GIT_SOURCE.replacen("noq?", "noq.git?", 1);
    let lock = lock_with(&[("noq-proto", with_suffix.as_str())]);
    assert_eq!(
        patch_problems(&manifest_with(GIT_ENTRY), &lock),
        Vec::<String>::new()
    );
    // The URL parser leaves the host of a scheme it does not know as it is written.
    let over_ssh = GIT_SOURCE.replacen("https://", "ssh://", 1);
    let lock = lock_with(&[("noq-proto", over_ssh.as_str())]);
    let manifest = manifest_with(&entry_at("ssh://GitHub.com/kalapowered/noq"));
    assert_eq!(patch_problems(&manifest, &lock), Vec::<String>::new());
    let lock = lock_with(&[("noq-proto", GIT_SOURCE)]);
    for url in [
        "https://github.com/kalapowered/other",
        "https://github.com/kalapowered",
        "https://github.com/KalaPowered/noq",
        "http://github.com/kalapowered/noq",
        "https://github.com:8443/kalapowered/noq",
        "https://user@github.com/kalapowered/noq",
        "https://example.org/kalapowered/noq",
        "https://github.com/kalapowered/noq?branch=main",
        "https://github.com/kalapowered/noq#main",
        "github.com/kalapowered/noq",
    ] {
        let manifest = manifest_with(&entry_at(url));
        let problems = patch_problems(&manifest, &lock);
        assert_eq!(problems.len(), 1, "{url}: {problems:?}");
    }
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
    for (name, packages) in [
        (
            "the registry crate only",
            vec![("noq-proto", REGISTRY), ("noq-udp", udp)],
        ),
        (
            "both",
            vec![
                ("noq-proto", REGISTRY),
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
            "the path in another case",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", "git+https://example.org/U?rev=ab#abcdef"),
            ],
        ),
        (
            "another commit",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", "git+https://example.org/u?rev=ab#ffff"),
            ],
        ),
        (
            "no commit",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", "git+https://example.org/u?rev=ab"),
            ],
        ),
        (
            "a branch for the revision",
            vec![
                ("noq-proto", GIT_SOURCE),
                ("noq-udp", "git+https://example.org/u?branch=ab#abcdef"),
            ],
        ),
    ] {
        let problems = patch_problems(&manifest, &lock_with(&packages));
        assert_eq!(problems.len(), 1, "{name}: {problems:?}");
    }
    assert!(patch_problems(&manifest_with(""), &lock_with(&[])).is_empty());
}

/// A manifest that does not parse is reported with the parser's message and its line, and an
/// entry or a patch table in a form that this check does not read is reported by its name.
#[test]
fn a_manifest_that_this_check_cannot_read_fails_it() {
    let lock = lock_with(&[("noq-proto", GIT_SOURCE)]);
    let broken = [
        manifest_with(&format!("{GIT_ENTRY} trailing")),
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
    ];
    for manifest in broken {
        let problems = patch_problems(&manifest, &lock);
        assert_eq!(problems.len(), 1, "{manifest}: {problems:?}");
        assert!(problems[0].contains("line "), "{problems:?}");
    }
    let not_read = [
        manifest_with("noq-proto = { git = \"https://example.org/n\", branch = \"main\" }"),
        manifest_with(
            "noq-proto = { git = \"https://example.org/n\", rev = \"ab\", branch = \"b\" }",
        ),
        manifest_with("noq-proto = { path = \"../noq\" }"),
        manifest_with("noq-proto = \"1.4.0\""),
        manifest_with("noq-proto.git = \"https://example.org/n\""),
        manifest_with("noq-proto = { git = \"https://example.org/n\", rev = 4 }"),
        manifest_with(&GIT_ENTRY.replace(" }", ", package = \"other\" }")),
        format!(
            "{}\n[patch.\"https://example.org/n\"]\n{GIT_ENTRY}\n",
            manifest_with(GIT_ENTRY)
        ),
        "patch = \"x\"\n\n[workspace]\nmembers = []\n".to_owned(),
    ];
    for manifest in not_read {
        let problems = patch_problems(&manifest, &lock);
        assert_eq!(problems.len(), 1, "{manifest}: {problems:?}");
    }
}

/// The entry of the manifest is read by its data: any TOML spelling of it gives the same patch, a
/// multiline string that holds a header is no header, and a trailing comma in an inline table
/// changes nothing.
#[test]
fn a_manifest_is_read_as_data_in_every_spelling_that_toml_gives_it() {
    let lock = lock_with(&[("noq-proto", GIT_SOURCE)]);
    let git = "https://github.com/kalapowered/noq";
    let rev = "d8d5e9153f22f521bc5768c83fc4a50963d02bf3";
    for manifest in [
        manifest_with(GIT_ENTRY),
        manifest_with(&format!(
            "noq-proto.git = \"{git}\"\nnoq-proto.rev = \"{rev}\""
        )),
        manifest_with(&format!(
            "\"noq-pr\\u006fto\" = {{ git = '{git}', rev = '{rev}' }}"
        )),
        manifest_with(&format!(
            "noq-proto = {{ git = \"{git}\", rev = \"{rev}\", }}"
        )),
        format!("note = '''\n[workspace]\n'''\n{}", manifest_with(GIT_ENTRY)),
        format!(
            "[workspace]\npatch = {{ crates-io = {{ noq-proto = {{ git = \"{git}\", rev = \"{rev}\" }} }} }}\n"
        ),
        format!("\u{feff}{}", manifest_with(GIT_ENTRY)),
        manifest_with(GIT_ENTRY).replace('\n', "\r\n"),
    ] {
        let problems = patch_problems(&manifest, &lock);
        assert!(problems.is_empty(), "{manifest:?}: {problems:?}");
    }
    let other = manifest_with(&format!(
        "noq-proto.git = \"{git}\"\nnoq-proto.rev = \"{rev}\"\nnoq-udp = {{ git = \"{git}\", rev = \"ab\" }}"
    ));
    let problems = patch_problems(&other, &lock);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("noq-udp"), "{problems:?}");
}

/// The sentence of `docs/README.md` that the list of crates taken from Git follows.
const LIST_INTRO: &str = "Core's lock takes these crates from Git:";

/// Whether a line starts a Markdown list item, in any marker.
fn starts_a_list_item(text: &str) -> bool {
    let Some((marker, _)) = text.split_once(' ') else {
        return false;
    };
    matches!(marker, "-" | "*" | "+")
        || marker
            .strip_suffix(['.', ')'])
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The crate names that a document lists after [`LIST_INTRO`], read as a whole: the code spans
/// after the last colon of each bullet of the list that follows the sentence. A bullet may wrap,
/// and a blank line may stand between bullets; the list ends at the first paragraph, heading or end
/// of the document after it. Anything else in the list is an error that names its line: a marker
/// other than `- `, a nested item, text before the first bullet, a bullet with no colon, and names
/// that are not code spans.
fn listed_git_crates(document: &str) -> Result<BTreeSet<String>, String> {
    let mut lines = document
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line));
    if !lines.any(|(_, line)| line.contains(LIST_INTRO)) {
        return Err(format!("no line holds {LIST_INTRO:?}"));
    }
    let mut items: Vec<(usize, String)> = Vec::new();
    let mut after_blank = false;
    for (number, line) in lines {
        let text = line.trim();
        if text.is_empty() {
            after_blank = true;
            continue;
        }
        let indented = line.starts_with([' ', '\t']);
        if !indented && line.starts_with("- ") {
            items.push((number, text[2..].trim().to_owned()));
        } else if starts_a_list_item(text) {
            return Err(format!(
                "line {number}: a list marker or a nested item that this reader does not know: \
                 {text}"
            ));
        } else if !indented && items.is_empty() {
            return Err(format!(
                "line {number}: no bullet list follows the sentence, this does: {text}"
            ));
        } else if !indented && (after_blank || text.starts_with('#')) {
            break;
        } else if let Some((_, item)) = items.last_mut() {
            item.push(' ');
            item.push_str(text);
        } else {
            return Err(format!(
                "line {number}: text before the first bullet: {text}"
            ));
        }
        after_blank = false;
    }
    let mut listed = BTreeSet::new();
    for (number, item) in items {
        let Some((_, names)) = item.rsplit_once(": ") else {
            return Err(format!(
                "line {number}: a bullet with no `: ` before its crate names: {item}"
            ));
        };
        for name in names.split(',') {
            let name = name
                .trim()
                .strip_prefix('`')
                .and_then(|name| name.strip_suffix('`'))
                .filter(|name| !name.is_empty() && !name.contains('`'));
            let Some(name) = name else {
                return Err(format!(
                    "line {number}: after its last `: ` the bullet holds more than crate names in \
                     code spans, separated by commas: {names}"
                ));
            };
            listed.insert(name.to_owned());
        }
    }
    Ok(listed)
}

/// The crates that a lock takes from a Git source, which `cargo audit` does not check.
fn git_crates(lock: &Lock) -> BTreeSet<String> {
    lock.packages
        .iter()
        .filter(|package| {
            package
                .source
                .as_deref()
                .is_some_and(|source| source.starts_with("git+"))
        })
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
    let listed =
        listed_git_crates(&read_repository_file("docs/README.md")).unwrap_or_else(|reason| {
            panic!("docs/README.md holds a list that cannot be read: {reason}")
        });
    let differences = list_differences(
        &listed,
        &git_crates(&read_lock(&read_repository_file("Cargo.lock"))),
    );
    assert!(
        differences.is_empty(),
        "the list in docs/README.md differs from the packages that Cargo.lock takes from Git, \
         which `cargo audit` does not check: {differences:?}"
    );
}

fn git_package(name: &str) -> (&str, &str) {
    (name, "git+https://example.org/x?rev=1#1")
}

/// The document that the cases below put a list into, and what it lists.
fn document(list: &str) -> String {
    format!("Text `x`.\n{LIST_INTRO}\n\n{list}\n\nAfter the list: `z`.\n")
}

fn listed(list: &str) -> BTreeSet<String> {
    listed_git_crates(&document(list)).expect("a list that the reader knows")
}

#[test]
fn a_list_that_differs_from_the_lock_is_reported_in_both_directions() {
    let registry = |name| (name, REGISTRY);
    let lock = git_crates(&lock_with(&[
        git_package("a"),
        git_package("c"),
        registry("b"),
    ]));
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
    assert!(listed_git_crates("`a`, `c`\n").is_err());
}

/// The list is read whole: a blank line between bullets does not end it, and only a paragraph, a
/// heading or the end of the document does.
#[test]
fn a_blank_line_between_bullets_does_not_end_the_list() {
    let lock = git_crates(&lock_with(&[git_package("a"), git_package("c")]));
    let loose = "- from a fork: `a`, `c`\n\n- from upstream\n\n  and a paragraph of that bullet: `b`\n\n- from a third place: `d`\n";
    assert_eq!(
        list_differences(&listed(loose), &lock),
        [
            "`b` is listed and not taken from Git by the lock",
            "`d` is listed and not taken from Git by the lock"
        ]
    );
    let ended = "- from a fork: `a`, `c`\n\nA paragraph: `b`\n\n- not a part of the list: `d`\n";
    assert!(list_differences(&listed(ended), &lock).is_empty());
    let heading = "Text.\n{INTRO}\n\n- from a fork: `a`, `c`\n## Next\n- from a place: `b`\n"
        .replace("{INTRO}", LIST_INTRO);
    assert_eq!(
        list_differences(&listed_git_crates(&heading).unwrap(), &lock),
        Vec::<String>::new()
    );
    let at_the_end = format!("{LIST_INTRO}\n\n- from a fork: `a`,\n  `c`");
    assert_eq!(
        list_differences(&listed_git_crates(&at_the_end).unwrap(), &lock),
        Vec::<String>::new()
    );
}

/// A structure that the reader does not know is an error with the number of its line, never a
/// bullet that is passed over.
#[test]
fn a_list_structure_that_the_reader_does_not_know_fails_with_its_line() {
    for (list, number) in [
        ("* from a fork: `a`\n", 4),
        ("+ from a fork: `a`\n", 4),
        ("1. from a fork: `a`\n", 4),
        ("- from a fork: `a`\n  - nested: `b`\n", 5),
        ("- from a fork: `a`\n\n  1) nested: `b`\n", 6),
        ("- from a fork `a`\n", 4),
        ("- from a fork: `a` and `b`\n", 4),
        ("- from a fork: `a`, , `b`\n", 4),
        ("- from a fork: a\n", 4),
        ("- from a fork: ``\n", 4),
        ("- from a fork: `a`.\n", 4),
        ("  text before the first bullet\n", 4),
        ("Text and no bullet: `a`\n", 4),
    ] {
        let error = listed_git_crates(&document(list)).expect_err(list);
        assert!(
            error.contains(&format!("line {number}:")),
            "{list:?}: {error}"
        );
    }
    assert!(listed_git_crates("`a`\n").is_err());
}
