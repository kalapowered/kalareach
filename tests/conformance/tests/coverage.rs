//! The targets a `cargo test` command selects, against the targets Cargo builds for it.
//!
//! Each case writes a set of workspaces into a directory of its own on the disk the system's
//! temporary directory is on, and for each command of a table compares the targets the report says
//! the command covers (from the workspace's metadata and the command's words) with the targets of
//! the `compiler-artifact` messages that `cargo test --no-run --message-format=json` writes for the
//! same words in the same workspace. The builds run offline, in a target directory of their own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_conformance::coverage;
use kr_conformance::workspace::{self, TargetId, TargetKind};

fn write(root: &Path, relative: &str, text: &str) {
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
    std::fs::write(path, text).expect("a file");
}

fn manifest(name: &str, extra: &str) -> String {
    format!(
        "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2024\"\npublish = false\n{extra}"
    )
}

const LIB: &str = "pub fn one() -> u32 {\n    1\n}\n";
const MAIN: &str = "fn main() {}\n";
const TEST: &str = "#[test]\nfn works() {}\n";

/// A package with a library, the binaries `x`, `y` and `z` (`z` is never tested), the integration
/// tests `t` and `u`, the examples `e` and `f` (`f` is tested), and the bench `m` that has no harness.
fn rich(root: &Path, directory: &str, name: &str) {
    write(
        root,
        &format!("{directory}/Cargo.toml"),
        &manifest(
            name,
            "\n[[bin]]\nname = \"z\"\npath = \"src/bin/z.rs\"\ntest = false\n\n\
             [[example]]\nname = \"f\"\npath = \"examples/f.rs\"\ntest = true\n\n\
             [[bench]]\nname = \"m\"\npath = \"benches/m.rs\"\nharness = false\n",
        ),
    );
    write(root, &format!("{directory}/src/lib.rs"), LIB);
    for bin in ["x", "y", "z"] {
        write(root, &format!("{directory}/src/bin/{bin}.rs"), MAIN);
    }
    for test in ["t", "u"] {
        write(root, &format!("{directory}/tests/{test}.rs"), TEST);
    }
    for example in ["e", "f"] {
        write(root, &format!("{directory}/examples/{example}.rs"), MAIN);
    }
    write(root, &format!("{directory}/benches/m.rs"), MAIN);
}

/// A package with a library, and the binary `x` and the test `t` when it is asked for them.
fn small(root: &Path, directory: &str, name: &str, binary: bool, test: bool) {
    write(
        root,
        &format!("{directory}/Cargo.toml"),
        &manifest(name, ""),
    );
    write(root, &format!("{directory}/src/lib.rs"), LIB);
    if binary {
        write(root, &format!("{directory}/src/bin/x.rs"), MAIN);
    }
    if test {
        write(root, &format!("{directory}/tests/t.rs"), TEST);
    }
}

/// The package `n`: its library is never tested, and it has the binary `x`, the integration tests
/// `t1`, `t2` and `off` (`off` is never tested), the example `e` and the bench `m` that has no harness.
fn names(root: &Path, directory: &str) {
    write(
        root,
        &format!("{directory}/Cargo.toml"),
        &manifest(
            "n",
            "\n[lib]\ntest = false\n\n\
             [[test]]\nname = \"off\"\npath = \"tests/off.rs\"\ntest = false\n\n\
             [[bench]]\nname = \"m\"\npath = \"benches/m.rs\"\nharness = false\n",
        ),
    );
    write(root, &format!("{directory}/src/lib.rs"), LIB);
    write(root, &format!("{directory}/src/bin/x.rs"), MAIN);
    for test in ["t1", "t2", "off"] {
        write(root, &format!("{directory}/tests/{test}.rs"), TEST);
    }
    write(root, &format!("{directory}/examples/e.rs"), MAIN);
    write(root, &format!("{directory}/benches/m.rs"), MAIN);
}

/// The workspaces with the commands each is asked about: a virtual one with `default-members`, a
/// virtual one without, one whose root is a package with two members, and one whose only package has
/// a library that is never tested.
fn fixtures(root: &Path) -> Vec<(&'static str, Vec<Vec<&'static str>>)> {
    for (name, defaults) in [
        (
            "virtual-with-defaults",
            "default-members = [\"a\", \"ab\"]\n",
        ),
        ("virtual-without-defaults", ""),
    ] {
        write(
            root,
            &format!("{name}/Cargo.toml"),
            &format!("[workspace]\nresolver = \"3\"\nmembers = [\"a\", \"ab\", \"b\"]\n{defaults}"),
        );
        rich(root, &format!("{name}/a"), "a");
        small(root, &format!("{name}/ab"), "ab", false, true);
        small(root, &format!("{name}/b"), "b", true, false);
    }
    write(
        root,
        "package-root/Cargo.toml",
        &manifest("r", "\n[workspace]\nmembers = [\"a\", \"ab\"]\n"),
    );
    write(root, "package-root/src/lib.rs", LIB);
    write(root, "package-root/src/bin/x.rs", MAIN);
    write(root, "package-root/tests/t.rs", TEST);
    rich(root, "package-root/a", "a");
    small(root, "package-root/ab", "ab", false, true);
    write(
        root,
        "names/Cargo.toml",
        "[workspace]\nresolver = \"3\"\nmembers = [\"n\"]\n",
    );
    names(root, "names/n");
    vec![
        ("virtual-with-defaults", table()),
        ("virtual-without-defaults", table()),
        ("package-root", table()),
        ("names", names_table()),
    ]
}

fn cargo(directory: &Path, target: &Path, arguments: &[&str]) -> std::process::Output {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .current_dir(directory)
        .args(arguments)
        .env("CARGO_TARGET_DIR", target)
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .output()
        .expect("cargo runs")
}

/// The commands of the table, each as the words after `cargo test`. A command that names a target
/// of the package `a` names the package, because the workspaces differ in what they select when no
/// package is named, and Cargo refuses a name that no selected package holds.
fn table() -> Vec<Vec<&'static str>> {
    [
        "",
        "-p a",
        "-p a*",
        "-p a -p ab",
        "--workspace",
        "--workspace --exclude b",
        "--workspace --exclude a --exclude ab",
        "--exclude a* --workspace",
        "--workspace -p a",
        "--lib",
        "--workspace --lib",
        "--bin x",
        "--lib --bin x",
        "--test t",
        "--workspace --test t",
        "--tests",
        "--all-targets",
        "--bins",
        "--benches",
        "-p a --bin z",
        "-p a --examples",
        "-p a --example e",
        "-p a --example f",
        "-p a --bench m",
        "-p a --all-targets",
        "-p a --tests",
        "-p a --benches",
        "-p a --bins --test u",
        "-p a --lib --example e --bench m",
        "-qp a",
        "-rp a",
        "-qpa -r",
        "-p ab -j -1",
        "--jobs=-1 -p a",
        "-p a --test t*",
        "-p a --test [tu]",
        "-p a --test ?",
        "-p a --bin [xy]",
        "-p a --bin ?",
        "-p a --example ?",
        "-p a --example [!e]",
        "-p a --bench *",
        "-p a --bench **",
        "-p a --bin x --bin [yz]",
        "somename",
        "-p a somename",
    ]
    .iter()
    .map(|line| line.split(' ').filter(|word| !word.is_empty()).collect())
    .collect()
}

/// The commands of the table for the workspace `names`.
fn names_table() -> Vec<Vec<&'static str>> {
    [
        "",
        "-p n",
        "somename",
        "-p n somename",
        "-qp n somename",
        "--lib",
        "--lib somename",
        "--tests",
        "--tests somename",
        "--bins somename",
        "--test t*",
        "--test t?",
        "--test t[12]",
        "--test off",
        "--test [!t]*",
        "--bin ?",
        "--bin [x]",
        "--example e*",
        "--bench *",
        "--bench m",
        "--benches",
        "--all-targets",
        "--all-targets somename",
    ]
    .iter()
    .map(|line| line.split(' ').filter(|word| !word.is_empty()).collect())
    .collect()
}

/// The targets of the test-profile `compiler-artifact` messages of `cargo test --no-run` for `words`.
fn built(
    directory: &Path,
    target: &Path,
    packages: &[kr_conformance::workspace::Package],
    words: &[&str],
) -> BTreeSet<TargetId> {
    let mut arguments = vec!["test", "--locked", "--offline"];
    arguments.extend_from_slice(words);
    arguments.extend(["--no-run", "--message-format=json"]);
    let output = cargo(directory, target, &arguments);
    assert!(
        output.status.success(),
        "cargo test {words:?} in {}: {}",
        directory.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifests: Vec<(PathBuf, &str)> = packages
        .iter()
        .map(|package| {
            (
                package.manifest.canonicalize().expect("a manifest"),
                package.name.as_str(),
            )
        })
        .collect();
    let mut found = BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let manifest = PathBuf::from(message["manifest_path"].as_str().expect("a manifest path"));
        let Some((_, package)) = manifests
            .iter()
            .find(|(held, _)| Some(held) == manifest.canonicalize().ok().as_ref())
        else {
            continue;
        };
        let kinds: Vec<&str> = message["target"]["kind"]
            .as_array()
            .expect("kinds")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        let Some(kind) = TargetKind::from_cargo(&kinds) else {
            continue;
        };
        found.insert(TargetId {
            package: (*package).to_owned(),
            kind,
            name: message["target"]["name"]
                .as_str()
                .expect("a target name")
                .to_owned(),
        });
    }
    found
}

/// For each command of the table, in each workspace, the targets the report says the command covers
/// are the targets Cargo builds to test it: the library and the binaries that a plain command takes,
/// what `default-members` or a root package leaves out, what `--workspace` and `--exclude` change,
/// what each flag that names targets takes and what a manifest's `test = false` and `test = true`
/// do.
#[test]
fn the_targets_a_command_covers_are_the_targets_cargo_builds_for_it() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    let mut wrong = Vec::new();
    let mut commands = 0;
    let mut asked = 0;
    for (name, rows) in fixtures(root) {
        let workspace = root.join(name);
        let target = root.join(format!("target-{name}"));
        let lock = cargo(&workspace, &target, &["generate-lockfile", "--offline"]);
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let read = workspace::read(root, &[format!("{name}/Cargo.toml")]);
        assert!(read.problems.is_empty(), "{name}: {:?}", read.problems);
        let members: Vec<&kr_conformance::workspace::Package> = read.packages.iter().collect();
        asked += rows.len();
        for words in rows {
            let built = built(&workspace, &target, &read.packages, &words);
            let mut command = vec!["cargo".to_owned(), "test".to_owned()];
            command.extend(words.iter().map(|word| (*word).to_owned()));
            let covered = coverage::parse(&command)
                .unwrap_or_else(|why| panic!("{words:?}: {why}"))
                .covers(&members);
            assert!(
                !built.is_empty(),
                "{name}: `{}` built nothing",
                words.join(" ")
            );
            commands += 1;
            if covered != built {
                let show = |set: &BTreeSet<TargetId>| {
                    set.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                wrong.push(format!(
                    "{name}: `cargo test {}`\n    covered: {}\n    built:   {}",
                    words.join(" "),
                    show(&covered),
                    show(&built)
                ));
            }
        }
    }
    assert_eq!(commands, asked);
    assert!(asked > 80, "{asked} commands");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The set a command covers differs between the commands of the table and between the workspaces,
/// so a rule that covers one set for every command cannot pass the case above: the plain command
/// of the workspace with `default-members` leaves `b` out, and that of the workspace without them
/// takes it.
#[test]
fn the_workspaces_of_the_table_select_different_targets_for_one_command() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    let mut plain = Vec::new();
    for (name, _) in fixtures(root).into_iter().take(3) {
        let workspace = root.join(name);
        let target = root.join(format!("target-{name}"));
        let lock = cargo(&workspace, &target, &["generate-lockfile", "--offline"]);
        assert!(
            lock.status.success(),
            "{}",
            String::from_utf8_lossy(&lock.stderr)
        );
        let read = workspace::read(root, &[format!("{name}/Cargo.toml")]);
        let members: Vec<&kr_conformance::workspace::Package> = read.packages.iter().collect();
        let command = ["cargo", "test"].map(str::to_owned);
        let covered = coverage::parse(&command)
            .expect("a command")
            .covers(&members);
        plain.push(
            covered
                .iter()
                .map(|target| target.package.clone())
                .collect::<BTreeSet<_>>(),
        );
    }
    let names = |packages: &[&str]| -> BTreeSet<String> {
        packages.iter().map(|name| (*name).to_owned()).collect()
    };
    assert_eq!(plain[0], names(&["a", "ab"]), "default-members");
    assert_eq!(plain[1], names(&["a", "ab", "b"]), "every member");
    assert_eq!(plain[2], names(&["r"]), "the root package");
}

/// A flag or a pattern the loader refuses is one Cargo refuses too, with `--no-run` as the run adds it,
/// and `-h` and `--help` are the two flags Cargo answers with its help text and no build.
#[test]
fn a_command_the_loader_refuses_for_its_flags_is_one_cargo_refuses_or_answers_with_help() {
    let directory = tempfile::tempdir().expect("a directory");
    let root = directory.path();
    fixtures(root);
    let workspace = root.join("virtual-with-defaults");
    let target = root.join("target-refused");
    let lock = cargo(&workspace, &target, &["generate-lockfile", "--offline"]);
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stderr)
    );
    let run = |line: &str| {
        let mut arguments = vec!["test", "--locked", "--offline"];
        arguments.extend(line.split(' '));
        arguments.extend(["--no-run", "--message-format=json"]);
        cargo(&workspace, &target, &arguments)
    };
    let loader = |line: &str| {
        let mut command = vec!["cargo".to_owned(), "test".to_owned()];
        command.extend(line.split(' ').map(str::to_owned));
        coverage::parse(&command)
    };
    let mut wrong = Vec::new();
    for line in [
        "-p a**",
        "--workspace --exclude a**",
        "--test a**",
        "--test ***",
        "--bin a**b",
        "--example a[b",
        "--timings=html",
        "--doc",
        "--nope",
        "--exclude a",
        "-p a --exclude b",
    ] {
        let output = run(line);
        if output.status.success() {
            wrong.push(format!("`{line}`: Cargo accepts it"));
        }
        if loader(line).is_ok() {
            wrong.push(format!("`{line}`: the loader accepts it"));
        }
    }
    for line in ["-h", "--help"] {
        let output = run(line);
        let shown = String::from_utf8_lossy(&output.stdout);
        if !output.status.success()
            || !shown.contains("Usage:")
            || shown.contains("compiler-artifact")
        {
            wrong.push(format!(
                "`{line}`: Cargo does not answer with its help text"
            ));
        }
        if loader(line).is_ok() {
            wrong.push(format!("`{line}`: the loader accepts it"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
