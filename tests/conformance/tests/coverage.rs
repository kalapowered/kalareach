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

/// The workspace `variants`: `p` has features, targets that need them, a dev-dependency on itself,
/// and targets with a `bench` key, written as TOML allows (single quotes, a spaced header, a quoted
/// key); `r` has a dev-dependency on itself that leaves its default
/// features off; `q` has no feature.
fn variants(root: &Path, directory: &str) {
    write(
        root,
        &format!("{directory}/Cargo.toml"),
        "[workspace]\nresolver = \"3\"\nmembers = [\"p\", \"q\", \"r\"]\n",
    );
    write(
        root,
        &format!("{directory}/p/Cargo.toml"),
        &manifest(
            "p",
            "\n[features]\ndefault = [\"d\"]\nd = []\nf = []\ng = [\"f\"]\ns = []\n\n\
             [dev-dependencies]\np = { path = \".\", features = [\"s\"] }\n\n\
             [[bin]]\nname = \"y\"\npath = \"src/bin/y.rs\"\nbench = false\n\n\
             [[test]]\nname = \"off\"\npath = \"tests/off.rs\"\ntest = false\n\n\
             [[test]]\nname = \"needf\"\npath = \"tests/needf.rs\"\nrequired-features = [\"f\"]\n\n\
             [[test]]\nname = \"needs\"\npath = \"tests/needs.rs\"\nrequired-features = [\"s\"]\n\n\
             [[test]]\nname = \"needd\"\npath = \"tests/needd.rs\"\nrequired-features = [\"d\"]\n\n\
             [[test]]\nname = \"needg\"\npath = \"tests/needg.rs\"\nrequired-features = [\"g\"]\n\n\
             [[test]]\nname = \"v\"\npath = \"tests/v.rs\"\ntest = false\nbench = true\n\n\
             [[test]]\nname = \"w\"\npath = \"tests/w.rs\"\nbench = true\n\n\
             [[test]]\nname = 'sq'\npath = 'tests/sq.rs'\nbench = true\n\n\
             [[ test ]]\nname = \"sp\"\npath = \"tests/sp.rs\"\nbench = true\n\n\
             [[test]]\nname = \"qk\"\npath = \"tests/qk.rs\"\n\"bench\" = true\n\n\
             [[bench]]\nname = \"m\"\npath = \"benches/m.rs\"\nharness = false\n\n\
             [[bench]]\nname = \"nb\"\npath = \"benches/nb.rs\"\nharness = false\nbench = false\n\n\
             [[example]]\nname = \"g\"\npath = \"examples/g.rs\"\nbench = true\n",
        ),
    );
    write(root, &format!("{directory}/p/src/lib.rs"), LIB);
    write(root, &format!("{directory}/p/src/bin/x.rs"), MAIN);
    write(root, &format!("{directory}/p/src/bin/y.rs"), MAIN);
    for test in [
        "t1", "off", "needf", "needs", "needd", "needg", "v", "w", "sq", "sp", "qk",
    ] {
        write(root, &format!("{directory}/p/tests/{test}.rs"), TEST);
    }
    for bench in ["m", "nb"] {
        write(root, &format!("{directory}/p/benches/{bench}.rs"), MAIN);
    }
    write(root, &format!("{directory}/p/examples/g.rs"), MAIN);
    write(
        root,
        &format!("{directory}/r/Cargo.toml"),
        &manifest(
            "r",
            "\n[features]\ndefault = [\"d\"]\nd = []\ns = []\n\n\
             [dev-dependencies]\nr = { path = \".\", default-features = false, features = [\"s\"] }\n\n\
             [[test]]\nname = \"rd\"\npath = \"tests/rd.rs\"\nrequired-features = [\"d\"]\n\n\
             [[test]]\nname = \"rs\"\npath = \"tests/rs.rs\"\nrequired-features = [\"s\"]\n",
        ),
    );
    write(root, &format!("{directory}/r/src/lib.rs"), LIB);
    for test in ["rd", "rs"] {
        write(root, &format!("{directory}/r/tests/{test}.rs"), TEST);
    }
    small(root, &format!("{directory}/q"), "q", false, true);
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
    variants(root, "variants");
    vec![
        ("virtual-with-defaults", table()),
        ("virtual-without-defaults", table()),
        ("package-root", table()),
        ("names", names_table()),
        ("variants", variants_table()),
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

/// The commands of the table for the workspace `variants`: the features a command turns on, the
/// targets that need them, and the `bench` key.
fn variants_table() -> Vec<Vec<&'static str>> {
    [
        "",
        "-p p",
        "-p p --features f",
        "-p p -F g",
        "-p p --features p/f",
        "-p p --features d",
        "-p p --features f,s",
        "-p p --features f\tg",
        "-p p --features f\ng",
        "-p p -F f\t\ts",
        "-p p --features=",
        "-p p -F=",
        "-p p -F= f",
        "-p p -F= --no-default-features",
        "-p p --features= -F g",
        "-p p --all-features",
        "-p p --no-default-features",
        "-p p --no-default-features --features f",
        "-p p --test off",
        "-p p --test needf --features f",
        "-p p --test need* --all-features",
        "-p p --test needg --features g",
        "-p p --tests",
        "-p p --tests --features f",
        "-p p --benches",
        "-p p --benches --features f",
        "-p p --all-targets",
        "-p p --all-targets --all-features",
        "-p p --bench nb",
        "-p p --bench m",
        "-p p --all-targets --test off",
        "-p p --all-targets --bench nb",
        "-p p --test off --all-targets",
        "-p p --all-targets --bin y --example g",
        "-p p --all-targets --test ***",
        "-p p --example g",
        "-p p --examples",
        "-p p --bins",
        "-p p --bin y",
        "-p p somename",
        "-p p somename --features g",
        "-p r",
        "-p r --no-default-features",
        "-p r --all-features",
        "-p r --test rs",
        "--features f",
        "--workspace --features p/f",
        "--features s",
        "--all-features",
        "--no-default-features",
        "--benches",
        "--all-targets",
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
        "--test **/t1",
        "--test **/t*",
        "--test **/**/t1",
        "--test **/t?",
        "--test **",
        "--tests --test ***",
        "--test *** --tests",
        "--test a** --tests --test t1",
        "--bins --bin ***",
        "--benches --bench **x",
        "--bin ?",
        "--bin [x]",
        "--bin **/x",
        "--example e*",
        "--example ?",
        "--example **/e",
        "--bench *",
        "--bench ?",
        "--bench [m]",
        "--bench **/m",
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
            commands += 1;
            let built = built(&workspace, &target, &read.packages, &words);
            let mut command = vec!["cargo".to_owned(), "test".to_owned()];
            command.extend(words.iter().map(|word| (*word).to_owned()));
            assert!(
                !built.is_empty(),
                "{name}: `{}` built nothing",
                words.join(" ")
            );
            let covered = match coverage::parse(&command) {
                Ok(selection) => selection.covers(&members),
                Err(why) => {
                    wrong.push(format!(
                        "{name}: `cargo test {}` is refused, and Cargo builds it: {why}",
                        words.join(" ")
                    ));
                    continue;
                }
            };
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
        "--test **x",
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
