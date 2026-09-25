//! Whether a built package is this tree's own, by the identity its build named it with.
//!
//! A built package is named by a digest of the inputs it was built from, so the identity an
//! installation's `current` names says which inputs those were. A package is this tree's only when
//! the tree's own inputs are among them. An installation can hold a build of other patches, left
//! there by a build of another tree, and a suite that drove it would report on those patches as
//! though they were this tree's.
//!
//! Some of the inputs are the tree's, and some are the machine's: the compiler, the flags in the
//! build's environment, the Rust toolchain, and for the PowerShell package the host and editor the
//! qualification found. The machine's are taken as the package's own record holds them, never
//! from this process's environment, which need not be the build's: a toolchain named in the
//! environment reaches a test run through `cargo` spelled out in full, and flags can be set for a
//! test run alone. So a correct package never reads as another tree's because of how it was run.
//!
//! `scripts/build-shells.sh` records the exact text it digested, so for the Zsh, Bash and Fish
//! packages the check is that the text digests to the identity, and that every line of it that is
//! the tree's is the line this tree gives; a package whose line differs is reported by that line.
//! `Publish-KalaReachQualification` in `shells/psreadline/module` records every fact of the
//! machine it digested, so for the PowerShell package the text is put together here by its rule,
//! from this tree and those facts, and digested.

use std::path::Path;

use kr_shell_integration::contract::qualification::ShellKind;
use sha2::{Digest as _, Sha256};

use super::repository_root;

/// The lines of a recorded build's inputs that are the tree's, by the names the build gives them.
const TREE_LINES: &[&str] = &[
    "shell", "manifest", "script", "upstream", "env", "patch", "source", "startup",
];

/// The lines that are the machine's, which are taken as recorded.
const MACHINE_LINES: &[&str] = &[
    "cc",
    "cppflags",
    "ldflags",
    "rustc",
    "toolchain",
    "rustflags",
];

/// The line every recorded build's inputs start with, which names the rule.
const RULE: &str = "kr-shell-package/1";

/// Says whether the package of `kind` named `identity`, whose record is `record`, is this tree's.
///
/// # Errors
///
/// Returns why it is not: its record cannot say, or the inputs it names are not this tree's, with
/// the first input that differs.
pub fn this_trees(
    kind: ShellKind,
    identity: &str,
    record: &serde_json::Value,
) -> Result<(), String> {
    let root = repository_root();
    match kind {
        ShellKind::Zsh | ShellKind::Bash | ShellKind::Fish => {
            let recorded = record["build"]["inputs"].as_str().ok_or(
                "its record does not hold the inputs it was built from, so it was built before \
                 the build recorded them",
            )?;
            recorded_build_is_this_trees(&tree_lines(&root, kind)?, identity, recorded)
        }
        ShellKind::PowerShell => {
            let inputs = qualification_inputs(&root, record)?;
            let tree = &hex(&Sha256::digest(inputs.as_bytes()))[..16];
            if tree == identity {
                Ok(())
            } else {
                Err(format!(
                    "this tree's module, manifest and startup entry, with the host and editor its \
                     record names, give {tree}"
                ))
            }
        }
    }
}

/// Checks a recorded build's inputs against the lines this tree gives, in order.
fn recorded_build_is_this_trees(
    tree: &[String],
    identity: &str,
    recorded: &str,
) -> Result<(), String> {
    let digest = hex(&Sha256::digest(recorded.as_bytes()));
    if &digest[..16] != identity {
        return Err(format!(
            "the inputs its record holds digest to {}, which is not its identity",
            &digest[..16]
        ));
    }
    let mut built = Vec::new();
    for line in recorded.lines().filter(|line| !line.is_empty()) {
        let name = line.split_once('=').map_or(line, |(name, _)| name);
        if line == RULE || TREE_LINES.contains(&name) {
            built.push(line);
        } else if !MACHINE_LINES.contains(&name) {
            return Err(format!(
                "its inputs hold {line:?}, which is neither this tree's nor the machine's by the \
                 rule this check knows; if the build's rule changed, restate it here"
            ));
        }
    }
    // The first place the two part names the input that differs: one the tree has and the build
    // did not, one the build had and the tree does not, or one each side has a different copy of.
    for index in 0..built.len().max(tree.len()) {
        let had = built.get(index).copied();
        let gives = tree.get(index).map(String::as_str);
        if had == gives {
            continue;
        }
        return Err(match (had, gives) {
            (Some(had), Some(gives)) if built[index..].contains(&gives) => {
                format!("it was built from {had:?}, which this tree does not have")
            }
            (Some(had), Some(gives)) if tree[index..].iter().any(|line| line == had) => {
                format!("this tree gives {gives:?}, which it was not built from")
            }
            (Some(had), Some(gives)) => {
                format!("it was built from {had:?} where this tree gives {gives:?}")
            }
            (Some(had), None) => {
                format!("it was built from {had:?}, which this tree does not have")
            }
            (None, Some(gives)) => {
                format!("this tree gives {gives:?}, which it was not built from")
            }
            (None, None) => unreachable!("an index past both ends is not visited"),
        });
    }
    Ok(())
}

/// The lines of a build's inputs that are this tree's, in the order `scripts/build-shells.sh`
/// writes them.
fn tree_lines(root: &Path, kind: ShellKind) -> Result<Vec<String>, String> {
    let package = root.join("shells").join(kind.as_str());
    let manifest_path = package.join("manifest.json");
    let manifest = read_json(&manifest_path)?;
    let text = |value: &serde_json::Value, what: &str| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{} names no {what}", manifest_path.display()))
    };
    let mut lines = vec![
        RULE.to_owned(),
        format!("shell={}", text(&manifest["shell"], "shell")?),
        format!("manifest={}", digest_file(&manifest_path)?),
        format!(
            "script={}",
            digest_file(&root.join("scripts").join("build-shells.sh"))?
        ),
        format!(
            "upstream={} {}",
            text(&manifest["upstream"]["sha256"], "upstream digest")?,
            text(&manifest["upstream"]["archive"], "upstream archive")?
        ),
    ];
    // A shell built through CMake is also named by the environment its manifest gives the build.
    if manifest["build_system"].as_str() == Some("cmake") {
        let mut pairs: Vec<String> = manifest["environment"]
            .as_object()
            .map(|pairs| {
                pairs
                    .iter()
                    .map(|(name, value)| format!("{name}={}", value.as_str().unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        pairs.sort();
        lines.push(format!("env={}", pairs.join(" ")));
    }
    for patch in manifest["patches"].as_array().into_iter().flatten() {
        let file = text(&patch["file"], "patch file")?;
        lines.push(format!(
            "patch={} {file}",
            digest_file(&package.join(&file))?
        ));
    }
    for source in manifest["sources"].as_array().into_iter().flatten() {
        let file = text(&source["file"], "source file")?;
        let install = text(&source["install"], "source destination")?;
        lines.push(format!(
            "source={} {install}",
            digest_file(&package.join(&file))?
        ));
    }
    let startup = text(&manifest["startup"]["file"], "startup entry")?;
    lines.push(format!(
        "startup={} {startup}",
        digest_file(&package.join(&startup))?
    ));
    Ok(lines)
}

/// The inputs `Publish-KalaReachQualification` digests for the PowerShell package, in its order.
fn qualification_inputs(root: &Path, record: &serde_json::Value) -> Result<String, String> {
    let package = root.join("shells").join("psreadline");
    let manifest_path = package.join("manifest.json");
    let manifest = read_json(&manifest_path)?;
    let fact = |value: &serde_json::Value, what: &str| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("the package's record names no {what}"))
    };
    let mut lines = vec![
        "kr-shell-package/1".to_owned(),
        format!(
            "shell={}",
            manifest["shell"]
                .as_str()
                .ok_or_else(|| format!("{} names no shell", manifest_path.display()))?
        ),
        format!("manifest={}", digest_file(&manifest_path)?),
    ];
    // The module's own files, as the host lists them: by name, whatever the case, and without the
    // ones it hides.
    let module = package.join("module");
    let mut files: Vec<(String, std::path::PathBuf)> = std::fs::read_dir(&module)
        .map_err(|error| format!("{}: {error}", module.display()))?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| {
            (
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            )
        })
        .filter(|(name, _)| !name.starts_with('.'))
        .collect();
    files.sort_by_key(|(name, _)| name.to_lowercase());
    for (name, path) in &files {
        lines.push(format!("module={} {name}", digest_file(path)?));
    }
    let startup = manifest["startup"]["file"]
        .as_str()
        .ok_or_else(|| format!("{} names no startup entry", manifest_path.display()))?;
    lines.push(format!(
        "startup={} {startup}",
        digest_file(&package.join(startup))?
    ));
    // The host and the editor the qualification found, which are the person's, as the record holds
    // them.
    lines.push(format!(
        "powershell={}",
        fact(&record["shell"]["upstream_version"], "PowerShell version")?
    ));
    lines.push(format!(
        "psreadline={}",
        fact(
            &record["qualified"]["psreadline_found"],
            "PSReadLine version"
        )?
    ));
    lines.push(format!(
        "executable={}",
        fact(
            &record["qualified"]["powershell_executable"],
            "qualified PowerShell host"
        )?
    ));
    Ok(format!("{}\n", lines.join("\n")))
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The Fish package's tree lines, laid out as `scripts/build-shells.sh` lays out a whole record
/// with the machine lines given, and the identity that text digests to.
fn a_fish_build(machine: &[&str]) -> (String, String) {
    let tree = tree_lines(&repository_root(), ShellKind::Fish).expect("this tree's Fish inputs");
    let (head, rest) = tree.split_at(5);
    let text = format!(
        "{}\n{}\n\n{}",
        head.join("\n"),
        machine.join("\n"),
        rest.join("\n")
    );
    let identity = hex(&Sha256::digest(text.as_bytes()))[..16].to_owned();
    (text, identity)
}

/// A build is this tree's by the inputs its record holds, whatever the machine it was built on
/// said: a toolchain named by its short name, and flags this process does not have.
#[test]
fn a_build_is_this_trees_whatever_its_machine_lines_say() {
    for toolchain in ["1.97.1", "1.97.1-x86_64-unknown-linux-gnu", "stable"] {
        let toolchain = format!("toolchain={toolchain}");
        let (text, identity) = a_fish_build(&[
            "cc=cc Apple clang version 21.0.0",
            "cppflags=-DSOMETHING=1",
            "ldflags=",
            "rustc=rustc 1.97.1 (00000000 2026-09-01)",
            &toolchain,
            "rustflags=-C instrument-coverage",
        ]);
        let record = serde_json::json!({"build": {"inputs": text}});
        assert_eq!(
            this_trees(ShellKind::Fish, &identity, &record),
            Ok(()),
            "{toolchain}"
        );
    }
}

/// A build that is not this tree's is named by the input that differs, and a record that cannot
/// say what it was built from is not taken for this tree's.
#[test]
fn a_build_of_other_inputs_is_named_by_the_input_that_differs() {
    let machine = [
        "cc=cc",
        "cppflags=",
        "ldflags=",
        "rustc=rustc",
        "toolchain=t",
        "rustflags=",
    ];
    let (text, identity) = a_fish_build(&machine);
    let patch = text
        .lines()
        .find(|line| line.starts_with("patch="))
        .expect("the Fish package has a patch")
        .to_owned();

    let changed = text.replacen(&patch, &format!("{patch}-older"), 1);
    let changed_identity = hex(&Sha256::digest(changed.as_bytes()))[..16].to_owned();
    let refusal = this_trees(
        ShellKind::Fish,
        &changed_identity,
        &serde_json::json!({"build": {"inputs": changed}}),
    )
    .expect_err("a build of another patch is not this tree's");
    assert!(
        refusal.contains(&patch) && refusal.contains("-older"),
        "{refusal}"
    );

    let without = text.replacen(&format!("{patch}\n"), "", 1);
    let without_identity = hex(&Sha256::digest(without.as_bytes()))[..16].to_owned();
    let refusal = this_trees(
        ShellKind::Fish,
        &without_identity,
        &serde_json::json!({"build": {"inputs": without}}),
    )
    .expect_err("a build without one of this tree's patches is not this tree's");
    assert!(refusal.contains("which it was not built from"), "{refusal}");

    let refusal = this_trees(
        ShellKind::Fish,
        "0000000000000000",
        &serde_json::json!({"build": {"inputs": text}}),
    )
    .expect_err("inputs that are not the identity's are not this build's");
    assert!(refusal.contains("which is not its identity"), "{refusal}");

    let refusal = this_trees(
        ShellKind::Fish,
        &identity,
        &serde_json::json!({"build": {}}),
    )
    .expect_err("a record from before the build recorded its inputs cannot say");
    assert!(
        refusal.contains("built before the build recorded them"),
        "{refusal}"
    );

    let unknown = format!("{text}\nsomething=new");
    let unknown_identity = hex(&Sha256::digest(unknown.as_bytes()))[..16].to_owned();
    let refusal = this_trees(
        ShellKind::Fish,
        &unknown_identity,
        &serde_json::json!({"build": {"inputs": unknown}}),
    )
    .expect_err("an input this check does not know is not taken on trust");
    assert!(refusal.contains("restate it here"), "{refusal}");
}
