//! The identity this tree's inputs give a package, by the rule its own build names it with.
//!
//! A built package is named by a digest of the inputs it was built from, so the identity an
//! installation's `current` names says which inputs those were. A package is this tree's only when
//! that identity is the one this tree's inputs give. An installation can hold a build of other
//! patches, left there by a build of another tree, and a suite that drove it would report on those
//! patches as though they were this tree's.
//!
//! The rule is the build's own, restated here: `scripts/build-shells.sh` for the Zsh, Bash and Fish
//! packages, and `Publish-KalaReachQualification` in `shells/psreadline/module` for the PowerShell
//! package. An input that is a fact of the machine rather than of the tree is taken from the
//! package's own record where the record holds it: the compiler a build used, and the PowerShell
//! host and PSReadLine a qualification found. The rest is read from this process's environment
//! the way the build reads its own: the preprocessor and linker flags, and for a package built
//! through CMake the Rust toolchain and its flags. A build whose rule changes without this module
//! names packages every suite here refuses, and the refusal says so.

use std::path::Path;

use kr_shell_integration::contract::qualification::ShellKind;
use sha2::{Digest as _, Sha256};

use super::repository_root;

/// What this tree's inputs make the identity of the package of `kind` whose record is `record`.
///
/// # Errors
///
/// Returns what could not be read: an input of this tree's, or a fact the record should hold.
pub fn tree_identity(kind: ShellKind, record: &serde_json::Value) -> Result<String, String> {
    let root = repository_root();
    let inputs = match kind {
        ShellKind::Zsh | ShellKind::Bash | ShellKind::Fish => build_inputs(&root, kind, record)?,
        ShellKind::PowerShell => qualification_inputs(&root, record)?,
    };
    Ok(hex(&Sha256::digest(inputs.as_bytes()))[..16].to_owned())
}

/// The inputs `scripts/build-shells.sh` digests for a package it builds, in its order and with its
/// separators.
fn build_inputs(
    root: &Path,
    kind: ShellKind,
    record: &serde_json::Value,
) -> Result<String, String> {
    let package = root.join("shells").join(kind.as_str());
    let manifest_path = package.join("manifest.json");
    let manifest = read_json(&manifest_path)?;
    let text = |value: &serde_json::Value, what: &str| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("{} names no {what}", manifest_path.display()))
    };
    // The compiler the build used, which its record holds as the build wrote it into the inputs.
    let compiler = record["build"]["toolchain"]
        .as_str()
        .ok_or("the package's record names no toolchain")?;
    let mut inputs = format!(
        "kr-shell-package/1\nshell={}\nmanifest={}\nscript={}\nupstream={} {}\ncc={compiler}\n\
         cppflags={}\nldflags={}\n",
        text(&manifest["shell"], "shell")?,
        digest_file(&manifest_path)?,
        digest_file(&root.join("scripts").join("build-shells.sh"))?,
        text(&manifest["upstream"]["sha256"], "upstream digest")?,
        text(&manifest["upstream"]["archive"], "upstream archive")?,
        variable("CPPFLAGS"),
        variable("LDFLAGS"),
    );
    if manifest["build_system"].as_str() == Some("cmake") {
        // A shell whose own source is Rust is named by that toolchain as well, which the build
        // pins by the name the repository's own toolchain file resolves to.
        // `cut -d' ' -f1` on each line of what rustup shows, as the build takes it.
        let toolchain = std::env::var("RUSTUP_TOOLCHAIN")
            .ok()
            .filter(|name| !name.is_empty())
            .or_else(|| {
                output(root, "rustup", &["show", "active-toolchain"], None).map(|shown| {
                    shown
                        .lines()
                        .map(|line| line.split(' ').next().unwrap_or_default())
                        .collect::<Vec<_>>()
                        .join("\n")
                })
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "stable".to_owned());
        let rustc = output(root, "rustc", &["--version"], Some(&toolchain)).unwrap_or_default();
        let environment = manifest["environment"]
            .as_object()
            .map(|pairs| {
                let mut pairs: Vec<String> = pairs
                    .iter()
                    .map(|(name, value)| format!("{name}={}", value.as_str().unwrap_or_default()))
                    .collect();
                pairs.sort();
                pairs.join(" ")
            })
            .unwrap_or_default();
        inputs.push_str(&format!(
            "\nrustc={rustc}\ntoolchain={toolchain}\nrustflags={}\nenv={environment}\n",
            variable("RUSTFLAGS")
        ));
    }
    for patch in manifest["patches"].as_array().into_iter().flatten() {
        let file = text(&patch["file"], "patch file")?;
        inputs.push_str(&format!(
            "\npatch={} {file}",
            digest_file(&package.join(&file))?
        ));
    }
    for source in manifest["sources"].as_array().into_iter().flatten() {
        let file = text(&source["file"], "source file")?;
        let install = text(&source["install"], "source destination")?;
        inputs.push_str(&format!(
            "\nsource={} {install}",
            digest_file(&package.join(&file))?
        ));
    }
    let startup = text(&manifest["startup"]["file"], "startup entry")?;
    inputs.push_str(&format!(
        "\nstartup={} {startup}",
        digest_file(&package.join(&startup))?
    ));
    Ok(inputs)
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

/// A variable the build reads with an empty default.
fn variable(name: &str) -> String {
    std::env::var(name).unwrap_or_default()
}

/// What a program prints, as a command substitution takes it, run in the repository's own root as
/// the build is, and under `toolchain` where one is named.
fn output(
    root: &Path,
    program: &str,
    arguments: &[&str],
    toolchain: Option<&str>,
) -> Option<String> {
    let mut command = std::process::Command::new(program);
    command
        .args(arguments)
        .current_dir(root)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(toolchain) = toolchain {
        command.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    let finished = command.output().ok()?;
    Some(
        String::from_utf8_lossy(&finished.stdout)
            .trim_end_matches('\n')
            .to_owned(),
    )
}
