//! The run's identities: what was tested, with what, where.
//!
//! Section 29 asks for results "with exact version/profile identities". Each identity is read from
//! the thing itself at run time, and one that cannot be read is recorded as unknown rather than
//! guessed.

use std::path::Path;
use std::process::Command;

use serde::Serialize;
use serde_json::Value;

/// The commit the run tested.
#[derive(Clone, Debug, Serialize)]
pub struct Commit {
    /// Its full identifier, or `unknown`.
    pub id: String,
    /// Whether tracked files differed from it.
    pub modified: bool,
}

/// The toolchain.
#[derive(Clone, Debug, Serialize)]
pub struct Toolchain {
    /// `rustc --version`.
    pub rustc: String,
    /// `cargo --version`.
    pub cargo: String,
    /// `node --version`, where the TypeScript group ran.
    pub node: Option<String>,
    /// `pnpm --version`, where the TypeScript group ran.
    pub pnpm: Option<String>,
}

/// The machine.
#[derive(Clone, Debug, Serialize)]
pub struct System {
    /// `linux`, `macos` or `windows`.
    pub os: String,
    /// The release the system reports.
    pub release: String,
    /// The processor architecture.
    pub arch: String,
    /// The target triple the toolchain builds for here.
    pub target: String,
}

/// A package and its version.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PackageVersion {
    /// Its name.
    pub name: String,
    /// Its version.
    pub version: String,
}

/// The terminal profile the host presents, as its committed fixture states it.
#[derive(Clone, Debug, Serialize)]
pub struct TerminalProfile {
    /// The profile's name and revision.
    pub profile: String,
    /// The `TERM` a session is given.
    pub term: String,
}

fn output(program: &str, arguments: &[&str], directory: &Path) -> Option<String> {
    let output = Command::new(program)
        .args(arguments)
        .current_dir(directory)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
}

/// The commit at `root`.
#[must_use]
pub fn commit(root: &Path) -> Commit {
    Commit {
        id: output("git", &["rev-parse", "HEAD"], root).unwrap_or_else(|| "unknown".to_owned()),
        modified: output(
            "git",
            &["status", "--porcelain", "--untracked-files=no"],
            root,
        )
        .is_some(),
    }
}

/// The toolchain, with Node and pnpm when `typescript` says the run used them.
#[must_use]
pub fn toolchain(root: &Path, typescript: bool) -> Toolchain {
    let unknown = || "unknown".to_owned();
    Toolchain {
        rustc: output("rustc", &["--version"], root).unwrap_or_else(unknown),
        cargo: output("cargo", &["--version"], root).unwrap_or_else(unknown),
        node: typescript
            .then(|| output("node", &["--version"], root))
            .flatten(),
        pnpm: typescript
            .then(|| output("pnpm", &["--version"], root))
            .flatten(),
    }
}

/// The machine.
#[must_use]
pub fn system(root: &Path) -> System {
    let release = if cfg!(target_os = "macos") {
        output("sw_vers", &["-productVersion"], root).map(|version| format!("macOS {version}"))
    } else if cfg!(target_os = "linux") {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|text| {
                text.lines()
                    .find_map(|line| line.strip_prefix("PRETTY_NAME="))
                    .map(|name| name.trim_matches('"').to_owned())
            })
    } else {
        output("cmd", &["/C", "ver"], root)
    };
    let kernel = if cfg!(unix) {
        output("uname", &["-sr"], root)
    } else {
        None
    };
    let release = match (release, kernel) {
        (Some(release), Some(kernel)) => format!("{release}, {kernel}"),
        (Some(release), None) => release,
        (None, Some(kernel)) => kernel,
        (None, None) => "unknown".to_owned(),
    };
    let target = output("rustc", &["-vV"], root)
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("host: "))
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "unknown".to_owned());
    System {
        os: std::env::consts::OS.to_owned(),
        release,
        arch: std::env::consts::ARCH.to_owned(),
        target,
    }
}

/// The terminal profile, from its committed fixture.
#[must_use]
pub fn terminal_profile(root: &Path) -> TerminalProfile {
    let value: Value = std::fs::read_to_string(root.join("fixtures/terminal/profile.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or(Value::Null);
    let read = |field: &str| value[field].as_str().unwrap_or("unknown").to_owned();
    TerminalProfile {
        profile: read("profile"),
        term: read("term"),
    }
}

/// The versions of the TypeScript packages in `directories`.
#[must_use]
pub fn typescript_packages(root: &Path, directories: &[&str]) -> Vec<PackageVersion> {
    directories
        .iter()
        .filter_map(|directory| {
            let text = std::fs::read_to_string(root.join(directory).join("package.json")).ok()?;
            let value: Value = serde_json::from_str(&text).ok()?;
            Some(PackageVersion {
                name: value["name"].as_str()?.to_owned(),
                version: value["version"].as_str()?.to_owned(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_is_named_by_what_it_reports() {
        let system = system(Path::new("."));
        assert_eq!(system.os, std::env::consts::OS);
        assert!(!system.target.is_empty());
    }
}
