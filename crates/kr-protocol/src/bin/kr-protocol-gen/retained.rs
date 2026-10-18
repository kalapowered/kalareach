//! The retained levels: checking them against this build, and cutting a new one.
//!
//! ```text
//! kr-protocol-gen --retain <level> --commit <full-commit>
//! kr-protocol-gen --release-commit <level> <full-commit>
//! ```
//!
//! `--retain` writes `crates/kr-protocol/retained/<level>/` from the release at `<commit>`: the
//! surface cut from the schema that release committed, its release record, the plugin host
//! protocol it spoke and an empty list of recorded frames. It refuses to overwrite a level.
//! `--release-commit` is for when the release a level was cut from is not the commit its record
//! names: it compares the schema at `<commit>` with the kept surface, refuses on a difference, and
//! only then edits the record.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_protocol::retained::{RETAINED, RETAINED_WORKER_LEVELS, SURFACE_ROOTS, Surface};

/// The directory the retained levels are kept in.
pub fn retained_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("retained")
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git(arguments: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository())
        .output()
        .map_err(|error| format!("git {}: {error}", arguments.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

/// What is wrong with the retained levels as they stand, without comparing them with this build's
/// surface: the directories, the list in the code and the records must agree.
pub fn problems(directory: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let mut kept: Vec<String> = match std::fs::read_dir(directory) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .collect(),
        Err(error) => {
            problems.push(format!("{}: {error}", directory.display()));
            return problems;
        }
    };
    kept.sort();
    let mut listed: Vec<String> = RETAINED_WORKER_LEVELS
        .iter()
        .map(ToString::to_string)
        .collect();
    listed.sort();
    if kept != listed {
        problems.push(format!(
            "the retained directories are {kept:?} and RETAINED_WORKER_LEVELS lists {listed:?}"
        ));
    }
    for retained in &RETAINED {
        let level = retained.level.to_string();
        for (name, embedded) in [
            ("surface.schema.json", retained.surface),
            ("RELEASE", retained.release),
            ("PLUGIN_HOST", retained.plugin_host),
        ] {
            match std::fs::read_to_string(directory.join(&level).join(name)) {
                Ok(on_disk) if on_disk == embedded => {}
                Ok(_) => problems.push(format!("{level}/{name} on disk is not the one built in")),
                Err(error) => problems.push(format!("{level}/{name}: {error}")),
            }
        }
        for name in ["frames.json"] {
            if !directory.join(&level).join(name).is_file() {
                problems.push(format!("{level}/{name} is missing"));
            }
        }
        for field in ["release", "commit", "released", "source"] {
            if retained.record(field).is_none() {
                problems.push(format!("{level}/RELEASE has no {field}"));
            }
        }
        if let Err(error) = Surface::parse(retained.surface) {
            problems.push(format!("{level}/surface.schema.json: {error}"));
        }
    }
    problems
}

/// Cuts a new retained level from the release at `commit`.
pub fn retain(level: &str, commit: &str) -> Result<(), String> {
    let target = retained_dir().join(level);
    if target.exists() {
        return Err(format!(
            "{} exists; a retained level is cut once",
            target.display()
        ));
    }
    let full = git(&["rev-parse", "--verify", &format!("{commit}^{{commit}}")])?
        .trim()
        .to_owned();
    if full != commit {
        return Err(format!("give the full commit: {commit} is {full}"));
    }
    let schema_text = git(&[
        "show",
        &format!("{full}:packages/protocol/schema/kalareach-protocol.schema.json"),
    ])?;
    let schema: serde_json::Value = serde_json::from_str(&schema_text)
        .map_err(|error| format!("the schema at {full}: {error}"))?;
    let surface = Surface::cut(&schema, SURFACE_ROOTS).map_err(|error| error.to_string())?;
    let package = git(&["show", &format!("{full}:packages/protocol/package.json")])?;
    let version = package
        .split("\"version\"")
        .nth(1)
        .and_then(|rest| rest.split('"').nth(1))
        .ok_or("the package manifest states no version")?
        .to_owned();
    if !version.starts_with(&format!("{level}.")) {
        return Err(format!(
            "the release at {full} is {version}, not level {level}"
        ));
    }
    let released = git(&["show", "-s", "--format=%cI", &full])?
        .trim()
        .to_owned();
    std::fs::create_dir_all(&target).map_err(|error| error.to_string())?;
    let write = |name: &str, contents: String| {
        std::fs::write(target.join(name), contents).map_err(|error| format!("{name}: {error}"))
    };
    write("surface.schema.json", surface.render())?;
    write(
        "RELEASE",
        format!(
            "release={version}+{}\ncommit={full}\nreleased={released}\nsource=the committer date of the commit\n",
            &full[..12]
        ),
    )?;
    write("PLUGIN_HOST", format!("{}\n", plugin_host_at(&full)?))?;
    write("frames.json", "[]\n".to_owned())?;
    println!("wrote {}", target.display());
    Ok(())
}

/// The protocol name the plugin host speaks at `commit`, read from that commit's source and not
/// from this build's: where the name is kept moved, and a level records what its own release spoke.
fn plugin_host_at(commit: &str) -> Result<String, String> {
    for (path, declaration) in [
        (
            "crates/kr-protocol/src/retained.rs",
            "pub const PLUGIN_HOST_PROTOCOL: &str = ",
        ),
        (
            "crates/kr-plugin-service/src/protocol.rs",
            "pub const PROTOCOL: &str = ",
        ),
    ] {
        let Ok(source) = git(&["show", &format!("{commit}:{path}")]) else {
            continue;
        };
        if let Some(rest) = source.split(declaration).nth(1)
            && let Some(name) = rest.split('"').nth(1)
        {
            return Ok(name.to_owned());
        }
    }
    Err(format!(
        "the source at {commit} does not state the plugin host protocol"
    ))
}

/// Moves a level's record to the commit the lead names, after comparing that commit's schema with
/// the kept surface.
pub fn release_commit(level: &str, commit: &str) -> Result<(), String> {
    let retained = RETAINED
        .iter()
        .find(|retained| retained.level.to_string() == level)
        .ok_or_else(|| format!("{level} is not a retained level"))?;
    let full = git(&["rev-parse", "--verify", &format!("{commit}^{{commit}}")])?
        .trim()
        .to_owned();
    if full != commit {
        return Err(format!("give the full commit: {commit} is {full}"));
    }
    let schema_text = git(&[
        "show",
        &format!("{full}:packages/protocol/schema/kalareach-protocol.schema.json"),
    ])?;
    let schema: serde_json::Value = serde_json::from_str(&schema_text)
        .map_err(|error| format!("the schema at {full}: {error}"))?;
    let surface = Surface::cut(&schema, SURFACE_ROOTS).map_err(|error| error.to_string())?;
    let found = kr_protocol::retained::differences(retained.surface(), &surface);
    if !found.is_empty() {
        let mut lines = vec![format!(
            "the schema at {full} differs from the surface kept for {level}; rebase onto that release and cut the level again at the rebased commit:"
        )];
        lines.extend(found.iter().map(ToString::to_string));
        return Err(lines.join("\n"));
    }
    let recorded = retained
        .record("commit")
        .ok_or("the record names no commit")?;
    let source_changes = git(&[
        "diff",
        "--stat",
        recorded,
        &full,
        "--",
        "crates/kr-protocol",
        "crates/kr-plugin-service",
        "crates/kr-cbor",
    ])?;
    if !source_changes.trim().is_empty() {
        println!(
            "the source the limits, validators and plugin host name come from changed between the recorded commit and {full}; the kr-cli retained_surface test run with KR_RELEASE_TREE decides whether the records still hold:\n{source_changes}"
        );
    }
    let version = retained
        .record("release")
        .ok_or("the record names no release")?;
    let version = version.split('+').next().unwrap_or(version);
    let released = git(&["show", "-s", "--format=%cI", &full])?
        .trim()
        .to_owned();
    let path = retained_dir().join(level).join("RELEASE");
    std::fs::write(
        &path,
        format!(
            "release={version}+{}\ncommit={full}\nreleased={released}\nsource=the committer date of the commit\n",
            &full[..12]
        ),
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    println!("wrote {}", path.display());
    Ok(())
}
