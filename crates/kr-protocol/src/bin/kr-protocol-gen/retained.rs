//! The retained levels: checking them against this build, and cutting a new one.
//!
//! ```text
//! kr-protocol-gen --retain <level> --commit <full-commit>
//! kr-protocol-gen --release-commit <level> <full-commit>
//! ```
//!
//! `--retain` writes `crates/kr-protocol/retained/<level>/` from the release at `<commit>`: the
//! surface cut from the schema that release committed, its release record, the plugin host
//! protocol it spoke, the table of public majors it listed (`PUBLIC_MAJORS`, where its source has
//! one: a release before the support window kept none) and an empty list of recorded frames. It
//! refuses to overwrite a level. A level that recorded a table is given it in `RETAINED` with
//! `RetainedLevel::with_public_majors`, and `--check` fails until it is.
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
        // A table of public majors the level recorded is built in, and one it did not is absent.
        match (
            retained.public_majors,
            std::fs::read_to_string(directory.join(&level).join("PUBLIC_MAJORS")),
        ) {
            (None, Err(_)) => {}
            (Some(embedded), Ok(on_disk)) if on_disk == embedded => {}
            (Some(_), Ok(_)) => problems.push(format!(
                "{level}/PUBLIC_MAJORS on disk is not the one built in"
            )),
            (None, Ok(_)) => problems.push(format!(
                "{level}/PUBLIC_MAJORS is on disk and the level is built without it (RetainedLevel::with_public_majors)"
            )),
            (Some(_), Err(error)) => problems.push(format!("{level}/PUBLIC_MAJORS: {error}")),
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
    if let Some(table) = public_majors_at(&full)? {
        write("PUBLIC_MAJORS", table)?;
    }
    write("frames.json", "[]\n".to_owned())?;
    println!("wrote {}", target.display());
    Ok(())
}

/// The table of public majors at `commit`, as a retained record, or none where the source there
/// has no table.
fn public_majors_at(commit: &str) -> Result<Option<String>, String> {
    let source = git(&["show", &format!("{commit}:crates/kr-protocol/src/hello.rs")])?;
    render_public_majors(&source)
}

/// Reads the table of public majors out of the source of `hello.rs` and renders it as a record:
/// a line per major (`major=.. versions=.. replaced=.. supported_until=.. retired=..`, a day or `-`)
/// and the digest of the table item's source with its comments and layout taken out. A name or a
/// shape this reader does not know is an error, never a skipped row.
fn render_public_majors(source: &str) -> Result<Option<String>, String> {
    const START: &str = "pub const PUBLIC_MAJORS: &[PublicMajor] = &[";
    let Some(start) = source.find(START) else {
        return Ok(None);
    };
    let inside = start + START.len();
    let Some(length) = closing(&source[inside..], '[', ']') else {
        return Err("the table of public majors does not end".to_owned());
    };
    let body = &source[inside..inside + length];
    let mut record = String::new();
    for row in body.split("PublicMajor {").skip(1) {
        let Some(end) = closing(row, '{', '}') else {
            return Err("a row of the table does not end".to_owned());
        };
        let mut major = None;
        let mut versions = Vec::new();
        let (mut replaced, mut supported_until, mut retired) =
            ("-".to_owned(), "-".to_owned(), None);
        for field in split_top(&row[..end]) {
            let (name, value) = field
                .split_once(':')
                .ok_or_else(|| format!("a field of the table without a name: {field}"))?;
            let value = value.trim();
            match name.trim() {
                "major" => major = Some(value.parse::<u16>().map_err(|e| format!("major: {e}"))?),
                "versions" => {
                    let list = value
                        .strip_prefix("&[")
                        .and_then(|rest| rest.strip_suffix(']'))
                        .ok_or_else(|| format!("versions: {value}"))?;
                    for entry in split_top(list) {
                        versions.push(version_of(source, entry.trim())?);
                    }
                }
                "replaced" => replaced = day_of(value)?,
                "supported_until" => supported_until = day_of(value)?,
                "retired" => retired = Some(value == "true"),
                other => {
                    return Err(format!(
                        "a field of the table this reader does not know: {other}"
                    ));
                }
            }
        }
        record.push_str(&format!(
            "major={} versions={} replaced={replaced} supported_until={supported_until} retired={}\n",
            major.ok_or("a row has no major")?,
            versions.join(","),
            retired.ok_or("a row has no retired")?,
        ));
    }
    let item: String = source[start..inside + length + 1]
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let digest: String = kr_cbor::sha256(item.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    record.push_str(&format!("digest={digest}\n"));
    Ok(Some(record))
}

/// The length of `text` up to the bracket that closes the one before it, `open` and `close` taken
/// in pairs and text between double quotes passed over.
fn closing(text: &str, open: char, close: char) -> Option<usize> {
    let (mut depth, mut quoted) = (0_usize, false);
    for (index, character) in text.char_indices() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            _ if character == open => depth += 1,
            _ if character == close => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

/// `text` split at the commas that are not inside brackets or quotes, empty parts left out.
fn split_top(text: &str) -> Vec<&str> {
    let (mut depth, mut quoted, mut from) = (0_usize, false, 0);
    let mut parts = Vec::new();
    for (index, character) in text.char_indices() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&text[from..index]);
                from = index + 1;
            }
            _ => {}
        }
    }
    parts.push(&text[from..]);
    parts
        .into_iter()
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

/// A version entry of a row: the build's own constant, or `ProtocolVersion::new(major, minor)`.
fn version_of(source: &str, entry: &str) -> Result<String, String> {
    let call = if entry == "PROTOCOL_VERSION" {
        let declaration = "pub const PROTOCOL_VERSION: ProtocolVersion = ";
        let rest = source
            .split(declaration)
            .nth(1)
            .ok_or("PROTOCOL_VERSION is not declared in the source")?;
        rest.split(';').next().unwrap_or_default().trim().to_owned()
    } else {
        entry.to_owned()
    };
    let numbers = call
        .strip_prefix("ProtocolVersion::new(")
        .and_then(|rest| rest.strip_suffix(')'))
        .ok_or_else(|| format!("a version this reader does not know: {entry}"))?;
    let (major, minor) = numbers
        .split_once(',')
        .ok_or_else(|| format!("a version: {entry}"))?;
    Ok(format!("{}.{}", major.trim(), minor.trim()))
}

/// `None` is `-`, and `Some("day")` is the day.
fn day_of(value: &str) -> Result<String, String> {
    if value == "None" {
        return Ok("-".to_owned());
    }
    value
        .strip_prefix("Some(\"")
        .and_then(|rest| rest.strip_suffix("\")"))
        .map(str::to_owned)
        .ok_or_else(|| format!("a day this reader does not know: {value}"))
}

#[cfg(test)]
mod tests {
    use super::render_public_majors;

    /// The table in this tree's own source reads as the one the build has.
    #[test]
    fn this_trees_table_is_read_as_it_is() {
        let record = render_public_majors(include_str!("../../hello.rs"))
            .expect("the source is read")
            .expect("this tree has a table");
        assert!(
            record.starts_with(
                "major=1 versions=1.0 replaced=- supported_until=- retired=false\ndigest="
            ),
            "{record}"
        );
    }

    /// Rows with days, several versions and a retirement are read, the digest ignores comments and
    /// layout, and a shape the reader does not know is an error.
    #[test]
    fn rows_with_days_and_versions_are_read_and_an_unknown_shape_is_refused() {
        let source = "pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(2, 0);\n\
            pub const PUBLIC_MAJORS: &[PublicMajor] = &[\n\
                // the first\n\
                PublicMajor { major: 1, versions: &[ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)],\n\
                    replaced: Some(\"2030-03-01\"), supported_until: Some(\"2031-09-01\"), retired: true },\n\
                PublicMajor { major: 2, versions: &[PROTOCOL_VERSION], replaced: None,\n\
                    supported_until: None, retired: false },\n\
            ];\n";
        let record = render_public_majors(source)
            .expect("read")
            .expect("a table");
        let rows: Vec<&str> = record.lines().filter(|l| l.starts_with("major=")).collect();
        assert_eq!(
            rows,
            [
                "major=1 versions=1.0,1.1 replaced=2030-03-01 supported_until=2031-09-01 retired=true",
                "major=2 versions=2.0 replaced=- supported_until=- retired=false",
            ]
        );
        let reflowed = source.replace("// the first\n", "").replace("\n    ", " ");
        assert_eq!(render_public_majors(&reflowed).unwrap(), Some(record));
        assert!(render_public_majors("fn nothing() {}").unwrap().is_none());
        let unknown = source.replace("retired: false", "retired: false, extra: 1");
        assert!(render_public_majors(&unknown).is_err());
    }
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
