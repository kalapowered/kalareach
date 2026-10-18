//! The retained levels: checking them against this build, and cutting a new one.
//!
//! ```text
//! kr-protocol-gen --retain <level> --commit <full-commit>
//! kr-protocol-gen --release-commit <level> <full-commit>
//! ```
//!
//! `--retain` writes `crates/kr-protocol/retained/<level>/` from the release at `<commit>`: the
//! surface cut from the schema that release committed, its release record, the plugin host
//! protocol it spoke, the table of public majors it listed (`PUBLIC_MAJORS`: the table its source
//! has, or for a release before the support window the one major it negotiated) and an empty list
//! of recorded frames. It refuses to overwrite a level. The record is given to `RETAINED` with
//! `RetainedLevel::with_public_majors`, and `--check` fails until it is.
//! `--release-commit` is for when the release a level was cut from is not the commit its record
//! names: it compares the schema at `<commit>` with the kept surface, refuses on a difference, and
//! only then edits the record. The commit has to be the release before this one, the newest
//! release tagged in this checkout's history below its level, and `--predecessor` prints that
//! release and fails unless its level is the newest retained.

use std::path::{Path, PathBuf};

use kr_protocol::retained::{RETAINED, RETAINED_WORKER_LEVELS, SURFACE_ROOTS, Surface};

use crate::{predecessor, public_majors};

/// The directory the retained levels are kept in.
pub fn retained_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("retained")
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn git(arguments: &[&str]) -> Result<String, String> {
    predecessor::git_in(&repository(), arguments)
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
        // Every level records the table its release listed, and the record is built in.
        match (
            retained.public_majors,
            std::fs::read_to_string(directory.join(&level).join("PUBLIC_MAJORS")),
        ) {
            (Some(embedded), Ok(on_disk)) if on_disk == embedded => {
                // From the first release that listed a table on, the record is the table's own,
                // with the digest of its source, and not the one major of a release without one.
                if retained.level >= kr_protocol::update::CompatibilityLevel::of(
                    kr_protocol::hello::PackageVersion::new(0, 75, 0),
                ) && !embedded.contains("digest=")
                {
                    problems.push(format!("{level}/PUBLIC_MAJORS has no digest of the table's source"));
                }
            }
            (Some(_), Ok(_)) => problems.push(format!(
                "{level}/PUBLIC_MAJORS on disk is not the one built in"
            )),
            (None, _) => problems.push(format!(
                "{level} is built without its table of public majors (RetainedLevel::with_public_majors)"
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
    // Everything read from the release is read before anything is written, so a source this tool
    // cannot read leaves no half-cut level behind.
    let plugin_host = plugin_host_at(&full)?;
    let public_majors = expected_public_majors_at(&full)?;
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
    write("PLUGIN_HOST", format!("{plugin_host}\n"))?;
    write("PUBLIC_MAJORS", public_majors)?;
    write("frames.json", "[]\n".to_owned())?;
    println!("wrote {}", target.display());
    Ok(())
}

/// The record of the table of public majors a release listed, read from its source at `commit`:
/// the table's own, or for a release whose source has none, the one major it negotiated.
pub fn expected_public_majors_at(commit: &str) -> Result<String, String> {
    let source = git(&["show", &format!("{commit}:crates/kr-protocol/src/hello.rs")])?;
    let context = |error: String| format!("the table of public majors at {commit}: {error}");
    match public_majors::record_of(&source).map_err(context)? {
        Some(record) => Ok(record),
        None => public_majors::record_without_a_table(&source).map_err(context),
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

/// The level and full commit of the release before this one, as one line of text. It fails unless
/// that release's level is the newest this build retains.
pub fn release_before() -> Result<String, String> {
    let release = predecessor::before(&repository(), "HEAD")?;
    predecessor::is_the_newest_retained(&release, &RETAINED_WORKER_LEVELS)?;
    Ok(format!("{} {}", release.level(), release.commit))
}

/// Moves a level's record to the release before this one, after comparing that release's schema,
/// table of public majors and sources with the kept ones. `commit` has to be that release: the
/// newest tagged below this checkout's level, which is the level's last release.
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
    let before = predecessor::before(&repository(), "HEAD")?;
    if before.commit != full || before.level() != retained.level {
        return Err(format!(
            "{full} is not the release before this one at level {level}: that is {} at {}",
            before.tag, before.commit
        ));
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
    // The table of public majors the level recorded is the one in the tree of the release it is
    // moved to, whole, digest included.
    let found = expected_public_majors_at(&full)?;
    if retained.public_majors != Some(found.as_str()) {
        return Err(format!(
            "the table of public majors at {full} is not the one recorded for {level}; rebase onto \
             that release and cut the level again at the rebased commit.\nrecorded: {}\nat the \
             commit: {found}",
            retained.public_majors.unwrap_or("none"),
        ));
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
    let version = before.version;
    let released = git(&["show", "-s", "--format=%cI", &full])?
        .trim()
        .to_owned();
    // The document is prepared first: a document without the level's row stops the command
    // before the record changes.
    let release = format!("{version}+{}", &full[..12]);
    let (document, text) = document_with(level, &release, &released)?;
    let path = retained_dir().join(level).join("RELEASE");
    std::fs::write(
        &path,
        format!(
            "release={release}\ncommit={full}\nreleased={released}\nsource=the committer date of the commit\n",
        ),
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    println!("wrote {}", path.display());
    std::fs::write(&document, text).map_err(|error| format!("{}: {error}", document.display()))?;
    println!("wrote {}", document.display());
    Ok(())
}

/// The document on the support window with the row of `level` given its release and the day it was
/// built, which the document's test holds equal to the records; and where it is.
fn document_with(level: &str, release: &str, released: &str) -> Result<(PathBuf, String), String> {
    let path = repository().join("docs/releases/support-window.md");
    let text =
        std::fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let begin = "<!-- retained-levels:begin -->\n";
    let end = "<!-- retained-levels:end -->";
    let (Some(from), Some(to)) = (text.find(begin), text.find(end)) else {
        return Err(format!(
            "{} has no block of retained levels",
            path.display()
        ));
    };
    let from = from + begin.len();
    let row = format!("| {level} |");
    let mut changed = false;
    let block: String = text[from..to]
        .lines()
        .map(|line| {
            if line.starts_with(&row) {
                changed = true;
                format!("| {level} | {release} | {released} |\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect();
    if !changed {
        return Err(format!("{} has no row for level {level}", path.display()));
    }
    Ok((path, format!("{}{block}{}", &text[..from], &text[to..])))
}

#[cfg(test)]
mod tests {
    use crate::public_majors::record_of;

    const TWO_ROWS: &str = r#"pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(2, 0);
pub const PUBLIC_MAJORS: &[PublicMajor] = &[
    // the first
    PublicMajor {
        major: 1,
        versions: &[ProtocolVersion::new(1, 0), ProtocolVersion::new(1, 1)],
        replaced: Some("2030-03-01"),
        supported_until: Some("2031-09-01"),
        retired: true,
    },
    PublicMajor {
        major: 2,
        versions: &[PROTOCOL_VERSION],
        replaced: None, // none yet
        supported_until: None,
        retired: false,
    },
];
"#;

    /// The table in this tree's own source reads as the one the build has.
    #[test]
    fn this_trees_table_is_read_as_it_is() {
        let record = record_of(include_str!("../../hello.rs"))
            .expect("the source is read")
            .expect("this tree has a table");
        assert!(
            record.starts_with(
                "major=1 versions=1.0 replaced=- supported_until=- retired=false\ndigest="
            ),
            "{record}"
        );
    }

    /// Rows with days, several versions, a constant and a retirement are read; the digest is the
    /// same whatever the comments and layout, and moves with a row.
    #[test]
    fn rows_are_read_and_the_digest_ignores_comments_and_layout() {
        let record = record_of(TWO_ROWS).expect("read").expect("a table");
        let rows: Vec<&str> = record.lines().filter(|l| l.starts_with("major=")).collect();
        assert_eq!(
            rows,
            [
                "major=1 versions=1.0,1.1 replaced=2030-03-01 supported_until=2031-09-01 retired=true",
                "major=2 versions=2.0 replaced=- supported_until=- retired=false",
            ]
        );
        let reflowed = TWO_ROWS
            .replace("    // the first\n", "")
            .replace(" // none yet", "")
            .replace("\n        ", " ");
        assert_eq!(record_of(&reflowed).unwrap(), Some(record.clone()));
        let moved = TWO_ROWS.replace("2031-09-01", "2031-09-02");
        assert_ne!(record_of(&moved).unwrap(), Some(record));
    }

    /// A release before the support window lists one major, from the protocol version it
    /// implements, and its record says so.
    #[test]
    fn a_release_without_a_table_is_recorded_as_the_one_major_it_negotiated() {
        let source = "// the version\npub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);\n";
        assert_eq!(record_of(source), Ok(None));
        assert_eq!(
            crate::public_majors::record_without_a_table(source).as_deref(),
            Ok("major=1 versions=1.0 replaced=- supported_until=- retired=false\n")
        );
        assert!(crate::public_majors::record_without_a_table("fn nothing() {}").is_err());
    }

    /// A source with no table is no table, and every other shape is refused: a different
    /// declaration, an entry that is not a literal, a value that is not a literal, a field twice or
    /// unknown, and a table followed by more code.
    #[test]
    fn a_shape_the_reader_does_not_know_is_refused_and_a_source_without_a_table_is_not_one() {
        assert_eq!(record_of("fn nothing() {}"), Ok(None));
        let named_entry = TWO_ROWS.replace(
            "    PublicMajor {\n        major: 2",
            "    OLD,\n    PublicMajor {\n        major: 2",
        );
        for (what, source) in [
            (
                "another declaration",
                TWO_ROWS.replace("pub const", "pub static"),
            ),
            (
                "the type spelled otherwise",
                TWO_ROWS.replace("&[PublicMajor]", "&'static [PublicMajor]"),
            ),
            ("a named entry", named_entry),
            (
                "a negated retired",
                TWO_ROWS.replace("retired: false", "retired: !false"),
            ),
            (
                "a named retired",
                TWO_ROWS.replace("retired: false", "retired: LATER"),
            ),
            (
                "a named version",
                TWO_ROWS.replace(
                    "ProtocolVersion::new(1, 1)",
                    "ProtocolVersion::new(1, MINOR)",
                ),
            ),
            (
                "a day that is not a day",
                TWO_ROWS.replace("2030-03-01", "March 2030"),
            ),
            (
                "an unknown field",
                TWO_ROWS.replace("retired: false", "retired: false, extra: 1"),
            ),
            (
                "a field twice",
                TWO_ROWS.replace("retired: false", "retired: false, retired: true"),
            ),
            (
                "a missing field",
                TWO_ROWS.replace("        retired: false,\n", ""),
            ),
            ("a major twice", TWO_ROWS.replace("major: 2", "major: 1")),
            ("text after the table", TWO_ROWS.replace("];", "].len();")),
        ] {
            assert!(record_of(&source).is_err(), "{what} is refused: {source}");
        }
        // A block comment is a comment, nested ones included.
        let block = TWO_ROWS.replace("// the first", "/* the /* first */ row */");
        assert_eq!(record_of(&block), record_of(TWO_ROWS));
        // A bracket or a declaration inside a comment is neither the end of the table nor a table.
        let bracket = TWO_ROWS.replace(
            "    PublicMajor {\n        major: 2",
            "    // ];\n    PublicMajor {\n        major: 2",
        );
        assert_eq!(
            record_of(&bracket),
            record_of(TWO_ROWS),
            "a comment holding `];` ends nothing"
        );
        let older = format!("// pub const PUBLIC_MAJORS: &[PublicMajor] = &[];\n{TWO_ROWS}");
        assert_eq!(
            record_of(&older),
            record_of(TWO_ROWS),
            "a commented declaration is not the table"
        );
        let twice = format!("{TWO_ROWS}{TWO_ROWS}");
        assert!(record_of(&twice).is_err(), "two declarations are refused");
        // A declaration a string holds is not a declaration, and a quote in a character literal does
        // not open a string.
        let example = format!(
            "const EXAMPLE: &str = \"pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(9, 0);\";\nconst QUOTE: u8 = b'\"';\nconst PATH: &str = \"// not a comment\";\n{TWO_ROWS}"
        );
        assert_eq!(record_of(&example), record_of(TWO_ROWS));
        let version = "const EXAMPLE: &str = \"pub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(9, 0);\";\npub const PROTOCOL_VERSION: ProtocolVersion = ProtocolVersion::new(1, 0);\n";
        assert_eq!(
            crate::public_majors::record_without_a_table(version).as_deref(),
            Ok("major=1 versions=1.0 replaced=- supported_until=- retired=false\n")
        );
        // A comment that only looks like a row is not one, and does not move the digest.
        let commented = TWO_ROWS.replace(
            "// the first",
            "// PublicMajor { major: 9, versions: &[], replaced: None, supported_until: None, retired: false },",
        );
        assert_eq!(record_of(&commented), record_of(TWO_ROWS));
    }
}
