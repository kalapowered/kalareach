//! The figures the performance tests record under `KR_TEST_ARTIFACTS_DIR`, and the rule for where
//! that directory may be.
//!
//! A measurement writes a Markdown section for each figure it takes, headed by the identifier it
//! measures (`## <identifier> <what>`), with the host, the figure and the verdict as indented lines,
//! and it writes that before it asserts anything, so a run the target failed keeps the number. The
//! report reads only what a file gained during this run, so a directory kept from an earlier run
//! lends it no figures.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::id::{self, Identifier};

/// One figure a measurement recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Figure {
    /// The file it is in, relative to the evidence directory.
    pub file: String,
    /// The section's heading, without its marker.
    pub measurement: String,
    /// The section's lines, trimmed.
    pub lines: Vec<String>,
}

/// How long each file of the evidence directory is, before a run.
#[derive(Clone, Debug, Default)]
pub struct Before {
    lengths: BTreeMap<PathBuf, u64>,
}

/// Records what the evidence directory holds before the run.
#[must_use]
pub fn before(directory: &Path) -> Before {
    let mut lengths = BTreeMap::new();
    if let Ok(entries) = std::fs::read_dir(directory) {
        for entry in entries.flatten() {
            if let Ok(metadata) = entry.metadata()
                && metadata.is_file()
            {
                lengths.insert(entry.path(), metadata.len());
            }
        }
    }
    Before { lengths }
}

/// The figures the Markdown files of `directory` gained since `before`, by identifier.
#[must_use]
pub fn figures(directory: &Path, before: &Before) -> BTreeMap<Identifier, Vec<Figure>> {
    let mut found: BTreeMap<Identifier, Vec<Figure>> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "md"))
        .collect();
    paths.sort();
    for path in paths {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let from = before.lengths.get(&path).copied().unwrap_or(0);
        let from = usize::try_from(from).unwrap_or(usize::MAX).min(bytes.len());
        let text = String::from_utf8_lossy(&bytes[from..]);
        let file = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        for (identifier, figure) in sections(&text, &file) {
            found.entry(identifier).or_default().push(figure);
        }
    }
    found
}

/// The sections of a record, each with the identifier its heading starts with.
fn sections(text: &str, file: &str) -> Vec<(Identifier, Figure)> {
    let mut found = Vec::new();
    let mut current: Option<(Identifier, Figure)> = None;
    for line in text.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            found.extend(current.take());
            let first = id::scan(heading).into_iter().next();
            if let Some(mention) = first.filter(|mention| mention.at == 0)
                && let Ok(identifier) = mention.read
            {
                current = Some((
                    identifier,
                    Figure {
                        file: file.to_owned(),
                        measurement: heading.trim().to_owned(),
                        lines: Vec::new(),
                    },
                ));
            }
        } else if let Some((_, figure)) = current.as_mut()
            && !line.trim().is_empty()
        {
            figure.lines.push(line.trim().to_owned());
        }
    }
    found.extend(current);
    found
}

/// A known difference between an application and the profile, as a case recorded it: what the
/// case is about, how the application reads it, how the grid does, and what the grid showed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct KnownDifference {
    /// The package whose test recorded it.
    pub package: String,
    /// That test's target.
    pub target: String,
    /// That test.
    pub test: String,
    /// What the difference is about.
    pub subject: String,
    /// How the application reads it.
    pub application: String,
    /// How the grid does, as the profile defines it.
    pub grid: String,
    /// What the grid showed.
    pub observed: String,
}

/// The file the cases append known differences to, one JSON record a line.
pub const KNOWN_DIFFERENCES: &str = "known-differences.jsonl";

/// The known differences recorded in `directory` since `before`.
///
/// # Errors
///
/// Returns a line that is not a record, because a record the report cannot read is evidence it
/// would otherwise lose without saying so.
pub fn known_differences(
    directory: &Path,
    before: &Before,
) -> Result<Vec<KnownDifference>, String> {
    let path = directory.join(KNOWN_DIFFERENCES);
    let Ok(bytes) = std::fs::read(&path) else {
        return Ok(Vec::new());
    };
    let from = before.lengths.get(&path).copied().unwrap_or(0);
    let from = usize::try_from(from).unwrap_or(usize::MAX).min(bytes.len());
    String::from_utf8_lossy(&bytes[from..])
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| {
                format!("{KNOWN_DIFFERENCES} holds a line that is not a record ({error}): {line}")
            })
        })
        .collect()
}

/// Why an evidence directory is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused(pub String);

/// Checks that `directory` is inside this platform's temporary directory, and only then creates
/// it. Returns its real path.
///
/// Section 21 keeps every test artefact in an operating-system-resolved temporary directory, and a
/// report that wrote its evidence anywhere else could put it inside a checkout or a person's own
/// files. On Unix, `/tmp` and `TMPDIR` are both this platform's temporary directory; on Windows it
/// is the one the system names for the user. The path is resolved before anything is created, so
/// a refused directory is never made.
///
/// # Errors
///
/// Returns why the directory is refused.
pub fn check_directory(directory: &Path) -> Result<PathBuf, Refused> {
    let real = resolve(directory).map_err(|error| {
        Refused(format!(
            "{} could not be resolved: {error}",
            directory.display()
        ))
    })?;
    let mut temporary = vec![std::env::temp_dir()];
    if cfg!(unix) {
        temporary.push(PathBuf::from("/tmp"));
    }
    let inside = temporary
        .iter()
        .filter_map(|candidate| std::fs::canonicalize(candidate).ok())
        .any(|base| real != base && real.starts_with(&base));
    if !inside {
        return Err(Refused(format!(
            "{} is outside this platform's temporary directory; the evidence directory has to be \
             inside it",
            directory.display()
        )));
    }
    std::fs::create_dir_all(&real)
        .map_err(|error| Refused(format!("{} could not be created: {error}", real.display())))?;
    Ok(real)
}

/// The real path `path` names, whether or not it exists yet: its longest existing ancestor
/// resolved through every link, and the rest of it after that, with `.` and `..` applied.
fn resolve(path: &Path) -> std::io::Result<PathBuf> {
    use std::path::Component;
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    // The part that exists is resolved by the system, links and all; from the first component
    // that does not exist, the rest is applied as written.
    let mut existing = PathBuf::new();
    let mut rest: Vec<Component<'_>> = Vec::new();
    for component in absolute.components() {
        if rest.is_empty() {
            let candidate = existing.join(component);
            if candidate.exists() {
                existing = candidate;
                continue;
            }
        }
        rest.push(component);
    }
    let mut real = std::fs::canonicalize(&existing)?;
    for component in rest {
        match component {
            Component::ParentDir => {
                real.pop();
            }
            Component::Normal(name) => real.push(name),
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    Ok(real)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_headed_by_an_identifier_is_a_figure_of_it() {
        let text = "## KR-PERF-007 kr-term scrolling output\n\n  processor  x\n  sustained  3.8 MiB/s\n\n## notes without an identifier\n  ignored\n## KR-PERF-005 remote input\n  added 7.5 ms\n";
        let found = sections(text, "kr-term-output-handling.md");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0.to_string(), "KR-PERF-007");
        assert_eq!(found[0].1.lines, ["processor  x", "sustained  3.8 MiB/s"]);
        assert_eq!(found[1].1.measurement, "KR-PERF-005 remote input");
    }

    #[test]
    fn only_what_a_file_gained_during_the_run_is_read() {
        let directory = tempfile_directory("gained");
        let file = directory.join("record.md");
        std::fs::write(&file, "## KR-PERF-007 an earlier run\n  old\n").expect("writes");
        let before = before(&directory);
        let mut text = std::fs::read_to_string(&file).expect("reads");
        text.push_str("## KR-PERF-007 this run\n  new\n");
        std::fs::write(&file, text).expect("appends");
        let found = figures(&directory, &before);
        let figures = &found[&"KR-PERF-007".parse().expect("an identifier")];
        assert_eq!(figures.len(), 1);
        assert_eq!(figures[0].lines, ["new"]);
        std::fs::remove_dir_all(&directory).expect("removes");
    }

    #[test]
    fn a_known_difference_recorded_during_the_run_is_read_and_an_earlier_one_is_not() {
        let directory = tempfile_directory("known");
        let file = directory.join(KNOWN_DIFFERENCES);
        let record = |subject: &str| {
            format!(
                "{{\"package\":\"p\",\"target\":\"t\",\"test\":\"x\",\"subject\":\"{subject}\",\"application\":\"a\",\"grid\":\"g\",\"observed\":\"o\"}}\n"
            )
        };
        std::fs::write(&file, record("earlier")).expect("writes");
        let before = before(&directory);
        let mut text = std::fs::read_to_string(&file).expect("reads");
        text.push_str(&record("this run"));
        std::fs::write(&file, text).expect("appends");
        let found = known_differences(&directory, &before).expect("reads");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].subject, "this run");
        std::fs::write(&file, "not a record\n").expect("writes");
        assert!(known_differences(&directory, &Before::default()).is_err());
        std::fs::remove_dir_all(&directory).expect("removes");
    }

    #[test]
    fn a_directory_outside_the_temporary_directory_is_refused_and_never_made() {
        let inside = tempfile_directory("inside");
        let child = inside.join("new").join("evidence");
        assert!(check_directory(&child).is_ok());
        assert!(child.is_dir(), "an accepted directory is made");
        assert!(
            check_directory(&std::env::temp_dir()).is_err(),
            "the temporary directory itself"
        );
        assert_eq!(
            resolve(&inside.join("x").join("..").join("y")).expect("resolves"),
            std::fs::canonicalize(&inside).expect("resolves").join("y"),
            "a step up is applied before the path is judged"
        );
        let here = std::env::current_dir()
            .expect("a directory")
            .join("kr-conformance-not-made")
            .join("evidence");
        assert!(check_directory(&here).is_err());
        assert!(
            !here.parent().expect("a parent").exists(),
            "a refused directory is never made"
        );
        std::fs::remove_dir_all(&inside).expect("removes");
    }

    fn tempfile_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("kr-conformance-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        directory
    }
}
