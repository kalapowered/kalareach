//! The figures the performance tests record under `KR_TEST_ARTIFACTS_DIR`, and the rule for where
//! that directory may be.
//!
//! A measurement writes a Markdown section for each figure it takes, headed by the identifier it
//! measures (`## <identifier> <what>`), with the host, the figure and the verdict as indented lines,
//! and it writes that before it asserts anything, so a run the target failed keeps the number. The
//! report reads only what a file gained during this run, so a directory kept from an earlier run
//! lends it no figures. A file or directory that cannot be read is a problem of the run, never an
//! absence: only a file that is not there is.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

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

/// The files directly in `directory`, each with its length.
fn files(directory: &Path) -> Result<Vec<(PathBuf, u64)>, String> {
    let unreadable = |path: &Path, error: std::io::Error| {
        format!("{} could not be read: {error}", path.display())
    };
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(unreadable(directory, error)),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| unreadable(directory, error))?;
        let path = entry.path();
        let metadata = entry.metadata().map_err(|error| unreadable(&path, error))?;
        if metadata.is_file() {
            found.push((path, metadata.len()));
        }
    }
    found.sort();
    Ok(found)
}

/// Reads a file of the evidence directory, or nothing when it is not there.
fn read(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{} could not be read: {error}", path.display())),
    }
}

/// Records what the evidence directory holds before the run.
///
/// # Errors
///
/// Returns what could not be read.
pub fn before(directory: &Path) -> Result<Before, String> {
    Ok(Before {
        lengths: files(directory)?.into_iter().collect(),
    })
}

/// The figures the Markdown files of `directory` gained since `before`, by identifier.
///
/// # Errors
///
/// Returns what could not be read.
pub fn figures(
    directory: &Path,
    before: &Before,
) -> Result<BTreeMap<Identifier, Vec<Figure>>, String> {
    let mut found: BTreeMap<Identifier, Vec<Figure>> = BTreeMap::new();
    for (path, _) in files(directory)? {
        if path.extension().is_none_or(|extension| extension != "md") {
            continue;
        }
        let Some(bytes) = read(&path)? else {
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
    Ok(found)
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
/// Returns a file that cannot be read, or a line that is not a record: a record the report cannot
/// read is evidence it would otherwise lose without saying so.
pub fn known_differences(
    directory: &Path,
    before: &Before,
) -> Result<Vec<KnownDifference>, String> {
    let path = directory.join(KNOWN_DIFFERENCES);
    let Some(bytes) = read(&path)? else {
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
/// is the one the system names for the user.
///
/// The path is resolved before anything is created, so a refused directory is never made: the part
/// that exists is resolved by the system, links and all, and the rest is new names under it. A
/// `..` is refused outright, because after a name that does not exist yet it could step back into
/// a link the resolution never saw. What was made is resolved again and judged again.
///
/// # Errors
///
/// Returns why the directory is refused.
pub fn check_directory(directory: &Path) -> Result<PathBuf, Refused> {
    if directory
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(Refused(format!(
            "{} steps up a directory with `..`; name the evidence directory without one",
            directory.display()
        )));
    }
    let real = resolve(directory).map_err(|error| {
        Refused(format!(
            "{} could not be resolved: {error}",
            directory.display()
        ))
    })?;
    let outside = || {
        Refused(format!(
            "{} is outside this platform's temporary directory; the evidence directory has to be \
             inside it",
            directory.display()
        ))
    };
    if !inside_temporary(&real) {
        return Err(outside());
    }
    std::fs::create_dir_all(&real)
        .map_err(|error| Refused(format!("{} could not be created: {error}", real.display())))?;
    let made = std::fs::canonicalize(&real)
        .map_err(|error| Refused(format!("{} could not be resolved: {error}", real.display())))?;
    if made != real || !inside_temporary(&made) {
        return Err(outside());
    }
    Ok(made)
}

/// Whether `real`, a resolved path, is inside this platform's temporary directory.
fn inside_temporary(real: &Path) -> bool {
    let mut temporary = vec![std::env::temp_dir()];
    if cfg!(unix) {
        temporary.push(PathBuf::from("/tmp"));
    }
    temporary
        .iter()
        .filter_map(|candidate| std::fs::canonicalize(candidate).ok())
        .any(|base| real != base && real.starts_with(&base))
}

/// The real path `path` names, whether or not it exists yet: its longest existing ancestor
/// resolved through every link, and the rest of it after that.
fn resolve(path: &Path) -> std::io::Result<PathBuf> {
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
        if let Component::Normal(name) = component {
            real.push(name);
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
        let before = before(&directory).expect("reads");
        let mut text = std::fs::read_to_string(&file).expect("reads");
        text.push_str("## KR-PERF-007 this run\n  new\n");
        std::fs::write(&file, text).expect("appends");
        let found = figures(&directory, &before).expect("reads");
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
        let before = before(&directory).expect("reads");
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
        // The temporary directory itself holds no evidence. A TMPDIR inside `/tmp`, as a host
        // that gives each job a directory of its own has, is inside the temporary directory and
        // may; `/tmp` itself never may.
        let base = if cfg!(unix) {
            PathBuf::from("/tmp")
        } else {
            std::env::temp_dir()
        };
        assert!(
            check_directory(&base).is_err(),
            "the temporary directory itself"
        );
        assert!(
            check_directory(&inside.join("x").join("..").join("y")).is_err(),
            "a step up is refused"
        );
        assert!(!inside.join("y").exists(), "and nothing is made for it");
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

    #[cfg(unix)]
    #[test]
    fn a_link_out_of_the_temporary_directory_is_refused_however_it_is_reached() {
        let inside = tempfile_directory("link");
        let away = std::env::current_dir()
            .expect("a directory")
            .join("kr-conformance-not-made-through-a-link");
        std::os::unix::fs::symlink(
            std::env::current_dir().expect("a directory"),
            inside.join("escape"),
        )
        .expect("a link");
        for path in [
            inside
                .join("escape")
                .join("kr-conformance-not-made-through-a-link"),
            inside
                .join("new")
                .join("..")
                .join("escape")
                .join("kr-conformance-not-made-through-a-link"),
        ] {
            assert!(check_directory(&path).is_err(), "{}", path.display());
            assert!(
                !away.exists(),
                "nothing is made outside: {}",
                path.display()
            );
        }
        std::fs::remove_dir_all(&inside).expect("removes");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_that_cannot_be_read_is_a_problem_and_not_an_absence() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile_directory("unreadable");
        let file = directory.join(KNOWN_DIFFERENCES);
        std::fs::write(&file, "").expect("writes");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).expect("locks");
        // A process that reads whatever the modes say proves nothing here.
        if std::fs::read(&file).is_err() {
            assert!(known_differences(&directory, &Before::default()).is_err());
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("unlocks");
        let record = directory.join("record.md");
        std::fs::write(&record, "## KR-PERF-007 x\n  y\n").expect("writes");
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o000)).expect("locks");
        if std::fs::read(&record).is_err() {
            assert!(figures(&directory, &Before::default()).is_err());
        }
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).expect("unlocks");
        std::fs::remove_dir_all(&directory).expect("removes");
        assert!(
            known_differences(&directory, &Before::default()).is_ok_and(|found| found.is_empty()),
            "a directory that is not there holds nothing"
        );
    }

    fn tempfile_directory(name: &str) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("kr-conformance-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        directory
    }
}
