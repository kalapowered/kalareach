//! The libsodium archive a Windows build links: the placing script holds the size and the SHA-256
//! of the archive and of its signature and refuses any other bytes, whether they were fetched or
//! were already in the directory, and no job restores a cargo cache before it has placed them. A job
//! whose later steps run after a failure runs the placing action after one too.

use std::fs;
use std::path::{Path, PathBuf};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read(relative: &str) -> String {
    fs::read_to_string(repository().join(relative))
        .unwrap_or_else(|error| panic!("{relative} is readable: {error}"))
}

/// A value the script holds, as it is written there: `name=value` at the start of a line.
fn pinned(name: &str) -> String {
    let prefix = format!("{name}=");
    read("scripts/place-libsodium-archive.sh")
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_else(|| panic!("the script holds {name}"))
}

/// The upstream names and the name the build reads, as the script spells them.
const ARCHIVE: &str = "libsodium-1.0.22-msvc.zip";
const SIGNATURE: &str = "libsodium-1.0.22-msvc.zip.minisig";
/// The cases that run the script, which need a POSIX shell and a file route for `curl`.
#[cfg(unix)]
mod script {
    use super::{ARCHIVE, SIGNATURE, pinned, read, repository};
    use std::fs::{self, File};
    use std::path::Path;
    use std::process::{Command, Output};

    const PLACED_ARCHIVE: &str = "libsodium-1.0.22-stable-msvc.zip";
    const PLACED_SIGNATURE: &str = "libsodium-1.0.22-stable-msvc.zip.minisig";

    /// A file of `length` zero bytes: the length of the file the script pins and another content.
    fn zeros(path: &Path, length: u64) {
        File::create(path)
            .and_then(|file| file.set_len(length))
            .expect("the file is written");
    }

    /// Runs the script on `directory`, with the files fetched from `source` and no other route.
    fn place(directory: &Path, source: &Path) -> Output {
        Command::new("bash")
            .arg("scripts/place-libsodium-archive.sh")
            .arg(directory)
            .env(
                "LIBSODIUM_ARCHIVE_BASE_URL",
                format!("file://{}", source.display()),
            )
            .current_dir(repository())
            .output()
            .expect("bash runs the script")
    }

    /// What the script said when it refused: it failed, and it named the file as upstream publishes
    /// it and the digest it holds, which are what a person needs to see.
    fn assert_refused(output: &Output, name: &str, digest: &str) {
        let said = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "the script went on: {said}");
        assert!(said.contains("refused"), "no refusal: {said}");
        assert!(said.contains(name), "the file is not named: {said}");
        assert!(said.contains(digest), "the digest is not named: {said}");
    }

    /// A file of the pinned length with other bytes is refused by its digest, for a job that restored
    /// it from a cache, and nothing else is placed beside it.
    #[test]
    fn a_file_in_the_directory_with_other_bytes_is_refused() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let directory = scratch.path().join("placed");
        fs::create_dir(&directory).expect("the directory");
        let length: u64 = pinned("archive_bytes").parse().expect("a length");
        zeros(&directory.join(PLACED_ARCHIVE), length);
        // No route to anything else: a script that went on to fetch would fail by another message.
        let output = place(&directory, &scratch.path().join("nowhere"));
        assert_refused(&output, ARCHIVE, &pinned("archive_sha256"));
        let placed: Vec<_> = fs::read_dir(&directory)
            .expect("the directory is listed")
            .map(|entry| entry.expect("an entry").file_name())
            .collect();
        assert_eq!(placed, [PLACED_ARCHIVE], "nothing was placed beside it");
    }

    /// The signature is held to its digest as the archive is, and what is in the directory is compared
    /// before anything is fetched: the archive's route does not exist, and the refusal is the
    /// signature's.
    #[test]
    fn a_signature_in_the_directory_with_other_bytes_is_refused_before_anything_is_fetched() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let directory = scratch.path().join("placed");
        fs::create_dir(&directory).expect("the directory");
        let length: u64 = pinned("signature_bytes").parse().expect("a length");
        zeros(&directory.join(PLACED_SIGNATURE), length);
        let output = place(&directory, &scratch.path().join("nowhere"));
        assert_refused(&output, SIGNATURE, &pinned("signature_sha256"));
    }

    /// A job that fetches (a release job takes nothing from a cache) is held to the same bytes: a
    /// file upstream serves with another content is refused where it was written, and no file under
    /// the name the build reads is left.
    #[test]
    fn a_fetched_file_with_other_bytes_is_refused_and_not_placed() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let served = scratch.path().join("served");
        fs::create_dir(&served).expect("the served directory");
        let length: u64 = pinned("archive_bytes").parse().expect("a length");
        zeros(&served.join(ARCHIVE), length);
        let directory = scratch.path().join("placed");
        let output = place(&directory, &served);
        assert_refused(&output, ARCHIVE, &pinned("archive_sha256"));
        assert!(
            !directory.join(PLACED_ARCHIVE).exists(),
            "the refused file was placed"
        );
        assert!(
            !directory.join(format!("{PLACED_ARCHIVE}.part")).exists(),
            "the refused file was kept"
        );
    }

    /// A file of another length is refused as well, and the refusal names what it expected.
    #[test]
    fn a_fetched_file_of_another_length_is_refused() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let served = scratch.path().join("served");
        fs::create_dir(&served).expect("the served directory");
        zeros(&served.join(ARCHIVE), 1_024);
        let directory = scratch.path().join("placed");
        let output = place(&directory, &served);
        assert_refused(&output, ARCHIVE, &pinned("archive_sha256"));
        assert!(!directory.join(PLACED_ARCHIVE).exists());
    }

    /// The cache is named by both digests, so that an entry saved with other bytes is not restored,
    /// and the directory the build is given has that name.
    #[test]
    fn the_cache_key_names_the_digests_of_both_files() {
        let output = Command::new("bash")
            .arg("scripts/place-libsodium-archive.sh")
            .arg("--key")
            .current_dir(repository())
            .output()
            .expect("bash runs the script");
        assert!(output.status.success(), "the key is printed");
        let key = String::from_utf8(output.stdout).expect("the key is text");
        let archive = pinned("archive_sha256");
        let signature = pinned("signature_sha256");
        assert!(
            key.trim()
                .ends_with(&format!("-{}-{}", &archive[..12], &signature[..12]))
        );
        let action = read(".github/actions/libsodium-archive/action.yml");
        assert!(
            action.contains("path=~/$key"),
            "the directory is named by the key"
        );
    }
}

/// The cryptography reference names the archive, its length and its digests, as the script holds
/// them, so that a change of the script without the document is found.
#[test]
fn the_cryptography_reference_names_what_the_script_pins() {
    let reference = read("docs/crypto/README.md");
    for name in ["archive", "signature"] {
        for field in ["bytes", "sha256"] {
            let key = format!("{name}_{field}");
            let value = pinned(&key);
            let shown = if field == "bytes" {
                // Grouped in thousands, as the document writes lengths.
                let digits: Vec<char> = value.chars().rev().collect();
                let grouped = digits
                    .chunks(3)
                    .map(|chunk| chunk.iter().rev().collect::<String>())
                    .rev()
                    .collect::<Vec<_>>()
                    .join(",");
                format!("{grouped} bytes")
            } else {
                value
            };
            assert!(
                reference.contains(&shown),
                "the cryptography reference does not name {key}: {shown}"
            );
        }
    }
    assert!(reference.contains(ARCHIVE));
    assert!(reference.contains(SIGNATURE));
}

/// A job's key: a name of two spaces' indent and nothing after its colon.
fn is_job_key(line: &str) -> bool {
    let Some(name) = line
        .strip_prefix("  ")
        .and_then(|rest| rest.strip_suffix(':'))
    else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Every job of every workflow, as the text from its key to the next one, with the path of the
/// workflow it is in.
fn jobs() -> Vec<(PathBuf, String)> {
    let workflows = repository().join(".github").join("workflows");
    let mut all = Vec::new();
    for entry in fs::read_dir(&workflows).expect("the workflows are listed") {
        let path = entry.expect("an entry").path();
        if path.extension().is_none_or(|extension| extension != "yml") {
            continue;
        }
        let text = fs::read_to_string(&path).expect("the workflow is readable");
        // A job starts at a key of two spaces' indent under `jobs:`.
        let mut jobs: Vec<String> = Vec::new();
        let mut in_jobs = false;
        for line in text.lines() {
            if line == "jobs:" {
                in_jobs = true;
            } else if in_jobs && is_job_key(line) {
                jobs.push(String::new());
            }
            if in_jobs && let Some(job) = jobs.last_mut() {
                job.push_str(line);
                job.push('\n');
            }
        }
        all.extend(jobs.into_iter().map(|job| (path.clone(), job)));
    }
    all
}

/// A job that restores a cargo cache places the archive first: the cache's key reads the name of
/// the directory the archive is placed in, which holds its digests, and the restore comes after
/// that name is set.
#[test]
fn a_job_places_the_libsodium_archive_before_it_restores_a_cargo_cache() {
    let mut checked = 0;
    for (path, job) in jobs() {
        let place = job.find("uses: ./.github/actions/libsodium-archive");
        let restore = job.find("uses: ./.github/actions/cargo-cache-restore");
        if let (Some(place), Some(restore)) = (place, restore) {
            checked += 1;
            assert!(
                place < restore,
                "{} restores a cargo cache before it places the libsodium archive",
                path.display()
            );
        }
    }
    assert!(
        checked > 0,
        "no job places the archive and restores a cache: the check read nothing"
    );
}

/// The steps of a job, each as its own text: a step starts at a dash of six spaces' indent under
/// the job's `steps:`.
fn steps(job: &str) -> Vec<String> {
    let mut steps: Vec<String> = Vec::new();
    let mut in_steps = false;
    for line in job.lines() {
        if line == "    steps:" {
            in_steps = true;
        } else if in_steps && line.starts_with("      - ") {
            steps.push(String::new());
        }
        if in_steps && let Some(step) = steps.last_mut() {
            step.push_str(line);
            step.push('\n');
        }
    }
    steps
}

/// A step's own key, of the step's indent and not of a block under another key: the first line
/// carries the dash, and the others sit at eight spaces.
fn step_key<'a>(step: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}:");
    step.lines().find_map(|line| {
        line.strip_prefix("      - ")
            .or_else(|| {
                line.strip_prefix("        ")
                    .filter(|rest| !rest.starts_with(' '))
            })
            .and_then(|rest| rest.strip_prefix(prefix.as_str()))
            .map(str::trim)
    })
}

/// A later step of a job runs after an earlier failure only when its condition names a status
/// function that lets it: any other condition has `success()` put in front of it.
fn runs_after_a_failure(step: &str) -> bool {
    step_key(step, "if").is_some_and(|condition| {
        ["!cancelled()", "always()", "failure()"]
            .iter()
            .any(|function| condition.contains(function))
    })
}

/// A step that fails before the placing action skips the whole composite action, which takes its
/// step that closes the route to the download host with it. A job whose later steps run after a
/// failure (they name `!cancelled()` or `always()`) would then run cargo with the route open and
/// `SODIUM_DIST_DIR` unset, and the crate's build script would fetch the archive that no digest
/// holds. So where a later step can run after a failure the use of the action runs after one too.
/// A job whose later steps are all skipped after a failure needs nothing.
#[test]
fn the_placing_action_runs_in_a_job_whose_later_steps_run_after_a_failure() {
    let (mut guarded, mut unguarded) = (0, Vec::new());
    for (path, job) in jobs() {
        let steps = steps(&job);
        for (index, step) in steps.iter().enumerate() {
            if step_key(step, "uses") != Some("./.github/actions/libsodium-archive") {
                continue;
            }
            if !steps[index + 1..]
                .iter()
                .any(|later| runs_after_a_failure(later))
            {
                continue;
            }
            guarded += 1;
            let condition = step_key(step, "if").unwrap_or_default();
            if !(condition.contains("!cancelled()") || condition.contains("always()")) {
                unguarded.push(format!("{} (condition {condition:?})", path.display()));
            }
        }
    }
    assert!(
        guarded > 0,
        "no job uses the action and has a later step that runs after a failure: the check read nothing"
    );
    assert!(
        unguarded.is_empty(),
        "a later step of the job runs after a failure, and the use of the libsodium archive action \
         does not: {unguarded:#?}"
    );
}

/// The route to the download host is closed whether or not the archive was placed: a job that is
/// already red still runs its later steps that name `!cancelled()`, and none of them may have the
/// crate's build script download an archive that no digest holds. The step stands after the
/// placing step and its condition survives that step's failure.
#[test]
fn the_route_to_the_download_host_is_closed_after_a_refusal_too() {
    let action = read(".github/actions/libsodium-archive/action.yml");
    let placing = action
        .find("- name: Place what the cache lacks")
        .expect("the action has the placing step");
    let closing = action
        .find("- name: Close the route")
        .expect("the action has the closing step");
    assert!(
        placing < closing,
        "the route is closed before the archive is placed"
    );
    let condition = action[closing..]
        .lines()
        .find(|line| line.trim_start().starts_with("if:"))
        .expect("the step has a condition");
    assert!(
        condition.contains("always()"),
        "the step is skipped after a failure: {condition}"
    );
}
