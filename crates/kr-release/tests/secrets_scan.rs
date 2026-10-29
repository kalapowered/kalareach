//! No private key reaches a repository, a release tree or a release archive.
//!
//! A release's private keys are made in the environment that signs it and nowhere else, so what a
//! release build assembles is scanned for a key before it is packed or kept
//! (`scripts/check-release-secrets.py`), and the repository's own tracked files are held to the
//! same scan. The scan runs here as the release workflows run it.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs the scan's script with `arguments`, from `directory`.
fn scan_script_in(directory: &Path, arguments: &[&str]) -> Output {
    Command::new("python3")
        .arg("-I")
        .arg(root().join("scripts/check-release-secrets.py"))
        .args(arguments)
        .current_dir(directory)
        .output()
        .expect("python3 runs the scan")
}

/// Runs the scan's script with `arguments`, from the repository's root.
fn scan_script(arguments: &[&str]) -> Output {
    scan_script_in(&root(), arguments)
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("a path that is text")
}

/// A private key in PEM, written as the text a key file holds. It is put together here, so that this
/// source file carries no header of its own for the scan of the repository's files to find.
fn a_private_key() -> String {
    let header = ["-----BEGIN ", "EC ", "PRIVATE KEY", "-----"].concat();
    let footer = ["-----END ", "EC ", "PRIVATE KEY", "-----"].concat();
    let body = "MHcCAQEEIHkTf2xN0cVQp8mZr1o3uYb6LwA9dEjK4sGtXnPqRvUyoAoGCCqGSM49";
    format!("{header}\n{body}\n{footer}\n")
}

/// A release tree of the shape a build assembles: programs, a share directory and a manifest that
/// states what the tree is, in the members the sealing script reads.
fn a_release_tree(parent: &Path) -> PathBuf {
    let tree = parent.join("kalareach-x86_64-unknown-linux-gnu-0.0.0");
    std::fs::create_dir_all(tree.join("bin")).expect("bin");
    std::fs::create_dir_all(tree.join("share")).expect("share");
    std::fs::write(tree.join("bin/kr"), b"\x7fELF an ordinary program").expect("a program");
    std::fs::write(tree.join("share/LICENSE"), "A licence.\n").expect("a licence");
    std::fs::write(tree.join("share/update-root.json"), "{}\n").expect("a root");
    std::fs::write(
        tree.join("release.json"),
        concat!(
            "{\"signed\":{\"release\":\"0.0.0\",\"sequence\":1,\"commit\":\"0000000\",",
            "\"target\":\"x86_64-unknown-linux-gnu\",",
            "\"os_floor\":{\"system\":\"linux\",\"version\":\"1\"}}}\n"
        ),
    )
    .expect("a manifest");
    tree
}

/// Packs `tree` into `archive` the way the sealing script does.
fn pack(tree: &Path, archive: &Path) {
    let status = Command::new("tar")
        .arg("-C")
        .arg(tree.parent().expect("a parent"))
        .arg("-czf")
        .arg(archive)
        .arg(tree.file_name().expect("a name"))
        .status()
        .expect("tar packs the tree");
    assert!(status.success(), "tar did not pack the tree");
}

/// KR-REQ-26.41: the scan finds each kind of secret it names in a directory, an archive and a
/// nested archive, and passes the near misses.
#[test]
fn the_scan_finds_what_it_names_and_passes_what_it_does_not() {
    let output = scan_script(&["self-test"]);
    assert!(
        output.status.success(),
        "the scan's own cases failed: {}",
        stderr_of(&output)
    );
}

/// KR-REQ-26.41: a repository whose tracked files hold a private key is refused by name, and one
/// whose tracked files do not is passed. A key that is not tracked is not the repository's.
#[test]
fn a_repository_with_a_tracked_private_key_is_refused() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let repository = scratch.path();
    let git = |arguments: &[&str]| {
        let status = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .status()
            .expect("git runs");
        assert!(status.success(), "git {arguments:?} failed");
    };
    git(&["init", "-q"]);
    std::fs::write(repository.join("README"), "A readme.\n").expect("a file");
    git(&["add", "README"]);

    // The control: a repository that tracks no key passes, with a key beside it that it does not
    // track.
    std::fs::write(repository.join("untracked.pem"), a_private_key()).expect("an untracked key");
    let clean = scan_script_in(repository, &["scan", "--tracked", path_text(repository)]);
    assert!(clean.status.success(), "{}", stderr_of(&clean));

    git(&["add", "untracked.pem"]);
    let refused = scan_script_in(repository, &["scan", "--tracked", path_text(repository)]);
    assert!(
        !refused.status.success(),
        "a repository that tracks a private key passed"
    );
    assert!(
        stderr_of(&refused).contains("untracked.pem"),
        "the refusal names the file: {}",
        stderr_of(&refused)
    );
}

/// KR-REQ-26.41: a release tree that holds a private key is refused, and so is the archive made
/// from it; the same tree without the key passes both.
#[test]
fn a_release_tree_and_its_archive_with_a_private_key_in_them_are_refused() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let tree = a_release_tree(scratch.path());
    let archive = scratch.path().join("release.tar.gz");

    // The control: the tree a build assembles, and the archive made from it, are clean.
    let clean_tree = scan_script(&["scan", path_text(&tree)]);
    assert!(clean_tree.status.success(), "{}", stderr_of(&clean_tree));
    pack(&tree, &archive);
    let clean_archive = scan_script(&["scan", path_text(&archive)]);
    assert!(
        clean_archive.status.success(),
        "{}",
        stderr_of(&clean_archive)
    );

    // A key left among the files of the tree is found, and named by its path.
    std::fs::write(tree.join("share/signing.pem"), a_private_key()).expect("a planted key");
    let refused_tree = scan_script(&["scan", path_text(&tree)]);
    assert!(
        !refused_tree.status.success(),
        "a tree with a private key in it passed"
    );
    assert!(
        stderr_of(&refused_tree).contains("signing.pem"),
        "the refusal names the file: {}",
        stderr_of(&refused_tree)
    );

    // The archive made from it is refused too, and names the member.
    pack(&tree, &archive);
    let refused_archive = scan_script(&["scan", path_text(&archive)]);
    assert!(
        !refused_archive.status.success(),
        "an archive with a private key in it passed"
    );
    assert!(
        stderr_of(&refused_archive).contains("signing.pem"),
        "the refusal names the member: {}",
        stderr_of(&refused_archive)
    );
}

/// KR-REQ-26.41: the script that seals a release tree stops at a tree that holds a private key,
/// before it packs one, and goes on to pack the same tree without the key. The signing and the
/// manifest are not what is under test, so `kr-release` is a stand-in that accepts every step.
#[test]
fn sealing_stops_at_a_tree_with_a_private_key_before_it_packs_anything() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let signer = scratch.path().join("kr-release");
    std::fs::write(&signer, "#!/bin/sh\nexit 0\n").expect("a stand-in signer");
    std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o755)).expect("executable");
    let root_file = scratch.path().join("root.json");
    std::fs::write(&root_file, "{}\n").expect("a root");
    let key_file = scratch.path().join("targets-1.pk8");
    std::fs::write(&key_file, "not read by the script\n").expect("a key argument");
    let tree = a_release_tree(scratch.path());
    let seal = |out: &Path| {
        Command::new("bash")
            .arg(root().join("scripts/seal-release-tree.sh"))
            .arg("--tree")
            .arg(&tree)
            .arg("--checkout")
            .arg(scratch.path())
            .arg("--plugins")
            .arg(scratch.path())
            .arg("--kr-release")
            .arg(&signer)
            .arg("--root")
            .arg(&root_file)
            .arg("--key")
            .arg(&key_file)
            .arg("--out")
            .arg(out)
            .output()
            .expect("bash runs the sealing script")
    };
    let archive_of = |out: &Path| out.join("kalareach-x86_64-unknown-linux-gnu-0.0.0.tar.gz");

    // The control: a tree with no key gets past the scan of the tree to the packing. The archive
    // check after the packing may refuse this small stand-in tree, which is not what is under test.
    let clean_out = scratch.path().join("clean-out");
    seal(&clean_out);
    assert!(
        archive_of(&clean_out).exists(),
        "a tree with no key was not packed"
    );

    // The same tree with a key among its files is refused by name, and nothing is packed.
    std::fs::write(tree.join("share/signing.pem"), a_private_key()).expect("a planted key");
    let refused_out = scratch.path().join("refused-out");
    let refused = seal(&refused_out);
    assert!(
        !refused.status.success(),
        "a tree with a private key in it was sealed"
    );
    assert!(
        stderr_of(&refused).contains("signing.pem"),
        "the refusal names the file: {}",
        stderr_of(&refused)
    );
    assert!(
        !archive_of(&refused_out).exists(),
        "an archive was made from a tree with a private key in it"
    );
}

/// The lines of `workflow`, with the 1-based number of each.
fn lines_of(workflow: &str) -> Vec<(usize, String)> {
    let path = root().join(".github/workflows").join(workflow);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.to_owned()))
        .collect()
}

/// Whether a line is a command that scans something for a private key.
fn is_a_scan(line: &str) -> bool {
    let line = line.trim_start();
    !line.starts_with('#') && line.contains("check-release-secrets.py") && line.contains(" scan ")
}

/// Whether a line of a workflow opens a job: a key at the first level under `jobs`.
fn starts_a_job(line: &str) -> bool {
    line.starts_with("  ")
        && !line.starts_with("   ")
        && line.trim_end().ends_with(':')
        && !line.trim_start().starts_with('#')
}

/// The step a line of a workflow is in: the index of its first line and of its last.
fn step_around(lines: &[(usize, String)], at: usize) -> (usize, usize) {
    let starts_a_step = |line: &str| line.starts_with("      - ");
    let first = lines[..at]
        .iter()
        .rposition(|(_, line)| starts_a_step(line))
        .unwrap_or(0);
    let last = lines[at + 1..]
        .iter()
        .position(|(_, line)| starts_a_step(line) || starts_a_job(line))
        .map_or(lines.len() - 1, |index| at + index);
    (first, last)
}

/// The index of the first line of the job a line of a workflow is in.
fn job_starting_before(lines: &[(usize, String)], at: usize) -> usize {
    lines[..at]
        .iter()
        .rposition(|(_, line)| starts_a_job(line))
        .expect("a scan is inside a job")
}

/// KR-REQ-26.41: the release workflows that assemble a tree or an archive scan it for a private key
/// in the job that makes it, before that job keeps anything, and nothing makes a scan optional. The
/// macOS and Linux trees are sealed by the script above, which the workflows that seal run.
#[test]
fn the_release_workflows_scan_what_they_assemble_before_they_keep_it() {
    for workflow in [
        "release-tree.yml",
        "release-host.yml",
        "release-windows.yml",
    ] {
        let lines = lines_of(workflow);
        let scans: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, (_, line))| is_a_scan(line))
            .map(|(index, _)| index)
            .collect();
        assert!(
            !scans.is_empty(),
            "{workflow} runs no scan for a private key"
        );
        let mut jobs_checked = Vec::new();
        for &scan in &scans {
            let (number, text) = &lines[scan];
            assert!(
                !text.contains("||") && !text.contains(';'),
                "{workflow}:{number} lets the scan fail without stopping the job: {text}"
            );
            let (first, last) = step_around(&lines, scan);
            assert!(
                lines[first..=last]
                    .iter()
                    .all(|(_, line)| !line.contains("continue-on-error")),
                "{workflow}:{number} is in a step that continues on error"
            );
            // The first scan of a job comes before the job keeps anything; a later scan, of what
            // the job packs afterwards, comes after the tree was kept and before the archive is.
            let job_first = job_starting_before(&lines, scan);
            if jobs_checked.contains(&job_first) {
                continue;
            }
            jobs_checked.push(job_first);
            let kept_before = lines[job_first..scan]
                .iter()
                .find(|(_, line)| line.contains("actions/upload-artifact"));
            assert!(
                kept_before.is_none(),
                "{workflow}:{number} scans after the job kept something: {kept_before:?}"
            );
        }
    }
    for workflow in ["release-tree.yml", "release-host.yml"] {
        assert!(
            lines_of(workflow).iter().any(|(_, line)| {
                let line = line.trim_start();
                !line.starts_with('#') && line.contains("scripts/seal-release-tree.sh")
            }),
            "{workflow} no longer seals a tree with the script that scans it"
        );
    }
}
