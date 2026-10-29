//! No private key reaches a repository, a release tree or a release archive.
//!
//! What a release build assembles is scanned for a key before it is packed or kept
//! (`scripts/check-release-secrets.py`), and the repository's own tracked files are held to the
//! same scan. The scan runs here as the release workflows run it.

#![cfg(unix)]

use std::collections::BTreeSet;
use std::ops::Range;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest as _, Sha256};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs the scan's script with `arguments`, from `directory`. Git reads neither the system's nor
/// the person's global configuration file, since a scan of tracked files asks it which files they
/// are.
fn scan_script_in(directory: &Path, arguments: &[&str]) -> Output {
    Command::new("python3")
        .arg("-I")
        .arg(root().join("scripts/check-release-secrets.py"))
        .args(arguments)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
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

/// Unpadded base64url, the form a manifest states a digest in.
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut text = String::new();
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0_u32, |word, (at, byte)| {
            word | u32::from(*byte) << (16 - 8 * at)
        });
        for at in 0..=chunk.len() {
            text.push(char::from(ALPHABET[(word >> (18 - 6 * at)) as usize & 63]));
        }
    }
    text
}

/// Every file under `directory`, by its path from `base` and its bytes.
fn files_under(base: &Path, directory: &Path, found: &mut Vec<(String, Vec<u8>)>) {
    for entry in std::fs::read_dir(directory).expect("a directory") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            files_under(base, &path, found);
        } else {
            let relative = path.strip_prefix(base).expect("under the base");
            let bytes = std::fs::read(&path).expect("a file");
            found.push((path_text(relative).to_owned(), bytes));
        }
    }
}

/// Writes the manifest of `tree` again with the list of its files that the archive check reads: the
/// path, the length and the SHA-256 digest of every file but the manifest, and of each of `also`,
/// which are listed and are not there yet.
fn list_files(tree: &Path, also: &[(&str, &[u8])]) {
    let mut files = Vec::new();
    files_under(tree, tree, &mut files);
    files.retain(|(path, _)| path != "release.json");
    files.extend(
        also.iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec())),
    );
    files.sort();
    let files: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, bytes)| {
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            serde_json::json!({
                "path": path,
                "length": bytes.len().to_string(),
                "sha256": base64url(&digest),
                "mode": "regular",
            })
        })
        .collect();
    let manifest = serde_json::json!({
        "signed": {
            "release": "0.0.0",
            "sequence": 1,
            "commit": "0000000",
            "target": "x86_64-unknown-linux-gnu",
            "os_floor": {"system": "linux", "version": "1"},
            "files": files,
        },
    });
    std::fs::write(tree.join("release.json"), format!("{manifest}\n")).expect("a manifest");
}

/// A release tree of the shape a build assembles: programs, a share directory and a manifest that
/// states what the tree is, in the members the sealing script reads, and lists its files.
fn a_release_tree(parent: &Path) -> PathBuf {
    let tree = parent.join("kalareach-x86_64-unknown-linux-gnu-0.0.0");
    std::fs::create_dir_all(tree.join("bin")).expect("bin");
    std::fs::create_dir_all(tree.join("share")).expect("share");
    std::fs::write(tree.join("bin/kr"), b"\x7fELF an ordinary program").expect("a program");
    std::fs::write(tree.join("share/LICENSE"), "A licence.\n").expect("a licence");
    std::fs::write(tree.join("share/update-root.json"), "{}\n").expect("a root");
    list_files(&tree, &[]);
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

/// Runs the sealing script over `tree` into `out`, with a signer that accepts every step: the real
/// one holds a tree to built shell packages, which an ordinary run does not have. When `programs` is
/// given, the directory is searched for a program before the rest of the path is.
fn seal(scratch: &Path, tree: &Path, out: &Path, programs: Option<&Path>) -> Output {
    let signer = scratch.join("kr-release");
    std::fs::write(&signer, "#!/bin/sh\nexit 0\n").expect("a stand-in signer");
    std::fs::set_permissions(&signer, std::fs::Permissions::from_mode(0o755)).expect("executable");
    let root_file = scratch.join("root.json");
    std::fs::write(&root_file, "{}\n").expect("a root");
    let key_file = scratch.join("targets-1.pk8");
    std::fs::write(&key_file, "not read by the script\n").expect("a key argument");
    let mut command = Command::new("bash");
    command
        .arg(root().join("scripts/seal-release-tree.sh"))
        .arg("--tree")
        .arg(tree)
        .arg("--checkout")
        .arg(scratch)
        .arg("--plugins")
        .arg(scratch)
        .arg("--kr-release")
        .arg(&signer)
        .arg("--root")
        .arg(&root_file)
        .arg("--key")
        .arg(&key_file)
        .arg("--out")
        .arg(out);
    if let Some(programs) = programs {
        let mut search = std::ffi::OsString::from(programs);
        search.push(":");
        search.push(std::env::var_os("PATH").unwrap_or_default());
        command.env("PATH", search);
    }
    command.output().expect("bash runs the sealing script")
}

fn archive_of(out: &Path) -> PathBuf {
    out.join("kalareach-x86_64-unknown-linux-gnu-0.0.0.tar.gz")
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
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
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

    // Forced: an excludes file of the person who runs the case may name `*.pem`.
    git(&["add", "-f", "untracked.pem"]);
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
/// before it packs one, and packs and checks the same tree without the key. `kr-release` is a
/// stand-in that accepts every step, because its real checks hold a tree to built shell packages,
/// which an ordinary run does not have; the tree's manifest lists its files, so that the archive
/// check of the script, which reads that manifest, passes in the clean run.
#[test]
fn sealing_stops_at_a_tree_with_a_private_key_before_it_packs_anything() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let tree = a_release_tree(scratch.path());

    // The control: a tree with no key is sealed.
    let clean_out = scratch.path().join("clean-out");
    let clean = seal(scratch.path(), &tree, &clean_out, None);
    assert!(
        clean.status.success() && archive_of(&clean_out).exists(),
        "a tree with no key was not sealed: {}",
        stderr_of(&clean)
    );

    // The same tree with a key among its files is refused by name, and nothing is packed.
    std::fs::write(tree.join("share/signing.pem"), a_private_key()).expect("a planted key");
    let refused_out = scratch.path().join("refused-out");
    let refused = seal(scratch.path(), &tree, &refused_out, None);
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

/// KR-REQ-26.41: the script that seals a release tree scans the archive it packed as well as the
/// tree: an archive that holds a private key the scan of the tree did not see is refused, by the
/// name of the member. A stand-in `tar` adds the key to the tree as it packs, after the scan of the
/// tree; the manifest lists that file, so that the archive check, which comes before the scan of the
/// archive, passes and only the scan of the archive can refuse it.
#[test]
fn sealing_refuses_an_archive_that_holds_a_private_key_the_scan_of_the_tree_did_not_see() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let tree = a_release_tree(scratch.path());
    let programs = scratch.path().join("programs");
    std::fs::create_dir_all(&programs).expect("a directory of programs");
    let late_key = scratch.path().join("late-key.pem");
    let stand_in = programs.join("tar");
    std::fs::write(
        &stand_in,
        format!(
            "#!/bin/sh\nif [ -f '{}' ]; then cp '{}' '{}'; fi\nexec /usr/bin/tar \"$@\"\n",
            path_text(&late_key),
            path_text(&late_key),
            path_text(&tree.join("share/late.pem")),
        ),
    )
    .expect("a stand-in tar");
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755))
        .expect("executable");

    // The control: with no key to add, the stand-in packs the tree as it is, and the seal passes.
    let clean_out = scratch.path().join("clean-out");
    let clean = seal(scratch.path(), &tree, &clean_out, Some(&programs));
    assert!(
        clean.status.success() && archive_of(&clean_out).exists(),
        "a tree with no key was not sealed: {}",
        stderr_of(&clean)
    );

    // With a key added as the tree is packed, the seal is refused by the member's name.
    let key = a_private_key();
    std::fs::write(&late_key, &key).expect("a key to add");
    list_files(&tree, &[("share/late.pem", key.as_bytes())]);
    let refused_out = scratch.path().join("refused-out");
    let refused = seal(scratch.path(), &tree, &refused_out, Some(&programs));
    assert!(
        !refused.status.success(),
        "an archive with a private key in it was sealed"
    );
    let message = stderr_of(&refused);
    assert!(
        message.contains(".tar.gz!") && message.contains("late.pem"),
        "the refusal names the member of the archive: {message}"
    );
}

// The release workflows.
//
// The case holds the three workflows in the plain style they are written in today, reading each
// line as it stands. In that style it refuses every change the cases after it make: a scan or a
// sealing that is not the exact command on the exact path, one that can fail without stopping its
// step (an optional or conditional step or job, another shell, `set +`, `||`, `&&`, `;`, `&`, a
// branch, a loop or a group around it, an `exit` before it), a value of `run`, `shell`, `if` or
// `path` that goes on to the next line, a step that keeps or uploads before its scan, after a
// failure, or from a wider path than the scan read, and an upload that the case does not name.
//
// It is not a YAML parser and not a shell parser, and it does not hold what they would read
// differently: a value continued on the next line under another key, an anchor or an alias, an
// escape in a double-quoted value, a folded scalar, an inline mapping; shell quoting (a quoted
// string that makes a comment of the scan), and the shell's grammar (`true; if false; then`, a
// function nothing calls, `exec`, a backslash before a command). Nor does it hold a loop that runs
// no time, a function, an alias or a search path that takes the place of a command, a step between
// a scan and a step that keeps, which can change what is there, a step that keeps by another
// action than `actions/upload-artifact`, a step of another job or workflow that takes what a job
// assembled, or that the runner runs the file as written (`actionlint` and a run of the workflow
// show that). A check that parses the YAML replaces it when it is built.

/// What a workflow can do that lets a private key past its scan. Each is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refusal {
    /// A scan or a sealing that the case does not know, or one it knows that is gone.
    Unregistered,
    /// The command scans or seals another path than the one the case names.
    Target,
    /// The command is joined to another by `||`, `&&`, `;`, `&` or a pipe, or comes after an
    /// operator that makes it depend on another command.
    Joined,
    /// The scan has other commands in its step, where the case holds it to be the only one.
    NotAlone,
    /// The command sits where it can be skipped: in a branch, a group or a loop that may not run,
    /// after an `exit`, or in a here-document.
    Skippable,
    /// `set +` in any form, which turns off the stop at a failing command.
    ErrexitOff,
    /// A shell other than `bash` (or `pwsh`, where a workflow runs it by default), whose
    /// fail-fast options a different `shell:` leaves off, or a variable that changes how it starts.
    Shell,
    /// `if` or `continue-on-error` on the step, in any spelling of the key.
    Optional,
    /// Any other key on a scan or a sealing step.
    StepKey,
    /// `continue-on-error` on the job, wherever the key is in it.
    JobOptional,
    /// An `actions/upload-artifact` step the case does not know, named or not.
    UnknownUpload,
    /// A step that keeps what a job assembled, before the scan it has to come after.
    KeptBeforeScan,
    /// A status function that lets a step run after a failure (`always()`, `failure()`,
    /// `cancelled()`, or `!success()`) on a step that keeps what a job assembled. `success()` is
    /// what a step without a condition has, and is not refused.
    KeptOnFailure,
    /// A step that keeps what a job assembled from another path than the one its scan read.
    KeptPath,
    /// A value of `run`, `shell`, `if` or `path` that goes on to the next line, where the case reads
    /// the first line only.
    Continued,
}

/// A step that refuses a private key.
enum Guard {
    /// The scan, as the whole of a command, and whether it is the only command of its step.
    Scan(&'static str, bool),
    /// The sealing script, which scans the tree before it packs one and the archive after, over
    /// this `--tree`.
    Seal(&'static str),
}

impl Guard {
    /// What the command starts with, up to the path it names.
    fn start(&self) -> &'static str {
        match self {
            Guard::Scan(command, _) => {
                let end = command.find(" scan ").expect("a scan command") + " scan ".len();
                &command[..end]
            }
            Guard::Seal(_) => "bash scripts/seal-release-tree.sh ",
        }
    }
}

/// The steps that scan, by workflow and name. Two scans share a step with other commands, which
/// the case holds to a plain run of them. The Windows `release` job, which signs and publishes,
/// scans nothing it packs: the trees it takes were scanned by the `build` job, and the signing
/// changes the files (`docs/releases/keys.md` names the gap).
static GUARDS: [(&str, &str, Guard); 8] = [
    (
        "release-tree.yml",
        "Refuse a private key in the tree",
        Guard::Scan(
            r#"python3 scripts/check-release-secrets.py scan "$RUNNER_TEMP/tree/$TOP""#,
            true,
        ),
    ),
    (
        "release-tree.yml",
        "Seal the tree with this run's keys, and pack the archive",
        Guard::Seal(r#""$RUNNER_TEMP/tree/$TOP""#),
    ),
    (
        "release-tree.yml",
        "Make the release after this one",
        Guard::Seal(r#""$RUNNER_TEMP/next/$top""#),
    ),
    (
        "release-tree.yml",
        "Seal each tree with this run's keys, and verify what comes out",
        Guard::Seal(r#""$RUNNER_TEMP/trees/$name/$name""#),
    ),
    (
        "release-host.yml",
        "Seal each tree",
        Guard::Seal(r#""$RUNNER_TEMP/trees/$target/$top""#),
    ),
    (
        "release-host.yml",
        "Unpack it, and verify it against the committed root",
        Guard::Scan(
            r#"python3 scripts/check-release-secrets.py scan "$RUNNER_TEMP/sealed/$top.tar.gz""#,
            false,
        ),
    ),
    (
        "release-windows.yml",
        "Refuse a private key in the tree",
        Guard::Scan(
            r#"python scripts/check-release-secrets.py scan "$(cygpath -m "$RUNNER_TEMP")/tree/$TOP""#,
            true,
        ),
    ),
    (
        "release-windows.yml",
        "Pack the archive and hold it to what a host stages",
        Guard::Scan(
            r#"python scripts/check-release-secrets.py scan "$temp/archive/$TOP.zip""#,
            false,
        ),
    ),
];

/// For each step of `GUARDS` after which something is kept, the steps that pack, keep or upload
/// what the job assembled, which have to come after it in the same job.
static KEPT: [(&str, &str, &[&str]); 7] = [
    (
        "release-tree.yml",
        "Refuse a private key in the tree",
        &[
            "Keep the tree for a release",
            "Seal the tree with this run's keys, and pack the archive",
            "Keep the tree a release is made from",
        ],
    ),
    (
        "release-tree.yml",
        "Seal the tree with this run's keys, and pack the archive",
        &[
            "Keep the release for the formula",
            "Keep the archive this run proved",
        ],
    ),
    (
        "release-tree.yml",
        "Make the release after this one",
        &["Keep the release after it for the formula"],
    ),
    (
        "release-host.yml",
        "Seal each tree",
        &[
            "Keep the sealed archive of aarch64-apple-darwin",
            "Keep the sealed archive of x86_64-apple-darwin",
            "Keep the sealed archive of aarch64-unknown-linux-gnu",
            "Keep the sealed archive of x86_64-unknown-linux-gnu",
        ],
    ),
    (
        "release-host.yml",
        "Unpack it, and verify it against the committed root",
        &["Keep the digest that was checked"],
    ),
    (
        "release-windows.yml",
        "Refuse a private key in the tree",
        &["Keep the tree for signing"],
    ),
    (
        "release-windows.yml",
        "Pack the archive and hold it to what a host stages",
        &["Keep the archive this run proved"],
    ),
];

/// What a step that keeps is held to, so that it keeps what its scan read and no more.
enum Holds {
    /// The `path:` of an upload, as a whole.
    Path(&'static str),
    /// A command of the step, as a whole.
    Command(&'static str),
}

/// The steps that keep, and what each keeps: the path its scan read, or the command that packs
/// the tree it scanned.
static HOLDS: [(&str, &str, Holds); 13] = [
    (
        "release-tree.yml",
        "Keep the tree for a release",
        Holds::Command(
            r#"COPYFILE_DISABLE=1 tar --no-xattrs -C "$RUNNER_TEMP/tree" -cf "$RUNNER_TEMP/unsigned/$TOP.tar" "$TOP""#,
        ),
    ),
    (
        "release-tree.yml",
        "Keep the tree a release is made from",
        Holds::Path("${{ runner.temp }}/unsigned"),
    ),
    (
        "release-tree.yml",
        "Keep the release for the formula",
        Holds::Path("${{ runner.temp }}/archive/${{ env.TOP }}.tar.gz"),
    ),
    (
        "release-tree.yml",
        "Make the release after this one",
        Holds::Command(
            r#"echo "NEXT_ARCHIVE=$RUNNER_TEMP/next-archive/$top.tar.gz" >> "$GITHUB_ENV""#,
        ),
    ),
    (
        "release-tree.yml",
        "Keep the release after it for the formula",
        Holds::Path("${{ env.NEXT_ARCHIVE }}"),
    ),
    (
        "release-tree.yml",
        "Keep the archive this run proved",
        Holds::Path("${{ runner.temp }}/archive"),
    ),
    (
        "release-host.yml",
        "Keep the sealed archive of aarch64-apple-darwin",
        Holds::Path("${{ runner.temp }}/sealed/aarch64-apple-darwin"),
    ),
    (
        "release-host.yml",
        "Keep the sealed archive of x86_64-apple-darwin",
        Holds::Path("${{ runner.temp }}/sealed/x86_64-apple-darwin"),
    ),
    (
        "release-host.yml",
        "Keep the sealed archive of aarch64-unknown-linux-gnu",
        Holds::Path("${{ runner.temp }}/sealed/aarch64-unknown-linux-gnu"),
    ),
    (
        "release-host.yml",
        "Keep the sealed archive of x86_64-unknown-linux-gnu",
        Holds::Path("${{ runner.temp }}/sealed/x86_64-unknown-linux-gnu"),
    ),
    (
        "release-host.yml",
        "Keep the digest that was checked",
        Holds::Path("${{ runner.temp }}/verified"),
    ),
    (
        "release-windows.yml",
        "Keep the tree for signing",
        Holds::Path(r"${{ runner.temp }}\tree"),
    ),
    (
        "release-windows.yml",
        "Keep the archive this run proved",
        Holds::Path("${{ runner.temp }}/archive"),
    ),
];

/// A workflow's text.
fn workflow_text(workflow: &str) -> String {
    let path = root().join(".github/workflows").join(workflow);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

/// The indentation of a line.
fn indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Whether a line is neither blank nor a comment.
fn is_code(line: &str) -> bool {
    let line = line.trim();
    !line.is_empty() && !line.starts_with('#')
}

/// Whether a line is a command that scans something for a private key.
fn is_a_scan(line: &str) -> bool {
    let line = line.trim_start();
    !line.starts_with('#') && line.contains("check-release-secrets.py") && line.contains(" scan ")
}

/// The key and the value of a mapping line, without the quotes around the key:
/// `"continue-on-error": true` is the key `continue-on-error`.
fn pair(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    let (key, rest) = match text.chars().next()? {
        quote @ ('"' | '\'') => {
            let inner = &text[1..];
            let end = inner.find(quote)?;
            (&inner[..end], &inner[end + 1..])
        }
        _ => {
            let end = text.find(':')?;
            (&text[..end], &text[end..])
        }
    };
    let value = rest.trim_start().strip_prefix(':')?;
    Some((key.trim(), value.trim()))
}

/// A command of a step's `run`: its lines joined, where a line ends in a backslash.
struct Statement {
    first: usize,
    last: usize,
    text: String,
}

struct Job {
    range: Range<usize>,
    /// The lines of its `steps:` list.
    steps: Range<usize>,
}

struct Step {
    job: usize,
    range: Range<usize>,
}

/// A workflow's lines, its jobs and their steps.
struct Workflow<'a> {
    lines: Vec<&'a str>,
    jobs: Vec<Job>,
    steps: Vec<Step>,
}

impl<'a> Workflow<'a> {
    /// A workflow's jobs are the keys at the first level under `jobs:`, and the steps of a job the
    /// items of its `steps:` list, which the files here write at six spaces.
    fn parse(text: &'a str) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let mut jobs = Vec::new();
        let mut steps = Vec::new();
        if let Some(at) = lines.iter().position(|line| *line == "jobs:") {
            let at_level =
                |line: usize, level: usize| is_code(lines[line]) && indent(lines[line]) == level;
            let end = (at + 1..lines.len())
                .find(|&line| at_level(line, 0))
                .unwrap_or(lines.len());
            let starts: Vec<usize> = (at + 1..end).filter(|&line| at_level(line, 2)).collect();
            for (job, &start) in starts.iter().enumerate() {
                let range = start..starts.get(job + 1).copied().unwrap_or(end);
                let list = match range.clone().find(|&line| lines[line] == "    steps:") {
                    Some(key) => {
                        let last = (key + 1..range.end)
                            .find(|&line| is_code(lines[line]) && indent(lines[line]) <= 4)
                            .unwrap_or(range.end);
                        key + 1..last
                    }
                    None => range.start..range.start,
                };
                let firsts: Vec<usize> = list
                    .clone()
                    .filter(|&line| lines[line].starts_with("      - "))
                    .collect();
                for (step, &first) in firsts.iter().enumerate() {
                    let last = firsts.get(step + 1).copied().unwrap_or(list.end);
                    steps.push(Step {
                        job,
                        range: first..last,
                    });
                }
                jobs.push(Job { range, steps: list });
            }
        }
        Workflow { lines, jobs, steps }
    }

    /// The keys of a step: the line, the key and the rest of the line.
    fn keys(&self, step: &Range<usize>) -> Vec<(usize, &'a str, &'a str)> {
        step.clone()
            .filter_map(|at| {
                let line = self.lines[at];
                let text = if at == step.start {
                    line.strip_prefix("      - ")?
                } else if is_code(line) && indent(line) == 8 {
                    line
                } else {
                    return None;
                };
                pair(text).map(|(key, value)| (at, key, value))
            })
            .collect()
    }

    /// The line and the value of a key under a step's `with:`.
    fn with_value(&self, step: &Range<usize>, key: &str) -> Option<(usize, &'a str)> {
        let keys = self.keys(step);
        let (with, ..) = keys.iter().find(|(_, found, _)| *found == "with")?;
        let end = keys.iter().map(|(line, ..)| *line).find(|line| line > with);
        (with + 1..end.unwrap_or(step.end)).find_map(|at| {
            let line = self.lines[at];
            let (found, value) = pair(line).filter(|_| is_code(line) && indent(line) == 10)?;
            (found == key).then_some((at, value))
        })
    }

    /// Whether the value of the key on line `at` goes on to the next line, where the case reads the
    /// first only: the next line of code is indented further than the key, or the value is a folded
    /// block, or a literal one for any key but `run`.
    fn goes_on(&self, at: usize) -> bool {
        let line = self.lines[at];
        let Some((key, value)) = pair(line.trim_start().trim_start_matches("- ")) else {
            return false;
        };
        if value.starts_with('|') {
            return key != "run";
        }
        let column = indent(line)
            + if line.trim_start().starts_with("- ") {
                2
            } else {
                0
            };
        let next = (at + 1..self.lines.len()).find(|&next| is_code(self.lines[next]));
        value.starts_with('>') || next.is_some_and(|next| indent(self.lines[next]) > column)
    }

    fn name_of(&self, step: &Step) -> Option<&'a str> {
        let keys = self.keys(&step.range);
        keys.iter()
            .find(|(_, key, _)| *key == "name")
            .map(|(_, _, value)| *value)
    }

    /// The one step with this name.
    fn find(&self, name: &str) -> Option<&Step> {
        let mut named = self
            .steps
            .iter()
            .filter(|step| self.name_of(step) == Some(name));
        let found = named.next()?;
        named.next().is_none().then_some(found)
    }

    /// The lines of a step that are neither blank nor comments.
    fn code(&self, step: &Range<usize>) -> Vec<&'a str> {
        step.clone()
            .map(|at| self.lines[at])
            .filter(|line| is_code(line))
            .collect()
    }

    /// The commands of a step's `run`, whether the value is on the key's line or in a block under it.
    fn run(&self, step: &Range<usize>) -> Vec<Statement> {
        let keys = self.keys(step);
        let Some(&(at, _, value)) = keys.iter().find(|(_, key, _)| *key == "run") else {
            return Vec::new();
        };
        let lines: Vec<(usize, &str)> = if !value.is_empty() && !value.starts_with(['|', '>']) {
            vec![(at, value)]
        } else {
            let end = keys.iter().map(|(line, ..)| *line).find(|&line| line > at);
            (at + 1..end.unwrap_or(step.end))
                .filter(|&line| is_code(self.lines[line]))
                .map(|line| (line, self.lines[line].trim()))
                .collect()
        };
        let mut statements = Vec::new();
        let mut open: Option<Statement> = None;
        for (at, text) in lines {
            let (body, continues) = match text.strip_suffix('\\') {
                Some(body) => (body.trim_end(), true),
                None => (text, false),
            };
            let mut statement = match open.take() {
                Some(mut statement) => {
                    statement.text.push(' ');
                    statement.text.push_str(body);
                    statement.last = at;
                    statement
                }
                None => Statement {
                    first: at,
                    last: at,
                    text: body.to_owned(),
                },
            };
            if continues {
                open = Some(statement);
            } else {
                statement.text = statement.text.trim().to_owned();
                statements.push(statement);
            }
        }
        statements.extend(open);
        statements
    }

    /// The shell a workflow runs its steps with when a step names none.
    fn default_shell(&self) -> Option<&'a str> {
        let jobs = self.lines.iter().position(|line| *line == "jobs:")?;
        let named = self.lines[..jobs]
            .iter()
            .copied()
            .filter(|line| is_code(line));
        let value = named.filter_map(pair).find(|(key, _)| *key == "shell")?.1;
        Some(value.trim_matches(['"', '\'']))
    }

    /// The keys of a job itself: those outside its steps.
    fn job_keys(&self, job: usize) -> Vec<(usize, &'a str)> {
        let Job { range, steps } = &self.jobs[job];
        range
            .clone()
            .filter(|at| !steps.contains(at))
            .filter(|&at| is_code(self.lines[at]) && indent(self.lines[at]) == 4)
            .filter_map(|at| pair(self.lines[at]).map(|(key, _)| (at, key)))
            .collect()
    }
}

/// The words of a command, split at spaces and at what joins or groups commands.
fn words(text: &str) -> Vec<&str> {
    let splits = |character: char| character.is_whitespace() || ";&|(){}<>".contains(character);
    text.split(splits).filter(|word| !word.is_empty()).collect()
}

/// Whether a command can leave the step, or the shell's stop at a failing command, behind: a trap,
/// an `eval`, a `return`, or an `exit` with any status but 1 (the status the steps here stop with).
fn escapes(words: &[&str]) -> bool {
    words.iter().enumerate().any(|(at, word)| match *word {
        "trap" | "eval" | "return" => true,
        "exit" => words.get(at + 1) != Some(&"1"),
        _ => false,
    })
}

/// Whether a command is `set` with an option that starts with `+`, as in `set +e`, `set +o
/// errexit` and `set -x +e`.
fn turns_errexit_off(words: &[&str]) -> bool {
    let sets = words.iter().enumerate().filter(|(_, word)| **word == "set");
    sets.into_iter()
        .any(|(at, _)| words[at + 1..].iter().any(|word| word.starts_with('+')))
}

/// Whether a branch or a loop on one line ends on that line: `if [ -d x ]; then echo x; fi`.
fn ends_on_its_line(text: &str) -> bool {
    let text = text.trim_end().trim_end_matches(';').trim_end();
    ["fi", "done", "esac"]
        .iter()
        .any(|end| text.ends_with(&format!(";{end}")) || text.ends_with(&format!("; {end}")))
}

/// The branches, loops and groups still open where the command at `at` starts, by their first word.
fn open_before(commands: &[Statement], at: usize) -> Vec<String> {
    let mut open: Vec<String> = Vec::new();
    for command in &commands[..at] {
        let text = command.text.as_str();
        let word = text.split_whitespace().next().unwrap_or("");
        let unbalanced = |opening: char, closing: char| {
            text.matches(opening).count() != text.matches(closing).count()
        };
        if ["if", "for", "while", "until", "case", "select"].contains(&word) {
            if !ends_on_its_line(text) {
                open.push(word.to_owned());
            }
        } else if matches!(word, "fi" | "done" | "esac") || text == ")" || text == "}" {
            open.pop();
        } else if (text.starts_with('(') && unbalanced('(', ')'))
            || (text.starts_with('{') && unbalanced('{', '}'))
            || text.ends_with('{')
            || word == "function"
        {
            open.push(text.to_owned());
        }
    }
    open
}

/// Whether lines name a status function of a workflow's expressions, which are not case-sensitive.
fn names_a_status_function(lines: &[&str]) -> bool {
    let squeezed: String = lines
        .iter()
        .flat_map(|line| line.chars())
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    // `success()` is what a step without a condition has; its negation is a failure.
    [
        "always(",
        "failure(",
        "cancelled(",
        "!success(",
        "!(success(",
    ]
    .iter()
    .any(|name| squeezed.contains(name))
}

/// One thing a workflow does that the case refuses: the rule, and the line (1-based; 0 for a
/// workflow as a whole) with what is on it.
struct Problem {
    refusal: Refusal,
    line: usize,
    what: String,
}

fn refuse(found: &mut Vec<Problem>, refusal: Refusal, line: usize, what: &str) {
    found.push(Problem {
        refusal,
        line: line + 1,
        what: what.trim().to_owned(),
    });
}

fn refuse_step(found: &mut Vec<Problem>, refusal: Refusal, step: &str) {
    found.push(Problem {
        refusal,
        line: 0,
        what: format!("the step {step:?}"),
    });
}

fn describe(workflow: &str, found: &[Problem]) -> String {
    let lines: Vec<String> = found
        .iter()
        .map(
            |Problem {
                 refusal,
                 line,
                 what,
             }| format!("{workflow}:{line} {refusal:?}: {what}"),
        )
        .collect();
    lines.join("\n")
}

/// Holds one scan or sealing step to what it must be.
fn check_guard(workflow: &Workflow, step: &Step, guard: &Guard, found: &mut Vec<Problem>) {
    let first = step.range.start;
    let allowed: &[&str] = match guard {
        Guard::Scan(..) => &["name", "run", "shell"],
        Guard::Seal(_) => &["name", "run", "env", "shell"],
    };
    let keys = workflow.keys(&step.range);
    for &(at, key, _) in &keys {
        if matches!(key, "if" | "continue-on-error") {
            refuse(found, Refusal::Optional, at, workflow.lines[at]);
        } else if !allowed.contains(&key) {
            refuse(found, Refusal::StepKey, at, workflow.lines[at]);
        }
    }
    let named = keys.iter().find(|(_, key, _)| *key == "shell");
    let shell = named.map_or_else(
        || workflow.default_shell().unwrap_or("bash"),
        |(_, _, value)| value.trim_matches(['"', '\'']),
    );
    if shell != "bash" {
        let at = named.map_or(first, |(at, ..)| *at);
        refuse(found, Refusal::Shell, at, workflow.lines[at]);
    }

    let commands = workflow.run(&step.range);
    for command in &commands {
        let (text, at) = (command.text.as_str(), command.first);
        let words = words(text);
        if text.contains("<<") || text.matches('"').count() % 2 == 1 || escapes(&words) {
            refuse(found, Refusal::Skippable, at, text);
        }
        if turns_errexit_off(&words) {
            refuse(found, Refusal::ErrexitOff, at, text);
        }
        if text.contains("||") || text.ends_with('&') || text.ends_with('|') {
            refuse(found, Refusal::Joined, at, text);
        }
    }

    let ours: Vec<usize> = (0..commands.len())
        .filter(|&at| commands[at].text.starts_with(guard.start()))
        .collect();
    let [at] = ours[..] else {
        refuse(found, Refusal::Unregistered, first, guard.start());
        return;
    };
    let command = &commands[at];
    let allowed_open: &[&str] = match guard {
        Guard::Scan(..) => &[],
        Guard::Seal(_) => &["for"],
    };
    if open_before(&commands, at)
        .iter()
        .any(|open| !allowed_open.contains(&open.as_str()))
    {
        refuse(found, Refusal::Skippable, command.first, &command.text);
    }
    match guard {
        Guard::Scan(expected, alone) => {
            if command.text != *expected {
                let rest = command.text.strip_prefix(expected);
                let joined = rest
                    .is_some_and(|rest| rest.trim_start().starts_with(['|', '&', ';', '>', '<']));
                let refusal = if joined {
                    Refusal::Joined
                } else {
                    Refusal::Target
                };
                refuse(found, refusal, command.first, &command.text);
            }
            if *alone && commands.len() != 1 {
                refuse(found, Refusal::NotAlone, first, workflow.lines[first]);
            }
        }
        Guard::Seal(tree) => {
            if command
                .text
                .contains(['|', '&', ';', '<', '>', '(', ')', '{', '}', '!', '`'])
            {
                refuse(found, Refusal::Joined, command.first, &command.text);
            }
            let words: Vec<&str> = command.text.split_whitespace().collect();
            let target = words
                .iter()
                .position(|word| *word == "--tree")
                .and_then(|at| words.get(at + 1));
            if target != Some(tree) {
                refuse(found, Refusal::Target, command.first, &command.text);
            }
        }
    }
}

/// What is wrong with the text of a release workflow, by the rules above.
fn problems_in(name: &str, text: &str) -> Vec<Problem> {
    let workflow = Workflow::parse(text);
    let mut found = Vec::new();
    let mine = |file: &str| file == name;

    // Every shell the workflow names is `bash`, or `pwsh` for a workflow that runs it by default,
    // and no variable changes how a shell starts.
    for (at, line) in workflow
        .lines
        .iter()
        .enumerate()
        .filter(|(_, line)| is_code(line))
    {
        let value = pair(line.trim_start().trim_start_matches("- "))
            .filter(|(key, _)| *key == "shell")
            .map(|(_, value)| value.trim_matches(['"', '\'']));
        let starts_differently = ["BASH_ENV", "SHELLOPTS", "BASHOPTS"]
            .iter()
            .any(|variable| line.contains(variable));
        if starts_differently || value.is_some_and(|value| !matches!(value, "bash" | "pwsh")) {
            refuse(&mut found, Refusal::Shell, at, line);
        }
        if value.is_some() && workflow.goes_on(at) {
            refuse(&mut found, Refusal::Continued, at, line);
        }
    }

    // Each scan and sealing is a step the case knows, and is what it must be.
    let mut guarded = BTreeSet::new();
    for (_, step_name, guard) in GUARDS.iter().filter(|(file, ..)| mine(file)) {
        match workflow.find(step_name) {
            Some(step) => {
                guarded.insert(step.job);
                check_guard(&workflow, step, guard, &mut found);
            }
            None => refuse_step(&mut found, Refusal::Unregistered, step_name),
        }
    }
    for step in &workflow.steps {
        let lines = workflow.code(&step.range);
        let runs_one = lines
            .iter()
            .any(|line| is_a_scan(line) || line.contains("seal-release-tree.sh"));
        let step_name = workflow.name_of(step);
        let known = GUARDS
            .iter()
            .any(|(file, guard, _)| mine(file) && Some(*guard) == step_name);
        if runs_one && !known {
            refuse(
                &mut found,
                Refusal::Unregistered,
                step.range.start,
                workflow.lines[step.range.start],
            );
        }
    }

    // In a job that scans, nothing is optional, and every upload is a step the case names.
    let kept_steps: Vec<&str> = KEPT
        .iter()
        .filter(|(file, ..)| mine(file))
        .flat_map(|(_, _, kept)| kept.iter().copied())
        .collect();
    for &job in &guarded {
        for (at, key) in workflow.job_keys(job) {
            if key == "continue-on-error" {
                refuse(&mut found, Refusal::JobOptional, at, workflow.lines[at]);
            }
        }
        for step in workflow.steps.iter().filter(|step| step.job == job) {
            let keys = workflow.keys(&step.range);
            let long = keys
                .iter()
                .filter(|(_, key, _)| matches!(*key, "run" | "shell" | "if"))
                .map(|(at, ..)| *at)
                .chain(workflow.with_value(&step.range, "path").map(|(at, _)| at));
            for at in long.filter(|&at| workflow.goes_on(at)) {
                refuse(&mut found, Refusal::Continued, at, workflow.lines[at]);
            }
            let uploads = workflow
                .code(&step.range)
                .iter()
                .any(|line| line.contains("actions/upload-artifact"));
            let known = workflow
                .name_of(step)
                .is_some_and(|step| kept_steps.contains(&step));
            if uploads && !known {
                refuse(
                    &mut found,
                    Refusal::UnknownUpload,
                    step.range.start,
                    workflow.lines[step.range.start],
                );
            }
        }
    }

    // Each step that keeps what the job assembled comes after its scan and runs only while the job
    // has not failed.
    for (_, scan, kept) in KEPT.iter().filter(|(file, ..)| mine(file)) {
        for step_name in *kept {
            let Some(step) = workflow.find(step_name) else {
                refuse_step(&mut found, Refusal::Unregistered, step_name);
                continue;
            };
            let first = step.range.start;
            if names_a_status_function(&workflow.code(&step.range)) {
                refuse(
                    &mut found,
                    Refusal::KeptOnFailure,
                    first,
                    workflow.lines[first],
                );
            }
            let after = workflow
                .find(scan)
                .is_some_and(|scan| scan.job == step.job && scan.range.start < first);
            if !after {
                refuse(
                    &mut found,
                    Refusal::KeptBeforeScan,
                    first,
                    workflow.lines[first],
                );
            }
        }
    }

    // Each step that keeps keeps what its scan read: the path, or the command that packs it.
    for (_, step_name, holds) in HOLDS.iter().filter(|(file, ..)| mine(file)) {
        let Some(step) = workflow.find(step_name) else {
            refuse_step(&mut found, Refusal::Unregistered, step_name);
            continue;
        };
        let (at, held) = match holds {
            Holds::Path(path) => match workflow.with_value(&step.range, "path") {
                Some((at, value)) => (at, value == *path),
                None => (step.range.start, false),
            },
            Holds::Command(command) => {
                let commands = workflow.run(&step.range);
                (
                    step.range.start,
                    commands.iter().any(|c| c.text == *command),
                )
            }
        };
        if !held {
            refuse(&mut found, Refusal::KeptPath, at, workflow.lines[at]);
        }
    }
    found
}

/// KR-REQ-26.41: the release workflows, in the plain style they are written in, scan what they
/// assemble for a private key before the step that seals or keeps it, in the same job; nothing in
/// that style makes a scan optional, or lets a failed scan go on to a step that keeps the tree or
/// the archive, or lets a step keep more than the scan read. The case is not a YAML or a shell
/// parser, and the comment above it names what it does not hold. The macOS and Linux trees are
/// sealed by the script above, which the workflows run.
#[test]
fn the_release_workflows_scan_what_they_assemble_before_they_keep_it() {
    for workflow in [
        "release-tree.yml",
        "release-host.yml",
        "release-windows.yml",
    ] {
        let found = problems_in(workflow, &workflow_text(workflow));
        assert!(found.is_empty(), "{}", describe(workflow, &found));
    }
}

/// A workflow's lines, changed the way a mistake would change them, and what was changed.
struct Mutant {
    workflow: &'static str,
    lines: Vec<String>,
    changes: Vec<String>,
}

impl Mutant {
    fn of(workflow: &'static str) -> Self {
        let lines = workflow_text(workflow).lines().map(str::to_owned).collect();
        Mutant {
            workflow,
            lines,
            changes: Vec::new(),
        }
    }

    fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The lines and the commands of the step with this name.
    fn step(&self, name: &str) -> (Range<usize>, Vec<Statement>) {
        let text = self.text();
        let workflow = Workflow::parse(&text);
        let step = workflow
            .find(name)
            .unwrap_or_else(|| panic!("no step {name:?}"));
        (step.range.clone(), workflow.run(&step.range))
    }

    /// The line of a key of a step, and whether its value is the lines under it.
    fn key(&self, name: &str, key: &str) -> Option<(usize, bool)> {
        let (range, _) = self.step(name);
        let text = self.text();
        let keys = Workflow::parse(&text).keys(&range);
        let (at, _, value) = keys.into_iter().find(|(_, found, _)| *found == key)?;
        Some((at, value.is_empty() || value.starts_with(['|', '>'])))
    }

    /// The command of a step that starts with `start`.
    fn command(&self, name: &str, start: &str) -> Statement {
        let (_, commands) = self.step(name);
        let mut ours = commands
            .into_iter()
            .filter(|command| command.text.starts_with(start));
        let command = ours
            .next()
            .unwrap_or_else(|| panic!("no command {start:?}"));
        assert!(ours.next().is_none(), "two commands {start:?}");
        command
    }

    /// Sets a key of a step: its line is replaced, or a line is put after the step's first.
    fn set_key(&mut self, name: &str, key: &str, value: &str) {
        self.changes.push(format!("`{key}: {value}` on {name:?}"));
        let line = format!("        {key}: {value}");
        match self.key(name, key.trim_matches(['"', '\''])) {
            Some((at, _)) => self.lines[at] = line,
            None => {
                let (range, _) = self.step(name);
                self.lines.insert(range.start + 1, line);
            }
        }
    }

    /// Puts the `run` of a step in a block, if it is on the key's line.
    fn put_run_in_block(&mut self, name: &str) {
        let (at, block) = self.key(name, "run").expect("a step that runs");
        if !block {
            let value = self.lines[at]
                .trim_start()
                .trim_start_matches("run:")
                .trim()
                .to_owned();
            self.lines[at] = "        run: |".to_owned();
            self.lines.insert(at + 1, format!("          {value}"));
        }
    }

    /// Puts a line first among the commands of a step.
    fn prepend_to_run(&mut self, name: &str, line: &str) {
        self.changes.push(format!("`{line}` first in {name:?}"));
        self.put_run_in_block(name);
        let (at, _) = self.key(name, "run").expect("a step that runs");
        self.lines.insert(at + 1, format!("          {line}"));
    }

    /// Puts a line last among the commands of a step.
    fn append_to_run(&mut self, name: &str, line: &str) {
        self.changes.push(format!("`{line}` last in {name:?}"));
        self.put_run_in_block(name);
        let (_, commands) = self.step(name);
        let last = commands.last().expect("a command").last;
        self.lines.insert(last + 1, format!("          {line}"));
    }

    /// Puts lines before and after the command of a step that starts with `start`.
    fn wrap(&mut self, name: &str, start: &str, before: &[&str], after: &[&str]) {
        self.changes.push(format!(
            "{before:?} and {after:?} around the command in {name:?}"
        ));
        self.put_run_in_block(name);
        let command = self.command(name, start);
        let pad = " ".repeat(indent(&self.lines[command.first]));
        for line in after.iter().rev() {
            self.lines.insert(command.last + 1, format!("{pad}{line}"));
        }
        for line in before.iter().rev() {
            self.lines.insert(command.first, format!("{pad}{line}"));
        }
    }

    /// Puts text at the end of the command of a step that starts with `start`.
    fn append_to_command(&mut self, name: &str, start: &str, suffix: &str) {
        self.changes
            .push(format!("`{suffix}` after the command in {name:?}"));
        let command = self.command(name, start);
        self.lines[command.last].push_str(suffix);
    }

    /// Takes the command of a step that starts with `start` out of it.
    fn remove_command(&mut self, name: &str, start: &str) {
        self.changes
            .push(format!("the command taken out of {name:?}"));
        let command = self.command(name, start);
        self.lines.drain(command.first..=command.last);
    }

    /// Replaces text in one line of a step.
    fn replace_in_step(&mut self, name: &str, old: &str, new: &str) {
        self.changes.push(format!("{old:?} is {new:?} in {name:?}"));
        let (range, _) = self.step(name);
        let hits: Vec<usize> = range.filter(|&at| self.lines[at].contains(old)).collect();
        assert_eq!(hits.len(), 1, "{old:?} in {name:?}");
        self.lines[hits[0]] = self.lines[hits[0]].replacen(old, new, 1);
    }

    fn remove_step(&mut self, name: &str) {
        self.changes.push(format!("{name:?} removed"));
        let (range, _) = self.step(name);
        self.lines.drain(range);
    }

    /// Puts lines in at a line.
    fn insert_at(&mut self, at: usize, lines: impl IntoIterator<Item = String>) {
        let tail = self.lines.split_off(at);
        self.lines.extend(lines);
        self.lines.extend(tail);
    }

    /// Puts a step after another.
    fn insert_step_after(&mut self, name: &str, step: &[&str]) {
        self.changes.push(format!("a step after {name:?}"));
        let (range, _) = self.step(name);
        self.insert_at(range.end, step.iter().map(|line| (*line).to_owned()));
    }

    /// Puts a step before another.
    fn insert_step_before(&mut self, name: &str, step: &[&str]) {
        self.changes.push(format!("a step before {name:?}"));
        let (range, _) = self.step(name);
        self.insert_at(range.start, step.iter().map(|line| (*line).to_owned()));
    }

    /// Moves a step to before another.
    fn move_step_before(&mut self, name: &str, before: &str) {
        self.changes.push(format!("{name:?} before {before:?}"));
        let (range, _) = self.step(name);
        let moved: Vec<String> = self.lines.drain(range).collect();
        let (target, _) = self.step(before);
        self.insert_at(target.start, moved);
    }

    /// Puts a line after the last line of the job that has the step.
    fn append_to_job_of(&mut self, name: &str, line: &str) {
        self.changes
            .push(format!("`{line}` at the end of the job of {name:?}"));
        let text = self.text();
        let workflow = Workflow::parse(&text);
        let range = workflow.jobs[workflow.find(name).expect("a step").job]
            .range
            .clone();
        let last = range
            .rev()
            .find(|&at| is_code(workflow.lines[at]))
            .expect("a line");
        self.lines.insert(last + 1, line.to_owned());
    }

    /// Changes the shell a workflow runs its steps with by default.
    fn set_default_shell(&mut self, shell: &str) {
        self.changes.push(format!("the default shell is `{shell}`"));
        let is_shell = |line: &String| pair(line).is_some_and(|(key, _)| key == "shell");
        let at = self
            .lines
            .iter()
            .position(is_shell)
            .expect("a default shell");
        self.lines[at] = format!("    shell: {shell}");
    }

    /// Puts a line under line `at` that goes on from it: indented further than it.
    fn continue_line(&mut self, at: usize) {
        self.changes
            .push(format!("line {} goes on to the next line", at + 1));
        let pad = " ".repeat(indent(&self.lines[at]) + 2);
        self.lines.insert(at + 1, format!("{pad}|| true"));
    }

    /// Makes the value of a key of a step go on to the next line.
    fn continue_key(&mut self, name: &str, key: &str) {
        let (at, _) = self
            .key(name, key)
            .unwrap_or_else(|| panic!("no key {key:?} in {name:?}"));
        self.continue_line(at);
    }

    /// Makes the `path` of a step go on to the next line.
    fn continue_path(&mut self, name: &str) {
        let (range, _) = self.step(name);
        let text = self.text();
        let (at, _) = Workflow::parse(&text)
            .with_value(&range, "path")
            .unwrap_or_else(|| panic!("no path in {name:?}"));
        self.continue_line(at);
    }

    /// Makes the default shell go on to the next line.
    fn continue_default_shell(&mut self) {
        let is_shell = |line: &String| pair(line).is_some_and(|(key, _)| key == "shell");
        let at = self
            .lines
            .iter()
            .position(is_shell)
            .expect("a default shell");
        self.continue_line(at);
    }

    /// Asserts that the case does not refuse the workflow so changed by this rule.
    fn is_not_refused_as(&self, refusal: Refusal) {
        let found = problems_in(self.workflow, &self.text());
        assert!(
            found.iter().all(|problem| problem.refusal != refusal),
            "{}: {} was refused as {refusal:?}; the case found:\n{}",
            self.workflow,
            self.changes.join(", "),
            describe(self.workflow, &found)
        );
    }

    /// Asserts that the case refuses the workflow so changed, by this rule.
    fn is_refused_as(&self, refusal: Refusal) {
        let found = problems_in(self.workflow, &self.text());
        assert!(
            found.iter().any(|problem| problem.refusal == refusal),
            "{}: {} was not refused as {refusal:?}; the case found:\n{}",
            self.workflow,
            self.changes.join(", "),
            describe(self.workflow, &found)
        );
    }
}

/// The steps of the workflows that scan or seal, with what each has to be.
fn guards() -> impl Iterator<Item = (&'static str, &'static str, &'static Guard)> {
    GUARDS
        .iter()
        .map(|(file, step, guard)| (*file, *step, guard))
}

const AN_UPLOAD: [&str; 4] = [
    "      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
    "        with:",
    "          name: early",
    "          path: .",
];

const A_NAMED_UPLOAD: [&str; 5] = [
    "      - name: Keep what is there before the scan",
    "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1",
    "        with:",
    "          name: early",
    "          path: .",
];

/// KR-REQ-26.41: a step that keeps or uploads what a job assembled is refused when it comes before
/// the scan, when it can run after the scan failed, or when the case does not know it, named or not.
#[test]
fn a_workflow_that_keeps_what_a_failed_scan_refused_is_refused() {
    for (workflow, scan, kept) in KEPT {
        for step in kept {
            for condition in [
                "always()",
                "${{ always() && runner.os == 'Linux' }}",
                "failure()",
                "${{ cancelled() }}",
                "${{ !cancelled() }}",
                "${{ !success() }}",
            ] {
                let mut mutant = Mutant::of(workflow);
                mutant.set_key(step, "if", condition);
                mutant.is_refused_as(Refusal::KeptOnFailure);
            }
            // The control: the status a step without a condition has is not a failure.
            for condition in ["success()", "${{ success() && runner.os == 'Linux' }}"] {
                let mut mutant = Mutant::of(workflow);
                mutant.set_key(step, "if", condition);
                mutant.is_not_refused_as(Refusal::KeptOnFailure);
            }
            let mut mutant = Mutant::of(workflow);
            mutant.move_step_before(step, scan);
            mutant.is_refused_as(Refusal::KeptBeforeScan);
        }
    }
    for (workflow, step, _) in guards() {
        for upload in [&AN_UPLOAD[..], &A_NAMED_UPLOAD[..]] {
            let mut mutant = Mutant::of(workflow);
            mutant.insert_step_before(step, upload);
            mutant.is_refused_as(Refusal::UnknownUpload);
        }
    }
}

/// KR-REQ-26.41: a step that keeps more than its scan read is refused: an upload from a wider path,
/// and the command that packs the tree from another place.
#[test]
fn a_step_that_keeps_more_than_its_scan_read_is_refused() {
    for (workflow, step, holds) in &HOLDS {
        let mut mutant = Mutant::of(workflow);
        match holds {
            Holds::Path(path) => {
                mutant.replace_in_step(step, &format!("path: {path}"), "path: ${{ runner.temp }}");
            }
            Holds::Command(command) => {
                mutant.replace_in_step(
                    step,
                    command,
                    &command.replacen("$RUNNER_TEMP", "$HOME", 1),
                );
            }
        }
        mutant.is_refused_as(Refusal::KeptPath);
    }
}

/// KR-REQ-26.41: a value of `run`, `shell`, `if` or `path` that goes on to the next line is refused
/// in a job that scans, and so is a default shell that does. The case reads the first line of a
/// value, and YAML reads the lines under it as part of it.
#[test]
fn a_value_that_goes_on_to_the_next_line_is_refused() {
    for (workflow, step, guard) in guards() {
        for key in ["shell", "if"] {
            let mut mutant = Mutant::of(workflow);
            mutant.set_key(step, key, "bash");
            mutant.continue_key(step, key);
            mutant.is_refused_as(Refusal::Continued);
        }
        if matches!(guard, Guard::Scan(_, true)) {
            let mut mutant = Mutant::of(workflow);
            mutant.continue_key(step, "run");
            mutant.is_refused_as(Refusal::Continued);
        }
    }
    for (workflow, _, kept) in KEPT {
        for step in kept {
            let mut mutant = Mutant::of(workflow);
            mutant.set_key(step, "if", "success()");
            mutant.continue_key(step, "if");
            mutant.is_refused_as(Refusal::Continued);
        }
    }
    for (workflow, step, holds) in &HOLDS {
        if matches!(holds, Holds::Path(_)) {
            let mut mutant = Mutant::of(workflow);
            mutant.continue_path(step);
            mutant.is_refused_as(Refusal::Continued);
        }
    }
    for workflow in [
        "release-tree.yml",
        "release-host.yml",
        "release-windows.yml",
    ] {
        let mut mutant = Mutant::of(workflow);
        mutant.continue_default_shell();
        mutant.is_refused_as(Refusal::Continued);
    }
}

/// KR-REQ-26.41: a branch that ends on its own line, before a scan or a sealing, does not hide it.
#[test]
fn a_branch_that_ends_on_its_line_before_a_scan_is_not_taken_for_one_that_hides_it() {
    for (workflow, step, guard) in guards() {
        if !matches!(guard, Guard::Scan(_, true)) {
            let mut mutant = Mutant::of(workflow);
            mutant.wrap(
                step,
                guard.start(),
                &["if [ ! -d x ]; then mkdir -p x; fi"],
                &[],
            );
            mutant.is_not_refused_as(Refusal::Skippable);
        }
    }
}

/// KR-REQ-26.41: a scan or a sealing of any other path than the one the case names is refused, and
/// so is a workflow that runs a scan or a sealing the case does not know, or no longer runs one it
/// does.
#[test]
fn a_workflow_that_scans_another_path_or_another_step_is_refused() {
    for (workflow, step, guard) in guards() {
        let start = guard.start();
        let mut narrower = Mutant::of(workflow);
        let mut elsewhere = Mutant::of(workflow);
        match guard {
            Guard::Scan(command, _) => {
                let path = command[start.len()..].trim_end_matches('"');
                narrower.replace_in_step(step, command, &format!("{start}{path}/bin\""));
                elsewhere.replace_in_step(step, command, &format!("{start}\"$RUNNER_TEMP/else\""));
            }
            Guard::Seal(tree) => {
                let flag = format!("--tree {tree}");
                let path = tree.trim_end_matches('"');
                narrower.replace_in_step(step, &flag, &format!("--tree {path}/bin\""));
                elsewhere.replace_in_step(step, &flag, "--tree \"$RUNNER_TEMP/else\"");
            }
        }
        narrower.is_refused_as(Refusal::Target);
        elsewhere.is_refused_as(Refusal::Target);

        let mut removed = Mutant::of(workflow);
        removed.remove_step(step);
        removed.is_refused_as(Refusal::Unregistered);
        if matches!(guard, Guard::Scan(_, false)) {
            let mut gone = Mutant::of(workflow);
            gone.remove_command(step, start);
            gone.is_refused_as(Refusal::Unregistered);
        }
        for command in [
            r#"python3 scripts/check-release-secrets.py scan "$RUNNER_TEMP/other""#,
            "bash scripts/seal-release-tree.sh --tree other",
        ] {
            let mut another = Mutant::of(workflow);
            another.insert_step_after(
                step,
                &["      - name: Another", &format!("        run: {command}")],
            );
            another.is_refused_as(Refusal::Unregistered);
        }
    }
}

/// KR-REQ-26.41: a scan or a sealing that can fail without stopping its step is refused: a step
/// that is optional or conditional in any spelling of its keys, with a shell that does not stop at
/// a failure, with `set +` in any form, or joined to another command; and so is one that sits where
/// it can be skipped, and a job that is optional wherever the key stands in it.
#[test]
fn a_scan_that_can_fail_without_stopping_its_step_is_refused() {
    for (workflow, step, guard) in guards() {
        let start = guard.start();
        for key in [
            "continue-on-error",
            "\"continue-on-error\"",
            "'continue-on-error'",
        ] {
            let mut mutant = Mutant::of(workflow);
            mutant.set_key(step, key, "true");
            mutant.is_refused_as(Refusal::Optional);
        }
        let mut conditional = Mutant::of(workflow);
        conditional.set_key(step, "if", "${{ false }}");
        conditional.is_refused_as(Refusal::Optional);
        let mut other = Mutant::of(workflow);
        other.set_key(step, "working-directory", "/");
        other.is_refused_as(Refusal::StepKey);
        for line in [
            "    continue-on-error: true",
            "    \"continue-on-error\": true",
        ] {
            let mut mutant = Mutant::of(workflow);
            mutant.append_to_job_of(step, line);
            mutant.is_refused_as(Refusal::JobOptional);
        }

        for shell in ["bash {0}", "bash --noprofile --norc {0}", "sh", "pwsh"] {
            let mut mutant = Mutant::of(workflow);
            mutant.set_key(step, "shell", shell);
            mutant.is_refused_as(Refusal::Shell);
        }
        let mut environment = Mutant::of(workflow);
        environment.set_key(step, "env", "{BASH_ENV: /tmp/start}");
        environment.is_refused_as(Refusal::Shell);
        for line in [
            "set +e",
            "set +o errexit",
            "set +xe",
            "set  +e",
            "set -x +e",
        ] {
            let mut mutant = Mutant::of(workflow);
            mutant.prepend_to_run(step, line);
            mutant.is_refused_as(Refusal::ErrexitOff);
        }

        for suffix in [" || true", "; true", " &", " && true", " | cat"] {
            let mut mutant = Mutant::of(workflow);
            mutant.append_to_command(step, start, suffix);
            mutant.is_refused_as(Refusal::Joined);
        }
        for line in ["true ||", "true || \\", "test -d . &&", "cat |"] {
            let mut mutant = Mutant::of(workflow);
            mutant.wrap(step, start, &[line], &[]);
            mutant.is_refused_as(Refusal::Joined);
        }

        let wraps: [(&str, &[&str]); 8] = [
            ("if false; then", &["fi"]),
            ("while false; do", &["done"]),
            ("{", &["}"]),
            ("(", &[")"]),
            ("cat <<'EOF' > /dev/null", &["EOF"]),
            ("exit 0", &[]),
            ("return 0", &[]),
            ("trap 'true' EXIT", &[]),
        ];
        for (before, after) in wraps {
            let mut mutant = Mutant::of(workflow);
            mutant.wrap(step, start, &[before], after);
            mutant.is_refused_as(Refusal::Skippable);
        }
        if matches!(guard, Guard::Scan(..)) {
            let mut counted = Mutant::of(workflow);
            counted.wrap(step, start, &["for once in 1; do"], &["done"]);
            counted.is_refused_as(Refusal::Skippable);
        }
        if matches!(guard, Guard::Scan(_, true)) {
            let mut before = Mutant::of(workflow);
            before.prepend_to_run(step, "echo before");
            before.is_refused_as(Refusal::NotAlone);
            let mut after = Mutant::of(workflow);
            after.append_to_run(step, "echo after");
            after.is_refused_as(Refusal::NotAlone);
        }
    }
    for (workflow, shell) in [
        ("release-tree.yml", "bash {0}"),
        ("release-host.yml", "bash {0}"),
        ("release-windows.yml", "pwsh {0}"),
    ] {
        let mut mutant = Mutant::of(workflow);
        mutant.set_default_shell(shell);
        mutant.is_refused_as(Refusal::Shell);
    }
}
