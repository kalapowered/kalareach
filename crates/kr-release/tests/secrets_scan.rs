//! No private key reaches a repository, a release tree or a release archive.
//!
//! A release's private keys are made in the environment that signs it and nowhere else, so what a
//! release build assembles is scanned for a key before it is signed, packed or kept
//! (`scripts/check-release-secrets.py`), and the repository's own tracked files are held to the
//! same scan. The scan runs here as the release workflows run it.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The repository's root.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Runs the scan's script with `arguments`, from the repository's root.
fn scan_script(arguments: &[&str]) -> Output {
    Command::new("python3")
        .arg("-I")
        .arg(root().join("scripts/check-release-secrets.py"))
        .args(arguments)
        .current_dir(root())
        .output()
        .expect("python3 runs the scan")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A private key in PEM, written as the text a key file holds. It is put together here, so that this
/// source file carries no header of its own for the scan of the repository's files to find.
fn a_private_key() -> String {
    let header = ["-----BEGIN ", "EC ", "PRIVATE KEY", "-----"].concat();
    let footer = ["-----END ", "EC ", "PRIVATE KEY", "-----"].concat();
    let body = "MHcCAQEEIHkTf2xN0cVQp8mZr1o3uYb6LwA9dEjK4sGtXnPqRvUyoAoGCCqGSM49";
    format!("{header}\n{body}\n{footer}\n")
}

/// A release tree of the shape a build assembles: programs, a share directory and a manifest.
fn a_release_tree(parent: &Path) -> PathBuf {
    let tree = parent.join("kalareach-x86_64-unknown-linux-gnu-0.0.0");
    std::fs::create_dir_all(tree.join("bin")).expect("bin");
    std::fs::create_dir_all(tree.join("share")).expect("share");
    std::fs::write(tree.join("bin/kr"), b"\x7fELF an ordinary program").expect("a program");
    std::fs::write(tree.join("share/LICENSE"), "A licence.\n").expect("a licence");
    std::fs::write(tree.join("release.json"), "{\"signed\":{}}\n").expect("a manifest");
    tree
}

/// KR-REQ-26.41: the scan finds each kind of secret it names in a directory, an archive and a
/// nested archive, passes the near misses, and finds nothing in this repository's tracked files.
#[test]
fn the_scan_finds_what_it_names_and_the_repository_holds_none() {
    let output = scan_script(&["self-test"]);
    assert!(
        output.status.success(),
        "the scan's own cases failed: {}",
        stderr_of(&output)
    );
}

/// KR-REQ-26.41: a release tree that holds a private key is refused, and so is the archive made
/// from it; the same tree without the key passes both.
#[test]
fn a_release_tree_and_its_archive_with_a_private_key_in_them_are_refused() {
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let tree = a_release_tree(scratch.path());
    let archive = scratch.path().join("release.tar.gz");
    let pack = |tree: &Path| {
        let status = Command::new("tar")
            .arg("-C")
            .arg(tree.parent().expect("a parent"))
            .arg("-czf")
            .arg(&archive)
            .arg(tree.file_name().expect("a name"))
            .status()
            .expect("tar packs the tree");
        assert!(status.success(), "tar did not pack the tree");
    };

    // The control: the tree a build assembles, and the archive made from it, are clean.
    let clean_tree = scan_script(&["scan", tree.to_str().expect("a path")]);
    assert!(clean_tree.status.success(), "{}", stderr_of(&clean_tree));
    pack(&tree);
    let clean_archive = scan_script(&["scan", archive.to_str().expect("a path")]);
    assert!(
        clean_archive.status.success(),
        "{}",
        stderr_of(&clean_archive)
    );

    // A key left among the files of the tree is found, and named by its path.
    std::fs::write(tree.join("share/signing.pem"), a_private_key()).expect("a planted key");
    let refused_tree = scan_script(&["scan", tree.to_str().expect("a path")]);
    assert!(
        !refused_tree.status.success(),
        "a tree with a private key in it passed"
    );
    assert!(
        stderr_of(&refused_tree).contains("signing.pem"),
        "the refusal names the file: {}",
        stderr_of(&refused_tree)
    );

    // The archive made from it is refused too, however it is named.
    pack(&tree);
    let refused_archive = scan_script(&["scan", archive.to_str().expect("a path")]);
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

/// KR-REQ-26.41: each release build runs the scan over what it assembles, before the result is
/// signed, packed or kept: the tree and the archive of the macOS, Linux and Windows builds, and the
/// script that seals a tree.
#[test]
fn every_release_build_scans_what_it_assembles() {
    for file in [
        ".github/workflows/release-tree.yml",
        ".github/workflows/release-host.yml",
        ".github/workflows/release-windows.yml",
        "scripts/seal-release-tree.sh",
    ] {
        let path = root().join(file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        assert!(
            text.lines().any(|line| {
                let line = line.trim_start();
                !line.starts_with('#')
                    && line.contains("check-release-secrets.py")
                    && line.contains(" scan ")
            }),
            "{file} runs no scan for a private key"
        );
    }
}
