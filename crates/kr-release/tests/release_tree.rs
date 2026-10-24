//! The manifest of a release tree names what its shell packages are made of, and a tree that
//! disagrees with the repository's pins is refused before anything is signed.
//!
//! The trees are made of the shell packages this checkout built, which an ordinary run does not
//! have, so the cases are left out of one; a run that built the packages runs them with
//! `--include-ignored`. The programs in `bin/` are stand-ins, since the manifest lists what a file
//! is and not what it does.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use kr_protocol::update::{FileMode, ReleaseManifest};
use kr_release::assemble::{Inputs, assemble};

const COMMIT: &str = "4254aa6e62e585478ff8dcff5518f23c7263f4ce";

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn target() -> &'static str {
    match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        other => panic!("no release target for {other:?}"),
    }
}

fn floor() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos=14.0"
    } else {
        "glibc=2.35"
    }
}

/// Where the packages this checkout built are.
fn package_root() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KR_SHELL_PREFIX") {
        return PathBuf::from(explicit);
    }
    let home = PathBuf::from(std::env::var_os("HOME").unwrap_or_default());
    if cfg!(target_os = "macos") {
        home.join("Library/Caches/kalareach/shells")
    } else if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(xdg).join("kalareach/shells")
    } else {
        home.join(".cache/kalareach/shells")
    }
}

/// Copies a directory, every file as a file of its own and no empty directory: a package's build
/// names one binary twice and leaves directories it never filled, and a release holds neither.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("a directory to copy") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        let kind = entry.file_type().expect("a type");
        if kind.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if kind.is_file() {
            std::fs::copy(entry.path(), &target).expect("a copy");
        }
    }
    if std::fs::read_dir(to).expect("the copy").next().is_none() {
        std::fs::remove_dir(to).expect("an empty directory goes");
    }
}

/// The directory of a tree and the keys that sign for its root.
struct Release {
    directory: tempfile::TempDir,
}

impl Release {
    fn tree(&self) -> PathBuf {
        self.directory.path().join("release")
    }

    fn keys(&self) -> PathBuf {
        self.directory.path().join("keys")
    }
}

/// A tree of the shells this checkout built, programs that are stand-ins and a channel root of this
/// run's own, assembled by the script a release is built with.
fn tree_of() -> Release {
    let release = Release {
        directory: tempfile::Builder::new()
            .prefix("kr-release-tree-")
            .tempdir()
            .expect("a directory"),
    };
    let programs = release.directory.path().join("programs");
    std::fs::create_dir_all(&programs).expect("programs");
    for program in kr_protocol::update::required_programs(target()) {
        std::fs::write(programs.join(program), format!("#!/bin/sh\n# {program}\n"))
            .expect("a program");
    }
    let made = kr_release_binary(&["dev-keys", "--out", release.keys().to_str().expect("utf-8")]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let built = Command::new("bash")
        .arg(checkout().join("scripts/build-release.sh"))
        .args(["--target", target(), "--release", "0.1.0+4254aa6e62e5"])
        .args(["--sequence", "3", "--commit", COMMIT, "--floor", floor()])
        .arg("--programs")
        .arg(&programs)
        .arg("--shells")
        .arg(package_root())
        .arg("--root")
        .arg(release.keys().join("root.json"))
        .arg("--out")
        .arg(release.tree())
        .arg("--kr-release")
        .arg(env!("CARGO_BIN_EXE_kr-release"))
        .output()
        .expect("the script runs");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    release
}

fn kr_release_binary(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kr-release"))
        .args(arguments)
        .output()
        .expect("kr-release runs")
}

fn manifest_arguments(tree: &Path) -> Vec<String> {
    manifest_arguments_for(tree, target(), floor())
}

fn manifest_arguments_for(tree: &Path, target: &str, floor: &str) -> Vec<String> {
    [
        "manifest",
        "--tree",
        tree.to_str().expect("utf-8"),
        "--checkout",
        checkout().to_str().expect("utf-8"),
        "--release",
        "0.1.0+4254aa6e62e5",
        "--sequence",
        "3",
        "--commit",
        COMMIT,
        "--target",
        target,
        "--floor",
        floor,
    ]
    .iter()
    .map(|argument| (*argument).to_owned())
    .collect()
}

fn run(arguments: &[String]) -> Output {
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    kr_release_binary(&borrowed)
}

fn manifest_of(tree: &Path) -> ReleaseManifest {
    let document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tree.join("release.json")).expect("release.json"))
            .expect("JSON");
    serde_json::from_value(document["signed"].clone()).expect("a manifest")
}

fn why(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn packages() -> Vec<&'static str> {
    ["bash", "fish", "zsh"]
        .into_iter()
        .filter(|shell| package_root().join(shell).join("current").is_file())
        .collect()
}

fn inputs(tree: &Path) -> Inputs {
    Inputs {
        tree: tree.to_path_buf(),
        checkout: checkout(),
        release: kr_protocol::update::ReleaseName::new("0.1.0+4254aa6e62e5").expect("a name"),
        sequence: 3,
        commit: kr_protocol::update::CommitId::new(COMMIT).expect("a commit"),
        target: target().to_owned(),
        os_floor: kr_protocol::update::OsFloor {
            system: if cfg!(target_os = "macos") {
                kr_protocol::update::FloorSystem::Macos
            } else {
                kr_protocol::update::FloorSystem::Glibc
            },
            version: kr_protocol::update::FloorVersion::leading(
                floor().split_once('=').expect("a floor").1,
            )
            .expect("a version"),
        },
    }
}

/// KR-REQ-07.38: the manifest of a tree names, for each shell package, the pins of
/// the shell and the identity the build recorded; the unedited tree passes, which is the control
/// of the refusals below.
#[test]
#[ignore = "builds a tree of this checkout's shell packages; it runs with --include-ignored where they are built"]
fn the_manifest_of_a_tree_names_the_pins_and_the_identity_the_build_recorded() {
    let shells = packages();
    assert_eq!(shells.len(), 3, "a release carries Zsh, Bash and Fish");
    let release = tree_of();
    let manifest = assemble(&inputs(&release.tree())).expect("the unedited tree passes");

    assert_eq!(manifest.shells.len(), shells.len());
    for (listed, shell) in manifest.shells.iter().zip(&shells) {
        let pins: serde_json::Value = serde_json::from_slice(
            &std::fs::read(checkout().join("shells").join(shell).join("manifest.json"))
                .expect("pins"),
        )
        .expect("pins");
        let recorded =
            std::fs::read_to_string(release.tree().join("shells").join(shell).join("current"))
                .expect("the pointer");
        assert_eq!(listed.shell, *shell);
        assert_eq!(
            listed.identity,
            recorded.trim(),
            "the identity the build recorded"
        );
        let upstream = listed
            .upstream
            .as_ref()
            .expect("the package states its upstream");
        assert_eq!(upstream.version, pins["upstream"]["version"]);
        assert_eq!(upstream.revision, pins["upstream"]["revision"]);
        assert_eq!(upstream.archive, pins["upstream"]["archive"]);
        let pinned = pins["patches"].as_array().expect("patches");
        assert_eq!(listed.patches.len(), pinned.len());
        // The release before package managers reads the package by these alone.
        assert_eq!(
            listed.patch_revisions,
            pinned
                .iter()
                .map(|pin| pin["revision"].as_str().expect("a revision").to_owned())
                .collect::<Vec<_>>()
        );
        for (patch, pin) in listed.patches.iter().zip(pinned) {
            assert_eq!(patch.name, pin["name"]);
            assert_eq!(patch.revision, pin["revision"]);
            assert_eq!(patch.base_revision, pins["upstream"]["revision"]);
            assert_eq!(
                patch.source_commit.as_deref(),
                pin["upstream_revision"].as_str()
            );
        }
        assert!(!listed.sources.is_empty());
        assert!(!listed.profile_order.is_empty());
        for module in &listed.modules {
            assert!(release.tree().join(module.search_path.as_str()).is_dir());
            assert_eq!(module.editor_abi, pins["editor_abi"]);
        }
    }
    // A patch whose source is a published upstream change keeps it apart from its base: the
    // official patches of the pinned Bash release name themselves as their source.
    if let Some(bash) = manifest.shells.iter().find(|listed| listed.shell == "bash") {
        let official = bash
            .patches
            .iter()
            .find(|patch| patch.name == "bash53-011")
            .expect("the official patch");
        assert_eq!(official.source_commit.as_deref(), Some("bash53-011"));
        assert_eq!(official.base_revision, "bash-5.3");
    }

    // The daemon's own protocol and public majors, which nothing in the tree states.
    assert_eq!(
        manifest.protocol_version,
        kr_protocol::hello::PACKAGE_VERSION
    );
    let majors: Vec<u16> = kr_protocol::hello::PUBLIC_MAJORS
        .iter()
        .filter(|row| !row.retired)
        .map(|row| row.major)
        .collect();
    assert_eq!(manifest.public_majors, majors);
    assert!(
        manifest
            .public_majors
            .contains(&kr_protocol::retained::stated_protocol().major),
        "the major the daemon states is one the manifest lists"
    );

    // Programs are the files the release says run; the rest of the tree does not.
    for file in &manifest.files {
        let program = file.path.as_str().starts_with("bin/")
            || file.path.as_str().split('/').nth(3) == Some("bin");
        assert_eq!(file.mode == FileMode::Executable, program, "{}", file.path);
    }
}

/// KR-REQ-07.38, KR-REQ-07.86: a tree is refused before it is signed when a package disagrees with
/// the pins or the checkout, and for a file a release does not hold.
#[test]
#[ignore = "builds a tree of this checkout's shell packages; it runs with --include-ignored where they are built"]
fn a_tree_that_disagrees_with_the_pins_is_refused_before_it_is_signed() {
    assert!(
        packages().contains(&"zsh"),
        "the Zsh package is not built here"
    );
    let shell = "zsh";
    let record_of = |release: &Release| {
        let identity =
            std::fs::read_to_string(release.tree().join("shells").join(shell).join("current"))
                .expect("the pointer");
        release
            .tree()
            .join("shells")
            .join(shell)
            .join(identity.trim())
            .join("kr-shell-identity.json")
    };
    let edit_record = |release: &Release, edit: &dyn Fn(&mut serde_json::Value)| {
        let path = record_of(release);
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("a record")).expect("a record");
        edit(&mut record);
        std::fs::write(path, record.to_string()).expect("the record");
    };

    // A patch revision other than the pin's.
    let release = tree_of();
    edit_record(&release, &|record| {
        record["shell"]["patches"][0]["revision"] = serde_json::json!("other");
    });
    let refused = assemble(&inputs(&release.tree())).expect_err("a patch of another revision");
    assert!(refused.to_string().contains("reader patch"), "{refused}");

    // An upstream archive other than the pin's.
    let release = tree_of();
    edit_record(&release, &|record| {
        record["build"]["upstream"]["sha256"] = serde_json::json!("0".repeat(64));
    });
    let refused = assemble(&inputs(&release.tree())).expect_err("another archive");
    assert!(
        refused.to_string().contains("upstream archive"),
        "{refused}"
    );

    // A build of other inputs than the checkout holds.
    let release = tree_of();
    edit_record(&release, &|record| {
        let inputs = record["build"]["inputs"]
            .as_str()
            .expect("inputs")
            .replacen("script=", "script=0000", 1);
        record["build"]["inputs"] = serde_json::json!(inputs);
    });
    let refused = assemble(&inputs(&release.tree())).expect_err("other inputs");
    assert!(refused.to_string().contains("other inputs"), "{refused}");

    // A startup entry that is not the checkout's: the profile the shell runs is edited.
    let release = tree_of();
    let entry = record_of(&release).parent().expect("the package").join(
        serde_json::from_slice::<serde_json::Value>(
            &std::fs::read(record_of(&release)).expect("a record"),
        )
        .expect("a record")["startup_entry"]["file"]
            .as_str()
            .expect("an entry"),
    );
    let mut edited = std::fs::read_to_string(&entry).expect("the entry");
    edited.push_str("exec kr\n");
    std::fs::write(&entry, edited).expect("the entry");
    let refused = assemble(&inputs(&release.tree())).expect_err("an edited entry");
    assert!(refused.to_string().contains("startup entry"), "{refused}");

    // The stable copy of the startup entry, which an installed host's startup files source: edited
    // after the script copied it, though the package's own copy is the checkout's.
    let release = tree_of();
    let stable = release.tree().join("shells/zsh/kr-zshrc.zsh");
    let mut edited = std::fs::read_to_string(&stable).expect("the stable entry");
    edited.push_str("exec kr\n");
    std::fs::write(&stable, edited).expect("the stable entry");
    let refused = assemble(&inputs(&release.tree())).expect_err("an edited stable entry");
    assert!(
        refused.to_string().contains("stable startup entry"),
        "{refused}"
    );

    // A package that states no module, with its module directory in place: the pins name one.
    let release = tree_of();
    edit_record(&release, &|record| {
        record["shell"]["modules"] = serde_json::json!([]);
    });
    let refused = assemble(&inputs(&release.tree())).expect_err("no module stated");
    assert!(refused.to_string().contains("modules"), "{refused}");

    // A Unix release that lacks one of the three shell packages.
    let release = tree_of();
    std::fs::remove_dir_all(release.tree().join("shells/bash")).expect("a package goes");
    let refused = assemble(&inputs(&release.tree())).expect_err("a package short");
    assert!(refused.to_string().contains("packages"), "{refused}");

    // A module directory that is not there.
    let release = tree_of();
    let package = record_of(&release)
        .parent()
        .expect("the package")
        .to_path_buf();
    let recorded: serde_json::Value =
        serde_json::from_slice(&std::fs::read(record_of(&release)).expect("a record"))
            .expect("a record");
    if let Some(module) = recorded["shell"]["modules"]
        .as_array()
        .and_then(|list| list.first())
    {
        let search = PathBuf::from(module["search_path"].as_str().expect("a path"));
        let relative = search
            .components()
            .skip_while(|part| {
                part.as_os_str() != recorded["identity"].as_str().expect("an identity")
            })
            .skip(1)
            .collect::<PathBuf>();
        // The directory and the ones that held only it: a release holds no empty directory.
        let top = relative.components().next().expect("a directory");
        std::fs::remove_dir_all(package.join(top)).expect("the module directory goes");
        let refused = assemble(&inputs(&release.tree())).expect_err("no module directory");
        assert!(
            refused.to_string().contains("module directory"),
            "{refused}"
        );
    }

    // A module searched for in another directory of the package than the pins name, one that holds
    // a file: the shell's module directory is still there, and it is not the one searched.
    let release = tree_of();
    edit_record(&release, &|record| {
        let search = record["shell"]["modules"][0]["search_path"]
            .as_str()
            .expect("a path")
            .to_owned();
        let (package, _) = search
            .rsplit_once("/lib/")
            .expect("the record names a directory under the package's lib");
        let moved = format!("{package}/bin");
        assert_ne!(moved, search, "the record names the pinned directory");
        record["shell"]["modules"][0]["search_path"] = serde_json::json!(moved);
    });
    let refused = assemble(&inputs(&release.tree())).expect_err("another module directory");
    assert!(refused.to_string().contains("the pins name"), "{refused}");

    // A file with a second name, and a link.
    let release = tree_of();
    std::fs::hard_link(
        release.tree().join("bin/kr"),
        release.tree().join("share/kr-again"),
    )
    .expect("a hard link");
    let refused = assemble(&inputs(&release.tree())).expect_err("a hard link");
    assert!(refused.to_string().contains("names"), "{refused}");
    let release = tree_of();
    std::os::unix::fs::symlink("kr", release.tree().join("bin/kr-link")).expect("a link");
    let refused = assemble(&inputs(&release.tree())).expect_err("a link");
    assert!(refused.to_string().contains("link"), "{refused}");
}

/// KR-REQ-07.86: the shipped Zsh started from a copy of the release tree finds its module
/// directory through the search path the manifest names, and a `release.json` whose profile order
/// was edited after it was written is not signed.
#[test]
#[ignore = "builds a tree of this checkout's shell packages; it runs with --include-ignored where they are built"]
fn a_relocated_tree_finds_its_modules_through_the_search_path_the_manifest_names() {
    assert!(
        packages().contains(&"zsh"),
        "the Zsh package is not built here"
    );
    let release = tree_of();
    let written = run(&manifest_arguments(&release.tree()));
    assert!(written.status.success(), "{}", why(&written));
    let manifest = manifest_of(&release.tree());
    let zsh = manifest
        .shells
        .iter()
        .find(|listed| listed.shell == "zsh")
        .expect("the Zsh package");
    let module = &zsh.modules[0];

    let elsewhere = tempfile::Builder::new()
        .prefix("kr-relocated-release-")
        .tempdir()
        .expect("a directory");
    let moved = elsewhere.path().join("versions").join("release-2");
    copy_tree(&release.tree(), &moved);
    let identity = &zsh.identity;
    let told = Command::new(moved.join("shells/zsh").join(identity).join("bin/zsh"))
        .args(["-f", "-c", "print -r -- \"module_path=$module_path[1]\"; zmodload zsh/zle && print -r -- zle=loaded"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("zsh starts");
    let said = String::from_utf8_lossy(&told.stdout).into_owned();
    let moved = moved.canonicalize().expect("the copy");
    assert!(
        said.contains(&format!(
            "module_path={}",
            moved.join(module.search_path.as_str()).display()
        )),
        "the module path names the moved tree's directory: {said}\n{}",
        String::from_utf8_lossy(&told.stderr)
    );
    assert!(said.contains("zle=loaded"), "{said}");

    // A profile order edited after the manifest was written is not what the tree makes.
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(release.tree().join("release.json")).expect("json"))
            .expect("json");
    let position = manifest
        .shells
        .iter()
        .position(|listed| listed.shell == "zsh")
        .expect("the Zsh package");
    document["signed"]["shells"][position]["profile_order"][0]["arguments"] =
        serde_json::json!(["-f"]);
    std::fs::write(release.tree().join("release.json"), document.to_string()).expect("edited");
    let refused = run(&[
        "sign".to_owned(),
        "--tree".to_owned(),
        release.tree().to_string_lossy().into_owned(),
        "--checkout".to_owned(),
        checkout().to_string_lossy().into_owned(),
        "--key".to_owned(),
        release
            .keys()
            .join("targets-1.pk8")
            .to_string_lossy()
            .into_owned(),
        "--key".to_owned(),
        release
            .keys()
            .join("targets-2.pk8")
            .to_string_lossy()
            .into_owned(),
    ]);
    assert!(!refused.status.success(), "an edited manifest was signed");
    assert!(
        why(&refused).contains("not what the tree"),
        "{}",
        why(&refused)
    );
}

/// A tree is signed by the threshold of keys the root names, and a host's check of
/// what was signed refuses a tree that changed after it, or one that one key signed.
#[test]
#[ignore = "builds a tree of this checkout's shell packages; it runs with --include-ignored where they are built"]
fn a_signed_tree_verifies_and_a_changed_or_short_signed_one_does_not() {
    let release = tree_of();
    let tree = release.tree().to_string_lossy().into_owned();
    let checkout = checkout().to_string_lossy().into_owned();
    let key = |n: u32| {
        release
            .keys()
            .join(format!("targets-{n}.pk8"))
            .to_string_lossy()
            .into_owned()
    };
    let root = release
        .keys()
        .join("root.json")
        .to_string_lossy()
        .into_owned();

    let written = run(&manifest_arguments(&release.tree()));
    assert!(written.status.success(), "{}", why(&written));
    let sign = |keys: &[&str]| {
        let mut arguments = vec![
            "sign".to_owned(),
            "--tree".to_owned(),
            tree.clone(),
            "--checkout".to_owned(),
            checkout.clone(),
        ];
        for key in keys {
            arguments.push("--key".to_owned());
            arguments.push((*key).to_owned());
        }
        run(&arguments)
    };
    let verify = || {
        run(&[
            "verify".to_owned(),
            "--tree".to_owned(),
            tree.clone(),
            "--root".to_owned(),
            root.clone(),
        ])
    };

    // One key of a two-key threshold does not meet it.
    let one = sign(&[&key(1)]);
    assert!(one.status.success(), "{}", why(&one));
    assert!(!verify().status.success(), "one key of two signed it");

    // Both do, and the control passes.
    let written = run(&manifest_arguments(&release.tree()));
    assert!(written.status.success(), "{}", why(&written));
    let both = sign(&[&key(1), &key(2)]);
    assert!(both.status.success(), "{}", why(&both));
    let control = verify();
    assert!(control.status.success(), "{}", why(&control));

    // One byte of one file changed after signing.
    let program = release.tree().join("bin/kr");
    let mut bytes = std::fs::read(&program).expect("a program");
    bytes.push(b'\n');
    std::fs::write(&program, bytes).expect("a program");
    let changed = verify();
    assert!(
        !changed.status.success(),
        "a tree changed after signing verified"
    );
    assert!(
        why(&changed).contains("not what its manifest says"),
        "{}",
        why(&changed)
    );
}

/// KR-REQ-07.86: a Windows release carries the PowerShell package as files, with no shell build to
/// state, and its executables are the `.exe` programs of `bin/`; a file of the package that is not
/// the checkout's, and a directory under `shells/` that is no part of it, are refused, and the
/// unedited tree is the control.
#[test]
fn a_windows_tree_carries_the_powershell_package_as_files() {
    const WINDOWS: &str = "x86_64-pc-windows-msvc";
    let directory = tempfile::Builder::new()
        .prefix("kr-release-windows-")
        .tempdir()
        .expect("a directory");
    let programs = directory.path().join("programs");
    std::fs::create_dir_all(&programs).expect("programs");
    for program in kr_protocol::update::required_programs(WINDOWS) {
        std::fs::write(programs.join(format!("{program}.exe")), "MZ").expect("a program");
    }
    let keys = directory.path().join("keys");
    let made = kr_release_binary(&["dev-keys", "--out", keys.to_str().expect("utf-8")]);
    assert!(made.status.success(), "{}", why(&made));
    let tree = directory.path().join("release");
    let built = Command::new("bash")
        .arg(checkout().join("scripts/build-release.sh"))
        .args(["--target", WINDOWS, "--release", "0.1.0+4254aa6e62e5"])
        .args([
            "--sequence",
            "3",
            "--commit",
            COMMIT,
            "--floor",
            "windows=10.0",
        ])
        .arg("--programs")
        .arg(&programs)
        .arg("--root")
        .arg(keys.join("root.json"))
        .arg("--out")
        .arg(&tree)
        .arg("--kr-release")
        .arg(env!("CARGO_BIN_EXE_kr-release"))
        .output()
        .expect("the script runs");
    assert!(built.status.success(), "{}", why(&built));

    let manifest = manifest_of(&tree);
    assert!(manifest.shells.is_empty(), "no shell build is stated");
    let listed = |path: &str| {
        manifest
            .files
            .iter()
            .find(|file| file.path.as_str() == path)
    };
    assert_eq!(
        listed("bin/kr.exe").map(|file| file.mode),
        Some(FileMode::Executable)
    );
    assert_eq!(
        listed("shells/psreadline/module/KalaReach.ShellBridge.psd1").map(|file| file.mode),
        Some(FileMode::Regular)
    );
    assert!(listed("shells/psreadline/startup/kr-profile.ps1").is_some());

    // A file of the PowerShell package that is not the checkout's: the module a policy that asks for
    // signed scripts would load, edited after it was copied.
    let module = tree.join("shells/psreadline/module/KrBridge.ps1");
    let original = std::fs::read(&module).expect("a module script");
    let mut edited = original.clone();
    edited.extend_from_slice(b"\n# another\n");
    std::fs::write(&module, edited).expect("edited");
    let refused = run(&manifest_arguments_for(&tree, WINDOWS, "windows=10.0"));
    assert!(!refused.status.success());
    assert!(
        why(&refused).contains("shells/psreadline"),
        "{}",
        why(&refused)
    );
    std::fs::write(&module, &original).expect("put back");
    let again = run(&manifest_arguments_for(&tree, WINDOWS, "windows=10.0"));
    assert!(again.status.success(), "{}", why(&again));

    // The same script as Authenticode leaves it: the checkout's text, then the block of comment
    // lines the signing appends. The manifest of a signed tree is written again, so it takes it.
    let block: &[u8] =
        b"\r\n# SIG # Begin signature block\r\n# MIIabcdefgh\r\n# SIG # End signature block\r\n";
    let with = |text: &[u8], tail: &[u8]| [text, tail].concat();
    std::fs::write(&module, with(&original, block)).expect("signed");
    let signed = run(&manifest_arguments_for(&tree, WINDOWS, "windows=10.0"));
    assert!(
        signed.status.success(),
        "a signed script is the checkout's: {}",
        why(&signed)
    );
    // A signed script whose text is not the checkout's, and a marker followed by code.
    for (what, bytes) in [
        (
            "a signed script of another text",
            with(&with(&original, b"\n# another\n"), block),
        ),
        (
            "code after the marker",
            with(
                &original,
                b"\r\n# SIG # Begin signature block\r\nWrite-Host smuggled\r\n",
            ),
        ),
    ] {
        std::fs::write(&module, bytes).expect("edited");
        let refused = run(&manifest_arguments_for(&tree, WINDOWS, "windows=10.0"));
        assert!(!refused.status.success(), "{what}");
        assert!(
            why(&refused).contains("shells/psreadline"),
            "{what}: {}",
            why(&refused)
        );
    }
    std::fs::write(&module, &original).expect("put back");

    // Another directory under `shells/` is no shell package of a Windows release.
    std::fs::create_dir_all(tree.join("shells/another")).expect("a directory");
    std::fs::write(tree.join("shells/another/file"), "x").expect("a file");
    let refused = run(&manifest_arguments_for(&tree, WINDOWS, "windows=10.0"));
    assert!(!refused.status.success());
    assert!(
        why(&refused).contains("shells/psreadline"),
        "{}",
        why(&refused)
    );
}
