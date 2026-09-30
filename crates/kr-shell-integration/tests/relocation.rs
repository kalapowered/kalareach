//! A managed Zsh tree that has been moved.
//!
//! A release is kept in a directory of its own, beside its predecessors, under the person's own
//! directories; the tree the shell package was built in is not where it will be. So the packaged
//! shell has to load its editor and its modules from where it is, and not from the prefix the build
//! named. This copies the built package to a new place and starts the copy: its `module_path` and
//! its `fpath` name the copy, and the editor and a shipped module load from the copy's own
//! `lib/zsh/5.9`.
//!
//! What proves that the copy's files were the ones loaded, and not the original's that are still
//! where they were, is the platform's own: on macOS the original's `lib` and `share` are hidden from
//! the copy by a sandbox profile, so a copy that reached for them fails to load anything, and on
//! Linux the shell's own memory map is read and names the copy's `zle.so`.
//!
//! The cases drive this tree's built package, which an ordinary run does not have, so they are left
//! out of one. A run that built the packages runs them with `--include-ignored`.

#![cfg(unix)]

mod shellpkg;

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_shell_integration::contract::qualification::ShellKind;
use shellpkg::Package;

/// What one run of a shell told: its lines, and whether it succeeded.
struct Told {
    lines: Vec<String>,
    stderr: String,
}

impl Told {
    fn value(&self, key: &str) -> String {
        self.lines
            .iter()
            .find_map(|line| line.strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| {
                panic!(
                    "the shell said nothing of {key}: {:?}\n{}",
                    self.lines, self.stderr
                )
            })
            .to_owned()
    }
}

/// Runs `script` in `zsh`, with the tree at `hidden` unreadable to it where the platform can say so.
fn run(zsh: &Path, hidden: Option<&Path>, script: &str) -> Told {
    let mut command = if let (true, Some(hidden)) = (cfg!(target_os = "macos"), hidden) {
        let profile = format!(
            "(version 1)(allow default)(deny file-read* (subpath \"{}\"))",
            hidden.display()
        );
        let mut command = Command::new("sandbox-exec");
        command.arg("-p").arg(profile).arg(zsh);
        command
    } else {
        Command::new(zsh)
    };
    let output = command
        .args(["-f", "-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("the shell starts");
    Told {
        lines: String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::to_owned)
            .collect(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

const SCRIPT: &str = r#"
print -r -- "module_path=$module_path"
print -r -- "fpath=$fpath"
zmodload zsh/zle && print -r -- "zle=loaded"
zmodload zsh/datetime && print -r -- "datetime=loaded"
if [[ -r /proc/$$/maps ]]; then
  print -r -- "maps=${(j: :)${(M)${(f)"$(</proc/$$/maps)"}:#*zsh/zle.so*}}"
fi
"#;

/// KR-REQ-07.86: the package as it was built finds its own modules, which is the control.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn the_package_where_it_was_built_finds_its_own_modules() {
    let package = Package::built(ShellKind::Zsh);
    let root = package_root(&package);
    let told = run(&package.executable, None, SCRIPT);
    assert_eq!(
        told.value("module_path"),
        format!("{}/lib/zsh/5.9", root.display())
    );
    assert_eq!(told.value("zle"), "loaded");
    assert_eq!(told.value("datetime"), "loaded");
}

/// KR-REQ-07.86: a moved copy finds its modules and functions where it is, and what a person sets
/// afterwards still wins.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_moved_tree_loads_its_editor_and_modules_from_where_it_is() {
    let package = Package::built(ShellKind::Zsh);
    let original = package_root(&package);
    let holder = tempfile::Builder::new()
        .prefix("kr-moved-package-")
        .tempdir()
        .expect("a directory on the internal disk");
    let moved = holder.path().join("versions").join("release-2");
    std::fs::create_dir_all(moved.parent().expect("a parent")).expect("a directory");
    let copied = Command::new("cp")
        .arg("-R")
        .arg(&original)
        .arg(&moved)
        .status()
        .expect("cp runs");
    assert!(copied.success(), "the tree copies");
    let moved = moved.canonicalize().expect("the copy is there");

    let told = run(&moved.join("bin/zsh"), Some(&original), SCRIPT);
    assert_eq!(
        told.value("module_path"),
        format!("{}/lib/zsh/5.9", moved.display()),
        "the module path names the moved tree; {}",
        told.stderr
    );
    let fpath = told.value("fpath");
    let prefix = format!("{}/", original.display());
    assert!(
        fpath.split(' ').all(|entry| !entry.starts_with(&prefix)),
        "no function directory is under the tree the build named: {fpath}"
    );
    assert!(
        fpath
            .split(' ')
            .any(|entry| entry.starts_with(&format!("{}/", moved.display()))),
        "the function path names the moved tree: {fpath}"
    );
    assert_eq!(told.value("zle"), "loaded", "{}", told.stderr);
    assert_eq!(told.value("datetime"), "loaded", "{}", told.stderr);
    if let Some(maps) = told
        .lines
        .iter()
        .find_map(|line| line.strip_prefix("maps="))
    {
        assert!(
            maps.contains(&format!("{}/lib/zsh/5.9/zsh/zle.so", moved.display()))
                && !maps.contains(&format!("{}/lib/", original.display())),
            "the editor that is mapped is the moved copy's: {maps}"
        );
    }

    // What a person sets in their startup files is set after this and wins.
    let told = run(
        &moved.join("bin/zsh"),
        None,
        r#"module_path=(/elsewhere); fpath=(/mine $fpath); print -r -- "chosen=$module_path[1] $fpath[1]""#,
    );
    assert_eq!(told.value("chosen"), "/elsewhere /mine");
}

/// The tree a package's executable is in: the package's own directory.
fn package_root(package: &Package) -> PathBuf {
    package
        .executable
        .parent()
        .and_then(Path::parent)
        .expect("the executable is in a bin directory")
        .canonicalize()
        .expect("the package is there")
}
