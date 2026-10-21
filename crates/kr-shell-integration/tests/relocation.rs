//! A managed shell tree that has been moved.
//!
//! A release is kept in a directory of its own, beside its predecessors, under the person's own
//! directories; the tree the shell package was built in is not where it will be. So the packaged
//! shell has to load its editor and its modules from where it is, and not from the prefix the build
//! named. This copies the built package to a new place and starts the copy: its `module_path` and
//! its `fpath` name the copy, and the editor and a shipped module load from the copy's own
//! `lib/zsh/5.9`. The managed session of each shell is started over a moved copy as well, which the
//! worker accepts only when it states the package as the build wrote it.
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
use std::sync::RwLock;
use std::time::Duration;

use kr_shell_integration::contract::qualification::ShellKind;
use shellpkg::Package;
use shellpkg::{CaseSetup, Session, StackIndex, cases};

/// Who is using the packages where they were built. A case that puts the original out of the way
/// takes it alone, so no other case of this file looks for a package that is not there.
static ORIGINALS: RwLock<()> = RwLock::new(());

/// A package directory moved aside for the length of a case, and put back when it ends, however it
/// ends.
struct Aside {
    from: PathBuf,
    to: PathBuf,
}

impl Aside {
    fn take(from: &Path) -> Self {
        let to = from.with_extension("aside-by-a-case");
        // What a case that was killed left behind goes back first.
        if to.exists() && !from.exists() {
            std::fs::rename(&to, from).expect("a package left aside goes back");
        }
        std::fs::rename(from, &to).expect("the package moves aside");
        Self {
            from: from.to_path_buf(),
            to,
        }
    }
}

impl Drop for Aside {
    fn drop(&mut self) {
        let _ = std::fs::rename(&self.to, &self.from);
    }
}

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
    let _using = ORIGINALS.read().expect("no case panicked holding the lock");
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
    let _using = ORIGINALS.read().expect("no case panicked holding the lock");
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

/// How long a moved package's first prompt is waited for.
const FIRST_PROMPT: Duration = Duration::from_secs(90);

/// A copy of `package` in a release's place for it, as a package is once it is installed.
fn moved(package: &Package, kind: ShellKind, holder: &Path) -> Package {
    let original_root = package_root(package);
    let moved_root = holder
        .join("versions")
        .join("release-2")
        .join("shells")
        .join(kind.as_str())
        .join(&package.identity);
    std::fs::create_dir_all(moved_root.parent().expect("a parent")).expect("a directory");
    let copied = Command::new("cp")
        .arg("-R")
        .arg(&original_root)
        .arg(&moved_root)
        .status()
        .expect("cp runs");
    assert!(copied.success(), "the tree copies");
    let moved_root = moved_root.canonicalize().expect("the copy is there");
    let within = |file: &Path| {
        moved_root.join(
            file.strip_prefix(&original_root)
                .expect("the file is in the package"),
        )
    };
    Package {
        kind: package.kind,
        identity: package.identity.clone(),
        executable: within(&package.executable),
        startup_entry: within(&package.startup_entry),
        module_directory: within(&package.module_directory),
        record: package.record.clone(),
    }
}

/// The plain case of a shell, which starts from nothing but the package.
fn plain(case_id: &str) -> shellpkg::QualificationCase {
    cases()
        .into_iter()
        .find(|case| case.id == case_id)
        .expect("the plain case of the shell")
}

/// Starts the plain case of `kind` over the package where it was built, which is the control, and
/// then over a copy of the package in another place with the original gone.
///
/// The worker states the package it launched from the record the build wrote, and the shell says
/// what it was built as; the two agree wherever the package sits, so the handshake accepts the
/// moved copy as it accepts the original, and the copy depends on nothing the original holds.
fn a_moved_package_starts_a_managed_session(kind: ShellKind, case_id: &str) {
    let _alone = ORIGINALS
        .write()
        .expect("no case panicked holding the lock");
    let package = Package::built(kind);
    let index = StackIndex::read().expect("the corpus index is there");
    let case = plain(case_id);

    let setup = CaseSetup::prepare(&case, &package, &index);
    let mut original = Session::start_for(&package, &case, &setup);
    original.first_prompt_within(FIRST_PROMPT);
    drop(original);

    let holder = tempfile::Builder::new()
        .prefix("kr-moved-package-")
        .tempdir()
        .expect("a directory on the internal disk");
    let copy = moved(&package, kind, holder.path());
    let _gone = Aside::take(&package_root(&package));

    let setup = CaseSetup::prepare(&case, &copy, &index);
    let mut session = Session::start_for(&copy, &case, &setup);
    session.first_prompt_within(FIRST_PROMPT);
}

/// KR-REQ-07.86: a Zsh package that was moved starts a managed session where it is.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_moved_zsh_package_starts_a_managed_session_where_it_is() {
    a_moved_package_starts_a_managed_session(ShellKind::Zsh, "zsh-plain");
}

/// KR-REQ-07.86: a Bash package that was moved starts a managed session where it is.
#[test]
#[ignore = "drives this tree's built Bash package; it runs with --include-ignored where the packages are built"]
fn a_moved_bash_package_starts_a_managed_session_where_it_is() {
    a_moved_package_starts_a_managed_session(ShellKind::Bash, "bash-plain");
}

/// KR-REQ-07.86: a Fish package that was moved starts a managed session where it is.
#[test]
#[ignore = "drives this tree's built Fish package; it runs with --include-ignored where the packages are built"]
fn a_moved_fish_package_starts_a_managed_session_where_it_is() {
    a_moved_package_starts_a_managed_session(ShellKind::Fish, "fish-plain");
}

/// KR-REQ-07.86: a package that says it is another build than the shell inside it is still refused
/// where it has been moved. The worker states the record the build wrote, and a shell that was
/// built from other patches does not agree with it.
#[test]
#[ignore = "drives this tree's built Zsh package; it runs with --include-ignored where the packages are built"]
fn a_moved_package_whose_record_is_another_build_is_refused() {
    let _using = ORIGINALS.read().expect("no case panicked holding the lock");
    let package = Package::built(ShellKind::Zsh);
    let index = StackIndex::read().expect("the corpus index is there");
    let case = plain("zsh-plain");
    let holder = tempfile::Builder::new()
        .prefix("kr-moved-package-")
        .tempdir()
        .expect("a directory on the internal disk");
    let copy = moved(&package, ShellKind::Zsh, holder.path());

    let record_path = copy
        .startup_entry
        .parent()
        .and_then(Path::parent)
        .expect("the package's directory")
        .join("kr-shell-identity.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&record_path).expect("a record"))
            .expect("a record");
    record["shell"]["patches"][0]["revision"] = serde_json::json!("another-revision");
    std::fs::write(&record_path, record.to_string()).expect("the record is rewritten");

    let setup = CaseSetup::prepare(&case, &copy, &index);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Session::start_for(&copy, &case, &setup)
    }));
    let message = match refused {
        Ok(_) => panic!("a package of another record started a managed session"),
        Err(payload) => payload
            .downcast_ref::<String>()
            .cloned()
            .unwrap_or_default(),
    };
    assert!(message.contains("PackageMismatch"), "refused as {message}");
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
