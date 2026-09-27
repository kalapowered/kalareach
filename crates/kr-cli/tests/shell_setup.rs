//! `kr shell install` and `kr shell remove`, run as the commands a person types.
//!
//! Removal takes the marked entry out of each file the install put one in, and only those: it
//! works from the files the install wrote, not from where the entries would go now and not from
//! the text a report shows. So an entry comes out of the file it was written to after the layout
//! has moved, and out of a file whose name is not text; a file the install never wrote is left as
//! it is, whatever it holds.
//!
//! Every run gets a home, a package root and the installation's directories of its own, on the
//! internal disk, and a `PATH` of the system's directories alone, so no PowerShell of the person's
//! is asked where its profile is.

#![cfg(unix)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::{
    CURRENT_BASENAME, MANIFEST_BASENAME, PACKAGE_ROOT_VARIABLE, PackageManifest, PackageShell,
    PackageStartupEntry,
};
use kr_shell_integration::host::startup::{MARKER_BEGIN, MARKER_END};

mod support;

use support::kr;

/// What the person wrote in their own startup file.
const THEIRS: &str = "export EDITOR=vim\nalias ll='ls -l'\n";

/// A home, a zsh package and the installation's directories, all of this test's own.
struct Setup {
    _root: tempfile::TempDir,
    home: PathBuf,
    packages: PathBuf,
    runtime: PathBuf,
    state: PathBuf,
}

impl Setup {
    /// A setup whose home directory is called `home`.
    fn new(home: &OsStr) -> Self {
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let home = root.path().join(home);
        let packages = root.path().join("packages");
        let runtime = root.path().join("runtime");
        let state = root.path().join("state");
        std::fs::create_dir(&home).expect("a home");
        // The installation's directories are its owner's alone, as a host makes them.
        for directory in [&runtime, &state] {
            kr_ipc::paths::create_private_tree(directory, directory)
                .expect("an owner-only directory");
        }
        // A zsh package, as a build installs one: its identity record, and the file beside it
        // naming the identity the installation uses. Nothing here starts it, so no binary is
        // needed where the record says the shell is.
        let package = packages.join("zsh").join("test-1");
        std::fs::create_dir_all(&package).expect("the package's directory");
        let manifest = PackageManifest {
            identity: "test-1".to_owned(),
            shell: PackageShell {
                kind: ShellKind::Zsh,
                executable: package.join("bin/zsh"),
                upstream_version: "5.9".to_owned(),
                editor_abi: "zle-5.9".to_owned(),
                integration_version: "1".to_owned(),
                patches: Vec::new(),
                modules: Vec::new(),
            },
            startup_entry: PackageStartupEntry {
                file: package
                    .join("startup/entry.zsh")
                    .to_str()
                    .expect("the package root is text")
                    .to_owned(),
            },
        };
        std::fs::write(
            package.join(MANIFEST_BASENAME),
            serde_json::to_string(&manifest).expect("the record encodes"),
        )
        .expect("writes the identity record");
        std::fs::write(packages.join("zsh").join(CURRENT_BASENAME), "test-1\n")
            .expect("names the identity in use");
        Self {
            _root: root,
            home,
            packages,
            runtime,
            state,
        }
    }

    /// A `kr` with this setup's home, package root and installation directories, and `zdotdir` as
    /// `ZDOTDIR` where one is given.
    fn command(&self, arguments: &[&str], zdotdir: Option<&Path>) -> std::process::Command {
        let mut command = std::process::Command::new(kr());
        command
            .args(arguments)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("KR_RUNTIME_DIR", &self.runtime)
            .env("KR_STATE_DIR", &self.state)
            .env(PACKAGE_ROOT_VARIABLE, &self.packages)
            .current_dir(&self.state)
            .stdin(std::process::Stdio::null());
        if let Some(zdotdir) = zdotdir {
            command.env("ZDOTDIR", zdotdir);
        }
        command
    }

    /// Runs `kr` as [`Self::command`] makes it, and requires it to succeed.
    fn kr(&self, arguments: &[&str], zdotdir: Option<&Path>) -> String {
        let output = self.command(arguments, zdotdir).output().expect("kr runs");
        said(arguments, &output)
    }
}

/// What a `kr` that had to succeed printed, or a failure saying what it printed instead.
fn said(arguments: &[&str], output: &std::process::Output) -> String {
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "kr {arguments:?}: {said}");
    said
}

/// A marked entry of the person's own making, which no install wrote.
fn a_marked_entry_by_hand() -> String {
    format!("{MARKER_BEGIN}\n. /opt/elsewhere/entry.zsh\n{MARKER_END}\n")
}

/// Whether a file holds a marked entry.
fn holds_an_entry(path: &Path) -> bool {
    std::fs::read_to_string(path).is_ok_and(|text| text.lines().any(|line| line == MARKER_BEGIN))
}

/// An entry comes out of the file the install wrote it to after the layout has moved, and a file
/// the install did not write is left, although it holds a marked entry and is where the entry
/// would go now.
#[test]
fn an_entry_comes_out_of_the_file_it_was_written_to_and_a_file_it_was_not_is_left() {
    let setup = Setup::new(OsStr::new("home"));
    let zdotdir = setup.home.join("zdot");
    std::fs::create_dir(&zdotdir).expect("a ZDOTDIR");
    let written = zdotdir.join(".zshrc");
    std::fs::write(&written, THEIRS).expect("the person's own startup file");
    setup.kr(&["shell", "install", "--shell", "zsh"], Some(&zdotdir));
    assert!(
        holds_an_entry(&written),
        "the install puts its entry in the .zshrc inside ZDOTDIR"
    );

    // The person stops setting ZDOTDIR, and has a marked entry of their own making in the .zshrc
    // in their home, which is where an entry would go now.
    let not_written = setup.home.join(".zshrc");
    let their_own = format!("{THEIRS}{}", a_marked_entry_by_hand());
    std::fs::write(&not_written, &their_own).expect("the home's own startup file");
    setup.kr(&["shell", "remove", "--shell", "zsh"], None);

    assert_eq!(
        std::fs::read_to_string(&written).expect("reads"),
        THEIRS,
        "the entry comes out of the file the install wrote it to, and what the person wrote stays"
    );
    assert_eq!(
        std::fs::read_to_string(&not_written).expect("reads"),
        their_own,
        "a file the install did not write is left as it is"
    );
}

/// An entry comes out of a file whose name is not text, which a report can only show with a
/// replacement character in it. The name is kept as it is, so the install writes the file itself
/// and the removal takes the entry out of it.
///
/// Linux only: a file system that keeps names as UTF-8, as macOS's does, cannot hold such a name.
#[cfg(target_os = "linux")]
#[test]
fn an_entry_comes_out_of_a_file_whose_name_is_not_text() {
    use std::os::unix::ffi::OsStrExt as _;

    let setup = Setup::new(OsStr::from_bytes(b"home-\xff"));
    let zshrc = setup.home.join(".zshrc");
    std::fs::write(&zshrc, THEIRS).expect("the person's own startup file");
    setup.kr(&["shell", "install", "--shell", "zsh"], None);
    assert!(
        holds_an_entry(&zshrc),
        "the install puts its entry in the file itself, not in one a report's text names"
    );
    setup.kr(&["shell", "remove", "--shell", "zsh"], None);
    assert_eq!(std::fs::read_to_string(&zshrc).expect("reads"), THEIRS);
    // Nothing was written under a name the report's text makes of it.
    let lossy = PathBuf::from(setup.home.to_string_lossy().into_owned());
    assert!(!lossy.exists(), "{} was not created", lossy.display());
}

/// The control: an ordinary installation, in a home the layout has not moved from, is removed as
/// before.
#[test]
fn an_ordinary_installation_is_removed() {
    let setup = Setup::new(OsStr::new("home"));
    let zshrc = setup.home.join(".zshrc");
    std::fs::write(&zshrc, THEIRS).expect("the person's own startup file");
    setup.kr(&["shell", "install", "--shell", "zsh"], None);
    assert!(holds_an_entry(&zshrc));
    let said = setup.kr(&["shell", "remove", "--shell", "zsh"], None);
    assert!(said.contains("removed"), "{said}");
    assert_eq!(std::fs::read_to_string(&zshrc).expect("reads"), THEIRS);
}

/// The control: a home whose name has a space and a quote in it, which a shell or a report would
/// quote, is installed into and removed from as any other.
#[test]
fn a_home_whose_name_has_a_space_and_a_quote_is_removed_from() {
    let setup = Setup::new(OsStr::new("the person's home"));
    let zshrc = setup.home.join(".zshrc");
    std::fs::write(&zshrc, THEIRS).expect("the person's own startup file");
    setup.kr(&["shell", "install", "--shell", "zsh"], None);
    assert!(holds_an_entry(&zshrc));
    setup.kr(&["shell", "remove", "--shell", "zsh"], None);
    assert_eq!(std::fs::read_to_string(&zshrc).expect("reads"), THEIRS);
}

/// An install and a removal that run at once, as two `kr` processes, leave the record and the
/// startup file agreeing: an entry in the file is one the record names, whichever of the two ran
/// first. A removal that read the record between an install's recording the file and its writing
/// the entry, found no entry and forgot the file, would leave an entry that no later removal takes
/// out.
///
/// The removal starts a little later in each round, a millisecond more each time for thirty, and
/// then again, so its reading of the record falls at every point of an install.
#[test]
fn an_install_and_a_removal_at_once_leave_no_entry_the_record_does_not_name() {
    const ROUNDS: usize = 90;
    const INSTALL: &[&str] = &["shell", "install", "--shell", "zsh"];
    const REMOVE: &[&str] = &["shell", "remove", "--shell", "zsh"];
    let mut unrecorded = Vec::new();
    for round in 0..ROUNDS {
        let setup = Setup::new(OsStr::new("home"));
        let zshrc = setup.home.join(".zshrc");
        std::fs::write(&zshrc, THEIRS).expect("the person's own startup file");
        let installing = setup.command(INSTALL, None).output_in_the_background();
        std::thread::sleep(std::time::Duration::from_millis(
            u64::try_from(round % 30).expect("a small number"),
        ));
        let removing = setup.command(REMOVE, None).output_in_the_background();
        said(INSTALL, &installing.join().expect("the install ran"));
        said(REMOVE, &removing.join().expect("the removal ran"));
        let recorded =
            kr_shell_integration::host::startup::EntryRecord::in_state_directory(&setup.state)
                .files(ShellKind::Zsh)
                .expect("the record reads");
        if holds_an_entry(&zshrc) && !recorded.contains(&zshrc) {
            unrecorded.push(round);
        }
    }
    assert!(
        unrecorded.is_empty(),
        "in {} of {ROUNDS} rounds the install's entry was left in the file with no record of it: \
         {unrecorded:?}",
        unrecorded.len()
    );
}

/// Starting a command and collecting what it printed on a thread of its own.
trait InTheBackground {
    /// Starts the command now, and returns the thread that collects its output.
    fn output_in_the_background(self) -> std::thread::JoinHandle<std::process::Output>;
}

impl InTheBackground for std::process::Command {
    fn output_in_the_background(mut self) -> std::thread::JoinHandle<std::process::Output> {
        let child = self
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("kr starts");
        std::thread::spawn(move || child.wait_with_output().expect("kr is waited for"))
    }
}
