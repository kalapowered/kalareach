//! KR-REQ-26.05: installing onto a home that already holds a plugin stack.
//!
//! The installer adds one marked entry to each startup file the shell reads and nothing else, adds
//! no shell-wide `exec kr` hook, and takes exactly what it added out again. This drives the real
//! `kr shell install`, `kr host startup --set` and `kr shell remove` over a home for each
//! customisation the qualification runs the managed shells under (the corpus under `tests/shells/`,
//! with the pinned stacks installed by `scripts/fetch-shell-stacks.sh`), and over the homes the
//! corpus does not have: one that sources iTerm2's shell integration, one whose startup file does
//! not end in a line break, and a PowerShell `$PROFILE`. For each home it asserts that
//!
//!   * the only change the install makes is one marked block in a startup file the section names,
//!     and every other file, directory and mode is what it was;
//!   * no startup file of the person's, and no file of the package's, has a line that runs `exec`
//!     on `kr`;
//!   * `kr shell remove` leaves the home byte for byte as it was before the install;
//!   * a managed session started over the installed home under that customisation qualifies, and the
//!     person's own startup files ran in the order the case records.
//!
//! The checks that decide those are pure functions over a snapshot of the home, and the first test
//! puts each of them through the faults it exists to refuse: an installer that appends an unmarked
//! line, or an `exec kr` line, to `.zshrc`, one that writes another file, and a removal that leaves
//! a byte behind. That test needs no package and runs everywhere.
//!
//! The home-driving cases need this tree's built packages, the fetched stacks and a built `kr`, so
//! an ordinary run leaves them out. A run that has them runs them with `--include-ignored`.

#![cfg(unix)]

mod shellpkg;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use kr_shell_integration::contract::events::BridgeEvent;
use kr_shell_integration::contract::qualification::ShellKind;
use kr_shell_integration::host::package::PACKAGE_ROOT_VARIABLE;
use kr_shell_integration::host::startup::{
    CHECK_MARKER_BEGIN, CHECK_MARKER_END, MARKER_BEGIN, MARKER_END,
};
use shellpkg::{CaseSetup, Package, QualificationCase, Session, StackIndex, cases, package_root};

/// One thing in a home.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Directory { mode: u32 },
    File { mode: u32, bytes: Vec<u8> },
    Link(PathBuf),
}

/// Every path under a home, relative to it, and what is there.
type Snapshot = BTreeMap<PathBuf, Node>;

fn snapshot(root: &Path) -> Snapshot {
    fn walk(root: &Path, directory: &Path, into: &mut Snapshot) {
        let mut entries: Vec<_> = std::fs::read_dir(directory)
            .expect("the directory reads")
            .map(|entry| entry.expect("an entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let relative = path.strip_prefix(root).expect("under the root").to_owned();
            let about = std::fs::symlink_metadata(&path).expect("metadata");
            let mode = about.permissions().mode() & 0o7777;
            if about.file_type().is_symlink() {
                into.insert(
                    relative,
                    Node::Link(std::fs::read_link(&path).expect("a link")),
                );
            } else if about.is_dir() {
                into.insert(relative, Node::Directory { mode });
                walk(root, &path, into);
            } else {
                into.insert(
                    relative,
                    Node::File {
                        mode,
                        bytes: std::fs::read(&path).expect("a file reads"),
                    },
                );
            }
        }
    }
    let mut found = Snapshot::new();
    walk(root, root, &mut found);
    found
}

/// The two marker pairs an entry can have: the one every shell's entry has, and the one that checks
/// PowerShell's reader at the end of its last profile.
const MARKERS: [(&str, &str); 2] = [
    (MARKER_BEGIN, MARKER_END),
    (CHECK_MARKER_BEGIN, CHECK_MARKER_END),
];

/// Whether `text` is exactly one marked block with these markers: the begin line, whatever the
/// block holds, the end line, and nothing else, each marker on a line of its own once.
fn is_one_block_of(text: &str, begin: &str, end: &str) -> bool {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let begins = lines.iter().filter(|line| line.trim_end() == begin).count();
    let ends = lines.iter().filter(|line| line.trim_end() == end).count();
    begins == 1
        && ends == 1
        && lines.first().is_some_and(|line| line.trim_end() == begin)
        && lines.last().is_some_and(|line| line.trim_end() == end)
        && text.ends_with('\n')
}

/// Whether `text` is exactly one marked block of either entry.
fn is_one_block(text: &str) -> bool {
    MARKERS
        .iter()
        .any(|(begin, end)| is_one_block_of(text, begin, end))
}

/// Whether `after` is `before` with one marked block put in at a line boundary and nothing else
/// changed: cutting the block's lines out gives the person's own text again, or that text and the
/// line break the block needed when it did not end in one.
///
/// A shell's entry goes after everything the person wrote; PowerShell's first entry goes below the
/// `using` statements and `param` block at the start of its profile, and its second at the end of
/// the last one. A byte-order mark is the file's encoding and belongs to no line.
fn one_block_put_in(before: &[u8], after: &[u8]) -> bool {
    let (Ok(before), Ok(after)) = (std::str::from_utf8(before), std::str::from_utf8(after)) else {
        return false;
    };
    let unmarked = |text: &str| text.strip_prefix('\u{feff}').unwrap_or(text).to_owned();
    let (before, after) = (unmarked(before), unmarked(after));
    MARKERS.iter().any(|(begin, end)| {
        let lines: Vec<&str> = after.split_inclusive('\n').collect();
        let begins: Vec<usize> = (0..lines.len())
            .filter(|index| lines[*index].trim_end() == *begin)
            .collect();
        let ends: Vec<usize> = (0..lines.len())
            .filter(|index| lines[*index].trim_end() == *end)
            .collect();
        let (&[from], &[to]) = (begins.as_slice(), ends.as_slice()) else {
            return false;
        };
        if to < from || !is_one_block_of(&lines[from..=to].concat(), begin, end) {
            return false;
        }
        let rest = [&lines[..from], &lines[to + 1..]].concat().concat();
        rest == before
            || (!before.is_empty() && !before.ends_with('\n') && rest == format!("{before}\n"))
    })
}

/// The only change an install may make: one marked block added to each startup file the section
/// names, whether the file was there before or is new, and the directories a new one needs.
/// Everything else has to be what it was.
///
/// # Errors
///
/// Returns the first thing that is not.
fn only_marked_entries(
    before: &Snapshot,
    after: &Snapshot,
    startup: &[PathBuf],
) -> Result<(), String> {
    let mut paths: Vec<&PathBuf> = before.keys().chain(after.keys()).collect();
    paths.sort();
    paths.dedup();
    for path in paths {
        let (was, now) = (before.get(path), after.get(path));
        if was == now {
            continue;
        }
        if startup.contains(path) {
            let Some(Node::File {
                mode: after_mode,
                bytes: after_bytes,
            }) = now
            else {
                return Err(format!(
                    "{} is not a file after the install",
                    path.display()
                ));
            };
            let after_text = String::from_utf8_lossy(after_bytes);
            match was {
                None => {
                    if !is_one_block(&after_text) {
                        return Err(format!(
                            "{} is new and holds more than one marked block: {after_text:?}",
                            path.display()
                        ));
                    }
                }
                Some(Node::File { mode, bytes }) => {
                    if mode != after_mode {
                        return Err(format!("{} changed its mode", path.display()));
                    }
                    if !one_block_put_in(bytes, after_bytes) {
                        return Err(format!(
                            "{} changed what the person wrote, or gained more than one marked block: {after_text:?}",
                            path.display()
                        ));
                    }
                }
                Some(other) => {
                    return Err(format!("{} was {other:?} and is a file", path.display()));
                }
            }
        } else if was.is_none()
            && matches!(now, Some(Node::Directory { .. }))
            && startup.iter().any(|file| file.starts_with(path))
        {
            // The directory a new startup file needed.
        } else {
            return Err(format!(
                "{} changed: {was:?} became {now:?}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// The first line that runs `exec` on `kr`, in whatever way the shell allows it to be written: a
/// command that starts with `exec` (or `builtin exec`, `command exec`) after any options it takes,
/// and whose program is `kr`, by name or by any path.
fn exec_of_kr(text: &str) -> Option<String> {
    for line in text.lines() {
        let plain = line.trim_start();
        if plain.starts_with('#') {
            continue;
        }
        for segment in line.split([';', '&', '|', '(', ')', '{', '}', '`']) {
            let mut words = segment.split_whitespace().peekable();
            while matches!(
                words.peek(),
                Some(&"builtin" | &"command" | &"then" | &"do" | &"else")
            ) {
                words.next();
            }
            if words.next() != Some("exec") {
                continue;
            }
            while let Some(word) = words.peek() {
                if *word == "-a" {
                    words.next();
                    words.next();
                } else if word.starts_with('-') {
                    words.next();
                } else {
                    break;
                }
            }
            if let Some(program) = words.next() {
                let program = program.trim_matches(['"', '\'']);
                if Path::new(program).file_name() == Some(OsStr::new("kr")) {
                    return Some(line.to_owned());
                }
            }
        }
    }
    None
}

/// Every file in the snapshot and every file the package ships for a shell, as text, keyed by
/// where it is; a file that is not text is not a startup file.
fn text_files(home: &Snapshot, package: &Path) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (path, node) in home {
        if let Node::File { bytes, .. } = node
            && let Ok(text) = std::str::from_utf8(bytes)
        {
            found.push((path.display().to_string(), text.to_owned()));
        }
    }
    if let Ok(entries) = std::fs::read_dir(package.join("startup")) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                found.push((entry.path().display().to_string(), text));
            }
        }
    }
    found
}

/// The startup files the section names for a shell, relative to the home.
fn startup_files(kind: ShellKind, home: &Snapshot) -> Vec<PathBuf> {
    match kind {
        ShellKind::Zsh => vec![PathBuf::from(".zshrc")],
        ShellKind::Bash => {
            // The login file a login Bash reads is the first of these that exists, and
            // `.bash_profile` when none does.
            let login = [".bash_profile", ".bash_login", ".profile"]
                .iter()
                .find(|name| home.contains_key(Path::new(name)))
                .unwrap_or(&".bash_profile");
            vec![PathBuf::from(".bashrc"), PathBuf::from(login)]
        }
        ShellKind::Fish => vec![PathBuf::from(".config/fish/conf.d/kalareach.fish")],
        // The profile every host reads gets the entry that opens the bridge, and the profile its
        // own host reads after it gets the one that checks the reader.
        ShellKind::PowerShell => vec![
            PathBuf::from(".config/powershell/profile.ps1"),
            PathBuf::from(".config/powershell/Microsoft.PowerShell_profile.ps1"),
        ],
    }
}

/// The controls: each check refuses the fault it exists to refuse, and passes the real thing.
/// No package and no `kr` is needed for this.
#[test]
fn the_checks_refuse_an_installer_that_does_more_than_the_marked_entry() {
    let block =
        format!("{MARKER_BEGIN}\nif [ -r /pkg/entry ]; then . /pkg/entry; fi\n{MARKER_END}\n");
    let theirs = "export EDITOR=vim\nalias ll='ls -l'\n";
    let before: Snapshot = [(
        PathBuf::from(".zshrc"),
        Node::File {
            mode: 0o644,
            bytes: theirs.as_bytes().to_vec(),
        },
    )]
    .into();
    let with = |files: &[(&str, &str)]| -> Snapshot {
        files
            .iter()
            .map(|(path, text)| {
                (
                    PathBuf::from(path),
                    Node::File {
                        mode: 0o644,
                        bytes: text.as_bytes().to_vec(),
                    },
                )
            })
            .collect()
    };
    let startup = [PathBuf::from(".zshrc")];

    // The control: the entry added after the person's own lines is the whole of the change.
    let installed = with(&[(".zshrc", &format!("{theirs}{block}"))]);
    assert_eq!(only_marked_entries(&before, &installed, &startup), Ok(()));

    // An installer that appends an unmarked line after its block, or before it.
    for hacked in [
        format!("{theirs}{block}export KR_ON=1\n"),
        format!("{theirs}export KR_ON=1\n{block}"),
        format!("{theirs}exec kr new\n{block}"),
    ] {
        assert!(
            only_marked_entries(&before, &with(&[(".zshrc", &hacked)]), &startup).is_err(),
            "an unmarked line was accepted: {hacked:?}"
        );
    }
    // One that writes a file it does not own, or changes the person's own lines.
    assert!(
        only_marked_entries(
            &before,
            &with(&[
                (".zshrc", &format!("{theirs}{block}")),
                (".zprofile", "export A=1\n")
            ]),
            &startup
        )
        .is_err()
    );
    assert!(
        only_marked_entries(
            &before,
            &with(&[(".zshrc", &format!("export EDITOR=nano\n{block}"))]),
            &startup
        )
        .is_err()
    );
    // One that leaves a lock file beside the startup file it wrote, which is a file it does not own
    // whatever it is for, and one that leaves it behind after the removal.
    assert!(
        only_marked_entries(
            &before,
            &with(&[
                (".zshrc", &format!("{theirs}{block}")),
                (".zshrc.kalareach-lock", "")
            ]),
            &startup
        )
        .is_err()
    );
    assert!(
        only_marked_entries(
            &before,
            &with(&[(".zshrc", theirs), (".zshrc.kalareach-lock", "")]),
            &startup
        )
        .is_err()
    );
    // One that adds two blocks.
    assert!(
        only_marked_entries(
            &before,
            &with(&[(".zshrc", &format!("{theirs}{block}{block}"))]),
            &startup
        )
        .is_err()
    );
    // A person's file without a final line break may gain the one that starts the block.
    let bare = with(&[(".zshrc", "export EDITOR=vim")]);
    assert_eq!(
        only_marked_entries(
            &bare,
            &with(&[(".zshrc", &format!("export EDITOR=vim\n{block}"))]),
            &startup
        ),
        Ok(())
    );

    // PowerShell's two profiles: the entry that opens the bridge goes below the person's `using`
    // statements in the profile every host reads, and the entry that checks the reader goes at the
    // end of the profile its own host reads, each with markers of its own.
    let load = format!("{MARKER_BEGIN}\nImport-Module x\n{MARKER_END}\n");
    let check = format!("{CHECK_MARKER_BEGIN}\nConfirm-KalaReachReadLine\n{CHECK_MARKER_END}\n");
    let all_hosts = ".config/powershell/profile.ps1";
    let current_host = ".config/powershell/Microsoft.PowerShell_profile.ps1";
    let powershell = [PathBuf::from(all_hosts), PathBuf::from(current_host)];
    let (using, mine) = ("using namespace System\n$x = 1\n", "Get-Date\n");
    let before_ps = with(&[(all_hosts, using), (current_host, mine)]);
    assert_eq!(
        only_marked_entries(
            &before_ps,
            &with(&[
                (
                    all_hosts,
                    &format!("using namespace System\n{load}$x = 1\n")
                ),
                (current_host, &format!("{mine}{check}")),
            ]),
            &powershell
        ),
        Ok(()),
        "each entry in its place is the whole of the change"
    );
    // Neither a statement the installer adds, nor a change to the person's own lines, nor a block
    // that is not whole, is accepted in either profile.
    for hacked in [
        with(&[
            (
                all_hosts,
                &format!("using namespace System\n{load}$x = 1\nexit\n"),
            ),
            (current_host, &format!("{mine}{check}")),
        ]),
        with(&[
            (
                all_hosts,
                &format!("using namespace System\n{load}$x = 2\n"),
            ),
            (current_host, &format!("{mine}{check}")),
        ]),
        with(&[
            (
                all_hosts,
                &format!("using namespace System\n{load}$x = 1\n"),
            ),
            (current_host, &format!("{mine}{check}{check}")),
        ]),
        with(&[
            (
                all_hosts,
                &format!("using namespace System\n{load}$x = 1\n"),
            ),
            (
                current_host,
                &format!("{mine}{MARKER_BEGIN}\nImport-Module x\n"),
            ),
        ]),
    ] {
        assert!(
            only_marked_entries(&before_ps, &hacked, &powershell).is_err(),
            "{hacked:?} was accepted"
        );
    }
    // A profile that did not end in a line break, and one that begins with a byte-order mark, gain
    // the block and, in the first case, the line break it needed.
    let bare_ps = with(&[
        (all_hosts, "using namespace System"),
        (current_host, "\u{feff}Get-Date"),
    ]);
    assert_eq!(
        only_marked_entries(
            &bare_ps,
            &with(&[
                (all_hosts, &format!("using namespace System\n{load}")),
                (current_host, &format!("\u{feff}Get-Date\n{check}")),
            ]),
            &powershell
        ),
        Ok(())
    );

    // `exec kr`, in every way a startup file can write it, and not the words that merely resemble it.
    for line in [
        "exec kr",
        "exec kr new",
        "  exec /usr/local/bin/kr attach",
        "[ -z \"$KR\" ] && exec kr",
        "exec -a kalareach kr",
        "if true; then exec \"$HOME/bin/kr\"; fi",
        "builtin exec kr",
    ] {
        assert!(
            exec_of_kr(line).is_some(),
            "{line:?} was not seen to run kr"
        );
    }
    for line in [
        "# exec kr",
        "exec zsh",
        "exec krita",
        "echo exec kr",
        "alias execkr=kr",
        "exec-kr() { :; }",
    ] {
        assert!(exec_of_kr(line).is_none(), "{line:?} is not an exec of kr");
    }

    // A removal that leaves a byte behind is not the home it was.
    let mut removed = before.clone();
    assert_eq!(removed, before);
    removed.insert(
        PathBuf::from(".zshrc"),
        Node::File {
            mode: 0o644,
            bytes: format!("{theirs}\n").into_bytes(),
        },
    );
    assert_ne!(removed, before);
}

/// A `kr` on the internal disk, and the environment it runs in: the home, the package root and the
/// installation's own directories, with a `PATH` of the system's directories alone.
struct Kr {
    binary: PathBuf,
    _root: tempfile::TempDir,
    runtime: PathBuf,
    state: PathBuf,
}

impl Kr {
    /// # Panics
    ///
    /// Panics when `kr` has not been built beside this test, which is a fault of the run.
    fn new() -> Self {
        let exe = std::env::current_exe().expect("this test's path");
        let built = exe
            .parent()
            .and_then(Path::parent)
            .expect("the target directory")
            .join("kr");
        assert!(
            built.is_file(),
            "{} is not built; run this with kr-cli's tests (cargo test -p kr-cli -p kr-shell-integration)",
            built.display()
        );
        let root = tempfile::tempdir().expect("a directory on the internal disk");
        let binary = root.path().join("kr");
        kr_ipc::testing::place_and_start_once(&built, &binary, &["--version"]);
        let runtime = root.path().join("runtime");
        let state = root.path().join("state");
        for directory in [&runtime, &state] {
            kr_ipc::paths::create_private_tree(directory, directory)
                .expect("an owner-only directory");
        }
        Self {
            binary,
            _root: root,
            runtime,
            state,
        }
    }

    /// Runs `kr` over `environment`, which is the home's own, and returns what it printed.
    fn run(
        &self,
        environment: &[(String, String)],
        powershell: Option<&Path>,
        arguments: &[&str],
    ) -> String {
        let mut path = "/usr/bin:/bin".to_owned();
        if let Some(directory) = powershell.and_then(Path::parent) {
            path = format!("{}:{path}", directory.display());
        }
        let output = Command::new(&self.binary)
            .args(arguments)
            .env_clear()
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .env("PATH", path)
            .env("KR_RUNTIME_DIR", &self.runtime)
            .env("KR_STATE_DIR", &self.state)
            .env(PACKAGE_ROOT_VARIABLE, package_root())
            .current_dir(&self.state)
            .stdin(std::process::Stdio::null())
            .output()
            .expect("kr runs");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "kr {arguments:?}: {said}");
        said
    }
}

/// A home to install onto: where it is, the environment a shell in it gets, and the shell.
struct Home {
    kind: ShellKind,
    path: PathBuf,
    environment: Vec<(String, String)>,
}

/// Installs, starts the daemon's startup choice, and removes, over `home`, asserting each of the
/// section's claims that needs no session.
fn install_and_remove(kr: &Kr, package: &Package, home: &Home, label: &str) {
    let powershell = (home.kind == ShellKind::PowerShell).then_some(package.executable.as_path());
    let before = snapshot(&home.path);
    let shell = home.kind.as_str();

    kr.run(
        &home.environment,
        powershell,
        &["shell", "install", "--shell", shell],
    );
    // Choosing how the daemon starts writes its document in the installation's own state
    // directory, and nothing in the home.
    kr.run(
        &home.environment,
        powershell,
        &["host", "startup", "--set", "standalone"],
    );
    let installed = snapshot(&home.path);

    let startup = startup_files(home.kind, &before);
    if let Err(fault) = only_marked_entries(&before, &installed, &startup) {
        panic!("{label}: the install changed more than its marked entry: {fault}");
    }
    let mut written = 0;
    for path in &startup {
        if installed.get(path) != before.get(path) {
            written += 1;
        }
    }
    assert!(
        written >= 1,
        "{label}: the install wrote no entry in {startup:?}"
    );
    if home.kind == ShellKind::PowerShell {
        // The entry that opens the bridge is in the profile every host reads, and the one that
        // checks the reader is in the profile its own host reads: neither is in the other.
        let holds = |path: &str, marker: &str| {
            matches!(installed.get(Path::new(path)),
                Some(Node::File { bytes, .. }) if String::from_utf8_lossy(bytes).lines().any(|line| line == marker))
        };
        assert!(
            holds(".config/powershell/profile.ps1", MARKER_BEGIN)
                && !holds(".config/powershell/profile.ps1", CHECK_MARKER_BEGIN),
            "{label}: the profile every host reads does not hold the bridge entry alone"
        );
        assert!(
            holds(
                ".config/powershell/Microsoft.PowerShell_profile.ps1",
                CHECK_MARKER_BEGIN
            ) && !holds(
                ".config/powershell/Microsoft.PowerShell_profile.ps1",
                MARKER_BEGIN
            ),
            "{label}: the profile its own host reads does not hold the reader check alone"
        );
    }

    let package_directory = package
        .executable
        .parent()
        .and_then(Path::parent)
        .expect("the package directory");
    for (path, text) in text_files(&installed, package_directory) {
        assert!(
            exec_of_kr(&text).is_none(),
            "{label}: {path} runs exec on kr: {:?}",
            exec_of_kr(&text)
        );
    }

    kr.run(
        &home.environment,
        powershell,
        &["shell", "remove", "--shell", shell],
    );
    let removed = snapshot(&home.path);
    assert_eq!(
        removed,
        before,
        "{label}: the home is not what it was before the install; changed: {:?}",
        removed
            .keys()
            .chain(before.keys())
            .filter(|path| removed.get(*path) != before.get(*path))
            .collect::<Vec<_>>()
    );
}

/// The corpus cases this run can drive: a package, and every stack the case needs.
fn drivable() -> (Vec<(QualificationCase, Package)>, Vec<String>) {
    let index = StackIndex::read().unwrap_or_else(|reason| panic!("{reason}"));
    let mut cases_to_run = Vec::new();
    let mut failures = Vec::new();
    for case in cases().into_iter().filter(|case| case.supported) {
        let package = match Package::find(case.shell) {
            Ok(package) => package,
            Err(reason) => {
                failures.push(format!("{}: no package: {reason}", case.id));
                continue;
            }
        };
        let missing: Vec<&String> = case
            .requires
            .iter()
            .filter(|required| {
                !index
                    .get(required)
                    .is_some_and(shellpkg::InstalledStack::installed)
            })
            .collect();
        if !missing.is_empty() {
            failures.push(format!("{}: {missing:?} are not installed", case.id));
            continue;
        }
        cases_to_run.push((case, package));
    }
    (cases_to_run, failures)
}

/// KR-REQ-26.05: over a home holding each plugin stack the qualification runs the managed shells
/// under, the installer adds its marked entry and nothing else, adds no `exec kr`, and takes what it
/// added out again; and a managed session started over the installed home qualifies under the stack.
#[test]
#[ignore = "needs this tree's built shell packages, the fetched stacks and a built kr; it runs with --include-ignored where they are"]
fn installing_over_each_plugin_stack_adds_only_the_marked_entry_and_removes_cleanly() {
    let kr = Kr::new();
    let index = StackIndex::read().unwrap_or_else(|reason| panic!("{reason}"));
    let (driven, failures) = drivable();
    assert!(
        failures.is_empty(),
        "cases this run could not drive:\n{}",
        failures.join("\n")
    );
    assert!(
        driven.len() >= 20,
        "the corpus has shrunk to {} drivable cases",
        driven.len()
    );
    for (case, package) in &driven {
        // The install and removal, on a home of its own.
        let setup = CaseSetup::before_install(case, package, &index);
        let home = Home {
            kind: case.shell,
            path: setup.home.clone(),
            environment: setup.environment.clone(),
        };
        install_and_remove(&kr, package, &home, &case.id);

        // A session under the stack, on a home the installer has been over: what it starts is the
        // person's own configuration in the order the case records, then the integration.
        let setup = CaseSetup::before_install(case, package, &index);
        let powershell =
            (case.shell == ShellKind::PowerShell).then_some(package.executable.as_path());
        kr.run(
            &setup.environment,
            powershell,
            &["shell", "install", "--shell", case.shell.as_str()],
        );
        let mut session = Session::start_for(package, case, &setup);
        let (_, event) =
            session.expect_event("the integration's report that it is live", |event| {
                matches!(
                    event,
                    BridgeEvent::HooksActivated(_) | BridgeEvent::IntegrationLost(_)
                )
            });
        assert!(
            matches!(event, BridgeEvent::HooksActivated(_)),
            "{}: the session installed by kr did not go live: {event:?}",
            case.id
        );
        assert_eq!(
            setup.recorded_order(),
            case.order,
            "{}: the person's startup ran in another order after the install",
            case.id
        );
    }
}

/// KR-REQ-26.05: the homes the corpus does not have. A home that sources iTerm2's shell integration
/// file, a startup file that does not end in a line break, and a bash home whose login file is
/// `.profile`: each takes the entry and gives it back, and the iTerm2 file is not touched.
#[test]
#[ignore = "needs this tree's built shell packages and a built kr; it runs with --include-ignored where they are"]
fn installing_beside_iterm2_and_over_unusual_files_adds_only_the_marked_entry() {
    /// The files a home starts with: each one's name and its text.
    type StartupFiles<'a> = Vec<(&'a str, &'a str)>;

    let kr = Kr::new();
    // A file shaped like the one iTerm2 installs for zsh: it defines hooks and prints its own escape
    // sequences, and the installer reads none of it. It is here to show that the installer leaves
    // it, and the line that sources it, exactly as they are.
    let iterm2 = "# iTerm2 shell integration\nif [[ -o interactive ]]; then\n  iterm2_hostname=$(hostname)\n  \
                  precmd_functions+=(iterm2_precmd)\n  iterm2_precmd() { printf '\\033]1337;RemoteHost=%s\\a' \"$USER@$iterm2_hostname\"; }\nfi\n";
    let homes: [(&str, ShellKind, StartupFiles); 3] = [
        (
            "zsh with iTerm2's shell integration",
            ShellKind::Zsh,
            vec![
                (
                    ".zshrc",
                    "test -e \"${HOME}/.iterm2_shell_integration.zsh\" && source \"${HOME}/.iterm2_shell_integration.zsh\"\nexport EDITOR=vim\n",
                ),
                (".iterm2_shell_integration.zsh", iterm2),
            ],
        ),
        (
            "zsh with a startup file that does not end in a line break",
            ShellKind::Zsh,
            vec![(".zshrc", "export EDITOR=vim")],
        ),
        (
            "bash with a .profile that sources .bashrc",
            ShellKind::Bash,
            vec![
                (
                    ".profile",
                    "[ -f \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"\n",
                ),
                (".bashrc", "set -o vi\n"),
            ],
        ),
    ];
    for (label, kind, files) in homes {
        let package = Package::built(kind);
        let root = tempfile::Builder::new()
            .prefix("kr-install-home-")
            .tempdir()
            .expect("a directory on the internal disk");
        let path = root.path().join("home");
        std::fs::create_dir(&path).expect("a home");
        for (name, text) in files {
            std::fs::write(path.join(name), text).expect("a startup file");
        }
        let told = |directory: &Path| directory.to_str().expect("a path that is text").to_owned();
        let home = Home {
            kind,
            environment: vec![
                ("HOME".to_owned(), told(&path)),
                ("ZDOTDIR".to_owned(), told(&path)),
                ("XDG_CONFIG_HOME".to_owned(), told(&path.join(".config"))),
                ("TERM".to_owned(), "xterm-256color".to_owned()),
            ],
            path,
        };
        install_and_remove(&kr, &package, &home, label);
    }
}
