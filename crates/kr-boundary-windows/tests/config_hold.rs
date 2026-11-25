//! `config_hold`: what the tree hold's handles do to the other opens of the project, shown on a
//! Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards, on NTFS. A sharing answer comes from the handles that are open and from the
//! access check of the token that asks, and not from how the asking process was made, so each token
//! does its work on a thread that acts under it.
//!
//! The first case repeats the probe that the design rests on: with the chain handles and the
//! configuration handle held, each of four tokens (the two boundary accounts' tokens, an ordinary
//! account's token and the system's own) gets the same answer to each of eighteen operations, and a
//! control with no hold shows that every operation succeeds without it. The second case runs Git as
//! a boundary token while the holds stand.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Storage::FileSystem::ReadFile;

use kr_boundary_windows::env::{Kind, QualifiedGit, RootPaths, TreePaths, build_env};
use kr_boundary_windows::frame::invocation::{Arg, Command, Identity, LineEndings};
use kr_boundary_windows::operation::parse_operation;
use kr_boundary_windows::operation::settings::{SettingsInput, command_arguments};
use kr_boundary_windows::quote::quote_command_line;
use kr_boundary_windows::repository::config::ConfigFacts;
use kr_boundary_windows::win::acl;
use kr_boundary_windows::win::ffi::{Handle, system_windows_directory};
use kr_boundary_windows::win::hold::{TreeHold, hold_tree};
use kr_boundary_windows::win::job::{Job, Limits};
use kr_boundary_windows::win::launch::{
    ChildSpec, InvocationId, ResumePermit, Std, TokenSpec, VerifiedPath, launch, pipe,
};
use kr_boundary_windows::win::sd::{Principals, SdKind, descriptor};

use common::people::{Boundary, Person, acting_as, prepare, runs_as_the_system};
use common::{Scratch, run};

const GUEST_GIT: &str = r"C:\Program Files\Git";
const DELETE: u32 = 0x0001_0000;
const INVOCATION: InvocationId = InvocationId([9; 16]);

/// The folders of a case's project: `base\t\mid\parent\root`, with its `.git` inside the root.
struct Project {
    base: PathBuf,
    top: PathBuf,
    mid: PathBuf,
    parent: PathBuf,
    root: PathBuf,
    git: PathBuf,
}

impl Project {
    /// Makes the folders and the repository's files. Everyone has full control by inheritance, so
    /// that no refusal below comes from an access list.
    fn make(scratch: &Scratch, label: &str) -> Project {
        let base = scratch.path(label);
        fs::create_dir_all(&base).unwrap();
        run(
            "icacls",
            &[base.to_str().unwrap(), "/grant", "*S-1-1-0:(OI)(CI)F"],
        );
        let top = base.join("t");
        let mid = top.join("mid");
        let parent = mid.join("parent");
        let root = parent.join("root");
        let git = root.join(".git");
        fs::create_dir_all(git.join("objects")).unwrap();
        fs::create_dir_all(git.join("refs")).unwrap();
        fs::write(git.join("config"), CONFIG).unwrap();
        fs::write(git.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        Project {
            base,
            top,
            mid,
            parent,
            root,
            git,
        }
    }
}

const CONFIG: &str = "[core]\n\trepositoryformatversion = 0\n\tfilemode = false\n\tbare = false\n";

/// What an operation answers: success, or the platform's error number.
type Answer = Result<(), i32>;

fn code(failure: &std::io::Error) -> i32 {
    failure.raw_os_error().unwrap_or(-1)
}

/// A rename that is undone when it succeeded, so that the next operation finds the project as it was.
fn rename_and_back(from: &Path, to: &Path) -> Answer {
    match fs::rename(from, to) {
        Ok(()) => {
            fs::rename(to, from).expect("a rename that succeeded is undone");
            Ok(())
        }
        Err(failure) => Err(code(&failure)),
    }
}

/// The operations, in the order they run: what Git does to a repository (the first seven are what
/// it does while it runs) and what the probe tried to do to a held one.
fn operations(project: &Project) -> Vec<(&'static str, Answer)> {
    let config = project.git.join("config");
    let link = project.git.join("config.link");
    let lock = project.git.join("config.lock");
    let mut answers: Vec<(&'static str, Answer)> = Vec::new();
    answers.push((
        "read config",
        fs::read(&config).map(|_| ()).map_err(|e| code(&e)),
    ));
    answers.push((
        "write HEAD",
        fs::write(project.git.join("HEAD"), "ref: refs/heads/main\n").map_err(|e| code(&e)),
    ));
    let index_lock = project.git.join("index.lock");
    answers.push((
        "rename index.lock over index",
        File::create_new(&index_lock)
            .map_err(|e| code(&e))
            .and_then(|file| {
                drop(file);
                fs::rename(&index_lock, project.git.join("index")).map_err(|e| code(&e))
            }),
    ));
    answers.push((
        "add an object file",
        fs::create_dir_all(project.git.join("objects").join("ab"))
            .and_then(|()| fs::write(project.git.join("objects").join("ab").join("cdef"), b"x"))
            .map_err(|e| code(&e)),
    ));
    answers.push((
        "create config.worktree",
        File::create_new(project.git.join("config.worktree"))
            .map(|_| ())
            .map_err(|e| code(&e)),
    ));
    answers.push((
        "create commondir",
        File::create_new(project.git.join("commondir"))
            .map(|_| ())
            .map_err(|e| code(&e)),
    ));
    answers.push((
        "create a hard link to config",
        fs::hard_link(&config, &link).map_err(|e| code(&e)),
    ));
    answers.push((
        "write through the second name",
        OpenOptions::new()
            .write(true)
            .open(&link)
            .map(|_| ())
            .map_err(|e| code(&e)),
    ));
    answers.push((
        "write config",
        OpenOptions::new()
            .write(true)
            .open(&config)
            .map(|_| ())
            .map_err(|e| code(&e)),
    ));
    answers.push((
        "open config for delete",
        OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(7)
            .open(&config)
            .map(|_| ())
            .map_err(|e| code(&e)),
    ));
    let removed = fs::remove_file(&config).map_err(|e| code(&e));
    if removed.is_ok() {
        fs::write(&config, CONFIG).expect("config is made again");
    }
    answers.push(("delete config", removed));
    let renamed_over = File::create_new(&lock)
        .map_err(|e| code(&e))
        .and_then(|file| {
            drop(file);
            fs::rename(&lock, &config).map_err(|e| code(&e))
        });
    if lock.exists() {
        fs::remove_file(&lock).expect("the lock file is removed");
    }
    answers.push(("create config.lock and rename it over config", renamed_over));
    answers.push((
        "rename config",
        rename_and_back(&config, &project.git.join("config.moved")),
    ));
    answers.push((
        "rename .git",
        rename_and_back(&project.git, &project.root.join(".git-moved")),
    ));
    answers.push((
        "rename the tree's root",
        rename_and_back(&project.root, &project.parent.join("root-moved")),
    ));
    answers.push((
        "rename the root's parent",
        rename_and_back(&project.parent, &project.mid.join("parent-moved")),
    ));
    answers.push((
        "rename a directory in the middle of the chain",
        rename_and_back(&project.mid, &project.top.join("mid-moved")),
    ));
    answers.push((
        "rename the directory above it",
        rename_and_back(&project.top, &project.base.join("t-moved")),
    ));
    answers
}

const SHARING_VIOLATION: i32 = 32;
const ACCESS_DENIED: i32 = 5;

/// What each operation answers while the holds stand: the probe's answers.
fn expected_while_held(name: &str) -> Answer {
    match name {
        "read config"
        | "write HEAD"
        | "rename index.lock over index"
        | "add an object file"
        | "create config.worktree"
        | "create commondir"
        | "create a hard link to config" => Ok(()),
        "create config.lock and rename it over config" => Err(ACCESS_DENIED),
        _ => Err(SHARING_VIOLATION),
    }
}

fn report(answers: &[(&'static str, Answer)]) -> String {
    answers
        .iter()
        .map(|(name, answer)| format!("{name}: {answer:?}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_each_of_four_tokens_gets_the_probes_answers_while_the_holds_stand() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let checkout = Boundary::new("krhca");
    let connect = Boundary::new("krhcb");
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    let actors: [(&str, Option<&Handle>); 4] = [
        ("the system", None),
        (
            "the checkout account's boundary token",
            Some(&checkout.primary),
        ),
        (
            "the connect account's boundary token",
            Some(&connect.primary),
        ),
        ("an ordinary account's token", Some(&ordinary.primary)),
    ];
    for (number, (who, token)) in actors.iter().enumerate() {
        // The control: no hold, a tree of its own for each actor. Every operation succeeds.
        let control = Project::make(&scratch, &format!("control{number}"));
        let answers = acting_as(*token, || operations(&control));
        for (name, answer) in &answers {
            assert_eq!(
                *answer,
                Ok(()),
                "control, {who}, {name}: with no hold every operation succeeds\n{}",
                report(&answers)
            );
        }
        // The same operations with the holds standing.
        let project = Project::make(&scratch, &format!("held{number}"));
        let hold = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
            .expect("the tree is held");
        assert_eq!(hold.config.bytes, CONFIG.as_bytes());
        assert_eq!(hold.chain.len(), hold.identity.chain.len());
        let answers = acting_as(*token, || operations(&project));
        for (name, answer) in &answers {
            assert_eq!(
                *answer,
                expected_while_held(name),
                "held, {who}, {name}\n{}",
                report(&answers)
            );
        }
        drop(hold);
    }
}

/// Runs Git as the boundary token and gives its exit code and what it wrote.
fn git_as(
    boundary: &Boundary,
    project: &Project,
    private_root: &Path,
    arguments: &[String],
) -> (u32, String) {
    let git = format!(r"{GUEST_GIT}\mingw64\bin\git.exe");
    let tree = project.root.display().to_string();
    let env = build_env(
        Kind::Operation,
        &RootPaths {
            system: system_windows_directory().unwrap(),
            boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
            private_root: private_root.display().to_string(),
        },
        Some(&TreePaths {
            tree: tree.clone(),
            parent: project.parent.display().to_string(),
        }),
        &QualifiedGit {
            dir: GUEST_GIT.to_owned(),
        },
    )
    .unwrap();
    let process_descriptor = descriptor(
        SdKind::ProcessThread,
        &Principals {
            group: Some(boundary.group.clone()),
            ..Principals::default()
        },
    )
    .unwrap();
    let mut parts = vec![git.as_str()];
    parts.extend(arguments.iter().map(String::as_str));
    let mut job = Job::new(Limits::INVOCATION).unwrap();
    let (output, output_end) = pipe().unwrap();
    let (errors, errors_end) = pipe().unwrap();
    let child = launch(ChildSpec {
        invocation: Some(INVOCATION),
        token: TokenSpec::Boundary(&boundary.primary),
        job: &job,
        program: VerifiedPath::new(Path::new(&git)).unwrap(),
        command_line: quote_command_line(&parts),
        cwd: &project.root,
        env: &env,
        stdin: Std::Nul,
        stdout: Std::Pipe(output_end),
        stderr: Std::Pipe(errors_end),
        process_descriptor: &process_descriptor,
        thread_descriptor: &process_descriptor,
        deadline: None,
    })
    .expect("Git is started");
    let permit = ResumePermit::for_cases(INVOCATION, &child);
    let child = child.resume(permit).expect("Git is resumed");
    let mut text = read_to_end(&output);
    text.push_str(&read_to_end(&errors));
    let code = child
        .wait(Duration::from_secs(60))
        .expect("the wait is made")
        .expect("Git ends within a minute");
    let ended = job.end(&[&child], Instant::now() + Duration::from_secs(10));
    assert!(ended.all_exited && ended.active_zero);
    (code, text)
}

fn read_to_end(pipe: &Handle) -> String {
    let mut text = Vec::new();
    let mut chunk = vec![0_u8; 16 * 1024];
    loop {
        let mut read = 0_u32;
        // SAFETY: the pipe is open and the buffer is the length given.
        let ok = unsafe {
            ReadFile(
                pipe.raw(),
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &raw mut read,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            return String::from_utf8_lossy(&text).into_owned();
        }
        text.extend_from_slice(&chunk[..read as usize]);
    }
}

fn arguments_for(project: &Project, command: Command, args: &[Arg]) -> Vec<String> {
    let facts = ConfigFacts::default();
    let line = parse_operation(command, args, &facts).expect("the form is accepted");
    let identity = Identity {
        name: "Held".to_owned(),
        email: "held@example.invalid".to_owned(),
    };
    let tree = project.root.display().to_string();
    command_arguments(
        &SettingsInput {
            boundary: r"C:\Program Files\KalaReach\Boundary",
            tree: &tree,
            identity: &identity,
            line_endings: LineEndings::Unset,
        },
        &facts,
        &line,
    )
    .expect("the settings are made")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_git_runs_status_and_commit_as_the_boundary_token_while_the_holds_stand() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let boundary = Boundary::new("krhcg");
    let ordinary = Person::new("krhcq");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "git");
    // The repository is made by the system's own Git before anything is held.
    fs::remove_dir_all(&project.git).unwrap();
    let init = std::process::Command::new(format!(r"{GUEST_GIT}\mingw64\bin\git.exe"))
        .args(["init", "-b", "main"])
        .arg(&project.root)
        .output()
        .expect("Git starts");
    assert!(init.status.success(), "git init: {init:?}");
    // The folder the child may write: its private root, as the invocation's group owns it.
    let private_root = scratch.path("private");
    fs::create_dir_all(&private_root).unwrap();
    let private = descriptor(
        SdKind::PrivateRoot,
        &Principals {
            group: Some(boundary.group.clone()),
            ..Principals::default()
        },
    )
    .unwrap();
    acl::set_protected(&private_root, &private).unwrap();
    fs::create_dir_all(private_root.join("tmp")).unwrap();
    fs::create_dir_all(private_root.join("home")).unwrap();
    run(
        "icacls",
        &[
            project.root.to_str().unwrap(),
            "/grant",
            "*S-1-1-0:(OI)(CI)F",
            "/T",
            "/Q",
        ],
    );
    let hold: TreeHold = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
        .expect("the repository is held");
    let held_digest = hold.config.digest;
    let status = git_as(
        &boundary,
        &project,
        &private_root,
        &arguments_for(
            &project,
            Command::Status,
            &[Arg::Word("--porcelain=v2".to_owned())],
        ),
    );
    assert_eq!(status.0, 0, "status under the holds: {}", status.1);
    fs::write(project.root.join("file.txt"), "held\n").unwrap();
    let add = git_as(
        &boundary,
        &project,
        &private_root,
        &arguments_for(
            &project,
            Command::Add,
            &[Arg::Word("--".to_owned()), Arg::Path("file.txt".to_owned())],
        ),
    );
    assert_eq!(add.0, 0, "add under the holds: {}", add.1);
    let commit = git_as(
        &boundary,
        &project,
        &private_root,
        &arguments_for(
            &project,
            Command::Commit,
            &[Arg::Word("-m".to_owned()), Arg::Message("held".to_owned())],
        ),
    );
    assert_eq!(commit.0, 0, "commit under the holds: {}", commit.1);
    let log = std::process::Command::new(format!(r"{GUEST_GIT}\mingw64\bin\git.exe"))
        .args(["-c"])
        .arg(format!("safe.directory={}", project.root.display()))
        .args(["log", "--format=%s"])
        .current_dir(&project.root)
        .output()
        .expect("Git starts");
    assert_eq!(String::from_utf8_lossy(&log.stdout).trim(), "held");
    // Git wrote the repository and left the held configuration as it was.
    assert_eq!(
        hold.config.digest, held_digest,
        "the snapshot does not change"
    );
    assert_eq!(
        fs::read(project.git.join("config")).unwrap(),
        hold.config.bytes
    );
    drop(hold);
}
