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
//! a boundary token while the holds stand, and the end check finds nothing that an honest Git
//! changed. The other four cases are about what the holds do not stop: a name made after the hold,
//! a hook rewritten with content of the same length, and a hooks folder past the bounds of the
//! listing.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::fs::{self, File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::Path;
use std::time::{Duration, Instant};

use windows_sys::Win32::Storage::FileSystem::ReadFile;

use kr_boundary_windows::env::{Kind, QualifiedGit, RootPaths, TreePaths, build_env};
use sha2::{Digest, Sha256};

use kr_boundary_windows::frame::invocation::{Arg, Command, Identity, LineEndings, RefusedKind};
use kr_boundary_windows::journal::rows::{Row, SnapshotKind};
use kr_boundary_windows::operation::parse_operation;
use kr_boundary_windows::operation::settings::{SettingsInput, command_arguments};
use kr_boundary_windows::quote::quote_command_line;
use kr_boundary_windows::repository::config::ConfigFacts;
use kr_boundary_windows::win::acl;
use kr_boundary_windows::win::admission::{
    CLOUD_WORDS, ENCRYPTED_WORDS, RULE_CLOUD, RULE_ENCRYPTED,
};
use kr_boundary_windows::win::ffi::{Handle, system_windows_directory};
use kr_boundary_windows::win::hold::{
    ABSENT_NAME_WORDS, Changed, LISTING_BOUND_WORDS, RULE_ABSENT_NAME, RULE_LISTING_BOUND,
    TreeHold, hold_tree,
};
use kr_boundary_windows::win::job::{Job, Limits};
use kr_boundary_windows::win::launch::{
    ChildSpec, InvocationId, ResumePermit, Std, TokenSpec, VerifiedPath, launch, pipe,
};
use kr_boundary_windows::win::sd::{Principals, SdKind, descriptor};

use common::people::{Boundary, Person, acting_as, prepare, runs_as_the_system};
use common::project::{CONFIG, Project};
use common::{Scratch, run};

const GUEST_GIT: &str = r"C:\Program Files\Git";
const DELETE: u32 = 0x0001_0000;
const INVOCATION: InvocationId = InvocationId([9; 16]);

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
    assert_eq!(hold.pre_resume_check(), Ok(()), "a repository Git made");
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
    assert_eq!(
        hold.end_check(),
        Ok(()),
        "an honest Git leaves nothing for the end check to find"
    );
    drop(hold);
}

/// The names that must be absent from a held Git folder, as the design lists them. The cases do not
/// read the list from the crate, so a name that the crate drops is seen.
const NAMES: [&str; 6] = [
    "commondir",
    "worktrees",
    "config.worktree",
    r"objects\info\alternates",
    r"objects\info\http-alternates",
    r"info\grafts",
];

/// Writes `bytes` to `path` and makes the folders above it.
fn plant(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

/// Makes one of the names that must be absent: a folder for `worktrees`, a file for the others.
fn make_name(git: &Path, name: &str) {
    if name == "worktrees" {
        fs::create_dir_all(git.join(name)).unwrap();
    } else {
        plant(&git.join(name), b"x\n");
    }
}

fn remove_name(git: &Path, name: &str) {
    if name == "worktrees" {
        fs::remove_dir_all(git.join(name)).unwrap();
    } else {
        fs::remove_file(git.join(name)).unwrap();
    }
}

fn changed(names: &[&str]) -> Changed {
    Changed {
        names: names.iter().map(|name| (*name).to_owned()).collect(),
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_each_name_that_must_be_absent_refuses_the_repository_by_name() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    // The control: a repository with a hook, an attributes folder and the folders on the way to two
    // of the names, and none of the names, is held, and the listing says which names it looked for.
    let control = Project::make(&scratch, "absent-control");
    plant(&control.git.join(r"hooks\pre-commit"), b"#!/bin/sh\n");
    fs::create_dir_all(control.git.join(r"objects\info")).unwrap();
    fs::create_dir_all(control.git.join("info")).unwrap();
    let hold = hold_tree(control.root.to_str().unwrap(), &ordinary.as_client())
        .expect("a repository with none of the names is held");
    assert_eq!(hold.listing.absent_names, NAMES);
    drop(hold);
    for (number, name) in NAMES.iter().enumerate() {
        let project = Project::make(&scratch, &format!("absent{number}"));
        make_name(&project.git, name);
        let refusal = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
            .expect_err(&format!("{name}: the repository is refused"));
        assert_eq!(refusal.kind, RefusedKind::Repository, "{name}");
        assert_eq!(refusal.rule, RULE_ABSENT_NAME, "{name}");
        assert_eq!(
            refusal.detail(),
            format!("{ABSENT_NAME_WORDS}: {name}"),
            "{name}"
        );
    }
    // A folder on the way to a name that is a link hides what is beyond it, so the name cannot be
    // shown absent: the repository is refused by the name that cannot be shown.
    let linked = Project::make(&scratch, "absent-link");
    let elsewhere = scratch.path("elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    let link = linked.git.join(r"objects\info");
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/J",
            link.to_str().unwrap(),
            elsewhere.to_str().unwrap(),
        ],
    );
    let refusal = hold_tree(linked.root.to_str().unwrap(), &ordinary.as_client())
        .expect_err("objects\\info is a link");
    assert_eq!(
        refusal.detail(),
        format!("{ABSENT_NAME_WORDS}: objects\\info\\alternates")
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_a_name_made_after_the_hold_is_seen_before_the_resume_and_at_the_end() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let checkout = Boundary::new("krhca");
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "late");
    let hold =
        hold_tree(project.root.to_str().unwrap(), &ordinary.as_client()).expect("the tree is held");
    assert_eq!(hold.pre_resume_check(), Ok(()), "nothing is made yet");
    assert_eq!(hold.end_check(), Ok(()), "nothing is made yet");
    for name in NAMES {
        // The holds allow the creation, as the probe showed: the boundary token makes the name.
        acting_as(Some(&checkout.primary), || make_name(&project.git, name));
        assert_eq!(
            hold.pre_resume_check(),
            Err(changed(&[name])),
            "before the resume, {name}"
        );
        assert_eq!(
            hold.end_check(),
            Err(changed(&[name])),
            "at the end, {name}"
        );
        remove_name(&project.git, name);
        assert_eq!(hold.pre_resume_check(), Ok(()), "{name} removed");
        assert_eq!(hold.end_check(), Ok(()), "{name} removed");
    }
    // A second name for the held configuration changes neither its identity, its size nor its
    // bytes, and the end check sees its link count. The second name cannot be removed while the
    // configuration is held, so this is the last step.
    let second = project.git.join("config.second");
    acting_as(Some(&checkout.primary), || {
        fs::hard_link(project.git.join("config"), &second).unwrap();
    });
    assert_eq!(
        hold.end_check(),
        Err(changed(&["config"])),
        "a second name for config"
    );
    assert_eq!(
        hold.pre_resume_check(),
        Ok(()),
        "the second name is not looked for there"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_a_listed_hook_is_held_for_reading_only_and_a_new_name_is_seen_at_the_end() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "hooks");
    let hook = project.git.join(r"hooks\pre-commit");
    let nested = project.git.join(r"hooks\sub\post-merge");
    let attributes = project.git.join(r"info\attributes");
    plant(&hook, b"echo one\n");
    plant(&nested, b"echo two\n");
    plant(&attributes, b"* text=auto\n");
    let hold =
        hold_tree(project.root.to_str().unwrap(), &ordinary.as_client()).expect("the tree is held");
    // What the hold took, by name, and the journal's row of it.
    let names: Vec<&str> = hold
        .listing
        .hooks
        .iter()
        .map(|file| file.name.as_str())
        .collect();
    assert_eq!(
        names,
        [r"hooks\pre-commit", r"hooks\sub\", r"hooks\sub\post-merge"]
    );
    assert_eq!(
        hold.listing
            .info_attributes
            .as_ref()
            .map(|file| file.name.as_str()),
        Some(r"info\attributes")
    );
    let row = hold.snapshot_row(1, SnapshotKind::Initial);
    row.check_caps().expect("the journal records the row");
    match row {
        Row::RepositorySnapshot {
            config_digest,
            hooks,
            absent_names,
            ..
        } => {
            assert_eq!(config_digest, hex::encode(Sha256::digest(CONFIG)));
            assert_eq!(hooks.len(), 3);
            assert_eq!(absent_names, NAMES);
        }
        other => panic!("the snapshot is a snapshot row: {other:?}"),
    }
    assert_eq!(hold.end_check(), Ok(()), "nothing is changed yet");
    // Each listed file is held for reading and shared for reading only: a write, a rename and a
    // removal are refused with a sharing violation, whoever asks, so a kept view of a hook cannot
    // be a view of a file that is changed after the check.
    for (what, file) in [
        ("a hook", &hook),
        ("a hook in a folder", &nested),
        ("the attributes file", &attributes),
    ] {
        let written = fs::write(file, b"echo ONE\n").expect_err(what);
        assert_eq!(code(&written), SHARING_VIOLATION, "{what} is written");
        let renamed = fs::rename(file, file.with_extension("moved")).expect_err(what);
        assert_eq!(code(&renamed), SHARING_VIOLATION, "{what} is renamed");
        let removed = fs::remove_file(file).expect_err(what);
        assert_eq!(code(&removed), SHARING_VIOLATION, "{what} is removed");
    }
    assert_eq!(
        fs::read(&hook).unwrap(),
        b"echo one\n",
        "a held hook is read as before"
    );
    assert_eq!(hold.end_check(), Ok(()), "nothing changed");
    // A new hook, and a new folder in the hooks folder: neither is held, and both are seen.
    let added = project.git.join(r"hooks\post-commit");
    plant(&added, b"echo three\n");
    assert_eq!(
        hold.end_check(),
        Err(changed(&[r"hooks\post-commit"])),
        "a new hook"
    );
    fs::remove_file(&added).unwrap();
    fs::create_dir(project.git.join(r"hooks\newdir")).unwrap();
    assert_eq!(
        hold.end_check(),
        Err(changed(&[r"hooks\newdir\"])),
        "a new folder"
    );
    fs::remove_dir(project.git.join(r"hooks\newdir")).unwrap();
    assert_eq!(hold.end_check(), Ok(()), "the folder removed");
}

/// Sets a reparse point with a cloud tag on a file or a folder through a handle that asks only for
/// the right to write attributes: the share mode of a held handle does not refuse that open.
fn set_cloud_tag(path: &Path) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::System::IO::DeviceIoControl;
    let file = OpenOptions::new()
        .access_mode(0x0100)
        .share_mode(7)
        .custom_flags(0x0220_0000)
        .open(path)?;
    let mut header = [0_u8; 8];
    header[..4].copy_from_slice(&0x9000_001A_u32.to_le_bytes());
    let mut returned = 0_u32;
    // SAFETY: the file is open; the buffer is 8 bytes and its length is passed.
    let set = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0009_00A4,
            header.as_ptr().cast(),
            8,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
        )
    };
    if set == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_a_reparse_point_set_on_the_held_config_or_a_held_folder_is_seen_at_the_end() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    let project = Project::make(&scratch, "tag");
    let hold =
        hold_tree(project.root.to_str().unwrap(), &ordinary.as_client()).expect("the tree is held");
    assert_eq!(hold.end_check(), Ok(()), "nothing is changed yet");

    // A reparse point changes no byte, size, name or identity of the file: only its attributes show
    // it.
    set_cloud_tag(&project.git.join("config"))
        .expect("the guest takes a reparse point on the held config");
    assert_eq!(
        hold.end_check(),
        Err(changed(&["config"])),
        "a reparse point on the held config"
    );

    // The same on a held folder, when the guest takes a tag on a folder that holds files.
    match set_cloud_tag(&project.git) {
        Ok(()) => {
            let names = hold
                .end_check()
                .expect_err("a reparse point on a held folder");
            assert!(
                names.names.iter().any(|name| name.ends_with(".git")),
                "{names:?}"
            );
        }
        Err(failure) => {
            println!("NOT SHOWN: the guest takes no tag on a folder that holds files: {failure}");
        }
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_a_cloud_folder_on_the_way_and_an_encrypted_config_are_refused_saying_why() {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::EncryptFileW;
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();

    // A folder that a cloud service synchronises, at the tree's root and above it, is told from a
    // link the person could follow: the refusal says why the broker does not accept it.
    let tagged = |label: &str, folder: &dyn Fn(&Project) -> std::path::PathBuf| {
        let project = Project::make(&scratch, label);
        match set_cloud_tag(&folder(&project)) {
            Ok(()) => {
                let refusal = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
                    .expect_err(label);
                assert_eq!(refusal.kind, RefusedKind::Admission, "{label}");
                assert_eq!(refusal.rule, RULE_CLOUD, "{label}");
                assert!(
                    refusal.detail().ends_with(CLOUD_WORDS),
                    "{label}: {}",
                    refusal.detail()
                );
            }
            Err(failure) => {
                println!("NOT SHOWN: {label}: the guest takes no tag on that folder: {failure}");
            }
        }
    };
    tagged("cloud-root", &|project| project.root.clone());
    tagged("cloud-parent", &|project| project.parent.clone());

    // A config that the person encrypted, when the guest lets the account encrypt: the broker has no
    // key, and the refusal says so, where a data open would only say "access denied".
    let project = Project::make(&scratch, "encrypted");
    let config: Vec<u16> = project
        .git
        .join("config")
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect();
    let (done, failure) = acting_as(Some(&ordinary.primary), || {
        // SAFETY: the path is NUL-terminated and lives through the call.
        let done = unsafe { EncryptFileW(config.as_ptr()) };
        (done, std::io::Error::last_os_error())
    });
    if done == 0 {
        println!("NOT SHOWN: the account cannot encrypt a file on this guest: {failure}");
    } else {
        let refusal = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
            .expect_err("an encrypted config is refused");
        assert_eq!(refusal.rule, RULE_ENCRYPTED);
        assert!(
            refusal.detail().ends_with(ENCRYPTED_WORDS),
            "{}",
            refusal.detail()
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn config_hold_a_hooks_folder_beyond_the_bounds_is_refused_at_the_hold() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let ordinary = Person::new("krhcp");
    let scratch = Scratch::new();
    let held = |project: &Project, what: &str| {
        let hold = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
            .unwrap_or_else(|refusal| panic!("{what}: the tree is held, not refused: {refusal}"));
        drop(hold);
    };
    let refused = |project: &Project, what: &str| {
        let refusal = hold_tree(project.root.to_str().unwrap(), &ordinary.as_client())
            .expect_err(&format!("{what}: the repository is refused"));
        assert_eq!(refusal.kind, RefusedKind::Repository, "{what}");
        assert_eq!(refusal.rule, RULE_LISTING_BOUND, "{what}");
        assert_eq!(refusal.detail(), LISTING_BOUND_WORDS, "{what}");
    };
    // 128 hook files are listed and 129 are refused.
    let files = Project::make(&scratch, "files128");
    for number in 0..128 {
        plant(&files.git.join(format!(r"hooks\hook{number:03}")), b"x");
    }
    held(&files, "128 hook files");
    plant(&files.git.join(r"hooks\hook128"), b"x");
    refused(&files, "129 hook files");
    // Four levels are listed; a folder at the fourth level would be a fifth.
    let levels = Project::make(&scratch, "levels4");
    plant(&levels.git.join(r"hooks\a\b\c\file"), b"x");
    held(&levels, "four levels");
    fs::create_dir(levels.git.join(r"hooks\a\b\c\d")).unwrap();
    refused(&levels, "five levels");
    // A hook of 1 MiB is read and one byte more is refused.
    let big = Project::make(&scratch, "hook1mib");
    plant(&big.git.join(r"hooks\big"), &vec![b'x'; 1 << 20]);
    held(&big, "a hook of 1 MiB");
    plant(&big.git.join(r"hooks\big"), &vec![b'x'; (1 << 20) + 1]);
    refused(&big, "a hook of 1 MiB and a byte");
    // The attributes file has the same bound.
    let attributes = Project::make(&scratch, "attributes1mib");
    plant(
        &attributes.git.join(r"info\attributes"),
        &vec![b'#'; 1 << 20],
    );
    held(&attributes, "an attributes file of 1 MiB");
    plant(
        &attributes.git.join(r"info\attributes"),
        &vec![b'#'; (1 << 20) + 1],
    );
    refused(&attributes, "an attributes file of 1 MiB and a byte");
    // A name of 255 bytes is recorded and one of 256 is refused, counted as the journal counts: the
    // name is relative to the Git folder and each backslash is two bytes.
    let names = Project::make(&scratch, "names255");
    plant(&names.git.join(format!(r"hooks\{}", "n".repeat(248))), b"x");
    held(&names, "a name of 255 bytes");
    plant(&names.git.join(format!(r"hooks\{}", "m".repeat(249))), b"x");
    refused(&names, "a name of 256 bytes");
    // What is counted is the name as the row records it: a folder's name ends in a backslash (two
    // bytes) and a link's in `:link` (five bytes).
    let folders = Project::make(&scratch, "folders255");
    fs::create_dir(folders.git.join(format!(r"hooks\{}", "f".repeat(246)))).unwrap();
    held(&folders, "a folder name of 255 bytes");
    fs::create_dir(folders.git.join(format!(r"hooks\{}", "g".repeat(247)))).unwrap();
    refused(&folders, "a folder name of 256 bytes");
    let links = Project::make(&scratch, "links255");
    let junction = |name: String| {
        let link = links.git.join(format!(r"hooks\{name}"));
        run(
            "cmd",
            &[
                "/c",
                "mklink",
                "/J",
                link.to_str().unwrap(),
                links.root.to_str().unwrap(),
            ],
        );
    };
    junction("l".repeat(243));
    held(&links, "a link name of 255 bytes");
    junction("k".repeat(244));
    refused(&links, "a link name of 256 bytes");
}
