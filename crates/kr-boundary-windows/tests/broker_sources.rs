//! What reaches a project's Git folder from outside the invocation, shown on a Windows guest: that a
//! boundary token cannot plant a file that Git reads into another tree's Git folder, and that the
//! holder of a kept token handle keeps the next request for the tree out.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored
//! afterwards, each one alone from a clean machine.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, FILETIME, GENERIC_READ, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    InitializeSecurityDescriptor, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorDacl,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, SYNCHRONIZE};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CreateProcessAsUserW, GetCurrentProcess, GetProcessTimes, OpenProcess,
    PROCESS_DUP_HANDLE, PROCESS_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
    TerminateProcess,
};

use kr_boundary_windows::env::{Kind as EnvKind, QualifiedGit, RootPaths, build_env};
use kr_boundary_windows::frame::Class;
use kr_boundary_windows::frame::invocation::{
    Cleanup, Command, Identity, InvocationReply, LineEndings, OperateRequest, RefusedKind,
    read_reply,
};
use kr_boundary_windows::lifecycle::{Session, UNCERTAIN_END_WORDS};
use kr_boundary_windows::refusal::Refusal;
use kr_boundary_windows::win::admission::{RULE_SIBLING, RULE_STALE, STALE_WORDS, admit};
use kr_boundary_windows::win::boot::BootMarker;
use kr_boundary_windows::win::client::ClientIdentity;
use kr_boundary_windows::win::ffi::{Handle, Sid, system_windows_directory, wide};
use kr_boundary_windows::win::hold::hold_tree;
use kr_boundary_windows::win::install::Paths;
use kr_boundary_windows::win::launch::VerifiedPath;
use kr_boundary_windows::win::lifecycle::fixture::{HeldTrees, Plan};
use kr_boundary_windows::win::lifecycle::testing as hooks;
use kr_boundary_windows::win::lifecycle::{
    ChildPlan, Environment, Slot, TreeHold, Trees, run_invocation,
};
use kr_boundary_windows::win::pipe::{
    Connection, Kind, Listener, ServerProcess, Stop, connect_held,
};
use kr_boundary_windows::win::rights::ImpersonationToken;
use kr_boundary_windows::win::sd::descriptor_from_text;
use kr_boundary_windows::win::{acl, session};

use common::people::{Person, Siblings, acting_as, prepare, runs_as_the_system};
use common::project::Project;
use common::{Scratch, run};

/// The files that Git reads from its folder and that change what an operation does: where objects
/// come from, which commits count, the code a hook runs, and the attributes a path gets. Each is
/// planted by making the folders on its way and then the file or folder itself.
const PLANTED: [(&str, &str); 7] = [
    ("commondir", "commondir"),
    ("an alternates file", r"objects\info\alternates"),
    ("a grafts file", r"info\grafts"),
    ("a hook", r"hooks\pre-commit"),
    ("an attributes file", r"info\attributes"),
    ("a .git file", ".git"),
    ("a worktrees folder", r"worktrees\"),
];

/// Plants one of the files in a Git folder, as the thread that calls it.
fn plant(git: &Path, relative: &str) -> std::io::Result<()> {
    let path = git.join(relative.trim_end_matches('\\'));
    if relative.ends_with('\\') {
        return std::fs::create_dir(&path);
    }
    let mut folder = git.to_path_buf();
    let steps: Vec<&str> = relative.split('\\').collect();
    for step in &steps[..steps.len() - 1] {
        folder.push(step);
        if let Err(failure) = std::fs::create_dir(&folder)
            && failure.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(failure);
        }
    }
    std::fs::write(&path, b"planted")
}

/// Adds an entry for `who` (a name, or `*` and an identifier) to the object's list.
fn grant(path: &Path, who: &str, rights: &str) {
    run(
        "icacls",
        &[path.to_str().unwrap(), "/grant", &format!("{who}:{rights}")],
    );
}

const ACCESS_DENIED: i32 = 5;

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_a_boundary_token_cannot_plant_a_file_in_another_trees_git_folder() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let client = person.as_client();
    let other = Project::make_private(&scratch, "other", &person.sid);

    // The other tree is the person's alone: admission takes it, and the boundary token's write of
    // each file is refused by the descriptor.
    let hold = hold_tree(other.root.to_str().unwrap(), &client).expect("the tree is held");
    admit(&hold, &client, &siblings.probes())
        .expect("a tree that only the person writes is admitted");
    drop(hold);
    for (what, relative) in PLANTED {
        let failure = acting_as(Some(&siblings.checkout.primary), || {
            plant(&other.git, relative)
        })
        .expect_err(&format!("{what}: the write of a boundary token is refused"));
        assert_eq!(
            failure.raw_os_error(),
            Some(ACCESS_DENIED),
            "{what}: refused by the descriptor, not by another failure: {failure}"
        );
        assert!(
            !other.git.join(relative.trim_end_matches('\\')).exists(),
            "{what}: nothing was planted"
        );
    }

    // Where everyone may write in the Git folder, admission refuses the tree, naming a write right
    // that a sibling holds; and the boundary token's write of each file then goes through, which is
    // what the refusal keeps from happening.
    grant(&other.git, "*S-1-1-0", "(OI)(CI)M");
    let hold = hold_tree(other.root.to_str().unwrap(), &client).expect("the tree is held");
    let refusal = admit(&hold, &client, &siblings.probes())
        .expect_err("a Git folder that everyone may write is refused");
    assert_eq!(refusal.rule, RULE_SIBLING, "{}", refusal.detail());
    drop(hold);
    for (what, relative) in PLANTED {
        acting_as(Some(&siblings.checkout.primary), || {
            plant(&other.git, relative)
        })
        .unwrap_or_else(|failure| {
            panic!("{what}: with the right to write, the boundary token plants it: {failure}")
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The holder of a kept token handle
// ---------------------------------------------------------------------------------------------

const GUEST_GIT: &str = r"C:\Program Files\Git";

fn bin() -> PathBuf {
    PathBuf::from(
        std::env::var_os("KR_BOUNDARY_BIN")
            .expect("KR_BOUNDARY_BIN names the directory with the stand-in"),
    )
}

fn request_for(directory: &Path) -> OperateRequest {
    OperateRequest {
        protocol_version: 1,
        class: Class::Checkout,
        directory: directory.to_str().unwrap().to_owned(),
        command: Command::Log,
        arguments: Vec::new(),
        identity: Identity {
            name: "A Person".to_owned(),
            email: "person@example.com".to_owned(),
        },
        line_endings: LineEndings::Input,
    }
}

fn process_handle(pid: u32) -> Handle {
    // SAFETY: opens a process by number for a limited query and a wait; the result is checked.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    Handle::new(raw, "a process").unwrap()
}

fn creation_of(process: &Handle) -> u64 {
    let (mut created, mut a, mut b, mut c) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the process is open for a limited query and the out-parameters are local.
    unsafe {
        GetProcessTimes(
            process.raw(),
            &raw mut created,
            &raw mut a,
            &raw mut b,
            &raw mut c,
        );
    }
    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime)
}

/// The person as a client of the broker: this process, whose pipe the connections come from, with
/// the person's own token.
fn client_of(person: &Person) -> ClientIdentity {
    let pid = std::process::id();
    let process = process_handle(pid);
    let creation_time = creation_of(&process);
    ClientIdentity {
        pid,
        process,
        creation_time,
        user_sid: person.sid.clone(),
        token: ImpersonationToken::duplicate_of(&person.primary).unwrap(),
    }
}

fn paths_under(dir: &Path) -> Paths {
    let journal = dir.join("journal");
    let run = dir.join("run");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::create_dir_all(&run).unwrap();
    Paths {
        program: dir.join("program"),
        program_top: dir.join("top"),
        data: dir.join("data"),
        journal,
        run,
        git: dir.join("git"),
        staging: dir.join("staging"),
        manifest: dir.join("manifest"),
        prior: dir.join("prior"),
    }
}

/// What a stand-in child runs: the program copied into the folder, with these arguments.
fn stand_in_plan(dir: &Path, arguments: &[&str]) -> Plan {
    let stand_in = dir.join("kr-launch-stand-in.exe");
    if std::fs::metadata(&stand_in).is_err() {
        std::fs::copy(bin().join("kr-launch-stand-in.exe"), &stand_in).unwrap();
    }
    let arguments: Vec<String> = arguments.iter().map(|text| (*text).to_owned()).collect();
    let scratch = dir.to_path_buf();
    let program = stand_in;
    Box::new(move |root: &kr_boundary_windows::win::root::PrivateRoot| {
        let name = program.display().to_string();
        let mut parts = vec![name.as_str()];
        parts.extend(arguments.iter().map(String::as_str));
        let env = build_env(
            EnvKind::Proof,
            &RootPaths {
                system: system_windows_directory().map_err(|failure| failure.to_string())?,
                boundary: r"C:\Program Files\KalaReach\Boundary".to_owned(),
                private_root: root.path().display().to_string(),
            },
            None,
            &QualifiedGit {
                dir: GUEST_GIT.to_owned(),
            },
        )
        .map_err(|failure| failure.to_string())?;
        Ok(ChildPlan {
            program: VerifiedPath::new(&program).map_err(|failure| failure.to_string())?,
            command_line: kr_boundary_windows::quote::quote_command_line(&parts),
            cwd: scratch.clone(),
            env,
        })
    })
}

fn open_data_pipe(name: &str) -> Handle {
    let wide = wide(name);
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        // SAFETY: the name is NUL-terminated; the result is checked.
        let opened = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if opened != INVALID_HANDLE_VALUE {
            return Handle::new(opened, "a data pipe").unwrap();
        }
        assert!(Instant::now() < until, "the data pipe {name} did not open");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs one invocation for the tree at `directory`: the broker's side on a thread, the client's
/// side here, which connects both data pipes and reads the replies. The replies come back in order.
fn run_one(
    env: &Arc<Environment>,
    client: ClientIdentity,
    directory: &Path,
) -> Vec<InvocationReply> {
    let mut listener = Listener::bind(
        Kind::Persons,
        &[Sid::parse("S-1-1-0").unwrap()],
        Stop::new().unwrap(),
    )
    .unwrap();
    let env = Arc::clone(env);
    let request = request_for(directory);
    let server = std::thread::spawn(move || {
        let mut connection = loop {
            match listener.accept() {
                Ok(Some(connection)) => break connection,
                Ok(None) => panic!("the listener was stopped"),
                Err(_) => {}
            }
        };
        run_invocation(&mut connection, client, &request, &env);
    });
    let me = ServerProcess::open(std::process::id()).unwrap();
    let until = Instant::now() + Duration::from_secs(30);
    let mut connection: Connection = loop {
        match connect_held(Kind::Persons, &me) {
            Ok(connection) => break connection,
            Err(failure) => {
                assert!(Instant::now() < until, "the pipe did not open: {failure}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    connection.set_deadline(Some(Instant::now() + Duration::from_secs(120)));
    let first = read_reply(&mut connection).expect("the first reply");
    let mut replies = vec![first.clone()];
    let InvocationReply::Accepted {
        stdout_pipe,
        stderr_pipe,
        ..
    } = first
    else {
        server.join().unwrap();
        return replies;
    };
    let pipes = (open_data_pipe(&stdout_pipe), open_data_pipe(&stderr_pipe));
    match read_reply(&mut connection) {
        Ok(reply) => replies.push(reply),
        Err(failure) => panic!("the last reply was not read: {failure}"),
    }
    drop(pipes);
    server.join().unwrap();
    replies
}

/// Keeps a copy of the invocation's token for the case: the broker's own handle closes, this one
/// does not.
fn hold_the_token(held: &Arc<Mutex<Option<Handle>>>) {
    let held = Arc::clone(held);
    hooks::set_hook(Some(Arc::new(move |name| {
        if name == "token made" {
            *held.lock().unwrap() = Some(copy_of_the_token());
        }
    })));
}

/// A copy of the token the broker made for the invocation in progress, in this process.
fn copy_of_the_token() -> Handle {
    let mut copy: HANDLE = std::ptr::null_mut();
    // SAFETY: duplicates a handle of this process into this process; the source is the token the
    // broker made, open while the hook that calls this runs.
    let done = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            hooks::token_handle() as HANDLE,
            GetCurrentProcess(),
            &raw mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    };
    assert_ne!(done, 0, "the token is copied");
    Handle::new(copy, "the held token").unwrap()
}

/// The broker's environment over the held trees: the project that a request names is held, given
/// its slot and admitted, and the invocation runs the stand-in that exits at once.
fn held_environment(home: &Scratch, siblings: &Siblings) -> Arc<Environment> {
    let account = siblings.checkout.name.clone();
    let trees = HeldTrees::new(siblings.probes(), stand_in_plan(&home.dir, &["exit", "0"]));
    let mut env = Environment::new(
        Box::new(move |_| Ok(account.clone())),
        paths_under(&home.dir),
        Stop::new().unwrap(),
        Arc::new(trees),
        vec![Sid::parse("S-1-1-0").unwrap()],
        &BootMarker {
            id: "sources-boot-marker".to_owned(),
            trusted: true,
            reason: None,
            made: false,
        },
    );
    env.bounds.session = Duration::from_secs(2);
    Arc::new(env)
}

/// Puts the entry of a group that this broker made on a file of the project, as the grant of an
/// invocation that did not end well leaves it.
fn leave_a_group_entry(project: &Project) -> PathBuf {
    let left = project.root.join("left.txt");
    std::fs::write(&left, b"x").unwrap();
    let group = kr_boundary_windows::win::token::new_invocation_group()
        .to_text()
        .unwrap();
    grant(&left, &format!("*{group}"), "(W)");
    left
}

/// What the next requests read after a guard was dropped without an end.
struct AfterADroppedGuard {
    /// The refusal of a second request for the same tree, when there was one.
    again: Option<Refusal>,
    /// The refusal of a request for the tree after it was moved under another parent, when there
    /// was one.
    next: Option<Refusal>,
    /// The tree's path after the move.
    moved: PathBuf,
}

/// A request is admitted and its slot taken; the group entry of its unfinished grant is left on a
/// file of the tree; then `drop_the_guard` drops the hold and the slot without an end. The row
/// closes as uncertain and holds no handles, so the tree is moved under another parent, where the
/// row no longer meets it, and a request for the moved tree is made. `None` when the case does not
/// run here.
fn after_a_dropped_guard(
    label: &str,
    drop_the_guard: impl FnOnce(Box<dyn TreeHold>, Box<dyn Slot>),
) -> Option<AfterADroppedGuard> {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return None;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let home = Scratch::new();
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, label, &person.sid);
    let trees = HeldTrees::new(siblings.probes(), stand_in_plan(&home.dir, &["exit", "0"]));
    let client = client_of(&person);
    let (hold, slot) = trees
        .resolve(&request_for(&project.root), &client)
        .unwrap_or_else(|refusal| panic!("the first request is admitted: {refusal}"));

    // The grant of that invocation leaves its group's entry on a file of the tree.
    leave_a_group_entry(&project);
    drop_the_guard(hold, slot);

    let again = trees.resolve(&request_for(&project.root), &client).err();
    let elsewhere = scratch.path(&format!("{label}-elsewhere"));
    std::fs::create_dir_all(&elsewhere).unwrap();
    let moved = elsewhere.join("moved");
    std::fs::rename(&project.root, &moved).expect("the tree is moved: no handle of it is held");
    let next = trees.resolve(&request_for(&moved), &client).err();
    Some(AfterADroppedGuard { again, next, moved })
}

/// A step that holds the tree and its slot and returns an error before it reaches an end: both are
/// dropped by the return.
fn returns_early(hold: Box<dyn TreeHold>, slot: Box<dyn Slot>) -> Result<(), &'static str> {
    let _slot = slot;
    let _hold = hold;
    Err("an early return")
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_a_guard_dropped_by_an_early_return_leaves_a_moved_tree_to_the_left_entry() {
    let Some(done) = after_a_dropped_guard("early", |hold, slot| {
        assert!(returns_early(hold, slot).is_err());
    }) else {
        return;
    };
    // The row is closed as uncertain: the same tree is refused as left unfinished.
    assert!(
        done.again.is_some(),
        "a dropped guard closes the tree: the row stays"
    );
    if let Some(refusal) = &done.again {
        assert_eq!(refusal.kind, RefusedKind::Leftover);
        assert_eq!(refusal.detail(), UNCERTAIN_END_WORDS);
    }
    // The row holds no handle of the tree: it was moved, the next request meets no row, and the
    // entry that the unfinished grant left refuses it.
    assert!(
        done.next.is_some(),
        "the moved tree is refused: the left entry stands in for the row"
    );
    if let Some(refusal) = &done.next {
        assert_eq!(refusal.rule, RULE_STALE);
        assert_eq!(
            refusal.detail(),
            format!("{STALE_WORDS} on {}", done.moved.join("left.txt").display())
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_a_guard_dropped_by_a_caught_panic_leaves_a_moved_tree_to_the_left_entry() {
    let Some(done) = after_a_dropped_guard("panic", |hold, slot| {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _slot = slot;
            let _hold = hold;
            panic!("a panic that the case catches");
        }));
        assert!(caught.is_err(), "the panic was caught");
    }) else {
        return;
    };
    // The row is closed as uncertain: the same tree is refused as left unfinished.
    assert!(
        done.again.is_some(),
        "a dropped guard closes the tree: the row stays"
    );
    if let Some(refusal) = &done.again {
        assert_eq!(refusal.kind, RefusedKind::Leftover);
        assert_eq!(refusal.detail(), UNCERTAIN_END_WORDS);
    }
    // The row holds no handle of the tree: it was moved, the next request meets no row, and the
    // entry that the unfinished grant left refuses it.
    assert!(
        done.next.is_some(),
        "the moved tree is refused: the left entry stands in for the row"
    );
    if let Some(refusal) = &done.next {
        assert_eq!(refusal.rule, RULE_STALE);
        assert_eq!(
            refusal.detail(),
            format!("{STALE_WORDS} on {}", done.moved.join("left.txt").display())
        );
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_a_request_that_the_admission_refuses_leaves_the_slot_open_for_the_next() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let home = Scratch::new();
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "refused", &person.sid);
    let env = held_environment(&home, &siblings);

    // A group entry on a file of the project: the admission refuses the tree.
    let left = leave_a_group_entry(&project);
    let first = run_one(&env, client_of(&person), &project.root);
    assert!(
        matches!(
            first.last(),
            Some(InvocationReply::Refused { detail, .. }) if detail.starts_with(STALE_WORDS)
        ),
        "{first:?}"
    );

    // The refusal gave the slot back: with the file gone, the next request runs and ends clean.
    std::fs::remove_file(&left).unwrap();
    let next = run_one(&env, client_of(&person), &project.root);
    assert!(
        matches!(
            next.last(),
            Some(InvocationReply::Finished {
                cleanup: Cleanup::Clean,
                ..
            })
        ),
        "{next:?}"
    );
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_the_holder_of_a_kept_token_handle_blocks_the_next_admission_of_the_tree() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let siblings = Siblings::new();
    let home = Scratch::new();
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "kept", &person.sid);
    let env = held_environment(&home, &siblings);

    // The invocation ends while a copy of its token is held: the session lives, so the end is not
    // proved.
    let held = Arc::new(Mutex::new(None));
    hold_the_token(&held);
    let replies = run_one(&env, client_of(&person), &project.root);
    assert!(
        matches!(
            replies.last(),
            Some(InvocationReply::Finished {
                cleanup: Cleanup::Uncertain,
                ..
            })
        ),
        "{replies:?}"
    );
    let luid = hooks::session();
    assert_ne!(luid, 0, "the invocation had a logon session");
    assert_eq!(
        session::wait_absent(luid, Duration::from_secs(1)),
        Session::Present,
        "the session {luid} lives while the copy of the token is held"
    );

    // The grant of an invocation that did not end well leaves its group's entry on the tree.
    leave_a_group_entry(&project);

    // The next request for the tree is held and takes its slot before it is admitted, so the tree
    // reads as left unfinished and not as one with a stale entry.
    let again = run_one(&env, client_of(&person), &project.root);
    assert!(
        matches!(
            again.last(),
            Some(InvocationReply::Refused { kind: RefusedKind::Leftover, detail }) if detail == UNCERTAIN_END_WORDS
        ),
        "the session {luid} keeps the tree closed: {again:?}"
    );

    // The holder lets go, and the session leaves the system's list.
    drop(held.lock().unwrap().take().expect("a handle was held"));
    assert_eq!(
        session::wait_absent(luid, Duration::from_secs(60)),
        Session::Absent,
        "the session {luid} is still in the system's list"
    );
    hooks::set_hook(None);
}

// ---------------------------------------------------------------------------------------------
// A right that a process of another account keeps
// ---------------------------------------------------------------------------------------------

/// What the peer, a process of an ordinary account in its own logon session, does: it opens the
/// section by its name and maps a view of it, says so, waits for the signal, writes through the
/// view and says so. A failure is written to the file that the case reads for the end.
const PEER_SCRIPT: &str = r#"param([string]$Dir, [string]$Name)
$ErrorActionPreference = 'Stop'
try {
    $deadline = (Get-Date).AddSeconds(60)
    $section = $null
    while ($section -eq $null -and (Get-Date) -lt $deadline) {
        try {
            $section = [System.IO.MemoryMappedFiles.MemoryMappedFile]::OpenExisting($Name, [System.IO.MemoryMappedFiles.MemoryMappedFileRights]::ReadWrite)
        } catch { Start-Sleep -Milliseconds 100 }
    }
    if ($section -eq $null) { throw 'the section did not open' }
    $view = $section.CreateViewAccessor()
    Set-Content -Path "$Dir\mapped.txt" -Value 'mapped'
    while (-not (Test-Path "$Dir\go.txt")) { Start-Sleep -Milliseconds 100 }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes('kept')
    $view.WriteArray(0, $bytes, 0, $bytes.Length)
    $view.Flush()
    Set-Content -Path "$Dir\done.txt" -Value 'written'
} catch {
    Set-Content -Path "$Dir\done.txt" -Value ('failed: ' + $_.Exception.Message)
}
"#;

/// Starts a program as the account the token belongs to. The error is read at the call that failed.
fn start_as(token: &Handle, command_line: &str, cwd: &Path) -> Result<(Handle, u32), String> {
    let mut line = wide(command_line);
    let directory = wide(&cwd.display().to_string());
    // SAFETY: a zeroed startup record with its size set, and an empty process record, are the
    // inputs the call documents.
    let (startup, mut started) = unsafe {
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        (startup, std::mem::zeroed::<PROCESS_INFORMATION>())
    };
    // SAFETY: the token is a primary token that is open; the command line is a buffer of this
    // call's own; the records outlive the call.
    let made = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            std::ptr::null(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null(),
            directory.as_ptr(),
            &raw const startup,
            &raw mut started,
        )
    };
    if made == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: the thread handle is open and is not used again.
    unsafe {
        CloseHandle(started.hThread);
    }
    Ok((
        Handle::new(started.hProcess, "the peer").map_err(|failure| failure.to_string())?,
        started.dwProcessId,
    ))
}

/// The text a file holds once it is written, or why the wait ended.
fn wait_for_text(path: &Path, seconds: u64) -> Result<String, String> {
    let until = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Ok(text) = std::fs::read_to_string(path)
            && !text.trim().is_empty()
        {
            return Ok(text.trim().to_owned());
        }
        if Instant::now() > until {
            return Err(format!(
                "{} was not written in {seconds} seconds",
                path.display()
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_sources_a_view_that_a_process_of_another_account_keeps_writes_after_the_release() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    // The peer is a second ordinary account with no right of its own on the tree's file: what it
    // writes after the release, it writes through the right that the view kept.
    let other = Person::new("krsec");
    let siblings = Siblings::new();
    let scratch = Scratch::on_drive();
    let boundary = &siblings.checkout;

    // The peer's folder, where it says what it did, and the tree's file, which the invocation's
    // group may change while the invocation lives.
    let talk = scratch.path("peer");
    std::fs::create_dir_all(&talk).unwrap();
    grant(&talk, "*S-1-1-0", "(OI)(CI)F");
    std::fs::write(talk.join("peer.ps1"), PEER_SCRIPT).unwrap();
    let project = Project::make_private(&scratch, "tree", &person.sid);
    let file = project.root.join("kept.txt");
    std::fs::write(&file, b"0123456789abcdef").unwrap();
    acl::set_protected(
        &file,
        &descriptor_from_text(&format!(
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{})(A;;FA;;;{})",
            person.sid.to_text().unwrap(),
            boundary.group.to_text().unwrap()
        ))
        .unwrap(),
    )
    .unwrap();
    let section_name = format!("krsources{}", uuid::Uuid::new_v4().simple());
    let line = format!(
        "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{}\" -Dir \"{}\" -Name {section_name}",
        talk.join("peer.ps1").display(),
        talk.display()
    );
    let (peer, pid) = match start_as(&other.primary, &line, &talk) {
        Ok(started) => started,
        Err(reason) => {
            println!(
                "NOT SHOWN: skipped, because the guest does not start a process of the account: {reason}"
            );
            return;
        }
    };

    // (1) A handle for the peer's process, which a duplicate could be put into: the process's own
    // list is its account's and the system's, and the boundary token is refused.
    let (opened, why) = acting_as(Some(&boundary.primary), || {
        // SAFETY: opens a process by number for one right; the result is checked below.
        let raw = unsafe { OpenProcess(PROCESS_DUP_HANDLE, 0, pid) };
        // SAFETY: reads this thread's last error, before anything else can change it.
        let why = unsafe { GetLastError() };
        let opened = !raw.is_null();
        if opened {
            // SAFETY: the handle was just opened and is not used.
            unsafe {
                CloseHandle(raw);
            }
        }
        (opened, why)
    });
    println!("the boundary token's open of the peer for a duplicate: opened {opened}, error {why}");
    assert!(
        !opened && why == 5,
        "the peer's process refuses the boundary token the right to duplicate into it ({why})"
    );

    // (2) A named section over the tree's file with no list, which any process opens: the boundary
    // token makes it, the peer maps it.
    let (kept_file, section) = acting_as(Some(&boundary.primary), || {
        let opened = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file)
            .expect("the group may open the tree's file");
        // SAFETY: a zeroed descriptor, initialised and given no list, is the one that every
        // process may open; the records outlive the call.
        let raw = unsafe {
            use std::os::windows::io::AsRawHandle as _;
            let mut descriptor: SECURITY_DESCRIPTOR = std::mem::zeroed();
            let pointer = (&raw mut descriptor).cast::<std::ffi::c_void>();
            InitializeSecurityDescriptor(pointer, 1);
            SetSecurityDescriptorDacl(pointer, 1, std::ptr::null(), 0);
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: pointer,
                bInheritHandle: 0,
            };
            let name = wide(&section_name);
            CreateFileMappingW(
                opened.as_raw_handle(),
                &raw const attributes,
                PAGE_READWRITE,
                0,
                0,
                name.as_ptr(),
            )
        };
        (
            opened,
            Handle::new(raw, "the section").expect("the section is made"),
        )
    });
    let peer_said = wait_for_text(&talk.join("mapped.txt"), 60)
        .or_else(|_| wait_for_text(&talk.join("done.txt"), 1));
    match peer_said {
        Ok(text) if text == "mapped" => {}
        Ok(text) => {
            println!("NOT SHOWN: skipped, because the peer did not map the section: {text}");
            // SAFETY: the peer's process handle is open for the right it needs.
            unsafe {
                TerminateProcess(peer.raw(), 1);
            }
            return;
        }
        Err(reason) => {
            println!("NOT SHOWN: skipped, because the peer said nothing: {reason}");
            // SAFETY: the peer's process handle is open for the right it needs.
            unsafe {
                TerminateProcess(peer.raw(), 1);
            }
            return;
        }
    }

    // The invocation ends and the release resets the file's list to the person's alone: a new open
    // by the boundary token is refused, and the view that the peer kept still writes the file.
    drop(section);
    drop(kept_file);
    acl::set_protected(
        &file,
        &descriptor_from_text(&format!(
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{})",
            person.sid.to_text().unwrap()
        ))
        .unwrap(),
    )
    .expect("the release resets the file's list");
    let reopened = acting_as(Some(&boundary.primary), || {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&file)
    })
    .expect_err("after the release the boundary token's new open is refused");
    assert_eq!(reopened.raw_os_error(), Some(ACCESS_DENIED), "{reopened}");
    std::fs::write(talk.join("go.txt"), b"go").unwrap();
    let written = wait_for_text(&talk.join("done.txt"), 30).expect("the peer finished");
    assert_eq!(
        written, "written",
        "the peer writes through the view it kept"
    );
    let bytes = std::fs::read(&file).expect("the file reads");
    assert!(
        bytes.starts_with(b"kept"),
        "the bytes the retained view wrote reached the file: {bytes:?}"
    );
    // SAFETY: the peer's process handle is open for the right it needs.
    unsafe {
        TerminateProcess(peer.raw(), 0);
    }
}
