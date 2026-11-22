//! How the broker knows its client, what it computes the client's rights from, and how the data
//! pipes keep every other account away from Git's output, shown on a Windows guest.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored
//! afterwards. A person is a throwaway local account whose token is made by the same logon the broker
//! uses for the accounts of its own, without a password; a child that runs as the person connects to
//! the broker's pipe as the person's own process. The cases make the persons' pipe in the case's own
//! process, so they need a machine on which no broker runs.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;
use windows_sys::Win32::Security::{
    ACL, CreateRestrictedToken, DACL_SECURITY_INFORMATION, DuplicateTokenEx, GetAce,
    GetTokenInformation, ImpersonateLoggedOnUser, RevertToSelf, SECURITY_CAPABILITIES,
    SID_AND_ATTRIBUTES, SecurityImpersonation, SetTokenInformation, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TokenElevationType, TokenImpersonation,
    TokenIntegrityLevel, TokenPrimary,
};
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_WRITE, OPEN_EXISTING,
    ReadFile, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT, SYNCHRONIZE, WriteFile,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessAsUserW, CreateProcessW, DETACHED_PROCESS,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, GetProcessHandleCount,
    GetProcessTimes, InitializeProcThreadAttributeList, OpenProcess, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute,
};

use kr_boundary_windows::channel::{CONNECT_BOUND, is_data_pipe_name};
use kr_boundary_windows::frame::invocation::{InvocationRequest, RefusedKind, read_request};
use kr_boundary_windows::frame::{self, Class, Request, Response};
use kr_boundary_windows::manifest::{Manifest, ObjectKind};
use kr_boundary_windows::pipe_access;
use kr_boundary_windows::standing::{
    self, MEDIUM_INTEGRITY, RULE_ELEVATED, RULE_LEVEL, RULE_LOW, RULE_NOT_ENROLLED, RULE_PROCESS,
    RULE_RESTRICTED,
};
use kr_boundary_windows::win::channel::{Outcome, make_data_pipes};
use kr_boundary_windows::win::client::{ClientIdentity, client_from_pipe, facts_of};
use kr_boundary_windows::win::ffi::{self, Handle, Sid, wide};
use kr_boundary_windows::win::pipe::{Connection, Kind, Listener, Stop};
use kr_boundary_windows::win::rights::{
    ImpersonationToken, Right, Sd, may, probe_token, system_may,
};
use kr_boundary_windows::win::sd::descriptor_from_text;
use kr_boundary_windows::win::{account, acl, broker, token};

use common::Scratch;

const ELEVATED_WORDS: &str = standing::ELEVATED_WORDS;

fn runs_as_the_system() -> bool {
    token::current_user().is_ok_and(|user| user.to_text().is_ok_and(|text| text == "S-1-5-18"))
}

/// What every case that makes a token needs: the broker's start-up and the three privileges that a
/// logon without a password and a start of a process under another token take.
fn prepare() {
    broker::init();
    for privilege in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        token::enable_privilege(privilege).unwrap();
    }
}

/// A throwaway account standing for a person, with a token of its own.
struct Person {
    name: String,
    sid: Sid,
    primary: Handle,
}

impl Person {
    fn new() -> Person {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("krperson{}", &id[..8]);
        let sid = account::create(&name).expect("the throwaway account is made");
        let primary = token::baseline_token(&name).expect("the person's token is made");
        Person { name, sid, primary }
    }

    fn token(&self) -> ImpersonationToken {
        ImpersonationToken::duplicate_of(&self.primary).unwrap()
    }
}

impl Drop for Person {
    fn drop(&mut self) {
        let _ = account::delete(&self.name);
    }
}

/// The persons' pipe, served by this process for one connection: the closure gets the connection
/// and its result is the thread's.
fn serve_once<T: Send + 'static>(
    people: Vec<Sid>,
    work: impl FnOnce(Connection) -> T + Send + 'static,
) -> JoinHandle<T> {
    assert!(
        std::fs::metadata(Kind::Persons.name()).is_err(),
        "the machine is not clean: the broker's pipe is in use"
    );
    let stop = Stop::new().unwrap();
    let mut listener = Listener::bind(Kind::Persons, &people, Arc::clone(&stop)).unwrap();
    std::thread::spawn(move || {
        let connection = loop {
            match listener.accept() {
                Ok(Some(connection)) => break connection,
                Ok(None) => panic!("the listener was stopped"),
                Err(_) => {}
            }
        };
        let result = work(connection);
        stop.set();
        drop(listener);
        result
    })
}

/// Opens a pipe by name for the rights of a client at the given security flags.
fn open_pipe(name: &str, access: u32, security: u32) -> Result<Handle, u32> {
    let name = wide(name);
    // SAFETY: the name is NUL-terminated; the result is checked.
    let opened = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            0,
            null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | security,
            null_mut(),
        )
    };
    if opened == INVALID_HANDLE_VALUE {
        // SAFETY: reads the last error of this thread.
        return Err(unsafe { GetLastError() });
    }
    Ok(Handle::new(opened, "a pipe").unwrap())
}

fn write_all(pipe: &Handle, bytes: &[u8]) {
    let mut written = 0_u32;
    // SAFETY: the pipe is open and the buffer is the length given.
    let done = unsafe {
        WriteFile(
            pipe.raw(),
            bytes.as_ptr(),
            bytes.len() as u32,
            &raw mut written,
            null_mut(),
        )
    };
    assert_ne!(done, 0, "the write on the pipe");
}

fn framed(body: &str) -> Vec<u8> {
    let mut bytes = (body.len() as u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(body.as_bytes());
    bytes
}

/// Reads up to `size` bytes; none when the read failed.
fn read_some(pipe: &Handle, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0_u8; size];
    let mut got = 0_u32;
    // SAFETY: the pipe is open and the buffer is the length given.
    let done = unsafe {
        ReadFile(
            pipe.raw(),
            buffer.as_mut_ptr(),
            size as u32,
            &raw mut got,
            null_mut(),
        )
    };
    (done != 0).then(|| {
        buffer.truncate(got as usize);
        buffer
    })
}

fn path_of_this_program() -> Vec<u16> {
    let exe = std::env::current_exe().unwrap();
    wide(&format!(
        "\"{}\" --ignored --exact zz_the_child --nocapture",
        exe.display()
    ))
}

/// A child of this program that runs as the token's account and acts for `mode`.
fn spawn_as(primary: &Handle, mode: &str) -> PROCESS_INFORMATION {
    // SAFETY: the variable is set before any thread of the case starts.
    unsafe { std::env::set_var("KR_AUTH_CHILD", mode) };
    let mut line = path_of_this_program();
    // SAFETY: a zeroed record is a valid start.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    // SAFETY: a zeroed record is a valid start.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the token is a primary token with the right to start a process; the line is a
    // mutable NUL-terminated string; the records are local.
    let made = unsafe {
        CreateProcessAsUserW(
            primary.raw(),
            null(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            DETACHED_PROCESS,
            null(),
            null(),
            &raw const startup,
            &raw mut info,
        )
    };
    assert_ne!(made, 0, "the child started under the person's token");
    info
}

fn exit_code(process: HANDLE) -> u32 {
    let waited = ffi::wait(process, 60_000, "waiting for a child of the case").unwrap();
    assert!(
        matches!(waited, ffi::Waited::Signalled(_)),
        "the child ended"
    );
    let mut code = 0_u32;
    // SAFETY: the process handle is open and has ended.
    unsafe {
        GetExitCodeProcess(process, &raw mut code);
    }
    code
}

/// The child that the cases start. It does nothing unless a case asks for it by the variable.
#[test]
#[ignore = "the helper of the cases of this file; it acts only when a case starts it"]
fn zz_the_child() {
    let Ok(mode) = std::env::var("KR_AUTH_CHILD") else {
        return;
    };
    match mode.as_str() {
        "person" => {
            let pipe = open_pipe(Kind::Persons.name(), pipe_access::CLIENT, 0x0001_0000)
                .expect("the person opens the persons' pipe");
            // A hello that names a process and a token of its own: nothing of it may count.
            write_all(
                &pipe,
                &framed(r#"{"request":"hello","version":1,"pid":4,"token":7}"#),
            );
            let size = read_some(&pipe, 4).expect("the answer's length");
            let length = u32::from_le_bytes(size.try_into().unwrap()) as usize;
            let body = read_some(&pipe, length).expect("the answer");
            assert!(String::from_utf8_lossy(&body).contains("hello"));
        }
        "wrong_client" => {
            let name = std::env::var("KR_AUTH_PIPE").unwrap();
            let pipe = open_pipe(&name, GENERIC_READ, 0).expect("the pipe opens for this account");
            // The broker disconnects every connection that is not its client's: the read fails.
            if read_some(&pipe, 1).is_some() {
                std::process::exit(7);
            }
        }
        other => panic!("no such mode: {other}"),
    }
}

// ---------------------------------------------------------------------------------------------
// The client of a connection
// ---------------------------------------------------------------------------------------------

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_person_is_identified_from_the_pipe_and_a_pid_in_a_message_changes_nothing() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let other = Person::new();
    let server = serve_once(vec![person.sid.clone()], |mut connection| {
        let first = frame::read::<_, Request>(&mut connection);
        let who = client_from_pipe(&connection);
        let alive_while_it_waits = who.as_ref().ok().map(|who| who.has_exited().unwrap());
        frame::write(&mut connection, &Response::Hello { version: 1 }).unwrap();
        (first, who, alive_while_it_waits)
    });
    let child = spawn_as(&person.primary, "person");
    let (first, who, alive) = server.join().unwrap();
    assert!(
        matches!(first, Err(frame::FrameError::Malformed(_))),
        "a pid and a token in a message are unknown fields: {first:?}"
    );
    let who = who.expect("an ordinary person is identified");
    assert_eq!(
        alive,
        Some(false),
        "the client's process is alive while it waits"
    );
    assert_eq!(
        who.pid, child.dwProcessId,
        "the pid is the pipe's, not the message's"
    );
    assert_eq!(who.user_sid, person.sid);
    // The creation time is the process's own, read from the process that the child's start returned.
    let (mut created, mut e, mut k, mut u) = ([0_u32; 2], [0_u32; 2], [0_u32; 2], [0_u32; 2]);
    // SAFETY: FILETIME is two u32; the handle is open.
    unsafe {
        GetProcessTimes(
            child.hProcess,
            created.as_mut_ptr().cast(),
            e.as_mut_ptr().cast(),
            k.as_mut_ptr().cast(),
            u.as_mut_ptr().cast(),
        );
    }
    assert_eq!(
        who.creation_time,
        (u64::from(created[1]) << 32) | u64::from(created[0])
    );
    assert_eq!(
        who.require_enrolled(std::slice::from_ref(&person.sid)),
        Ok(())
    );
    let refusal = who
        .require_enrolled(std::slice::from_ref(&other.sid))
        .expect_err("an account that is not enrolled");
    assert_eq!(refusal.rule, RULE_NOT_ENROLLED);
    assert_eq!(refusal.kind, RefusedKind::Authentication);
    assert_eq!(exit_code(child.hProcess), 0, "the child saw the answer");
    // The identity is the handle held since the connection: it says the process ended, whatever
    // process now has the number.
    assert!(who.has_exited().unwrap());
    // SAFETY: the handles came from the start of the child.
    unsafe {
        CloseHandle(child.hProcess);
        CloseHandle(child.hThread);
    }
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_an_elevated_client_and_an_unsplit_administrator_are_refused_with_the_text() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    let server = serve_once(Vec::new(), |mut connection| {
        let _ = frame::read::<_, Request>(&mut connection);
        client_from_pipe(&connection).err()
    });
    // The system's token reports the default elevation type, which an unsplit administrator's does.
    let own = own_primary();
    let mut kind = [0_u32; 2];
    let mut size = 0_u32;
    // SAFETY: the token is open and the buffer holds the 4 bytes of the class.
    unsafe {
        GetTokenInformation(
            own.raw(),
            TokenElevationType,
            kind.as_mut_ptr().cast(),
            8,
            &raw mut size,
        );
    }
    assert_eq!(kind[0], 1, "the elevation type is the default one");
    let pipe = open_pipe(Kind::Persons.name(), pipe_access::CLIENT, 0x0001_0000).unwrap();
    write_all(&pipe, &framed(r#"{"request":"hello","version":1}"#));
    let refusal = server
        .join()
        .unwrap()
        .expect("an elevated client is refused");
    assert_eq!(refusal.kind, RefusedKind::Authentication);
    assert_eq!(refusal.rule, RULE_ELEVATED);
    assert_eq!(refusal.detail(), ELEVATED_WORDS);
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_caller_that_opens_the_pipe_anonymously_cannot_be_identified() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    let server = serve_once(Vec::new(), |mut connection| {
        let _ = frame::read::<_, Request>(&mut connection);
        client_from_pipe(&connection).err()
    });
    let pipe = open_pipe(
        Kind::Persons.name(),
        pipe_access::CLIENT,
        SECURITY_ANONYMOUS,
    )
    .unwrap();
    write_all(&pipe, &framed(r#"{"request":"hello","version":1}"#));
    let refusal = server
        .join()
        .unwrap()
        .expect("an anonymous caller is refused");
    assert_eq!(refusal.rule, RULE_LEVEL);
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_process_that_runs_as_another_account_than_the_connection_is_refused() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let server = serve_once(vec![person.sid.clone()], |mut connection| {
        let _ = frame::read::<_, Request>(&mut connection);
        client_from_pipe(&connection).err()
    });
    // This process runs as the system; the connection is made by a thread that is the person.
    let primary = person.primary.raw() as usize;
    let client = std::thread::spawn(move || {
        // SAFETY: the token is open for as long as the case.
        unsafe {
            assert_ne!(ImpersonateLoggedOnUser(primary as HANDLE), 0);
        }
        let pipe = open_pipe(Kind::Persons.name(), pipe_access::CLIENT, 0x0001_0000)
            .expect("the person opens the pipe");
        // SAFETY: reverts this thread.
        unsafe {
            RevertToSelf();
        }
        write_all(&pipe, &framed(r#"{"request":"hello","version":1}"#));
        pipe
    });
    let refusal = server
        .join()
        .unwrap()
        .expect("a caller that is not its process's account");
    assert_eq!(refusal.rule, RULE_PROCESS);
    drop(client.join().unwrap());
}

// ---------------------------------------------------------------------------------------------
// What a token says of itself
// ---------------------------------------------------------------------------------------------

fn own_primary() -> Handle {
    let mut own: HANDLE = null_mut();
    // SAFETY: this process's own token, opened to be queried and copied.
    unsafe {
        assert_ne!(
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY,
                &raw mut own
            ),
            0
        );
    }
    Handle::new(own, "this process's token").unwrap()
}

/// A copy of a token with every right, as a primary token or an impersonation token.
fn copy_of(source: &Handle, primary: bool) -> Handle {
    let mut copy: HANDLE = null_mut();
    // SAFETY: the source is open with the right to be duplicated; the result is owned below.
    unsafe {
        assert_ne!(
            DuplicateTokenEx(
                source.raw(),
                TOKEN_ALL_ACCESS,
                null(),
                SecurityImpersonation,
                if primary {
                    TokenPrimary
                } else {
                    TokenImpersonation
                },
                &raw mut copy,
            ),
            0
        );
    }
    Handle::new(copy, "a copy of a token").unwrap()
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_the_facts_of_real_tokens_are_read_and_refused_by_the_rule_that_names_them() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    // An ordinary person: medium integrity, nothing elevated, nothing restricted.
    let ordinary = facts_of(&person.token()).unwrap();
    assert_eq!(standing::refuse(&ordinary), Ok(()), "{ordinary:?}");
    assert_eq!(ordinary.integrity, MEDIUM_INTEGRITY);
    // The system: elevated, the Administrators group enabled, above high integrity.
    let own = ImpersonationToken::duplicate_of(&own_primary()).unwrap();
    let system = facts_of(&own).unwrap();
    assert!(
        system.elevated && system.administrators_enabled,
        "{system:?}"
    );
    assert_eq!(standing::refuse(&system).unwrap_err().rule, RULE_ELEVATED);
    // A restricted token of the person.
    let everyone = Sid::parse("S-1-1-0").unwrap();
    let restrict = [SID_AND_ATTRIBUTES {
        Sid: everyone.as_ptr(),
        Attributes: 0,
    }];
    let mut restricted: HANDLE = null_mut();
    // SAFETY: the person's token is open; the restricting list names one identifier.
    unsafe {
        assert_ne!(
            CreateRestrictedToken(
                person.primary.raw(),
                0,
                0,
                null(),
                0,
                null(),
                1,
                restrict.as_ptr(),
                &raw mut restricted,
            ),
            0
        );
    }
    let restricted = Handle::new(restricted, "a restricted token").unwrap();
    let facts = facts_of(&ImpersonationToken::duplicate_of(&restricted).unwrap()).unwrap();
    assert!(facts.restricted, "{facts:?}");
    assert_eq!(standing::refuse(&facts).unwrap_err().rule, RULE_RESTRICTED);
    // A token of the person at low integrity.
    let low = copy_of(&person.primary, true);
    let low_sid = Sid::parse("S-1-16-4096").unwrap();
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low_sid.as_ptr(),
            Attributes: 0x20,
        },
    };
    // SAFETY: the copy has every right; the label is the structure of the class.
    unsafe {
        assert_ne!(
            SetTokenInformation(
                low.raw(),
                TokenIntegrityLevel,
                (&raw const label).cast::<c_void>(),
                size_of::<TOKEN_MANDATORY_LABEL>() as u32 + 16,
            ),
            0
        );
    }
    let facts = facts_of(&ImpersonationToken::duplicate_of(&low).unwrap()).unwrap();
    assert_eq!(facts.integrity, 0x1000);
    assert_eq!(standing::refuse(&facts).unwrap_err().rule, RULE_LOW);
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_token_of_an_app_container_is_read_as_one() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    let name = wide("krauthcontainer");
    let mut container: *mut c_void = null_mut();
    // SAFETY: the name is NUL-terminated and the result is freed below.
    unsafe {
        assert_eq!(
            DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &raw mut container),
            0
        );
    }
    let mut capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: container,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut size = 0_usize;
    // SAFETY: the first call only asks for the size of a list of one attribute.
    unsafe {
        InitializeProcThreadAttributeList(null_mut(), 1, 0, &raw mut size);
    }
    let mut list = vec![0_u64; size.div_ceil(8)];
    let attributes = list.as_mut_ptr().cast::<c_void>();
    // SAFETY: the list is the size the first call asked for; the capabilities outlive the start.
    unsafe {
        assert_ne!(
            InitializeProcThreadAttributeList(attributes, 1, 0, &raw mut size),
            0
        );
        assert_ne!(
            UpdateProcThreadAttribute(
                attributes,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw mut capabilities).cast(),
                size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            ),
            0
        );
    }
    // SAFETY: a zeroed record is a valid start.
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes;
    // SAFETY: a zeroed record is a valid start.
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut line = wide(r"C:\Windows\System32\cmd.exe");
    // SAFETY: the line is mutable and NUL-terminated; the records are local; the child starts
    // suspended and is ended below.
    let made = unsafe {
        CreateProcessW(
            null(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS,
            null(),
            null(),
            &raw const startup.StartupInfo,
            &raw mut info,
        )
    };
    assert_ne!(
        made,
        0,
        "a child of the app container starts: error {}",
        unsafe { GetLastError() }
    );
    let mut token: HANDLE = null_mut();
    // SAFETY: the process handle is open; the result is owned below.
    unsafe {
        assert_ne!(
            OpenProcessToken(info.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &raw mut token),
            0
        );
    }
    let token = Handle::new(token, "the child's token").unwrap();
    let facts = facts_of(&ImpersonationToken::duplicate_of(&token).unwrap()).unwrap();
    // SAFETY: the child has not run; the handles are the start's own; the container identifier
    // came from the platform's allocator.
    unsafe {
        TerminateProcess(info.hProcess, 1);
        CloseHandle(info.hProcess);
        CloseHandle(info.hThread);
        LocalFree(container);
    }
    assert!(facts.app_container, "{facts:?}");
    assert!(facts.integrity < MEDIUM_INTEGRITY, "{facts:?}");
    assert!(standing::refuse(&facts).is_err());
}

// ---------------------------------------------------------------------------------------------
// What a token may do to an object
// ---------------------------------------------------------------------------------------------

/// A folder with the descriptor given, as an `Sd` that an access check reads.
fn folder(scratch: &Scratch, name: &str, sddl: &str) -> (std::path::PathBuf, Sd) {
    let path = scratch.path(name);
    std::fs::create_dir_all(&path).unwrap();
    acl::set_protected(&path, &descriptor_from_text(sddl).unwrap()).unwrap();
    let handle = open_directory(&path, 0x0002_0000);
    (path, Sd::of_handle(&handle).unwrap())
}

fn open_directory(path: &std::path::Path, access: u32) -> Handle {
    let wide_path = ffi::wide_path(path);
    // SAFETY: the path is NUL-terminated.
    let opened = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            access,
            7,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    Handle::new(opened, "a folder").unwrap()
}

/// Whether a thread that acts as the person can create a file in the folder, and can list it.
fn real_open(person: &Person, path: &std::path::Path) -> (bool, bool) {
    let primary = person.primary.raw() as usize;
    let path = path.to_owned();
    std::thread::spawn(move || {
        // SAFETY: the token is open for as long as the case.
        unsafe {
            assert_ne!(ImpersonateLoggedOnUser(primary as HANDLE), 0);
        }
        let file = ffi::wide_path(&path.join("made.txt"));
        // SAFETY: the path is NUL-terminated; the result is checked.
        let created = unsafe {
            CreateFileW(
                file.as_ptr(),
                FILE_GENERIC_WRITE,
                0,
                null(),
                CREATE_NEW,
                0,
                null_mut(),
            )
        };
        let can_create = created != INVALID_HANDLE_VALUE;
        if can_create {
            // SAFETY: the handle is the one just opened.
            unsafe {
                CloseHandle(created);
            }
        }
        let dir = ffi::wide_path(&path);
        // SAFETY: the path is NUL-terminated; the result is checked.
        let listed = unsafe {
            CreateFileW(
                dir.as_ptr(),
                0x0001,
                7,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        let can_list = listed != INVALID_HANDLE_VALUE;
        if can_list {
            // SAFETY: the handle is the one just opened.
            unsafe {
                CloseHandle(listed);
            }
        }
        // SAFETY: reverts this thread.
        unsafe {
            RevertToSelf();
        }
        (can_create, can_list)
    })
    .join()
    .unwrap()
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_the_rights_come_from_the_descriptor_and_agree_with_a_real_open() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let who = person.sid.to_text().unwrap();
    let scratch = Scratch::new();
    let token = person.token();
    // (name, list, may create, may list, may change the list)
    let cases = [
        (
            "read_only",
            format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;{who})"),
            false,
            true,
            false,
        ),
        (
            "modify",
            format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;{who})"),
            true,
            true,
            false,
        ),
        (
            "no_entry",
            "O:SYD:P(A;OICI;FA;;;SY)".to_owned(),
            false,
            false,
            false,
        ),
        (
            "deny_overrides",
            format!("O:SYD:P(A;OICI;FA;;;SY)(D;OICI;0x2;;;{who})(A;OICI;0x1301bf;;;AU)"),
            false,
            true,
            false,
        ),
        (
            "generic_read",
            format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;GR;;;{who})"),
            false,
            true,
            false,
        ),
        (
            "write_dac",
            format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;{who})(A;OICI;0x40000;;;{who})"),
            true,
            true,
            true,
        ),
    ];
    for (name, list, create, list_it, change) in cases {
        let (path, sd) = folder(&scratch, name, &list);
        assert_eq!(may(&token, &sd, Right::WriteData), create, "{name}: create");
        assert_eq!(may(&token, &sd, Right::ReadData), list_it, "{name}: list");
        assert_eq!(
            may(&token, &sd, Right::WriteDac),
            change,
            "{name}: change the list"
        );
        assert_eq!(
            real_open(&person, &path),
            (create, list_it),
            "{name}: a real open agrees"
        );
    }
    // The broker's own token, with its privileges off, asks what the list gives the system.
    let (_, only_the_person) = folder(
        &scratch,
        "person_only",
        &format!("O:{who}D:P(A;OICI;FA;;;{who})"),
    );
    let (_, system_full) = folder(&scratch, "system_full", "O:SYD:P(A;OICI;FA;;;SY)");
    assert!(!system_may(&only_the_person, Right::ReadControl));
    assert!(system_may(&system_full, Right::WriteDac));
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_probe_token_stands_for_a_sibling_whose_own_account_allows_nothing() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let account = Person::new();
    let mut manifest = Manifest::begin();
    manifest.record(
        ObjectKind::Account,
        "krb-checkout",
        Some(&account.sid.to_text().unwrap()),
    );
    let probe = probe_token(&manifest, Class::Checkout).expect("the probe token is made");
    let scratch = Scratch::new();
    let who = account.sid.to_text().unwrap();
    let (_, by_account) = folder(
        &scratch,
        "by_account",
        &format!("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;{who})"),
    );
    let (_, by_users) = folder(
        &scratch,
        "by_users",
        "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)",
    );
    let baseline = account.token();
    assert!(
        may(&baseline, &by_account, Right::ReadData),
        "the account's own entry allows its baseline"
    );
    assert!(
        !may(&probe, &by_account, Right::ReadData),
        "the account's identifier is deny-only in the probe"
    );
    assert!(
        may(&probe, &by_users, Right::ReadData),
        "the groups the real token has are enabled"
    );
    let missing = Manifest::begin();
    assert!(probe_token(&missing, Class::Checkout).is_err());
}

// ---------------------------------------------------------------------------------------------
// The data pipes
// ---------------------------------------------------------------------------------------------

/// A client that is this very process, so that the pipes' wrong-client check has a pid to compare.
fn stand_in_client(person: &Sid) -> ClientIdentity {
    let pid = std::process::id();
    // SAFETY: the call takes this process's own number; the result is checked.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    ClientIdentity {
        pid,
        process: Handle::new(process, "this process").unwrap(),
        creation_time: 0,
        user_sid: person.clone(),
        token: ImpersonationToken::duplicate_of(&own_primary()).unwrap(),
    }
}

fn dacl_of(pipe: HANDLE) -> Vec<(u8, u32, String)> {
    let mut descriptor: *mut c_void = null_mut();
    let mut dacl: *mut ACL = null_mut();
    // SAFETY: the handle is an open pipe; the out-parameters are local; the block is freed below.
    unsafe {
        assert_eq!(
            GetSecurityInfo(
                pipe,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &raw mut dacl,
                null_mut(),
                &raw mut descriptor
            ),
            0
        );
        let mut entries = Vec::new();
        for index in 0..u32::from((*dacl).AceCount) {
            let mut ace: *mut c_void = null_mut();
            assert_ne!(GetAce(dacl, index, &raw mut ace), 0);
            let kind = *ace.cast::<u8>();
            let mask = *ace.cast::<u8>().add(4).cast::<u32>();
            let sid = Sid::from_ptr(ace.cast::<u8>().add(8).cast());
            entries.push((kind, mask, sid.to_text().unwrap()));
        }
        LocalFree(descriptor);
        entries
    }
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_the_data_pipes_open_to_the_person_alone_and_carry_bytes_one_way() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let client = stand_in_client(&person.sid);
    let pipes = make_data_pipes(&client).unwrap();
    assert!(is_data_pipe_name(&pipes.names.stdout) && is_data_pipe_name(&pipes.names.stderr));
    let (stdout_name, stderr_name) = (pipes.names.stdout.clone(), pipes.names.stderr.clone());
    // The stand-in host opens each pipe by name, for reading, at the anonymous level.
    let stop = Stop::new().unwrap();
    let names = (stdout_name.clone(), stderr_name.clone());
    let host = std::thread::spawn(move || {
        let out =
            open_pipe(&names.0, GENERIC_READ, SECURITY_ANONYMOUS).expect("the host opens stdout");
        let err =
            open_pipe(&names.1, GENERIC_READ, SECURITY_ANONYMOUS).expect("the host opens stderr");
        (out, err)
    });
    assert_eq!(
        pipes.wait_connected(CONNECT_BOUND, &stop).unwrap(),
        Outcome::Connected
    );
    let (out, _err) = host.join().unwrap();
    let (server_out, server_err) = pipes.into_child_ends().expect("both ends are inheritable");
    // The descriptor: the system and the person, the person with the read rights and nothing else.
    for server in [&server_out, &server_err] {
        let entries = dacl_of(server.raw());
        assert_eq!(entries.len(), 2, "{entries:?}");
        assert!(
            entries
                .iter()
                .any(|(kind, mask, sid)| *kind == 0 && *mask == 0x1f01ff && sid == "S-1-5-18")
        );
        assert!(
            entries.iter().any(|(kind, mask, sid)| *kind == 0
                && *mask == 0x0012_0089
                && *sid == person.sid.to_text().unwrap()),
            "{entries:?}"
        );
    }
    // The server end only writes: a read through it is refused.
    let mut byte = 0_u8;
    let mut got = 0_u32;
    // SAFETY: the end is open and the buffer is one byte.
    let read = unsafe { ReadFile(server_out.raw(), &raw mut byte, 1, &raw mut got, null_mut()) };
    assert_eq!(read, 0);
    // SAFETY: reads the last error of this thread.
    assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
    // What is written to the server end is what the client reads.
    let mut written = 0_u32;
    // SAFETY: the end is open and the buffer is the length given.
    unsafe {
        assert_ne!(
            WriteFile(
                server_out.raw(),
                b"git says".as_ptr(),
                8,
                &raw mut written,
                null_mut()
            ),
            0
        );
    }
    assert_eq!(read_some(&out, 8).unwrap(), b"git says");
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_boundary_token_opens_neither_data_pipe_for_any_right() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let account = Person::new();
    let boundary = token::boundary_token(&account.name, &token::new_invocation_group()).unwrap();
    let pipes = make_data_pipes(&stand_in_client(&person.sid)).unwrap();
    let names = [pipes.names.stdout.clone(), pipes.names.stderr.clone()];
    let primary = boundary.raw() as usize;
    let refused = std::thread::spawn(move || {
        // SAFETY: the token is open for as long as the case.
        unsafe {
            assert_ne!(ImpersonateLoggedOnUser(primary as HANDLE), 0);
        }
        let mut answers = Vec::new();
        for name in &names {
            for right in [
                GENERIC_READ,
                GENERIC_WRITE,
                0x1,
                0x2,
                0x4,
                0x80,
                0x2_0000,
                SYNCHRONIZE,
                0x4_0000,
                0x1_0000,
                0x0200_0000,
            ] {
                answers.push((right, open_pipe(name, right, 0).err()));
            }
        }
        // SAFETY: reverts this thread.
        unsafe {
            RevertToSelf();
        }
        answers
    })
    .join()
    .unwrap();
    for (right, answer) in refused {
        assert_eq!(answer, Some(ERROR_ACCESS_DENIED), "right {right:#x}");
    }
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_wrong_connecting_client_is_disconnected_and_the_instance_stays() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let pipes = make_data_pipes(&stand_in_client(&person.sid)).unwrap();
    let (out_name, err_name) = (pipes.names.stdout.clone(), pipes.names.stderr.clone());
    let stop = Stop::new().unwrap();
    let (waiting, done) = mpsc::channel();
    let waiter = std::thread::spawn(move || {
        let outcome = pipes
            .wait_connected(Duration::from_secs(60), &stop)
            .unwrap();
        waiting.send(()).unwrap();
        (outcome, pipes)
    });
    // Another process opens the pipe; the broker disconnects it and the instance stays.
    // SAFETY: the variables are set before the child starts and read by the child alone.
    unsafe {
        std::env::set_var("KR_AUTH_CHILD", "wrong_client");
        std::env::set_var("KR_AUTH_PIPE", &out_name);
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "zz_the_child", "--nocapture"])
        .status()
        .unwrap();
    assert!(
        status.success(),
        "the wrong client's read was refused by a disconnect: {status}"
    );
    assert!(
        done.try_recv().is_err(),
        "the wrong client did not count as the client"
    );
    // The instance is still there for the right client, whose open is the case's own process.
    let out = open_pipe(&out_name, GENERIC_READ, SECURITY_ANONYMOUS)
        .expect("the name is still the broker's");
    let err = open_pipe(&err_name, GENERIC_READ, SECURITY_ANONYMOUS).unwrap();
    let (outcome, _pipes) = waiter.join().unwrap();
    assert_eq!(outcome, Outcome::Connected);
    drop((out, err));
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_client_that_never_connects_ends_the_wait_by_its_bound_or_by_the_stop() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    prepare();
    let person = Person::new();
    let pipes = make_data_pipes(&stand_in_client(&person.sid)).unwrap();
    let stop = Stop::new().unwrap();
    let outcome = pipes
        .wait_connected(Duration::from_millis(300), &stop)
        .unwrap();
    assert_eq!(outcome, Outcome::TimedOut);
    let setter = Arc::clone(&stop);
    let release = std::thread::spawn(move || setter.set());
    let outcome = pipes
        .wait_connected(Duration::from_secs(600), &stop)
        .unwrap();
    release.join().unwrap();
    assert_eq!(outcome, Outcome::Stopped);
}

// ---------------------------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------------------------

fn handle_count() -> u32 {
    let mut count = 0_u32;
    // SAFETY: the current process pseudo-handle is always valid.
    unsafe {
        GetProcessHandleCount(GetCurrentProcess(), &raw mut count);
    }
    count
}

#[test]
#[ignore = "runs as the system in a disposable guest"]
fn broker_auth_a_handle_value_in_an_operate_frame_is_an_unknown_field_and_nothing_is_duplicated() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    let valid = serde_json::json!({
        "request": "operate", "protocol_version": 1, "class": "checkout",
        "directory": r"C:\Users\person\project", "command": "log", "arguments": [],
        "identity": { "name": "A Person", "email": "person@example.com" },
        "line_endings": "input"
    });
    // A real handle of this process, as the value that a client would put in a frame.
    let real = own_primary().raw() as usize;
    let mut frames = vec![valid.to_string()];
    for field in [
        "handle",
        "stdin",
        "stdout",
        "stderr",
        "pipe",
        "process",
        "token",
        "file",
        "directory_handle",
    ] {
        let mut body = valid.clone();
        body[field] = serde_json::json!(real);
        frames.push(body.to_string());
    }
    let count = frames.len();
    let server = serve_once(Vec::new(), move |mut connection| {
        let before = handle_count();
        let mut answers = Vec::new();
        for _ in 0..count {
            answers.push(
                read_request(&mut connection)
                    .map(|request| matches!(request, InvocationRequest::Operate(_))),
            );
        }
        (answers, before, handle_count())
    });
    let pipe = open_pipe(Kind::Persons.name(), pipe_access::CLIENT, 0x0001_0000).unwrap();
    for body in &frames {
        write_all(&pipe, &framed(body));
    }
    let (answers, before, after) = server.join().unwrap();
    assert!(
        matches!(answers[0], Ok(true)),
        "the control frame is accepted: {:?}",
        answers[0]
    );
    for answer in &answers[1..] {
        assert!(
            matches!(answer, Err(frame::FrameError::Malformed(_))),
            "{answer:?}"
        );
    }
    assert_eq!(after, before, "the reader duplicated no handle");
}
