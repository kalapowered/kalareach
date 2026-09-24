//! The Windows endpoint, descriptor and process identity, run on Windows.
//!
//! Where this crate differs by platform, Windows differs most: a named pipe in a namespace every
//! account can see, where Unix has a socket inside an owner-only directory; an access-control list
//! where Unix has mode bits; and a creation time where Linux has start ticks. Everything here needs
//! the real thing, so this suite exists only on that platform. What it covers, row by row:
//!
//! | Row | What is checked here |
//! | --- | --- |
//! | KR-REQ-02.04, KR-REQ-05.02 | A worker's endpoint is a pipe whose protected list names its owner and no account the machine does not already trust; a caller that holds every identity the owner holds but the owner's own is refused when it opens it; and the owner arriving over the network is refused as well |
//! | KR-REQ-02.07 | The listener names the process at the other end of the pipe as the kernel records it: the process that connected, never the listener |
//! | KR-REQ-05.03 | A descriptor is published under a list that grants its owner alone, and is replaced whole: a reader holding the old version still reads the old version, and a reader by name reads one version or the other and never part of one |
//! | KR-REQ-11.52 | A process's start identity is the creation time the operating system records for that process |
//!
//! The environment identity's list and the profile it is kept in, KR-REQ-03.08, are checked by
//! this crate's own tests in `src/paths.rs`, which run on this platform too.

#![cfg(windows)]

use std::io::Read as _;
use std::os::windows::io::AsHandle as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::endpoint::Listener;
use kr_ipc::paths::{Endpoint, check_access_list};
use kr_ipc::testing::TempHost;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource, WorkerProfile};
use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::{AuthorisationKey, TimestampMs, Uuid};
use kr_protocol::session::DisplayNumber;
use kr_protocol::worker::WorkerDescriptor;

/// How long a test waits for another process before it calls that a failure.
///
/// PowerShell is not quick to start, and a build machine under load is slower still. It bounds a
/// wait; it measures nothing.
const PATIENCE: Duration = Duration::from_secs(60);

/// The name a client opens a pipe by on this machine.
fn local_name(endpoint: &Endpoint) -> String {
    format!(r"\\.\pipe\{}", endpoint.as_text())
}

/// Returns PowerShell 7, which the Windows test machine and the hosted Windows runners both have.
///
/// # Panics
///
/// Panics when it is not installed, naming what to install: a test that quietly did nothing would
/// report a pass it never earned.
fn powershell() -> PathBuf {
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join("pwsh.exe"))
            .find(|candidate| candidate.is_file())
    });
    on_path
        .or_else(|| {
            std::env::var_os("ProgramFiles")
                .map(|base| {
                    Path::new(&base)
                        .join("PowerShell")
                        .join("7")
                        .join("pwsh.exe")
                })
                .filter(|candidate| candidate.is_file())
        })
        .unwrap_or_else(|| {
            panic!(
                "PowerShell 7 is not installed on this machine, and these tests ask the operating \
                 system through it; install it from https://aka.ms/powershell or with `winget \
                 install Microsoft.PowerShell`. See docs/host/README.md."
            )
        })
}

/// Writes one PowerShell script where the test can run it, and returns its path.
fn script(host: &TempHost, name: &str, text: &str) -> PathBuf {
    let path = host.root().join(format!("{name}.ps1"));
    std::fs::write(&path, text).expect("writes the script");
    path
}

/// Builds the command that runs a script with its arguments, unattended.
fn powershell_running(script: &Path, arguments: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new(powershell());
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(script)
        .args(arguments)
        .stdin(std::process::Stdio::null());
    command
}

/// Runs a script to its end and returns what it printed, failing the test when it failed.
fn output_of(script: &Path, arguments: &[&str]) -> String {
    let output = powershell_running(script, arguments)
        .output()
        .expect("PowerShell starts");
    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{} failed: {printed}\n{}",
        script.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    printed
}

/// Opens the pipe once under a token that holds everything this process holds except the identity
/// that owns the pipe, then once as this process, and prints the Windows error of each: zero where
/// the open succeeded.
///
/// The token is this process's own with its user, and the owner new objects of this process
/// receive, made deny-only. Every group stays: everyone, the authenticated users, the interactive
/// users and whatever else this account is a member of. So a list that granted any account but
/// the pipe's owner lets the first open through, and a list that grants the owner alone refuses it
/// with an access denial. The second open is the control: the owner is admitted.
const OPEN_WITHOUT_THE_OWNER: &str = r#"
param([string]$Pipe)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

public static class KrOwnerProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { public IntPtr Sid; public uint Attributes; }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CreateRestrictedToken(IntPtr existing, uint flags, uint disableCount,
        SidAndAttributes[] disable, uint deleteCount, IntPtr delete, uint restrictCount,
        IntPtr restrict, out IntPtr created);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security,
        uint disposition, uint flags, IntPtr template);

    // TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE and TOKEN_QUERY.
    private const uint TokenAccess = 0x0001 | 0x0002 | 0x0004 | 0x0008;
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint OpenExisting = 3;

    public static int Open(string path)
    {
        IntPtr handle = CreateFileW(path, GenericRead | GenericWrite, 0, IntPtr.Zero, OpenExisting,
            0, IntPtr.Zero);
        if (handle == new IntPtr(-1)) { return Marshal.GetLastWin32Error(); }
        CloseHandle(handle);
        return 0;
    }

    public static int OpenWithoutTheOwner(string path)
    {
        WindowsIdentity self = WindowsIdentity.GetCurrent();
        List<SecurityIdentifier> owners = new List<SecurityIdentifier>();
        owners.Add(self.User);
        if (self.Owner != null && !self.Owner.Equals(self.User)) { owners.Add(self.Owner); }
        List<IntPtr> buffers = new List<IntPtr>();
        try
        {
            SidAndAttributes[] disable = new SidAndAttributes[owners.Count];
            for (int index = 0; index < owners.Count; index++)
            {
                byte[] binary = new byte[owners[index].BinaryLength];
                owners[index].GetBinaryForm(binary, 0);
                IntPtr buffer = Marshal.AllocHGlobal(binary.Length);
                buffers.Add(buffer);
                Marshal.Copy(binary, 0, buffer, binary.Length);
                disable[index].Sid = buffer;
                disable[index].Attributes = 0;
            }
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), TokenAccess, out token))
            {
                throw new System.ComponentModel.Win32Exception();
            }
            IntPtr restricted;
            bool made = CreateRestrictedToken(token, 0, (uint)disable.Length, disable, 0,
                IntPtr.Zero, 0, IntPtr.Zero, out restricted);
            int failure = Marshal.GetLastWin32Error();
            CloseHandle(token);
            if (!made) { throw new System.ComponentModel.Win32Exception(failure); }
            int result = -1;
            using (SafeAccessTokenHandle held = new SafeAccessTokenHandle(restricted))
            {
                WindowsIdentity.RunImpersonated(held, () => { result = Open(path); });
            }
            return result;
        }
        finally
        {
            foreach (IntPtr buffer in buffers) { Marshal.FreeHGlobal(buffer); }
        }
    }
}
'@
$refused = [KrOwnerProbe]::OpenWithoutTheOwner($Pipe)
$admitted = [KrOwnerProbe]::Open($Pipe)
Write-Output "refused=$refused admitted=$admitted"
"#;

/// Connects to a pipe on this machine as its client, says so, and stays connected for a minute.
const CONNECT_AND_WAIT: &str = r"
param([string]$Name)
$ErrorActionPreference = 'Stop'
$client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $Name,
    [System.IO.Pipes.PipeDirection]::InOut)
$client.Connect(60000)
Write-Output 'connected'
Start-Sleep -Seconds 60
";

/// Prints when the operating system says one process was created, in whole seconds since 1970.
///
/// The standard library of PowerShell reads it through its own process API, not through the reader
/// under test.
const CREATED_AT: &str = r"
param([int]$Id)
$ErrorActionPreference = 'Stop'
$started = (Get-Process -Id $Id).StartTime
Write-Output ([DateTimeOffset]::new($started.ToUniversalTime()).ToUnixTimeSeconds())
";

/// KR-REQ-02.04, KR-REQ-05.02: a worker's private endpoint carries the operating system's access
/// control. On this platform the endpoint is a named pipe rather than a file in an owner-only
/// directory, so the pipe has to carry the list itself, and what it carries is read back here from
/// a handle to the pipe the listener made: it is owned by this account, it is protected so nothing
/// is inherited into it, and it grants no account the machine does not already trust.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workers_pipe_carries_a_protected_list_of_its_own() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let _listener = Listener::bind(&endpoint).expect("binds the endpoint");

    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(local_name(&endpoint))
        .expect("the owner opens the worker's pipe");
    check_access_list(pipe.as_handle(), "the worker's pipe", true)
        .expect("the pipe's list is its own and names nobody the machine does not already trust");
}

/// KR-REQ-05.02: the list a worker's pipe carries is what the operating system enforces when the
/// pipe is opened. A caller that holds every identity this account holds except the one that owns
/// the pipe, every group included, is refused with an access denial; the owner opening the same
/// pipe a moment later is admitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_without_the_owners_identity_is_refused_when_it_opens_the_pipe() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let _listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let probe = script(&host, "open-without-the-owner", OPEN_WITHOUT_THE_OWNER);

    let path = local_name(&endpoint);
    let printed = tokio::task::spawn_blocking(move || output_of(&probe, &[&path]))
        .await
        .expect("the probe finishes");
    let printed = printed.trim();
    // Error 5 is the access denial. Anything else, including an open that succeeded, is not the
    // list refusing the caller.
    assert!(
        printed.contains("refused=5 "),
        "a caller without the owner's identity is denied access to the pipe: {printed}"
    );
    assert!(
        printed.ends_with("admitted=0"),
        "and the owner is admitted to the same pipe: {printed}"
    );
}

/// KR-REQ-05.02: a network client reaches a worker only through the control daemon. A named pipe
/// can be opened from another machine by name, through the machine's file-sharing server, unless
/// the pipe refuses remote callers, and that is also how the pipe's own owner arrives when it
/// names this machine over the network. So the owner tries that path twice: to a pipe made to
/// accept remote callers, which shows the path is open on this machine, and to the worker's pipe,
/// which refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_owner_arriving_over_the_network_is_refused() {
    use interprocess::os::windows::named_pipe::{PipeListenerOptions, pipe_mode};
    use interprocess::os::windows::security_descriptor::SecurityDescriptor;

    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let _listener = Listener::bind(&endpoint).expect("binds the endpoint");

    let control = format!("kr-network-control-{}", kr_ipc::new_uuid());
    // Everyone, and remote callers accepted: the only thing that can refuse the owner here is the
    // path itself.
    let everyone = SecurityDescriptor::deserialize(
        &widestring::U16CString::from_str("D:(A;;GA;;;WD)").expect("valid text"),
    )
    .expect("a list that grants everyone");
    let _accepting = PipeListenerOptions::new()
        .path(format!(r"\\.\pipe\{control}"))
        .accept_remote(true)
        .security_descriptor(Some(everyone))
        .create_duplex::<pipe_mode::Bytes>()
        .expect("a pipe that accepts remote callers");

    let over_the_network = |name: String| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!(r"\\localhost\pipe\{name}"))
    };
    let path_is_open = tokio::task::spawn_blocking({
        let control = control.clone();
        move || over_the_network(control)
    })
    .await
    .expect("the open finishes");
    if let Err(error) = path_is_open {
        panic!(
            "this machine does not reach a pipe over its own file-sharing server, so whether the \
             worker's pipe refuses a network caller was not established: {error}. The Server \
             service has to be running; see docs/host/README.md."
        );
    }
    let name = endpoint.as_text();
    let refused = tokio::task::spawn_blocking(move || over_the_network(name))
        .await
        .expect("the open finishes");
    assert!(
        refused.is_err(),
        "the worker's pipe refuses a caller that arrives over the network"
    );
}

/// KR-REQ-02.07: a command line on this machine is authenticated by what the operating system
/// says about the other end of its connection. The pipe names the process that opened it, and the
/// listener reports that process: another process that connects is named as itself, with the start
/// identity the kernel gives it, and never as the listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listener_names_the_process_at_the_other_end_of_the_pipe() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let connect = script(&host, "connect-and-wait", CONNECT_AND_WAIT);

    let mut client = powershell_running(&connect, &[&endpoint.as_text()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the client starts");
    let accepted = tokio::time::timeout(PATIENCE, listener.accept()).await;
    let client_id = client.id();
    let identity = kr_ipc::identity::process_start_identity(client_id);
    let _ = client.kill();
    let _ = client.wait();

    let (_connection, peer) = accepted
        .expect("the client connected in time")
        .expect("the listener accepts it");
    assert_eq!(
        peer.pid,
        Some(client_id),
        "the listener names the process that connected"
    );
    assert_ne!(
        peer.pid,
        Some(std::process::id()),
        "and not the listener itself"
    );
    let identity = identity.expect("the kernel describes the process that connected");
    assert_eq!(identity.pid.get(), u64::from(client_id));
    assert_eq!(
        identity.source,
        ProcessStartSource::WindowsProcessStartSeconds
    );
}

/// KR-REQ-11.52: what binds a caller to its own process and start time is the operating system's
/// record of that process. The start identity this host reads for a process is the creation time
/// the operating system gives for it, in whole seconds, read here through PowerShell's own process
/// API rather than the reader under test; the identity reads as running while the process runs,
/// another start value under the same identifier reads as another process, and once the process has
/// gone the identity reads as ended.
#[test]
fn a_process_start_identity_is_the_creation_time_the_system_records() {
    let host = TempHost::create();
    let created_at = script(&host, "created-at", CREATED_AT);
    let mut child = std::process::Command::new("ping.exe")
        .args(["-n", "60", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a process to describe");
    let pid = child.id();
    let identity = kr_ipc::identity::process_start_identity(pid);
    let recorded = output_of(&created_at, &[&pid.to_string()]);
    let running = identity.as_ref().map(kr_ipc::identity::process_state).ok();
    let mut another = identity.as_ref().ok().cloned();
    if let Some(another) = another.as_mut() {
        another.start_value = kr_protocol::scalars::U64::new(another.start_value.get() + 1);
    }
    let _ = child.kill();
    let _ = child.wait();

    let identity = identity.expect("the kernel describes the process");
    let recorded: u64 = recorded
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("PowerShell printed a creation time: {recorded:?}"));
    assert_eq!(
        identity,
        ProcessStartIdentity::new(
            u64::from(pid),
            ProcessStartSource::WindowsProcessStartSeconds,
            recorded
        ),
        "the start identity is the process and the creation time the operating system records"
    );
    assert_eq!(running, Some(kr_ipc::identity::ProcessState::Running));
    assert_eq!(
        another.map(|another| kr_ipc::identity::process_state(&another)),
        Some(kr_ipc::identity::ProcessState::Ended),
        "another start value under the same identifier is another process"
    );
    let deadline = Instant::now() + PATIENCE;
    while kr_ipc::identity::process_state(&identity) != kr_ipc::identity::ProcessState::Ended {
        assert!(
            Instant::now() < deadline,
            "the process was ended and its identity still reads as {:?}",
            kr_ipc::identity::process_state(&identity)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A descriptor for `session` in `host`'s environment, naming `endpoint`.
fn descriptor(host: &TempHost, session: u8, endpoint: &str) -> WorkerDescriptor {
    WorkerDescriptor {
        session_id: SessionId::new(Uuid::from_bytes([session; 16])),
        session_epoch: SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: DisplayNumber::new(u64::from(session)),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: kr_ipc::identity::current_process_start_identity()
            .expect("this process's identity"),
        protocol_version: PROTOCOL_VERSION,
        endpoint: endpoint.to_owned(),
        worker_public_key: AuthorisationKey::from_bytes([session; 32]),
        worker_profile: WorkerProfile::HeadlessUser,
        published_at_ms: TimestampMs::new(1),
    }
}

/// Opens a directory the way this host's own checks do.
fn opened_directory(path: &Path) -> std::fs::File {
    use std::os::windows::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .expect("opens the directory")
}

/// KR-REQ-05.03: a worker's descriptor is published owner-only. The file's list, read back from a
/// handle to the file, belongs to this account and grants no account the machine does not already
/// trust, and the directory it is published in carries a protected list of its own, so nothing
/// above it can widen what a descriptor inherits.
#[test]
fn a_descriptor_is_published_under_a_list_of_its_owners_own() {
    let host = TempHost::create();
    let paths = host.environment();
    let published = descriptor(&host, 1, "kalareach-descriptor-list");
    kr_ipc::descriptor::publish(&paths, &published).expect("publishes");

    let file = std::fs::File::open(paths.descriptor_file(published.session_id))
        .expect("the descriptor is there");
    check_access_list(file.as_handle(), "the descriptor", false)
        .expect("the descriptor's list names nobody the machine does not already trust");
    check_access_list(
        opened_directory(&paths.descriptors_dir()).as_handle(),
        "the descriptor directory",
        true,
    )
    .expect("the directory it is published in carries a protected list of its own");
    assert_eq!(
        kr_ipc::descriptor::read(&paths, published.session_id)
            .expect("reads")
            .expect("present"),
        published,
        "and it reads back as it was published"
    );
}

/// KR-REQ-05.03: a descriptor is published atomically. A reader that opened the descriptor before
/// it was published again still reads the version it opened, whole, because the new version is a
/// new file that replaced the old one's name rather than new bytes written into the old file; a
/// reader by name reads the new version, whole. And a reader that keeps reading while the
/// descriptor is published again and again always finds one version or the other: never nothing,
/// never part of one.
#[test]
fn a_descriptor_is_replaced_whole_and_a_reader_keeps_the_version_it_opened() {
    let host = TempHost::create();
    let paths = host.environment();
    let first = descriptor(&host, 2, "kalareach-descriptor-first");
    let second = descriptor(&host, 2, "kalareach-descriptor-second-and-longer");
    kr_ipc::descriptor::publish(&paths, &first).expect("publishes");
    let file = paths.descriptor_file(first.session_id);

    let mut held = std::fs::File::open(&file).expect("a reader opens the descriptor");
    kr_ipc::descriptor::publish(&paths, &second)
        .expect("publishes again while a reader holds the version before");
    let mut kept = Vec::new();
    held.read_to_end(&mut kept)
        .expect("the reader reads what it opened");
    assert_eq!(
        kept,
        kr_cbor::to_canonical_vec(&first).expect("encodes"),
        "a reader holding the version before reads that version, whole"
    );
    assert_eq!(
        std::fs::read(&file).expect("reads by name"),
        kr_cbor::to_canonical_vec(&second).expect("encodes"),
        "a reader by name reads the version published since, whole"
    );
    drop(held);

    let versions = [first, second];
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = std::thread::spawn({
        let paths = paths.clone();
        let stop = std::sync::Arc::clone(&stop);
        let versions = versions.clone();
        move || {
            let mut reads = 0_u64;
            let mut wrong = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match kr_ipc::descriptor::read(&paths, versions[0].session_id) {
                    Ok(Some(found)) if versions.contains(&found) => {}
                    other => wrong.push(format!("{other:?}")),
                }
                reads += 1;
            }
            (reads, wrong)
        }
    });
    for round in 0..300 {
        kr_ipc::descriptor::publish(&paths, &versions[round % 2])
            .unwrap_or_else(|error| panic!("publication {round} failed: {error}"));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let (reads, wrong) = reader.join().expect("the reader finishes");
    assert!(reads > 0, "the descriptor was read while it was published");
    assert!(
        wrong.is_empty(),
        "{} of {reads} reads found something other than a whole version: {:?}",
        wrong.len(),
        wrong.iter().take(3).collect::<Vec<_>>()
    );
}
