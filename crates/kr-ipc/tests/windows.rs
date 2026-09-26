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
//! | KR-REQ-05.03 | A descriptor is published under a list that grants its owner alone, and is replaced whole: a reader holding the old version still reads the old version, and a reader by name reads one version or the other and never part of one. A reader refuses a descriptor whose list grants another account, a directory whose list is widened, one reached through a junction, and a file in a directory swapped since it was checked |
//! | KR-REQ-11.52 | A process's start identity is the creation time the operating system records for that process, two processes started within one second carry two start values, and a process this account may only ask when it started is identified without its liveness being guessed |
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

/// Prints when the operating system says one process was created, in hundreds of nanoseconds since
/// 1970.
///
/// The standard library of PowerShell reads it through its own process API, not through the reader
/// under test, and keeps the unit the kernel records.
const CREATED_AT: &str = r"
param([int]$Id)
$ErrorActionPreference = 'Stop'
$started = (Get-Process -Id $Id).StartTime.ToUniversalTime()
Write-Output ($started.Ticks - [DateTime]::UnixEpoch.Ticks)
";

/// Prints when the operating system says each of two processes was created, in hundreds of
/// nanoseconds since 1970, one line each in the order given.
///
/// The standard library of PowerShell reads it through its own process API, not through the reader
/// under test, and keeps the unit the kernel records.
const CREATED_TICKS: &str = r"
param([int]$First, [int]$Second)
$ErrorActionPreference = 'Stop'
foreach ($id in @($First, $Second)) {
    $started = (Get-Process -Id $id).StartTime.ToUniversalTime()
    Write-Output ($started.Ticks - [DateTime]::UnixEpoch.Ticks)
}
";

/// Hundreds of nanoseconds in one second, the unit Windows records a creation time in.
const TICKS_PER_SECOND: u64 = 10_000_000;

/// Replaces one process's access-control list with a protected one that grants this account the
/// rights given, in hexadecimal, and nobody anything else, and prints `granted`.
///
/// The owner of a process may always rewrite its list, so this needs no privilege.
const GRANT_ONLY: &str = r#"
param([int]$Id, [string]$Rights)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class KrProcessList
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string sddl, uint revision, out IntPtr descriptor, IntPtr size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr descriptor, out bool present, out IntPtr dacl, out bool defaulted);

    [DllImport("advapi32.dll")]
    private static extern uint SetSecurityInfo(IntPtr handle, int type, uint information,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr memory);

    private const uint WriteDac = 0x00040000;
    private const int KernelObject = 6;
    private const uint DaclInformation = 0x00000004;
    private const uint ProtectedDacl = 0x80000000;

    public static void Grant(int pid, uint rights)
    {
        string user = WindowsIdentity.GetCurrent().User.Value;
        IntPtr process = OpenProcess(WriteDac, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception();
        try
        {
            IntPtr descriptor;
            string sddl = "D:P(A;;0x" + rights.ToString("x") + ";;;" + user + ")";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out descriptor,
                    IntPtr.Zero))
                throw new Win32Exception();
            try
            {
                bool present;
                bool defaulted;
                IntPtr dacl;
                if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted))
                    throw new Win32Exception();
                uint error = SetSecurityInfo(process, KernelObject,
                    DaclInformation | ProtectedDacl, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (error != 0) throw new Win32Exception((int)error);
            }
            finally { LocalFree(descriptor); }
        }
        finally { CloseHandle(process); }
    }
}
'@
[KrProcessList]::Grant($Id, [Convert]::ToUInt32($Rights, 16))
Write-Output 'granted'
"#;

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
/// names this machine over the network. So the owner tries that path twice: to a pipe that carries
/// the worker pipe's own list and accepts remote callers, which shows that the path is open on
/// this machine and that the list admits the owner arriving that way, and to the worker's pipe,
/// which differs from it only in refusing remote callers and refuses it.
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
    // The list a worker's pipe carries, and remote callers accepted: whatever refuses the owner on
    // the worker's pipe and not here is the refusal of remote callers, not the list.
    let owner_only = SecurityDescriptor::deserialize(
        &widestring::U16CString::from_str("D:P(A;;GA;;;OW)").expect("valid text"),
    )
    .expect("the list a worker's pipe carries");
    let _accepting = PipeListenerOptions::new()
        .path(format!(r"\\.\pipe\{control}"))
        .accept_remote(true)
        .security_descriptor(Some(owner_only))
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
            "the owner does not reach a pipe with the worker's list over this machine's own \
             file-sharing server, so whether the worker's pipe refuses a network caller was not \
             established: {error}. The Server service has to be running, and the owner has to \
             arrive over the network with the identity that owns the pipe."
        );
    }
    let name = endpoint.as_text();
    let refused = tokio::task::spawn_blocking(move || over_the_network(name))
        .await
        .expect("the open finishes");
    // An access denial, and not a name that was not found or a pipe that was busy: those would
    // say nothing about whether the pipe refuses a network caller.
    assert_eq!(
        refused.err().map(|error| error.kind()),
        Some(std::io::ErrorKind::PermissionDenied),
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
        ProcessStartSource::WindowsProcessCreationTime
    );
}

/// KR-REQ-11.52: what binds a caller to its own process and start time is the operating system's
/// record of that process. The start identity this host reads for a process is the creation time
/// the operating system gives for it, in hundreds of nanoseconds since 1970, read here through
/// PowerShell's own process API rather than the reader under test; the identity reads as running
/// while the process runs, another start value under the same identifier - one interval of the
/// kernel's later - reads as another process, and once the process has gone the identity reads as
/// ended.
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
    // Both readings are taken while the process runs, so the only difference between the two
    // identities they are asked about is the start value.
    let running = identity.as_ref().map(kr_ipc::identity::process_state).ok();
    let another = identity
        .as_ref()
        .ok()
        .map(|identity| {
            let mut another = identity.clone();
            another.start_value = kr_protocol::scalars::U64::new(identity.start_value.get() + 1);
            another
        })
        .map(|another| kr_ipc::identity::process_state(&another));
    let still_running = child.try_wait().expect("the process's status").is_none();
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
            ProcessStartSource::WindowsProcessCreationTime,
            recorded
        ),
        "the start identity is the process and the creation time the operating system records"
    );
    assert!(
        still_running,
        "the process was still running when both identities were asked about"
    );
    assert_eq!(running, Some(kr_ipc::identity::ProcessState::Running));
    assert_eq!(
        another,
        Some(kr_ipc::identity::ProcessState::Ended),
        "another start value under the same identifier, while the process runs, is another process"
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

/// KR-REQ-11.52: two processes started one after the other within one second are two start
/// identities, because the start value is the creation time at the resolution the kernel records
/// it.
///
/// The creation times are read through PowerShell as well, not through the reader under test, to
/// establish two things about each pair before anything is asserted: that both fall in one second,
/// which is where a start value in whole seconds gives the two processes one value; and that the
/// kernel recorded two creation times, since two processes it stamped alike are two processes no
/// reader can tell apart by when they started. A pair that is not both is started again.
#[test]
fn two_processes_started_within_one_second_carry_different_start_values() {
    const ATTEMPTS: usize = 20;
    let host = TempHost::create();
    let created_ticks = script(&host, "created-ticks", CREATED_TICKS);
    let start = || {
        std::process::Command::new("ping.exe")
            .args(["-n", "60", "127.0.0.1"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("a process to describe")
    };
    let mut passed_over = Vec::new();
    for _ in 0..ATTEMPTS {
        let mut first = start();
        let mut second = start();
        let pids = [first.id(), second.id()];
        let identities = pids.map(kr_ipc::identity::process_start_identity);
        let recorded = output_of(
            &created_ticks,
            &[&pids[0].to_string(), &pids[1].to_string()],
        );
        for child in [&mut first, &mut second] {
            let _ = child.kill();
            let _ = child.wait();
        }
        let ticks: Vec<u64> = recorded
            .lines()
            .map(|line| {
                line.trim()
                    .parse()
                    .unwrap_or_else(|_| panic!("PowerShell printed a creation time: {recorded:?}"))
            })
            .collect();
        let [first_ticks, second_ticks] = ticks[..] else {
            panic!("PowerShell printed two creation times: {recorded:?}");
        };
        if first_ticks == second_ticks
            || first_ticks / TICKS_PER_SECOND != second_ticks / TICKS_PER_SECOND
        {
            passed_over.push((first_ticks, second_ticks));
            continue;
        }
        let [first_identity, second_identity] =
            identities.map(|identity| identity.expect("the kernel describes the process"));
        assert_eq!(first_identity.pid.get(), u64::from(pids[0]));
        assert_eq!(second_identity.pid.get(), u64::from(pids[1]));
        assert_ne!(
            first_identity.start_value,
            second_identity.start_value,
            "two processes created {} hundred-nanosecond intervals apart within one second carry \
             different start values: {first_identity:?} and {second_identity:?}",
            second_ticks.abs_diff(first_ticks)
        );
        // Each is the creation time PowerShell reads, in the same unit from the same epoch, which
        // is what the shell bridge reports for itself.
        assert_eq!(first_identity.start_value.get(), first_ticks);
        assert_eq!(second_identity.start_value.get(), second_ticks);
        // Control: in whole seconds, the unit the previous build read, the two are one value.
        assert_eq!(
            first_identity.start_value.get() / TICKS_PER_SECOND,
            second_identity.start_value.get() / TICKS_PER_SECOND
        );
        return;
    }
    panic!(
        "no pair of processes was created within one second and apart in {ATTEMPTS} attempts: \
         {passed_over:?}"
    );
}

/// Leaves the debug privilege disabled in the token of one process, given by its identifier, and
/// prints `disabled`.
///
/// An account that holds that privilege enabled opens any process whatever its list says, so a
/// case built on a process's list needs a token without it. A process's token is its user's to
/// adjust, so this needs no privilege of its own, and a token that does not hold the privilege at
/// all is left as it is.
const DROP_DEBUG: &str = r#"
param([int]$Id)
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class KrDebugPrivilege
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValueW(string system, string name, out long luid);

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct OnePrivilege { public int Count; public long Luid; public int Attributes; }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref OnePrivilege state, int length, IntPtr previous, IntPtr returned);

    private const uint QueryLimited = 0x00001000;
    private const uint AdjustPrivileges = 0x0020;
    private const uint Query = 0x0008;

    public static void Disable(int pid)
    {
        IntPtr process = OpenProcess(QueryLimited, false, pid);
        if (process == IntPtr.Zero) throw new Win32Exception();
        try
        {
            IntPtr token;
            if (!OpenProcessToken(process, AdjustPrivileges | Query, out token))
                throw new Win32Exception();
            try
            {
                long luid;
                if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid))
                    throw new Win32Exception();
                OnePrivilege state = new OnePrivilege { Count = 1, Luid = luid, Attributes = 0 };
                if (!AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception();
            }
            finally { CloseHandle(token); }
        }
        finally { CloseHandle(process); }
    }
}
'@
[KrDebugPrivilege]::Disable($Id)
Write-Output 'disabled'
"#;

/// KR-REQ-11.52: a process whose list grants this account the right to ask when it started, and no
/// other right, is identified: its start identity is its creation time. Whether it is still running
/// takes the right to wait on it as well. Without that right the answer is that nothing is
/// established, never that the process has ended; with it, the process is running.
#[test]
fn a_process_this_account_may_only_ask_about_is_identified() {
    // PROCESS_QUERY_LIMITED_INFORMATION, then that and SYNCHRONIZE.
    const QUERY: &str = "1000";
    const QUERY_AND_WAIT: &str = "101000";
    let host = TempHost::create();
    let grant = script(&host, "grant-only", GRANT_ONLY);
    let created_at = script(&host, "created-at", CREATED_AT);
    let drop_debug = script(&host, "drop-debug", DROP_DEBUG);
    // An elevated account holds the debug privilege, and a token with it enabled opens any process
    // whatever its list says. This test process, which is the one that reads the process, gives
    // it up first. That only makes a list mean more, and every other case here asks about
    // processes this account owns, whose lists grant it every right anyway. What the process's
    // list is checked against is this process's own token: a PowerShell started to change the list
    // may hold the privilege again, and needs nothing but the owner's right to rewrite a list.
    let dropped = output_of(&drop_debug, &[&std::process::id().to_string()]);
    assert_eq!(dropped.trim(), "disabled");
    let mut child = std::process::Command::new("ping.exe")
        .args(["-n", "60", "127.0.0.1"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("a process to describe");
    let pid = child.id();
    let recorded = output_of(&created_at, &[&pid.to_string()]);
    let query_only = output_of(&grant, &[&pid.to_string(), QUERY]);
    let identity = kr_ipc::identity::process_start_identity(pid);
    let unwaited = identity.as_ref().ok().map(kr_ipc::identity::process_state);
    let with_wait = output_of(&grant, &[&pid.to_string(), QUERY_AND_WAIT]);
    let waited = identity.as_ref().ok().map(kr_ipc::identity::process_state);
    let still_running = child.try_wait().expect("the process's status").is_none();
    // The handle this test started it with keeps every right, whatever the list says now.
    let _ = child.kill();
    let _ = child.wait();

    assert_eq!(query_only.trim(), "granted");
    assert_eq!(with_wait.trim(), "granted");
    let recorded: u64 = recorded
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("PowerShell printed a creation time: {recorded:?}"));
    assert_eq!(
        identity.expect("a process this account may ask when it started is identified"),
        ProcessStartIdentity::new(
            u64::from(pid),
            ProcessStartSource::WindowsProcessCreationTime,
            recorded
        )
    );
    assert!(
        still_running,
        "the process was still running when it was asked about"
    );
    assert!(
        matches!(
            unwaited,
            Some(kr_ipc::identity::ProcessState::Unknown { .. })
        ),
        "without the right to wait on it, whether it runs is not established: {unwaited:?} (a \
         reading of running here means this process still opens it to wait, which a debug \
         privilege left enabled would allow)"
    );
    assert_eq!(waited, Some(kr_ipc::identity::ProcessState::Running));
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

    // At least this many reads race the republication, so the evidence is a rate over a run long
    // enough to catch a reader that opens a version mid-replacement: the reader that opened the file
    // by full path and checked its list afterwards refused a handful of reads in every thousand,
    // where the reader that opens each entry relative to the directory handle refuses none.
    const CONCURRENT_READS: u64 = 1_200;
    let versions = [first, second];
    let reads = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = std::thread::spawn({
        let paths = paths.clone();
        let reads = std::sync::Arc::clone(&reads);
        let stop = std::sync::Arc::clone(&stop);
        let versions = versions.clone();
        move || {
            let mut wrong = Vec::new();
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                match kr_ipc::descriptor::read(&paths, versions[0].session_id) {
                    Ok(Some(found)) if versions.contains(&found) => {}
                    other => wrong.push(format!("{other:?}")),
                }
                reads.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            wrong
        }
    });
    let mut round = 0_usize;
    while reads.load(std::sync::atomic::Ordering::Relaxed) < CONCURRENT_READS {
        kr_ipc::descriptor::publish(&paths, &versions[round % 2])
            .unwrap_or_else(|error| panic!("publication {round} failed: {error}"));
        round += 1;
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let wrong = reader.join().expect("the reader finishes");
    let reads = reads.load(std::sync::atomic::Ordering::Relaxed);
    println!("== concurrent reads: {reads}; refused: {}", wrong.len());
    assert!(
        reads >= CONCURRENT_READS,
        "the descriptor was read while it was published"
    );
    assert!(
        wrong.is_empty(),
        "{} of {reads} reads found something other than a whole version: {:?}",
        wrong.len(),
        wrong.iter().take(3).collect::<Vec<_>>()
    );
}

/// Runs one command-line tool and fails the test when it fails.
fn run(program: &str, arguments: &[&std::ffi::OsStr]) -> String {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("{program} starts: {error}"));
    let printed = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{program} failed: {printed}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    printed
}

/// Grants an account full control of a path, adding to whatever list it already carries.
///
/// Adding an entry is what every account may do to a thing it owns, so it is reliable across hosts
/// in a way that narrowing a list with `icacls` is not: the same narrowing produced a different
/// list on a hosted runner than on this machine, which is why these tests widen a list to prove a
/// refusal rather than narrow one. The grant carries no inheritance flags, which `icacls` applies
/// to a file and a directory alike; the object's own list is what the reader checks.
fn grant_full(path: &Path, account: &str) {
    run(
        "icacls.exe",
        &[
            path.as_os_str(),
            "/grant".as_ref(),
            format!("*{account}:F").as_ref(),
        ],
    );
}

/// The security identifier of the Everyone group, which no descriptor's list may name.
const EVERYONE: &str = "S-1-1-0";

/// KR-REQ-05.03: a descriptor whose access-control list grants an account this host does not trust
/// is refused, rather than read and acted on. The public key inside a descriptor decides which
/// worker a client trusts, so a file any account could have written is not one to read a key from.
#[test]
fn a_descriptor_whose_list_grants_another_account_is_refused() {
    let host = TempHost::create();
    let paths = host.environment();
    let published = descriptor(&host, 3, "kalareach-descriptor-widened-file");
    kr_ipc::descriptor::publish(&paths, &published).expect("publishes");
    // The negative control: as published, it reads.
    kr_ipc::descriptor::read(&paths, published.session_id)
        .expect("reads")
        .expect("present");

    grant_full(&paths.descriptor_file(published.session_id), EVERYONE);
    let error = kr_ipc::descriptor::read(&paths, published.session_id)
        .expect_err("a descriptor granting Everyone is refused");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
}

/// KR-REQ-05.03: a descriptor directory whose list has been widened is refused, so nothing inside a
/// directory another account can write to is read at all.
#[test]
fn a_descriptor_directory_whose_list_is_widened_is_refused() {
    let host = TempHost::create();
    let paths = host.environment();
    let published = descriptor(&host, 4, "kalareach-descriptor-widened-dir");
    kr_ipc::descriptor::publish(&paths, &published).expect("publishes");
    kr_ipc::descriptor::read(&paths, published.session_id)
        .expect("reads")
        .expect("present");

    grant_full(&paths.descriptors_dir(), EVERYONE);
    let error = kr_ipc::descriptor::read(&paths, published.session_id)
        .expect_err("a directory granting Everyone is refused");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    // Enumeration refuses the same directory: a listing is not a warrant to trust it.
    let listed = kr_ipc::descriptor::read_all(&paths).expect_err("enumeration refuses it too");
    assert_eq!(
        listed.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
}

/// KR-REQ-05.03: a descriptor reached through a reparse point - a junction here, which needs no
/// privilege to make, where a symbolic link to a file needs one this account does not hold - is
/// refused. The reader opens the link itself rather than following it, and refuses it by its
/// attributes.
#[test]
fn a_descriptor_reached_through_a_junction_is_refused() {
    let host = TempHost::create();
    let paths = host.environment();
    let real = descriptor(&host, 5, "kalareach-descriptor-behind-a-junction");
    kr_ipc::descriptor::publish(&paths, &real).expect("publishes a real descriptor");

    // A second session's descriptor is a junction, pointing at a directory this account owns. A
    // junction is a directory reparse point, so its name can stand where a descriptor file would.
    let elsewhere = host.root().join("elsewhere");
    std::fs::create_dir(&elsewhere).expect("a directory to point at");
    let planted = paths.descriptor_file(SessionId::new(Uuid::from_bytes([6; 16])));
    run(
        "cmd.exe",
        &[
            "/d".as_ref(),
            "/c".as_ref(),
            "mklink".as_ref(),
            "/J".as_ref(),
            planted.as_os_str(),
            elsewhere.as_os_str(),
        ],
    );

    let error = kr_ipc::descriptor::read(&paths, SessionId::new(Uuid::from_bytes([6; 16])))
        .expect_err("a descriptor that is a junction is refused");
    assert_eq!(
        error.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    // Enumeration reaches the junction and refuses it, and still reads the real descriptor beside
    // it, so one planted entry does not hide the rest.
    let entries = kr_ipc::descriptor::read_all(&paths).expect("the directory lists");
    let planted_entry = entries
        .iter()
        .find(|entry| entry.path == planted)
        .expect("the junction is among the entries");
    assert!(
        planted_entry.descriptor.is_err(),
        "the junction is not read as a descriptor"
    );
    let real_entry = entries
        .iter()
        .find(|entry| entry.path == paths.descriptor_file(real.session_id))
        .expect("the real descriptor is among the entries");
    assert_eq!(
        real_entry.descriptor.as_ref().expect("it reads"),
        &real,
        "the real descriptor beside it still reads"
    );
}

/// KR-REQ-05.03: a descriptor directory swapped for another after it was checked never hands back a
/// file from the directory that took its name. The reader holds a handle on the directory it checked
/// and opens every entry relative to it, the way `openat` does on Unix, so an impostor written into
/// a directory that took the checked one's name since is never the file it reads: it reads the real
/// descriptor from the directory it checked, or nothing.
#[test]
fn a_descriptor_directory_swapped_after_its_check_never_returns_the_impostor() {
    let host = TempHost::create();
    let paths = host.environment();
    let real = descriptor(&host, 7, "kalareach-descriptor-before-the-swap");
    kr_ipc::descriptor::publish(&paths, &real).expect("publishes");

    let directory = kr_ipc::descriptor::DescriptorDirectory::open(&paths.descriptors_dir())
        .expect("opens the directory")
        .expect("the directory is there");

    // The checked directory is moved aside and another put in its place, holding an impostor under
    // the real descriptor's own name. The handle above still names the directory that was checked,
    // which still holds the real descriptor.
    let sessions = paths.descriptors_dir();
    let moved = host.root().join("sessions-moved");
    std::fs::rename(&sessions, &moved).expect("the checked directory is moved aside");
    std::fs::create_dir(&sessions).expect("another directory takes its name");
    let impostor = descriptor(&host, 9, "kalareach-descriptor-the-impostor");
    let impostor = kr_protocol::worker::WorkerDescriptor {
        session_id: real.session_id,
        ..impostor
    };
    std::fs::write(
        paths.descriptor_file(real.session_id),
        kr_cbor::to_canonical_vec(&impostor).expect("encodes"),
    )
    .expect("the impostor is written into the new directory");

    // Read relative to the checked directory: the real descriptor, never the impostor.
    let read = directory
        .read_entry(&paths.descriptor_file(real.session_id))
        .expect("reads relative to the checked directory")
        .expect("the real descriptor is still there");
    assert_eq!(
        read, real,
        "the reader reads the real descriptor, not the impostor"
    );
    assert_ne!(read, impostor, "the impostor is never returned");
}

// KR-REQ-02.07, KR-REQ-23.10: the endpoint checks the account at both ends.
//
// On this platform the endpoint namespace is shared by every account, so the owner-only list is not
// the only line: a client proves the pipe it reached is owned by this account before it writes, and
// the listener proves the connecting caller's account from the connection itself before any byte of
// it reaches a reader. The cases that cross accounts need a second local account, which the hosted
// runner does not have, so they are ignored there and run on the Windows test machine, where the
// task's script makes a standard second account and exports it below.

use kr_ipc::endpoint::Connection;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// The second local account this run was given, or `None` when it was not.
///
/// The name and password are exported by the task's native script for this session only; the
/// password is never written to a log or a file here.
fn second_account() -> Option<(String, String)> {
    let user = std::env::var("KR_TEST_SECOND_USER")
        .ok()
        .filter(|value| !value.is_empty())?;
    let password = std::env::var("KR_TEST_SECOND_PASS")
        .ok()
        .filter(|value| !value.is_empty())?;
    Some((user, password))
}

/// Uses the second account's own logon token, held by this script's thread, to create a pipe (which
/// the second account then owns) or to open one (which then records the second account as its
/// client), and reports progress in a status file.
///
/// A console process started under another account from the non-interactive session the test runs
/// in cannot start, because it cannot reach that session's window station, so the second account's
/// identity is carried the way a pipe sees it: a real logon token of that account, held by a thread
/// while it creates or opens the pipe. The password comes from this process's environment and is
/// never written anywhere.
///
/// `server`: create the pipe first, with a list that admits this account too, wait for one client
/// and report how many bytes it sent. `client`: open the pipe, send one byte, and report whether the
/// server refused it (closed it with nothing sent back). `client-exit`: open it, send one byte and
/// end at once, leaving the byte behind.
const AS_SECOND_ACCOUNT: &str = r#"
param([string]$Role, [string]$Name, [string]$Status)
Set-Content -Path $Status -Value 'started'
$ErrorActionPreference = 'Stop'
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class KrSecondAccount
{
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LogonUserW(string user, string domain, string password, int type,
        int provider, out IntPtr token);

    public static SafeAccessTokenHandle Network(string user, string password)
    {
        IntPtr token;
        // LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT: an impersonation token of the account.
        if (!LogonUserW(user, ".", password, 3, 0, out token))
        {
            throw new System.ComponentModel.Win32Exception();
        }
        return new SafeAccessTokenHandle(token);
    }
}
'@
    $token = [KrSecondAccount]::Network($env:KR_TEST_SECOND_USER, $env:KR_TEST_SECOND_PASS)
    if ($Role -eq 'server') {
        $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $list = [System.IO.Pipes.PipeSecurity]::new()
        $list.SetAccessRuleProtection($true, $false)
        foreach ($account in @($me)) {
            $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
                $account, [System.IO.Pipes.PipeAccessRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow))
        }
        $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new('S-1-3-4'),
            [System.IO.Pipes.PipeAccessRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))
        $server = [System.Security.Principal.WindowsIdentity]::RunImpersonated($token, [Func[object]]{
            [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($Name, 'InOut', 1, 'Byte',
                'Asynchronous', 0, 0, $list)
        })
        Add-Content -Path $Status -Value 'ready'
        $server.WaitForConnection()
        $buffer = New-Object byte[] 64
        $read = $server.ReadAsync($buffer, 0, 64)
        if ($read.Wait(10000)) { $count = $read.Result } else { $count = 'none' }
        Add-Content -Path $Status -Value ('received=' + $count)
        Start-Sleep -Seconds 5
        $server.Dispose()
    } else {
        # The byte is written under the second account's token too: a client that sets no quality
        # of service has its context taken at each write, so a byte written under this account's
        # own token would rightly be read as this account's.
        $client = [System.IO.Pipes.NamedPipeClientStream]::new('.', $Name, 'InOut', 'Asynchronous')
        [System.Security.Principal.WindowsIdentity]::RunImpersonated($token, [Action]{
            $client.Connect(30000)
            $client.WriteByte(1)
            $client.Flush()
        })
        Add-Content -Path $Status -Value 'connected'
        if ($Role -eq 'client-exit') { exit 0 }
        $buffer = New-Object byte[] 16
        try {
            $read = $client.ReadAsync($buffer, 0, 16)
            if ($read.Wait(30000)) {
                if ($read.Result -eq 0) { Add-Content -Path $Status -Value 'refused' }
                else { Add-Content -Path $Status -Value 'served' }
            } else { Add-Content -Path $Status -Value 'timeout' }
        } catch { Add-Content -Path $Status -Value 'refused' }
        $client.Dispose()
    }
} catch {
    Add-Content -Path $Status -Value ('error=' + $_.Exception.Message)
}
"#;

/// Starts [`AS_SECOND_ACCOUNT`] in `role` against the pipe `name`, reporting into `status`.
fn start_as_second(host: &TempHost, role: &str, name: &str, status: &Path) -> std::process::Child {
    let helper = script(host, "as-second-account", AS_SECOND_ACCOUNT);
    powershell_running(&helper, &[role, name, &status.display().to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the helper starts")
}

/// Waits until `path` holds a line equal to `token`, or fails after [`PATIENCE`] with what it held.
fn wait_for_line(path: &Path, token: &str) {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.lines().any(|line| line.trim() == token) {
            return;
        }
        assert!(
            !text.lines().any(|line| line.starts_with("error=")),
            "the helper failed while waiting for '{token}':\n{text}"
        );
        assert!(
            Instant::now() < deadline,
            "waited for '{token}' in {}; it held:\n{text}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits until `path` holds a line starting with `prefix`, and returns that line, or fails after
/// [`PATIENCE`] with what it held.
fn wait_for_prefix(path: &Path, prefix: &str) -> String {
    let deadline = Instant::now() + PATIENCE;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if let Some(line) = text.lines().find(|line| line.starts_with(prefix)) {
            return line.trim().to_owned();
        }
        assert!(
            !text.lines().any(|line| line.starts_with("error=")),
            "the helper failed while waiting for '{prefix}':\n{text}"
        );
        assert!(
            Instant::now() < deadline,
            "waited for '{prefix}' in {}; it held:\n{text}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Waits off the runtime for [`wait_for_line`].
async fn waited_for(path: &Path, token: &'static str) {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || wait_for_line(&path, token))
        .await
        .expect("the wait finishes");
}

/// Opens `endpoint` as a raw client of this account, for identification only, and sends `opening`.
///
/// Raw, because the production client refuses a pipe whose list admits other accounts, and the
/// listener's own check is what these cases prove. The pipe may be busy for a moment while the
/// listener makes its next instance.
async fn raw_owner(
    endpoint: &Endpoint,
    opening: &[u8],
) -> tokio::net::windows::named_pipe::NamedPipeClient {
    let path = local_name(endpoint);
    let deadline = tokio::time::Instant::now() + PATIENCE;
    let mut client = loop {
        match tokio::net::windows::named_pipe::ClientOptions::new().open(&path) {
            Ok(client) => break client,
            Err(error)
                if error.raw_os_error() == Some(231) && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(error) => panic!("the owner could not open the pipe: {error}"),
        }
    };
    client
        .write_all(opening)
        .await
        .expect("the owner sends its opening");
    client
}

/// Reads what the next accepted connection delivers, within [`PATIENCE`].
async fn first_read(connection: &mut Connection, length: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; length];
    tokio::time::timeout(PATIENCE, connection.read_exact(&mut buffer))
        .await
        .expect("the read settles in time")?;
    Ok(buffer)
}

/// KR-REQ-23.10, KR-REQ-02.07: a client refuses a pipe another account created first, by the pipe's
/// owner and before it writes anything, and the host cannot bind a name another account holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a second local account; run on the Windows test machine"]
async fn a_client_refuses_a_server_of_another_account_and_the_host_bind_fails() {
    let (user, _) = second_account().expect("a second local account in the environment");
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .controller_endpoint()
        .expect("an endpoint");
    let status = host.root().join("a-status.txt");
    let mut helper = start_as_second(&host, "server", &endpoint.as_text(), &status);
    waited_for(&status, "ready").await;

    // The host cannot take a name another account already holds, so it does not start on it, and it
    // says the name is held rather than giving a bare access denial.
    let refused = Listener::bind(&endpoint)
        .expect_err("the host does not bind a name another account holds")
        .to_string();
    assert!(
        refused.contains("the name is held by another pipe"),
        "the host says the name is held: {refused}"
    );

    // The client reads the pipe's owner and refuses it before it writes a frame, naming that owner.
    let second = kr_ipc::starter::account_sid(&user).expect("the second account's identifier");
    match Connection::connect(&endpoint).await {
        Err(kr_ipc::IpcError::PeerAccountRejected { detail }) => assert!(
            detail.contains(&second),
            "the refusal names the account that holds the pipe: {detail}"
        ),
        other => panic!("the client refuses a server of another account: {other:?}"),
    }

    // Nothing the client would have sent the host reached the other account.
    waited_for(&status, "received=0").await;
    let _ = helper.kill();
    let _ = helper.wait();
}

/// KR-REQ-23.10, KR-REQ-02.07: a listener refuses a caller of another account by that account, even
/// when the operating system's own list admits it, before any of its bytes reach a reader; and the
/// same listener goes on serving the owner. The caller's process runs as this account, with its
/// thread holding the second account's token, so the check is proved to read the connection, not
/// the process at the other end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a second local account; run on the Windows test machine"]
async fn a_listener_refuses_a_caller_of_another_account_and_serves_the_owner() {
    second_account().expect("a second local account in the environment");
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    // A list that admits every account, so the operating system does not keep the second account
    // out and the listener's own check is the only thing that refuses it.
    let listener = Listener::bind_with_access_list(&endpoint, "D:P(A;;GA;;;WD)")
        .expect("binds a widely-listed endpoint");
    let status = host.root().join("b-status.txt");
    let mut helper = start_as_second(&host, "client", &endpoint.as_text(), &status);
    waited_for(&status, "connected").await;

    let (mut foreign, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the connection");
    let refused = first_read(&mut foreign, 1)
        .await
        .expect_err("nothing of the second account's reaches the reader");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        refused.to_string().contains("another account"),
        "the caller is refused by its account: {refused}"
    );
    drop(foreign);
    waited_for(&status, "refused").await;

    let _owner = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { raw_owner(&endpoint, b"owner").await }
    });
    let (mut owner, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the owner");
    assert_eq!(
        first_read(&mut owner, 5)
            .await
            .expect("the owner is served"),
        b"owner",
        "the same listener goes on serving the owner"
    );
    let _ = helper.kill();
    let _ = helper.wait();
}

/// KR-REQ-23.10: bytes a caller of another account sent before its process ended are never handed
/// to a reader, however the check reads that caller after it has gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a second local account; run on the Windows test machine"]
async fn bytes_left_by_a_caller_of_another_account_that_has_gone_reach_no_reader() {
    second_account().expect("a second local account in the environment");
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind_with_access_list(&endpoint, "D:P(A;;GA;;;WD)")
        .expect("binds a widely-listed endpoint");
    let status = host.root().join("g-status.txt");
    let mut helper = start_as_second(&host, "client-exit", &endpoint.as_text(), &status);
    // Explicitly after the caller has sent its byte and its process has ended.
    let ended = tokio::task::spawn_blocking(move || helper.wait())
        .await
        .expect("the wait finishes")
        .expect("the helper ends");
    assert!(ended.success(), "the helper ended normally");
    wait_for_line(&status, "connected");

    let (mut left, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the connection");
    let refused = first_read(&mut left, 1)
        .await
        .expect_err("the byte left behind reaches no reader");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
}

/// KR-REQ-23.10, KR-REQ-02.07 control: a connection between two ends of this one account passes end
/// to end, so the account check does not stand in the way of the owner it protects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_same_account_connection_passes_end_to_end() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(2))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds an owner-only endpoint");
    let connecting = endpoint.clone();
    let client = tokio::spawn(async move {
        let mut client = Connection::connect(&connecting)
            .await
            .expect("the owner connects to its own endpoint");
        client.write_all(b"hello").await.expect("the owner writes");
        client
    });
    let (mut connection, peer) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the owner");
    assert_eq!(peer.uid, kr_ipc::paths::current_uid());
    assert_eq!(
        first_read(&mut connection, 5)
            .await
            .expect("the owner is served"),
        b"hello"
    );
    let _client = client.await.expect("the client task finishes");
}

/// Prints the impersonation level of the one client that connects to a pipe it creates, owned by
/// this account and listing no other, once the client has sent a byte.
const IMPERSONATION_LEVEL: &str = r#"
param([string]$Name, [string]$Status)
Set-Content -Path $Status -Value 'started'
$ErrorActionPreference = 'Stop'
try {
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $list = [System.IO.Pipes.PipeSecurity]::new()
    $list.SetAccessRuleProtection($true, $false)
    $list.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
        $me, [System.IO.Pipes.PipeAccessRights]::FullControl,
        [System.Security.AccessControl.AccessControlType]::Allow))
    $server = [System.IO.Pipes.NamedPipeServerStreamAcl]::Create($Name, 'InOut', 1, 'Byte',
        'Asynchronous', 0, 0, $list)
    Add-Content -Path $Status -Value 'ready'
    $server.WaitForConnection()
    [void]$server.ReadByte()
    # Read in compiled code: while it runs as an identification-only client, PowerShell itself could
    # not load a command from disk.
    Add-Type -TypeDefinition @'
using System.IO.Pipes;
using System.Security.Principal;
public static class KrClientLevel
{
    public static string Of(NamedPipeServerStream server)
    {
        string level = "unknown";
        server.RunAsClient(() => { level = WindowsIdentity.GetCurrent(true).ImpersonationLevel.ToString(); });
        return level;
    }
}
'@
    $level = [KrClientLevel]::Of($server)
    Add-Content -Path $Status -Value ('level=' + $level)
    $server.Dispose()
} catch {
    Add-Content -Path $Status -Value ('error=' + $_.Exception.Message)
}
"#;

/// KR-REQ-23.10: this host's client lets the server it reaches identify it but never act as it, so
/// a server another account created first gains nothing from the connection itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_lets_a_server_identify_it_but_never_act_as_it() {
    let host = TempHost::create();
    let endpoint = Endpoint::from_name(format!("kalareach-test-{}", kr_ipc::new_uuid()))
        .expect("a short name");
    let status = host.root().join("level-status.txt");
    let observer = script(&host, "impersonation-level", IMPERSONATION_LEVEL);
    let mut child = powershell_running(
        &observer,
        &[&endpoint.as_text(), &status.display().to_string()],
    )
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null())
    .spawn()
    .expect("the observer starts");
    waited_for(&status, "ready").await;

    let mut client = Connection::connect(&endpoint)
        .await
        .expect("the client reaches a pipe of its own account");
    client.write_all(&[1]).await.expect("the client speaks");
    let level = tokio::task::spawn_blocking({
        let status = status.clone();
        move || wait_for_prefix(&status, "level=")
    })
    .await
    .expect("the wait finishes");
    assert_eq!(
        level, "level=Identification",
        "the server may identify the client and nothing more"
    );
    let _ = child.wait();
}

/// KR-REQ-23.10: a caller whose account cannot be read from the connection, because it opened the
/// pipe anonymously, is refused before any of its bytes reach a reader, and the listener goes on
/// serving the owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_anonymous_caller_is_refused_and_the_listener_serves_the_owner() {
    use windows_sys::Win32::Storage::FileSystem::SECURITY_ANONYMOUS;

    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(3))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds an owner-only endpoint");
    let mut anonymous = tokio::net::windows::named_pipe::ClientOptions::new()
        .security_qos_flags(SECURITY_ANONYMOUS)
        .open(local_name(&endpoint))
        .expect("an anonymous client of this account opens the pipe");
    anonymous.write_all(&[1]).await.expect("it speaks");

    let (mut unread, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the connection");
    let refused = first_read(&mut unread, 1)
        .await
        .expect_err("an unreadable caller gets nothing through");
    assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        refused.to_string().contains("could not be read"),
        "the refusal says the account could not be read, not that it is another: {refused}"
    );

    let _owner = tokio::spawn({
        let endpoint = endpoint.clone();
        async move { raw_owner(&endpoint, b"owner").await }
    });
    let (mut owner, _) = tokio::time::timeout(PATIENCE, listener.accept())
        .await
        .expect("the listener accepts in time")
        .expect("the listener accepts the owner");
    assert_eq!(
        first_read(&mut owner, 5)
            .await
            .expect("the owner is served"),
        b"owner"
    );
}

/// A caller that has connected and not yet spoken does not hold up the next one: the account is
/// proved at a connection's first read, not at accept, so accept returns at once as it does on the
/// Unix family.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_caller_that_has_not_spoken_does_not_hold_up_the_next() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(4))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds an owner-only endpoint");
    let _silent = Connection::connect(&endpoint)
        .await
        .expect("a silent caller of this account connects");
    let (mut silent, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("accept returns without waiting for the caller to speak")
        .expect("the listener accepts it");

    let mut speaking = Connection::connect(&endpoint)
        .await
        .expect("a second caller connects");
    speaking.write_all(b"hello").await.expect("it speaks");
    let (mut next, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("the next caller is accepted while the first says nothing")
        .expect("the listener accepts it");
    assert_eq!(
        first_read(&mut next, 5)
            .await
            .expect("the second caller is served"),
        b"hello"
    );
    let mut nothing = [0_u8; 1];
    assert!(
        tokio::time::timeout(Duration::from_millis(300), silent.read(&mut nothing))
            .await
            .is_err(),
        "the silent caller's connection is still waiting for it to speak"
    );
}

/// A connect that is cancelled while the pipe is busy leaves nothing behind: no later connection
/// arrives at the server once an instance frees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cancelled_connect_to_a_busy_pipe_leaves_nothing_behind() {
    let endpoint = Endpoint::from_name(format!("kalareach-test-{}", kr_ipc::new_uuid()))
        .expect("a short name");
    let path = local_name(&endpoint);
    let server = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .max_instances(1)
        .create(&path)
        .expect("a one-instance pipe");
    let holder = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(&path)
        .expect("the holder takes the only instance");
    server.connect().await.expect("the holder is connected");

    assert!(
        tokio::time::timeout(Duration::from_millis(300), Connection::connect(&endpoint))
            .await
            .is_err(),
        "a connect to a busy pipe waits, and is cancelled here"
    );
    drop(holder);
    server.disconnect().expect("the instance is freed");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), server.connect())
            .await
            .is_err(),
        "no connection arrives from the connect that was cancelled"
    );
}

/// The last frame a client sends before it closes reaches the listener, even when the listener
/// reads it only afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_last_frame_a_client_sends_before_it_closes_arrives() {
    use kr_protocol::envelope::{ControlFrame, ParamsValue, Request};
    use kr_protocol::frame::StreamKind;
    use kr_protocol::ids::RequestId;
    use kr_protocol::method::{Method, MethodVersion};

    let last = ControlFrame::Request(Request {
        request_id: RequestId::new(7),
        method: Method::SessionList.into(),
        method_version: MethodVersion::V1,
        params: ParamsValue::empty(),
    });

    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(5))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds an owner-only endpoint");
    let accepting = tokio::spawn(async move { listener.accept().await });
    let client = Connection::connect(&endpoint)
        .await
        .expect("the owner connects");
    let (reader, mut writer) = kr_ipc::framed::split(client, StreamKind::Control);
    writer
        .write_message(&last)
        .await
        .expect("the frame is sent");
    drop(writer);
    drop(reader);

    let (connection, _) = tokio::time::timeout(PATIENCE, accepting)
        .await
        .expect("the listener accepts in time")
        .expect("the accept task finishes")
        .expect("the listener accepts the owner");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (mut reader, _writer) = kr_ipc::framed::split(connection, StreamKind::Control);
    let received: ControlFrame = tokio::time::timeout(PATIENCE, reader.read_message())
        .await
        .expect("the frame is read in time")
        .expect("the last frame arrived whole");
    assert_eq!(received, last);
}

/// Prints the owner new objects of this process receive, as a security identifier.
const DEFAULT_OWNER: &str = r"
$ErrorActionPreference = 'Stop'
Write-Output ([System.Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value)
";

/// KR-REQ-23.10: the client trusts a pipe owned by this account's user or by the owner its own new
/// objects receive, and no other. A token whose default owner is the Administrators group trusts a
/// pipe that group owns; every other token refuses it. The policy is stated here as it is, not as a
/// same-account guarantee it is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_client_trusts_a_pipe_only_its_own_user_or_default_owner_owns() {
    let host = TempHost::create();
    let endpoint = host
        .environment()
        .worker_endpoint(DisplayNumber::new(6))
        .expect("an endpoint");
    let owner_script = script(&host, "default-owner", DEFAULT_OWNER);
    let default_owner = output_of(&owner_script, &[]).trim().to_owned();
    let Ok(_listener) = Listener::bind_with_access_list(&endpoint, "O:BAD:P(A;;GA;;;OW)") else {
        // A token that may not name the Administrators group as an owner cannot make this pipe;
        // such a token's default owner is not that group, and the case has nothing to prove.
        assert_ne!(default_owner, "S-1-5-32-544");
        return;
    };
    let reached = Connection::connect(&endpoint).await;
    if default_owner == "S-1-5-32-544" {
        reached.expect("a token whose default owner is Administrators trusts a pipe it owns");
    } else {
        assert!(
            matches!(reached, Err(kr_ipc::IpcError::PeerAccountRejected { .. })),
            "any other token refuses a pipe the Administrators group owns: {reached:?}"
        );
    }
}
