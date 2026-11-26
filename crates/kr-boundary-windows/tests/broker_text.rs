//! `broker_text`: the text that names a project folder is checked before the broker opens
//! anything, and no link on the way to the project is followed.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is
//! restored afterwards, on NTFS. The broker opens folders as the system, so a text that leads to a
//! host (a share, a host with a port), to a pipe or to a device would make the computer's account
//! call that host, or hand the system's identity to that pipe's server. Each case therefore holds
//! the thing a refused text would have reached and asserts that it saw nothing: the pipe's own
//! server sees no connection, the case's own listener sees no connection, and the computer has no
//! new SMB connection. The refusal alone would not show that: a check that runs after the open
//! refuses the same way.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

mod common;

use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::ptr::null;
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GetLastError, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::{
    DDD_EXACT_MATCH_ON_REMOVE, DDD_NO_BROADCAST_SYSTEM, DDD_RAW_TARGET_PATH, DDD_REMOVE_DEFINITION,
    DefineDosDeviceW, FILE_FLAG_OVERLAPPED, GetVolumeNameForVolumeMountPointW, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

use kr_boundary_windows::frame::invocation::{MAX_DETAIL_BYTES, MAX_PATH_BYTES};
use kr_boundary_windows::win::client::ClientIdentity;
use kr_boundary_windows::win::ffi::wide;
use kr_boundary_windows::win::hold::{
    FOLDER_FORM_WORDS, FOLDER_LINK_WORDS, MOUNT_POINT_WORDS, RULE_FOLDER_FORM, RULE_FOLDER_LINK,
    RULE_FOLDER_MISSING, RULE_FOLDER_MOUNT, hold_tree,
};

use common::disk::Disk;
use common::people::{Person, prepare, runs_as_the_system};
use common::project::{Project, repository_at};
use common::{Scratch, Substituted, run, smb_connections};

/// A named pipe with one server end that waits for a client, and what it saw.
struct PipeServer {
    pipe: HANDLE,
    event: HANDLE,
    // The kernel writes into this when a client connects, so it stays put until the pipe closes.
    _overlapped: Box<OVERLAPPED>,
}

impl PipeServer {
    fn new(name: &str) -> PipeServer {
        let text = wide(name);
        // SAFETY: the name is NUL-terminated, and the call keeps nothing of it.
        let pipe = unsafe {
            CreateNamedPipeW(
                text.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                null(),
            )
        };
        assert_ne!(pipe, INVALID_HANDLE_VALUE, "the case's pipe is made");
        // SAFETY: a manual-reset event with no name and no security.
        let event = unsafe { CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null(), "the case's event is made");
        // SAFETY: the structure is plain data, and zero is its valid initial state.
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = event;
        // SAFETY: the pipe is open for overlapped use, and the structure lives as long as the
        // pipe does.
        let connected = unsafe { ConnectNamedPipe(pipe, &raw mut *overlapped) };
        // SAFETY: reads the calling thread's last error.
        let error = unsafe { GetLastError() };
        assert!(
            connected == 0 && (error == ERROR_IO_PENDING || error == ERROR_PIPE_CONNECTED),
            "the pipe waits for a client: error {error}"
        );
        PipeServer {
            pipe,
            event,
            _overlapped: overlapped,
        }
    }

    /// Whether a client has opened the pipe, after giving a late one two seconds to arrive.
    fn saw_a_connection(&self) -> bool {
        // SAFETY: the event is open.
        unsafe { WaitForSingleObject(self.event, 2000) == WAIT_OBJECT_0 }
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        // SAFETY: both handles are open and closed once.
        unsafe {
            CloseHandle(self.pipe);
            CloseHandle(self.event);
        }
    }
}

/// A drive letter that stands for a raw device path, removed when it is dropped even if a
/// refusal's assertion fails first. It is a link and nothing more: it connects to nothing.
struct DriveLink {
    letter: Vec<u16>,
    target: Vec<u16>,
}

impl DriveLink {
    fn new(letter: &str, target: &str) -> DriveLink {
        let link = DriveLink {
            letter: wide(letter),
            target: wide(target),
        };
        // SAFETY: both texts are NUL-terminated, and the call keeps neither.
        let made = unsafe {
            DefineDosDeviceW(
                DDD_RAW_TARGET_PATH | DDD_NO_BROADCAST_SYSTEM,
                link.letter.as_ptr(),
                link.target.as_ptr(),
            )
        };
        assert_ne!(made, 0, "the case's drive letter is defined");
        link
    }
}

impl Drop for DriveLink {
    fn drop(&mut self) {
        // SAFETY: both texts are NUL-terminated; this removes the one definition this case made.
        unsafe {
            DefineDosDeviceW(
                DDD_REMOVE_DEFINITION
                    | DDD_RAW_TARGET_PATH
                    | DDD_EXACT_MATCH_ON_REMOVE
                    | DDD_NO_BROADCAST_SYSTEM,
                self.letter.as_ptr(),
                self.target.as_ptr(),
            );
        }
    }
}

fn refused_as_form(text: &str, client: &ClientIdentity) {
    let refusal = hold_tree(text, client).expect_err(&format!("{text}: the text is refused"));
    assert_eq!(refusal.rule, RULE_FOLDER_FORM, "{text}");
    assert_eq!(refusal.detail(), FOLDER_FORM_WORDS, "{text}");
}

fn below_the_drive(path: &Path) -> String {
    path.strip_prefix(r"C:\")
        .expect("the case's folders are on the system drive")
        .display()
        .to_string()
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_text_a_text_that_is_not_a_path_on_a_local_drive_is_refused_before_anything_is_opened() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "text", &person.sid);
    let client = person.as_client();
    let rest = below_the_drive(&project.root);
    let connections = smb_connections();

    // A pipe, by the name of the pipe folder and by the device behind it: the server sees nobody.
    let pipe_name = format!("kr-hold-text-{}", std::process::id());
    let server = PipeServer::new(&format!(r"\\.\pipe\{pipe_name}"));
    refused_as_form(&format!(r"\\.\pipe\{pipe_name}"), &client);
    refused_as_form(
        &format!(r"\\.\GLOBALROOT\Device\NamedPipe\{pipe_name}"),
        &client,
    );
    refused_as_form(
        &format!(r"\\?\GLOBALROOT\Device\NamedPipe\{pipe_name}"),
        &client,
    );
    assert!(
        !server.saw_a_connection(),
        "the pipe's server saw a client: the text was opened"
    );
    drop(server);

    // A host with a port: the case's own listener on this computer sees nobody.
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port is free");
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    refused_as_form(&format!(r"\\127.0.0.1@{port}\DavWWWRoot\{rest}"), &client);
    refused_as_form(&format!(r"\\127.0.0.1@{port}\x"), &client);
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        listener.accept().map(|_| ()).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::WouldBlock),
        "the listener saw a client: the text was opened"
    );

    // A share of this computer that holds the project itself, in each spelling.
    for text in [
        format!(r"\\localhost\C$\{rest}"),
        format!(r"\\127.0.0.1\C$\{rest}"),
        format!(r"\\?\UNC\localhost\C$\{rest}"),
        format!(r"\\?\GLOBALROOT\Device\Mup\localhost\C$\{rest}"),
        format!(r"\\.\UNC\localhost\C$\{rest}"),
    ] {
        refused_as_form(&text, &client);
    }

    // A device name of a drive, a text with no drive, one with the drive but no root, and one
    // that climbs: none is a path on a local drive.
    for text in [
        format!(r"\\.\C:\{rest}"),
        format!(r"\??\C:\{rest}"),
        rest.clone(),
        format!(r"C:{rest}"),
        format!(r"..\{rest}"),
        format!("C:/{}", rest.replace('\\', "/")),
        format!(r"C:\{rest}\..\{}", rest.rsplit('\\').next().unwrap()),
        format!(r"C:\{rest}:stream"),
    ] {
        refused_as_form(&text, &client);
    }

    // Nothing above reached a host: the computer has no SMB connection it did not have.
    assert_eq!(
        smb_connections(),
        connections,
        "a text was opened: the computer made an SMB connection"
    );
    // The project itself is held by its own path, in either spelling of a path on a local drive.
    hold_tree(project.root.to_str().unwrap(), &client).expect("the plain path is held");
    hold_tree(&format!(r"\\?\{}", project.root.display()), &client)
        .expect("the verbatim spelling of the same path is held");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_text_a_drive_letter_that_is_not_a_local_disk_is_refused_before_its_root_is_opened() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "drive", &person.sid);
    let client = person.as_client();
    let connections = smb_connections();

    // A letter that stands for the share of this computer that holds the project: its root would
    // be opened through the redirector, so the check must come before that open. The connections
    // are counted after the letter is gone: a PowerShell that starts while the letter exists reads
    // each drive's root itself and would make the connection it is asked about.
    let answers = {
        let _share = DriveLink::new("Y:", r"\Device\Mup\localhost\C$");
        let on_the_share = format!(r"Y:\{}", below_the_drive(&project.root));
        [
            hold_tree(r"Y:\x\y", &client),
            hold_tree(&on_the_share, &client),
            // The verbatim spelling of the same path: the letter's link is read for it the same way.
            hold_tree(r"\\?\Y:\x\y", &client),
            hold_tree(&format!(r"\\?\{on_the_share}"), &client),
        ]
    };
    assert_eq!(
        smb_connections(),
        connections,
        "the letter's root was opened: the computer made an SMB connection"
    );
    for answer in answers {
        let refusal = answer.expect_err("a letter that stands for a share is refused");
        assert_eq!(refusal.rule, RULE_FOLDER_FORM);
        assert_eq!(refusal.detail(), FOLDER_FORM_WORDS);
    }

    // A letter that a `subst` made of a folder is a folder, not a volume's root.
    {
        let _folder = Substituted::new("Z:", &project.base);
        refused_as_form(r"Z:\t\mid\parent\root", &client);
    }

    // A letter that stands for nothing is a folder that is not there.
    let missing = hold_tree(r"Q:\x\y", &client).expect_err("a letter with no link is refused");
    assert_eq!(missing.rule, RULE_FOLDER_MISSING);

    // The control: the drive that holds the project is a local disk volume.
    hold_tree(project.root.to_str().unwrap(), &client).expect("the local drive's path is held");
}

#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_text_a_link_or_a_mounted_volume_above_the_tree_is_refused_and_never_followed() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "links", &person.sid);
    let client = person.as_client();
    let connections = smb_connections();
    let link_refused = |text: &str| {
        let refusal = hold_tree(text, &client).expect_err(&format!("{text}: a link is refused"));
        assert_eq!(refusal.rule, RULE_FOLDER_LINK, "{text}");
        assert!(
            refusal.detail().starts_with(FOLDER_LINK_WORDS),
            "{}",
            refusal.detail()
        );
    };

    // A junction as the tree, and one above it, lead to the real tree and are refused.
    let as_root = scratch.path("as-root");
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/J",
            as_root.to_str().unwrap(),
            project.root.to_str().unwrap(),
        ],
    );
    link_refused(as_root.to_str().unwrap());
    let above = scratch.path("above");
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/J",
            above.to_str().unwrap(),
            project.parent.to_str().unwrap(),
        ],
    );
    link_refused(above.join("root").to_str().unwrap());

    // A symbolic link above the tree whose target is a share of this computer: the walk does not
    // follow it, so the computer makes no connection.
    let over_share = scratch.path("over-share");
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/D",
            over_share.to_str().unwrap(),
            &format!(r"\\localhost\C$\{}", below_the_drive(&project.parent)),
        ],
    );
    link_refused(over_share.join("root").to_str().unwrap());
    assert_eq!(
        smb_connections(),
        connections,
        "the link was followed: the computer made an SMB connection"
    );

    // A volume mounted in a folder on the way has words of its own that say what to do.
    let disk = Disk::new(&scratch, "ntfs", 100, 'R').expect("an NTFS disk can be made");
    let mounted_root = Path::new(r"R:\p");
    std::fs::create_dir(mounted_root).unwrap();
    repository_at(mounted_root);
    let mount = scratch.path("mount");
    std::fs::create_dir(&mount).unwrap();
    let volume = {
        let root = wide(r"R:\");
        let mut buffer = vec![0_u16; 64];
        // SAFETY: the root is NUL-terminated and the buffer length is passed.
        let read = unsafe {
            GetVolumeNameForVolumeMountPointW(
                root.as_ptr(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        assert_ne!(read, 0, "the volume's name is read");
        let end = buffer.iter().position(|unit| *unit == 0).unwrap();
        String::from_utf16_lossy(&buffer[..end])
    };
    let mount_text = format!("{}\\", mount.display());
    run("mountvol", &[&mount_text, &volume]);
    let unmount = Unmount(mount_text);
    let mounted = format!(r"{}\p", mount.display());
    let refusal = hold_tree(&mounted, &client).expect_err("a volume mounted above is refused");
    assert_eq!(refusal.rule, RULE_FOLDER_MOUNT);
    assert_eq!(refusal.detail(), MOUNT_POINT_WORDS);
    drop(unmount);
    drop(disk);
}

/// A path that is too long for the reply's words and itself is cut at its start, so the reply
/// keeps the last parts of the path and the words stay whole.
#[test]
#[ignore = "needs an elevated SYSTEM session in a disposable Windows guest (see the file's header)"]
fn broker_text_a_path_too_long_for_the_reply_is_cut_at_its_start_and_keeps_its_end() {
    if !runs_as_the_system() {
        eprintln!("skipped: the case needs the system's token");
        return;
    }
    prepare();
    let person = Person::new("krhap");
    let scratch = Scratch::on_drive();
    let project = Project::make_private(&scratch, "long", &person.sid);
    let client = person.as_client();
    // A long folder, then a junction with a short name in it: the last parts of the path are the
    // name, which the cut keeps whole.
    let name = "the-link-to-the-tree";
    let folder = scratch.path(&"p".repeat(150));
    std::fs::create_dir(&folder).unwrap();
    let link = folder.join(name);
    let text = link.to_str().unwrap();
    let room = MAX_DETAIL_BYTES - FOLDER_LINK_WORDS.len() - ": ".len();
    assert!(
        text.len() > room && text.len() <= MAX_PATH_BYTES,
        "the path is longer than the reply has room for and a request may hold it: {}",
        text.len()
    );
    run(
        "cmd",
        &["/c", "mklink", "/J", text, project.root.to_str().unwrap()],
    );
    let refusal = hold_tree(text, &client).expect_err("a link is refused");
    assert_eq!(refusal.rule, RULE_FOLDER_LINK);
    let detail = refusal.detail();
    assert_eq!(detail.len(), MAX_DETAIL_BYTES, "{detail}");
    let kept = detail
        .strip_prefix(&format!("{FOLDER_LINK_WORDS}: ..."))
        .unwrap_or_else(|| panic!("the words are whole and the cut path follows: {detail}"));
    assert!(
        text.ends_with(kept),
        "the reply keeps the end of the path: {detail}"
    );
    assert!(kept.ends_with(name), "{detail}");
}

/// A volume mounted in a folder, unmounted when it is dropped: the case's own mount, by its path.
struct Unmount(String);

impl Drop for Unmount {
    fn drop(&mut self) {
        // A mount that cannot be removed here is gone with the guest's checkpoint.
        Command::new("mountvol")
            .args([self.0.as_str(), "/D"])
            .output()
            .expect("mountvol runs");
    }
}
