//! What the private-root and walk cases share: a scratch folder, an administrator-only `run`
//! directory held open, rows that check their order, and the hostile objects a taken-over Git could
//! leave behind.

#![allow(dead_code, unsafe_code)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::Command;

use windows_sys::Win32::Foundation::GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS,
    WriteFile,
};

use kr_boundary_windows::filekey::FileKey;
use kr_boundary_windows::win::ffi::{Handle, Sid, wide_path};
use kr_boundary_windows::win::root::{RootError, RootRows};
use kr_boundary_windows::win::sd::{
    self, OwnedSd, Principals, SdKind, Summary, descriptor, descriptor_from_text,
};
use kr_boundary_windows::win::walk::DirHandle;
use kr_boundary_windows::win::{acl, privilege, token};

/// A folder of one case, removed when the case ends if it can be.
pub struct Scratch {
    pub dir: PathBuf,
}

impl Scratch {
    pub fn new() -> Scratch {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let dir = PathBuf::from(r"C:\Users\Public").join(format!("krroot-{}", &id[..12]));
        std::fs::create_dir_all(&dir).unwrap();
        let readable = descriptor(
            SdKind::AdminDir,
            &Principals {
                users_may_read: true,
                ..Principals::default()
            },
        )
        .unwrap();
        acl::set_protected(&dir, &readable).unwrap();
        Scratch { dir }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // A case that left a hostile object behind on purpose removes it itself; this is the rest.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// An administrator-only directory held open, the way the broker holds its `run` directory.
pub struct Run {
    pub dir: DirHandle,
    pub path: PathBuf,
}

pub fn run_dir(scratch: &Scratch) -> Run {
    let path = scratch.path("run");
    std::fs::create_dir_all(&path).unwrap();
    acl::set_protected(
        &path,
        &descriptor(SdKind::AdminDir, &Principals::default()).unwrap(),
    )
    .unwrap();
    let dir = DirHandle::open_anchor(&path)
        .expect("the platform answers")
        .expect("the run directory is accepted");
    Run { dir, path }
}

/// Rows that remember their order, and check what the directory looks like when each is written.
#[derive(Default)]
pub struct Rows {
    pub log: Vec<String>,
    pub key: Option<FileKey>,
}

impl RootRows for Rows {
    fn intent(&mut self, path: &Path) -> Result<(), RootError> {
        assert!(
            !path.exists(),
            "the intent is durable before the directory exists"
        );
        self.log.push(format!("intent {}", path.display()));
        Ok(())
    }

    fn made(&mut self, path: &Path, key: &FileKey) -> Result<(), RootError> {
        assert!(path.exists(), "the root exists when it is recorded as made");
        self.key = Some(*key);
        self.log.push(format!("made {}", path.display()));
        Ok(())
    }

    fn removed(&mut self) -> Result<(), RootError> {
        self.log.push("removed".to_owned());
        Ok(())
    }
}

pub fn group() -> Sid {
    token::new_invocation_group()
}

/// A descriptor that refuses the system and names only its owner, which is what a taken-over Git's
/// own object can look like to the broker.
pub fn hostile_descriptor(owner: &Sid) -> OwnedSd {
    let owner = owner.to_text();
    descriptor_from_text(&format!("O:{owner}D:P(D;;FA;;;SY)(A;;FA;;;{owner})")).unwrap()
}

/// Makes a file with a hostile descriptor. The caller holds a guard that enables the restore
/// privilege, which an owner other than the caller needs.
pub fn hostile_file(path: &Path, owner: &Sid, bytes: &[u8]) {
    let descriptor = hostile_descriptor(owner);
    let attributes = descriptor.attributes();
    let wide = wide_path(path);
    // SAFETY: the path is NUL-terminated and the attributes point at a descriptor that lives
    // through the call.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            0,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    let handle = Handle::new(raw, "making a hostile file").expect("the hostile file is made");
    let mut written = 0_u32;
    // SAFETY: the handle is open for writing and the buffer is as long as the length passed.
    let wrote = unsafe {
        WriteFile(
            handle.raw(),
            bytes.as_ptr(),
            bytes.len() as u32,
            &raw mut written,
            std::ptr::null_mut(),
        )
    };
    assert_ne!(wrote, 0, "the hostile file takes its bytes");
}

/// Makes a directory with a hostile descriptor, under the same condition as [`hostile_file`].
pub fn hostile_dir(path: &Path, owner: &Sid) {
    let descriptor = hostile_descriptor(owner);
    let attributes = descriptor.attributes();
    let wide = wide_path(path);
    // SAFETY: as above.
    let made = unsafe { CreateDirectoryW(wide.as_ptr(), &raw const attributes) };
    assert_ne!(made, 0, "the hostile directory is made");
}

/// Runs `body` on a thread that holds the walk's privileges, the way the broker's walk does.
pub fn privileged<T>(body: impl FnOnce() -> T) -> T {
    let guard = privilege::enter().expect("the walk's privileges can be enabled");
    let out = body();
    drop(guard);
    out
}

/// What an object looks like from outside: its attributes, its bytes when it is a file and its
/// descriptor. The privileges are enabled for the length of the read, since a case reads objects
/// whose list refuses the system.
#[derive(Debug, PartialEq, Eq)]
pub struct Outside {
    pub attributes: u32,
    pub bytes: Option<Vec<u8>>,
    pub summary: Summary,
    pub links: u32,
}

pub fn look_at(path: &Path) -> Outside {
    use std::os::windows::fs::MetadataExt as _;
    privileged(|| {
        let metadata = std::fs::symlink_metadata(path).expect("the object is there");
        let bytes = if metadata.is_file() {
            // The backup privilege reaches an object that refuses the system only for an open that
            // asks for backup semantics, which the standard library's `read` does not.
            use std::io::Read as _;
            use std::os::windows::fs::OpenOptionsExt as _;
            let mut bytes = Vec::new();
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(path)
                .and_then(|mut file| file.read_to_end(&mut bytes))
                .expect("the file reads");
            Some(bytes)
        } else {
            None
        };
        let handle = open_for_descriptor(path);
        let summary = sd::summary_of_handle(&handle).expect("the descriptor reads");
        Outside {
            attributes: metadata.file_attributes(),
            bytes,
            summary,
            links: links_of(&handle),
        }
    })
}

fn open_for_descriptor(path: &Path) -> Handle {
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::IntoRawHandle as _;
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, with READ_CONTROL alone.
    let file = std::fs::OpenOptions::new()
        .access_mode(0x0002_0000 | 0x0080)
        .share_mode(7)
        .custom_flags(0x0200_0000 | 0x0020_0000)
        .open(path)
        .expect("the object opens for its descriptor");
    Handle::new(file.into_raw_handle(), "an object").unwrap()
}

fn links_of(handle: &Handle) -> u32 {
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open and the buffer is the structure the call fills.
    let read = unsafe { GetFileInformationByHandle(handle.raw(), &raw mut info) };
    assert_ne!(read, 0, "the link count reads");
    info.nNumberOfLinks
}

/// Runs a command and asserts it succeeded.
pub fn run(program: &str, arguments: &[&str]) {
    let output = Command::new(program).args(arguments).output().unwrap();
    assert!(
        output.status.success(),
        "{program} {arguments:?} failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn pointer(handle: &Handle) -> *mut c_void {
    handle.raw()
}
