#![cfg(windows)]
#![allow(unsafe_code, clippy::all, missing_docs)]
//! Probe of how a sealed file is deleted. Not committed.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    SetKernelObjectSecurity,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY, FILE_BASIC_INFO,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_WRITE_ATTRIBUTES, FileBasicInfo, FileDispositionInfoEx,
    READ_CONTROL, SetFileInformationByHandle, WRITE_DAC,
};

const CURRENT: &str = "D:P(D;;0x10116;;;OW)(A;;0x1600a9;;;OW)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)";
const WA_ALLOWED: &str =
    "D:P(D;;0x10016;;;OW)(A;;0x1601a9;;;OW)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)";
const DEFAULT_LIKE: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

fn set_sddl(path: &Path, sddl: &str) {
    let handle = OpenOptions::new()
        .access_mode(WRITE_DAC | READ_CONTROL)
        .share_mode(7)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .expect("opens for WRITE_DAC");
    let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    unsafe {
        assert!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut()
            ) != 0
        );
        let set = SetKernelObjectSecurity(
            handle.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        assert!(set != 0, "set list: {}", io::Error::last_os_error());
        LocalFree(descriptor.cast());
    }
}

fn set_readonly(path: &Path, on: bool) {
    let mut p = std::fs::metadata(path).unwrap().permissions();
    p.set_readonly(on);
    std::fs::set_permissions(path, p).unwrap();
}

fn open(path: &Path, access: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(7)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

fn dispose(file: &File, flags: u32) -> io::Result<()> {
    let info = FILE_DISPOSITION_INFO_EX { Flags: flags };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfoEx,
            (&raw const info).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn clear_readonly(file: &File) -> io::Result<()> {
    let info = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: FILE_ATTRIBUTE_NORMAL,
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&raw const info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

const POSIX: u32 = FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS;
const POSIX_IGNORE: u32 = POSIX | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;

fn code(r: &io::Result<()>) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => format!("err {:?}", e.raw_os_error()),
    }
}

/// Runs one method on `path`; returns a description of each stage.
fn method(path: &Path, m: &str) -> String {
    match m {
        "M1 open(DELETE)+posix" => match open(path, DELETE) {
            Err(e) => format!("open err {:?}", e.raw_os_error()),
            Ok(f) => format!("open ok; dispose {}", code(&dispose(&f, POSIX))),
        },
        "M2 open(DELETE)+posix+ignore" => match open(path, DELETE) {
            Err(e) => format!("open err {:?}", e.raw_os_error()),
            Ok(f) => format!("open ok; dispose {}", code(&dispose(&f, POSIX_IGNORE))),
        },
        "M3 open(DELETE|WA)+posix+ignore" => match open(path, DELETE | FILE_WRITE_ATTRIBUTES) {
            Err(e) => format!("open err {:?}", e.raw_os_error()),
            Ok(f) => format!("open ok; dispose {}", code(&dispose(&f, POSIX_IGNORE))),
        },
        "M4 open(DELETE|WA)+clear+posix" => match open(path, DELETE | FILE_WRITE_ATTRIBUTES) {
            Err(e) => format!("open err {:?}", e.raw_os_error()),
            Ok(f) => {
                let c = clear_readonly(&f);
                format!(
                    "open ok; clear {}; dispose {}",
                    code(&c),
                    code(&dispose(&f, POSIX))
                )
            }
        },
        _ => unreachable!(),
    }
}

const METHODS: [&str; 4] = [
    "M1 open(DELETE)+posix",
    "M2 open(DELETE)+posix+ignore",
    "M3 open(DELETE|WA)+posix+ignore",
    "M4 open(DELETE|WA)+clear+posix",
];

fn root() -> PathBuf {
    let r = PathBuf::from(r"C:\kala\scratch\T-INSTALL-4\f1");
    let _ = std::fs::remove_dir_all(&r);
    std::fs::create_dir_all(&r).unwrap();
    r
}

#[test]
fn probe_f1() {
    let root = root();
    // 1. the matrix of file seals and methods
    let variants: [(&str, bool, &str); 5] = [
        ("ro+CURRENT", true, CURRENT),
        ("ro+WA_ALLOWED", true, WA_ALLOWED),
        ("ro+default", true, DEFAULT_LIKE),
        ("noro+CURRENT", false, CURRENT),
        ("noro+WA_ALLOWED", false, WA_ALLOWED),
    ];
    for (name, ro, sddl) in variants {
        for m in METHODS {
            let d = root.join("d");
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            let f = d.join("f");
            std::fs::write(&f, b"data").unwrap();
            if ro {
                set_readonly(&f, true);
            }
            set_sddl(&f, sddl);
            // the directory as a removal leaves it: given back to its owner
            let result = method(&f, m);
            println!(
                "PROBE matrix {name:16} {m:34} -> {result}; exists={}",
                f.exists()
            );
            scrub(&f);
        }
    }

    // 2. a hard link to a read-only file outside
    for (name, sddl_on_link) in [
        ("outside ro default DACL", None),
        ("outside ro WA_ALLOWED", Some(WA_ALLOWED)),
        ("outside ro CURRENT", Some(CURRENT)),
    ] {
        for m in METHODS {
            let outside = root.join("outside");
            let d = root.join("d2");
            let _ = std::fs::remove_dir_all(&d);
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::create_dir_all(&outside).unwrap();
            let s = outside.join("shared");
            std::fs::write(&s, b"shared contents").unwrap();
            let link = d.join("link");
            std::fs::hard_link(&s, &link).unwrap();
            set_readonly(&s, true);
            if let Some(sddl) = sddl_on_link {
                set_sddl(&link, sddl);
            }
            let result = method(&link, m);
            let still = std::fs::metadata(&s);
            println!(
                "PROBE hardlink {name:26} {m:34} -> {result}; link exists={}; shared: {}",
                link.exists(),
                match &still {
                    Ok(md) => format!("readonly={} len={}", md.permissions().readonly(), md.len()),
                    Err(e) => format!("meta err {e}"),
                }
            );
            scrub(&s);
            scrub(&link);
        }
    }

    // 3. a running image
    let system = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    for (name, sddl) in [("ro+WA_ALLOWED", WA_ALLOWED), ("ro+CURRENT", CURRENT)] {
        let d = root.join("d3");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let exe = d.join("waiting.exe");
        std::fs::copy(system.join("System32").join("ping.exe"), &exe).unwrap();
        set_readonly(&exe, true);
        set_sddl(&exe, sddl);
        let mut running = std::process::Command::new(&exe)
            .args(["-n", "300", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for m in METHODS {
            let result = method(&exe, m);
            println!(
                "PROBE running {name:16} {m:34} -> {result}; exists={}",
                exe.exists()
            );
        }
        running.kill().unwrap();
        running.wait().unwrap();
        for m in METHODS {
            let result = method(&exe, m);
            println!(
                "PROBE ended   {name:16} {m:34} -> {result}; exists={}",
                exe.exists()
            );
            if !exe.exists() {
                std::fs::copy(system.join("System32").join("ping.exe"), &exe).unwrap();
                set_readonly(&exe, true);
                set_sddl(&exe, sddl);
            }
        }
    }

    // 4. std's remove_dir_all over a tree of files sealed as WA_ALLOWED
    for (name, ro, sddl) in [
        ("ro+WA_ALLOWED", true, WA_ALLOWED),
        ("noro+CURRENT", false, CURRENT),
        ("ro+CURRENT", true, CURRENT),
    ] {
        let d = root.join("d4");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("sub")).unwrap();
        for p in [d.join("a"), d.join("sub").join("b")] {
            std::fs::write(&p, b"x").unwrap();
            if ro {
                set_readonly(&p, true);
            }
            set_sddl(&p, sddl);
        }
        let r = std::fs::remove_dir_all(&d);
        println!(
            "PROBE remove_dir_all {name:16} -> {:?}",
            r.as_ref().map_err(|e| e.raw_os_error())
        );
    }
}

fn scrub(path: &Path) {
    if path.exists() {
        set_sddl(path, DEFAULT_LIKE);
        set_readonly(path, false);
        let _ = std::fs::remove_file(path);
    }
}
