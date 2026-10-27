//! The programs that run their futures on the main thread reserve as much stack for it on Windows
//! as Linux and macOS give it.
//!
//! `kr`, the control daemon, the worker, the plugin host and the release tool each block the main
//! thread on the future they run, so that future lives on a stack the program does not size
//! itself. Linux and macOS give the main thread 8 MiB. Windows reads the size from the executable's
//! header, and the linker's default there is 1 MiB. Without the larger reserve a command overflowed
//! only on Windows, and a later change to any command could bring that back. This case reads the
//! header of each program the workspace built and holds the reserve to what the other platforms
//! give.

#![cfg(windows)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use kr_controller::supervision::windows::testing::built_binary;

/// The main thread's stack on Linux and macOS.
const MAIN_THREAD_STACK_BYTES: u64 = 8 * 1024 * 1024;

/// The stack a Windows executable asks for its first thread, from its PE header.
fn stack_reserve(program: &Path) -> Result<u64, String> {
    let mut file = File::open(program).map_err(|error| format!("it cannot be opened: {error}"))?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos)
        .map_err(|error| format!("its DOS header cannot be read: {error}"))?;
    if &dos[..2] != b"MZ" {
        return Err("it is not a Windows executable".to_owned());
    }
    let header = u32::from_le_bytes(dos[60..64].try_into().expect("four bytes"));
    file.seek(SeekFrom::Start(u64::from(header)))
        .map_err(|error| format!("its PE header cannot be reached: {error}"))?;
    // The signature, the file header and the optional header as far as the stack reserve.
    let mut pe = [0u8; 4 + 20 + 80];
    file.read_exact(&mut pe)
        .map_err(|error| format!("its PE header cannot be read: {error}"))?;
    if &pe[..4] != b"PE\0\0" {
        return Err("its PE signature is missing".to_owned());
    }
    let optional = &pe[24..];
    match u16::from_le_bytes(optional[..2].try_into().expect("two bytes")) {
        // PE32: the reserve is four bytes.
        0x10b => Ok(u64::from(u32::from_le_bytes(
            optional[72..76].try_into().expect("four bytes"),
        ))),
        // PE32+: the reserve is eight bytes.
        0x20b => Ok(u64::from_le_bytes(
            optional[72..80].try_into().expect("eight bytes"),
        )),
        other => Err(format!("its optional header is of kind {other:#x}")),
    }
}

/// A program is built in the workspace's target directory by `cargo build -p <package>`.
fn built(name: &str) -> PathBuf {
    built_binary(name).unwrap_or_else(|missing| panic!("{missing}"))
}

#[test]
fn each_program_that_blocks_its_main_thread_on_a_future_reserves_the_stack_unix_gives_it() {
    let programs = [
        ("kr", PathBuf::from(env!("CARGO_BIN_EXE_kr"))),
        ("kr-controller", built("kr-controller")),
        ("kr-worker", built("kr-worker")),
        ("kr-plugin-host", built("kr-plugin-host")),
        ("kr-release", built("kr-release")),
    ];
    let mut short = Vec::new();
    for (name, path) in &programs {
        match stack_reserve(path) {
            Ok(reserve) if reserve >= MAIN_THREAD_STACK_BYTES => {}
            Ok(reserve) => short.push(format!(
                "{name} reserves {reserve} bytes for the main thread's stack, and the other \
                 platforms give it {MAIN_THREAD_STACK_BYTES}"
            )),
            Err(why) => short.push(format!("the header of {name} cannot be read: {why}")),
        }
    }
    assert!(short.is_empty(), "{}", short.join("; "));
}
