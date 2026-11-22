//! How an invocation lives and ends in the broker, shown on a Windows guest: that a refusal the
//! broker sends before it closes a connection reaches a client that reads it in parts, the phases of
//! an invocation on the fixture tree, the one ending function and what proves an end, and what a
//! restart of the broker makes of an invocation that was cut short.
//!
//! These cases run only in a disposable guest, as SYSTEM, under a Hyper-V checkpoint that is restored
//! afterwards, each one alone from a clean machine.

#![cfg(all(windows, feature = "testing"))]
#![allow(unsafe_code)]

use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, OPEN_EXISTING, ReadFile, SECURITY_SQOS_PRESENT, WriteFile,
};

use kr_boundary_windows::frame::{self, Response};
use kr_boundary_windows::manifest::Manifest;
use kr_boundary_windows::pipe_access;
use kr_boundary_windows::win::ffi::{Handle, Sid, wide};
use kr_boundary_windows::win::install::Paths;
use kr_boundary_windows::win::pipe::{Kind, Stop};
use kr_boundary_windows::win::{broker, token};

fn runs_as_the_system() -> bool {
    token::current_user().is_ok_and(|user| user.to_text().is_ok_and(|text| text == "S-1-5-18"))
}

fn open_pipe(name: &str) -> Result<Handle, u32> {
    let name = wide(name);
    // SAFETY: the name is NUL-terminated; the result is checked.
    let opened = unsafe {
        CreateFileW(
            name.as_ptr(),
            pipe_access::CLIENT,
            0,
            null(),
            OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | 0x0001_0000,
            null_mut(),
        )
    };
    if opened == INVALID_HANDLE_VALUE {
        // SAFETY: reads the last error of this thread.
        return Err(unsafe { GetLastError() });
    }
    Ok(Handle::new(opened, "a pipe").unwrap())
}

fn open_when_it_exists(name: &str) -> Handle {
    let until = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match open_pipe(name) {
            Ok(pipe) => return pipe,
            Err(code) => {
                assert!(
                    std::time::Instant::now() < until,
                    "the pipe did not open: {code}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
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

/// Reads exactly `size` bytes with one call, or says why not.
fn read_exactly(pipe: &Handle, size: usize) -> Result<Vec<u8>, u32> {
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
    if done == 0 {
        // SAFETY: reads the last error of this thread.
        return Err(unsafe { GetLastError() });
    }
    buffer.truncate(got as usize);
    Ok(buffer)
}

/// The broker's two pipes, served by this process until the case ends.
struct BrokerLoop {
    stop: Arc<Stop>,
    thread: Option<JoinHandle<Result<(), String>>>,
}

impl BrokerLoop {
    fn start() -> BrokerLoop {
        assert!(
            std::fs::metadata(Kind::Persons.name()).is_err(),
            "the machine is not clean: the broker's pipe is in use"
        );
        let stop = Stop::new().unwrap();
        let thread = std::thread::spawn({
            let stop = Arc::clone(&stop);
            move || {
                let everyone = Sid::parse("S-1-1-0").unwrap();
                broker::testing::serve(
                    Manifest::begin(),
                    Paths::system().expect("the system's folders are read"),
                    &[everyone],
                    stop,
                )
            }
        });
        BrokerLoop {
            stop,
            thread: Some(thread),
        }
    }

    fn end(mut self) -> Result<(), String> {
        self.stop.set();
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for BrokerLoop {
    fn drop(&mut self) {
        self.stop.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The broker closes a connection right after it sends a refusal. A client that reads the length
/// and then the body, with a pause between the two reads, gets the whole refusal and not a broken
/// pipe: the close waits until the client has read what was sent.
#[test]
#[ignore = "runs as the system in a disposable guest"]
fn a_refusal_reaches_a_client_that_reads_its_length_and_its_body_apart() {
    if !runs_as_the_system() {
        eprintln!("SKIPPED: needs the system's token");
        return;
    }
    broker::init();
    let broker_loop = BrokerLoop::start();
    let pipe = open_when_it_exists(Kind::Persons.name());
    write_all(&pipe, &framed(r#"{"request":"hello","version":99}"#));
    let length = read_exactly(&pipe, 4).expect("the length of the refusal");
    let length = u32::from_le_bytes(length.try_into().unwrap()) as usize;
    // A client that does something else between its two reads: the broker has long since sent its
    // answer and would have closed the connection.
    std::thread::sleep(Duration::from_millis(500));
    let body = read_exactly(&pipe, length)
        .unwrap_or_else(|code| panic!("the body of the refusal was lost: the pipe's error {code}"));
    let answer: Response = serde_json::from_slice(&body).unwrap();
    assert!(
        matches!(
            answer,
            Response::Refused {
                reason: frame::Refusal::Version,
                ..
            }
        ),
        "{answer:?}"
    );
    drop(pipe);
    assert_eq!(broker_loop.end(), Ok(()));
}
