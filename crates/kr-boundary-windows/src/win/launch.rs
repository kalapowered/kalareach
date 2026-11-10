//! Starting a program under a token and waiting for it to end.

#![allow(unsafe_code)]

use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Threading::{
    CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DETACHED_PROCESS, GetExitCodeProcess,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use super::ffi::{Handle, Result, wide, wide_path};

/// What became of a program started under a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The platform refused to start it, with this error number. The application-control policy's
    /// refusal is 1260.
    NotStarted(u32),
    /// It started and ended with this exit code.
    Ran(u32),
    /// It started and was still running when the bound ran out, and was ended.
    TimedOut,
}

/// The error number the platform gives a program that application control refused.
pub const REFUSED_BY_POLICY: u32 = 1260;

/// The environment block a child gets: only what is passed, in the form the platform wants.
fn environment(pairs: &[(&str, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(&str, String)> = pairs.iter().collect();
    sorted.sort_by_key(|pair| pair.0.to_uppercase());
    let mut block = Vec::new();
    for (name, value) in sorted {
        block.extend(format!("{name}={value}").encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

fn null_device(access: u32) -> Result<Handle> {
    let name = wide("NUL");
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the name is NUL-terminated and the attributes are this function's own for the call.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    Handle::new(handle, "opening the null device")
}

/// Starts a program under a token, with no console and the null device on all three standard
/// handles and an environment of exactly the pairs given, and waits for it up to a bound.
///
/// The program, its command line and its directory are the caller's. This function opens no path
/// the token could not and gives the child nothing else.
///
/// # Errors
///
/// Returns the platform's error when the standard handles cannot be made or the wait fails.
pub fn run_as(
    token: &Handle,
    program: &Path,
    command_line: &str,
    directory: &Path,
    environment_pairs: &[(&str, String)],
    bound: Duration,
) -> Result<Outcome> {
    let input = null_device(GENERIC_READ)?;
    let output = null_device(GENERIC_WRITE)?;
    let program = wide_path(program);
    let mut command = wide(command_line);
    let directory = wide_path(directory);
    let block = environment(environment_pairs);
    // SAFETY: a zeroed startup record is the documented starting point.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.raw();
    startup.hStdOutput = output.raw();
    startup.hStdError = output.raw();
    // SAFETY: a zeroed record is what the platform fills in.
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the token is open, every string is NUL-terminated and outlives the call, and the
    // environment block ends with its double terminator.
    let started = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            program.as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            DETACHED_PROCESS | CREATE_UNICODE_ENVIRONMENT,
            block.as_ptr().cast(),
            directory.as_ptr(),
            &raw const startup,
            &raw mut process,
        )
    };
    if started == 0 {
        // SAFETY: reads the calling thread's last error.
        return Ok(Outcome::NotStarted(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    let child = Handle::new(process.hProcess, "the started process")?;
    let _thread = Handle::new(process.hThread, "the started process's thread")?;
    let milliseconds = u32::try_from(bound.as_millis()).unwrap_or(u32::MAX);
    // SAFETY: the process handle is open.
    let waited: u32 = unsafe { WaitForSingleObject(child.raw(), milliseconds) };
    if waited != WAIT_OBJECT_0 {
        // SAFETY: the process handle is open and the process is this function's own child.
        unsafe {
            TerminateProcess(child.raw(), 1);
        }
        return Ok(Outcome::TimedOut);
    }
    let mut code = 0_u32;
    // SAFETY: the process has ended and the handle is open.
    unsafe {
        GetExitCodeProcess(child.raw(), &raw mut code);
    }
    Ok(Outcome::Ran(code))
}
