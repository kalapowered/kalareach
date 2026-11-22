//! The logon sessions of the system: the session a token belongs to, the list of every session, and
//! the wait until one session is gone.
//!
//! The broker makes a logon for each invocation, and the system keeps that logon's session as long
//! as any token or process of it lives. That the session is gone is the evidence that nothing of the
//! invocation lives: no process and no token. The list is read with `LsaEnumerateLogonSessions`.

#![allow(unsafe_code)]

use std::ptr::null_mut;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::LUID;
use windows_sys::Win32::Security::Authentication::Identity::{
    LsaEnumerateLogonSessions, LsaFreeReturnBuffer, LsaGetLogonSessionData, LsaNtStatusToWinError,
    SECURITY_LOGON_SESSION_DATA,
};
use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_STATISTICS, TokenStatistics};

use crate::lifecycle::Session;

use super::ffi::{Handle, Result, Sid, error, last};

/// The platform's time now, as the 64-bit count of 100-nanosecond steps since 1601 that the system
/// uses for a process's creation.
#[must_use]
pub fn now() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    let mut time = FILETIME::default();
    // SAFETY: the out-parameter is local.
    unsafe {
        GetSystemTimeAsFileTime(&raw mut time);
    }
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

/// How often the wait for a session to go reads the list again.
const POLL: Duration = Duration::from_millis(50);

/// The status that says a session is not in the list any more: it ended between the list and the
/// read of its data.
const STATUS_NO_SUCH_LOGON_SESSION: i32 = 0xC000_005F_u32 as i32;

fn number(luid: &LUID) -> u64 {
    (u64::from(luid.HighPart as u32) << 32) | u64::from(luid.LowPart)
}

fn luid(number: u64) -> LUID {
    LUID {
        LowPart: number as u32,
        HighPart: (number >> 32) as i32,
    }
}

/// The logon session that a token belongs to, as a number.
///
/// # Errors
///
/// Returns the platform's error when the token's statistics cannot be read.
pub fn session_of(token: &Handle) -> Result<u64> {
    // SAFETY: a zeroed record is a valid out-parameter of the size the call is given.
    let mut statistics: TOKEN_STATISTICS = unsafe { std::mem::zeroed() };
    let mut returned = 0_u32;
    // SAFETY: the token is open for query and the buffer is a TOKEN_STATISTICS.
    let read = unsafe {
        GetTokenInformation(
            token.raw(),
            TokenStatistics,
            (&raw mut statistics).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &raw mut returned,
        )
    };
    if read == 0 {
        // text: session_of-1
        return Err(last("reading the logon session of a token"));
    }
    Ok(number(&statistics.AuthenticationId))
}

/// Every logon session of the system, as numbers.
///
/// # Errors
///
/// Returns the platform's error when the list cannot be read.
pub fn sessions() -> Result<Vec<u64>> {
    let mut count = 0_u32;
    let mut list: *mut LUID = null_mut();
    // SAFETY: both out-parameters are this function's own; the buffer is freed below.
    let status = unsafe { LsaEnumerateLogonSessions(&raw mut count, &raw mut list) };
    if status != 0 {
        // SAFETY: converts a status to the platform's error number.
        let code = unsafe { LsaNtStatusToWinError(status) };
        // text: sessions-1
        return Err(error(code, "listing the logon sessions"));
    }
    // SAFETY: the call returned `count` records at `list`, valid until the buffer is freed.
    let found = unsafe { std::slice::from_raw_parts(list, count as usize) }
        .iter()
        .map(number)
        .collect();
    // SAFETY: the buffer came from the call above and is freed once.
    unsafe {
        LsaFreeReturnBuffer(list.cast());
    }
    Ok(found)
}

/// Whether a session is in the system's list.
///
/// # Errors
///
/// Returns the platform's error when the list cannot be read.
pub fn session_present(session: u64) -> Result<bool> {
    Ok(sessions()?.contains(&session))
}

/// The sessions of the system that belong to one of the accounts: those whose user is one of the
/// identifiers.
///
/// # Errors
///
/// Returns the platform's error when the list, or the data of a session that is still in it, cannot
/// be read. A session that ends between the list and the read of its data is not one.
pub fn sessions_of(accounts: &[Sid]) -> Result<Vec<u64>> {
    let mut found = Vec::new();
    for session in sessions()? {
        let mut id = luid(session);
        let mut data: *mut SECURITY_LOGON_SESSION_DATA = null_mut();
        // SAFETY: the number is a session's; the out-parameter is this function's own and its buffer
        // is freed below.
        let status = unsafe { LsaGetLogonSessionData(&raw mut id, &raw mut data) };
        if status == STATUS_NO_SUCH_LOGON_SESSION {
            continue;
        }
        if status != 0 {
            // SAFETY: converts a status to the platform's error number.
            let code = unsafe { LsaNtStatusToWinError(status) };
            // text: sessions_of-1
            return Err(error(code, "reading the data of a logon session"));
        }
        // SAFETY: the call returned a record that is valid until the buffer is freed.
        let user = unsafe { (*data).Sid };
        let belongs = !user.is_null() && {
            // SAFETY: the identifier points into the record, valid until the buffer is freed.
            let user = unsafe { Sid::from_ptr(user) };
            accounts.contains(&user)
        };
        // SAFETY: the buffer came from the call above and is freed once.
        unsafe {
            LsaFreeReturnBuffer(data.cast());
        }
        if belongs {
            found.push(session);
        }
    }
    Ok(found)
}

/// Waits until the session is not in the list, for at most `bound`, by reading the list again and
/// again: the end of the wait is an observed state, never a time. The answer is `Absent` when the
/// session is gone, `Present` when it was still there at the bound, and `Unread` when the list
/// could not be read.
#[must_use]
pub fn wait_absent(session: u64, bound: Duration) -> Session {
    let until = Instant::now() + bound;
    loop {
        match session_present(session) {
            Ok(false) => return Session::Absent,
            Ok(true) => {}
            Err(failure) => return Session::Unread(failure.to_string()),
        }
        if Instant::now() >= until {
            return Session::Present;
        }
        std::thread::sleep(POLL);
    }
}
