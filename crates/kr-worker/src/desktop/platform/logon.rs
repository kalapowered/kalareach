//! Terminal Services' record of one session, which is where the Windows reader finds a login.
//!
//! The record is the account's to read for its own sessions whatever rights the account has,
//! which is what the logon process of a session is not: the system owns that process, and only an
//! elevated administrator may open it.

#![expect(
    unsafe_code,
    reason = "the session query is a wtsapi32 call with no safe interface"
)]

use windows_sys::Win32::Foundation::ERROR_CTX_WINSTATION_NOT_FOUND;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOW,
    WTSQuerySessionInformationW, WTSSessionInfo,
};

use super::{Asked, SessionRecord};

/// What is said of a session whose record could not be read: that the system has no such session
/// when its list of sessions does not hold the number, and otherwise nothing.
///
/// The error a query for a session that is not there fails with, and what it returns for one, are
/// the system's to choose and differ between machines, so the answer to "is it there" is asked of
/// the list of sessions and not read out of the query's failure.
fn unread(session: u32) -> Asked {
    match listed(session) {
        Some(false) => Asked::NoSuchSession,
        Some(true) | None => Asked::Unanswered,
    }
}

/// Whether the system's list of sessions holds `session`, or nothing when the list could not be
/// had.
fn listed(session: u32) -> Option<bool> {
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0_u32;
    // SAFETY: a null server is this machine, the reserved word is zero and the version one as the
    // call requires, and the two out parameters are live. The call returns a list that it
    // allocated, which is freed below.
    let asked = unsafe {
        WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &raw mut sessions,
            &raw mut count,
        )
    };
    if asked == 0 || sessions.is_null() {
        return None;
    }
    // SAFETY: the call returned `count` entries at `sessions`, and nothing frees them before the
    // slice is done with.
    let held = unsafe { std::slice::from_raw_parts(sessions, usize::try_from(count).ok()?) }
        .iter()
        .any(|entry| entry.SessionId == session);
    // SAFETY: the list was allocated by the call above and nothing else holds it.
    unsafe { WTSFreeMemory(sessions.cast()) };
    Some(held)
}

/// Asks Terminal Services about one session.
pub(super) fn record(session: u32) -> Asked {
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes = 0_u32;
    // SAFETY: a null server is this machine, and the two out parameters are live. The call returns
    // a buffer that it allocated, which is freed below.
    let asked = unsafe {
        WTSQuerySessionInformationW(
            WTS_CURRENT_SERVER_HANDLE,
            session,
            WTSSessionInfo,
            &raw mut buffer,
            &raw mut bytes,
        )
    };
    if asked == 0 {
        return match std::io::Error::last_os_error()
            .raw_os_error()
            .map(i32::cast_unsigned)
        {
            Some(ERROR_CTX_WINSTATION_NOT_FOUND) => Asked::NoSuchSession,
            _ => unread(session),
        };
    }
    let whole = usize::try_from(bytes).is_ok_and(|bytes| bytes >= size_of::<WTSINFOW>());
    let info = if buffer.is_null() || !whole {
        None
    } else {
        // SAFETY: the buffer holds at least one whole `WTSINFOW`, as was just checked, and nothing
        // promises it is aligned for one.
        Some(unsafe { buffer.cast::<WTSINFOW>().read_unaligned() })
    };
    if !buffer.is_null() {
        // SAFETY: the buffer was allocated by the query above and nothing else holds it.
        unsafe { WTSFreeMemory(buffer.cast()) };
    }
    let Some(info) = info else {
        return unread(session);
    };
    let station = String::from_utf16_lossy(
        &info.WinStationName[..info
            .WinStationName
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(info.WinStationName.len())],
    );
    // A time before the epoch is a value this host cannot read, which is not nobody being logged
    // on.
    let Ok(logon_time) = u64::try_from(info.LogonTime) else {
        return unread(session);
    };
    Asked::Record(SessionRecord {
        logon_time,
        remote: !station.is_empty() && !station.eq_ignore_ascii_case("console"),
    })
}
