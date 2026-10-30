//! Terminal Services' record of one session, which is where the Windows reader finds a login.
//!
//! The record is the account's to read for its own sessions whatever rights the account has,
//! which is what the logon process of a session is not: the system owns that process, and only an
//! elevated administrator may open it.

#![expect(
    unsafe_code,
    reason = "the session queries are kernel32 and wtsapi32 calls with no safe interface"
)]

use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTS_CURRENT_SERVER_HANDLE, WTSFreeMemory, WTSINFOW,
    WTSQuerySessionInformationW, WTSSessionInfo,
};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

use super::{Asked, SessionRecord};

/// What the system says when no session has the number asked about.
const ERROR_CTX_WINSTATION_NOT_FOUND: i32 = 7022;

/// Returns the session this process runs in, or nothing when the system will not say.
pub(super) fn own_session() -> Option<u32> {
    let mut session = 0_u32;
    // SAFETY: the process identifier is this process's own, and `session` is a live out parameter.
    let asked = unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &raw mut session) };
    (asked != 0).then_some(session)
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
        return match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_CTX_WINSTATION_NOT_FOUND) => Asked::NoSuchSession,
            _ => Asked::Unanswered,
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
        return Asked::Unanswered;
    };
    let station = String::from_utf16_lossy(
        &info.WinStationName[..info
            .WinStationName
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(info.WinStationName.len())],
    );
    Asked::Record(SessionRecord {
        logon_time: u64::try_from(info.LogonTime).unwrap_or(0),
        remote: !station.is_empty() && !station.eq_ignore_ascii_case("console"),
    })
}
