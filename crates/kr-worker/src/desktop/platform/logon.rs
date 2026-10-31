//! Terminal Services' record of one session, which is where the Windows reader finds a login.
//!
//! The record is the account's to read for its own sessions whatever rights the account has, which
//! is what the logon process of a session is not: the system owns that process, and only an
//! elevated administrator may open it.

#![expect(
    unsafe_code,
    reason = "the session record and the list of sessions are wtsapi32 calls with no safe interface"
)]

use windows_sys::Win32::Foundation::ERROR_CTX_WINSTATION_NOT_FOUND;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory, WTSINFOW,
    WTSQuerySessionInformationW, WTSSessionInfo,
};

use super::{Asked, Listing, NO_SUCH_SESSION_ERROR, Query, SessionRecord, asked_of, listing_of};

// The pure mapping names the error by its number so that it compiles where this module does not.
const _: () = assert!(NO_SUCH_SESSION_ERROR == ERROR_CTX_WINSTATION_NOT_FOUND);

/// Memory that Terminal Services allocated, freed when this goes out of scope, so that no path out
/// of the function that holds it can leave it allocated.
struct Allocated(*mut core::ffi::c_void);

impl Drop for Allocated {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the memory was allocated by a wtsapi32 call that asks for it to be freed
            // with this one, and nothing else holds it.
            unsafe { WTSFreeMemory(self.0) };
        }
    }
}

/// The numbers of the sessions the system lists, or none when the list could not be had.
///
/// A list that comes back with no session in it is the same as one that could not be had: every
/// host has the services session.
pub(super) fn sessions() -> Vec<u32> {
    let mut sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0_u32;
    // SAFETY: a null server is this machine, the reserved word is zero and the version one as the
    // call requires, and the two out parameters are live. The call returns a list that it
    // allocated, which `list` frees.
    let asked = unsafe {
        WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &raw mut sessions,
            &raw mut count,
        )
    };
    let list = Allocated(sessions.cast());
    if asked == 0 || sessions.is_null() {
        return Vec::new();
    }
    // SAFETY: the call returned `count` entries at `sessions`, and `list` keeps them until this
    // function returns.
    let entries =
        unsafe { std::slice::from_raw_parts(sessions, usize::try_from(count).unwrap_or(0)) };
    let numbers = entries.iter().map(|entry| entry.SessionId).collect();
    drop(list);
    numbers
}

/// What the system's list of sessions makes of `session`.
fn listed(session: u32) -> Listing {
    listing_of(&sessions(), session)
}

/// Asks Terminal Services about one session.
///
/// A query that fails with the error for a session it does not have is that answer. Any other
/// failure, and a reply with nothing readable in it, leave the question open and are put to the
/// list of sessions. The system does not fail every query about a number it lacks in one way: on
/// the host these were tried on, a standard account got `ERROR_FILE_NOT_FOUND` (2) for the
/// numbers 10 to 65535 that it tried and `ERROR_CTX_WINSTATION_NOT_FOUND` (7022) for 1048576 and
/// above, so only the second is taken as an answer. `ERROR_ACCESS_DENIED` was not seen for any
/// number, and the same account read the record of another account's session, so it is not taken
/// for an answer either: it goes to the list like any other failure. The number `u32::MAX` names
/// no session: the system reads it as the caller's own.
pub(super) fn record(session: u32) -> Asked {
    asked_of(query(session), || listed(session))
}

/// What Terminal Services returns for a query about one session.
fn query(session: u32) -> Query {
    let mut buffer: *mut u16 = std::ptr::null_mut();
    let mut bytes = 0_u32;
    // SAFETY: a null server is this machine, and the two out parameters are live. The call returns
    // a buffer that it allocated, which `reply` frees.
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
        return Query::Failed(
            std::io::Error::last_os_error()
                .raw_os_error()
                .map(i32::cast_unsigned),
        );
    }
    let reply = Allocated(buffer.cast());
    let whole = usize::try_from(bytes).is_ok_and(|bytes| bytes >= size_of::<WTSINFOW>());
    if buffer.is_null() || !whole {
        return Query::Unreadable;
    }
    // SAFETY: the buffer holds at least one whole `WTSINFOW`, as was just checked, `reply` keeps it
    // until this function returns, and nothing promises it is aligned for one.
    let info = unsafe { buffer.cast::<WTSINFOW>().read_unaligned() };
    drop(reply);
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
        return Query::Unreadable;
    };
    Query::Record(SessionRecord {
        logon_time,
        remote: !station.is_empty() && !station.eq_ignore_ascii_case("console"),
    })
}
