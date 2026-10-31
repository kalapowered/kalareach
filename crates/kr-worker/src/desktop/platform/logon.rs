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
    // a buffer that it allocated, which `_reply` frees.
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
    let _reply = Allocated(buffer.cast());
    if buffer.is_null() {
        return Query::Unreadable;
    }
    let length = usize::try_from(bytes).unwrap_or(0);
    // SAFETY: the call returned a buffer of `bytes` bytes at `buffer`, which `_reply` keeps until
    // this function returns.
    let held = unsafe { std::slice::from_raw_parts(buffer.cast::<u8>(), length) };
    reply_of(held)
}

/// What a reply to the query for one session's information says.
///
/// A reply shorter than the record is nothing this host can read, and so is a logon time before
/// the epoch, which is not nobody being logged on.
fn reply_of(reply: &[u8]) -> Query {
    if reply.len() < size_of::<WTSINFOW>() {
        return Query::Unreadable;
    }
    // SAFETY: the reply holds at least one whole `WTSINFOW`, as was just checked, the structure is
    // plain integers for which every pattern of bytes is a value, and nothing promises the reply
    // is aligned for one.
    let info = unsafe { reply.as_ptr().cast::<WTSINFOW>().read_unaligned() };
    let station = String::from_utf16_lossy(
        &info.WinStationName[..info
            .WinStationName
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(info.WinStationName.len())],
    );
    let Ok(logon_time) = u64::try_from(info.LogonTime) else {
        return Query::Unreadable;
    };
    Query::Record(SessionRecord {
        logon_time,
        remote: !station.is_empty() && !station.eq_ignore_ascii_case("console"),
    })
}

#[cfg(test)]
mod tests {
    use std::hint::black_box;
    use std::process::Command;

    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    use super::{
        Query, SessionRecord, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSEnumerateSessionsW,
        WTSINFOW, WTSQuerySessionInformationW, WTSSessionInfo, query, reply_of, sessions,
    };

    /// A reply as Terminal Services lays it out: the record `WTSINFOW` in bytes, with the name of
    /// the session's station and its logon time and nothing else set.
    fn reply(station: &str, logon_time: i64) -> Vec<u8> {
        let mut bytes = vec![0_u8; size_of::<WTSINFOW>()];
        let name = core::mem::offset_of!(WTSINFOW, WinStationName);
        for (index, unit) in station.encode_utf16().enumerate() {
            bytes[name + 2 * index..name + 2 * index + 2].copy_from_slice(&unit.to_ne_bytes());
        }
        let at = core::mem::offset_of!(WTSINFOW, LogonTime);
        bytes[at..at + 8].copy_from_slice(&logon_time.to_ne_bytes());
        bytes
    }

    fn recorded(logon_time: u64, remote: bool) -> Query {
        Query::Record(SessionRecord { logon_time, remote })
    }

    /// A reply is read only when it holds the whole record the system describes a session with:
    /// one a byte short, and one with nothing in it, are nothing this host can read.
    #[test]
    fn a_reply_shorter_than_the_record_is_not_read() {
        let whole = reply("Console", 133_900_000_000_000_000);
        assert_eq!(reply_of(&whole), recorded(133_900_000_000_000_000, false));
        // A longer reply is read from its start.
        let mut longer = whole.clone();
        longer.extend([0xAA; 16]);
        assert_eq!(reply_of(&longer), recorded(133_900_000_000_000_000, false));
        assert_eq!(reply_of(&whole[..whole.len() - 1]), Query::Unreadable);
        assert_eq!(reply_of(&[]), Query::Unreadable);
    }

    /// The station's name says whether the session is a remote desktop one: the console is not,
    /// nor is a session with no station, and any other name is.
    #[test]
    fn a_session_is_remote_unless_it_is_the_console_or_has_no_station() {
        assert_eq!(reply_of(&reply("RDP-Tcp#3", 7)), recorded(7, true));
        assert_eq!(reply_of(&reply("Console", 7)), recorded(7, false));
        assert_eq!(reply_of(&reply("console", 7)), recorded(7, false));
        assert_eq!(reply_of(&reply("", 7)), recorded(7, false));
    }

    /// A logon time before the epoch is a value this host cannot read, which is not nobody being
    /// logged on: it reads as nothing, where zero reads as a record of no user.
    #[test]
    fn a_logon_time_before_the_epoch_is_not_nobody_being_logged_on() {
        assert_eq!(reply_of(&reply("Console", -1)), Query::Unreadable);
        assert_eq!(reply_of(&reply("Console", i64::MIN)), Query::Unreadable);
        assert_eq!(reply_of(&reply("Console", 0)), recorded(0, false));
        assert_eq!(
            reply_of(&reply("Console", i64::MAX)),
            recorded(i64::MAX.cast_unsigned(), false)
        );
    }

    /// The private bytes this process holds.
    fn private_bytes() -> usize {
        let mut counters = PROCESS_MEMORY_COUNTERS_EX::default();
        let size = u32::try_from(size_of::<PROCESS_MEMORY_COUNTERS_EX>()).unwrap_or(0);
        counters.cb = size;
        // SAFETY: the structure is live and of the size given, and the pseudo handle of the
        // current process needs no closing.
        let read =
            unsafe { GetProcessMemoryInfo(GetCurrentProcess(), (&raw mut counters).cast(), size) };
        assert_ne!(read, 0, "the process's memory was not read");
        counters.PrivateUsage
    }

    /// Asks for the list of sessions and keeps it, as `sessions` would if it never gave it back.
    fn keep_a_list() {
        let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0_u32;
        // SAFETY: a null server is this machine, the reserved word is zero and the version one as
        // the call requires, and the two out parameters are live. The list is kept on purpose.
        unsafe {
            WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                &raw mut list,
                &raw mut count,
            )
        };
    }

    /// Asks about a session and keeps the reply, as `query` would if it never gave it back.
    fn keep_a_reply(session: u32) {
        let mut buffer: *mut u16 = std::ptr::null_mut();
        let mut bytes = 0_u32;
        // SAFETY: a null server is this machine, and the two out parameters are live. The reply is
        // kept on purpose.
        unsafe {
            WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session,
                WTSSessionInfo,
                &raw mut buffer,
                &raw mut bytes,
            )
        };
    }

    /// How much more private memory the process holds after `calls` of `each` than before.
    fn growth(calls: usize, mut each: impl FnMut()) -> usize {
        let before = private_bytes();
        for _ in 0..calls {
            each();
        }
        private_bytes().saturating_sub(before)
    }

    const PROBE: &str = "a_process_that_asks_often_holds_no_more_memory_for_it";

    /// KR-REQ-03.18: the list of sessions and the reply about one are given back to Terminal
    /// Services on every path, so that a reader that asks often does not grow. The measurement is
    /// of a whole process, so the case runs it in a process of its own.
    #[test]
    fn memory_that_terminal_services_allocated_is_given_back() {
        let program = std::env::current_exe().expect("the program of this test");
        let name = format!(
            "{}::{PROBE}",
            module_path!()
                .split_once("::")
                .expect("a path in the crate")
                .1
        );
        let run = Command::new(program)
            .args([
                "--exact",
                &name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .output()
            .expect("the probe starts");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        println!("{said}");
        assert!(run.status.success(), "the probe failed: {said}");
        assert!(said.contains("1 passed"), "the probe did not run: {said}");
    }

    /// The probe of the case above. Many calls that give their memory back leave the process with
    /// about what it had, and as many that keep it leave it with far more, which shows that the
    /// measurement sees a leak at all.
    #[test]
    #[ignore = "measures the process it runs in; the case above runs it in one of its own"]
    fn a_process_that_asks_often_holds_no_more_memory_for_it() {
        const CALLS: usize = 10_000;
        // Far under what the calls keep when they are not given back, and over the jitter of a
        // process that is doing nothing else.
        const BOUND: usize = 256 * 1024;
        let session = kr_ipc::starter::current_session().expect("the process's own session");
        // The first calls set up what the calls themselves keep for good.
        for _ in 0..200 {
            black_box(sessions());
            black_box(query(session));
        }
        let lists = growth(CALLS, || {
            black_box(sessions());
        });
        let replies = growth(CALLS, || {
            black_box(query(session));
        });
        let kept_lists = growth(CALLS, keep_a_list);
        let kept_replies = growth(CALLS, || keep_a_reply(session));
        println!(
            "growth: lists {lists}, replies {replies}, kept lists {kept_lists}, kept replies {kept_replies}"
        );
        assert!(
            kept_lists > 2 * BOUND,
            "{CALLS} lists kept grew the process by only {kept_lists}"
        );
        assert!(
            kept_replies > 2 * BOUND,
            "{CALLS} replies kept grew the process by only {kept_replies}"
        );
        assert!(
            lists < BOUND,
            "{CALLS} lists asked for and given back grew the process by {lists}"
        );
        assert!(
            replies < BOUND,
            "{CALLS} replies asked for and given back grew the process by {replies}"
        );
    }
}
