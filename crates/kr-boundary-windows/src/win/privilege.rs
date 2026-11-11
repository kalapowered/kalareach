//! The backup and restore privileges, held by one thread for the length of one privileged action.
//!
//! The service's process token holds the privileges disabled and this module never enables them
//! there. A walk that needs them makes a copy of the process token, enables them on the copy and
//! installs the copy as the walking thread's own token. No other thread of the service runs with
//! them while that happens, and the thread has none when the guard is gone, however the walk
//! ended: a return, an error or a panic all drop the guard.
//!
//! The guard cannot be sent to another thread, so the privilege cannot be used where it was not
//! asked for, and the functions that act with the privilege take the guard as an argument, so the
//! compiler shows that none runs outside one. If the thread's own token cannot be taken away
//! again, the broker's process ends at once, with [`FAIL_CLOSED_EXIT`]: no thread goes on with the
//! enabled token and no open connection is served again. The service's failure action starts the
//! broker anew, and its journal says what was unfinished.

#![allow(unsafe_code)]

use std::cell::Cell;
use std::marker::PhantomData;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_NO_TOKEN, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE,
    TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenImpersonation,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken, SetThreadToken,
    TerminateProcess,
};

use super::ffi::{Handle, Result, error, last, wide};

/// A privilege a walk may enable on its own thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Privilege {
    /// Open any object for reading, whatever its permission list says.
    Backup,
    /// Open any object for writing or deleting, and write any object's permission list.
    Restore,
    /// Take the ownership of any object.
    TakeOwnership,
}

impl Privilege {
    fn name(self) -> &'static str {
        match self {
            Privilege::Backup => "SeBackupPrivilege",
            Privilege::Restore => "SeRestorePrivilege",
            Privilege::TakeOwnership => "SeTakeOwnershipPrivilege",
        }
    }
}

/// The privileges a walk enables: the least set the cases showed is enough.
pub const WALK_PRIVILEGES: [Privilege; 2] = [Privilege::Backup, Privilege::Restore];

/// The exit code of a broker that could not give a privilege back and ended at once. The service
/// manager sees a process that ended without reporting its stop and applies the service's failure
/// action.
pub const FAIL_CLOSED_EXIT: u32 = 0x4B52_0001;

/// Set when a thread's own token could not be taken away. Ending the process follows at once, so
/// nothing in a running broker sees it set; the service's loops read it as well, so that a
/// connection that outlives a stand-in for the exit is dropped and not served.
static REVERT_FAILED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// A guard of this thread is alive: a second would replace the first one's token.
    static ENTERED: Cell<bool> = const { Cell::new(false) };
    /// This thread could not be taken back to its own token and runs no further walk.
    static POISONED: Cell<bool> = const { Cell::new(false) };
    /// A case asks the next revert on this thread to fail.
    #[cfg(feature = "testing")]
    static FORCE_REVERT_FAILURE: Cell<bool> = const { Cell::new(false) };
}

/// Whether a thread ever failed to give its privileges back: nothing is served after that.
#[must_use]
pub fn revert_failed() -> bool {
    REVERT_FAILED.load(Ordering::SeqCst)
}

/// A thread token with privileges enabled, installed on the thread that made it and removed
/// when this value is dropped.
#[derive(Debug)]
pub struct PrivGuard {
    token: Handle,
    /// A raw pointer is neither `Send` nor `Sync`: the guard stays on its thread.
    not_send: PhantomData<*const ()>,
}

/// Enables the walk's privileges on this thread. See [`enter_with`].
///
/// # Errors
///
/// Returns an error when the thread may not walk, already holds a guard, or the privileges cannot
/// be enabled.
pub fn enter() -> Result<PrivGuard> {
    enter_with(&WALK_PRIVILEGES)
}

/// Enables exactly the privileges given on this thread, on a copy of the process token that only
/// this thread uses.
///
/// # Errors
///
/// Returns an error when the thread is poisoned or already holds a guard, when the process token
/// does not hold one of the privileges, or when the platform refuses a step.
pub fn enter_with(privileges: &[Privilege]) -> Result<PrivGuard> {
    if POISONED.get() || revert_failed() {
        return Err(error(
            ERROR_NO_TOKEN,
            "this thread could not give its privileges back and runs no further walk",
        ));
    }
    if ENTERED.get() {
        return Err(error(
            ERROR_ALREADY_EXISTS,
            "this thread already runs a privileged walk",
        ));
    }
    let copy = copy_of_process_token()?;
    enable(&copy, privileges)?;
    // SAFETY: a null thread handle means the calling thread; the copy is an impersonation token
    // that this thread's guard keeps open for as long as the thread uses it.
    if unsafe { SetThreadToken(null(), copy.raw()) } == 0 {
        return Err(last("installing the privileged token on the thread"));
    }
    ENTERED.set(true);
    Ok(PrivGuard {
        token: copy,
        not_send: PhantomData,
    })
}

impl Drop for PrivGuard {
    fn drop(&mut self) {
        let reverted = revert();
        ENTERED.set(false);
        if !reverted {
            POISONED.set(true);
            REVERT_FAILED.store(true, Ordering::SeqCst);
            fail_closed();
        }
        // The token handle closes when `self.token` drops, after the thread stopped using it.
        let _ = &self.token;
    }
}

/// Ends the broker's process at once: this thread still holds the enabled token, and nothing may go
/// on with it. No destructor runs, and nothing is written, since the thread that failed cannot be
/// trusted to write anything.
fn fail_closed() {
    #[cfg(feature = "testing")]
    if testing::stand_in_for_exit() {
        return;
    }
    // SAFETY: ends the calling process; the pseudo-handle of the current process is always valid.
    unsafe {
        TerminateProcess(GetCurrentProcess(), FAIL_CLOSED_EXIT);
    }
    // The call does not return. If it did, a process that cannot be ended is stopped another way.
    std::process::abort();
}

fn revert() -> bool {
    #[cfg(feature = "testing")]
    if FORCE_REVERT_FAILURE.replace(false) {
        return false;
    }
    // SAFETY: a null thread handle and a null token take the thread's impersonation away.
    unsafe { SetThreadToken(null(), null_mut()) != 0 }
}

fn copy_of_process_token() -> Result<Handle> {
    let mut process_token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle of the current process is always valid and the out-parameter is local.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &raw mut process_token,
        )
    };
    if opened == 0 {
        return Err(last("opening the service's token"));
    }
    let process_token = Handle::new(process_token, "the service's token")?;
    let mut copy: HANDLE = null_mut();
    // SAFETY: the token is open and the out-parameter is local.
    let duplicated = unsafe {
        DuplicateTokenEx(
            process_token.raw(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_IMPERSONATE,
            null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut copy,
        )
    };
    if duplicated == 0 {
        return Err(last("copying the service's token"));
    }
    Handle::new(copy, "the copy of the service's token")
}

fn luid_of(privilege: Privilege) -> Result<LUID> {
    let name = wide(privilege.name());
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: the name is NUL-terminated and the out-parameter is local.
    if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &raw mut luid) } == 0 {
        return Err(last(format!("looking up {}", privilege.name())));
    }
    Ok(luid)
}

/// Enables the privileges on a token, and says so if any of them is not in it.
fn enable(token: &Handle, privileges: &[Privilege]) -> Result<()> {
    if privileges.is_empty() {
        return Ok(());
    }
    #[repr(C)]
    struct Request {
        count: u32,
        entries: [LUID_AND_ATTRIBUTES; 3],
    }
    let mut request = Request {
        count: 0,
        entries: [LUID_AND_ATTRIBUTES {
            Luid: LUID {
                LowPart: 0,
                HighPart: 0,
            },
            Attributes: 0,
        }; 3],
    };
    for privilege in privileges.iter().take(request.entries.len()) {
        request.entries[request.count as usize] = LUID_AND_ATTRIBUTES {
            Luid: luid_of(*privilege)?,
            Attributes: SE_PRIVILEGE_ENABLED,
        };
        request.count += 1;
    }
    // SAFETY: the request has the layout of TOKEN_PRIVILEGES with `count` entries; the token is open
    // with the right to adjust privileges; no previous state is asked for.
    let adjusted = unsafe {
        AdjustTokenPrivileges(
            token.raw(),
            0,
            (&raw const request).cast::<TOKEN_PRIVILEGES>(),
            0,
            null_mut(),
            null_mut(),
        )
    };
    if adjusted == 0 {
        return Err(last("enabling the privileges on the thread's token"));
    }
    // SAFETY: reads the calling thread's last error, which AdjustTokenPrivileges set.
    let code = unsafe { GetLastError() };
    if code == ERROR_NOT_ALL_ASSIGNED {
        return Err(error(
            code,
            "the service's token does not hold every privilege the walk needs",
        ));
    }
    Ok(())
}

/// Whether the calling thread has a token of its own.
#[must_use]
pub fn thread_has_token() -> bool {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle of the current thread is valid and the out-parameter is local.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
    if opened == 0 {
        return false;
    }
    drop(Handle::new(token, "the thread's token"));
    true
}

/// What the cases use to make the next revert on a thread fail, to see the process end, and to clear
/// the latch afterwards.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::atomic::{AtomicBool, Ordering};

    static STAND_IN: AtomicBool = AtomicBool::new(false);
    static EXIT_ASKED: AtomicBool = AtomicBool::new(false);

    /// The next guard dropped on this thread fails to revert.
    pub fn fail_next_revert() {
        super::FORCE_REVERT_FAILURE.set(true);
    }

    /// Makes the end of the process, after a failed revert, a record that a case reads with
    /// [`exit_was_asked`], so that a case can go on in the same process and see that nothing is
    /// served afterwards. A case that shows the real end runs a program of its own.
    pub fn stand_in_for_the_process_end() {
        STAND_IN.store(true, Ordering::SeqCst);
    }

    pub(super) fn stand_in_for_exit() -> bool {
        if STAND_IN.load(Ordering::SeqCst) {
            EXIT_ASKED.store(true, Ordering::SeqCst);
            return true;
        }
        false
    }

    /// Whether a failed revert asked for the end of the process while the stand-in was in place.
    #[must_use]
    pub fn exit_was_asked() -> bool {
        EXIT_ASKED.load(Ordering::SeqCst)
    }

    /// Clears the latch and the thread's poisoned state after a case.
    pub fn clear() {
        STAND_IN.store(false, Ordering::SeqCst);
        EXIT_ASKED.store(false, Ordering::SeqCst);
        super::REVERT_FAILED.store(false, Ordering::SeqCst);
        super::POISONED.set(false);
        super::ENTERED.set(false);
        // SAFETY: a null thread handle and a null token take the thread's impersonation away.
        unsafe {
            windows_sys::Win32::System::Threading::SetThreadToken(
                std::ptr::null(),
                std::ptr::null_mut(),
            );
        }
    }
}
