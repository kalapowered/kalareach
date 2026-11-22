//! The client of an invocation, known from the pipe and never from a message.
//!
//! The pipe gives the caller's process number and the token that the caller's side of the
//! connection carries. The broker opens that process once and holds the handle for as long as the
//! invocation lasts, so that its number cannot name another process in the meantime, records when it
//! was created, and checks that the process's own token belongs to the same account as the
//! connection's. The rights of the client are computed from the connection's token, as an
//! impersonation token at identification level, and from nothing a message says. A client whose
//! token the permission computation does not model is refused before anything else: see
//! [`crate::standing`]. The broker performs no file operation as the client.

#![allow(unsafe_code)]

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_CANT_OPEN_ANONYMOUS, FILETIME, HANDLE};
use windows_sys::Win32::Security::{
    CheckTokenMembership, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    IsTokenRestricted, TOKEN_ELEVATION, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, TokenElevation, TokenImpersonationLevel, TokenIntegrityLevel, TokenIsAppContainer,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::refusal::Refusal;
use crate::standing::{self, TokenFacts};

use super::ffi::{self, Handle, Result, Sid, error, last};
use super::pipe::Connection;
use super::rights::{self, ImpersonationToken, Right, Sd};
use super::token;

/// Who is on the other end of a connection, and what its token may do.
#[derive(Debug)]
pub struct ClientIdentity {
    /// The caller's process number, read from the pipe.
    pub pid: u32,
    /// The caller's process, held open for as long as the identity lives, so that the number
    /// cannot name another process while it does.
    pub process: Handle,
    /// When the process was created, in the platform's 100-nanosecond ticks.
    pub creation_time: u64,
    /// The account of the caller, the same in the connection's token and in the process's own.
    pub user_sid: Sid,
    /// The connection's token, as an impersonation token at identification level.
    pub token: ImpersonationToken,
}

/// Identifies the client on the other end of a connection and refuses one the broker does not model.
///
/// The first message of the connection must have been read: the platform lets a server take the
/// caller's identity only after that.
///
/// # Errors
///
/// Refuses, with the kind `authentication`, a caller that cannot be identified, whose process
/// cannot be held, whose process runs as another account than the connection's, or whose token is
/// elevated, restricted, an app container, below medium integrity or connected below identification
/// level.
pub fn client_from_pipe(connection: &Connection) -> std::result::Result<ClientIdentity, Refusal> {
    let (pid, caller) = match connection.caller() {
        Ok(found) => found,
        Err(failure) if failure.code == ERROR_CANT_OPEN_ANONYMOUS => {
            return Err(standing::unidentified(standing::RULE_LEVEL));
        }
        Err(_) => return Err(standing::unidentified(standing::RULE_IDENTIFY)),
    };
    let unidentified = |_: ffi::Error| standing::unidentified(standing::RULE_IDENTIFY);
    let token = ImpersonationToken::duplicate_of(&caller).map_err(unidentified)?;
    let facts = facts_of(&token).map_err(unidentified)?;
    standing::refuse(&facts)?;
    let caller_user = token::user_of(&caller).map_err(unidentified)?;
    // The process is held before its token is read, so the token is the held process's.
    let process = hold_process(pid).map_err(|_| process_refusal())?;
    let creation_time = created(&process).map_err(|_| process_refusal())?;
    // A process that has ended may have had its number given to another one before it was opened.
    // text: client_wait-1
    match ffi::wait(process.raw(), 0, "checking the caller's process") {
        Ok(ffi::Waited::TimedOut) => {}
        Ok(ffi::Waited::Signalled(_)) | Err(_) => return Err(process_refusal()),
    }
    let process_user = user_of_process(&process).map_err(|_| process_refusal())?;
    let caller_text = caller_user.to_text().map_err(unidentified)?;
    let process_text = process_user.to_text().map_err(unidentified)?;
    standing::same_user(&caller_text, &process_text)?;
    Ok(ClientIdentity {
        pid,
        process,
        creation_time,
        user_sid: caller_user,
        token,
    })
}

fn process_refusal() -> Refusal {
    Refusal::new(
        crate::frame::invocation::RefusedKind::Authentication,
        standing::RULE_PROCESS,
        standing::PROCESS_WORDS,
    )
}

impl ClientIdentity {
    /// Refuses a client whose account is not one of the enrolled persons.
    ///
    /// # Errors
    ///
    /// Refuses with the kind `authentication` when the account is not enrolled, or when an
    /// identifier cannot be written as text.
    pub fn require_enrolled(&self, persons: &[Sid]) -> std::result::Result<(), Refusal> {
        let unidentified = |_: ffi::Error| standing::unidentified(standing::RULE_IDENTIFY);
        let mut texts = Vec::with_capacity(persons.len());
        for person in persons {
            texts.push(person.to_text().map_err(unidentified)?);
        }
        standing::enrolled(&self.user_sid.to_text().map_err(unidentified)?, &texts)
    }

    /// Whether the client's token holds one right on the descriptor, as the platform's access check
    /// reads it. A check that cannot be made answers no.
    #[must_use]
    pub fn may(&self, descriptor: &Sd, right: Right) -> bool {
        rights::may(&self.token, descriptor, right)
    }

    /// Whether the client's process has ended, by the handle held since the connection and not by
    /// the number, which another process may have taken.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the wait fails.
    pub fn has_exited(&self) -> Result<bool> {
        // text: client_wait-2
        let waited = ffi::wait(self.process.raw(), 0, "checking the client's process")?;
        Ok(matches!(waited, ffi::Waited::Signalled(_)))
    }
}

/// Opens the process with the number the pipe gave, for the queries and the wait that the identity
/// needs and no other right.
fn hold_process(pid: u32) -> Result<Handle> {
    // SAFETY: the call takes a process number and returns a handle that is checked.
    let opened = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    // text: client_hold_process-1
    Handle::new(opened, "opening the caller's process")
}

/// When the process was created.
fn created(process: &Handle) -> Result<u64> {
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: the process is open with the right to query it; the out-parameters are local.
    let read = unsafe {
        GetProcessTimes(
            process.raw(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    };
    if read == 0 {
        // text: client_created-1
        return Err(last("reading when the caller's process was created"));
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// The account of the process's own token.
fn user_of_process(process: &Handle) -> Result<Sid> {
    let mut own: HANDLE = null_mut();
    // SAFETY: the process is open with the right to query it; the out-parameter is local.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut own) } == 0 {
        // text: client_user_of_process-1
        return Err(last("opening the caller's own token"));
    }
    // text: client_user_of_process-2
    let own = Handle::new(own, "opening the caller's own token")?;
    token::user_of(&own)
}

/// A token's information of one class, in storage that is aligned for the platform's structures.
fn information(token: &ImpersonationToken, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>> {
    let mut needed = 0_u32;
    // SAFETY: the first call only asks for the size.
    unsafe {
        GetTokenInformation(token.raw(), class, null_mut(), 0, &raw mut needed);
    }
    let mut buffer = vec![0_u64; (needed as usize).div_ceil(8).max(1)];
    // SAFETY: the buffer is the size the first call asked for and is aligned.
    let read = unsafe {
        GetTokenInformation(
            token.raw(),
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    };
    if read == 0 {
        // text: client_information-1
        return Err(last("reading a client's token"));
    }
    Ok(buffer)
}

/// What the platform says of a token that is an impersonation token: its level, whether it is
/// elevated, whether the Administrators group is enabled in it, its integrity level, and whether it
/// is restricted or belongs to an app container.
///
/// # Errors
///
/// Returns the platform's error when a fact cannot be read.
pub fn facts_of(token: &ImpersonationToken) -> Result<TokenFacts> {
    let level = information(token, TokenImpersonationLevel)?;
    let elevation = information(token, TokenElevation)?;
    let label = information(token, TokenIntegrityLevel)?;
    let container = information(token, TokenIsAppContainer)?;
    // SAFETY: each buffer holds the structure of the class that was asked for, in aligned storage.
    let (impersonation_level, elevated, app_container, integrity) = unsafe {
        let level = *level.as_ptr().cast::<i32>();
        let elevated = (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0;
        let app_container = *container.as_ptr().cast::<u32>() != 0;
        let sid = (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = u32::from(*GetSidSubAuthorityCount(sid));
        let integrity = if count == 0 {
            0
        } else {
            *GetSidSubAuthority(sid, count - 1)
        };
        (level, elevated, app_container, integrity)
    };
    let Ok(impersonation_level) = u32::try_from(impersonation_level) else {
        // text: client_facts-2
        return Err(error(0, "reading a client's impersonation level"));
    };
    // SAFETY: the token is open.
    let restricted = unsafe { IsTokenRestricted(token.raw()) } != 0;
    let administrators = Sid::parse("S-1-5-32-544")?;
    let mut member = 0;
    // SAFETY: the token is an impersonation token and the identifier is valid.
    let checked =
        unsafe { CheckTokenMembership(token.raw(), administrators.as_ptr(), &raw mut member) };
    if checked == 0 {
        // text: client_facts-1
        return Err(last("checking a client's standing"));
    }
    Ok(TokenFacts {
        impersonation_level,
        elevated,
        administrators_enabled: member != 0,
        integrity,
        restricted,
        app_container,
    })
}
