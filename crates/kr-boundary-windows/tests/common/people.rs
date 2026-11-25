//! The accounts and tokens the tree cases act as: an ordinary account, a boundary account with its
//! token, and a thread that does a piece of work under a token.

use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TokenImpersonation,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, SetThreadToken,
};

use kr_boundary_windows::win::client::ClientIdentity;
use kr_boundary_windows::win::ffi::{Handle, Sid};
use kr_boundary_windows::win::rights::ImpersonationToken;
use kr_boundary_windows::win::{account, broker, token};

const SYNCHRONIZE: u32 = 0x0010_0000;

/// Whether the case runs as the system, which the cases that make tokens need.
pub fn runs_as_the_system() -> bool {
    token::current_user().is_ok_and(|user| user.to_text().is_ok_and(|text| text == "S-1-5-18"))
}

/// What every case that makes a token needs: the broker's start-up and the three privileges that a
/// logon without a password and the start of a process under another token take.
pub fn prepare() {
    broker::init();
    for privilege in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        token::enable_privilege(privilege).unwrap();
    }
}

/// A throwaway account with the token of an ordinary logon, removed when it is dropped.
pub struct Person {
    pub name: String,
    pub sid: Sid,
    pub primary: Handle,
}

impl Person {
    pub fn new(prefix: &str) -> Person {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("{prefix}{}", &id[..8]);
        let sid = account::create(&name).expect("the throwaway account is made");
        let primary = token::baseline_token(&name).expect("the person's token is made");
        Person { name, sid, primary }
    }

    /// The account as a client of the broker: this process, with the account's own token.
    pub fn as_client(&self) -> ClientIdentity {
        let pid = std::process::id();
        // SAFETY: the call takes this process's own number; the result is checked.
        let process =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
        ClientIdentity {
            pid,
            process: Handle::new(process, "this process").unwrap(),
            creation_time: 0,
            user_sid: self.sid.clone(),
            token: ImpersonationToken::duplicate_of(&self.primary).unwrap(),
        }
    }
}

impl Drop for Person {
    fn drop(&mut self) {
        let _ = account::delete(&self.name);
        let _ = account::delete_profile(&self.sid);
    }
}

/// A throwaway account with the boundary token of one invocation: the account's identifier
/// deny-only, a fresh group as owner.
pub struct Boundary {
    pub name: String,
    pub sid: Sid,
    pub group: Sid,
    pub primary: Handle,
}

impl Boundary {
    pub fn new(prefix: &str) -> Boundary {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("{prefix}{}", &id[..8]);
        let sid = account::create(&name).expect("the throwaway account is made");
        let group = token::new_invocation_group();
        let primary = token::boundary_token(&name, &group).expect("the boundary token is made");
        Boundary {
            name,
            sid,
            group,
            primary,
        }
    }
}

impl Drop for Boundary {
    fn drop(&mut self) {
        let _ = account::delete(&self.name);
        let _ = account::delete_profile(&self.sid);
    }
}

/// Does the work on a thread of its own that acts as the token, or as this process when there is
/// none, and gives the work's result. A thread that acts under a token makes every file call under
/// it, so the answers are those of the platform's access check and sharing for that token.
pub fn acting_as<T: Send>(token: Option<&Handle>, work: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if let Some(primary) = token {
                    let mut copy: HANDLE = null_mut();
                    // SAFETY: the token is open and may be duplicated; the out-parameter is local
                    // and owned below.
                    let made = unsafe {
                        DuplicateTokenEx(
                            primary.raw(),
                            TOKEN_ALL_ACCESS,
                            null(),
                            SecurityImpersonation,
                            TokenImpersonation,
                            &raw mut copy,
                        )
                    };
                    assert_ne!(made, 0, "the token is copied for impersonation");
                    let copy = Handle::new(copy, "the impersonation copy").unwrap();
                    // SAFETY: a null thread means the calling thread; the token is open.
                    let set = unsafe { SetThreadToken(null(), copy.raw()) };
                    assert_ne!(set, 0, "the thread takes the token");
                    let result = work();
                    // SAFETY: a null token ends the thread's impersonation.
                    unsafe {
                        SetThreadToken(null(), null_mut());
                    }
                    result
                } else {
                    work()
                }
            })
            .join()
            .expect("the work did not panic")
    })
}
