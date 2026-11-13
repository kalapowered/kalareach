//! Services, as the service manager sees them: making the broker's, starting and stopping it, and
//! the few changes the installation makes to the Application Identity service.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_MARKED_FOR_DELETE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    CreateServiceW, DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
    QueryServiceConfigW, QueryServiceStatusEx, SC_ACTION, SC_ACTION_RESTART, SC_HANDLE,
    SC_MANAGER_ALL_ACCESS, SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS,
    SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, SERVICE_CONTINUE_PENDING, SERVICE_CONTROL_STOP,
    SERVICE_DESCRIPTIONW, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_NO_CHANGE,
    SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_REQUIRED_PRIVILEGES_INFOW, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
};

use super::ffi::{Result, error, from_wide, last, wide};

/// The service manager, open with every right.
pub struct Manager(SC_HANDLE);

/// One service, open with every right.
pub struct Service(SC_HANDLE, String);

impl Drop for Manager {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value and closed once.
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

/// What the service manager says a service is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    /// The state: stopped, running, or on the way to either.
    pub state: u32,
    /// The process it runs in, or zero when it has none.
    pub pid: u32,
}

impl Status {
    /// Whether the service is running.
    #[must_use]
    pub fn running(&self) -> bool {
        self.state == SERVICE_RUNNING
    }

    /// Whether the service is stopped.
    #[must_use]
    pub fn stopped(&self) -> bool {
        self.state == SERVICE_STOPPED
    }

    /// The state as a run that stops the service reads it: stopped, on its way to running or to
    /// stopped, running, paused, on its way to either of those two, or a number that is none of
    /// the seven that the service manager defines.
    #[must_use]
    pub fn broker_state(&self) -> crate::remedy::ServiceState {
        use crate::remedy::ServiceState;
        match self.state {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING => ServiceState::Pending,
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_PAUSED => ServiceState::Paused,
            SERVICE_PAUSE_PENDING => ServiceState::PausePending,
            SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
            other => ServiceState::Unknown(other),
        }
    }
}

/// Opens the service manager.
///
/// # Errors
///
/// Returns the platform's error when the manager cannot be opened.
pub fn manager() -> Result<Manager> {
    // SAFETY: the two names are null, which means this computer's active database.
    let handle = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_ALL_ACCESS) };
    if handle.is_null() {
        Err(last("opening the service manager"))
    } else {
        Ok(Manager(handle))
    }
}

impl Manager {
    /// Opens a service by name, or says there is none.
    ///
    /// # Errors
    ///
    /// Returns the platform's error for any failure but a missing service.
    pub fn open(&self, name: &str) -> Result<Option<Service>> {
        let wide_name = wide(name);
        // SAFETY: the manager is open and the name is NUL-terminated.
        let handle = unsafe { OpenServiceW(self.0, wide_name.as_ptr(), SERVICE_ALL_ACCESS) };
        if handle.is_null() {
            let failure = last(format!("opening the service {name}"));
            if failure.code == ERROR_SERVICE_DOES_NOT_EXIST {
                Ok(None)
            } else {
                Err(failure)
            }
        } else {
            Ok(Some(Service(handle, name.to_owned())))
        }
    }

    /// Makes the broker's service: its own process, started with Windows, run as the system.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the service cannot be made.
    pub fn create(&self, name: &str, display: &str, binary: &str) -> Result<Service> {
        let wide_name = wide(name);
        let wide_display = wide(display);
        let wide_binary = wide(&format!("\"{binary}\""));
        // SAFETY: the manager is open and every string is NUL-terminated.
        let handle = unsafe {
            CreateServiceW(
                self.0,
                wide_name.as_ptr(),
                wide_display.as_ptr(),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                SERVICE_AUTO_START,
                SERVICE_ERROR_NORMAL,
                wide_binary.as_ptr(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
            )
        };
        if handle.is_null() {
            Err(last(format!("making the service {name}")))
        } else {
            Ok(Service(handle, name.to_owned()))
        }
    }
}

impl Service {
    /// Gives the service its description, a restart after a failure and the privileges it uses
    /// and no others.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when a setting is refused.
    pub fn configure(&self, description: &str, privileges: &[&str]) -> Result<()> {
        let mut text = wide(description);
        let info = SERVICE_DESCRIPTIONW {
            lpDescription: text.as_mut_ptr(),
        };
        // SAFETY: the service is open and the structure and its text outlive the call.
        unsafe {
            if ChangeServiceConfig2W(self.0, SERVICE_CONFIG_DESCRIPTION, (&raw const info).cast())
                == 0
            {
                return Err(last("describing the service"));
            }
        }
        let mut actions = [
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 5_000,
            },
            SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: 30_000,
            },
        ];
        let failure = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 86_400,
            lpRebootMsg: null_mut(),
            lpCommand: null_mut(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_mut_ptr(),
        };
        // SAFETY: the service is open and the structure and the actions outlive the call.
        unsafe {
            if ChangeServiceConfig2W(
                self.0,
                SERVICE_CONFIG_FAILURE_ACTIONS,
                (&raw const failure).cast(),
            ) == 0
            {
                return Err(last("setting what happens when the service fails"));
            }
        }
        let mut multi: Vec<u16> = Vec::new();
        for privilege in privileges {
            multi.extend(privilege.encode_utf16());
            multi.push(0);
        }
        multi.push(0);
        let required = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: multi.as_mut_ptr(),
        };
        // SAFETY: the service is open and the structure and the list outlive the call.
        unsafe {
            if ChangeServiceConfig2W(
                self.0,
                SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
                (&raw const required).cast(),
            ) == 0
            {
                return Err(last("limiting the service's privileges"));
            }
        }
        Ok(())
    }

    /// Sets who may do what to the service from an SDDL string.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the text is not a list or the list is refused.
    pub fn set_security(&self, sddl: &str) -> Result<()> {
        use windows_sys::Win32::System::Services::SetServiceObjectSecurity;
        let text = wide(sddl);
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: the text is NUL-terminated; the descriptor is an out-parameter freed below.
        unsafe {
            if ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &raw mut descriptor,
                null_mut(),
            ) == 0
            {
                return Err(last(format!("reading the permission list {sddl}")));
            }
            let set = SetServiceObjectSecurity(self.0, DACL_SECURITY_INFORMATION, descriptor);
            LocalFree(descriptor);
            if set == 0 {
                return Err(last("setting the service's permissions"));
            }
        }
        Ok(())
    }

    /// Starts the service.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the service cannot be started.
    pub fn start(&self) -> Result<()> {
        // SAFETY: the service is open; no arguments are passed.
        if unsafe { StartServiceW(self.0, 0, null()) } == 0 {
            Err(last("starting the service"))
        } else {
            Ok(())
        }
    }

    /// Asks the service to stop.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the request is refused.
    pub fn stop(&self) -> Result<()> {
        let mut status = SERVICE_STATUS {
            dwServiceType: 0,
            dwCurrentState: 0,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
        };
        // SAFETY: the service is open and the status is an out-parameter.
        if unsafe { ControlService(self.0, SERVICE_CONTROL_STOP, &raw mut status) } == 0 {
            Err(last("stopping the service"))
        } else {
            Ok(())
        }
    }

    /// Marks the service for deletion.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the service cannot be deleted.
    pub fn delete(&self) -> Result<()> {
        // SAFETY: the service is open.
        if unsafe { DeleteService(self.0) } == 0 {
            Err(last("deleting the service"))
        } else {
            Ok(())
        }
    }

    /// Whether the service has been deleted and is only still listed because some other program
    /// (a services console, a command) holds it open: the manager removes it when the last handle
    /// closes.
    ///
    /// The service manager refuses every change to such a service, so the answer comes from a
    /// change that sets nothing.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the change is refused for any other reason.
    pub fn marked_for_deletion(&self) -> Result<bool> {
        // SAFETY: the service is open; every setting is left as it is.
        let changed = unsafe {
            ChangeServiceConfigW(
                self.0,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                SERVICE_NO_CHANGE,
                null(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        };
        if changed != 0 {
            return Ok(false);
        }
        let failure = last("asking whether the service is deleted");
        if failure.code == ERROR_SERVICE_MARKED_FOR_DELETE {
            Ok(true)
        } else {
            Err(failure)
        }
    }

    /// What the service manager says the service is doing.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the status cannot be read.
    pub fn status(&self) -> Result<Status> {
        let mut process = SERVICE_STATUS_PROCESS {
            dwServiceType: 0,
            dwCurrentState: 0,
            dwControlsAccepted: 0,
            dwWin32ExitCode: 0,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: 0,
            dwProcessId: 0,
            dwServiceFlags: 0,
        };
        let mut needed = 0_u32;
        // SAFETY: the service is open; the buffer is the structure and its size is passed.
        let queried = unsafe {
            QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                (&raw mut process).cast(),
                size_of::<SERVICE_STATUS_PROCESS>() as u32,
                &raw mut needed,
            )
        };
        if queried == 0 {
            Err(last("reading the service's status"))
        } else {
            Ok(Status {
                state: process.dwCurrentState,
                pid: process.dwProcessId,
            })
        }
    }

    /// Waits for the service to reach a state, polling the manager's answer, and fails when the
    /// bound runs out. The wait ends on the service's own state.
    ///
    /// # Errors
    ///
    /// Returns an error when the state is not reached within the bound.
    pub fn wait_for(&self, stopped: bool, bound: Duration) -> Result<()> {
        let end = Instant::now() + bound;
        loop {
            let status = self.status()?;
            if (stopped && status.stopped()) || (!stopped && status.running()) {
                return Ok(());
            }
            if Instant::now() >= end {
                // text: service-1
                return Err(error(
                    0,
                    format!(
                        "the service {} is in state {}, not {}",
                        self.1,
                        status.state,
                        if stopped { "stopped" } else { "running" }
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Whether the service is on its way down.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the status cannot be read.
    pub fn stopping(&self) -> Result<bool> {
        Ok(self.status()?.state == SERVICE_STOP_PENDING)
    }

    /// Makes the service start with Windows. The service manager refuses every move of this kind
    /// back, so a start type set here is put back through the registry.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the change is refused.
    pub fn set_automatic(&self) -> Result<()> {
        // SAFETY: the service is open; every other setting is left as it is.
        let changed = unsafe {
            ChangeServiceConfigW(
                self.0,
                SERVICE_NO_CHANGE,
                SERVICE_AUTO_START,
                SERVICE_NO_CHANGE,
                null(),
                null(),
                null_mut(),
                null(),
                null(),
                null(),
                null(),
            )
        };
        if changed == 0 {
            Err(last("setting the service to start with Windows"))
        } else {
            Ok(())
        }
    }

    /// The service's start type and the program it runs.
    ///
    /// # Errors
    ///
    /// Returns the platform's error when the configuration cannot be read.
    pub fn configuration(&self) -> Result<(u32, String)> {
        let mut needed = 0_u32;
        // SAFETY: the first call only asks for the size.
        unsafe {
            QueryServiceConfigW(self.0, null_mut(), 0, &raw mut needed);
        }
        if needed == 0 {
            return Err(last("reading the service's configuration"));
        }
        let mut buffer = vec![0_u64; (needed as usize).div_ceil(8)];
        // SAFETY: the buffer is the size the first call asked for and is aligned for the structure.
        unsafe {
            if QueryServiceConfigW(
                self.0,
                buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>(),
                needed,
                &raw mut needed,
            ) == 0
            {
                return Err(last("reading the service's configuration"));
            }
            let config = &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            Ok((config.dwStartType, from_wide(config.lpBinaryPathName)))
        }
    }
}
