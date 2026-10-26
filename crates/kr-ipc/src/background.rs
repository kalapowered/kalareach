//! The background class of a process or a thread for the work that can wait, set and then read
//! back from the system.
//!
//! A class that was asked for and a class the system holds are different facts: a call can succeed
//! and leave the class unchanged, a later call can undo it, and a platform can quietly ignore the
//! request. So every function here that sets a class reads it back from the system before it says
//! what it did, and it names the class the system reported.
//!
//! # What each platform gives
//!
//! | Platform | CPU | I/O |
//! | --- | --- | --- |
//! | Windows | the idle priority class of the process | very low I/O priority of the process |
//! | macOS | the caller's own (this module sets none) | the throttled disk policy of the process |
//! | Linux | the caller's own (this module sets none) | the lowest best-effort level of the calling thread, which threads it starts afterwards inherit |
//! | the remaining platforms | none | none |
//!
//! The Linux class is the lowest level of the best-effort class and not the idle class. The idle
//! class is served only when nothing else wants the disk, and a model's files are read once, at
//! load, under a deadline; a busy disk would hold that read for as long as it stayed busy. The
//! lowest best-effort level still yields to every other process on a scheduler that honours
//! priorities, and it cannot be starved by one.
//!
//! Windows has a background mode for a process (`PROCESS_MODE_BACKGROUND_BEGIN`) that lowers the
//! CPU, I/O and memory priority together, and this module does not use it: on Windows Server 2025
//! it holds the process's working set to about 32 MB however much memory the process writes, which
//! leaves a model that must stay resident to fault its weights back in on every token, and makes
//! the process's resident set read as 32 MB to anything that measures it. The idle priority class
//! and the very low I/O priority are set on their own and leave the working set alone.
//!
//! The system applies an I/O class only through the I/O scheduler that serves the disk. A scheduler
//! that ignores priorities (the `none` scheduler of most NVMe disks) keeps the class and acts on
//! nothing, so the read-back says what the system holds and not that a disk obeys it.

/// An I/O class, by what the system reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoClass {
    /// Linux: the best-effort class at its lowest level.
    BestEffortLowest,
    /// macOS: the throttled disk policy.
    Throttled,
    /// Windows: the very low I/O priority.
    VeryLow,
}

impl IoClass {
    /// Returns the stable name this class is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BestEffortLowest => "best_effort_lowest",
            Self::Throttled => "throttled",
            Self::VeryLow => "very_low",
        }
    }
}

/// Why a class was not applied.
pub type Refusal = &'static str;

/// Lowers the I/O class of the calling thread on Linux, where a thread starts the threads that
/// read the model, and of the calling process on macOS, where the policy is the process's.
///
/// Returns the class the system reports once it was set. A system that refuses the call, or that
/// reports something else afterwards, is a refusal.
///
/// # Errors
///
/// Returns why nothing was applied.
pub fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
    platform::lower_io_class()
}

/// Reads the I/O class the system holds for the calling thread on Linux and for the calling
/// process on macOS and Windows, when it is one this module sets.
#[must_use]
pub fn io_class() -> Option<IoClass> {
    platform::io_class()
}

/// What the system reports of a process that entered the background class.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessClass {
    /// Whether the process's priority class is the idle class.
    pub idle_priority_class: bool,
    /// The process's I/O class, when it is one this module names.
    pub io: Option<IoClass>,
}

/// Puts the calling process into the background class: the idle priority class and the very low
/// I/O priority, each read back from the system.
///
/// The process stays in the class until it ends or calls [`leave_process_background`].
///
/// # Errors
///
/// Returns why nothing was applied, or what the system reported instead.
#[cfg(windows)]
pub fn enter_process_background() -> std::result::Result<ProcessClass, Refusal> {
    platform::enter_process_background()
}

/// Reads the priority class and the I/O class the system holds for the calling process.
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn process_class() -> Option<ProcessClass> {
    platform::process_class()
}

/// Reads the priority class and the I/O class the system holds for the process `pid`, which a parent uses to check what its child reports of itself.
///
/// Nothing when the process is not there or the system will not tell.
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn process_class_of(pid: u32) -> Option<ProcessClass> {
    platform::process_class_of(pid)
}

/// Takes the calling process out of the background class and back to the priority class it had
/// before [`enter_process_background`] and the normal I/O priority, which a test uses to leave its
/// own process as it found it.
///
/// # Errors
///
/// Returns why the system refused.
#[cfg(all(windows, any(test, feature = "testing")))]
pub fn leave_process_background(priority_class: u32) -> std::result::Result<(), Refusal> {
    platform::leave_process_background(priority_class)
}

/// Reads the priority class number of the calling process, for [`leave_process_background`].
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn priority_class_number() -> u32 {
    platform::priority_class_number()
}

#[cfg(target_os = "linux")]
mod platform {
    #![expect(
        unsafe_code,
        reason = "the I/O priority of a thread has no safe interface"
    )]

    use super::{IoClass, Refusal};

    /// `IOPRIO_WHO_PROCESS`: the target is a thread, and zero is the calling thread.
    const WHO_PROCESS: libc::c_int = 1;
    /// `IOPRIO_CLASS_BE`, the best-effort class.
    const CLASS_BEST_EFFORT: libc::c_int = 2;
    /// The shift of the class in the value the system takes.
    const CLASS_SHIFT: libc::c_int = 13;
    /// The lowest level a best-effort thread can have.
    const LOWEST_LEVEL: libc::c_int = 7;

    const LOWEST: libc::c_int = (CLASS_BEST_EFFORT << CLASS_SHIFT) | LOWEST_LEVEL;

    pub(super) fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        // SAFETY: the call takes three integers and changes the I/O priority of the calling
        // thread; it reads no memory of this process.
        let set = unsafe { libc::syscall(libc::SYS_ioprio_set, WHO_PROCESS, 0, LOWEST) };
        if set != 0 {
            return Err("this host refused the lowest best-effort I/O level");
        }
        io_class().ok_or("this host did not report the I/O level it was given")
    }

    pub(super) fn io_class() -> Option<IoClass> {
        // SAFETY: the call takes two integers and reads the I/O priority of the calling thread; it
        // reads no memory of this process.
        let held = unsafe { libc::syscall(libc::SYS_ioprio_get, WHO_PROCESS, 0) };
        (held == libc::c_long::from(LOWEST)).then_some(IoClass::BestEffortLowest)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    #![expect(
        unsafe_code,
        reason = "the I/O policy of a process has no safe interface"
    )]

    use super::{IoClass, Refusal};

    /// `IOPOL_TYPE_DISK`: the policy for disk I/O.
    const TYPE_DISK: libc::c_int = 0;
    /// `IOPOL_SCOPE_PROCESS`: the policy of the whole process.
    const SCOPE_PROCESS: libc::c_int = 0;
    /// `IOPOL_THROTTLE`: disk I/O is throttled when it contends with other I/O.
    const THROTTLE: libc::c_int = 3;

    unsafe extern "C" {
        /// `setiopolicy_np(2)`.
        fn setiopolicy_np(
            iotype: libc::c_int,
            scope: libc::c_int,
            policy: libc::c_int,
        ) -> libc::c_int;
        /// `getiopolicy_np(2)`: the policy, or -1.
        fn getiopolicy_np(iotype: libc::c_int, scope: libc::c_int) -> libc::c_int;
    }

    pub(super) fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        // SAFETY: the call takes three integers and changes the disk I/O policy of the calling
        // process; it reads no memory of this process.
        let set = unsafe { setiopolicy_np(TYPE_DISK, SCOPE_PROCESS, THROTTLE) };
        if set != 0 {
            return Err("this host refused the throttled disk policy");
        }
        io_class().ok_or("this host did not report the disk policy it was given")
    }

    pub(super) fn io_class() -> Option<IoClass> {
        (policy() == THROTTLE).then_some(IoClass::Throttled)
    }

    /// The disk policy of the calling process, or -1.
    pub(super) fn policy() -> libc::c_int {
        // SAFETY: the call takes two integers and reads the disk I/O policy of the calling
        // process; it reads no memory of this process.
        unsafe { getiopolicy_np(TYPE_DISK, SCOPE_PROCESS) }
    }

    /// Puts the disk policy of the calling process back to `policy`, which a test uses to leave
    /// its own process as it found it.
    #[cfg(test)]
    pub(super) fn set_policy(policy: libc::c_int) -> bool {
        // SAFETY: the call takes three integers and changes the disk I/O policy of the calling
        // process; it reads no memory of this process.
        unsafe { setiopolicy_np(TYPE_DISK, SCOPE_PROCESS, policy) == 0 }
    }
}

#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "the priority class and I/O priority of a process have no safe interface"
    )]

    use super::{IoClass, ProcessClass, Refusal};
    use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessIoPriority};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetPriorityClass, IDLE_PRIORITY_CLASS, SetPriorityClass,
    };

    #[link(name = "ntdll")]
    unsafe extern "system" {
        /// `NtSetInformationProcess`, which the bindings this crate uses do not declare.
        fn NtSetInformationProcess(
            process: HANDLE,
            class: i32,
            information: *mut std::ffi::c_void,
            length: u32,
        ) -> i32;
    }

    /// The I/O priority of a process that has been asked to stay out of the way.
    const IO_VERY_LOW: u32 = 0;
    /// The I/O priority of an ordinary process.
    #[cfg(any(test, feature = "testing"))]
    const IO_NORMAL: u32 = 2;

    pub(super) fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        Err("on this platform the I/O class is the whole process's, set with its priority class")
    }

    pub(super) fn io_class() -> Option<IoClass> {
        process_class().and_then(|class| class.io)
    }

    pub(super) fn enter_process_background() -> std::result::Result<ProcessClass, Refusal> {
        // SAFETY: the call takes the pseudo-handle of the calling process and a class, and reads
        // no memory of this process.
        let idle = unsafe { SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS) };
        if idle == 0 {
            return Err("this host refused the idle priority class");
        }
        set_io_priority(IO_VERY_LOW).map_err(|()| "this host refused the very low I/O priority")?;
        let class = process_class().ok_or("this host did not report the class it was given")?;
        if !class.idle_priority_class {
            return Err("this host reports a priority class that is not the idle class");
        }
        if class.io != Some(IoClass::VeryLow) {
            return Err("this host reports an I/O priority that is not the very low one");
        }
        Ok(class)
    }

    /// Sets the I/O priority of the calling process.
    fn set_io_priority(priority: u32) -> std::result::Result<(), ()> {
        let mut priority = priority;
        // SAFETY: the call reads one 32-bit value through a pointer to a live local of that size.
        let status = unsafe {
            NtSetInformationProcess(
                GetCurrentProcess(),
                ProcessIoPriority,
                (&raw mut priority).cast(),
                4,
            )
        };
        if status < 0 { Err(()) } else { Ok(()) }
    }

    pub(super) fn process_class() -> Option<ProcessClass> {
        // SAFETY: the call takes no argument and returns the pseudo-handle of the calling process,
        // which needs no closing.
        class_of(unsafe { GetCurrentProcess() })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn process_class_of(pid: u32) -> Option<ProcessClass> {
        // SAFETY: the call takes a process identifier and an access mask and returns a handle or
        // null; it reads no memory of this process.
        let handle = unsafe {
            windows_sys::Win32::System::Threading::OpenProcess(
                windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return None;
        }
        let class = class_of(handle);
        // SAFETY: the handle was opened above and is closed once, here.
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(handle);
        }
        class
    }

    /// Reads the class of the process a handle names, which needs query access.
    fn class_of(process: HANDLE) -> Option<ProcessClass> {
        // SAFETY: the call takes a handle and reads no memory of this process.
        let priority_class = unsafe { GetPriorityClass(process) };
        let mut io = 0_u32;
        // SAFETY: the call writes one 32-bit value through a pointer to a live local of that size.
        let queried = unsafe {
            NtQueryInformationProcess(
                process,
                ProcessIoPriority,
                (&raw mut io).cast(),
                4,
                std::ptr::null_mut(),
            )
        };
        if queried < 0 {
            return None;
        }
        Some(ProcessClass {
            idle_priority_class: priority_class == IDLE_PRIORITY_CLASS,
            io: (io == IO_VERY_LOW).then_some(IoClass::VeryLow),
        })
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn leave_process_background(
        priority_class: u32,
    ) -> std::result::Result<(), Refusal> {
        set_io_priority(IO_NORMAL).map_err(|()| "this host refused the normal I/O priority")?;
        // SAFETY: the call takes the pseudo-handle of the calling process and a class, and reads
        // no memory of this process.
        let restored = unsafe { SetPriorityClass(GetCurrentProcess(), priority_class) };
        if restored == 0 {
            return Err("this host refused to restore the priority class");
        }
        Ok(())
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn priority_class_number() -> u32 {
        // SAFETY: the call takes the pseudo-handle of the calling process and reads no memory of
        // this process.
        unsafe { GetPriorityClass(GetCurrentProcess()) }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::{IoClass, Refusal};

    pub(super) const fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        Err("this platform gives no I/O class this build sets")
    }

    pub(super) const fn io_class() -> Option<IoClass> {
        None
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{IoClass, io_class, lower_io_class};

    /// A thread that lowers its I/O class finds the system holding it, and a thread that did not
    /// is still at the class it started with: the class is the calling thread's on Linux, so the
    /// check runs on threads of its own.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_io_class_of_a_thread_that_lowered_it_is_read_back_and_another_threads_is_not() {
        let untouched = std::thread::spawn(io_class)
            .join()
            .expect("the thread ends");
        assert_eq!(untouched, None, "a thread that lowered nothing");

        let lowered = std::thread::spawn(|| (lower_io_class(), io_class()))
            .join()
            .expect("the thread ends");
        assert_eq!(lowered.0, Ok(IoClass::BestEffortLowest));
        assert_eq!(lowered.1, Some(IoClass::BestEffortLowest));

        // A thread started by a thread that lowered its class has the class it was started with.
        let inherited = std::thread::spawn(|| {
            lower_io_class().expect("the class is lowered");
            std::thread::spawn(io_class)
                .join()
                .expect("the thread ends")
        })
        .join()
        .expect("the thread ends");
        assert_eq!(inherited, Some(IoClass::BestEffortLowest));
    }

    /// The process's own disk policy is set and read back, and put back as it was found, so the
    /// tests that run beside this one in the same process are not throttled by it.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_disk_policy_of_this_process_is_set_read_back_and_put_back() {
        use super::platform::{policy, set_policy};

        let before = policy();
        assert!(
            before >= 0,
            "the policy this process started with is readable"
        );
        assert_eq!(
            io_class(),
            None,
            "the policy at the start is not the throttled one"
        );

        let lowered = lower_io_class();
        let held = io_class();
        assert!(set_policy(before), "the policy is put back");

        assert_eq!(lowered, Ok(IoClass::Throttled));
        assert_eq!(held, Some(IoClass::Throttled));
        assert_eq!(io_class(), None, "and the read-back follows it back");
    }

    /// The process enters the background class, and the system reports the idle priority class,
    /// the very low I/O priority, both to the process itself and to
    /// a handle opened on it by its identifier. The process is put back as it was found, so the
    /// tests that run beside this one are not left in the class.
    #[cfg(windows)]
    #[test]
    fn the_background_class_of_this_process_is_set_read_back_and_left() {
        use super::{
            IoClass, ProcessClass, enter_process_background, leave_process_background,
            priority_class_number, process_class, process_class_of,
        };

        let before = process_class().expect("the class this process started with is readable");
        assert!(!before.idle_priority_class);
        assert_eq!(before.io, None);
        let number = priority_class_number();

        let entered = enter_process_background();
        let seen_from_outside = process_class_of(std::process::id());
        let left = leave_process_background(number);

        let in_the_class = ProcessClass {
            idle_priority_class: true,
            io: Some(IoClass::VeryLow),
        };
        assert_eq!(entered, Ok(in_the_class));
        assert_eq!(seen_from_outside, Some(in_the_class));
        assert_eq!(left, Ok(()));
        assert_eq!(process_class(), Some(before), "and the class is left");
    }
}
