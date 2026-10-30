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
//! | Windows | the idle priority class of the process | very low I/O priority of the process, read back from the calling thread as well |
//! | macOS | the caller's own (this module sets none) | the throttled disk policy of the process |
//! | Linux | the caller's own (this module sets none) | the idle class of the calling thread, which threads it starts afterwards inherit |
//! | the remaining platforms | none | none |
//!
//! The Linux class is the idle class. A model's files are read once, at load, and a resident model
//! does no I/O after it, so the load is the only read the class touches. The idle class serves a
//! request after the requests of the other classes: the kernel's deadline scheduler (`mq-deadline`)
//! serves an idle request once it has aged past a bound, ten seconds by default, and the budget fair
//! queueing scheduler gives the idle class a bounded share. The best-effort class would give the
//! reads nothing that sets them apart from the owner's: under `mq-deadline` it has no levels, so
//! even its lowest level is the same as the owner's. A load that a busy disk delays past its
//! deadline ends as a load that did not finish, and the session then shows the delayed or stale
//! description that section 22 already gives when demand exceeds capacity. The cost falls on that
//! description and not on the terminal.
//!
//! Windows has a background mode for a process (`PROCESS_MODE_BACKGROUND_BEGIN`) that lowers the
//! CPU, I/O and memory priority together, and this module does not use it: on Windows Server 2025
//! (build 26100) a process that begins it and then writes 600 MB keeps a working set of 32 MB with
//! 683 MB committed, where the same process with only the idle class, only the I/O priority or only
//! the lowest memory priority keeps 694 MB. A model that must stay resident would fault its weights
//! back in on every token, and the process's resident set would read as 32 MB to anything that
//! measures it. The idle priority class and the very low I/O priority are set on their own and
//! leave the working set alone.
//!
//! The system applies an I/O class only through the I/O scheduler that serves the disk. Under the
//! `none` scheduler of most NVMe disks no I/O class has an effect: the class is kept and acts on
//! nothing, so only the processor class lowers the model's share there, and the read-back says what
//! the system holds and not that a disk obeys it.

/// An I/O class, by what the system reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoClass {
    /// Linux: the idle class.
    Idle,
    /// macOS: the throttled disk policy.
    Throttled,
    /// Windows: the very low I/O priority.
    VeryLow,
}

/// Why a class was not applied.
pub type Refusal = &'static str;

/// Lowers the I/O class of the calling thread on Linux, where a thread starts the threads that
/// read the model, and of the calling process on macOS and Windows, where the class is the
/// process's. Windows also keeps an I/O priority for each thread, and a thread that was already
/// running reads the process's value once it is lowered, so the read-back is taken from the calling
/// thread as well.
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

/// Reads the I/O class the system holds for the calling thread on Linux, for the calling process
/// on macOS, and on Windows for the calling process and the calling thread together, which have the
/// class only when both read it, when it is one this module sets.
#[must_use]
pub fn io_class() -> Option<IoClass> {
    platform::io_class()
}

/// Puts the calling process into the idle priority class, and reads the class back.
///
/// The class is the process's, so every thread of the process runs in it, those the process starts
/// later included.
///
/// # Errors
///
/// Returns why the class was not applied.
#[cfg(windows)]
pub fn lower_priority_class() -> std::result::Result<(), Refusal> {
    platform::lower_priority_class()
}

/// What the system reports of a process's priority class and I/O class.
#[cfg(all(windows, any(test, feature = "testing")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessClass {
    /// Whether the process's priority class is the idle class.
    pub idle_priority_class: bool,
    /// The process's I/O class, when it is one this module names.
    pub io: Option<IoClass>,
}

/// Reads the priority class and the I/O class the system holds for the calling process.
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn process_class() -> Option<ProcessClass> {
    platform::process_class()
}

/// Reads the priority class and the I/O class the system holds for the process `pid`, which a
/// parent uses to check what its child reports of itself.
///
/// Nothing when the process is not there or the system will not tell.
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn process_class_of(pid: u32) -> Option<ProcessClass> {
    platform::process_class_of(pid)
}

/// Reads the I/O class the system holds for the calling thread alone, when it is one this module
/// names.
#[cfg(all(windows, any(test, feature = "testing")))]
#[must_use]
pub fn thread_io_class() -> Option<IoClass> {
    platform::thread_io_priority().and_then(platform::io_class_named)
}

/// Sets the I/O priority of the calling thread alone to the normal one, whatever the process's is,
/// which is how a test shows that the thread's own value is read apart from the process's.
///
/// # Errors
///
/// Returns why the system refused.
#[cfg(all(windows, any(test, feature = "testing")))]
pub fn set_thread_io_class_normal() -> std::result::Result<(), Refusal> {
    platform::set_thread_io_priority(platform::IO_NORMAL)
        .map_err(|()| "this host refused the normal I/O priority for the thread")
}

/// The classes a test found its process or thread in, so that it can leave them as it found them.
#[cfg(any(test, feature = "testing"))]
#[derive(Debug)]
pub struct Saved(platform::Saved);

/// Notes the classes this module sets, as the calling thread (Linux) or process (macOS and Windows)
/// has them now.
#[cfg(any(test, feature = "testing"))]
#[must_use]
pub fn save() -> Saved {
    Saved(platform::save())
}

#[cfg(any(test, feature = "testing"))]
impl Saved {
    /// Puts back the classes that were noted.
    ///
    /// # Errors
    ///
    /// Returns why the system refused.
    pub fn restore(self) -> std::result::Result<(), Refusal> {
        platform::restore(self.0)
    }
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
    /// `IOPRIO_CLASS_IDLE`, the idle class.
    const CLASS_IDLE: libc::c_int = 3;
    /// The shift of the class in the value the system takes.
    const CLASS_SHIFT: libc::c_int = 13;

    /// The value the system takes for the idle class, which has no level.
    const IDLE: libc::c_int = CLASS_IDLE << CLASS_SHIFT;

    pub(super) fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        // SAFETY: the call takes three integers and changes the I/O priority of the calling
        // thread; it reads no memory of this process.
        let set = unsafe { libc::syscall(libc::SYS_ioprio_set, WHO_PROCESS, 0, IDLE) };
        if set != 0 {
            return Err("this host refused the idle I/O class");
        }
        io_class().ok_or("this host did not report the I/O class it was given")
    }

    pub(super) fn io_class() -> Option<IoClass> {
        (raw() == libc::c_long::from(IDLE)).then_some(IoClass::Idle)
    }

    /// The I/O priority of the calling thread as the system numbers it, or -1.
    fn raw() -> libc::c_long {
        // SAFETY: the call takes two integers and reads the I/O priority of the calling thread; it
        // reads no memory of this process.
        unsafe { libc::syscall(libc::SYS_ioprio_get, WHO_PROCESS, 0) }
    }

    /// The I/O priority of the calling thread when it was noted.
    #[cfg(any(test, feature = "testing"))]
    #[derive(Debug)]
    pub(super) struct Saved(libc::c_long);

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn save() -> Saved {
        Saved(raw())
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn restore(saved: Saved) -> std::result::Result<(), Refusal> {
        // SAFETY: the call takes three integers and changes the I/O priority of the calling
        // thread; it reads no memory of this process.
        let set = unsafe { libc::syscall(libc::SYS_ioprio_set, WHO_PROCESS, 0, saved.0) };
        if set == 0 {
            Ok(())
        } else {
            Err("this host refused to put the I/O level back")
        }
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

    /// The disk policy of the calling process when it was noted.
    #[cfg(any(test, feature = "testing"))]
    #[derive(Debug)]
    pub(super) struct Saved(libc::c_int);

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn save() -> Saved {
        Saved(policy())
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn restore(saved: Saved) -> std::result::Result<(), Refusal> {
        // SAFETY: the call takes three integers and changes the disk I/O policy of the calling
        // process; it reads no memory of this process.
        let set = unsafe { setiopolicy_np(TYPE_DISK, SCOPE_PROCESS, saved.0) };
        if set == 0 {
            Ok(())
        } else {
            Err("this host refused to put the disk policy back")
        }
    }
}

#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "the priority class and I/O priority of a process have no safe interface"
    )]

    use super::{IoClass, Refusal};
    #[cfg(any(test, feature = "testing"))]
    use windows_sys::Wdk::System::Threading::NtSetInformationThread;
    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationProcess, NtQueryInformationThread, ProcessIoPriority, ThreadIoPriority,
    };
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetPriorityClass, IDLE_PRIORITY_CLASS,
        SetPriorityClass,
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

    /// The I/O priority a thread has when nothing has asked it to stay out of the way.
    #[cfg(any(test, feature = "testing"))]
    pub(super) const IO_NORMAL: u32 = 2;

    /// Lowers the I/O priority of the calling process, and reads it back from the process and from
    /// the calling thread. On the Windows build this was tried on (Windows Server 2025, build
    /// 26100) a thread reads the process's value for itself once it is set; the read-back does not
    /// rely on that, and counts the class as applied only when both read very low.
    pub(super) fn lower_io_class() -> std::result::Result<IoClass, Refusal> {
        set_io_priority(IO_VERY_LOW).map_err(|()| "this host refused the very low I/O priority")?;
        io_class().ok_or("this host did not report the I/O priority it was given")
    }

    /// The class the calling thread has only when the thread and the process both hold it, because
    /// either one left at the normal priority is a path the weights can be read by.
    pub(super) fn io_class() -> Option<IoClass> {
        // SAFETY: the call takes no argument and returns the pseudo-handle of the calling process,
        // which needs no closing.
        let process = io_priority_of(unsafe { GetCurrentProcess() })?;
        let thread = thread_io_priority()?;
        (process == IO_VERY_LOW && thread == IO_VERY_LOW).then_some(IoClass::VeryLow)
    }

    /// The class this module names for an I/O priority the system reported.
    #[cfg(any(test, feature = "testing"))]
    pub(super) fn io_class_named(io: u32) -> Option<IoClass> {
        (io == IO_VERY_LOW).then_some(IoClass::VeryLow)
    }

    /// Reads the I/O priority of the calling thread.
    pub(super) fn thread_io_priority() -> Option<u32> {
        let mut io = 0_u32;
        // SAFETY: the call takes the pseudo-handle of the calling thread, which needs no closing,
        // and writes one 32-bit value through a pointer to a live local of that size.
        let queried = unsafe {
            NtQueryInformationThread(
                GetCurrentThread(),
                ThreadIoPriority,
                (&raw mut io).cast(),
                4,
                std::ptr::null_mut(),
            )
        };
        (queried >= 0).then_some(io)
    }

    /// Sets the I/O priority of the calling thread.
    #[cfg(any(test, feature = "testing"))]
    pub(super) fn set_thread_io_priority(priority: u32) -> std::result::Result<(), ()> {
        // SAFETY: the call takes the pseudo-handle of the calling thread, which needs no closing,
        // and reads one 32-bit value through a pointer to a live local of that size.
        let status = unsafe {
            NtSetInformationThread(
                GetCurrentThread(),
                ThreadIoPriority,
                (&raw const priority).cast(),
                4,
            )
        };
        if status < 0 { Err(()) } else { Ok(()) }
    }

    pub(super) fn lower_priority_class() -> std::result::Result<(), Refusal> {
        // SAFETY: the call takes the pseudo-handle of the calling process and a class, and reads
        // no memory of this process.
        let set = unsafe { SetPriorityClass(GetCurrentProcess(), IDLE_PRIORITY_CLASS) };
        if set == 0 {
            return Err("this host refused the idle priority class");
        }
        // SAFETY: the call takes the pseudo-handle of the calling process and reads no memory of
        // this process.
        if unsafe { GetPriorityClass(GetCurrentProcess()) } == IDLE_PRIORITY_CLASS {
            Ok(())
        } else {
            Err("this host reports a priority class that is not the idle class")
        }
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

    /// Reads the I/O priority of the process a handle names, which needs query access.
    fn io_priority_of(process: HANDLE) -> Option<u32> {
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
        (queried >= 0).then_some(io)
    }

    #[cfg(any(test, feature = "testing"))]
    use super::ProcessClass;

    #[cfg(any(test, feature = "testing"))]
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

    #[cfg(any(test, feature = "testing"))]
    fn class_of(process: HANDLE) -> Option<ProcessClass> {
        // SAFETY: the call takes a handle and reads no memory of this process.
        let priority_class = unsafe { GetPriorityClass(process) };
        let io = io_priority_of(process)?;
        Some(ProcessClass {
            idle_priority_class: priority_class == IDLE_PRIORITY_CLASS,
            io: (io == IO_VERY_LOW).then_some(IoClass::VeryLow),
        })
    }

    /// The priority class and the I/O priority of the calling process when they were noted.
    #[cfg(any(test, feature = "testing"))]
    #[derive(Debug)]
    pub(super) struct Saved {
        priority_class: u32,
        io_priority: Option<u32>,
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn save() -> Saved {
        // SAFETY: the call takes no argument and returns the pseudo-handle of the calling process,
        // which needs no closing.
        let process = unsafe { GetCurrentProcess() };
        // SAFETY: the call takes a handle and reads no memory of this process.
        let priority_class = unsafe { GetPriorityClass(process) };
        Saved {
            priority_class,
            io_priority: io_priority_of(process),
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) fn restore(saved: Saved) -> std::result::Result<(), Refusal> {
        if let Some(io) = saved.io_priority {
            set_io_priority(io).map_err(|()| "this host refused to put the I/O priority back")?;
        }
        // SAFETY: the call takes the pseudo-handle of the calling process and a class, and reads
        // no memory of this process.
        let restored = unsafe { SetPriorityClass(GetCurrentProcess(), saved.priority_class) };
        if restored == 0 {
            return Err("this host refused to put the priority class back");
        }
        Ok(())
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

    #[cfg(any(test, feature = "testing"))]
    #[derive(Debug)]
    pub(super) struct Saved;

    #[cfg(any(test, feature = "testing"))]
    pub(super) const fn save() -> Saved {
        Saved
    }

    #[cfg(any(test, feature = "testing"))]
    pub(super) const fn restore(_saved: Saved) -> std::result::Result<(), Refusal> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{IoClass, io_class, lower_io_class, save};

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

        let lowered = std::thread::spawn(|| {
            let saved = save();
            let lowered = (lower_io_class(), io_class());
            assert_eq!(saved.restore(), Ok(()));
            (lowered, io_class())
        })
        .join()
        .expect("the thread ends");
        assert_eq!(lowered.0.0, Ok(IoClass::Idle));
        assert_eq!(lowered.0.1, Some(IoClass::Idle));
        assert_eq!(lowered.1, None, "and the class is put back");

        // A thread started by a thread that lowered its class has the class it was started with.
        let inherited = std::thread::spawn(|| {
            lower_io_class().expect("the class is lowered");
            std::thread::spawn(io_class)
                .join()
                .expect("the thread ends")
        })
        .join()
        .expect("the thread ends");
        assert_eq!(inherited, Some(IoClass::Idle));
    }

    /// The process's own disk policy is set and read back, and put back as it was found, so the
    /// tests that run beside this one in the same process are not throttled by it.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_disk_policy_of_this_process_is_set_read_back_and_put_back() {
        assert_eq!(
            io_class(),
            None,
            "the policy at the start is not the throttled one"
        );
        let saved = save();

        let lowered = lower_io_class();
        let held = io_class();
        assert_eq!(saved.restore(), Ok(()), "the policy is put back");

        assert_eq!(lowered, Ok(IoClass::Throttled));
        assert_eq!(held, Some(IoClass::Throttled));
        assert_eq!(io_class(), None, "and the read-back follows it back");
    }

    /// The tests that change this process's class take turns, since the class is the process's and
    /// each starts from the class the process was found in.
    #[cfg(windows)]
    static CLASS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The process enters the background class, and the system reports the idle priority class and
    /// the very low I/O priority, both to the process itself and to a handle opened on it by its
    /// identifier. The process is put back as it was found, so the tests that run beside this one
    /// are not left in the class.
    #[cfg(windows)]
    #[test]
    fn the_background_class_of_this_process_is_set_read_back_and_left() {
        use super::{
            IoClass, ProcessClass, lower_io_class, lower_priority_class, process_class,
            process_class_of, save,
        };

        let _turn = CLASS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = process_class().expect("the class this process started with is readable");
        assert!(!before.idle_priority_class);
        assert_eq!(before.io, None);
        let saved = save();

        let priority = lower_priority_class();
        let io = lower_io_class();
        let seen_from_outside = process_class_of(std::process::id());
        let left = saved.restore();

        let in_the_class = ProcessClass {
            idle_priority_class: true,
            io: Some(IoClass::VeryLow),
        };
        assert_eq!(priority, Ok(()));
        assert_eq!(io, Ok(IoClass::VeryLow));
        assert_eq!(seen_from_outside, Some(in_the_class));
        assert_eq!(left, Ok(()));
        assert_eq!(process_class(), Some(before), "and the class is left");
    }

    /// The class is read from the thread that asks, and the thread that loads the model exists
    /// before the process's class is lowered. On the Windows build this was tried on (Windows
    /// Server 2025, build 26100), a thread that was already running when the process's class was
    /// lowered reads the lowered value for itself, so the read-back taken on that thread says the
    /// process's. The class is put back for the thread as well as the process.
    #[cfg(windows)]
    #[test]
    fn the_io_class_a_windows_thread_reads_is_its_own_and_follows_the_process() {
        use super::{IoClass, io_class, lower_io_class, save, thread_io_class};
        use std::sync::mpsc::channel;

        let _turn = CLASS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (running, hears_running) = channel();
        let (go, goes) = channel::<()>();
        let bystander = std::thread::spawn(move || {
            let before = (io_class(), thread_io_class());
            running.send(()).expect("the test listens");
            goes.recv().expect("the test goes on");
            (before, io_class(), thread_io_class())
        });
        hears_running.recv().expect("the thread is running");

        let (lowered, hears_lowered) = channel();
        let (read, reads) = channel::<()>();
        let lowering = std::thread::spawn(move || {
            let saved = save();
            let while_lowered = (lower_io_class(), io_class(), thread_io_class());
            lowered.send(()).expect("the test listens");
            reads.recv().expect("the test goes on");
            let put_back = saved.restore();
            (while_lowered, put_back, io_class(), thread_io_class())
        });
        hears_lowered.recv().expect("the thread lowered its class");
        go.send(()).expect("the other thread waits");
        let (bystander_before, bystander_class, bystander_thread) =
            bystander.join().expect("the thread ends");
        read.send(()).expect("the lowering thread waits");
        let (while_lowered, put_back, class_after, thread_after) =
            lowering.join().expect("the thread ends");

        assert_eq!(
            bystander_before,
            (None, None),
            "a thread before the class is lowered"
        );
        assert_eq!(while_lowered.0, Ok(IoClass::VeryLow));
        assert_eq!(while_lowered.1, Some(IoClass::VeryLow));
        assert_eq!(while_lowered.2, Some(IoClass::VeryLow));
        assert_eq!(
            bystander_thread,
            Some(IoClass::VeryLow),
            "a thread that was running when the class was lowered"
        );
        assert_eq!(bystander_class, Some(IoClass::VeryLow));
        assert_eq!(put_back, Ok(()));
        assert_eq!(class_after, None, "and the class is put back");
        assert_eq!(thread_after, None, "for the thread as well");
    }

    /// The thread's own value is part of the class apart from the process's: with the process's
    /// I/O priority lowered and the calling thread's set back to normal, the process reads very low
    /// and the thread reads normal, and the class is not applied to the thread that loads the
    /// model, because either one left at the normal priority is a path the weights can be read by.
    #[cfg(windows)]
    #[test]
    fn a_thread_set_back_to_normal_is_not_in_the_class_though_its_process_is() {
        use super::{
            IoClass, io_class, lower_io_class, process_class, save, set_thread_io_class_normal,
            thread_io_class,
        };

        let _turn = CLASS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let thread = std::thread::spawn(|| {
            let saved = save();
            let lowered = lower_io_class();
            let set_back = set_thread_io_class_normal();
            let seen = (
                process_class().and_then(|class| class.io),
                thread_io_class(),
                io_class(),
            );
            (lowered, set_back, seen, saved.restore())
        });
        let (lowered, set_back, seen, put_back) = thread.join().expect("the thread ends");

        assert_eq!(lowered, Ok(IoClass::VeryLow));
        assert_eq!(set_back, Ok(()));
        assert_eq!(
            seen.0,
            Some(IoClass::VeryLow),
            "the process is still lowered"
        );
        assert_eq!(seen.1, None, "the thread's own value is normal");
        assert_eq!(seen.2, None, "so the class is not applied to the thread");
        assert_eq!(put_back, Ok(()));
    }
}
