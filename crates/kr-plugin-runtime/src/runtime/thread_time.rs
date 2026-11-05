//! The processor time the calling thread has used.
//!
//! A compile's budget is a limit on the work a component makes the host do, and work is what a
//! thread's own processor time measures. The clock does not: a compile that runs at background
//! priority on a host other work keeps busy is kept off the processor for most of the time it
//! takes, and a budget held to the clock would measure the host and not the component.
//!
//! | Platform | Where the figure comes from |
//! | --- | --- |
//! | Linux, Android and Apple | the thread's CPU-time clock, `CLOCK_THREAD_CPUTIME_ID` |
//! | Windows | the thread's kernel and user time, `GetThreadTimes` |
//! | any other | nothing: the caller holds to the clock instead |
//!
//! Every figure is of the thread that asks, so a pair of readings taken on one thread is the
//! processor time that thread used between them, whatever the process's other threads did.

use core::time::Duration;

/// Returns the processor time the calling thread has used since it started, or `None` where the
/// platform does not say.
///
/// Only the difference between two readings on one thread means anything.
#[must_use]
pub fn thread_cpu_time() -> Option<Duration> {
    #[cfg(feature = "testing")]
    if let Some(scripted) = scripted::read() {
        return scripted;
    }
    platform::thread_cpu_time()
}

#[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
mod platform {
    use core::time::Duration;

    use rustix::time::{ClockId, DynamicClockId, clock_gettime_dynamic};

    pub fn thread_cpu_time() -> Option<Duration> {
        let used = clock_gettime_dynamic(DynamicClockId::Known(ClockId::ThreadCPUTime)).ok()?;
        Some(Duration::new(
            u64::try_from(used.tv_sec).ok()?,
            u32::try_from(used.tv_nsec).ok()?,
        ))
    }
}

#[cfg(windows)]
mod platform {
    #![expect(
        unsafe_code,
        reason = "a thread's processor time has no safe interface on this platform"
    )]

    use core::time::Duration;

    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, GetThreadTimes};

    pub fn thread_cpu_time() -> Option<Duration> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: `GetCurrentThread` returns the calling thread's pseudo handle, which needs no
        // closing and always carries the right to query the thread's times. Each out parameter is
        // a live local of the type the call writes, and the call keeps none of them.
        let read = unsafe {
            GetThreadTimes(
                GetCurrentThread(),
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        };
        if read == 0 {
            return None;
        }
        // Hundreds of nanoseconds, in two halves.
        let hundreds =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        let total = hundreds(kernel).checked_add(hundreds(user))?;
        Some(Duration::from_nanos(total.checked_mul(100)?))
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    windows
)))]
mod platform {
    use core::time::Duration;

    pub const fn thread_cpu_time() -> Option<Duration> {
        None
    }
}

/// What a test makes the calling thread's processor-time clock read.
#[cfg(feature = "testing")]
mod scripted {
    use core::time::Duration;
    use std::cell::RefCell;

    type Reader = Box<dyn FnMut() -> Option<Duration>>;

    thread_local! {
        static READER: RefCell<Option<Reader>> = const { RefCell::new(None) };
    }

    pub fn read() -> Option<Option<Duration>> {
        READER.with(|slot| slot.borrow_mut().as_mut().map(|reader| reader()))
    }

    pub fn set(reader: Option<Reader>) {
        READER.with(|slot| *slot.borrow_mut() = reader);
    }
}

/// Runs `run` with the calling thread's processor-time clock answering from `reader`, one call of
/// it for each reading, and puts the platform's clock back afterwards.
///
/// For the cases that show what the compile budget does with a thread that waited for the
/// processor: no test can make a machine starve a thread, and a case that waited for the clock to
/// pass would decide by time. Only the thread that calls this is scripted. A compile that runs on
/// the compile pool's threads reads the platform's clock.
#[cfg(feature = "testing")]
pub fn with_scripted_thread_cpu_time<R>(
    reader: impl FnMut() -> Option<Duration> + 'static,
    run: impl FnOnce() -> R,
) -> R {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            scripted::set(None);
        }
    }
    scripted::set(Some(Box::new(reader)));
    let _restore = Restore;
    run()
}
