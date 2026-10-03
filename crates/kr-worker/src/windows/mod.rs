//! What only Windows has: the pseudo-console this worker owns, the job object that holds
//! everything it starts, and the console interrupt it delivers.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`conpty`] | The pseudo-console, its two pipes, the shell inside it and the reader that drains it |
//! | [`job`] | The per-session job object: kill-on-close, breakaway disabled, and the processes it holds |
//! | [`lineage`] | Which process started a process and when, on the kernel's interrupt clock |
//! | [`launch`] | Starting an agent in its jobs with only the handles it is given |
//!
//! Section 7 puts the three together. The worker holds the sole owning handle for a per-session
//! job object with kill-on-close; every process it starts joins that job **before** it runs, which
//! is why the shell is created suspended and resumed only once it is inside; default breakaway
//! stays disabled, so a child cannot leave by asking; and a GUI resource that has to outlive the
//! session is created through the desktop broker, outside the job, and recorded as an external
//! resource rather than killed.
//!
//! What this platform does not have is a foreground process group, so there is nothing to signal.
//! The console's own interrupt is a byte written into the pseudo-console's input, which the
//! console host turns into a control event for whatever is attached to it: see
//! [`conpty::Console::interrupt`].

#[cfg(windows)]
pub mod conpty;
#[cfg(windows)]
pub mod job;
#[cfg(windows)]
pub mod launch;
// The decisions are written over a table of readings and run on every platform's tests; the
// readings themselves are the kernel's and exist only here.
#[cfg(any(windows, test))]
pub mod lineage;
