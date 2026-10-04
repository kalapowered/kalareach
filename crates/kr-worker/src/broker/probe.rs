//! Running a package's launch probe.
//!
//! A package can declare how to read the mode its application will run in: the application's own
//! diagnostic, the options of the launch that decide which configuration it reads, and where in
//! what it prints the mode is (see [`kr_plugin_sdk::launch_probe`]). This runs that declaration for
//! one launch, with what it can cost bounded: the probe is a program the package chose, run on this
//! host before a launch, so it gets no input, no shell, a short deadline, a cap on what it may
//! print, and a job of its own (a process group on Unix) that ends with it, so nothing it started
//! outlives the answer.
//!
//! The answer is a word or no word. A probe that cannot be started, does not finish, prints too
//! much or prints something the declaration cannot read records no mode and says why; it never
//! stops a launch by itself, because what the host could not read it does not guess at. A nonzero
//! exit status is not a failure: an application's diagnostic exits nonzero for a problem it reports
//! in the output the host reads, and the output is the answer.

use std::io::Read as _;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use kr_plugin_sdk::launch_probe::LaunchProbe;

/// How long a probe is given to print its answer and end, in all.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// The most a probe may print, in bytes.
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// What running a probe produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probed {
    /// The mode the application reported, exactly as it printed it, where the probe read one.
    pub mode: Option<String>,
    /// Why no mode was read, where none was.
    pub unread: Option<String>,
}

impl Probed {
    fn read(mode: String) -> Self {
        Self {
            mode: Some(mode),
            unread: None,
        }
    }

    fn unread(why: impl Into<String>) -> Self {
        Self {
            mode: None,
            unread: Some(why.into()),
        }
    }
}

/// Runs `probe` against `executable` for a launch whose own arguments are `launch`, in
/// `directory`, and reads the mode from what it prints.
///
/// The probe runs in this process's environment, which is the environment the launch it precedes
/// runs in, and in the launch's own directory. It belongs on a thread that may block.
#[must_use]
pub fn run(executable: &Path, probe: &LaunchProbe, launch: &[String], directory: &Path) -> Probed {
    run_within(
        executable,
        probe,
        launch,
        directory,
        DEADLINE,
        MAX_OUTPUT_BYTES,
    )
}

/// [`run`] with the deadline and the output cap named, which this host's own tests set small.
#[must_use]
pub fn run_within(
    executable: &Path,
    probe: &LaunchProbe,
    launch: &[String],
    directory: &Path,
    deadline: Duration,
    cap: usize,
) -> Probed {
    let arguments = match probe.invocation(launch) {
        Ok(arguments) => arguments,
        Err(why) => return Probed::unread(why),
    };
    let started = Instant::now();
    let mut process = match Process::start(executable, &arguments, directory) {
        Ok(process) => process,
        Err(error) => {
            return Probed::unread(format!(
                "{} could not be started to read its mode: {error}",
                executable.display()
            ));
        }
    };
    let output = process.take_output();
    // Read in a thread of its own, because a pipe read has no deadline of its own: the answer
    // arrives here, or the deadline passes and the process is ended, which closes the pipe and
    // lets the reader finish.
    let (sender, receiver) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut printed = Vec::new();
        let mut output = output;
        let read = output
            .by_ref()
            .take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut printed);
        let _ = sender.send(read.map(|_| printed));
    });
    let remaining = deadline.saturating_sub(started.elapsed());
    let outcome = receiver.recv_timeout(remaining);
    let printed = match outcome {
        Ok(Ok(printed)) if printed.len() <= cap => Ok(printed),
        Ok(Ok(_)) => Err(format!(
            "{} printed more than {} bytes",
            executable.display(),
            cap
        )),
        Ok(Err(error)) => Err(format!(
            "what {} printed could not be read: {error}",
            executable.display()
        )),
        Err(_) => Err(format!(
            "{} did not finish within {} ms",
            executable.display(),
            deadline.as_millis()
        )),
    };
    // Ended whatever happened: an application that printed its answer and then kept running is
    // not one this host leaves behind, and what it started goes with it.
    process.end();
    // Not waited for: a descendant that left the probe's group or job (a Unix process that made a
    // session of its own) can hold the pipe open, and the launch must not wait on it. The reader
    // ends by itself when the last holder lets go; where it has already finished it is collected.
    if reader.is_finished() {
        let _ = reader.join();
    }
    match printed {
        Ok(printed) => probe.read_mode(&printed).map_or_else(
            || {
                Probed::unread(format!(
                    "what {} printed holds no mode at {}",
                    executable.display(),
                    probe.mode
                ))
            },
            Probed::read,
        ),
        Err(why) => Probed::unread(why),
    }
}

/// The process a probe is, and what ends it and everything it started.
#[cfg(unix)]
struct Process {
    child: std::process::Child,
}

#[cfg(unix)]
impl Process {
    fn start(executable: &Path, arguments: &[String], directory: &Path) -> std::io::Result<Self> {
        use std::os::unix::process::CommandExt as _;

        let child = std::process::Command::new(executable)
            .args(arguments)
            .current_dir(directory)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            // A group of its own, so ending the probe ends what it started.
            .process_group(0)
            .spawn()?;
        Ok(Self { child })
    }

    fn take_output(&mut self) -> std::process::ChildStdout {
        self.child.stdout.take().expect("the output is piped")
    }

    /// Ends the probe's group and waits for the probe.
    fn end(&mut self) {
        if let Some(group) = i32::try_from(self.child.id())
            .ok()
            .and_then(rustix::process::Pid::from_raw)
        {
            // Best effort: a group that has ended already cannot be signalled, which is the
            // outcome wanted.
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
        let _ = self.child.wait();
    }
}

/// The process a probe is, and what ends it and everything it started.
#[cfg(windows)]
struct Process {
    child: crate::windows::launch::Child,
    /// The job the probe runs in: kill-on-close, so nothing it started outlives it.
    job: crate::windows::job::AgentJob,
}

#[cfg(windows)]
impl Process {
    fn start(executable: &Path, arguments: &[String], directory: &Path) -> std::io::Result<Self> {
        let job = crate::windows::job::AgentJob::create_owning()?;
        let child = crate::windows::launch::start(&crate::windows::launch::Spec {
            program: executable,
            arguments,
            directory,
            environment: &[],
            session: None,
            agent: &job,
            pipe_input: false,
            pipe_output: true,
        })?;
        Ok(Self { child, job })
    }

    fn take_output(&mut self) -> std::fs::File {
        self.child.stdout.take().expect("the output is piped")
    }

    /// Ends the probe's job and waits for the probe.
    fn end(&mut self) {
        let _ = self.job.terminate(1);
        let _ = self.child.wait();
    }
}
