//! Starting the stub description process from the internal disk, and talking to it over its real
//! standard input and output.
//!
//! The executable is copied to a directory of the test's own on the internal disk before it is
//! started, and it runs there with a runtime directory there, so nothing it does touches the volume
//! the workspace is on.
#![allow(dead_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use kr_describe::context::{ContextBuilder, ContextRevision};
use kr_describe::output::{DESCRIPTION_GRAMMAR, prompt};
use kr_describe::profile::ModelProfile;
use kr_describe::testing::{SCRIPT_VARIABLE, Script};
use kr_describe::wire::{
    Answer, AssetFile, JobLimits, Request, WIRE_VERSION, frame_of, read_message,
};
use kr_protocol::ids::SessionEpoch;
use kr_protocol::scalars::U64;

/// A copy of the stub executable, in a directory of the test's own on the internal disk.
pub struct Placed {
    directory: tempfile::TempDir,
    program: PathBuf,
}

impl Placed {
    /// Places a copy of the stub executable.
    pub fn stub() -> Self {
        let directory = tempfile::tempdir().expect("a directory on the internal disk");
        let program = directory
            .path()
            .join(format!("kr-describe-stub{}", std::env::consts::EXE_SUFFIX));
        kr_ipc::testing::place_program(Path::new(env!("CARGO_BIN_EXE_kr-describe-stub")), &program);
        Self { directory, program }
    }

    /// Returns the placed executable.
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns a new directory beside it, for a runtime directory or a working directory.
    pub fn directory(&self, name: &str) -> PathBuf {
        let path = self.directory.path().join(name);
        std::fs::create_dir_all(&path).expect("a directory beside the executable");
        path
    }
}

/// Waits until a stub that marks its work has begun some of this kind in `runtime_dir`.
pub fn wait_until_began(runtime_dir: &Path, kind: &str) {
    let prefix = format!("{}{kind}-", kr_describe::testing::BEGAN_PREFIX);
    let give_up = Instant::now() + Duration::from_secs(20);
    loop {
        let began = std::fs::read_dir(runtime_dir)
            .expect("the runtime directory")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix));
        if began {
            return;
        }
        assert!(
            Instant::now() < give_up,
            "no {kind} began in {}",
            runtime_dir.display()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// One running stub, spoken to directly.
pub struct Process {
    child: Child,
    input: Option<ChildStdin>,
    answers: Receiver<Result<Answer, String>>,
}

impl Process {
    /// Starts the stub with a script and a runtime directory.
    pub fn start(placed: &Placed, script: &Script, runtime_dir: &Path) -> Self {
        Self::start_with(placed, script, runtime_dir, None)
    }

    /// Starts the stub with a script and a runtime directory, and the test catalogue at
    /// `catalogue` when one is given.
    pub fn start_with(
        placed: &Placed,
        script: &Script,
        runtime_dir: &Path,
        catalogue: Option<&Path>,
    ) -> Self {
        let mut command = Command::new(placed.program());
        command
            .arg("--runtime-dir")
            .arg(runtime_dir)
            .current_dir(runtime_dir)
            .env(SCRIPT_VARIABLE, script.to_env());
        if let Some(catalogue) = catalogue {
            command.env(kr_describe::testing::CATALOGUE_VARIABLE, catalogue);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("the stub starts");
        let input = child.stdin.take();
        let mut output = child.stdout.take().expect("the stub's output");
        let (tell, answers) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            loop {
                match read_message::<Answer>(&mut output) {
                    Ok(Some(answer)) => {
                        if tell.send(Ok(answer)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = tell.send(Err(error.to_string()));
                        return;
                    }
                }
            }
        });
        Self {
            child,
            input,
            answers,
        }
    }

    /// Returns the process identifier.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Sends one request.
    pub fn send(&mut self, request: &Request) {
        let frame = frame_of(request).expect("a request frames");
        let input = self.input.as_mut().expect("the input is open");
        input.write_all(&frame).expect("the request is written");
        input.flush().expect("the request is flushed");
    }

    /// Returns the next answer, when one arrives in time.
    pub fn answer(&self, within: Duration) -> Option<Answer> {
        match self.answers.recv_timeout(within) {
            Ok(Ok(answer)) => Some(answer),
            Ok(Err(error)) => panic!("the stub's answer did not read: {error}"),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Returns the next answer, which has to arrive within `within`.
    pub fn expect_answer(&self, within: Duration, what: &str) -> Answer {
        self.answer(within)
            .unwrap_or_else(|| panic!("{what} did not arrive within {within:?}"))
    }

    /// Returns the next answer that is not the control thread's acknowledgement of a cancellation,
    /// which has to arrive within `within`.
    pub fn expect_terminal(&self, within: Duration, what: &str) -> Answer {
        loop {
            let answer = self.expect_answer(within, what);
            if !matches!(answer, Answer::Cancelling { .. }) {
                return answer;
            }
        }
    }

    /// Closes the process's input, which is what it sees when its daemon goes.
    pub fn close_input(&mut self) {
        self.input = None;
    }

    /// Returns the exit status, when the process ends in time.
    pub fn exit_within(&mut self, within: Duration) -> Option<ExitStatus> {
        let until = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("the stub's status") {
                return Some(status);
            }
            if Instant::now() >= until {
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Ends the process and collects it.
    pub fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Says hello and returns the answer.
    pub fn hello(&mut self) -> Answer {
        self.send(&Request::Hello {
            build: "kr-describe-tests/0".to_owned(),
            wire: U64::new(WIRE_VERSION),
        });
        self.expect_answer(Duration::from_secs(10), "ready")
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        self.kill();
    }
}

/// A load of a profile, with each of its files at a path that names it.
pub fn load(id: u64, profile: &ModelProfile, deadline_ms: u64) -> Request {
    Request::Load {
        id: U64::new(id),
        profile_id: profile.profile_id().to_owned(),
        revision: U64::new(profile.revision().get()),
        assets: profile
            .assets()
            .iter()
            .map(|asset| AssetFile {
                file_name: asset.file_name.clone(),
                path: format!("/nowhere/{}", asset.file_name),
            })
            .collect(),
        deadline_ms: U64::new(deadline_ms),
    }
}

/// A job for one session's context at one revision.
pub fn generate(id: u64, revision: u64, deadline_ms: u64) -> Request {
    let context = ContextBuilder::new(
        super::support::environment_id(1),
        super::support::session(1),
        SessionEpoch::V1,
        super::support::binding(),
        ContextRevision::new(revision),
    )
    .directory("kalareach")
    .build();
    Request::Generate {
        id: U64::new(id),
        prompt: prompt(&context),
        grammar: DESCRIPTION_GRAMMAR.to_owned(),
        limits: JobLimits {
            context_tokens: U64::new(4_096),
            max_output_tokens: U64::new(128),
            cpu_threads: U64::new(4),
        },
        deadline_ms: U64::new(deadline_ms),
        ceiling_bytes: U64::new(4 << 30),
    }
}
