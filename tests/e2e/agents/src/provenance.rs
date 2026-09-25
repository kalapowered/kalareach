//! What a part's agent ran, and whether that was the build under test.
//!
//! A part tests the pinned build only when its sessions ran nothing else. The session's shell
//! searches the run's link to the installed build, the run's links to the runtimes the build
//! needs, and the system's own directories, and nothing another installation keeps on a person's
//! PATH; and every process beneath a session runs an executable image that lies in the build's own
//! directory, a runtime's, the run's own, the managed shell's or the system's. Each image is
//! recorded with its file's SHA-256. A session that searched another PATH, or ran an image from
//! anywhere else, did not test the pinned build: the part stops, and the record names what ran.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use kr_e2e_m1b::LIVENESS;
use kr_e2e_m1b::run::{Run, output_within};
use kr_e2e_m1b::shells::ManagedShell;
use serde::Serialize;

use crate::build::Build;
use crate::stage::{AgentProcess, text_image};

/// How a part's failure begins when its session ran something other than the build under test.
/// The harness records such a part as not run, with the rest of the line as its reason.
pub const NOT_PINNED: &str = "not the pinned build:";

/// The file the session's shell writes its PATH to before each prompt, in the run's home.
pub const PATH_FILE: &str = ".kr-agents-path";

/// Where the system keeps the executables a build may start. `/usr/local` is not among them:
/// another installation of an agent can live there.
const SYSTEM: [&str; 10] = [
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/usr/lib/",
    "/bin/",
    "/sbin/",
    "/System/",
    "/Library/Apple/",
    "/Library/Developer/CommandLineTools/",
    "/Applications/Xcode.app/",
];

/// The system's directories a session's PATH may name after the run's own.
const SYSTEM_PATH: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];

/// One executable image a process beneath a session ran.
#[derive(Clone, Debug, Serialize)]
pub struct Executed {
    /// The image, as the kernel mapped it, with links resolved.
    pub image: String,
    /// Its file's SHA-256, lower-case hexadecimal.
    pub sha256: String,
    /// Where it lies: `build`, `newer build`, `runtime`, `run`, `shell`, `system`, or `elsewhere`.
    pub from: &'static str,
    /// The first process seen running it.
    pub pid: u32,
    /// That process's command line, as the process table shows it.
    pub command: String,
}

/// What a stage's sessions ran, checked as they ran it.
pub struct Provenance {
    marks: Vec<PathBuf>,
    places: Vec<(PathBuf, &'static str)>,
    run_root: PathBuf,
    run_resolved: PathBuf,
    link: PathBuf,
    path_file: PathBuf,
    seen_path: Mutex<Option<String>>,
    executed: Mutex<BTreeMap<PathBuf, Executed>>,
}

impl Provenance {
    /// What `build` may run on `run`, with its sessions' shell from `shell`.
    #[must_use]
    pub fn new(build: &Build, run: &Run, shell: &ManagedShell) -> Self {
        let run_resolved = resolved(run.root());
        let runtimes: Vec<PathBuf> = build
            .runtime
            .iter()
            .map(|file| runtime_root(file))
            .collect();
        let mut marks = vec![build.prefix.clone(), run.root().join("agent")];
        marks.extend(build.newer.iter().map(|newer| newer.prefix.clone()));
        marks.extend(runtimes.iter().cloned());
        let written = marks.clone();
        marks.extend(written.iter().map(|mark| resolved(mark)));
        let mut places = vec![(resolved(&build.prefix), "build")];
        places.extend(
            build
                .newer
                .iter()
                .map(|newer| (resolved(&newer.prefix), "newer build")),
        );
        places.extend(runtimes.iter().map(|root| (root.clone(), "runtime")));
        places.push((run_resolved.clone(), "run"));
        places.push((resolved(&shell.prefix), "shell"));
        places.extend(SYSTEM.iter().map(|root| (PathBuf::from(root), "system")));
        Self {
            marks,
            places,
            run_root: run.root().to_path_buf(),
            run_resolved,
            link: run.root().join("agent").join("current").join("bin"),
            path_file: run.home().join(PATH_FILE),
            seen_path: Mutex::new(None),
            executed: Mutex::new(BTreeMap::new()),
        }
    }

    /// The directories whose presence in a process's command line or executable says it belongs
    /// to the build: the pinned build's and the newer one's, their runtimes', and the run's link to
    /// the installation, each as written and as resolved.
    #[must_use]
    pub fn marks(&self) -> &[PathBuf] {
        &self.marks
    }

    /// Checks the PATH the session's shell searches, as it wrote it before its last prompt: every
    /// directory lies in the run's own directory or is the system's, and `command` is found first
    /// in the run's link to the installed build.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when the shell searches anything else.
    pub fn check_path(&self, command: &str) -> Result<(), String> {
        let seen = std::fs::read_to_string(&self.path_file).map_err(|error| {
            format!(
                "{NOT_PINNED} the session's shell wrote no PATH to {}: {error}",
                self.path_file.display()
            )
        })?;
        let seen = seen.trim_end_matches('\n').to_owned();
        *self.seen_path.lock().expect("the PATH record") = Some(seen.clone());
        let outside: Vec<&str> = seen
            .split(':')
            .filter(|directory| {
                !(SYSTEM_PATH.contains(directory)
                    || Path::new(directory).starts_with(&self.run_root)
                    || Path::new(directory).starts_with(&self.run_resolved))
            })
            .collect();
        if !outside.is_empty() {
            return Err(format!(
                "{NOT_PINNED} the session's shell searches {}, outside the run and the system",
                outside.join(", ")
            ));
        }
        let found = seen
            .split(':')
            .map(|directory| Path::new(directory).join(command))
            .find(|candidate| candidate.is_file());
        match found {
            Some(file) if file.parent() == Some(self.link.as_path()) => Ok(()),
            Some(file) => Err(format!(
                "{NOT_PINNED} `{command}` is found first at {}, not in the run's link to the build",
                file.display()
            )),
            None => Err(format!(
                "{NOT_PINNED} `{command}` is not found on the session's PATH {seen}"
            )),
        }
    }

    /// Records the executable image each of `processes` runs, with its file's SHA-256, and checks
    /// where it lies. A process that has ended since it was listed is passed over.
    ///
    /// # Errors
    ///
    /// Returns why, beginning with [`NOT_PINNED`], when one runs an image from anywhere else.
    pub fn record(&self, processes: &[AgentProcess]) -> Result<(), String> {
        let mut executed = self.executed.lock().expect("the image record");
        for process in processes {
            let Ok(pid) = u32::try_from(process.identity.pid.get()) else {
                continue;
            };
            let Ok((image, _inode)) = text_image(pid) else {
                continue;
            };
            let image = resolved(&image);
            if executed.contains_key(&image) {
                continue;
            }
            let from = self
                .places
                .iter()
                .find(|(root, _)| image.starts_with(root))
                .map_or("elsewhere", |(_, from)| *from);
            let entry = Executed {
                image: image.display().to_string(),
                sha256: sha256_of(&image)?,
                from,
                pid,
                command: process.command.clone(),
            };
            executed.insert(image, entry.clone());
            if from == "elsewhere" {
                return Err(format!(
                    "{NOT_PINNED} process {pid} ({}) ran {} (sha256 {}), which is not the pinned \
                     build, its runtime, the run's own or the system's",
                    entry.command, entry.image, entry.sha256
                ));
            }
        }
        Ok(())
    }

    /// What the stage's sessions searched and ran, for the part's evidence.
    #[must_use]
    pub fn evidence(&self) -> serde_json::Value {
        let executed: Vec<Executed> = self
            .executed
            .lock()
            .expect("the image record")
            .values()
            .cloned()
            .collect();
        serde_json::json!({
            "session_path": *self.seen_path.lock().expect("the PATH record"),
            "executed": executed,
        })
    }
}

/// Where a runtime's installation lies: the directory above the one its executable is in, with
/// links resolved, so the images it runs from its own tree count as the runtime's.
fn runtime_root(executable: &Path) -> PathBuf {
    let file = resolved(executable);
    file.parent()
        .and_then(Path::parent)
        .or_else(|| file.parent())
        .map_or_else(|| file.clone(), Path::to_path_buf)
}

/// A path with its links resolved, or as written when it cannot be.
fn resolved(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// A file's SHA-256, lower-case hexadecimal.
fn sha256_of(file: &Path) -> Result<String, String> {
    let mut shasum = Command::new("/usr/bin/shasum");
    shasum
        .args(["-a", "256"])
        .arg(file)
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let output = output_within(shasum, LIVENESS).map_err(|why| format!("shasum {why}"))?;
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .filter(|digest| digest.len() == 64)
        .map(str::to_owned)
        .ok_or_else(|| format!("shasum named no digest for {}", file.display()))
}
