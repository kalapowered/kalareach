//! The restricted Git execution profile.
//!
//! Section 14 requires brokered Git reads to use installed qualified Git through argument vectors
//! **and a restricted execution profile**, and says outright that argument-vector construction
//! alone is not this isolation. So every invocation this crate makes goes through one type, and
//! that type decides four things a repository cannot argue with.
//!
//! 1. **Which program runs.** The Git binary is resolved once, to an absolute path, and its own
//!    `--exec-path` is recorded with it. Both are passed explicitly, so an inherited
//!    `GIT_EXEC_PATH` or a directory earlier on `PATH` cannot substitute another program.
//! 2. **What environment it runs in.** The child's environment is built from nothing
//!    ([`std::process::Command::env_clear`]) and then filled in. Every variable Git reads that can
//!    name a program — `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_ASKPASS`,
//!    `GIT_PAGER`, `GIT_EDITOR`, `GIT_TEMPLATE_DIR`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`,
//!    `GIT_CONFIG_KEY_<n>` — is therefore absent unless this module put it there. `PATH` holds the
//!    Git binary's own directory and its exec-path and nothing else, so a remote helper somewhere
//!    on the user's path is not reachable.
//! 3. **What configuration applies.** `GIT_CONFIG_NOSYSTEM=1`, and `GIT_CONFIG_GLOBAL` and
//!    `GIT_CONFIG_SYSTEM` both point at a zero-byte file this host owns, so the only configuration
//!    left is the repository's own. On top of it go the overrides below, carried as
//!    `GIT_CONFIG_COUNT` with a `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>` pair for each one.
//!    That form has the same precedence as `git -c`, beats every configuration file, and reaches
//!    every subprocess Git starts. It is used in place of `-c` because `-c` splits its argument at
//!    the first `=`, so a configuration key whose subsection contains one could not be overridden
//!    at all: `-c filter.with=equals.clean=` sets `filter.with` and leaves the driver alone.
//! 4. **What the repository's own configuration is allowed to name.** A `filter`, `diff` or `merge`
//!    driver is named by an attribute and *defined* in configuration, and the set of names is
//!    unbounded, so a fixed list of overrides cannot cover it. Instead the effective configuration
//!    is read first ([`ConfigurationAudit`]) and every driver it defines is blanked by name, every
//!    execution-capable key is reported as a limitation rather than honoured, and the keys that
//!    cannot be neutralised at all are a refusal.
//!
//! What the profile does **not** do is rewrite the user's Git configuration. Nothing here writes to
//! `.git/config`, to `~/.gitconfig` or to the system file; the overrides live on the command line
//! and in the environment of one child process, and a terminal command under broad shell access
//! keeps normal Git behaviour because it never comes through here.
//!
//! ## What a planted repository cannot do
//!
//! `fixtures/project/restricted-profile.json` is the list, and the fixture repositories the tests
//! build plant every one of them: a `core.fsmonitor` hook, `core.hooksPath` hooks, a `filter.*`
//! clean and smudge pair with a `.gitattributes` that names it, a `diff.*` textconv driver, a
//! `diff.external` helper, a `core.pager`, a `credential.helper` and a `core.sshCommand`. Each
//! writes a sentinel file when it runs, and the tests assert that no sentinel exists after a
//! status, a review refresh, a clone and an adoption.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kr_protocol::project::{GIT_READ_DEADLINE, MAX_GIT_OUTPUT_BYTES, RemoteTransport};

use crate::error::{ProjectError, Result};

/// The minimum Git version this host will use.
///
/// `GIT_CONFIG_GLOBAL` and `GIT_CONFIG_SYSTEM` arrived in 2.32 and the whole profile rests on
/// them, so an older Git is refused rather than trusted to ignore a file it still reads.
pub const MINIMUM_GIT_VERSION: (u32, u32) = (2, 32);

/// The name of the profile directory inside the service's own directory.
pub const PROFILE_DIRECTORY: &str = "git-profile";

/// The zero-byte file both global and system configuration are read from.
pub const EMPTY_CONFIG_FILE: &str = "empty-config";

/// The empty directory `core.hooksPath` names.
pub const HOOKS_DIRECTORY: &str = "hooks";

/// The empty directory `init.templateDir` names.
pub const TEMPLATE_DIRECTORY: &str = "template";

/// The empty directory the child's home is set to.
pub const HOME_DIRECTORY: &str = "home";

/// How a repository's execution-capable key is dealt with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposal {
    /// A command-line override sets it to nothing, which no configuration file can undo.
    Blank,
    /// No override removes it, because the key is multi-valued and an override appends to it. An
    /// operation that would depend on it is refused instead.
    Refuse,
}

/// One configuration key this host refuses to honour.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionKey {
    /// The lowercase key. One `*` stands for a section name the repository chose.
    pub pattern: &'static str,
    /// What the key names, for a diagnostic a person reads.
    pub names: &'static str,
    /// How it is dealt with.
    pub disposal: Disposal,
}

impl ExecutionKey {
    const fn blank(pattern: &'static str, names: &'static str) -> Self {
        Self {
            pattern,
            names,
            disposal: Disposal::Blank,
        }
    }

    const fn refuse(pattern: &'static str, names: &'static str) -> Self {
        Self {
            pattern,
            names,
            disposal: Disposal::Refuse,
        }
    }

    /// Returns whether one lowercase configuration key is this one.
    #[must_use]
    pub fn matches(&self, key: &str) -> bool {
        match self.pattern.split_once('*') {
            None => key == self.pattern,
            Some((head, tail)) => {
                key.len() > head.len() + tail.len() && key.starts_with(head) && key.ends_with(tail)
            }
        }
    }
}

/// Every configuration key this host refuses to honour, and how it is dealt with.
///
/// A key in this table names a program, so honouring it would execute something the caller did not
/// grant.
pub const EXECUTION_KEYS: &[ExecutionKey] = &[
    ExecutionKey::blank("core.fsmonitor", "a filesystem-monitor hook or daemon"),
    ExecutionKey::blank("core.fsmonitorhookversion", "the fsmonitor hook protocol"),
    ExecutionKey::blank("core.hookspath", "the directory hooks are found in"),
    ExecutionKey::blank("core.pager", "a pager"),
    ExecutionKey::blank("core.editor", "an editor"),
    ExecutionKey::blank("core.askpass", "a credential prompt program"),
    ExecutionKey::blank("core.sshcommand", "the ssh program"),
    ExecutionKey::blank("core.gitproxy", "a proxy program for the git protocol"),
    ExecutionKey::blank("core.alternaterefscommand", "a reference-listing program"),
    ExecutionKey::blank("diff.external", "an external diff program"),
    ExecutionKey::blank("sequence.editor", "the rebase sequence editor"),
    ExecutionKey::blank("gpg.program", "a signature program"),
    ExecutionKey::blank("gpg.openpgp.program", "a signature program"),
    ExecutionKey::blank("gpg.x509.program", "a signature program"),
    ExecutionKey::blank("gpg.ssh.program", "a signature program"),
    ExecutionKey::blank("uploadpack.packobjectshook", "a pack-serving program"),
    ExecutionKey::blank(
        "init.templatedir",
        "a template directory whose hooks are copied",
    ),
    // One empty `credential.helper` from the command line empties the whole list, including the
    // per-URL entries, because the command line is read after every file.
    ExecutionKey::blank("credential.helper", "a credential helper program"),
    ExecutionKey::blank("credential.*.helper", "a credential helper program"),
    // A remote helper: `remote.<name>.vcs = foo` makes Git run `git-remote-foo`.
    ExecutionKey::refuse("remote.*.vcs", "a remote helper program"),
    ExecutionKey::refuse(
        "remote.*.uploadpack",
        "the program the other side runs to serve a fetch",
    ),
    ExecutionKey::refuse(
        "remote.*.receivepack",
        "the program the other side runs to serve a push",
    ),
    // URL rewriting is multi-valued, so an override adds to it rather than removing it.
    ExecutionKey::refuse("url.*.insteadof", "a URL rewrite"),
    ExecutionKey::refuse("url.*.pushinsteadof", "a URL rewrite"),
];

/// The driver sections whose execution keys are blanked by name, and the value each is set to.
///
/// A driver is named by a `.gitattributes` entry and defined in configuration, and the name is
/// whatever the repository chose, so the overrides are built from the configuration that is
/// actually there rather than from a list nobody can close. A boolean key is set to `false` rather
/// than to nothing, because Git reads an empty boolean as a malformed value and stops.
pub const DRIVER_SECTIONS: &[(&str, &[(&str, &str)])] = &[
    (
        "filter",
        &[
            ("clean", ""),
            ("smudge", ""),
            ("process", ""),
            ("required", "false"),
        ],
    ),
    (
        "diff",
        &[
            ("textconv", ""),
            ("command", ""),
            ("cachetextconv", "false"),
        ],
    ),
    ("merge", &[("driver", "")]),
];

/// Every Git subcommand this service runs.
///
/// An allowlist rather than a list of things to avoid, because the question is not which commands
/// can destroy the user's work (a list nobody can close) but which ones this service needs. What
/// it leaves out is the point: `clean`, `stash`, `reset`, `restore`, `commit`, `push`, `revert`,
/// `rebase`, `merge`, `gc` and `prune` are not commands this code can run at all, which is what
/// "never clean, stash or discard untracked files to start a reviewer" and "never run commit, push
/// or destructive revert merely because review was marked complete" come to in code.
pub const PERMITTED_SUBCOMMANDS: &[&str] = &[
    "cat-file",
    "checkout",
    "clone",
    "config",
    "diff",
    "init",
    "ls-files",
    "rev-parse",
    "show-ref",
    "status",
    "symbolic-ref",
    "worktree",
];

/// Short arguments no invocation carries, whatever subcommand it is.
const FORBIDDEN_SHORT: &[&str] = &["-c", "-f", "-u"];

/// Long arguments no invocation carries, whatever subcommand it is.
///
/// `--force` is how a Git command is told to discard what is in the way; the rest are how one
/// would be told to run something else or to work somewhere else, and the profile owns those
/// rather than the caller. They are matched in both directions, because Git's own subcommand
/// parser accepts an unambiguous abbreviation: `--conf` would reach `--config`.
const FORBIDDEN_LONG: &[&str] = &[
    "--attr-source",
    "--config",
    "--config-env",
    "--exec-path",
    "--force",
    "--git-dir",
    "--namespace",
    "--receive-pack",
    "--recurse-submodules",
    "--separate-git-dir",
    "--super-prefix",
    "--upload-pack",
    "--work-tree",
];

/// Refuses an argument vector this service does not run.
///
/// # Errors
///
/// Returns [`ProjectError::InvalidArgument`] naming the subcommand or the argument.
pub fn check_arguments(arguments: &[&OsStr]) -> Result<()> {
    let Some(subcommand) = arguments.first() else {
        return Err(ProjectError::InvalidArgument(
            "an invocation names a subcommand".to_owned(),
        ));
    };
    let subcommand = subcommand.to_string_lossy();
    if !PERMITTED_SUBCOMMANDS.contains(&subcommand.as_ref()) {
        return Err(ProjectError::InvalidArgument(format!(
            "git {subcommand} is not a subcommand this service runs; it runs {}",
            PERMITTED_SUBCOMMANDS.join(", ")
        )));
    }
    for argument in arguments {
        let text = argument.to_string_lossy();
        let head = text.split_once('=').map_or(text.as_ref(), |(head, _)| head);
        let refused = FORBIDDEN_SHORT.contains(&head)
            // An attached short option: `-cfilter.x.clean=sh` is `-c` with its value stuck to it.
            || FORBIDDEN_SHORT
                .iter()
                .any(|short| text.len() > short.len() && text.starts_with(short))
            // A long option, or any abbreviation of one that Git's own parser would accept.
            || (head.starts_with("--")
                && head.len() > 2
                && FORBIDDEN_LONG
                    .iter()
                    .any(|long| long.starts_with(head) || head.starts_with(long)));
        if refused {
            return Err(ProjectError::InvalidArgument(format!(
                "{} is not an argument this service passes: a forced command discards what is in \
                 the way, and the configuration, the programs and the directories are the \
                 profile's rather than the caller's",
                redact(&text)
            )));
        }
        // A combined short option hides its members: `-qf` is `-q` and `-f`, and the second is
        // the one this service never passes.
        if text.starts_with('-')
            && !text.starts_with("--")
            && text.len() > 2
            && text.chars().skip(1).any(|character| {
                FORBIDDEN_SHORT
                    .iter()
                    .any(|short| short.ends_with(character))
            })
        {
            return Err(ProjectError::InvalidArgument(format!(
                "{} combines a short option this service never passes",
                redact(&text)
            )));
        }
        // The one template directory an invocation may name is the empty one the profile already
        // points at, so an explicit `--template=` carries nothing. An abbreviation of it is the
        // same option, so only the exact empty form is allowed through.
        if "--template".starts_with(head) && head.len() > 2 && text != "--template=" {
            return Err(ProjectError::InvalidArgument(format!(
                "{} names a template directory whose hooks would be copied into the new \
                 repository",
                redact(&text)
            )));
        }
    }
    Ok(())
}

/// The flag one operation's Git invocations watch, and what stopping them counted.
///
/// A cancellation cannot reach inside a running subprocess, so it sets this and the invocation
/// that holds the child ends the child *it* started. Nothing else on the machine is touched: the
/// identity is the child handle this process owns rather than a name or a pattern.
#[derive(Debug, Default)]
pub struct Cancellation {
    requested: AtomicBool,
    stopped: AtomicU64,
}

impl Cancellation {
    /// Asks every invocation of this operation to stop.
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    /// Returns whether a stop has been asked for.
    #[must_use]
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Records that one subprocess this host started was stopped.
    pub fn record_stop(&self) {
        self.stopped.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns how many subprocesses this host started and stopped.
    #[must_use]
    pub fn stopped(&self) -> u64 {
        self.stopped.load(Ordering::SeqCst)
    }
}

/// Installed Git, resolved once.
#[derive(Clone, Debug)]
pub struct GitProgram {
    program: PathBuf,
    exec_path: PathBuf,
    version: String,
}

impl GitProgram {
    /// Resolves installed Git, its own `--exec-path` and its version.
    ///
    /// The process's own `PATH` is consulted exactly here, once, at startup. Every invocation
    /// afterwards runs with the `PATH` the profile builds.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitUnavailable`] when Git is not installed, cannot be resolved to
    /// an absolute path, or is older than [`MINIMUM_GIT_VERSION`].
    pub fn discover() -> Result<Self> {
        let program = search_path(GIT_FILE_NAME).ok_or_else(|| ProjectError::GitUnavailable {
            detail: "installed Git was not found on this host".to_owned(),
        })?;
        Self::at(&program)
    }

    /// Resolves one named Git binary, its helper directory and its version.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitUnavailable`] when the path cannot be resolved or the version is
    /// older than [`MINIMUM_GIT_VERSION`].
    pub fn at(path: &Path) -> Result<Self> {
        let program = path
            .canonicalize()
            .map_err(|error| ProjectError::GitUnavailable {
                detail: format!("{} could not be resolved: {error}", path.display()),
            })?;
        if !program.is_absolute() {
            return Err(ProjectError::GitUnavailable {
                detail: format!("{} is not an absolute path", program.display()),
            });
        }
        // Asked of the resolved binary with an environment of nothing, so the answer is the
        // program's own rather than an inherited `GIT_EXEC_PATH`.
        let exec_path = PathBuf::from(ask(&program, &["--exec-path"])?.trim_end());
        if !exec_path.is_absolute() {
            return Err(ProjectError::GitUnavailable {
                detail: format!(
                    "{} reports a relative helper directory {}",
                    program.display(),
                    exec_path.display()
                ),
            });
        }
        let version = ask(&program, &["--version"])?.trim_end().to_owned();
        let parsed = parse_version(&version).ok_or_else(|| ProjectError::GitUnavailable {
            detail: format!("{version} does not report a version this host can read"),
        })?;
        if parsed < MINIMUM_GIT_VERSION {
            return Err(ProjectError::GitUnavailable {
                detail: format!(
                    "this host needs Git {}.{} or later for the restricted execution profile, and \
                     {version} is installed",
                    MINIMUM_GIT_VERSION.0, MINIMUM_GIT_VERSION.1
                ),
            });
        }
        Ok(Self {
            program,
            exec_path,
            version,
        })
    }

    /// Returns the absolute path of the Git binary.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Returns the helper directory the binary reported for itself.
    #[must_use]
    pub fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    /// Returns the version string the binary reported.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
}

/// The restricted profile: the program, and the empty directories the overrides point at.
#[derive(Clone, Debug)]
pub struct RestrictedProfile {
    git: GitProgram,
    empty_config: PathBuf,
    hooks: PathBuf,
    template: PathBuf,
    home: PathBuf,
}

impl RestrictedProfile {
    /// Prepares the profile inside the service's own directory.
    ///
    /// The three directories are created empty and stay empty: hooks are looked for in one,
    /// templates are copied from another, and the child's home is the third so that no
    /// `~/.gitconfig`, `~/.gitignore` or `~/.ssh/config` is ever read.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StagingUnavailable`] when a directory or the empty file cannot be
    /// created, or [`ProjectError::GitUnavailable`] when Git cannot be resolved.
    pub fn prepare(root: &Path) -> Result<Self> {
        Self::prepare_with(root, GitProgram::discover()?)
    }

    /// Prepares the profile around one already-resolved Git program.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::StagingUnavailable`] when a directory or the empty file cannot be
    /// created, or when one of them is not empty.
    pub fn prepare_with(root: &Path, git: GitProgram) -> Result<Self> {
        let profile = root.join(PROFILE_DIRECTORY);
        std::fs::create_dir_all(&profile).map_err(ProjectError::staging)?;
        let hooks = profile.join(HOOKS_DIRECTORY);
        let template = profile.join(TEMPLATE_DIRECTORY);
        let home = profile.join(HOME_DIRECTORY);
        for directory in [&hooks, &template, &home] {
            std::fs::create_dir_all(directory).map_err(ProjectError::staging)?;
            // The emptiness of these directories is the profile's guarantee, so something left in
            // one of them is a refusal rather than a thing to work around.
            let mut entries = std::fs::read_dir(directory).map_err(ProjectError::staging)?;
            if let Some(entry) = entries.next() {
                let entry = entry.map_err(ProjectError::staging)?;
                return Err(ProjectError::StagingUnavailable {
                    detail: format!(
                        "{} must be empty for the restricted profile and it holds {}",
                        redact(&directory.display().to_string()),
                        redact(&entry.file_name().to_string_lossy())
                    ),
                });
            }
        }
        let empty_config = profile.join(EMPTY_CONFIG_FILE);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&empty_config)
        {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let length = std::fs::metadata(&empty_config)
                    .map_err(ProjectError::staging)?
                    .len();
                if length != 0 {
                    return Err(ProjectError::StagingUnavailable {
                        detail: format!(
                            "{} must be empty for the restricted profile and it holds {length} \
                             bytes",
                            empty_config.display()
                        ),
                    });
                }
            }
            Err(error) => return Err(ProjectError::staging(error)),
        }
        Ok(Self {
            git,
            empty_config,
            hooks,
            template,
            home,
        })
    }

    /// Returns the resolved Git program.
    #[must_use]
    pub const fn git(&self) -> &GitProgram {
        &self.git
    }

    /// Returns the empty directory hooks are looked for in.
    #[must_use]
    pub fn hooks_directory(&self) -> &Path {
        &self.hooks
    }

    /// Returns the zero-byte file global and system configuration are read from.
    #[must_use]
    pub fn empty_config(&self) -> &Path {
        &self.empty_config
    }

    /// Runs one Git invocation and returns its output.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the invocation cannot start, cannot be waited on,
    /// or runs past its deadline. A non-zero exit is an output rather than an error, because a
    /// caller often needs the exit code.
    pub fn run(&self, request: &GitRequest<'_>) -> Result<GitOutput> {
        // The allowlist is checked here rather than at each call site, because here is the one
        // place a subprocess is started.
        check_arguments(request.arguments)?;
        let mut command = Command::new(&self.git.program);
        command.env_clear();
        for (name, value) in self.environment(request) {
            command.env(name, value);
        }
        command.args(self.argument_vector(request));
        // A Git subprocess never gets a terminal: it cannot prompt, it cannot page, and a helper
        // that wanted to read from one finds nothing to read.
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // The child leads its own process group, so ending it ends everything it started: a
        // remote helper, an ssh process, a credential helper. Killing the child alone would leave
        // those holding the connection this cancellation was meant to drop.
        own_process_group(&mut command);
        let mut child = command.spawn().map_err(|error| ProjectError::GitFailed {
            detail: format!("{} could not start: {error}", request.describe()),
        })?;
        let out = child.stdout.take().map(read_bounded);
        let err = child.stderr.take().map(read_bounded);
        let deadline = Instant::now() + request.deadline;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    return Err(ProjectError::GitFailed {
                        detail: format!("{} could not be waited on: {error}", request.describe()),
                    });
                }
            }
            if let Some(cancel) = request.cancel.as_ref()
                && cancel.requested()
            {
                // This host started the group, so this host ends it, by the identity it recorded
                // rather than by a name or a pattern that could match somebody else's work.
                let stopped = end_group(&mut child);
                if stopped {
                    cancel.record_stop();
                }
                return Err(ProjectError::Cancelled {
                    detail: format!(
                        "{} was stopped by its owner{}",
                        request.describe(),
                        if stopped {
                            ""
                        } else {
                            ", and this host could not confirm that every process it started ended"
                        }
                    ),
                });
            }
            if Instant::now() >= deadline {
                let stopped = end_group(&mut child);
                if let Some(cancel) = request.cancel.as_ref()
                    && stopped
                {
                    cancel.record_stop();
                }
                return Err(ProjectError::GitFailed {
                    detail: format!(
                        "{} ran longer than {} milliseconds and was stopped{}",
                        request.describe(),
                        request.deadline.as_millis(),
                        if stopped {
                            ""
                        } else {
                            ", and this host could not confirm that every process it started ended"
                        }
                    ),
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let out = join(out, request)?;
        let err = join(err, request)?;
        let stderr = git_said(&String::from_utf8_lossy(&err.bytes));
        Ok(GitOutput {
            status: status.code(),
            success: status.success(),
            stdout: out.bytes,
            stdout_truncated: out.truncated,
            stderr: if err.truncated {
                format!("{stderr}, of which this host read part")
            } else {
                stderr
            },
            command: request.describe(),
        })
    }

    /// Runs one invocation and returns its standard output as text, refusing a failure.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the invocation fails or its output was truncated.
    pub fn run_checked(&self, request: &GitRequest<'_>) -> Result<String> {
        let output = self.run(request)?;
        output.require_success()?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Builds the complete argument vector one invocation runs with.
    ///
    /// The configuration overrides are not here: they travel in the environment, because a
    /// command-line `-c` cannot express a key whose subsection contains an equals sign.
    ///
    /// Public because the profile's fixture reads it: a profile whose overrides drifted from the
    /// documented list is a profile nobody noticed changing.
    #[must_use]
    pub fn argument_vector(&self, request: &GitRequest<'_>) -> Vec<OsString> {
        let mut argv: Vec<OsString> = vec![OsString::from("--no-pager")];
        if let Some(directory) = request.directory {
            argv.push(OsString::from("-C"));
            argv.push(directory.as_os_str().to_owned());
        }
        if request.read_only {
            // No index write, no reference-log rewrite, no optional lock: a read leaves the
            // repository exactly as it found it.
            argv.push(OsString::from("--no-optional-locks"));
        }
        argv.extend(
            request
                .arguments
                .iter()
                .map(|argument| (*argument).to_owned()),
        );
        argv
    }

    /// Builds the configuration overrides one invocation runs with, in the order they are applied.
    ///
    /// The order matters in one place: `credential.helper` is blanked first, which empties the
    /// list, and the approved broker's helper is appended after it. Everything else is independent.
    /// Each pair reaches Git as `GIT_CONFIG_KEY_<n>` and `GIT_CONFIG_VALUE_<n>`, in this order.
    #[must_use]
    pub fn overrides(&self, request: &GitRequest<'_>) -> Vec<(String, OsString)> {
        let mut settings: Vec<(String, OsString)> = vec![
            // Hooks are looked for in a directory this host owns and keeps empty, so a planted
            // `.git/hooks/post-checkout` is never found.
            (
                "core.hooksPath".to_owned(),
                self.hooks.as_os_str().to_owned(),
            ),
            // No filesystem monitor: neither a hook program nor the built-in daemon.
            ("core.fsmonitor".to_owned(), OsString::from("false")),
            ("core.fsmonitorHookVersion".to_owned(), OsString::new()),
            ("core.untrackedCache".to_owned(), OsString::from("false")),
            // No pager and no editor. The child has no terminal either, so both are belt and
            // braces rather than the only bar.
            ("core.pager".to_owned(), OsString::from("cat")),
            ("core.editor".to_owned(), OsString::from("false")),
            ("sequence.editor".to_owned(), OsString::from("false")),
            // No interactive credential prompt and no proxy program.
            ("core.askPass".to_owned(), OsString::new()),
            ("core.gitProxy".to_owned(), OsString::new()),
            ("core.alternateRefsCommand".to_owned(), OsString::new()),
            ("core.alternateRefsPrefixes".to_owned(), OsString::new()),
            // Attribute and exclude files outside the repository are not this operation's input.
            ("core.attributesFile".to_owned(), OsString::new()),
            ("core.excludesFile".to_owned(), OsString::new()),
            // No external diff program.
            ("diff.external".to_owned(), OsString::new()),
            // No signature program, and nothing that would ask for one.
            ("gpg.program".to_owned(), OsString::from("false")),
            ("gpg.openpgp.program".to_owned(), OsString::from("false")),
            ("gpg.x509.program".to_owned(), OsString::from("false")),
            ("gpg.ssh.program".to_owned(), OsString::from("false")),
            ("commit.gpgSign".to_owned(), OsString::from("false")),
            ("tag.gpgSign".to_owned(), OsString::from("false")),
            ("log.showSignature".to_owned(), OsString::from("false")),
            // Nothing this host runs starts background maintenance in the user's repository.
            ("gc.auto".to_owned(), OsString::from("0")),
            ("gc.autoDetach".to_owned(), OsString::from("false")),
            ("maintenance.auto".to_owned(), OsString::from("false")),
            // A template directory's hooks are copied into a new repository, so the template is
            // one this host owns and keeps empty.
            (
                "init.templateDir".to_owned(),
                self.template.as_os_str().to_owned(),
            ),
            ("uploadpack.packObjectsHook".to_owned(), OsString::new()),
            // A bare repository reached through a path is served only when the caller asked for
            // one, which nothing here does.
            ("safe.bareRepository".to_owned(), OsString::from("explicit")),
            // Every transport is refused, and the one this operation validated is allowed back
            // below.
            ("protocol.allow".to_owned(), OsString::from("never")),
            ("protocol.version".to_owned(), OsString::from("2")),
            // A submodule is its own repository, and its configuration lives in the parent's
            // modules directory, which the parent's own configuration listing does not read. So a
            // driver defined there is one the audit cannot see, and the only safe answer is never
            // to enter a submodule: every read passes `--ignore-submodules=all` as well, because
            // `submodule.recurse` alone does not stop a status from checking a submodule's
            // dirtiness, and checking it runs Git inside the submodule.
            ("fetch.recurseSubmodules".to_owned(), OsString::from("no")),
            ("submodule.recurse".to_owned(), OsString::from("false")),
            ("diff.ignoreSubmodules".to_owned(), OsString::from("all")),
            (
                "status.submoduleSummary".to_owned(),
                OsString::from("false"),
            ),
            // Objects a remote sends are checked rather than taken on trust.
            ("transfer.fsckObjects".to_owned(), OsString::from("true")),
            ("fetch.fsckObjects".to_owned(), OsString::from("true")),
            ("http.sslVerify".to_owned(), OsString::from("true")),
            ("advice.detachedHead".to_owned(), OsString::from("false")),
            // The credential list is emptied here. The broker's helper is appended below, so a
            // helper the repository or a user file named is gone and only an approved one remains.
            ("credential.helper".to_owned(), OsString::new()),
            ("credential.useHttpPath".to_owned(), OsString::from("false")),
        ];
        if let Some(transport) = request.transport {
            settings.push((
                format!("protocol.{}.allow", transport.scheme()),
                OsString::from("always"),
            ));
        }
        // An ssh transport needs a program, and the only one it gets is the approved broker's.
        settings.push((
            "core.sshCommand".to_owned(),
            request
                .ssh_command
                .map_or_else(OsString::new, OsStr::to_owned),
        ));
        if let Some(helper) = request.credential_helper {
            settings.push(("credential.helper".to_owned(), helper.to_owned()));
        }
        // Every driver the repository defines, blanked by name. The names come from the audit,
        // which read the effective configuration, because the set of possible names is unbounded.
        for (section, driver) in &request.drivers {
            let keys = DRIVER_SECTIONS
                .iter()
                .find(|(name, _)| name == section)
                .map_or(&[] as &[(&str, &str)], |(_, keys)| *keys);
            for (key, blank) in keys {
                settings.push((format!("{section}.{driver}.{key}"), OsString::from(*blank)));
            }
        }
        settings
    }

    /// Builds the complete environment one invocation runs with.
    #[must_use]
    pub fn environment(&self, request: &GitRequest<'_>) -> Vec<(OsString, OsString)> {
        let mut path = OsString::from(
            self.git
                .program
                .parent()
                .unwrap_or_else(|| Path::new(""))
                .as_os_str(),
        );
        path.push(PATH_SEPARATOR);
        path.push(self.git.exec_path.as_os_str());
        let mut environment: Vec<(OsString, OsString)> = vec![
            (OsString::from("PATH"), path),
            (
                OsString::from("GIT_EXEC_PATH"),
                self.git.exec_path.as_os_str().to_owned(),
            ),
            (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
            (
                OsString::from("GIT_CONFIG_GLOBAL"),
                self.empty_config.as_os_str().to_owned(),
            ),
            (
                OsString::from("GIT_CONFIG_SYSTEM"),
                self.empty_config.as_os_str().to_owned(),
            ),
            (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
            (OsString::from("GIT_ASKPASS"), OsString::new()),
            (OsString::from("SSH_ASKPASS"), OsString::new()),
            (
                OsString::from("SSH_ASKPASS_REQUIRE"),
                OsString::from("never"),
            ),
            // A graphical askpass is chosen from this, so it names nothing.
            (OsString::from("DISPLAY"), OsString::new()),
            (OsString::from("GIT_PAGER"), OsString::from("cat")),
            (OsString::from("GIT_EDITOR"), OsString::from("false")),
            (
                OsString::from("GIT_SEQUENCE_EDITOR"),
                OsString::from("false"),
            ),
            (OsString::from("GIT_ATTR_NOSYSTEM"), OsString::from("1")),
            (
                OsString::from("GIT_NO_REPLACE_OBJECTS"),
                OsString::from("1"),
            ),
            (
                OsString::from("GIT_PROTOCOL_FROM_USER"),
                OsString::from("0"),
            ),
            (OsString::from("GIT_FLUSH"), OsString::from("1")),
            // Text this host parses, so the locale is fixed rather than the machine's.
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("TZ"), OsString::from("UTC")),
            (OsString::from("HOME"), self.home.as_os_str().to_owned()),
            // The transport allowlist, stated in the environment as well as in the configuration,
            // because this is the form a helper's own child inherits.
            (
                OsString::from("GIT_ALLOW_PROTOCOL"),
                request.transport.map_or_else(OsString::new, |transport| {
                    OsString::from(transport.scheme())
                }),
            ),
        ];
        // The overrides, as the environment form of `git -c`. Setting the count here also
        // neutralises an inherited one: the child's environment is built from nothing, so the only
        // key and value pairs Git reads are these.
        let overrides = self.overrides(request);
        environment.push((
            OsString::from("GIT_CONFIG_COUNT"),
            OsString::from(overrides.len().to_string()),
        ));
        for (index, (key, value)) in overrides.into_iter().enumerate() {
            environment.push((
                OsString::from(format!("GIT_CONFIG_KEY_{index}")),
                OsString::from(key),
            ));
            environment.push((OsString::from(format!("GIT_CONFIG_VALUE_{index}")), value));
        }
        if request.read_only {
            environment.push((OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")));
        }
        if let Some(ceiling) = request.ceiling {
            // Repository discovery stops here, so a command run in a staging directory never walks
            // upward into whatever happens to be above it.
            environment.push((
                OsString::from("GIT_CEILING_DIRECTORIES"),
                ceiling.as_os_str().to_owned(),
            ));
        }
        environment.extend(inherited_platform_environment(&self.home));
        environment
    }
}

/// Puts the child in a process group of its own, so ending it ends its descendants.
///
/// On Windows there is no equivalent that stays inside safe Rust: the containment there is a Job
/// Object, which is a call into `kernel32`, and this crate does not leave safe Rust. So a
/// cancellation on Windows ends the Git process and says it could not confirm the rest; the
/// qualification pass on Windows owns closing that.
#[cfg(unix)]
fn own_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

/// Puts the child in a process group of its own, so ending it ends its descendants.
#[cfg(not(unix))]
fn own_process_group(_command: &mut Command) {}

/// Ends a child and everything it started, and says whether it could confirm that.
#[cfg(unix)]
fn end_group(child: &mut std::process::Child) -> bool {
    let Ok(raw) = i32::try_from(child.id()) else {
        return false;
    };
    // The child leads its own group, so its identifier is the group's. Nothing else on this
    // machine is in it.
    let Some(pid) = rustix::process::Pid::from_raw(raw) else {
        return false;
    };
    let killed = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL).is_ok();
    let reaped = child.wait().is_ok();
    killed && reaped
}

/// Ends a child and everything it started, and says whether it could confirm that.
///
/// It could not: containment here is a Job Object, which is a call outside safe Rust and therefore
/// not in this crate. Ending the Git process leaves a remote helper, an ssh process or a credential
/// helper that Git started still running, so this returns false and the caller says the host could
/// not confirm that everything it started ended.
#[cfg(not(unix))]
fn end_group(child: &mut std::process::Child) -> bool {
    let _ = child.kill();
    let _ = child.wait();
    false
}

/// The separator between two entries of `PATH` on this platform.
#[cfg(windows)]
const PATH_SEPARATOR: &str = ";";
/// The separator between two entries of `PATH` on this platform.
#[cfg(not(windows))]
const PATH_SEPARATOR: &str = ":";

/// The Git executable's file name on this platform.
#[cfg(windows)]
const GIT_FILE_NAME: &str = "git.exe";
/// The Git executable's file name on this platform.
#[cfg(not(windows))]
const GIT_FILE_NAME: &str = "git";

/// The variables a child process needs from this platform to start at all.
///
/// On Unix there are none: a process starts with the environment it is given. On Windows the
/// loader itself reads several, and a process without them does not run, so they are passed
/// through by name. The home-shaped ones are pointed at the profile's own empty directory rather
/// than at the user's, so no user configuration file is reachable through them either.
#[cfg(windows)]
fn inherited_platform_environment(home: &Path) -> Vec<(OsString, OsString)> {
    let mut passed = Vec::new();
    for name in [
        "SystemRoot",
        "SYSTEMROOT",
        "windir",
        "WINDIR",
        "SystemDrive",
        "COMSPEC",
        "PATHEXT",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            passed.push((OsString::from(name), value));
        }
    }
    for name in ["USERPROFILE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"] {
        passed.push((OsString::from(name), home.as_os_str().to_owned()));
    }
    passed
}

/// The variables a child process needs from this platform to start at all.
#[cfg(not(windows))]
fn inherited_platform_environment(_home: &Path) -> Vec<(OsString, OsString)> {
    Vec::new()
}

/// One Git invocation, as the profile runs it.
#[derive(Clone, Debug)]
pub struct GitRequest<'a> {
    /// The directory Git runs in, passed as `-C`.
    pub directory: Option<&'a Path>,
    /// The arguments after the overrides.
    pub arguments: &'a [&'a OsStr],
    /// True when the invocation must leave the repository exactly as it found it.
    pub read_only: bool,
    /// The one transport this invocation is allowed to use, when it reaches a remote.
    pub transport: Option<RemoteTransport>,
    /// The approved credential broker's helper program, when the transport needs one.
    pub credential_helper: Option<&'a OsStr>,
    /// The approved broker's ssh program, when the transport is ssh.
    pub ssh_command: Option<&'a OsStr>,
    /// The driver sections and names the audit found, each blanked by name.
    pub drivers: Vec<(String, String)>,
    /// Where repository discovery stops.
    pub ceiling: Option<&'a Path>,
    /// How long it may run.
    pub deadline: Duration,
    /// The flag this invocation watches, when it belongs to a cancellable operation.
    pub cancel: Option<Arc<Cancellation>>,
}

impl<'a> GitRequest<'a> {
    /// A read that leaves the repository exactly as it found it.
    #[must_use]
    pub fn read(directory: &'a Path, arguments: &'a [&'a OsStr]) -> Self {
        Self {
            directory: Some(directory),
            arguments,
            read_only: true,
            transport: None,
            credential_helper: None,
            ssh_command: None,
            drivers: Vec::new(),
            ceiling: None,
            deadline: Duration::from_millis(GIT_READ_DEADLINE.get()),
            cancel: None,
        }
    }

    /// A write, which is one of the operations that create a repository or a working tree.
    #[must_use]
    pub fn write(directory: &'a Path, arguments: &'a [&'a OsStr]) -> Self {
        Self {
            read_only: false,
            ..Self::read(directory, arguments)
        }
    }

    /// Sets the drivers the audit found, so each is blanked by name.
    #[must_use]
    pub fn with_drivers(mut self, drivers: Vec<(String, String)>) -> Self {
        self.drivers = drivers;
        self
    }

    /// Sets how long the invocation may run.
    #[must_use]
    pub const fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    /// Sets the flag this invocation watches, so a cancellation ends the child it started.
    #[must_use]
    pub fn with_cancellation(mut self, cancel: Arc<Cancellation>) -> Self {
        self.cancel = Some(cancel);
        self
    }

    /// Sets where repository discovery stops.
    #[must_use]
    pub const fn with_ceiling(mut self, ceiling: &'a Path) -> Self {
        self.ceiling = Some(ceiling);
        self
    }

    /// Sets the one transport this invocation may use and the broker programs for it.
    #[must_use]
    pub const fn with_transport(
        mut self,
        transport: RemoteTransport,
        credential_helper: Option<&'a OsStr>,
        ssh_command: Option<&'a OsStr>,
    ) -> Self {
        self.transport = Some(transport);
        self.credential_helper = credential_helper;
        self.ssh_command = ssh_command;
        self
    }

    /// Returns the invocation as a person reads it: the subcommand, and how much followed it.
    ///
    /// Not the arguments. An argument is a path, a revision, a branch name or a remote the caller
    /// supplied, and a caller can put anything in one; `--initial-branch=access_token=…` is a
    /// branch name Git will reject and this string would otherwise carry. The subcommand is this
    /// host's own, checked against [`PERMITTED_SUBCOMMANDS`] before anything runs, so it is the
    /// one part of an invocation this host can vouch for.
    ///
    /// What a person needs beyond it comes from this host's own records rather than from the
    /// argument vector: which repository, which workspace, which destination, which remote as it
    /// was validated.
    #[must_use]
    pub fn describe(&self) -> String {
        let subcommand = self
            .arguments
            .first()
            .map(|argument| argument.to_string_lossy().into_owned())
            .filter(|argument| PERMITTED_SUBCOMMANDS.contains(&argument.as_str()))
            .unwrap_or_else(|| "no subcommand".to_owned());
        match self.arguments.len().saturating_sub(1) {
            0 => format!("git {subcommand}"),
            1 => format!("git {subcommand} with one argument"),
            rest => format!("git {subcommand} with {rest} arguments"),
        }
    }
}

/// What one Git invocation produced.
#[derive(Clone, Debug)]
pub struct GitOutput {
    /// Its exit code, or nothing when it ended on a signal.
    pub status: Option<i32>,
    /// True when it exited zero.
    pub success: bool,
    /// Its standard output, bounded.
    pub stdout: Vec<u8>,
    /// True when the output reached the bound and the rest was discarded.
    pub stdout_truncated: bool,
    /// Its standard error, with any credential-bearing URL removed.
    pub stderr: String,
    /// The invocation, as a person reads it.
    pub command: String,
}

impl GitOutput {
    /// Refuses a non-zero exit or a truncated output.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] naming the command, its status and its scrubbed output.
    pub fn require_success(&self) -> Result<()> {
        if !self.success {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} exited {} and said: {}",
                    self.command,
                    self.status
                        .map_or_else(|| "on a signal".to_owned(), |code| code.to_string()),
                    self.stderr.trim()
                ),
            });
        }
        if self.stdout_truncated {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} produced more than {MAX_GIT_OUTPUT_BYTES} bytes",
                    self.command
                ),
            });
        }
        Ok(())
    }

    /// Refuses when the output this host holds is not the whole of what Git wrote.
    ///
    /// A caller that reads the output without going through [`Self::require_success`] — one that
    /// treats a non-zero exit as an answer rather than a failure — needs this: a short read looks
    /// exactly like an empty answer, and an empty answer is a fact about the repository.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the standard output was cut short.
    pub fn require_complete(&self) -> Result<()> {
        if self.stdout_truncated {
            return Err(ProjectError::GitFailed {
                detail: format!(
                    "{} produced more output than this host could read, so what it said is not \
                     what this host holds",
                    self.command
                ),
            });
        }
        Ok(())
    }

    /// Returns the standard output as text.
    #[must_use]
    pub fn text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }
}

/// What the repository's own configuration says, and what has to be done about it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfigurationAudit {
    /// The driver sections and names to blank, as `("filter", "marker")`.
    ///
    /// The section is lowercase, because Git writes it that way. The name keeps the bytes the
    /// repository chose, because a configuration subsection is case-sensitive and an override
    /// spelled differently overrides nothing.
    pub drivers: Vec<(String, String)>,
    /// The execution-capable keys that an override empties.
    pub blanked: Vec<String>,
    /// The execution-capable keys no override removes.
    ///
    /// These are multi-valued or name the other side's program, so an override adds to them rather
    /// than replacing them. A *read* of such a repository is allowed and states the limitation; a
    /// record in this host's registry is not, because that is a promise to serve the repository
    /// including its remotes.
    pub refused: Vec<String>,
    /// The driver names this host cannot express as an override at all.
    ///
    /// A key that is not valid text, or whose subsection holds a control character, cannot be
    /// carried in an environment value. Whether it would run cannot be decided either way, so
    /// **every** operation on the repository is refused: a read that ran beside one of these could
    /// be a read that executed it.
    pub unexpressible: Vec<String>,
    /// The digest of the listing this audit was taken from.
    ///
    /// A caller compares it against a second reading to find out whether the configuration
    /// changed under an invocation. See [`ConfigurationAudit::unchanged`].
    pub digest: [u8; 32],
}

impl ConfigurationAudit {
    /// Reads one repository's effective configuration and classifies every key.
    ///
    /// The invocation itself executes nothing: `git config --list` reads files. It runs under the
    /// same profile, so the only configuration it can see is the repository's own.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::GitFailed`] when the configuration cannot be read.
    pub fn take(profile: &RestrictedProfile, directory: &Path) -> Result<Self> {
        let arguments: [&OsStr; 3] = [
            OsStr::new("config"),
            OsStr::new("--list"),
            OsStr::new("--null"),
        ];
        let request = GitRequest::read(directory, &arguments);
        let output = profile.run(&request)?;
        output.require_success()?;
        // The listing is classified from its bytes. Git accepts a configuration subsection that is
        // not valid text, and reading the listing lossily would hand this host a name with a
        // replacement character in it: the override would then be for a different key and the
        // driver would run.
        Ok(Self::classify_bytes(&output.stdout))
    }

    /// Classifies a `git config --list --null` listing.
    ///
    /// Separated from the invocation so the rules are tested against recorded listings on every
    /// platform rather than only against whatever this machine's Git happens to hold.
    #[must_use]
    pub fn classify(listing: &str) -> Self {
        Self::classify_bytes(listing.as_bytes())
    }

    /// Classifies a `git config --list --null` listing from its bytes.
    ///
    /// Git accepts a configuration subsection that is not valid text, so the listing is split and
    /// matched as bytes. A key this host cannot carry exactly — one that is not valid text, or
    /// whose subsection holds a control character — is refused rather than overridden wrongly.
    #[must_use]
    pub fn classify_bytes(listing: &[u8]) -> Self {
        let mut drivers: BTreeMap<(String, String), ()> = BTreeMap::new();
        let mut blanked = Vec::new();
        let mut refused = Vec::new();
        let mut unexpressible = Vec::new();
        for record in listing.split(|byte| *byte == 0) {
            if record.is_empty() {
                continue;
            }
            // Each record is `key` or `key\nvalue`. A key with no value is a boolean true.
            let key_bytes = record.split(|byte| *byte == b'\n').next().unwrap_or(record);
            let Ok(key) = std::str::from_utf8(key_bytes) else {
                // A key this host cannot read as text is one it cannot write as an override
                // either. Whether it names a driver cannot be decided, so the whole operation is
                // refused rather than run beside it.
                unexpressible.push(
                    "a configuration key this host cannot read as text, so it cannot be \
                     overridden either"
                        .to_owned(),
                );
                continue;
            };
            let lower = key.to_ascii_lowercase();
            // A driver's section and leaf are case-insensitive and Git writes them lowercase; its
            // subsection is case-sensitive and Git writes it verbatim. So the section and the leaf
            // are matched against the lowercase form and the name is taken from the key itself.
            if let (Some((section, lower_rest)), Some((_, rest))) =
                (lower.split_once('.'), key.split_once('.'))
                && let (Some((_, leaf)), Some((name, _))) =
                    (lower_rest.rsplit_once('.'), rest.rsplit_once('.'))
                && !name.is_empty()
                && DRIVER_SECTIONS.iter().any(|(known, keys)| {
                    *known == section && keys.iter().any(|(candidate, _)| *candidate == leaf)
                })
            {
                if name.chars().any(char::is_control) {
                    // A subsection with a control character in it is not a name this host can put
                    // in an environment value, so the driver cannot be neutralised and the
                    // operation is refused instead of run beside it.
                    unexpressible.push(format!(
                        "{section}.<a name holding a control character>.{leaf}"
                    ));
                } else {
                    drivers.insert((section.to_owned(), name.to_owned()), ());
                }
            }
            for rule in EXECUTION_KEYS {
                if rule.matches(&lower) {
                    // The key is matched against its lowercase form and recorded as it is
                    // written. A subsection is case-sensitive, and a key whose subsection holds a
                    // URL carries that URL's own case: recording the lowercase form would put a
                    // key in a diagnostic that is not the key the repository holds, and would
                    // hide a credential from the redaction that runs over it.
                    match rule.disposal {
                        Disposal::Blank => blanked.push(key.to_owned()),
                        Disposal::Refuse => refused.push(key.to_owned()),
                    }
                }
            }
        }
        blanked.sort_unstable();
        blanked.dedup();
        refused.sort_unstable();
        refused.dedup();
        unexpressible.sort_unstable();
        unexpressible.dedup();
        Self {
            drivers: drivers.into_keys().collect(),
            blanked,
            refused,
            unexpressible,
            digest: kr_cbor::sha256(listing),
        }
    }

    /// Refuses when the configuration changed between this audit and a later reading.
    ///
    /// The overrides an invocation runs with are built from the drivers *this* audit found, and a
    /// writer under the same operating-system account can add one afterwards. Nothing available
    /// through Git's own interface prevents that, so what the host does is notice: a second reading
    /// that differs means the result was produced under a configuration this host did not audit,
    /// and the result is refused rather than returned.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::IdentityChanged`] when the two readings differ.
    pub fn unchanged(&self, later: &Self) -> Result<()> {
        if self.digest == later.digest {
            return Ok(());
        }
        Err(ProjectError::IdentityChanged {
            detail: "this repository's configuration changed while the host was reading it, so \
                     what it read was produced under a configuration the host did not audit"
                .to_owned(),
        })
    }

    /// Returns the limitations this audit exposes, one line each.
    #[must_use]
    pub fn limitations(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for key in &self.blanked {
            lines.push(format!(
                "{} names {}, which this host does not execute for a repository operation",
                key_for_diagnostic(key),
                names_of(key)
            ));
        }
        for (section, name) in &self.drivers {
            lines.push(format!(
                "the {section} driver {} is defined and is not run, so content it would have \
                 converted is read as it is stored",
                subsection_for_diagnostic(name)
            ));
        }
        for key in &self.refused {
            lines.push(format!(
                "{} names {}, which no override removes, so an operation that would depend on it \
                 is refused",
                key_for_diagnostic(key),
                names_of(key)
            ));
        }
        for key in &self.unexpressible {
            lines.push(format!(
                "{} is a name this host cannot express as an override, so it does not read this \
                 repository at all",
                key_for_diagnostic(key)
            ));
        }
        lines
    }

    /// Refuses when this repository's configuration names something no override removes.
    ///
    /// This is the bar for taking a repository into the host's registry, which is a promise to
    /// serve it including its remotes. A read is allowed under the same configuration and states
    /// the limitation.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ConfigurationRejected`] naming every such key.
    pub fn require_neutralised(&self) -> Result<()> {
        self.require_expressible()?;
        if self.refused.is_empty() {
            return Ok(());
        }
        Err(ProjectError::ConfigurationRejected {
            detail: format!(
                "this repository's configuration names {}, which no override removes, so the \
                 operation is refused rather than run under it",
                names(&self.refused)
            ),
        })
    }

    /// Refuses when this repository's configuration names a driver this host cannot override.
    ///
    /// This is the bar for *every* operation, a read included: a driver whose name cannot be
    /// carried in an environment value is one whose override would be for a different key, so a
    /// status run beside it could be a status that executed it.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::ConfigurationRejected`] naming every such key.
    pub fn require_expressible(&self) -> Result<()> {
        if self.unexpressible.is_empty() {
            return Ok(());
        }
        Err(ProjectError::ConfigurationRejected {
            detail: format!(
                "this repository's configuration names {}, which this host cannot express as an \
                 override, so it does not read the repository at all rather than reading it beside \
                 something it cannot neutralise",
                names(&self.unexpressible)
            ),
        })
    }
}

/// Returns a list of configuration keys for a diagnostic, with nothing a subsection holds echoed.
fn names(keys: &[String]) -> String {
    keys.iter()
        .map(|key| key_for_diagnostic(key))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Returns one configuration key for a diagnostic, with an unsafe subsection replaced.
///
/// A configuration key is `section.subsection.leaf`, and the subsection is whatever the repository
/// chose: `[url "https://token@host/"] insteadOf = …` puts a credential in it. A URL redaction is
/// the wrong instrument for that, because a subsection is not a URL. It is arbitrary text that can
/// hold a quote, a control character or nothing at all, and every review of this branch found one
/// more shape a URL parser read wrongly. So a subsection that *could* carry a credential is not
/// parsed and not echoed: it is replaced, and the section, the leaf and a fingerprint are what a
/// person gets. Those are enough to find the key in the file and to tell two keys apart.
fn key_for_diagnostic(key: &str) -> String {
    let (Some(first), Some(last)) = (key.find('.'), key.rfind('.')) else {
        // No subsection at all. `core.pager` holds nothing a repository chose.
        return key.to_owned();
    };
    if first == last {
        return key.to_owned();
    }
    let section = &key[..first];
    let subsection = &key[first + 1..last];
    let leaf = &key[last + 1..];
    format!("{section}.{}.{leaf}", subsection_for_diagnostic(subsection))
}

/// Returns one configuration subsection for a diagnostic, replaced where it could carry a secret.
///
/// A subsection that holds none of the characters a credential needs is repeated as it is, because
/// naming the remote or the driver is the whole use of the diagnostic. Anything else is replaced
/// by its length and a fingerprint of its bytes: a person can still tell two keys apart and find
/// the one the message is about, and nothing the repository chose is echoed.
fn subsection_for_diagnostic(subsection: &str) -> String {
    // Repeated only when it is a *name*: ASCII letters, digits and the three characters a name
    // uses. A remote, a driver and a filter are all named that way; a URL, a query and anything
    // holding a credential are not. An allowlist rather than a list of characters to look out for,
    // because the list of characters to look out for is what thirteen reviews kept extending.
    let is_a_name = !subsection.is_empty()
        && subsection.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        });
    if is_a_name {
        return subsection.to_owned();
    }
    format!(
        "..a-name-of-{}-characters-this-host-does-not-repeat-{}..",
        subsection.chars().count(),
        fingerprint(subsection)
    )
}

/// Returns what one execution-capable key names, for a diagnostic.
fn names_of(key: &str) -> &'static str {
    EXECUTION_KEYS
        .iter()
        .find(|rule| rule.matches(key))
        .map_or("a program", |rule| rule.names)
}

/// Returns what this host says about text Git wrote, which is never the text.
///
/// Git's standard error is a configuration *value* as often as a message, and a value is
/// unconstrained: `bad boolean config value 'user:TOKEN+1<tab>@host:x'`, and Git cuts its own
/// diagnostics off at four kilobytes, so the part that reaches this host can be a credential with
/// every character of punctuation removed by the truncation. Fourteen reviews of this service each
/// found one more shape a rule over that text read wrongly, and the last two found shapes with no
/// URL and no punctuation in them at all. There is no rule over unconstrained text that tells a
/// secret from a message.
///
/// So this host does not repeat it. What it says instead is the class Git itself names in its
/// first word — `fatal`, `error`, `warning`, `hint` — with how much text there was and a
/// fingerprint of it, so two failures can be told apart and one can be recognised again. What
/// carries the *meaning* of a failure is this host's own text: which invocation, which exit code,
/// which repository and workspace, which destination, all from its own records rather than from
/// Git's mouth.
#[must_use]
pub fn git_said(text: &str) -> String {
    let trimmed = text.trim();
    let class = ["fatal", "error", "warning", "hint"]
        .into_iter()
        .find(|class| trimmed.starts_with(&format!("{class}:")))
        .unwrap_or("nothing this host recognises");
    if trimmed.is_empty() {
        return "nothing".to_owned();
    }
    format!(
        "{class}, in ..{}-characters-this-host-does-not-repeat-{}..",
        trimmed.chars().count(),
        fingerprint(trimmed)
    )
}

/// Removes anything a caller or a repository supplied that this host cannot vouch for, whole.
///
/// Git's own standard error reaches a caller and a journal, and what it holds is the repository's
/// text: a URL, a configuration key, a configuration value, a key with a URL and a space inside
/// the quotes Git puts round it, or the first four kilobytes of any of those, because Git truncates
/// its own diagnostics. Thirteen reviews of this service looked for the credential in that text and
/// each found one more place it was not: past a space, past a tab, past the truncation, in the
/// half of a word the search had already approved.
///
/// The lesson is the one those thirteen findings have in common. **A fragment that holds no
/// credential punctuation is not evidence that the text is safe**, because the punctuation may be
/// in the next word or in the part Git cut off. So the decision is taken over the whole text, and
/// it is one question: does this text hold anything a URL or a credential is made of? A `://`
/// anywhere, or any character outside the set below, and the **whole** text is replaced by its
/// length and a fingerprint of its bytes. Otherwise it is repeated as Git wrote it.
///
/// The set is a letter, a digit, whitespace, or one of `- _ . , ; : ( ) ! ' * + ~ /`. So
/// `fatal: not a git repository (or any of the parent directories): .git`,
/// `fatal: bad boolean config value 'invalid' for 'diff.review.binary'` and
/// `fatal: could not open '/Users/someone/work/x/.git/config'` all come back as Git wrote them,
/// and any message with a URL in it does not. What a person loses in that case is Git's own words
/// about a remote; what they keep is this host's own description of the invocation and the remote
/// on the operation's record, which is a remote validated to carry no credential.
///
/// The limit, stated rather than implied: a secret that is *itself* an ordinary word — a bare
/// token with no punctuation, echoed as a configuration value — is indistinguishable from an
/// ordinary word, and this repeats it. Nothing short of repeating none of Git's text would not.
#[must_use]
pub fn redact(text: &str) -> String {
    if text.contains("://") || !text.chars().all(repeatable) {
        // The whole text, because the part that looks harmless may be the half of a credential
        // whose `@` is in the next word or past Git's own truncation.
        return replacement(text);
    }
    text.to_owned()
}

/// Returns whether one character is one this host repeats from text Git wrote.
///
/// A letter, a digit, whitespace, or punctuation that cannot carry a credential or make one piece
/// of text pose as another. Anything else, including every character of user information, a query,
/// a fragment and an escape, and every non-ASCII letter, means the text it is in is replaced.
fn repeatable(character: char) -> bool {
    character.is_ascii_alphanumeric()
        || character.is_whitespace()
        || matches!(
            character,
            '-' | '_' | '.' | ',' | ';' | ':' | '(' | ')' | '!' | '\'' | '*' | '+' | '~' | '/'
        )
}

/// Returns the stand-in for text this host will not repeat.
///
/// Every character of it is one [`repeatable`] allows, which makes the rule idempotent: a message
/// whose untrusted fragment has already been replaced passes the next application unchanged. That
/// matters because the rule is applied twice on purpose, once where a message is composed and
/// again where every message leaves, and a second pass that fingerprinted the first one's output
/// would take away the host's own words and make a retained copy differ from the answer the caller
/// already had.
fn replacement(text: &str) -> String {
    format!(
        "..{}-characters-this-host-does-not-repeat-{}..",
        text.chars().count(),
        fingerprint(text)
    )
}

/// Returns the first eight bytes of one piece of text's digest, as hexadecimal.
///
/// Enough to tell two replaced pieces of text apart and to recognise one again, and not enough to
/// be the text.
fn fingerprint(text: &str) -> String {
    let digest = kr_cbor::sha256(text.as_bytes());
    let mut out = String::with_capacity(16);
    for byte in &digest[..8] {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// What a bounded read produced.
#[derive(Debug, Default)]
struct Bounded {
    bytes: Vec<u8>,
    truncated: bool,
}

/// How long a reader thread may go on holding a pipe after the Git process has ended.
///
/// A descendant Git started can keep a pipe open after Git itself is gone, and a reader waiting on
/// one would hold this call for as long as that descendant lives. So the wait is bounded and what
/// was read so far is what the caller gets, with the shortfall reported.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(5);

/// One pipe being read, and the bytes read so far.
struct Reader {
    handle: std::thread::JoinHandle<Result<()>>,
    read: Arc<Mutex<Bounded>>,
}

/// Waits for one bounded reader, for no longer than [`PIPE_DRAIN_GRACE`].
///
/// What the caller gets back is what has been read when the wait ends, whether that is the whole
/// of the output or the part of it that arrived before something Git started stopped closing the
/// pipe. A short read is reported: `truncated` is what every checked caller refuses on, so a
/// partial answer is never mistaken for a complete one.
fn join(reader: Option<Reader>, request: &GitRequest<'_>) -> Result<Bounded> {
    let Some(reader) = reader else {
        return Ok(Bounded::default());
    };
    let deadline = Instant::now() + PIPE_DRAIN_GRACE;
    let mut ran_out = false;
    while !reader.handle.is_finished() {
        if Instant::now() >= deadline {
            // Something Git started still holds the pipe. The thread owns its own end and goes
            // when the pipe closes; this call does not wait for it.
            ran_out = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if ran_out {
        let held = reader.read.lock().map_err(|_| ProjectError::GitFailed {
            detail: format!(
                "{} produced output this host could not read",
                request.describe()
            ),
        })?;
        return Ok(Bounded {
            bytes: held.bytes.clone(),
            truncated: true,
        });
    }
    let outcome = reader.handle.join().map_err(|_| ProjectError::GitFailed {
        detail: format!(
            "{} produced output this host could not read",
            request.describe()
        ),
    })?;
    let held = reader.read.lock().map_err(|_| ProjectError::GitFailed {
        detail: format!(
            "{} produced output this host could not read",
            request.describe()
        ),
    })?;
    outcome?;
    Ok(Bounded {
        bytes: held.bytes.clone(),
        truncated: held.truncated,
    })
}

/// Reads one pipe to its end, keeping at most [`MAX_GIT_OUTPUT_BYTES`].
///
/// Reading continues past the bound and discards, because a child whose output nobody reads stops
/// on a full pipe and would then be killed for running past its deadline instead of reported for
/// producing too much.
fn read_bounded<R: std::io::Read + Send + 'static>(pipe: R) -> Reader {
    let read = Arc::new(Mutex::new(Bounded::default()));
    let held = Arc::clone(&read);
    let handle = std::thread::spawn(move || {
        let mut pipe = pipe;
        let ceiling = usize::try_from(MAX_GIT_OUTPUT_BYTES).unwrap_or(usize::MAX);
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    // The shared buffer is what a caller whose wait runs out reads, so each chunk
                    // goes into it as it arrives rather than at the end.
                    let mut kept = held.lock().map_err(|_| ProjectError::GitFailed {
                        detail: "a pipe reader could not reach its own buffer".to_owned(),
                    })?;
                    let room = ceiling.saturating_sub(kept.bytes.len());
                    if read > room {
                        kept.bytes.extend_from_slice(&buffer[..room]);
                        kept.truncated = true;
                    } else {
                        kept.bytes.extend_from_slice(&buffer[..read]);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(ProjectError::staging(error)),
            }
        }
        Ok(())
    });
    Reader { handle, read }
}

/// Finds one program on the process's own `PATH`.
fn search_path(file_name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(file_name))
        .find(|candidate| candidate.is_file())
}

/// Asks the resolved binary one question with an environment of nothing.
fn ask(program: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .env_clear()
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| ProjectError::GitUnavailable {
            detail: format!(
                "{} {} could not run: {error}",
                program.display(),
                arguments.join(" ")
            ),
        })?;
    if !output.status.success() {
        return Err(ProjectError::GitUnavailable {
            detail: format!(
                "{} {} exited {}",
                program.display(),
                arguments.join(" "),
                output
                    .status
                    .code()
                    .map_or_else(|| "on a signal".to_owned(), |code| code.to_string())
            ),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Reads the major and minor version out of `git --version`.
fn parse_version(reported: &str) -> Option<(u32, u32)> {
    let figures = reported
        .split_whitespace()
        .find(|word| word.starts_with(|character: char| character.is_ascii_digit()))?;
    let mut parts = figures.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts
        .next()?
        .split(|character: char| !character.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    Some((major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_text_holding_what_a_url_is_made_of_survives_a_message() {
        // Thirteen reviews of this service each found one more place the credential was not: past
        // a space, past a tab, past Git's own truncation, in the half of a word a search had
        // already approved. So the decision is taken over the whole text.
        let shapes = [
            "url.https://a.invalid/p,https://user:VERYSECRET@b.invalid/x.insteadof",
            "https://a.invalid/p?access_token=VERYSECRET",
            "https://a.invalid/p?next=https://b.invalid/x&access_token=VERYSECRET after",
            "https://a.invalid/p,\u{e9}https://user:VERYSECRET@b.invalid/x",
            "https://a.invalid,https://user:VERYSECRET@b.invalid/x?q=1",
            "https://o'brien:VERYSECRET@b.invalid/x",
            "https://b.invalid/x?access_token=prefix'VERYSECRET",
            "ssh://user:VERYSECRET@b.invalid/x",
            "https://VERYSECRET@b.invalid/x",
            "https://VERYSECRET:x-oauth-basic@b.invalid/x",
            "fatal: bad boolean config value 'invalid' for \
             'diff.https://b.invalid/x?next=\"quoted\"&access_token=VERYSECRET.binary'",
            "fatal: bad boolean config value 'invalid' for \
             'diff.https://b.invalid/x?next=\"two words\"&access_token=VERYSECRET.binary'",
            "fatal: bad boolean config value 'ssh:///user:VERYSECRET@b.invalid/../safe' for \
             'diff.review.binary'",
            "fatal: bad boolean config value 'ssh:///user:VERYSECRET@b.invalid/%2e%2e/safe'",
            // The two review 13 found: the `@` in the *next* word, and a diagnostic Git cut off
            // before it reached the `@` at all.
            "fatal: bad boolean config value 'https://user:VERYSECRET+123\t@b.invalid/x'",
            "fatal: bad boolean config value 'https://VERYSECRET:aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ];
        for shape in shapes {
            let redacted = redact(shape);
            assert!(
                !redacted.contains("VERYSECRET"),
                "no text holding what a URL is made of survives: {shape} became {redacted}"
            );
            assert!(
                redacted.contains("does-not-repeat"),
                "and what it replaced is named: {shape} became {redacted}"
            );
        }
        // What a person reads survives whole: Git's own words, a path, a quoted configuration key.
        // A message naming a URL does not, and the invocation's own description carries the remote
        // instead.
        for plain in [
            "fatal: not a git repository (or any of the parent directories): .git",
            "fatal: bad boolean config value 'invalid' for 'diff.review.binary'",
            "error: pathspec 'x' did not match any file(s) known to git",
            "fatal: could not open '/Users/someone/work/repository/.git/config'",
            "Couldn't connect to server",
            "no url here",
            "  spaced\tout\n",
        ] {
            assert_eq!(
                redact(plain),
                plain,
                "a message with nothing in it a URL is made of is repeated whole"
            );
        }
        // And a message that does name a URL is replaced whole, credential or not, because a
        // fragment that looks harmless may be half of one.
        let redacted = redact("fatal: unable to access 'https://github.com/user/repo.git/'");
        assert!(redacted.starts_with(".."), "{redacted}");
        assert!(redacted.contains("does-not-repeat"), "{redacted}");
    }

    #[test]
    fn what_git_said_is_named_by_its_class_and_never_repeated() {
        // A configuration value is unconstrained text, and Git cuts its own diagnostics off at
        // four kilobytes, so the part that reaches this host can be a credential with every
        // character of punctuation removed by the truncation. There is no rule over that text
        // that tells a secret from a message, so none is repeated.
        let truncated = format!(
            "fatal: bad boolean config value 'user:VERYSECRET+123{}",
            "a".repeat(4000)
        );
        for said in [
            truncated.as_str(),
            "fatal: bad boolean config value 'user:VERYSECRET+123\t@b.invalid:x' for 'd.r.binary'",
            "error: something VERYSECRET happened",
            "warning: VERYSECRET",
            "hint: VERYSECRET",
            "VERYSECRET with no class at all",
        ] {
            let told = git_said(said);
            assert!(
                !told.contains("VERYSECRET"),
                "nothing Git said is repeated: {said} became {told}"
            );
            assert!(
                told.contains("does-not-repeat"),
                "and what it stands for is named: {told}"
            );
        }
        // The class Git names is the one thing repeated, because Git chose it rather than the
        // repository, and it is what a person reads first.
        assert!(git_said("fatal: x").starts_with("fatal,"));
        assert!(git_said("error: x").starts_with("error,"));
        assert!(git_said("warning: x").starts_with("warning,"));
        assert!(git_said("hint: x").starts_with("hint,"));
        assert!(git_said("something else").starts_with("nothing this host recognises,"));
        assert_eq!(git_said("   "), "nothing");
        // Two different messages are two different fingerprints, so a failure can be recognised
        // again and two can be told apart.
        assert_ne!(git_said("fatal: one"), git_said("fatal: two"));
        // And what it says survives the rule, because the rule is applied again at every boundary
        // a message crosses.
        let told = git_said("fatal: bad boolean config value 'https://user:VERYSECRET@b/x'");
        assert_eq!(
            redact(&told),
            told,
            "what Git said is already safe to repeat"
        );
    }

    #[test]
    fn the_rule_leaves_its_own_output_alone() {
        // The rule is applied twice on purpose: where a message is composed, and again where every
        // message leaves. A second pass that replaced the first one's output would take away this
        // host's own words and make a retained copy differ from the answer the caller already had.
        for text in [
            "https://user:VERYSECRET@b.invalid/x",
            "access_token=VERYSECRET",
            "a message with no secret in it",
            "",
        ] {
            let once = redact(text);
            assert_eq!(redact(&once), once, "{text} became {once} and then changed");
        }
        // A whole message keeps this host's own words when the untrusted part of it is already
        // replaced, which is the point of making the stand-in repeatable.
        let composed = format!("{} is not a branch name", redact("access_token=VERYSECRET"));
        assert_eq!(redact(&composed), composed, "{composed}");
        assert!(composed.ends_with(" is not a branch name"), "{composed}");
        assert!(!composed.contains("VERYSECRET"), "{composed}");
    }

    #[test]
    fn a_version_is_read_from_what_git_prints_on_every_platform() {
        assert_eq!(parse_version("git version 2.50.1"), Some((2, 50)));
        assert_eq!(
            parse_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        assert_eq!(parse_version("git version 2.45.2.windows.1"), Some((2, 45)));
        assert_eq!(parse_version("git version 2.32"), Some((2, 32)));
        assert_eq!(parse_version("no version here"), None);
    }

    #[test]
    fn every_driver_a_repository_defines_is_found_by_name() {
        // The set of driver names is whatever the repository chose, so the overrides are built
        // from the configuration that is there. A driver the audit missed is a driver that runs.
        let listing = concat!(
            "filter.marker.clean\0/tmp/marker clean\0",
            "filter.marker.smudge\0/tmp/marker smudge\0",
            "filter.marker.required\0true\0",
            "diff.planted.textconv\0/tmp/marker textconv\0",
            "merge.planted.driver\0/tmp/marker merge\0",
            "core.bare\0false\0",
        );
        let audit = ConfigurationAudit::classify(listing);
        assert_eq!(
            audit.drivers,
            vec![
                ("diff".to_owned(), "planted".to_owned()),
                ("filter".to_owned(), "marker".to_owned()),
                ("merge".to_owned(), "planted".to_owned()),
            ]
        );
    }

    #[test]
    fn a_found_driver_is_blanked_by_name_and_a_boolean_is_set_rather_than_emptied() {
        let profile = test_profile();
        let arguments: [&OsStr; 1] = [OsStr::new("status")];
        let request = GitRequest::read(Path::new("/tree"), &arguments)
            .with_drivers(vec![("filter".to_owned(), "marker".to_owned())]);
        let overrides = profile.overrides(&request);
        let named = |key: &str| {
            overrides
                .iter()
                .find(|(candidate, _)| candidate == key)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(named("filter.marker.clean"), Some(OsString::new()));
        assert_eq!(named("filter.marker.smudge"), Some(OsString::new()));
        assert_eq!(named("filter.marker.process"), Some(OsString::new()));
        // An empty boolean is a malformed value Git stops on, so this one is set rather than
        // emptied.
        assert_eq!(
            named("filter.marker.required"),
            Some(OsString::from("false"))
        );
        // The hook directory is the profile's empty one, whatever the repository says.
        assert_eq!(
            named("core.hooksPath"),
            Some(OsString::from("/state/git-profile/hooks"))
        );
        assert_eq!(named("core.fsmonitor"), Some(OsString::from("false")));
        assert_eq!(named("diff.external"), Some(OsString::new()));
        // No transport was named, so every one of them stays refused.
        assert_eq!(named("protocol.allow"), Some(OsString::from("never")));
        assert!(
            overrides
                .iter()
                .all(|(key, _)| !key.starts_with("protocol.https")),
            "no transport is allowed back without one being named"
        );
        // A read passes the flag that stops an index write, and nothing else touches the tree.
        let argv = profile.argument_vector(&request);
        assert!(argv.contains(&OsString::from("--no-optional-locks")));
        assert!(argv.contains(&OsString::from("--no-pager")));
        // The environment is built rather than inherited, so what Git reads is exactly this.
        let environment = profile.environment(&request);
        let value = |name: &str| {
            environment
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            value("GIT_CONFIG_NOSYSTEM"),
            Some(OsString::from("1")),
            "the system configuration file is not read"
        );
        assert_eq!(
            value("GIT_CONFIG_GLOBAL"),
            Some(OsString::from("/state/git-profile/empty-config"))
        );
        // The overrides travel as key and value pairs, and the count is theirs.
        let count = value("GIT_CONFIG_COUNT").expect("the count is set");
        assert_eq!(
            count.to_string_lossy().parse::<usize>().expect("a count"),
            overrides.len(),
            "every override is carried"
        );
        let carried: Vec<(OsString, OsString)> = (0..overrides.len())
            .map(|index| {
                (
                    value(&format!("GIT_CONFIG_KEY_{index}")).expect("a key"),
                    value(&format!("GIT_CONFIG_VALUE_{index}")).expect("a value"),
                )
            })
            .collect();
        assert_eq!(
            carried,
            overrides
                .iter()
                .map(|(key, value)| (OsString::from(key), value.clone()))
                .collect::<Vec<_>>(),
            "in the order the overrides are applied"
        );
        assert_eq!(value("GIT_TERMINAL_PROMPT"), Some(OsString::from("0")));
        assert_eq!(value("GIT_OPTIONAL_LOCKS"), Some(OsString::from("0")));
        assert_eq!(value("GIT_ALLOW_PROTOCOL"), Some(OsString::new()));
        assert_eq!(
            value("HOME"),
            Some(OsString::from("/state/git-profile/home")),
            "no user configuration file is reachable through the home directory"
        );
        assert_eq!(
            value("PATH"),
            Some(OsString::from(format!(
                "/usr/bin{PATH_SEPARATOR}/usr/libexec/git-core"
            ))),
            "a remote helper somewhere else on the user's path is not reachable"
        );
        // Every program-naming variable Git reads is absent unless the profile put it there.
        for name in [
            "GIT_EXTERNAL_DIFF",
            "GIT_SSH",
            "GIT_SSH_COMMAND",
            "GIT_TEMPLATE_DIR",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_TRACE",
        ] {
            assert!(
                value(name).is_none(),
                "{name} is not in the child's environment"
            );
        }
        // The configuration overrides are not on the command line, because `-c` splits its
        // argument at the first equals sign and a driver's name may hold one.
        assert!(
            !argv.contains(&OsString::from("-c")),
            "no override travels as a command-line setting"
        );
    }

    #[test]
    fn a_named_transport_is_allowed_back_and_the_broker_supplies_the_only_programs() {
        let profile = test_profile();
        let arguments: [&OsStr; 1] = [OsStr::new("clone")];
        let helper = OsString::from("/usr/libexec/git-core/git-credential-osxkeychain");
        let request = GitRequest::write(Path::new("/stage"), &arguments).with_transport(
            RemoteTransport::Https,
            Some(helper.as_os_str()),
            None,
        );
        let overrides = profile.overrides(&request);
        let helpers: Vec<&OsString> = overrides
            .iter()
            .filter(|(key, _)| key == "credential.helper")
            .map(|(_, value)| value)
            .collect();
        // The list is emptied and then holds exactly the approved broker's helper.
        assert_eq!(helpers.len(), 2);
        assert_eq!(helpers[0], &OsString::new());
        assert_eq!(helpers[1], &helper);
        assert!(
            overrides
                .iter()
                .any(|(key, value)| key == "protocol.https.allow" && value == "always")
        );
        assert!(
            overrides
                .iter()
                .any(|(key, value)| key == "protocol.allow" && value == "never")
        );
        // No ssh command was supplied, so the one Git could use is nothing.
        assert!(
            overrides
                .iter()
                .any(|(key, value)| key == "core.sshCommand" && value.is_empty())
        );
        let environment = profile.environment(&request);
        assert!(
            environment
                .iter()
                .any(|(name, value)| name == "GIT_ALLOW_PROTOCOL" && value == "https")
        );
        // A write does not pass the read-only flags.
        let argv = profile.argument_vector(&request);
        assert!(!argv.contains(&OsString::from("--no-optional-locks")));
    }

    #[test]
    fn an_execution_capable_key_is_either_blanked_or_refused_and_never_ignored() {
        let listing = concat!(
            "core.fsmonitor\0/tmp/marker fsmonitor\0",
            "core.hookspath\0/tmp/hooks\0",
            "core.pager\0/tmp/marker pager\0",
            "diff.external\0/tmp/marker external\0",
            "credential.helper\0/tmp/marker credential\0",
            "credential.https://example.invalid.helper\0/tmp/marker scoped\0",
            "core.sshcommand\0/tmp/marker ssh\0",
            "remote.origin.vcs\0planted\0",
            "url.https://example.invalid/.insteadof\0kr:\0",
            "uploadpack.packobjectshook\0/tmp/marker pack\0",
        );
        let audit = ConfigurationAudit::classify(listing);
        assert_eq!(
            audit.blanked,
            vec![
                "core.fsmonitor",
                "core.hookspath",
                "core.pager",
                "core.sshcommand",
                "credential.helper",
                "credential.https://example.invalid.helper",
                "diff.external",
                "uploadpack.packobjectshook",
            ]
        );
        assert_eq!(
            audit.refused,
            vec![
                "remote.origin.vcs",
                "url.https://example.invalid/.insteadof"
            ]
        );
        // A refusal is a refusal, not a warning: the operation does not run under it.
        let refusal = audit.require_neutralised().expect_err("it is refused");
        assert!(
            refusal.to_string().contains("remote.origin.vcs"),
            "the refusal names the key: {refusal}"
        );
        // Everything found is exposed as a limitation, which is what section 14 asks for in place
        // of executing the helper.
        let limitations = audit.limitations();
        assert!(
            limitations
                .iter()
                .any(|line| line.contains("core.fsmonitor") && line.contains("filesystem-monitor")),
            "the fsmonitor limitation is stated: {limitations:?}"
        );
    }

    #[test]
    fn a_configuration_this_host_can_neutralise_entirely_is_not_refused() {
        let audit = ConfigurationAudit::classify(
            "core.bare\0false\0core.repositoryformatversion\0{}\0"
                .replace("{}", "0")
                .as_str(),
        );
        assert!(audit.refused.is_empty());
        assert!(audit.blanked.is_empty());
        assert!(audit.drivers.is_empty());
        audit
            .require_neutralised()
            .expect("nothing needs refusing here");
    }

    #[test]
    fn a_credential_in_a_diagnostic_is_removed_rather_than_shown() {
        // The shapes a remote's own diagnostic carries. Each is replaced whole, so the shape it
        // was in does not matter, and nothing of the message survives to be pieced together.
        for carrying in [
            "fatal: could not read https://user:secret@example.invalid/x.git",
            // A token is often the *user* of an https URL, so it goes whether or not it has a
            // password half.
            "fatal: https://ghp_TOKEN:x-oauth-basic@example.invalid/x.git",
            "fatal: https://ghp_TOKEN@example.invalid/x.git",
            "ssh://git:secret@example.invalid/x.git",
            "first https://one:SECRETA@one.invalid/x then https://two:SECRETB@two.invalid/y",
            // An ssh login name is not a secret and it goes anyway, because this host does not
            // decide from a shape which user information is a login name and which is a token.
            // What a caller keeps instead is this host's own description of the invocation, which
            // names the remote it validated.
            "ssh://git@example.invalid/x.git",
        ] {
            let redacted = redact(carrying);
            for secret in [
                "secret",
                "ghp_TOKEN",
                "SECRETA",
                "SECRETB",
                "example.invalid",
            ] {
                assert!(!redacted.contains(secret), "{carrying} became {redacted}");
            }
            assert!(redacted.contains("does-not-repeat"), "{redacted}");
        }
        assert_eq!(redact("nothing to redact"), "nothing to redact");
    }

    #[test]
    fn a_driver_name_keeps_the_bytes_the_repository_chose() {
        // A configuration subsection is case-sensitive, and Git writes it verbatim. An override
        // spelled differently overrides nothing, so the audit keeps the name it read.
        let audit = ConfigurationAudit::classify(
            "filter.Mixed.clean\0echo\0filter.with=equals.clean\0echo\0",
        );
        assert_eq!(
            audit.drivers,
            vec![
                ("filter".to_owned(), "Mixed".to_owned()),
                ("filter".to_owned(), "with=equals".to_owned()),
            ]
        );
        let profile = test_profile();
        let arguments: [&OsStr; 1] = [OsStr::new("status")];
        let request =
            GitRequest::read(Path::new("/tree"), &arguments).with_drivers(audit.drivers.clone());
        let overrides = profile.overrides(&request);
        assert!(
            overrides
                .iter()
                .any(|(key, value)| key == "filter.Mixed.clean" && value.is_empty()),
            "the mixed-case driver is overridden under its own name"
        );
        // A key holding an equals sign is expressible only in the environment form, which is why
        // the overrides travel there: the key and the value are separate variables.
        let environment = profile.environment(&request);
        let keys: Vec<String> = environment
            .iter()
            .filter(|(name, _)| name.to_string_lossy().starts_with("GIT_CONFIG_KEY_"))
            .map(|(_, value)| value.to_string_lossy().into_owned())
            .collect();
        assert!(
            keys.iter().any(|key| key == "filter.with=equals.clean"),
            "a driver whose name holds an equals sign is overridden exactly: {keys:?}"
        );
    }

    #[test]
    fn a_driver_name_this_host_cannot_express_is_refused_rather_than_left_alone() {
        let audit = ConfigurationAudit::classify("filter.bad\u{1}name.clean\0echo\0");
        assert!(audit.drivers.is_empty());
        let refusal = audit
            .require_neutralised()
            .expect_err("a name this host cannot carry is refused");
        // The refusal names the section and the leaf. It does not repeat the name itself, which
        // is the whole point: a name this host cannot express is a name it will not echo either.
        let refusal = refusal.to_string();
        assert!(refusal.contains("filter."), "{refusal}");
        assert!(refusal.contains(".clean"), "{refusal}");
        assert!(refusal.contains("cannot express"), "{refusal}");
        assert!(
            !refusal.contains("badname") && !refusal.contains('\u{1}'),
            "and nothing of the name is in it: {refusal}"
        );
    }

    #[test]
    fn a_configuration_that_changed_under_a_reading_is_refused_rather_than_returned() {
        // The overrides an invocation runs with are the drivers the audit found. A writer that
        // adds one afterwards is not something Git's interface lets this host prevent, so what it
        // does is notice.
        let first = ConfigurationAudit::classify("core.bare\0false\0");
        let same = ConfigurationAudit::classify("core.bare\0false\0");
        first.unchanged(&same).expect("nothing changed");
        let later = ConfigurationAudit::classify("core.bare\0false\0filter.new.clean\0echo\0");
        let refusal = first
            .unchanged(&later)
            .expect_err("a configuration that changed is refused");
        assert_eq!(refusal.code(), kr_protocol::error::ErrorCode::SourceChanged);
    }

    #[test]
    fn an_abbreviated_or_attached_option_is_refused_like_its_whole_form() {
        // Git's own subcommand parser accepts an unambiguous abbreviation, and a short option may
        // carry its value attached, so both forms are refused as the whole form is.
        for refused in [
            "--conf=filter.x.clean=sh",
            "--config=filter.x.clean=sh",
            "--config-e=core.pager=sh",
            "-cfilter.x.clean=sh",
            "--upload-pack=sh",
            "--upl=sh",
            "--attr-source=HEAD",
            "--recurse-submodules",
            "--separate-git-dir=/tmp/x",
            "--super-prefix=x",
        ] {
            let arguments = [OsStr::new("clone"), OsStr::new(refused)];
            assert!(
                check_arguments(&arguments).is_err(),
                "{refused} is not an argument this service passes"
            );
        }
        // And the forms this service does pass are still accepted.
        for permitted in [
            "--porcelain=v2",
            "--untracked-files=all",
            "--ignored=matching",
            "--ignore-submodules=all",
            "--no-renames",
            "--detach",
            "--no-hardlinks",
            "--no-checkout",
            "--template=",
            "--origin=origin",
            "--initial-branch=main",
            "--end-of-options",
            "--path-format=absolute",
        ] {
            let arguments = [OsStr::new("status"), OsStr::new(permitted)];
            check_arguments(&arguments)
                .unwrap_or_else(|error| panic!("{permitted} is one this service passes: {error}"));
        }
    }

    /// A profile whose directories are named but never created, for the tests that read its lists.
    fn test_profile() -> RestrictedProfile {
        RestrictedProfile {
            git: GitProgram {
                program: PathBuf::from("/usr/bin/git"),
                exec_path: PathBuf::from("/usr/libexec/git-core"),
                version: "git version 2.50.1".to_owned(),
            },
            empty_config: PathBuf::from("/state/git-profile/empty-config"),
            hooks: PathBuf::from("/state/git-profile/hooks"),
            template: PathBuf::from("/state/git-profile/template"),
            home: PathBuf::from("/state/git-profile/home"),
        }
    }

    #[test]
    fn a_key_rule_matches_a_whole_key_or_a_per_section_one() {
        let fsmonitor = EXECUTION_KEYS
            .iter()
            .find(|rule| rule.pattern == "core.fsmonitor")
            .expect("the rule is in the table");
        assert!(fsmonitor.matches("core.fsmonitor"));
        assert!(!fsmonitor.matches("core.fsmonitorhookversion"));
        let vcs = EXECUTION_KEYS
            .iter()
            .find(|rule| rule.pattern == "remote.*.vcs")
            .expect("the rule is in the table");
        assert!(vcs.matches("remote.origin.vcs"));
        assert!(vcs.matches("remote.other.name.vcs"));
        assert!(!vcs.matches("remote..vcs"));
        assert!(!vcs.matches("vcs"));
        assert!(!vcs.matches("other.origin.vcs"));
    }
}
