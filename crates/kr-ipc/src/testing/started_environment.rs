//! The environment a test gives a program it starts, when that program may run a session's shell.
//!
//! A session's shell starts as a login shell, and a login shell reads the startup files of the
//! home folder it is given. A program a test starts inherits the test program's environment, so
//! without this the home folder is the person's own: the result of a case then depends on the
//! person's profile, and the commands in that profile run inside the case. On a machine whose
//! profile names a removable volume in its search path, the system asks the person to allow the
//! worker's shell to read that volume.
//!
//! [`StartedEnvironment`] is what every harness that starts a controller, a worker, a `kr` command
//! that starts one, or a session gives that program instead: a home folder and a working folder
//! inside the case's own temporary root, the system folders alone as the search path, and nothing
//! else of the test program's environment. The test program's own environment is never changed,
//! since a program with threads must not change it; the environment is given to the started
//! program, or, for a daemon the test runs in its own process, to the daemon as the environment its
//! sessions are started with.
//!
//! On Windows a session's shell reads the account's PowerShell profile, which this does not give a
//! home to: there a started program keeps the test program's environment and is given only the
//! working folder.

use std::path::{Path, PathBuf};
use std::process::Command;

use kr_protocol::session::EnvironmentVariable;

/// The search path a started program has: the system's folders and no other.
pub const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The name of the folder inside the root that a started program has as its home.
const HOME_NAME: &str = "home";

/// The name of the folder inside the root that a started program works in.
const WORKING_NAME: &str = "work";

/// The two variables through which a program reaches the user's own service manager on Linux, for
/// the daemon that must choose that manager (`systemctl --user` needs one of them): a daemon a test
/// starts keeps them through [`StartedEnvironment::apply_keeping`], and a session's snapshot never
/// does.
pub const USER_MANAGER_VARIABLES: [&str; 2] = ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"];

/// The variable that names where a started program makes its temporary files. It is passed on
/// because the case's own root was made under it, so a program that makes a socket or a file there
/// makes it beside the root rather than in another place on the machine.
#[cfg(unix)]
const TEMPORARY_DIRECTORY: &str = "TMPDIR";

/// A home folder and a working folder inside a case's temporary root, and the environment that
/// names them.
#[derive(Clone, Debug)]
pub struct StartedEnvironment {
    home: PathBuf,
    working_directory: PathBuf,
}

impl StartedEnvironment {
    /// Makes a new empty home folder and a working folder inside `root`.
    ///
    /// # Panics
    ///
    /// Panics when a folder cannot be made, which in a test means the environment is unusable
    /// rather than that the case under test failed.
    #[must_use]
    pub fn within(root: &Path) -> Self {
        let home = root.join(HOME_NAME);
        let working_directory = root.join(WORKING_NAME);
        for folder in [&home, &working_directory] {
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(folder)
                .unwrap_or_else(|error| panic!("{} could not be made: {error}", folder.display()));
        }
        Self {
            home,
            working_directory,
        }
    }

    /// The home folder a started program is given.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// Gives `command` this environment and working folder, and returns it for the caller to add
    /// what its own case needs by name.
    ///
    /// Nothing of the test program's environment passes but the temporary directory's name. On
    /// Windows the environment is left as it is and only the working folder is set.
    pub fn apply<'a>(&self, command: &'a mut Command) -> &'a mut Command {
        self.apply_keeping(command, &[])
    }

    /// As [`Self::apply`], and passes on the variables of the test program's environment that
    /// `kept` names, for the one whose case starts a program that reads them.
    pub fn apply_keeping<'a>(&self, command: &'a mut Command, kept: &[&str]) -> &'a mut Command {
        command.current_dir(&self.working_directory);
        #[cfg(unix)]
        {
            command
                .env_clear()
                .env("PATH", SYSTEM_PATH)
                .env("HOME", &self.home);
            for name in std::iter::once(&TEMPORARY_DIRECTORY).chain(kept) {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
        #[cfg(not(unix))]
        let _ = kept;
        command
    }

    /// The variables a test's own create request carries so that the session's shell has this
    /// home.
    ///
    /// A visible create from a client takes the creator's snapshot of the environment and nothing
    /// of the daemon's, and the worker adds no home to it: a login shell that is given none reads
    /// the startup files of the account's own home, which the account database names, and neither
    /// the test program's home nor a recorder in this one sees the read. Every maker of create
    /// parameters in a test puts this into its snapshot.
    ///
    /// On Windows it is empty: a session's shell there reads the PowerShell profile, which no
    /// variable of this kind gives a home to.
    #[must_use]
    pub fn snapshot_home(&self) -> Vec<EnvironmentVariable> {
        #[cfg(unix)]
        {
            vec![EnvironmentVariable {
                name: "HOME".to_owned(),
                value: self.home.display().to_string(),
            }]
        }
        #[cfg(not(unix))]
        {
            Vec::new()
        }
    }

    /// The environment a daemon that runs inside the test's own process starts its sessions with
    /// when the session's creator brought none, for the test to give it through
    /// `Controller::set_host_environment`.
    ///
    /// The daemon reads the environment of its process once, at its start, and the test gives it
    /// this after the start returns. A run that the daemon resumes from its journal at its start,
    /// and a trigger that is due, can create a session before the test's next line runs, and that
    /// session has the test program's own environment, so a case that restarts a daemon over such a
    /// run is not covered by this.
    ///
    /// On Windows it is the test program's own environment, as the daemon would have read it.
    #[must_use]
    pub fn host_variables(&self) -> Vec<(String, String)> {
        #[cfg(unix)]
        {
            let mut variables = vec![
                ("PATH".to_owned(), SYSTEM_PATH.to_owned()),
                ("HOME".to_owned(), self.home.display().to_string()),
            ];
            if let Some(value) =
                std::env::var_os(TEMPORARY_DIRECTORY).and_then(|v| v.into_string().ok())
            {
                variables.push((TEMPORARY_DIRECTORY.to_owned(), value));
            }
            variables
        }
        #[cfg(not(unix))]
        {
            std::env::vars_os()
                .filter_map(|(name, value)| {
                    Some((name.into_string().ok()?, value.into_string().ok()?))
                })
                .collect()
        }
    }
}
