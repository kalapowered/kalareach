//! What `kr host restart` compares before it stops a daemon: how the daemon was started against what
//! the start this installation chooses gives.
//!
//! A restart starts a daemon as `kr new` does, not as the stopped daemon was started, so a daemon
//! that was started with something a start does not give would come back without it. The comparison
//! is by meaning and not by text:
//!
//! - The two roots and `--own-session` belong to the start, and are not compared. `--starter` is the
//!   Windows task's own.
//! - `--secret-store file` is a difference only where a daemon started without it would not find
//!   the device keys: on a platform with no file fallback, and where the store's own record names the
//!   platform store. Where the fallback exists and nothing names the platform store, the daemon
//!   falls back to the file store by itself.
//! - Every other argument is a difference: `--worker`, and `--seed` in a build that has it.
//! - The variables that decide where the host keeps something are compared with this command's own,
//!   for the standalone start alone: that start gives the daemon this command's environment. A
//!   service manager gives its own.
//! - The working directory is compared only where a path the daemon was given is relative to it, and
//!   again for the standalone start alone, which works in the state directory.
//!
//! A launch the daemon could not state is not compared: the restart goes on, because a start that
//! fails after the stop says so and loses nothing.

use std::path::Path;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_crypto::store::StoreKind;
use kr_protocol::hostinfo::configuration::{ControllerStartup, path_variables};
use kr_protocol::ids::EnvironmentId;
use kr_protocol::update::HostLaunch;

/// What the daemon was started with that the start does not give.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Differences {
    /// The arguments, by name: only this program's own names are said.
    arguments: Vec<&'static str>,
    /// The daemon keeps its device keys in the file store, and a daemon started without
    /// `--secret-store file` would look for them in the platform store.
    file_store: bool,
    /// The variables that differ, by name.
    variables: Vec<&'static str>,
    /// The daemon works in a directory that a path it was given is relative to, and the start works
    /// in another.
    directory: bool,
}

/// What the store's record says, for the platform this build is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Record {
    /// The record could not be read: a daemon started without the file store would not read it
    /// either.
    Unreadable,
    /// The record names a store, or none has been chosen yet.
    Named(Option<StoreKind>),
}

impl Differences {
    /// Whether the start gives everything the daemon was started with.
    pub(crate) fn is_none(&self) -> bool {
        self.arguments.is_empty()
            && !self.file_store
            && self.variables.is_empty()
            && !self.directory
    }

    /// What the command says when it refuses: what the daemon was started with, why a restart
    /// would not give it, and what a person does. Nothing was stopped.
    pub(crate) fn said(&self, id: EnvironmentId) -> Shown {
        let mut parts: Vec<Shown> = Vec::new();
        if !self.arguments.is_empty() || self.file_store {
            let mut names: Vec<Shown> = self
                .arguments
                .iter()
                .map(|name| Shown::said(name))
                .collect();
            if self.file_store {
                names.push(Shown::said("--secret-store file"));
            }
            parts.push(shown!(
                "the {} {}",
                if names.len() == 1 {
                    "argument"
                } else {
                    "arguments"
                },
                Shown::joined(names, ", ")
            ));
        }
        if !self.variables.is_empty() {
            let names: Vec<Shown> = self
                .variables
                .iter()
                .map(|name| Shown::said(name))
                .collect();
            parts.push(shown!(
                "{} {} set to values that this command's environment does not have",
                if names.len() == 1 {
                    "the variable"
                } else {
                    "the variables"
                },
                Shown::joined(names, ", ")
            ));
        }
        if self.directory {
            parts.push(Shown::said(
                "a working directory that a path it was given is relative to",
            ));
        }
        let store = if self.file_store {
            Shown::said(
                " Its device keys are in the file store, and a daemon started without \
                 --secret-store file looks for them in the platform store and does not start.",
            )
        } else {
            Shown::said("")
        };
        let only_variables = self.arguments.is_empty() && !self.file_store && !self.directory;
        let tail = if only_variables {
            Shown::said(
                "Run kr host restart again with the same variables set in this command's \
                 environment, or run kr host stop and start kr-controller yourself the way it \
                 was started.",
            )
        } else {
            Shown::said("Run kr host stop and start kr-controller yourself the way it was started.")
        };
        shown!(
            "The control daemon for environment {} was started with {}, and kr host restart \
             starts it without them.{} Nothing was stopped. {}",
            id,
            Shown::joined(parts, "; and with "),
            store,
            tail
        )
    }
}

/// Whether a daemon started with `--secret-store file` and one started without it keep their device
/// keys in different stores.
const fn file_store_is_a_difference(file_fallback: bool, record: Record) -> bool {
    !file_fallback
        || matches!(
            record,
            Record::Unreadable | Record::Named(Some(StoreKind::Platform))
        )
}

/// Compares how the daemon was started with the start `start` gives.
///
/// `own_variable` is this command's own value of a variable, and `start_directory` is where the
/// standalone start works.
pub(crate) fn compare(
    launch: &HostLaunch,
    start: ControllerStartup,
    start_directory: &Path,
    file_fallback: bool,
    record: Record,
    own_variable: impl Fn(&str) -> Option<String>,
) -> Differences {
    let mut found = Differences::default();
    let mut file_store = false;
    let mut arguments = launch.arguments.iter();
    while let Some(argument) = arguments.next() {
        let (name, inline) = match argument.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value)),
            _ => (argument.as_str(), None),
        };
        // The value of a flag that takes one: the next argument, unless it was given inline.
        let mut value = || inline.or_else(|| arguments.next().map(String::as_str));
        match name {
            "--runtime-dir" | "--state-dir" => {
                value();
            }
            "--own-session" | "--starter" => {}
            "--secret-store" => file_store |= value() == Some("file"),
            "--worker" => {
                value();
                found.arguments.push("--worker");
            }
            "--seed" => found.arguments.push("--seed"),
            // A value that follows a flag this program does not know is not a flag.
            other if !other.starts_with("--") => {}
            _ => found
                .arguments
                .push("an argument that this command does not know"),
        }
    }
    found.arguments.dedup();
    found.file_store = file_store && file_store_is_a_difference(file_fallback, record);
    if start == ControllerStartup::Standalone {
        found.variables = path_variables()
            .filter(|name| {
                let theirs = launch
                    .variables
                    .iter()
                    .find(|variable| variable.name == *name)
                    .and_then(|variable| variable.value.0.clone());
                theirs != own_variable(name)
            })
            .collect();
        let relative = launch.variables.iter().any(|variable| {
            variable
                .value
                .0
                .as_deref()
                .is_some_and(|value| !value.is_empty() && !Path::new(value).is_absolute())
        });
        found.directory = relative && Path::new(&launch.directory) != start_directory;
    }
    found
}

/// What this program reads of the platform and the store's record, for [`compare`].
pub(crate) fn compare_here(
    launch: &HostLaunch,
    start: ControllerStartup,
    environment: &kr_ipc::paths::EnvironmentPaths,
) -> Differences {
    let record = match kr_crypto::store::recorded_store_kind(&environment.secrets_dir()) {
        Ok(kind) => Record::Named(kind),
        Err(_) => Record::Unreadable,
    };
    compare(
        launch,
        start,
        environment.state_dir(),
        kr_crypto::store::FILE_FALLBACK_SUPPORTED,
        record,
        |name| std::env::var_os(name).map(|value| value.to_string_lossy().into_owned()),
    )
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Nullable;
    use kr_protocol::update::HostLaunchVariable;

    use super::*;

    fn launched(arguments: &[&str]) -> HostLaunch {
        HostLaunch {
            arguments: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            variables: Vec::new(),
            directory: "/state".to_owned(),
        }
    }

    fn compared(arguments: &[&str], file_fallback: bool, record: Record) -> Differences {
        compare(
            &launched(arguments),
            ControllerStartup::Standalone,
            Path::new("/state"),
            file_fallback,
            record,
            |_| None,
        )
    }

    /// What a start gives is no difference: the roots, the session flag and the Windows starter's
    /// flag, spelled with a space or with an equals sign.
    #[test]
    fn what_a_start_gives_is_no_difference() {
        let none = compared(
            &[
                "--runtime-dir",
                "/run",
                "--state-dir=/state",
                "--own-session",
                "--starter",
            ],
            true,
            Record::Named(None),
        );
        assert!(none.is_none(), "{none:?}");
    }

    /// The worker and the seed are differences, whatever the platform, and a value that follows a
    /// flag is not read as a flag.
    #[test]
    fn a_worker_and_a_seed_are_differences() {
        let found = compared(
            &["--worker", "/bin/worker", "--seed", "--runtime-dir", "/run"],
            true,
            Record::Named(None),
        );
        assert_eq!(found.arguments, vec!["--worker", "--seed"]);
        assert!(!found.is_none());
        let unknown = compared(&["--other"], true, Record::Named(None));
        assert_eq!(
            unknown.arguments,
            vec!["an argument that this command does not know"]
        );
    }

    /// The file store is a difference where there is no file fallback, and where the record names
    /// the platform store or cannot be read; it is none where the fallback is there and nothing
    /// names the platform store. The platform store named by `--secret-store platform` is none.
    #[test]
    fn the_file_store_is_a_difference_only_where_a_daemon_without_it_would_not_find_the_keys() {
        let file = ["--secret-store", "file"];
        assert!(compared(&file, false, Record::Named(None)).file_store);
        assert!(compared(&file, true, Record::Named(Some(StoreKind::Platform))).file_store);
        assert!(compared(&file, true, Record::Unreadable).file_store);
        assert!(!compared(&file, true, Record::Named(None)).file_store);
        assert!(!compared(&file, true, Record::Named(Some(StoreKind::FileFallback))).file_store);
        assert!(
            compared(&["--secret-store=file"], false, Record::Named(None)).file_store,
            "the inline spelling is the same argument"
        );
        assert!(
            compared(&["--secret-store", "platform"], false, Record::Named(None)).is_none(),
            "the platform store is what a start gives"
        );
    }

    /// Variables are compared for the standalone start alone, by the name this program has for
    /// them, and the working directory only where a path that the daemon has is relative to it.
    #[test]
    fn variables_are_compared_for_the_standalone_start_and_the_directory_where_a_path_is_relative()
    {
        let name = path_variables().next().expect("a variable that locates");
        let mut launch = launched(&[]);
        launch.variables = vec![HostLaunchVariable {
            name: name.to_owned(),
            value: Nullable(Some("elsewhere".to_owned())),
        }];
        launch.directory = "/other".to_owned();
        let own = |variable: &str| (variable == name).then(|| "here".to_owned());
        let standalone = compare(
            &launch,
            ControllerStartup::Standalone,
            Path::new("/state"),
            true,
            Record::Named(None),
            own,
        );
        assert_eq!(standalone.variables, vec![name]);
        assert!(
            standalone.directory,
            "a relative value and another directory"
        );
        let service = compare(
            &launch,
            ControllerStartup::Service,
            Path::new("/state"),
            true,
            Record::Named(None),
            own,
        );
        assert!(
            service.is_none(),
            "a manager gives its own environment: {service:?}"
        );
        // A path that is absolute on the platform that runs the case: a value without a drive is
        // relative on Windows.
        let absolute_path = if cfg!(windows) {
            r"C:\absolute"
        } else {
            "/absolute"
        };
        launch.variables[0].value = Nullable(Some(absolute_path.to_owned()));
        let absolute = compare(
            &launch,
            ControllerStartup::Standalone,
            Path::new("/state"),
            true,
            Record::Named(None),
            |variable| (variable == name).then(|| absolute_path.to_owned()),
        );
        assert!(
            absolute.is_none(),
            "the same value and an absolute path: {absolute:?}"
        );
    }
}
