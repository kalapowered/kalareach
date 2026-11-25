//! Checks of what stays outside the two host roots and is read from no tree: the program the daemon
//! finds as Git, the values it inherits from the harness's own environment, the shell packages and
//! the daemon's log. Each returns the lines that refuse.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::Access;

use crate::run::{RootPin, open_file_below};

/// What the daemon is given from outside the run's tree, and the log it appends to.
#[derive(Clone, Debug)]
pub struct Outside<'a> {
    /// The run's directory.
    pub run_root: &'a Path,
    /// The directory `run_root` was pinned as.
    pub pin: &'a RootPin,
    /// The daemon's search path, the value of its `PATH`.
    pub search_path: &'a str,
    /// The values the daemon inherits from the harness's own environment, by name.
    pub inherited: &'a [(&'a str, Option<OsString>)],
    /// The prefix of the shell packages, where the daemon is given one.
    pub shell_packages: Option<&'a Path>,
    /// The daemon's log, relative to the run's directory.
    pub log: &'a Path,
}

impl Outside<'_> {
    /// Every refusal, one line each: none where nothing outside the roots could change what a
    /// restarted daemon runs or reads.
    #[must_use]
    pub fn refusals(&self) -> Vec<String> {
        let mut refused = Vec::new();
        let canonical =
            std::fs::canonicalize(self.run_root).unwrap_or_else(|_| self.run_root.to_path_buf());
        let in_the_tree =
            |path: &Path| path.starts_with(self.run_root) || path.starts_with(&canonical);
        if let Some(git) = self.git() {
            let resolved = std::fs::canonicalize(&git).unwrap_or_else(|_| git.clone());
            if in_the_tree(&git) || in_the_tree(&resolved) {
                refused.push(
                    "the Git program that the daemon's search path finds lies in the run's tree"
                        .to_owned(),
                );
            } else if writable(&git) || writable(&resolved) {
                refused.push(
                    "the Git program that the daemon's search path finds, or the directory that \
                     holds it, can be written by the account"
                        .to_owned(),
                );
            }
        }
        for (name, value) in self.inherited {
            let Some(value) = value else { continue };
            let said = value.to_string_lossy();
            let names_the_tree = [self.run_root, canonical.as_path()]
                .iter()
                .any(|root| said.contains(&*root.to_string_lossy()));
            if names_the_tree {
                refused.push(format!(
                    "{name} is given to the daemon from the harness's own environment and names a \
                     place in the run's tree"
                ));
            }
        }
        if let Some(packages) = self.shell_packages {
            let resolved =
                std::fs::canonicalize(packages).unwrap_or_else(|_| packages.to_path_buf());
            if in_the_tree(packages) || in_the_tree(&resolved) {
                refused.push("the shell packages lie in the run's tree".to_owned());
            }
        }
        let class = match open_file_below(self.run_root, self.pin, self.log) {
            Ok(Some(_)) => None,
            Ok(None) => Some("it is not there".to_owned()),
            Err(why) => Some(why.to_string()),
        };
        if let Some(class) = class {
            refused.push(format!(
                "the daemon's log is not a regular file with one name: {class}"
            ));
        }
        refused
    }

    /// The program the daemon's search path finds as `git`: the first file of that name with an
    /// execute bit, in the order of the path.
    fn git(&self) -> Option<PathBuf> {
        self.search_path
            .split(':')
            .map(|directory| Path::new(directory).join("git"))
            .find(|candidate| {
                std::fs::metadata(candidate)
                    .is_ok_and(|found| found.is_file() && found.permissions().mode() & 0o111 != 0)
            })
    }
}

/// Whether the account can write the file at `path` or the directory that holds it.
fn writable(path: &Path) -> bool {
    let can = |place: &Path| rustix::fs::access(place, Access::WRITE_OK).is_ok();
    can(path) || path.parent().is_some_and(can)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A run directory of this test's own with a daemon log in it, and its pin.
    fn world(name: &str) -> (PathBuf, RootPin) {
        let base = if cfg!(target_os = "macos") {
            PathBuf::from("/private/tmp")
        } else {
            std::fs::canonicalize(std::env::temp_dir()).expect("the temporary directory")
        };
        let root = base.join(format!(
            "ko-{name}-{}",
            &kr_ipc::new_uuid().to_string()[..8]
        ));
        std::fs::create_dir_all(&root).expect("a run directory");
        std::fs::write(root.join("controller.log"), b"log").expect("a log");
        let pin = RootPin::of(&root).expect("a pin");
        (root, pin)
    }

    /// An executable file `git` in the directory `directory`.
    fn a_git_in(directory: &Path) {
        std::fs::create_dir_all(directory).expect("a directory");
        std::fs::write(directory.join("git"), b"#!/bin/sh\n").expect("a program");
        std::fs::set_permissions(
            directory.join("git"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("executable");
    }

    fn refusals(
        root: &Path,
        pin: &RootPin,
        search_path: &str,
        inherited: &[(&str, Option<OsString>)],
        packages: Option<&Path>,
    ) -> Vec<String> {
        Outside {
            run_root: root,
            pin,
            search_path,
            inherited,
            shell_packages: packages,
            log: Path::new("controller.log"),
        }
        .refusals()
    }

    fn clean(root: &Path) {
        std::fs::remove_dir_all(root).expect("clean up");
    }

    /// A run with its log and the system's own search path and no inherited value that names the
    /// tree is refused by none of the checks.
    #[test]
    fn nothing_is_refused_for_the_systems_git_and_values_outside_the_tree() {
        let (root, pin) = world("clear");
        let outside = std::env::temp_dir();
        let none = refusals(
            &root,
            &pin,
            "/usr/bin:/bin",
            &[
                ("XDG_RUNTIME_DIR", Some(OsString::from("/run/user/1000"))),
                (
                    "DBUS_SESSION_BUS_ADDRESS",
                    Some(OsString::from("unix:path=/run/user/1000/bus")),
                ),
                ("UNSET", None),
            ],
            Some(&outside.join("not-in-the-run")),
        );
        assert_eq!(none, Vec::<String>::new());
        clean(&root);
    }

    /// A Git the search path finds inside the run's tree is refused, by its path or through a link
    /// that leads there.
    #[test]
    fn a_git_inside_the_run_tree_is_refused() {
        let (root, pin) = world("git-in-tree");
        a_git_in(&root.join("b"));
        let found = refusals(
            &root,
            &pin,
            &format!("{}:/usr/bin", root.join("b").display()),
            &[],
            None,
        );
        assert_eq!(
            found,
            ["the Git program that the daemon's search path finds lies in the run's tree"]
        );
        // The first match is the one that counts: a Git ahead of the one in the tree is the one
        // the daemon runs, and a link to the tree is the tree.
        let outside =
            std::env::temp_dir().join(format!("kg-{}", &kr_ipc::new_uuid().to_string()[..8]));
        std::fs::create_dir_all(&outside).expect("a directory outside the run");
        std::os::unix::fs::symlink(root.join("b/git"), outside.join("git")).expect("a link");
        let found = refusals(&root, &pin, &outside.display().to_string(), &[], None);
        assert_eq!(
            found,
            ["the Git program that the daemon's search path finds lies in the run's tree"]
        );
        std::fs::remove_dir_all(&outside).expect("clean up");
        clean(&root);
    }

    /// A Git that the account can write, or whose directory it can write, is refused.
    #[test]
    fn a_git_the_account_can_write_is_refused() {
        if rustix::process::getuid().is_root() {
            eprintln!("skipping: a privileged process writes everywhere");
            return;
        }
        let (root, pin) = world("git-writable");
        let outside =
            std::env::temp_dir().join(format!("kw-{}", &kr_ipc::new_uuid().to_string()[..8]));
        a_git_in(&outside);
        let said = "the Git program that the daemon's search path finds, or the directory that \
                    holds it, can be written by the account";
        assert_eq!(
            refusals(&root, &pin, &outside.display().to_string(), &[], None),
            [said]
        );
        // A program the account cannot write in a directory it cannot write is not refused.
        std::fs::set_permissions(outside.join("git"), std::fs::Permissions::from_mode(0o555))
            .expect("read only");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o555))
            .expect("read only");
        assert_eq!(
            refusals(&root, &pin, &outside.display().to_string(), &[], None),
            Vec::<String>::new()
        );
        // A directory the account can write is enough, whatever the program's own mode.
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o755))
            .expect("writable");
        assert_eq!(
            refusals(&root, &pin, &outside.display().to_string(), &[], None),
            [said]
        );
        std::fs::remove_dir_all(&outside).expect("clean up");
        clean(&root);
    }

    /// An inherited value that names a place in the run's tree is refused, by the name of the
    /// variable; a value that names the tree among other text is too.
    #[test]
    fn an_inherited_value_that_names_the_run_tree_is_refused() {
        let (root, pin) = world("inherited");
        let runtime = root.join("r");
        let bus = format!("unix:path={}/bus,guid=1", root.join("r").display());
        let found = refusals(
            &root,
            &pin,
            "/usr/bin:/bin",
            &[
                ("XDG_RUNTIME_DIR", Some(runtime.into_os_string())),
                ("DBUS_SESSION_BUS_ADDRESS", Some(OsString::from(bus))),
            ],
            None,
        );
        assert_eq!(
            found,
            [
                "XDG_RUNTIME_DIR is given to the daemon from the harness's own environment and \
                 names a place in the run's tree",
                "DBUS_SESSION_BUS_ADDRESS is given to the daemon from the harness's own \
                 environment and names a place in the run's tree"
            ]
        );
        clean(&root);
    }

    /// A shell-packages prefix inside the run's tree is refused, also through a link into it.
    #[test]
    fn a_shell_packages_prefix_inside_the_run_tree_is_refused() {
        let (root, pin) = world("packages");
        std::fs::create_dir_all(root.join("h/shells")).expect("a prefix in the tree");
        let said = ["the shell packages lie in the run's tree"];
        assert_eq!(
            refusals(
                &root,
                &pin,
                "/usr/bin:/bin",
                &[],
                Some(&root.join("h/shells"))
            ),
            said
        );
        let outside =
            std::env::temp_dir().join(format!("kp-{}", &kr_ipc::new_uuid().to_string()[..8]));
        std::os::unix::fs::symlink(root.join("h/shells"), &outside).expect("a link into the tree");
        assert_eq!(
            refusals(&root, &pin, "/usr/bin:/bin", &[], Some(&outside)),
            said
        );
        std::fs::remove_file(&outside).expect("clean up");
        clean(&root);
    }

    /// A log that is a link, a log with a second name, and a log that is gone are refused, each with
    /// what is found.
    #[test]
    fn a_daemon_log_that_is_a_link_has_a_second_name_or_is_gone_is_refused() {
        let (root, pin) = world("log");
        let log = root.join("controller.log");
        let said = |class: &str| {
            vec![format!(
                "the daemon's log is not a regular file with one name: {class}"
            )]
        };
        std::fs::remove_file(&log).expect("removed");
        assert_eq!(
            refusals(&root, &pin, "/usr/bin:/bin", &[], None),
            said("it is not there")
        );
        std::fs::write(root.join("elsewhere"), b"a file of the person's").expect("a file");
        std::os::unix::fs::symlink(root.join("elsewhere"), &log).expect("a link at the log");
        assert_eq!(
            refusals(&root, &pin, "/usr/bin:/bin", &[], None),
            said("an entry on the way is a symbolic link, which is followed by nothing")
        );
        std::fs::remove_file(&log).expect("removed");
        std::fs::write(&log, b"log").expect("a log");
        std::fs::hard_link(&log, root.join("second-name")).expect("a second name");
        assert_eq!(
            refusals(&root, &pin, "/usr/bin:/bin", &[], None),
            said("the file has more than one name, which is refused and read through by nothing")
        );
        clean(&root);
    }
}
