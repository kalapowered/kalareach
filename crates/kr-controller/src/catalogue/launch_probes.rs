//! The doctor's reading of each admitted package's launch probe.
//!
//! A package can declare how to read the mode its application runs in: the application's own
//! diagnostic and where in what it prints the mode is. A launch the worker starts runs the
//! declaration where the worker owns the launch's environment, and records the word it read in the
//! launch's profile; this host starts no such launch. The doctor runs the same declaration here,
//! for the executable this daemon's own search path names, and says what it read word for word: a
//! person asking `kr doctor` how a launch would go sees the mode the application is configured for
//! without starting one. The daemon runs it in its own environment and directory, which a launch's
//! may differ from, and says that beside the answer.
//!
//! A probe runs only while the installation holds the capability the owner confirmed it under,
//! checked as the worker checks it: from the connector read under the grants these admissions
//! give. A package whose release declares one and whose installation does not hold it is reported
//! as not granted, and nothing is run.

use std::path::{Path, PathBuf};

use kr_protocol::hostinfo::{LaunchProbeReport, LaunchProbeState};
use kr_protocol::scalars::Nullable;
use kr_worker::broker::catalogue::{ReadPackage, Reading};
use kr_worker::broker::connectors::InstalledConnector;

/// The most probe reports the doctor's answer carries.
pub const MAX_REPORTS: usize = 64;

/// The probe reports of the packages `reading` holds that declare a probe, in package order, and
/// no more than [`MAX_REPORTS`] of them.
///
/// It resolves each package's executable on `search_path`, runs the probes against them in
/// `directory`, and belongs on a thread that may block: each probe is given the time its own
/// deadline allows.
#[must_use]
pub fn report(
    reading: &Reading,
    search_path: &[PathBuf],
    directory: &Path,
) -> Vec<LaunchProbeReport> {
    let mut reports = Vec::new();
    for (package, read) in &reading.packages {
        let Ok(ReadPackage::Connector(connector)) = read else {
            continue;
        };
        if connector.manifest().launch_probe.is_none() {
            continue;
        }
        reports.push(one(
            package.plugin_id.as_str(),
            package.version.as_str(),
            connector,
            search_path,
            directory,
        ));
    }
    reports.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    reports.truncate(MAX_REPORTS);
    reports
}

fn one(
    plugin_id: &str,
    version: &str,
    connector: &InstalledConnector,
    search_path: &[PathBuf],
    directory: &Path,
) -> LaunchProbeReport {
    let report = |state: LaunchProbeState,
                  executable: Option<&Path>,
                  mode: Option<String>,
                  reason: Option<String>| LaunchProbeReport {
        plugin_id: plugin_id.to_owned(),
        version: version.to_owned(),
        state,
        executable: Nullable(executable.map(|path| path.display().to_string())),
        mode: Nullable(mode),
        reason: Nullable(reason),
    };
    let Some(probe) = connector.launch_probe() else {
        return report(LaunchProbeState::NotGranted, None, None, None);
    };
    let Some(executable) = executable_of(connector, search_path) else {
        return report(LaunchProbeState::NoExecutable, None, None, None);
    };
    // A launch starts a program and not the script a package manager puts in front of it, and so
    // does a probe: what the search finds first is what would be run.
    if !kr_worker::broker::commands::starts_directly(&executable) {
        return report(
            LaunchProbeState::NotRead,
            Some(&executable),
            None,
            Some(format!(
                "first hit is {}, a script or shim that is not started directly, so its mode was \
                 not read",
                executable.display()
            )),
        );
    }
    // The doctor holds no launch, so no options of one are carried.
    let probed = kr_worker::broker::probe::run(&executable, probe, &[], directory);
    match probed.mode {
        Some(mode) => report(LaunchProbeState::Read, Some(&executable), Some(mode), None),
        None => report(
            LaunchProbeState::NotRead,
            Some(&executable),
            None,
            probed.unread,
        ),
    }
}

/// The first executable one of the connector's match rules names on `search_path`, as a shell's
/// search finds it, that the connector recognises.
fn executable_of(connector: &InstalledConnector, search_path: &[PathBuf]) -> Option<PathBuf> {
    connector
        .manifest()
        .match_rules
        .iter()
        .filter_map(|rule| super::integrations::resolve(&rule.executable.file_stem, search_path))
        .find(|path| connector.matches_executable(&path.display().to_string()))
}

#[cfg(test)]
mod tests {
    use kr_plugin_sdk::capability::PluginCapability;
    use kr_protocol::admission::AdmittedPackage;
    use kr_worker::broker::catalogue::testing::admitted;
    use kr_worker::broker::connectors::fixture;

    use super::*;
    use crate::catalogue::integrations::Integrations;

    /// A directory of the test's own, removed when it is dropped.
    struct Store(PathBuf);

    /// The pointer to the mode in what the stand-in application prints.
    const MODE: &str = "/m";

    /// What the stand-in application prints.
    const PRINTED: &str = r#"{"m":"elevated"}"#;

    /// The file the stand-in application writes in the directory it runs in, which says it ran.
    const RAN: &str = "ran";

    impl Store {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("kr-launch-probes-{name}-{}", kr_ipc::new_uuid()));
            std::fs::create_dir_all(&root).expect("a store directory");
            Self(root)
        }

        /// One Codex-shaped package whose probe runs `arguments` and reads [`MODE`], as an
        /// admission hands it over, with what `installed` makes of its installation.
        fn admitted(
            &self,
            arguments: &[&str],
            installed: impl FnOnce(&mut kr_worker::broker::connectors::ConnectorSource),
        ) -> AdmittedPackage {
            let mut probe = fixture::codex_probe(arguments);
            probe["mode"] = serde_json::json!(MODE);
            let mut source =
                fixture::package(&self.0, &self.0.join("kr-hook"), &fixture::probing(probe))
                    .expect("the package is written");
            installed(&mut source);
            admitted(&source)
        }

        /// A directory on the search path holding `codex`, a program that writes [`RAN`] beside
        /// where it runs and prints [`PRINTED`], and the arguments a package's probe gives it.
        ///
        /// On Unix it is a script that exits 1 as a diagnostic does when it reports a problem; on
        /// Windows a copy of Windows PowerShell, since a batch file is not a program a probe starts.
        #[cfg(unix)]
        fn application(&self) -> (PathBuf, Vec<String>) {
            use std::os::unix::fs::PermissionsExt as _;

            let directory = self.0.join("bin");
            std::fs::create_dir_all(&directory).expect("a directory");
            let path = directory.join("codex");
            std::fs::write(
                &path,
                format!("#!/bin/sh\ntouch {RAN}\nprintf '%s' '{PRINTED}'\nexit 1\n"),
            )
            .expect("the application is written");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("the application is made executable");
            (directory, vec!["doctor".to_owned(), "--json".to_owned()])
        }

        #[cfg(windows)]
        fn application(&self) -> (PathBuf, Vec<String>) {
            let directory = self.0.join("bin");
            std::fs::create_dir_all(&directory).expect("a directory");
            kr_ipc::testing::place_program(
                &Path::new(&std::env::var_os("SystemRoot").expect("a system directory"))
                    .join(r"System32\WindowsPowerShell\v1.0\powershell.exe"),
                &directory.join("codex.exe"),
            );
            // The script as Windows PowerShell reads an encoded command: base64 of its UTF-16 text.
            let script = format!("'x' | Out-File {RAN}; [Console]::Out.Write('{PRINTED}')");
            let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut encoded = String::new();
            for chunk in bytes.chunks(3) {
                let word = u32::from(chunk[0]) << 16
                    | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
                    | u32::from(*chunk.get(2).unwrap_or(&0));
                for index in 0..4 {
                    encoded.push(if index <= chunk.len() {
                        char::from(alphabet[(word >> (18 - 6 * index) & 63) as usize])
                    } else {
                        '='
                    });
                }
            }
            let arguments = [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded.as_str(),
            ];
            (
                directory,
                arguments.iter().map(|word| (*word).to_owned()).collect(),
            )
        }
    }

    impl Drop for Store {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn reported(
        store: &Store,
        package: AdmittedPackage,
        search: &[PathBuf],
    ) -> Vec<LaunchProbeReport> {
        let reading = Integrations::new().read(&[package]);
        report(&reading, search, &store.0)
    }

    fn words(arguments: &[String]) -> Vec<&str> {
        arguments.iter().map(String::as_str).collect()
    }

    /// KR-REQ-07.64: the doctor runs a granted package's probe against the executable its search
    /// path names, and reports the application's own word for its mode, whatever status the
    /// application exits with.
    #[test]
    fn kr_req_07_64_the_doctor_reports_the_mode_the_application_prints() {
        let store = Store::new("read");
        let (bin, arguments) = store.application();
        let reports = reported(
            &store,
            store.admitted(&words(&arguments), |_| {}),
            std::slice::from_ref(&bin),
        );
        assert_eq!(reports.len(), 1, "{reports:?}");
        let report = &reports[0];
        assert_eq!(report.plugin_id, "kalareach/codex");
        assert_eq!(report.state, LaunchProbeState::Read, "{report:?}");
        assert_eq!(report.mode.0.as_deref(), Some("elevated"));
        assert!(
            report
                .executable
                .0
                .as_deref()
                .is_some_and(|path| path.starts_with(&bin.display().to_string())),
            "{report:?}"
        );
        assert_eq!(report.reason.0, None);
    }

    /// KR-REQ-07.64: a probe the installation did not grant is not run, and the doctor says so;
    /// the control is the same package and search path with the grant, which reads a mode.
    #[test]
    fn kr_req_07_64_a_probe_not_granted_is_not_run_and_the_doctor_says_so() {
        let store = Store::new("ungranted");
        let (bin, arguments) = store.application();
        let ran = store.0.join(RAN);
        let granted = reported(
            &store,
            store.admitted(&words(&arguments), |_| {}),
            std::slice::from_ref(&bin),
        );
        assert_eq!(granted[0].state, LaunchProbeState::Read, "{:?}", granted[0]);
        assert!(ran.exists(), "the control ran the application");
        std::fs::remove_file(&ran).expect("the marker is removed");

        let withheld = reported(
            &store,
            store.admitted(&words(&arguments), |source| {
                source.granted.remove(&PluginCapability::LaunchProbe);
            }),
            &[bin],
        );
        assert_eq!(withheld[0].state, LaunchProbeState::NotGranted);
        assert_eq!(withheld[0].mode.0, None);
        assert_eq!(withheld[0].executable.0, None);
        assert!(!ran.exists(), "an ungranted probe ran the application");
    }

    /// KR-REQ-07.64: a package whose application the search path does not name is reported as
    /// having no executable, and a package that declares no probe is not reported at all.
    #[test]
    fn kr_req_07_64_no_executable_is_said_and_a_package_without_a_probe_is_left_out() {
        let store = Store::new("none");
        let empty = store.0.join("empty");
        std::fs::create_dir_all(&empty).expect("a directory");
        let reports = reported(
            &store,
            store.admitted(&["doctor"], |_| {}),
            std::slice::from_ref(&empty),
        );
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, LaunchProbeState::NoExecutable);

        let without = {
            let source = fixture::package(
                &store.0,
                &store.0.join("kr-hook"),
                &fixture::Shape::qoder_cli(),
            )
            .expect("the package is written");
            admitted(&source)
        };
        assert!(reported(&store, without, &[empty]).is_empty());
    }
}
