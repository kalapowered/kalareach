//! What the job definition hands the plugin host.
//!
//! Six non-secret facts, and nothing else. The host generates its own signing key at startup and
//! keeps the private half in memory for its whole life, so there is nothing here that a job
//! definition, a process listing or a crash report should not be allowed to show.

use std::path::PathBuf;

use clap::Parser;
use kr_protocol::scalars::Uuid;

/// The arguments the service manager starts the host with.
#[derive(Clone, Debug, PartialEq, Eq, Parser)]
#[command(
    name = "kr-plugin-host",
    version,
    about = "The KalaReach plugin-runtime service. Started by the host's control daemon, never by hand."
)]
pub struct Options {
    /// The reservation this process was started for.
    #[arg(long)]
    pub reservation: Uuid,
    /// The environment it serves.
    #[arg(long)]
    pub environment: Uuid,
    /// The control daemon's owner-only rendezvous endpoint.
    #[arg(long)]
    pub rendezvous: String,
    /// The per-user runtime directory.
    #[arg(long = "runtime-dir")]
    pub runtime_dir: PathBuf,
    /// The per-user state directory.
    #[arg(long = "state-dir")]
    pub state_dir: PathBuf,
    /// The only directory a component payload may be read from.
    #[arg(long = "packages-dir")]
    pub packages_dir: PathBuf,
}

impl Options {
    /// Returns the directory name compiled artefacts are filed under, inside the state directory.
    pub const CACHE_DIRECTORY: &'static str = "plugin-cache";

    /// Returns the environment identifier.
    #[must_use]
    pub const fn environment_id(&self) -> kr_protocol::ids::EnvironmentId {
        kr_protocol::ids::EnvironmentId::new(self.environment)
    }

    /// Returns the reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> kr_protocol::worker::ReservationId {
        kr_protocol::worker::ReservationId::new(self.reservation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_arguments_parse_as_the_launcher_writes_them() {
        let options = Options::try_parse_from([
            "kr-plugin-host",
            "--reservation",
            "01010101-0101-0101-0101-010101010101",
            "--environment",
            "02020202-0202-0202-0202-020202020202",
            "--rendezvous",
            "/run/kr/ab/pr.sock",
            "--runtime-dir",
            "/run/kr",
            "--state-dir",
            "/var/lib/kr",
            "--packages-dir",
            "/var/lib/kr/packages",
        ])
        .expect("the launcher's arguments parse");
        assert_eq!(
            options.reservation_id().to_string(),
            "01010101-0101-0101-0101-010101010101"
        );
        assert_eq!(options.rendezvous, "/run/kr/ab/pr.sock");
        assert_eq!(options.packages_dir, PathBuf::from("/var/lib/kr/packages"));
    }

    #[test]
    fn a_missing_argument_is_a_failure_rather_than_a_default() {
        // A host that defaulted its packages directory would read component payloads from
        // somewhere nobody chose.
        assert!(
            Options::try_parse_from([
                "kr-plugin-host",
                "--reservation",
                "01010101-0101-0101-0101-010101010101",
                "--environment",
                "02020202-0202-0202-0202-020202020202",
                "--rendezvous",
                "/run/kr/ab/pr.sock",
                "--runtime-dir",
                "/run/kr",
                "--state-dir",
                "/var/lib/kr",
            ])
            .is_err()
        );
    }
}
