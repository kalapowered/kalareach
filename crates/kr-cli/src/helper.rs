//! Reaching a session whose worker runs another release.
//!
//! A worker outlives the update of the host, so `kr` can meet a worker of a release whose frames it
//! does not read. It never reads such a worker in the shape it has. Three commands, which start
//! with one session, hand the command to the `kr` of the worker's release instead: `kr attach`,
//! `kr detach` and the contact tools (`kr agent-tools`). The `kr` of that release is installed in
//! this host's store beside this one. This one replaces itself with it, with the session named by
//! its identifier, and it starts already holding the worker's release, so an update that removes
//! releases cannot take it between the choice and the start.
//!
//! Every other command that opens a worker goes on without one of another release and says that it
//! did not read it, naming the release and the command that does ([`Unread`]).
//!
//! A `kr` started this way is told so by [`MARKER`]. It never starts another, and the `kr` of the
//! worker's release, which reads that worker's frames, has no reason to.

use std::ffi::OsString;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::hello::PACKAGE_VERSION;
use kr_protocol::local::LocalBuild;
use kr_protocol::update::ReleaseName;

/// The variable a `kr` started in place of another is given, with the release of the one that
/// started it.
pub const MARKER: &str = "KR_HELPER_FROM";

/// A worker of a release other than this `kr`'s, as it stated itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Other {
    /// What the worker said it is, where it said anything.
    pub stated: Option<LocalBuild>,
}

impl Other {
    /// The worker, when `stated` is not a build whose frames this `kr` reads.
    ///
    /// A worker reads and writes this build's frames when the protocol version it states shares
    /// this build's compatibility level. One that states no build is of a build before the
    /// statement.
    #[must_use]
    pub fn of(stated: Option<&LocalBuild>) -> Option<Self> {
        match stated {
            Some(build) if build.protocol_version.shares_frames_with(PACKAGE_VERSION) => None,
            other => Some(Self {
                stated: other.cloned(),
            }),
        }
    }

    /// The release the worker runs, from the build it stated: `kr-worker/<release>`.
    #[must_use]
    pub fn release(&self) -> Option<ReleaseName> {
        let build = self.stated.as_ref()?;
        let release = build.build_id.as_str().strip_prefix("kr-worker/")?;
        ReleaseName::new(release).ok()
    }

    /// The `kr` of the worker's release in this host's store, held, where the store keeps one that
    /// states the worker's level and holds a `kr`.
    ///
    /// Nothing waits: a release an update is removing is not there to be reached.
    #[cfg(unix)]
    #[must_use]
    pub fn stored_kr(&self) -> Option<Stored> {
        use kr_ipc::install::Program;
        use kr_protocol::update::CompatibilityLevel;

        let build = self.stated.as_ref()?;
        let release = self.release()?;
        let this = kr_ipc::install::this_process().ok()?;
        let store = this.store()?;
        if this.release() == Some(&release) {
            return None;
        }
        let pin = store.pin(&release).ok().flatten()?;
        if !CompatibilityLevel::of(pin.manifest().protocol_version).admits(build.protocol_version) {
            return None;
        }
        let program = store
            .release_directory(&release)
            .join("bin")
            .join(Program::Kr.file_name());
        program.is_file().then_some(Stored {
            release,
            program,
            pin,
        })
    }

    /// No release is held by a command on this platform.
    #[cfg(not(unix))]
    #[must_use]
    pub fn stored_kr(&self) -> Option<Stored> {
        None
    }
}

/// The `kr` of another release in this host's store, and the hold that keeps the release there.
#[derive(Debug)]
pub struct Stored {
    /// The release.
    pub release: ReleaseName,
    /// Its `kr`.
    pub program: std::path::PathBuf,
    #[cfg(unix)]
    pin: kr_ipc::install::Pin,
}

impl Stored {
    /// Replaces this process with that `kr`, run with `arguments`. Returns only when it could not
    /// be started, and why.
    #[cfg(unix)]
    pub fn exec(self, arguments: &[OsString]) -> std::io::Error {
        let this = kr_ipc::install::this_process()
            .ok()
            .and_then(|running| running.release().map(|release| release.as_str().to_owned()))
            .unwrap_or_default();
        let mut command = std::process::Command::new(&self.program);
        command.args(arguments).env(MARKER, this);
        self.pin.exec(&mut command)
    }

    /// Not started on this platform.
    #[cfg(not(unix))]
    pub fn exec(self, _arguments: &[OsString]) -> std::io::Error {
        std::io::Error::other("a release of a store is not started on this platform")
    }
}

/// What the worker behind `descriptor` states of its build, when it answers its hello and proves it
/// is the worker the descriptor names inside [`STATED_WITHIN`]; none when it does not, and then the
/// command goes on to say what is wrong in its own way.
pub async fn stated_by(
    descriptor: &kr_protocol::worker::WorkerDescriptor,
) -> Option<Option<LocalBuild>> {
    let opened = tokio::time::timeout(
        STATED_WITHIN,
        crate::resolve::open_worker(descriptor, crate::build_id()),
    )
    .await
    .ok()?
    .ok()?;
    Some(opened.acknowledgement().build.clone())
}

/// Refuses to read a worker that runs another release, and says which release and which command
/// reads it, for a command that talks to one worker and never hands itself over.
///
/// # Errors
///
/// Returns `UNSUPPORTED_SCHEMA` naming the worker's release and the command of that release's `kr`
/// when `stated` is not a build whose frames this `kr` reads.
pub fn read_only_same(
    stated: Option<&LocalBuild>,
    display: u64,
    command: &'static str,
) -> crate::error::Result<()> {
    match Other::of(stated) {
        None => Ok(()),
        Some(other) => Err(crate::error::CliError::Refused(kr_client::error::refusal(
            kr_protocol::error::ErrorCode::UnsupportedSchema,
            Unread { display, other }.said(command),
        ))),
    }
}

/// How long a command waits for a worker to state its build before it goes on without a hand-over.
pub const STATED_WITHIN: std::time::Duration = std::time::Duration::from_secs(5);

/// Hands the command to the `kr` of the worker's release, when `stated` is a worker of another
/// release whose `kr` this host's store holds and this `kr` was not itself started in another's
/// place; returns when it did not, or could not.
///
/// `arguments` are the new command line without the program: the frozen form of the command, with
/// the session named by its identifier.
pub fn hand_over(stated: Option<&LocalBuild>, arguments: &[OsString]) -> Option<std::io::Error> {
    if std::env::var_os(MARKER).is_some() {
        return None;
    }
    let stored = Other::of(stated)?.stored_kr()?;
    Some(stored.exec(arguments))
}

/// A worker this command did not read, because it runs another release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unread {
    /// The session, as a person names it.
    pub display: u64,
    /// The worker.
    pub other: Other,
}

impl Unread {
    /// What the command says of it: which session, which release, and the command that reads it.
    ///
    /// The command is said without its arguments, which can hold what a person typed to answer.
    #[must_use]
    pub fn said(&self, command: &'static str) -> Shown {
        let release = self.other.stated.as_ref().map_or_else(
            || Shown::said("a worker of an earlier build"),
            |build| shown!("{}", crate::shown::build_name(&build.build_id)),
        );
        match self.other.stored_kr() {
            Some(stored) => shown!(
                "session {} was not read: it runs {}, another release than this kr. The kr of that \
                 release reads it: run {} {} with the same arguments",
                self.display,
                release,
                Shown::stored(&stored.program, &["kr"], &[]),
                command
            ),
            None => shown!(
                "session {} was not read: it runs {}, another release than this kr, and no kr of \
                 that release is installed on this host to read it",
                self.display,
                release
            ),
        }
    }
}
