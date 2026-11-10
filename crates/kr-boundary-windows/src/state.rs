//! What the doctor says in each state of the installation.
//!
//! The runtime check reads the whole installation and answers with one [`Verdict`]. The doctor shows
//! the verdict's status, the one fact it rests on and the command that mends it. Only an absence
//! that was proved is "not installed": anything the check could not read is "unreadable", never
//! "not installed", so a computer whose state cannot be known does not report itself clean.

/// How the doctor grades a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The state is as it should be.
    Ok,
    /// The state is allowed and the person may want to change it.
    Warning,
    /// The state needs mending.
    Failed,
}

/// What the runtime check found. Each variant carries the fact the doctor names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// No service, no recorded account and no rule of ours: proved absent.
    NotInstalled,
    /// The installation is in force.
    Ready,
    /// An installation that did not finish.
    Partial(String),
    /// An object of our names that the manifest does not list.
    Foreign(String),
    /// The policy, the service, the accounts, the files, the rights, Git's version or a helper's
    /// identity differs from what was installed.
    Altered(String),
    /// Everything is present and the policy does not refuse: the proof's result.
    NotInForce(String),
    /// The broker does not answer, or answers from another process, or speaks another version.
    BrokerUnreachable(String),
    /// Git does not start under the boundary.
    GitFails(String),
    /// A file grant of an earlier invocation could not be taken back.
    CleanupFailed(String),
    /// A part of the state could not be read.
    Unreadable(String),
}

/// The doctor's account of a verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// How the doctor grades the state.
    pub status: Status,
    /// What the check found.
    pub detail: String,
    /// The command that mends it, when one does.
    pub remedy: Option<&'static str>,
}

impl Verdict {
    /// The doctor's account of this verdict.
    #[must_use]
    pub fn report(&self) -> Report {
        let (status, detail, remedy) = match self {
            Verdict::NotInstalled => (
                Status::Warning,
                "the repository boundary is not installed, so Windows refuses repository \
                 operations until it is"
                    .to_owned(),
                Some("kr host boundary install"),
            ),
            Verdict::Ready => (
                Status::Ok,
                "the repository boundary is installed and in force".to_owned(),
                None,
            ),
            Verdict::Partial(what) => (
                Status::Failed,
                format!("an installation did not finish: {what}"),
                Some("kr host boundary repair, or kr host boundary remove"),
            ),
            Verdict::Foreign(what) => (
                Status::Failed,
                format!("an object the installation did not make has its names: {what}"),
                Some("kr host boundary remove"),
            ),
            Verdict::Altered(what) => (
                Status::Failed,
                format!("the installation was changed: {what}"),
                Some("kr host boundary repair"),
            ),
            Verdict::NotInForce(what) => (
                Status::Failed,
                format!("the installation is present and does not take effect: {what}"),
                Some("kr host boundary repair"),
            ),
            Verdict::BrokerUnreachable(what) => (
                Status::Failed,
                format!("the broker cannot be used: {what}"),
                Some("kr host boundary repair"),
            ),
            Verdict::GitFails(what) => (
                Status::Failed,
                format!("Git does not start under the boundary: {what}"),
                Some("kr host boundary repair"),
            ),
            Verdict::CleanupFailed(what) => (
                Status::Failed,
                format!("an earlier invocation left a file grant behind: {what}"),
                Some("kr host boundary repair"),
            ),
            Verdict::Unreadable(what) => (
                Status::Failed,
                format!("the installation's state could not be read: {what}"),
                Some("kr host boundary status, run as an administrator"),
            ),
        };
        Report {
            status,
            detail,
            remedy,
        }
    }
}
