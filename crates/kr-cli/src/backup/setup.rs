//! `kr backup setup`: the owner sets this host's backups up.
//!
//! The command is a dialogue at a terminal. It asks the control daemon where this host stands,
//! shows what setting up does, makes the recovery seed, shows the kit once, and gives the daemon
//! the one call that sets backups up only after the person has typed back the end of the seed and
//! said that the kit is stored. The seed stays in this process: the daemon is given the recovery
//! recipient's public key, the bundle's locator and the sealed bundle.
//!
//! # What keeps the kit from other readers
//!
//! * The command runs at a terminal outside every session, whose worker keeps its output.
//! * Before the seed exists the process is kept out of a core dump: the core size limit is zero,
//!   and on Linux the process is made non-dumpable, because a core pattern that pipes to a handler
//!   ignores the limit. Setup is refused if either call fails.
//! * The kit is written straight to the terminal from the buffer that holds it, and the buffer
//!   clears when it is dropped. It does not pass through standard output's buffer or the line
//!   writer.
//! * However the dialogue ends, the terminal's modes are put back with the input still waiting
//!   discarded, so text pasted past a line never reaches the shell or its history.
//!
//! # How a setup ends
//!
//! The daemon answers one of three ways, and the command says what each means for the kit.
//! *Enabled*: backups are set up and the kit is in use. *Declined*: the daemon confirmed that
//! nothing was recorded, so the kit opens nothing; the same kit is offered again, three times at
//! most, for a refusal a person can mend. *Unknown*: the daemon cannot say. The call is repeated
//! with the same bytes and a new action identity, as the answer says, up to five times; if the
//! outcome stays unknown the person is told to keep the kit until `kr doctor` settles it.
//!
//! Only a *Declined* answer says that the kit opens nothing once the call has been sent. Any
//! other end of a sent call is unknown: a refusal, a failed connection and an interrupt can each
//! come after the daemon recorded the setup, for example a refusal of an answer that the daemon
//! withheld because the local owner's membership lease ended while it was being written.

use std::fs::File;
use std::io::{IsTerminal as _, Write as _};
use std::os::fd::AsFd as _;
use std::time::Duration;

use kr_client::recovery::{SetupInputs, prepare_setup};
use kr_client::shown;
use kr_client::shown::{Said as _, Shown};
use kr_ipc::paths::HostPaths;
use kr_protocol::backup_read::BackupSignIn;
use kr_protocol::backup_setup::{
    BackupEnableCause, BackupEnableParams, BackupEnableResult, BackupHostKeys, BackupSetupState,
    BackupStatusParams, BackupStatusResult, BackupUnusable,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ArchiveId;
use kr_protocol::method::Method;
use rustix::termios::{OptionalActions, Termios};
use zeroize::Zeroizing;

use super::interrupt::{self, Interrupt};
use super::kit::ask_line;
use crate::cli::{BackupSetupArguments, EnvironmentSelector};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output;
use crate::report::{self, Completion};

/// How many symbols from the end of the seed line the person types back.
const TYPED_BACK: usize = 8;

/// How many times the person may type the end of the seed wrongly before nothing is set up.
const TRIES: usize = 3;

/// How many times a call whose outcome is unknown is repeated.
const REPEATS: usize = 5;

/// How many times the same kit is offered again after a refusal a person can mend.
const OFFERS: usize = 3;

/// The longest the command waits for a delay the service named. The daemon passes on the delay it
/// was given, so a longer one is cut here; the repeat then meets the delay again and ends unknown.
const LONGEST_WAIT: u64 = 3600;

/// How long the command waits before it repeats a call whose outcome is unknown and named no delay.
const REPEAT_PAUSE: Duration = Duration::from_secs(1);

/// Sets this host's backups up.
///
/// # Errors
///
/// Returns the refusal or failure that stopped it, and a failure when the outcome of the setup is
/// not known or when nothing was set up.
pub async fn run(
    paths: &HostPaths,
    arguments: BackupSetupArguments,
    json: bool,
) -> Result<Completion> {
    if json {
        return Err(CliError::Usage(Shown::said(
            "this command is a dialogue at a terminal and has no --json form",
        )));
    }
    if !(std::io::stdin().is_terminal() && output::is_terminal() && report::is_terminal()) {
        return Err(CliError::NotATerminal);
    }
    crate::bind::require_outside(
        &crate::build_id(),
        "a recovery kit is shown outside every session, whose output its worker keeps and an \
         agent in it can read",
    )
    .await?;
    keep_out_of_a_core_dump()?;

    let interrupt = Interrupt::install()?;
    // Held from here to the end, so that every exit puts the terminal back and drops what is
    // waiting in it.
    let _terminal = Terminal::hold()?;
    let mut dialogue = Dialogue {
        interrupt,
        stage: Stage::Asking,
        replacing: None,
        kit: None,
    };

    // The connection that reads the status is let go of before the dialogue begins: a person can
    // take longer over it than a connection nobody reads from is kept.
    let status = {
        let mut daemon = dialogue.connect(paths, &arguments.selector).await?;
        tokio::select! {
            status = daemon.read::<_, BackupStatusResult>(Method::BackupStatus, &BackupStatusParams {}) => status?,
            () = dialogue.interrupt.arrived() => return Err(dialogue.stopped()),
        }
    };
    let ready = Ready::of(&status, arguments.replace)?;
    dialogue.replacing = ready.replacing.clone();

    show_the_plan(&ready);
    let go = dialogue
        .ask(&Shown::said("Type yes to go on, or anything else to stop:"))
        .await?;
    if !is_yes(go.as_ref()) {
        return Err(dialogue.nothing_done());
    }

    let (kit, tail, params, fingerprint) = {
        let prepared = prepare_setup(&SetupInputs {
            origin: &ready.origin,
            archive_id: ArchiveId::new(kr_ipc::new_uuid()),
            writer: (ready.keys.writer_key_id, ready.keys.writer_public_key),
            producer: (ready.keys.producer_key_id, ready.keys.producer_public_key),
            enabled_at_ms: kr_ipc::now_ms(),
            replace: arguments.replace,
        })
        .map_err(|error| {
            CliError::Other(shown!("the recovery kit could not be made: {}", error))
        })?;
        let tail = end_of_the_seed(&prepared.kit).ok_or_else(|| {
            CliError::Other(Shown::said(
                "the recovery kit could not be made: it has no seed line",
            ))
        })?;
        (
            prepared.kit,
            tail,
            prepared.params,
            prepared.kit_fingerprint,
        )
    };
    let shown_fingerprint = crate::shown::kit_fingerprint(&fingerprint);

    dialogue.stage = Stage::KitShown;
    dialogue.kit = Some(shown_fingerprint.clone());
    show_the_kit(&kit, &shown_fingerprint).map_err(|error| dialogue.failed(error))?;
    // The kit has been shown once. It is cleared now, and the seed lives on only as the end the
    // person types back.
    drop(kit);
    dialogue.read_back(&tail).await?;
    drop(tail);
    let stored = dialogue
        .ask(&Shown::said(
            "Type yes when the kit is stored somewhere safe, or anything else to stop. Nothing is \
             set up until you do:",
        ))
        .await?;
    if !is_yes(stored.as_ref()) {
        return Err(dialogue.nothing_done());
    }

    let mut offers = OFFERS;
    loop {
        report::say(&Shown::said("Setting backups up."));
        match dialogue.call(paths, &arguments.selector, &params).await? {
            Ended::Enabled { fingerprint } => {
                output::say(&shown!(
                    "Backups are set up. The kit's fingerprint is {}.",
                    crate::shown::kit_fingerprint(&fingerprint)
                ));
                output::say(&Shown::said(
                    "Closed sessions and this host's configuration are backed up at most once a \
                     day, when something has changed; kr doctor shows the newest backup. Keep the \
                     kit and its fingerprint together.",
                ));
                return Ok(Completion::Done);
            }
            Ended::Declined(cause) => {
                report::say(&shown!(
                    "Backups were not set up: {}.",
                    declined_words(&cause)
                ));
                if offers > 0 && mendable(&cause) {
                    offers -= 1;
                    let again = dialogue
                        .ask(&Shown::said(
                            "Mend that, then type retry to use the same kit again, or anything \
                             else to stop:",
                        ))
                        .await?;
                    if again
                        .as_deref()
                        .is_some_and(|typed| typed.trim().eq_ignore_ascii_case("retry"))
                    {
                        // The same bytes: a repeat is answered from what the first left.
                        continue;
                    }
                }
                return Err(dialogue.nothing_done());
            }
            Ended::Unknown => return Err(dialogue.outcome_unknown()),
        }
    }
}

/// Where the dialogue stands, which decides what an ending that the person did not choose says
/// about the kit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// No kit has been shown: nothing is made.
    Asking,
    /// The kit has been shown and no call has been sent, or the daemon confirmed that it recorded
    /// nothing.
    KitShown,
    /// A call has been sent, and the daemon has not confirmed that it recorded nothing.
    Sending,
}

/// What the dialogue holds between its questions.
struct Dialogue {
    interrupt: Interrupt,
    stage: Stage,
    /// The fingerprint of the setup this one replaces, when it replaces one.
    replacing: Option<String>,
    /// The fingerprint of the kit, once it has been shown.
    kit: Option<Shown>,
}

impl Dialogue {
    /// Puts `question` to the person and returns the line they typed, or none at the end of the
    /// input. A line is cleared when dropped.
    async fn ask(&mut self, question: &Shown) -> Result<Option<Zeroizing<String>>> {
        let answer = tokio::select! {
            answer = ask_line(question) => answer.map_err(|error| self.failed(error))?,
            () = self.interrupt.arrived() => return Err(self.stopped()),
        };
        Ok(answer.map(Zeroizing::new))
    }

    /// Opens a connection to the daemon, which the person can interrupt.
    async fn connect(
        &mut self,
        paths: &HostPaths,
        selector: &EnvironmentSelector,
    ) -> Result<Daemon> {
        tokio::select! {
            daemon = Daemon::open(paths, selector) => daemon,
            () = self.interrupt.arrived() => Err(self.stopped()),
        }
    }

    /// Asks for the end of the seed line until it is typed or the tries are used.
    async fn read_back(&mut self, tail: &Zeroizing<Vec<u8>>) -> Result<()> {
        let question = shown!(
            "To show that you read the kit, type the last {} symbols of its seed line, without the \
             dashes:",
            TYPED_BACK
        );
        for left in (0..TRIES).rev() {
            let typed = self.ask(&question).await?;
            let Some(typed) = typed else {
                return Err(self.nothing_done());
            };
            if matches_the_end(&typed, tail) {
                return Ok(());
            }
            if left > 0 {
                report::say(&shown!(
                    "That is not the end of the seed line. Tries left: {}.",
                    left
                ));
            }
        }
        Err(self.nothing_done())
    }

    /// Calls `backup.enable`, and again with the same bytes while the outcome is unknown.
    ///
    /// Each attempt has a connection of its own: the one that read the status, or the one before,
    /// has had nobody reading from it for as long as the person took over the questions or the
    /// wait took, and the daemon ends a connection that stops reading.
    async fn call(
        &mut self,
        paths: &HostPaths,
        selector: &EnvironmentSelector,
        params: &BackupEnableParams,
    ) -> Result<Ended> {
        let mut repeats = 0;
        loop {
            let mut daemon = match self.connect(paths, selector).await {
                Ok(daemon) => daemon,
                // Nothing has been sent when the first attempt cannot reach the daemon.
                Err(error) if self.stage != Stage::Sending => return Err(self.failed(error)),
                // A repeat: the earlier attempt may have been run.
                Err(_) => return Ok(Ended::Unknown),
            };
            self.stage = Stage::Sending;
            // A new action identity each time: a claimed action keeps no result for an error that
            // can be tried again, and would answer "outcome unknown" for ever.
            let answer = tokio::select! {
                answer = daemon.mutate::<_, BackupEnableResult>(Method::BackupEnable, params) => answer,
                () = self.interrupt.arrived() => return Err(self.stopped()),
            };
            drop(daemon);
            let delay = match answer_of(answer) {
                Answer::Ended(Ended::Declined(cause)) => {
                    self.stage = Stage::KitShown;
                    return Ok(Ended::Declined(cause));
                }
                Answer::Ended(ended) => return Ok(ended),
                Answer::Again { delay } => delay,
            };
            repeats += 1;
            if repeats > REPEATS {
                return Ok(Ended::Unknown);
            }
            let pause = delay.map_or(REPEAT_PAUSE, |seconds| {
                Duration::from_secs(seconds.min(LONGEST_WAIT))
            });
            if let Some(seconds) = delay {
                report::say(&shown!(
                    "The service asked to be left alone for {} seconds. Waiting, then trying again.",
                    seconds.min(LONGEST_WAIT)
                ));
            }
            tokio::select! {
                () = tokio::time::sleep(pause) => {}
                () = self.interrupt.arrived() => return Err(self.stopped()),
            }
        }
    }

    /// What is said when the dialogue ends before any call was sent, or after the daemon confirmed
    /// that it recorded nothing.
    fn nothing_set_up(&self) -> Vec<Shown> {
        let mut lines = Vec::new();
        match self.stage {
            Stage::Asking => lines.push(Shown::said("Nothing was set up.")),
            Stage::KitShown => {
                lines.push(Shown::said(
                    "Nothing was set up. The kit that was shown opens nothing: delete it.",
                ));
            }
            // A call is on its way: only the daemon's own word makes the kit void.
            Stage::Sending => {}
        }
        if self.replacing.is_some() {
            lines.push(Shown::said("The earlier setup is as it was."));
        }
        lines
    }

    /// The ending of a dialogue the person did not carry on with.
    fn nothing_done(&self) -> CliError {
        for line in self.nothing_set_up() {
            report::say(&line);
        }
        CliError::Other(Shown::said("backups were not set up"))
    }

    /// The ending of a failure that is not the daemon's answer to the call, such as a terminal
    /// that could not be read: no call was sent, so the kit that was shown, if one was, opens
    /// nothing.
    fn failed(&self, error: CliError) -> CliError {
        for line in self.nothing_set_up() {
            report::say(&line);
        }
        error
    }

    /// The ending of a command that was interrupted, with what it means for the kit.
    fn stopped(&self) -> CliError {
        match self.stage {
            Stage::Asking | Stage::KitShown => {
                for line in self.nothing_set_up() {
                    report::say(&line);
                }
            }
            Stage::Sending => {
                report::say(&Shown::said(
                    "The command stopped while the setup was under way, so how it ended is not \
                     known.",
                ));
                self.keep_the_kit();
            }
        }
        interrupt::stopped()
    }

    /// The ending of a call whose outcome stayed unknown.
    fn outcome_unknown(&self) -> CliError {
        report::say(&Shown::said("How the setup ended is not known."));
        self.keep_the_kit();
        CliError::Other(Shown::said("how the setup ended is not known"))
    }

    /// What the person does with a kit whose setup may or may not have been recorded.
    fn keep_the_kit(&self) {
        report::say(&Shown::said("Keep the kit until kr doctor settles it."));
        if let Some(fingerprint) = &self.kit {
            report::say(&shown!(
                "If kr doctor shows backups set up with kit fingerprint {}, the kit is in use: \
                 keep it.",
                fingerprint.clone()
            ));
        }
        match &self.replacing {
            None => report::say(&Shown::said(
                "If it shows no setup and none in progress, the kit opens nothing and you can \
                 delete it.",
            )),
            Some(earlier) => report::say(&shown!(
                "If it shows backups set up with the earlier kit fingerprint {} and none in \
                 progress, the earlier setup stands and the kit opens nothing: you can delete it.",
                crate::shown::kit_fingerprint(earlier)
            )),
        }
        report::say(&Shown::said(
            "If it shows a setup in progress, run kr doctor again a little later.",
        ));
        report::say(&Shown::said(
            "If it shows any other fingerprint, keep the kit: its setup may have been made and \
             replaced since.",
        ));
    }
}

/// What an answer to a sent `backup.enable` comes to.
enum Answer {
    /// The call ended.
    Ended(Ended),
    /// The daemon could not say, and the call is made again after `delay` seconds, when the answer
    /// names one.
    Again { delay: Option<u64> },
}

/// Sorts the daemon's answer to a sent call.
///
/// Only a confirmed refusal ([`BackupEnableResult::Declined`]) says that nothing was recorded.
/// A refusal in an error, and a connection that failed, can each follow the daemon's recording of
/// the setup, so they end the call as unknown; a refusal is not made again, because a withheld
/// answer is not to be repeated under a new identity.
fn answer_of(answer: Result<BackupEnableResult>) -> Answer {
    match answer {
        Ok(BackupEnableResult::Enabled {
            kit_fingerprint, ..
        }) => Answer::Ended(Ended::Enabled {
            fingerprint: kit_fingerprint,
        }),
        Ok(BackupEnableResult::Declined { cause }) => Answer::Ended(Ended::Declined(cause)),
        Ok(BackupEnableResult::Unknown {
            retry_after_seconds,
        }) => Answer::Again {
            delay: retry_after_seconds.as_ref().map(|seconds| seconds.get()),
        },
        Err(CliError::Refused(error)) if error.code == ErrorCode::OutcomeUnknown => {
            Answer::Again { delay: None }
        }
        Err(refused @ (CliError::Refused(_) | CliError::ServiceRefused { .. })) => {
            report::say(&shown!("The daemon refused the call: {}", refused.said()));
            Answer::Ended(Ended::Unknown)
        }
        Err(_) => Answer::Ended(Ended::Unknown),
    }
}

/// How a call to `backup.enable` ended.
enum Ended {
    /// Backups are set up, under the kit with this fingerprint.
    Enabled { fingerprint: String },
    /// The daemon confirmed that nothing was recorded.
    Declined(BackupEnableCause),
    /// The daemon could not say how it ended.
    Unknown,
}

/// What `backup.status` says that the setup goes on from.
struct Ready {
    /// The storage service's origin, exactly as the daemon holds it.
    origin: String,
    /// The host's writer and producer.
    keys: BackupHostKeys,
    /// Whether privacy mode is on now.
    privacy_mode: bool,
    /// The fingerprint of the setup this one replaces.
    replacing: Option<String>,
}

impl Ready {
    /// Decides from the daemon's status whether a setup can go on, and says why when it cannot.
    fn of(status: &BackupStatusResult, replace: bool) -> Result<Self> {
        let (Some(origin), Some(keys)) = (status.service.as_ref(), status.keys.as_ref()) else {
            return Err(CliError::Usage(Shown::said(
                "this host's configuration selects no storage service, so there is nothing to set \
                 backups up at: set storage.origin to the service that will hold them, then run \
                 this again",
            )));
        };
        let replacing = match &status.setup {
            BackupSetupState::None {} => None,
            BackupSetupState::InProgress { kit_fingerprints } => {
                let fingerprints = Shown::joined(
                    kit_fingerprints
                        .iter()
                        .map(|fingerprint| crate::shown::kit_fingerprint(fingerprint)),
                    ", ",
                );
                return Err(CliError::Usage(shown!(
                    "a setup of this host's backups is under way, with the kit fingerprint {}: \
                     run kr doctor to see when it ends, and keep that kit until then",
                    fingerprints
                )));
            }
            BackupSetupState::Committed {
                kit_fingerprint,
                unusable,
                ..
            } => {
                if !replace {
                    return Err(already_set_up(kit_fingerprint, unusable.as_ref().copied()));
                }
                Some(kit_fingerprint.clone())
            }
        };
        if !matches!(status.sign_in, BackupSignIn::Usable) {
            return Err(CliError::Usage(sign_in_words(status.sign_in)));
        }
        Ok(Self {
            origin: origin.clone(),
            keys: keys.clone(),
            privacy_mode: status.privacy_mode,
            replacing,
        })
    }
}

/// The refusal to set up again without `--replace`.
fn already_set_up(fingerprint: &str, unusable: Option<BackupUnusable>) -> CliError {
    let fingerprint = crate::shown::kit_fingerprint(fingerprint);
    let words = match unusable {
        None => shown!(
            "backups are already set up on this host, with the kit whose fingerprint is {}: run \
             with --replace to set them up again under a new kit",
            fingerprint
        ),
        Some(BackupUnusable::Account) => shown!(
            "backups are set up on this host with the kit whose fingerprint is {}, but this host \
             is signed in as another account, or to another service, than the one they belong \
             to: sign in as that account again, or run with --replace to start new backups under \
             the account signed in now",
            fingerprint
        ),
        Some(BackupUnusable::Keys) => shown!(
            "backups are set up on this host with the kit whose fingerprint is {}, but this host \
             holds other keys than the setup names: run with --replace to start new backups",
            fingerprint
        ),
        Some(BackupUnusable::WriterRetired) => shown!(
            "backups are set up on this host with the kit whose fingerprint is {}, but this \
             host's writer is no longer enrolled for the archive, for example because the \
             collection was deleted from the account console: run with --replace to start new \
             backups",
            fingerprint
        ),
    };
    CliError::Usage(words)
}

/// What a sign-in that cannot carry a backup request says, and what mends it.
fn sign_in_words(sign_in: BackupSignIn) -> Shown {
    Shown::said(match sign_in {
        BackupSignIn::Usable => "this host's sign-in could not be used just now: try again",
        BackupSignIn::SignedOut => {
            "this host is signed in to no account: run kr account sign-in, then run this again"
        }
        BackupSignIn::Waiting => {
            "a sign-in on this host is waiting for your browser: finish it, or run kr account \
             sign-in again, then run this again"
        }
        BackupSignIn::Ended => {
            "the service ended this host's sign-in: run kr account sign-in, then run this again"
        }
        BackupSignIn::WithoutScope => {
            "this host's sign-in does not allow backups: run kr account sign-in again and allow \
             them, then run this again"
        }
        BackupSignIn::NotRenewed => {
            "no token could be had from this host's sign-in just now: try again, or run kr \
             account sign-in"
        }
    })
}

/// What a refusal the daemon confirmed says.
fn declined_words(cause: &BackupEnableCause) -> Shown {
    match cause {
        BackupEnableCause::NoService {} => {
            Shown::said("this host's configuration selects no storage service")
        }
        BackupEnableCause::SignIn { sign_in } => sign_in_words(*sign_in),
        BackupEnableCause::AnotherAccount {} => Shown::said(
            "this host was signed in as another account while the setup ran: sign in as the \
             account you began with",
        ),
        BackupEnableCause::KeysChanged {} => Shown::said(
            "a key this host holds changed while the setup ran: run this again for a new kit",
        ),
        BackupEnableCause::BundleTooLarge {} => {
            Shown::said("the recovery bundle is larger than the service accepts")
        }
        BackupEnableCause::AlreadySetUp {} => Shown::said(
            "backups are set up on this host for another archive: run with --replace to replace \
             them",
        ),
        BackupEnableCause::ArchiveInUse {} => Shown::said(
            "this host already records backups of that archive: run this again for a new kit",
        ),
        BackupEnableCause::NoAllowance {} => {
            Shown::said("the account has no allowance for backup storage")
        }
        BackupEnableCause::TokenNotAccepted {} => Shown::said(
            "the service did not accept this host's sign-in for backups: run kr account sign-in",
        ),
        BackupEnableCause::BundleConflict {} => Shown::said(
            "the service already holds another recovery bundle at this kit's place: run this \
             again for a new kit",
        ),
        BackupEnableCause::ServiceRefused { code } => {
            shown!("the service refused the setup ({})", *code)
        }
    }
}

/// Whether the person can mend a refusal and try the same kit again: the kit and its bundle are
/// not what was refused.
const fn mendable(cause: &BackupEnableCause) -> bool {
    matches!(
        cause,
        BackupEnableCause::SignIn { .. }
            | BackupEnableCause::AnotherAccount {}
            | BackupEnableCause::NoAllowance {}
            | BackupEnableCause::TokenNotAccepted {}
            | BackupEnableCause::ServiceRefused { .. }
    )
}

/// Tells the person what setting up does, and what it does not.
fn show_the_plan(ready: &Ready) {
    report::say(&shown!(
        "Setting this host's backups up at {}.",
        Shown::address(&ready.origin)
    ));
    for line in [
        "",
        "What this does:",
        "  - It backs up the retained output of closed sessions and this host's configuration, \
         at most once a day and when something has changed. A session that is still open is not \
         backed up until it closes.",
        "  - It encrypts everything on this host. The service holds ciphertext only.",
        "  - It turns managed backup storage on for the account when it is off.",
        "  - It reads nothing while privacy mode is on.",
        "  - It binds the backups to the account signed in now. If this host signs in as another \
         account, backups stop until it signs in as this one again or is set up again with \
         --replace.",
        "  - It keeps the newest backups the account's retention records, at least two and at \
         most 16, and deletes the older ones at the service, which charges for deleted storage \
         for seven more days. A backup that privacy mode drew a line under stays until you \
         delete it, so the account can hold more than 16.",
        "  - It shows a recovery kit once. The kit is the only way to read these backups if this \
         host is lost, and KalaReach keeps no copy of it. Keep the kit and its fingerprint \
         together: the fingerprint matches a kit to this host only if it is with the kit.",
    ] {
        report::say(&Shown::said(line));
    }
    if ready.privacy_mode {
        report::say(&Shown::said(
            "Privacy mode is on now, so nothing is backed up until it is off.",
        ));
    }
    if let Some(fingerprint) = &ready.replacing {
        report::say(&shown!(
            "Replacing the setup whose kit fingerprint is {}:",
            crate::shown::kit_fingerprint(fingerprint)
        ));
        for line in [
            "  - The earlier kit stops being the kit of new backups.",
            "  - The earlier archive's unfinished uploads are stopped.",
            "  - The earlier archive stays at the service until you delete it.",
        ] {
            report::say(&Shown::said(line));
        }
    }
    report::say(&Shown::said(""));
}

/// Writes the kit to the terminal, once.
fn show_the_kit(kit: &Zeroizing<String>, fingerprint: &Shown) -> Result<()> {
    let failed = |error: &std::io::Error| {
        CliError::Terminal(shown!(
            "the recovery kit could not be shown: {}",
            Shown::io(error)
        ))
    };
    // The controlling terminal, opened as itself and written with no buffer of ours in between;
    // the command runs only where standard output is that terminal.
    let mut terminal = File::options()
        .write(true)
        .open("/dev/tty")
        .map_err(|error| failed(&error))?;
    report::say(&Shown::said(
        "Your recovery kit follows. It is shown once. The terminal's scrollback keeps it until \
         you clear the scrollback.",
    ));
    terminal.write_all(b"\n").map_err(|error| failed(&error))?;
    terminal
        .write_all(kit.as_bytes())
        .map_err(|error| failed(&error))?;
    terminal.write_all(b"\n").map_err(|error| failed(&error))?;
    report::say(&shown!("Kit fingerprint: {}", fingerprint.clone()));
    Ok(())
}

/// The last symbols of the seed line of a rendered kit, without the dashes.
fn end_of_the_seed(kit: &str) -> Option<Zeroizing<Vec<u8>>> {
    let seed = kit.lines().find_map(|line| line.strip_prefix("seed: "))?;
    let mut end: Zeroizing<Vec<u8>> = Zeroizing::new(
        seed.bytes()
            .rev()
            .filter(|symbol| *symbol != b'-')
            .take(TYPED_BACK)
            .collect(),
    );
    end.reverse();
    (end.len() == TYPED_BACK).then_some(end)
}

/// Whether `typed` is `end`, read as a kit's seed is read: either case, dashes and spaces
/// ignored, `I` and `L` for `1`, and `O` for `0`. The typed line is compared as it is read and
/// never collected, so no copy of it is left behind.
fn matches_the_end(typed: &str, end: &[u8]) -> bool {
    typed
        .bytes()
        .filter(|byte| *byte != b'-' && !byte.is_ascii_whitespace())
        .map(|byte| match byte.to_ascii_uppercase() {
            b'I' | b'L' => b'1',
            b'O' => b'0',
            other => other,
        })
        .eq(end.iter().copied())
}

/// Whether the person's line is the word yes.
fn is_yes(answer: Option<&Zeroizing<String>>) -> bool {
    answer.is_some_and(|typed| typed.trim().eq_ignore_ascii_case("yes"))
}

/// Keeps this process out of a core dump, before the seed exists.
///
/// The core size limit is zero. On Linux the process is also made non-dumpable, because a core
/// pattern that pipes to a handler ignores the limit. A failure of either refuses the setup.
fn keep_out_of_a_core_dump() -> Result<()> {
    let refused = |error: rustix::io::Errno| {
        CliError::Other(shown!(
            "the recovery kit is not made because this process could not be kept out of a core \
             dump: {}",
            crate::shown::errno(error)
        ))
    };
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(refused)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(refused)?;
    Ok(())
}

/// The terminal's modes as they were found. They are put back when this is dropped, and the input
/// still waiting is discarded with them: what was pasted past a line the dialogue read is not for
/// the shell.
struct Terminal {
    input: File,
    saved: Termios,
}

impl Terminal {
    fn hold() -> Result<Self> {
        let input = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map(File::from)
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the terminal could not be reached: {}",
                    Shown::io(&error)
                ))
            })?;
        let saved = rustix::termios::tcgetattr(&input).map_err(|error| {
            CliError::Terminal(shown!(
                "the terminal's modes could not be read: {}",
                crate::shown::errno(error)
            ))
        })?;
        Ok(Self { input, saved })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // The call waits for output to drain, so a signal can end it early; it is asked again.
        while let Err(rustix::io::Errno::INTR) =
            rustix::termios::tcsetattr(&self.input, OptionalActions::Flush, &self.saved)
        {}
    }
}

#[cfg(test)]
mod tests {
    use kr_protocol::error::ProtocolError;

    use super::*;

    /// A kit that was shown is told to be deleted only when the daemon confirmed that it recorded
    /// nothing. A refusal can follow a recording (an answer the daemon withheld because the local
    /// owner's membership lease ended while it was written), so it ends the call as unknown, and so
    /// does a connection that failed.
    #[test]
    fn only_a_confirmed_refusal_says_that_nothing_was_recorded() {
        let refusals = [
            ErrorCode::PermissionDenied,
            ErrorCode::InvalidArgument,
            ErrorCode::StorageUnavailable,
        ];
        for code in refusals {
            let refused = CliError::Refused(ProtocolError::new(code, "refused"));
            assert!(
                matches!(answer_of(Err(refused)), Answer::Ended(Ended::Unknown)),
                "{code:?} is not a confirmed refusal"
            );
        }
        assert!(matches!(
            answer_of(Err(CliError::Other(Shown::said("the connection failed")))),
            Answer::Ended(Ended::Unknown)
        ));
        assert!(matches!(
            answer_of(Ok(BackupEnableResult::Declined {
                cause: BackupEnableCause::NoAllowance {}
            })),
            Answer::Ended(Ended::Declined(BackupEnableCause::NoAllowance {}))
        ));
    }
}
