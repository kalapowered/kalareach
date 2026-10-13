//! `kr backup restore`: a backup, opened with the recovery kit, written as readable files.
//!
//! The restore runs in this process. The control daemon relays the ciphertext it reads with the
//! host's account ([`super::source`]); the kit, the seed derived from it and every plaintext stay
//! here. Nothing is imported into the host. The files go into a folder the person made, and what
//! comes back is data to read: no key, no grant, no device, and the host's configuration as a file
//! and not applied.
//!
//! The order is the library's ([`kr_client::recovery::FilesRestore`]), with this command's steps
//! around it:
//!
//! 1. Outside every session, and the folder checked, before anything is read.
//! 2. Privacy mode read: a restore puts content on disk outside the host's retention, so it does
//!    not start while privacy mode is on.
//! 3. The kit read, and shown back with echo on, so a mistyped locator shows before it is used.
//! 4. The plan: what would be written, what is refused and why, and a digest of all of it with the
//!    destination and the environment. The person confirms that digest: at the terminal, or by
//!    giving it back with `--confirm-plan` after a `--preview`.
//! 5. Only then the folder is opened and held, its publication probed, and each member read,
//!    opened and written, one at a time.
//! 6. Privacy mode read again. If it is on, or moved, the files are removed and no record is made.
//! 7. `restore.json`, written last and given its name whole.
//!
//! A run that fails or is interrupted before step 7 removes the files it made, by name, through
//! the handle on the folder. A directory without `restore.json` is an incomplete restore.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use kr_client::error::ClientError;
use kr_client::recovery::{
    CandidateState, MemberRole, PreparedRestore, RestoreError, RestorePlan, RestoreSource,
};
use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ArchiveId, BackupObjectId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};

use super::directory::{Destination, Held};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output::Document;

/// What the person asked of this restore.
#[derive(Clone, PartialEq, Eq)]
pub enum Decision {
    /// Show the plan and its digest, and write nothing.
    Preview,
    /// Write only when the plan has this digest.
    Confirmed(String),
    /// Show the plan, and ask at the terminal.
    Ask,
}

kr_client::debug_as_name!(Decision);

/// The two readings of privacy mode a restore makes.
pub trait Privacy {
    /// Where privacy mode stands for the environment this connection reaches.
    ///
    /// # Errors
    ///
    /// Returns the daemon's refusal, or a transport failure.
    fn status(&mut self) -> impl Future<Output = Result<PrivacyReport>>;
}

impl Privacy for Daemon {
    async fn status(&mut self) -> Result<PrivacyReport> {
        self.read(Method::PrivacyStatus, &PrivacyStatusParams {})
            .await
    }
}

/// How the restore reaches the person.
pub trait Conversation {
    /// Shows the plan.
    fn show(&mut self, lines: &[Shown]);

    /// Puts a question and returns the answer, or none at the end of the input.
    ///
    /// # Errors
    ///
    /// Returns an error when the answer cannot be read.
    fn ask(&mut self, question: &Shown) -> impl Future<Output = Result<Option<String>>>;
}

/// The person at the terminal: the plan and the question on the error stream, the answer from
/// standard input.
pub struct AtTheTerminal;

impl Conversation for AtTheTerminal {
    fn show(&mut self, lines: &[Shown]) {
        for line in lines {
            crate::report::say(line);
        }
    }

    async fn ask(&mut self, question: &Shown) -> Result<Option<String>> {
        super::kit::ask_line(question).await
    }
}

/// What one restore is given besides the kit.
pub struct Run<'a> {
    /// Where ciphertext comes from.
    pub source: Arc<dyn RestoreSource>,
    /// Privacy mode as it stood when the command began.
    pub began: &'a PrivacyReport,
    /// The folder, checked.
    pub destination: &'a Destination,
    /// The environment, as the plan's digest holds it.
    pub environment: String,
    /// The archive asked for, when the bundle names several.
    pub archive: Option<ArchiveId>,
    /// What the person asked.
    pub decision: Decision,
}

/// The plan, with the digest the person confirms and where it would be written.
pub struct Planned {
    plan: RestorePlan,
    digest: String,
    folder: PathBuf,
}

kr_client::debug_as_name!(Planned);

impl Planned {
    /// The digest, as lowercase hexadecimal.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The folder the files go into.
    #[must_use]
    pub fn folder(&self) -> &std::path::Path {
        &self.folder
    }

    /// The plan.
    #[must_use]
    pub const fn plan(&self) -> &RestorePlan {
        &self.plan
    }

    /// The plan as lines for a person.
    #[must_use]
    pub fn lines(&self) -> Vec<Shown> {
        let plan = &self.plan;
        let mut lines = vec![
            Shown::said(
                "A restore writes readable copies into the folder below. Nothing is imported into \
                 this host.",
            ),
            shown!("  folder           {}", crate::shown::named(&self.folder)),
            shown!("  service          {}", Shown::address(&plan.origin)),
            shown!("  archive          {}", plan.archive_id.get()),
            shown!("  generation       {}", plan.generation.get()),
            shown!(
                "  published        {}",
                crate::shown::utc_moment(plan.published_at_ms.get())
            ),
            shown!("  written by key   {}", Shown::key_identifier(&plan.writer)),
            shown!(
                "  standing         {}",
                Shown::restore_standing(&plan.standing)
            ),
            shown!("  bundle revision  {}", plan.bundle_revision),
            Shown::said("Files:"),
        ];
        let mut any = false;
        for (member, file, role) in plan.restored() {
            any = true;
            lines.push(shown!(
                "  {}  {} bytes  ({})",
                Shown::restored_file(file),
                member.plaintext_len.unwrap_or(0),
                role_words(role)
            ));
        }
        if !any {
            lines.push(Shown::said("  none"));
        }
        for (member, refusal) in plan.refused() {
            lines.push(shown!(
                "Not restored: object {}, stored as {} bytes: {}",
                member.object_id.get(),
                member.stored_len,
                refusal.said()
            ));
        }
        lines.push(Shown::said(
            "No key, grant or device comes back, and the host's configuration, if it is in the \
             backup, is a file to read and not applied.",
        ));
        lines.push(shown!(
            "Digest of this plan: {}",
            crate::shown::hex_digest(&self.digest)
        ));
        lines
    }

    /// The plan as the one `--json` document.
    #[must_use]
    pub fn document(&self) -> Document {
        let plan = &self.plan;
        let files: Vec<Document> = plan
            .restored()
            .map(|(member, file, role)| {
                Document::new()
                    .with("file", Shown::restored_file(file))
                    .with("bytes", member.plaintext_len.unwrap_or(0))
                    .with("role", role_words(role))
            })
            .collect();
        let refused: Vec<Document> = plan
            .refused()
            .map(|(member, refusal)| {
                Document::new()
                    .with("object", crate::output::said(&member.object_id.get()))
                    .with("stored_bytes", member.stored_len)
                    .with("because", refusal.said())
            })
            .collect();
        Document::new()
            .with("folder", shown!("{}", crate::shown::named(&self.folder)))
            .with("service", Shown::address(&plan.origin))
            .with("archive", crate::output::said(&plan.archive_id.get()))
            .with("backup_generation", plan.generation.get())
            .with("published_at_ms", plan.published_at_ms.get())
            .with("writer_key", Shown::key_identifier(&plan.writer))
            .with("standing", Shown::restore_standing(&plan.standing))
            .with("bundle_revision", plan.bundle_revision)
            .with("digest", crate::shown::hex_digest(&self.digest))
            .with("files", files)
            .with("not_restored", refused)
    }
}

const fn role_words(role: MemberRole) -> &'static str {
    match role {
        MemberRole::Session => "a session's export",
        MemberRole::Configuration => "the host's configuration document",
    }
}

/// What a restore did.
pub enum Outcome {
    /// The plan was shown and nothing was written.
    Previewed(Planned),
    /// Every file in the plan was written and the record was published.
    Restored {
        /// The plan that was confirmed.
        planned: Planned,
        /// What could not be tidied after the record was published.
        warnings: Vec<Shown>,
    },
}

kr_client::debug_as_name!(Outcome);

/// Opens the archive the kit names, shows the plan, and, once it is confirmed, writes the files.
///
/// `held` is where the folder's handle is kept once it is opened, so a caller whose run ends
/// early can remove what was written whatever ended it.
///
/// # Errors
///
/// Returns the refusal that stopped the restore, said with what a person does about it. A failure
/// after the first file was written leaves the cleanup to the caller.
pub async fn restore_with<P: Privacy, C: Conversation>(
    run: Run<'_>,
    kit: kr_protocol::archive::RecoveryKit,
    privacy: &mut P,
    talk: &mut C,
    held: &mut Option<Held>,
) -> Result<Outcome> {
    let prepared =
        match kr_client::recovery::FilesRestore::prepare(kit, Arc::clone(&run.source), run.archive)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => return Err(explain(error, privacy, run.began).await),
        };
    let planned = plan_of(&prepared, &run)?;
    match &run.decision {
        Decision::Preview => return Ok(Outcome::Previewed(planned)),
        Decision::Confirmed(digest) => {
            if *digest != planned.digest {
                return Err(changed());
            }
        }
        Decision::Ask => {
            talk.show(&planned.lines());
            let question = Shown::said("Type yes to write these files, or anything else to stop:");
            let yes = talk
                .ask(&question)
                .await?
                .is_some_and(|typed| typed.trim().eq_ignore_ascii_case("yes"));
            if !yes {
                return Err(CliError::Other(Shown::said(
                    "the restore was not confirmed, so nothing was written",
                )));
            }
        }
    }

    // Confirmed: the folder is opened for the run and held, and tried before the first download.
    let folder = held.insert(run.destination.open()?);
    folder.probe_publication()?;
    let mut written: Vec<BackupObjectId> = Vec::new();
    for (member, file, _) in planned.plan.restored() {
        let plaintext = match prepared.member(member.object_id).await {
            Ok(plaintext) => plaintext,
            Err(error) => return Err(explain(error, privacy, run.began).await),
        };
        folder.write_member(file, plaintext.expose())?;
        written.push(member.object_id);
    }

    // The second reading: a change in the window after the last answer is caught here.
    let after = privacy.status().await?;
    if after.enabled || after.generation != run.began.generation {
        return Err(moved());
    }
    let record = serde_json::to_vec_pretty(&planned.plan.record(&planned.digest, &written))
        .map_err(|error| {
            CliError::Other(shown!(
                "the record could not be encoded: {}",
                Shown::json(&error)
            ))
        })?;
    let warnings = folder.publish_record(&record)?;
    Ok(Outcome::Restored { planned, warnings })
}

fn plan_of(prepared: &PreparedRestore, run: &Run<'_>) -> Result<Planned> {
    let plan = prepared.plan().clone();
    let digest = plan
        .digest(&run.environment, &run.destination.spelled())
        .map_err(|error| CliError::Other(shown!("{}", error)))?;
    Ok(Planned {
        plan,
        digest,
        folder: run.destination.path().to_path_buf(),
    })
}

/// Refuses a restore that starts while privacy mode is on.
///
/// # Errors
///
/// Returns a refusal naming privacy mode when it is on.
pub fn refuse_while_private(report: &PrivacyReport) -> Result<()> {
    if report.enabled {
        return Err(CliError::refused_in_its_own_words(
            ErrorCode::PermissionDenied,
            Shown::said(
                "privacy mode is on in this environment, so nothing is restored while it is on: \
                 a restore puts content on disk outside what this host retains; turn privacy mode \
                 off with `kr privacy off` once its cleanup is complete, then restore",
            ),
        ));
    }
    Ok(())
}

fn moved() -> CliError {
    CliError::Unfinished {
        code: ErrorCode::ResourceUnavailable,
        message: Shown::said(
            "privacy mode was turned on, or changed, while the files were being written, so the \
             files this restore wrote were removed and no record was made; restore again",
        ),
    }
}

fn changed() -> CliError {
    CliError::Other(Shown::said(
        "that is not the digest of what would be restored now: the backup, the folder or the \
         environment is not what was previewed, so nothing was written; preview again",
    ))
}

/// Says why a restore stopped, and what a person does about it.
async fn explain<P: Privacy>(
    error: RestoreError,
    privacy: &mut P,
    began: &PrivacyReport,
) -> CliError {
    match error {
        RestoreError::NotSignedIn { cause, .. } => CliError::refused_in_its_own_words(
            ErrorCode::PermissionDenied,
            shown!("{}. {}", cause.why(), cause.remedy()),
        ),
        RestoreError::OriginNotConfigured => CliError::Usage(Shown::said(
            "the recovery kit names no storage service this host is configured for. This host \
             reads backups from the managed account service its storage.origin names, and a \
             backup kept only at a self-hosted service cannot be restored here",
        )),
        RestoreError::BundleAbsent => CliError::Other(Shown::said(
            "the storage service holds no recovery bundle for this account at that locator. The \
             service may not have accepted this host's sign-in (sign in again with `kr account \
             sign-in`), this host may be signed in to another account than the one that holds \
             the backup (`kr account show` says which), or the locator may have been copied \
             wrongly",
        )),
        RestoreError::SeveralArchives { count, candidates } => {
            let mut lines = vec![shown!(
                "the recovery bundle names {} archives at this service; choose one with --archive:",
                count
            )];
            for candidate in &candidates {
                lines.push(match &candidate.newest {
                    CandidateState::Nothing => shown!(
                        "  {}: the service holds nothing as new as the bundle's checkpoint",
                        candidate.archive_id.get()
                    ),
                    CandidateState::Refused(refusal) => shown!(
                        "  {}: its newest publication is not one a restore opens: {}",
                        candidate.archive_id.get(),
                        *refusal
                    ),
                    CandidateState::Newest(newest) => shown!(
                        "  {}: generation {}, published {}, signed by key {}",
                        candidate.archive_id.get(),
                        newest.generation.get(),
                        crate::shown::utc_moment(newest.published_at_ms.get()),
                        Shown::key_identifier(&newest.writer)
                    ),
                });
            }
            CliError::Usage(Shown::joined(lines, "\n"))
        }
        RestoreError::Read(ClientError::Host(refusal))
            if refusal.code == ErrorCode::PermissionDenied =>
        {
            // The relay refuses with one code for privacy mode and for a sign-in the service did
            // not accept; privacy mode decides which advice is true.
            let private = match privacy.status().await {
                Ok(now) => Some(now.enabled || now.generation != began.generation),
                Err(_) => None,
            };
            match private {
                Some(true) => CliError::refused_in_its_own_words(
                    ErrorCode::PermissionDenied,
                    Shown::said(
                        "privacy mode is on, or changed, so nothing is restored: turn it off with \
                         `kr privacy off` once its cleanup is complete, then restore again",
                    ),
                ),
                Some(false) => CliError::refused_in_its_own_words(
                    ErrorCode::PermissionDenied,
                    Shown::said(
                        "the storage service did not accept this host's sign-in; sign this host \
                         in again with `kr account sign-in`",
                    ),
                ),
                None => CliError::Refused(refusal),
            }
        }
        RestoreError::Read(ClientError::Host(refusal)) => CliError::Refused(refusal),
        RestoreError::Read(ClientError::Ipc(failure)) => CliError::Ipc(failure),
        other => CliError::Other(shown!("{}", other)),
    }
}
