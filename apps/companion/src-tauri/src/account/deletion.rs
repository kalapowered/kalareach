//! Deleting the account: what the page is told, and what this device settles once it is closed.
//!
//! The page asks what deleting would do, asks for the emailed code, confirms with it, and learns
//! how the removal goes. It names the code and the organisations the person accepted losing and
//! nothing else: the token, the address the codes go to and the receipt that settles a lost answer
//! stay in [`kr_client::services::account::deletion`] and the device's secure store.
//!
//! Every answer is a value the page branches on. A step that could not be taken is a
//! [`Problem`], a kind and never a message, so what the person reads is the page's words for it.
//! Only a failure of this device's own records is an error.
//!
//! # What this device settles
//!
//! Once the account is known to be closed, the stored sign-in is ended by the client. What is
//! left is what only the application can reach: on a phone, the registration of each host's
//! notifications, which the service removed with the account's records of the devices and which
//! the phone would otherwise go on showing as on; and on a computer, the recovery record, which
//! says a bundle is kept at the service when the bundle was deleted, and which is cleared only when
//! it is the deleted account's own. The client runs both as the one owner of the deletion, each
//! until it says it is done, when the confirmation closes the account and at every look after.

use std::sync::Arc;
use std::time::Duration;

use kr_client::services::ServiceHttp;
use kr_client::services::account::deletion::{
    CodeRefusal, DeletionFault, DeletionOutcome, DeletionPreview, DeletionProgress, DeletionRead,
    DeviceSteps, ManagedAccountDeletion, OwnedOrganisation, StepFuture,
};
use kr_client::services::account::{AccountMark, SignedInAccount};
use kr_protocol::service::GatewayOrigin;
use serde::Serialize;

use super::Account;
use crate::error::{CommandError, Result};
use crate::state::AppState;

/// Why a step could not be taken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Problem {
    /// No account is signed in, or the sign-in ended: signing in mends it.
    NeedsSignIn,
    /// The service or this version of the application does not accept the request as made.
    Refused,
    /// Too many tries; try again after this many seconds.
    Busy {
        /// How long to wait.
        seconds: u64,
    },
    /// The service could not send the email.
    MailFailed,
    /// Whether the request had its effect is not known.
    Unsure,
    /// The service could not be reached.
    Unreachable,
    /// A different account is signed in than the one the deletion began for.
    AccountChanged,
    /// The deletion is being worked on, here or in another window of the application.
    InProgress,
}

/// What reading the preview came to.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ViewAnswer {
    /// What deleting would do.
    Ready {
        /// The preview.
        preview: DeletionPreview,
    },
    /// A warning or a choice this version does not know, so the person is not asked to go on.
    CannotShow,
    /// The step could not be taken.
    Problem {
        /// Why.
        problem: Problem,
    },
}

/// What asking for the code came to.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SendAnswer {
    /// The code was sent to the account's address.
    Sent,
    /// The step could not be taken.
    Problem {
        /// Why.
        problem: Problem,
    },
}

/// What the confirmation came to.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConfirmAnswer {
    /// The account is closed. `finished` says the removal was done already.
    Closed {
        /// Whether the whole removal was done inside the request.
        finished: bool,
    },
    /// The code was refused and nothing changed.
    CodeRefused {
        /// Why.
        reason: CodeRefusal,
        /// How many checks the code still allows.
        attempts_left: u32,
    },
    /// The account owns organisations the request did not accept losing; nothing changed.
    Acknowledge {
        /// The organisations.
        organisations: Vec<OwnedOrganisation>,
    },
    /// The answer was lost and the receipt could not say whether the request arrived.
    Unsettled,
    /// The step could not be taken.
    Problem {
        /// Why.
        problem: Problem,
    },
}

impl ConfirmAnswer {
    /// Whether the account is closed.
    #[must_use]
    pub const fn closed(&self) -> bool {
        matches!(self, Self::Closed { .. })
    }
}

/// How the removal is going.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum StatusAnswer {
    /// No deletion is in progress on this device.
    None,
    /// A confirmation left and nothing yet says whether it arrived.
    Unsettled,
    /// The account is closed and the removal is running.
    Open,
    /// The removal has finished.
    Done,
    /// The step could not be taken.
    Problem {
        /// Why.
        problem: Problem,
    },
}

/// The kind of a fault, or the failure of this device's own records.
fn problem(fault: DeletionFault) -> Result<Problem> {
    Ok(match fault {
        DeletionFault::NeedsSignIn => Problem::NeedsSignIn,
        DeletionFault::Refused => Problem::Refused,
        DeletionFault::Busy { seconds } => Problem::Busy { seconds },
        DeletionFault::MailFailed => Problem::MailFailed,
        DeletionFault::Unsure => Problem::Unsure,
        DeletionFault::Unreachable => Problem::Unreachable,
        DeletionFault::AccountChanged => Problem::AccountChanged,
        DeletionFault::InProgress => Problem::InProgress,
        DeletionFault::Local(said) => {
            return Err(CommandError::local_failure(said.to_string()));
        }
    })
}

impl Account {
    /// What deleting the account would do.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this device's records could not be read.
    pub async fn deletion_view(&self) -> Result<ViewAnswer> {
        Ok(match self.deletion.preview().await {
            Ok(DeletionRead::Ready(preview)) => ViewAnswer::Ready { preview },
            Ok(DeletionRead::CannotShow) => ViewAnswer::CannotShow,
            Err(fault) => ViewAnswer::Problem {
                problem: problem(fault)?,
            },
        })
    }

    /// Asks the service to email the code that confirms the deletion.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this device's records could not be read.
    pub async fn deletion_send_code(&self) -> Result<SendAnswer> {
        Ok(match self.deletion.send_code().await {
            Ok(()) => SendAnswer::Sent,
            Err(fault) => SendAnswer::Problem {
                problem: problem(fault)?,
            },
        })
    }

    /// Confirms the deletion. When it closes the account, the device settles what is its own and the
    /// page is told where the device now stands.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this device's records could not be read or kept.
    pub async fn deletion_confirm(
        &self,
        state: &AppState,
        code: &str,
        acknowledged: &[String],
    ) -> Result<ConfirmAnswer> {
        let answer = match self
            .deletion
            .confirm(code, acknowledged, &Steps(state))
            .await
        {
            Ok(DeletionOutcome::Closed { finished }) => ConfirmAnswer::Closed { finished },
            Ok(DeletionOutcome::CodeRefused {
                reason,
                attempts_left,
            }) => ConfirmAnswer::CodeRefused {
                reason,
                attempts_left,
            },
            Ok(DeletionOutcome::Acknowledge { organisations }) => {
                ConfirmAnswer::Acknowledge { organisations }
            }
            Ok(DeletionOutcome::Unsettled) => ConfirmAnswer::Unsettled,
            Err(fault) => ConfirmAnswer::Problem {
                problem: problem(fault)?,
            },
        };
        if answer.closed() {
            self.after_deletion().await;
        }
        Ok(answer)
    }

    /// How the removal is going, for the person whose deletion it is. A look that finds the account
    /// closed settles what this device holds of it. `following` says the page is showing the result
    /// of a deletion and asks how it goes; a page that has only opened is told of a deletion that
    /// has not closed the account, and of nothing else.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this device's records could not be read or kept.
    pub async fn deletion_status(&self, state: &AppState, following: bool) -> Result<StatusAnswer> {
        Ok(match self.deletion.status(following, &Steps(state)).await {
            Ok(status) => {
                if status.closed_now {
                    self.after_deletion().await;
                }
                match status.progress {
                    DeletionProgress::None => StatusAnswer::None,
                    DeletionProgress::Unsettled => StatusAnswer::Unsettled,
                    DeletionProgress::Open => StatusAnswer::Open,
                    DeletionProgress::Done => StatusAnswer::Done,
                }
            }
            Err(fault) => StatusAnswer::Problem {
                problem: problem(fault)?,
            },
        })
    }

    /// Gives up on a deletion whose request is not known to have run, so that this device stops
    /// asking after it.
    ///
    /// # Errors
    ///
    /// Returns a local failure when this device's records could not be read or kept.
    pub async fn deletion_forget(&self) -> Result<StatusAnswer> {
        Ok(match self.deletion.forget().await {
            Ok(()) => StatusAnswer::None,
            Err(fault) => StatusAnswer::Problem {
                problem: problem(fault)?,
            },
        })
    }

    /// The account is closed: no sign-out message belongs beside the signed-out view, and every
    /// window is told.
    async fn after_deletion(&self) {
        self.set_outcome(None);
        self.publish().await;
    }
}

/// How long the recovery record's step waits for another step of recovery to end before it is left
/// for the next look: an export that is saving offline copies holds it for as long as the download.
const RECOVERY_STEP_WAITS: Duration = Duration::from_secs(5);

/// This device's own state, as the client settles it once an account is closed.
struct Steps<'a>(&'a AppState);

impl DeviceSteps for Steps<'_> {
    /// A phone's notification registrations: the service removed them with the account's records of
    /// the devices, and this phone would go on showing them as on. A computer has none, and a phone
    /// whose notifications are not open yet is asked again once they are.
    fn notifications(&self) -> StepFuture<'_> {
        Box::pin(async move {
            match self.0.push() {
                Some(desk) => desk.account_deleted(),
                None => !cfg!(mobile),
            }
        })
    }

    /// The recovery record says a bundle is kept at the service, and the bundle was deleted: when it
    /// is the deleted account's own.
    fn recovery(&self, deleted: AccountMark) -> StepFuture<'_> {
        Box::pin(async move {
            let Ok(recovery) = self.0.recovery() else {
                return false;
            };
            match tokio::time::timeout(RECOVERY_STEP_WAITS, recovery.account_deleted(deleted)).await
            {
                Ok(Ok(())) => true,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "the recovery record could not be cleared after the account was deleted");
                    false
                }
                Err(_) => {
                    tracing::warn!(
                        "another step of recovery is running, so its record is cleared later"
                    );
                    false
                }
            }
        })
    }
}

/// Looks after a deletion an earlier run left, at each start once the records the steps settle are
/// open: the account's closure is learned and settled if it has not been, and a step that was not
/// done is done.
pub async fn resume(state: &AppState, account: &Account) {
    if let Err(error) = account.deletion_status(state, false).await {
        tracing::warn!(
            %error,
            "what the closed account left on this device could not be settled"
        );
    }
}

/// A client for an account that never deletes in this process: it makes no request, because the
/// transport it is given has no way to send one.
#[must_use]
pub fn never_deleting(
    origin: &GatewayOrigin,
    signed_in: &Arc<SignedInAccount>,
) -> Arc<ManagedAccountDeletion> {
    Arc::new(ManagedAccountDeletion::new(
        origin,
        Arc::new(Silent) as Arc<dyn ServiceHttp>,
        Arc::clone(signed_in),
    ))
}

/// A transport that sends nothing.
#[derive(Debug)]
struct Silent;

impl ServiceHttp for Silent {
    fn post_json<'a>(
        &'a self,
        _url: &'a str,
        _body: &'a [u8],
        _headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, kr_client::services::ServiceHttpAnswer> {
        Box::pin(async {
            Err(kr_client::error::ClientError::refusal(
                kr_protocol::error::ErrorCode::UpstreamUnavailable,
                kr_client::Shown::said("this application sends no request to delete the account"),
            ))
        })
    }
}
