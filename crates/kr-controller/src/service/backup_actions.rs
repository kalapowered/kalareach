//! The methods that serve this host's backups to the command line: a restore's reads of the managed
//! storage service, and the owner's setup of what the host backs up.

use kr_protocol::backup_bundle::BackupBundleWriteParams;
use kr_protocol::backup_checkpoint::{
    BackupCheckpointParams, BackupCheckpointResult, HOST_CHECKPOINT_PROOF_DOMAIN,
    HostCheckpointProof, SealedCheckpointProof,
};
use kr_protocol::backup_read::{BackupReadParams, BackupReadResult};
use kr_protocol::backup_setup::{BackupEnableParams, BackupEnableResult, BackupStatusParams};
use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::scalars::{Bytes, Nullable};

use kr_crypto::sealed::seal_stored_envelope;
use kr_crypto::sign::SigningTranscript;

use crate::backup::setup::SetupAdmission;
use crate::error::{ControllerError, Result};
use crate::given::Given;

use super::{Controller, parse};

impl Controller {
    /// Answers `backup.read`.
    ///
    /// Everything but the question of which service this host is configured for reads content that
    /// a restore writes outside the host's retention, so it follows privacy mode as `kr export`
    /// does. It is refused while privacy mode is on. The state is read as the read begins, checked
    /// again where the request leaves the host (after the wait for an account token, which can be
    /// long), and read once more when the service has answered: an answer whose read ended under
    /// another state than it began under is not given. A request already on its way when privacy
    /// mode is turned on cannot be recalled; what it returns is dropped here, and the command
    /// reads privacy mode again after the last answer.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::PermissionDenied`] while privacy mode is on or when it changed during the
    /// read, and the relay's own refusals otherwise.
    pub(super) async fn backup_read(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let read: BackupReadParams = parse(params)?;
        let Some(relay) = &self.backup_relay else {
            return Err(ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so there \
                 is nothing to read a backup from",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            )));
        };
        let held = !matches!(read, BackupReadParams::Service {});
        let before = self.privacy.state().now();
        if held && before.private {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode is on, and a restore reads nothing while it is".to_owned(),
            });
        }
        let answer: BackupReadResult = relay.read(read, before).await?;
        if held && self.privacy.state().now() != before {
            return Err(ControllerError::PermissionDenied {
                detail: "privacy mode changed while that was read, so the answer is not given"
                    .to_owned(),
            });
        }
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.bundle.write`: moves the recovery bundle on by one compare-and-swap, for a
    /// restore that has verified a generation and records it.
    ///
    /// The bundle is key material (collection locators, trusted writer keys, generation
    /// checkpoints), not content, so privacy mode neither stops this call nor is stopped by it, as
    /// with `backup.enable`; the restore that calls it has refused to run under privacy mode
    /// before it does. A delay the service named still holds it. The daemon keeps no record of the
    /// write.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service, and
    /// the relay's own refusals otherwise.
    pub(super) async fn backup_bundle_write(
        &self,
        mutation: &MutationRequest,
    ) -> Result<ParamsValue> {
        let write: BackupBundleWriteParams = parse(&mutation.params)?;
        let Some(relay) = &self.backup_relay else {
            return Err(ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so there \
                 is no bundle to write",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            )));
        };
        let answer = relay.write_bundle(write).await?;
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.status`: where this host's backups stand, for the owner who is setting them
    /// up.
    ///
    /// The service is read live, bounded, and not at all while the service has asked to be left
    /// alone.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::InvalidArgument`] for parameters that are not empty, and
    /// [`ControllerError::RegistryUnavailable`] when the record of the setup cannot be read: a
    /// store that could not be read does not say that the host is not set up.
    pub(super) async fn backup_status(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let _: BackupStatusParams = parse(params)?;
        let setup = self.backup_setup_of()?;
        let answer = setup.status(self.privacy.state().now().private).await?;
        ParamsValue::from_typed(&answer)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.checkpoint`: the newest generation of the current setup that the storage
    /// service accepted and this host still keeps, and a box that proves which host answered.
    ///
    /// The host reads its own records and asks no service, so the answer does not wait for the
    /// service and privacy mode does not hold it: the record names a generation and the hash of
    /// its manifest and carries no content. A host with no storage service configured answers from
    /// its store as any other does.
    ///
    /// The box goes from this host's own stored-envelope key to the key the ask carried, and holds
    /// the challenge the ask carried, the endpoint this host's own identity serves and the answer.
    /// The endpoint is never a value of the ask: a host that is asked on behalf of another host
    /// names its own. The box is made after the blocking read has joined.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] for parameters that lack the challenge or the
    /// reply key or carry another member, [`ControllerError::RegistryUnavailable`] when the records
    /// cannot be read as a checkpoint (a host that could not read them does not say it has
    /// published nothing), and [`ControllerError::Storage`] when the box cannot be made.
    pub(super) async fn backup_checkpoint(&self, params: &ParamsValue) -> Result<ParamsValue> {
        let ask: BackupCheckpointParams = parse(params)?;
        let backup = std::sync::Arc::clone(&self.backup);
        let checkpoint = tokio::task::spawn_blocking(move || backup.latest_published())
            .await
            .map_err(|_| ControllerError::RegistryUnavailable {
                detail: "the thread that reads the recorded backups did not finish".to_owned(),
            })??;
        let checkpoint = Nullable(checkpoint);
        let unsealed = |error: kr_crypto::CryptoError| ControllerError::Storage {
            operation: "seal the proof of the backup checkpoint",
            detail: error.to_string(),
        };
        let plaintext = SigningTranscript::from_object(
            HOST_CHECKPOINT_PROOF_DOMAIN,
            &HostCheckpointProof {
                challenge: ask.challenge,
                host_endpoint_id: self.owner_authority().endpoint(),
                checkpoint: checkpoint.clone(),
            },
        )
        .map_err(unsealed)?;
        let (nonce, ciphertext) =
            seal_stored_envelope(&self.stored_envelope, &ask.reply_key, plaintext.as_bytes())
                .map_err(unsealed)?;
        ParamsValue::from_typed(&BackupCheckpointResult {
            checkpoint,
            proof: SealedCheckpointProof {
                nonce,
                ciphertext: Bytes::new(ciphertext),
            },
        })
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `backup.enable`: sets this host's backups up, as the command asked.
    ///
    /// Setting up moves no content: the bundle is key material, so privacy mode neither stops it
    /// nor is stopped by it. What the call writes to the service is the sealed bundle, a writer's
    /// enrolment and the account's retention switch. The registration the call was admitted under
    /// is asked again before each request to the storage service leaves (and once its account
    /// token is in hand, for a request that carries one) and in the transaction that records the
    /// setup, after the requests that can outlast it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when the host selects no storage service,
    /// [`ControllerError::InvalidArgument`] for a call that is not well formed, and what
    /// [`Self::under_registration`] refuses with when the fence this host owes, a withdrawn
    /// registration or the passed deadline stops a request, the record or an answer that tells a
    /// delay.
    pub(super) async fn backup_enable(
        self: &std::sync::Arc<Self>,
        mutation: &MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Given<Result<ParamsValue>> {
        #[cfg(any(test, feature = "testing"))]
        crate::testing::note_backup_enable(self.paths.environment_id(), mutation);
        let params: BackupEnableParams = match parse(&mutation.params) {
            Ok(params) => params,
            Err(refusal) => return Given::fresh(Err(refusal)),
        };
        let admission = std::sync::Arc::new(SetupStands {
            controller: std::sync::Arc::clone(self),
            carried,
        });
        self.enable_backups(params, admission).await.map(|answer| {
            answer.and_then(|answer| {
                ParamsValue::from_typed(&answer)
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
            })
        })
    }

    async fn enable_backups(
        &self,
        params: BackupEnableParams,
        admission: std::sync::Arc<dyn SetupAdmission>,
    ) -> Given<Result<BackupEnableResult>> {
        match self.backup_setup_of() {
            Ok(setup) => setup.enable(params, admission).await,
            Err(refusal) => Given::fresh(Err(refusal)),
        }
    }

    /// Sets this host's backups up as `backup.enable` does, for a suite that stops waiting for the
    /// call while its commit is still to be made. Nothing asks an admission, and the daemon is kept
    /// until the commit has ended, as a call's is.
    ///
    /// # Errors
    ///
    /// As `backup.enable`.
    #[cfg(feature = "testing")]
    pub async fn enable_backups_for_a_test(
        self: &std::sync::Arc<Self>,
        params: BackupEnableParams,
    ) -> Result<BackupEnableResult> {
        self.enable_backups(
            params,
            std::sync::Arc::new(Unchecked(std::sync::Arc::clone(self))),
        )
        .await
        .into_answer_for_test()
    }

    /// Stops the next `backup.status` between its two reads, for a suite that holds a call before
    /// its commit and lets it end in the gap. Returns the end that says the status has arrived and
    /// the end that lets it go.
    #[cfg(feature = "testing")]
    pub fn pause_the_next_status_between_its_reads(
        &self,
    ) -> Option<(
        std::sync::Arc<tokio::sync::Notify>,
        std::sync::Arc<tokio::sync::Notify>,
    )> {
        self.backup_setup
            .as_ref()
            .map(|setup| setup.pause_the_next_status_between_its_reads())
    }

    /// How many reads of the storage state that `backup.status` makes the service has answered with
    /// a refusal, for a suite that needs to tell a read the service refused from one that a bound
    /// cut before the answer came.
    #[cfg(feature = "testing")]
    pub fn backup_status_reads_refused(&self) -> u64 {
        self.backup_setup
            .as_ref()
            .map_or(0, |setup| setup.refused_reads())
    }

    fn backup_setup_of(&self) -> Result<&std::sync::Arc<crate::backup::setup::BackupSetup>> {
        self.backup_setup.as_ref().ok_or_else(|| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) selects no storage service, so \
                 there is nothing to set backups up at",
                kr_protocol::hostinfo::configuration::STORAGE_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })
    }
}

/// The registration a `backup.enable` call was admitted under, asked again as the call goes on. It
/// holds the daemon until the commit has ended, so a commit that went on after the call stopped
/// waiting for it cannot outlive the environment's lock.
struct SetupStands {
    controller: std::sync::Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
}

impl SetupAdmission for SetupStands {
    fn stands(&self) -> Result<()> {
        self.controller.check_registration(&self.carried)
    }

    fn retained(&self) -> Result<()> {
        self.controller
            .check_registration(&crate::authority::AdmittedMutation {
                deadline: None,
                ..self.carried
            })
    }

    fn admitted(&self, write: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        self.controller.under_registration(&self.carried, write)?
    }
}

/// An admission that asks nothing, for a suite that drives the setup without a connection. It
/// keeps the daemon until the commit has ended, as a call's does.
#[cfg(feature = "testing")]
struct Unchecked(std::sync::Arc<Controller>);

#[cfg(feature = "testing")]
impl SetupAdmission for Unchecked {
    fn stands(&self) -> Result<()> {
        let _daemon = &self.0;
        Ok(())
    }

    fn retained(&self) -> Result<()> {
        Ok(())
    }

    fn admitted(&self, write: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let _daemon = &self.0;
        write()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use kr_crypto::keys::StoredEnvelopeKeyPair;
    use kr_crypto::sign::SigningTranscript;
    use kr_protocol::envelope::{ControlFrame, Outcome, Request, Response};
    use kr_protocol::ids::{ActorId, ConnectionId, RequestId};
    use kr_protocol::method::{Method, MethodVersion};

    use super::super::AdmittedConnection;
    use super::super::a_transfer_left_unanswered::daemon;
    use super::*;
    use crate::authority::AdmittedMutation;

    /// One ask of `backup.checkpoint`, as a device makes it: a fresh challenge and the public half
    /// of a fresh key pair, whose secret half opens the box that answers.
    fn fresh_ask() -> (BackupCheckpointParams, StoredEnvelopeKeyPair) {
        let reply = StoredEnvelopeKeyPair::generate().expect("a key pair");
        let ask = BackupCheckpointParams {
            challenge: kr_transport::random::fresh_nonce().expect("a challenge"),
            reply_key: *reply.public(),
        };
        (ask, reply)
    }

    /// One read of `backup.checkpoint` with these parameters, as the daemon's read switch is asked
    /// for it.
    fn request_with(params: &impl serde::Serialize) -> Request {
        Request {
            request_id: RequestId::new(1),
            method: Method::BackupCheckpoint.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(params).expect("encodes"),
        }
    }

    /// One read of `backup.checkpoint` with a complete ask.
    fn checkpoint_request() -> Request {
        request_with(&fresh_ask().0)
    }

    /// The checkpoint is read under a decision that holds `host.manage`, and by no caller that has
    /// no such decision: the guard asks for the decision and never for a name. A caller that the
    /// host cannot name as the owner's socket is refused as the owner's socket is, so a new way
    /// into the read switch does not publish the checkpoint.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_checkpoint_is_refused_to_every_caller_with_no_decision_that_holds_host_manage() {
        let (_temp, controller) = daemon().await;
        let request = checkpoint_request();
        for name in ["local:test", "device:test", "workflow:test", "user:1"] {
            let caller = ActorId::new(name).expect("a principal");
            let answer = controller.read_method(&caller, &request, false).await;
            assert!(
                matches!(
                    &answer,
                    ControlFrame::Response(Response {
                        outcome: Outcome::Error(error),
                        ..
                    }) if error.code == kr_protocol::error::ErrorCode::PermissionDenied
                        && error.message
                            == "the backup checkpoint is read by a paired device, and the \
                                local socket does not serve it"
                ),
                "{name} with no decision that holds host.manage is refused with the checkpoint's \
                 own words: {answer:?}"
            );
        }
    }

    /// The same read under a decision that holds `host.manage` is answered, so the guard refuses
    /// what has no such decision and nothing else.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_checkpoint_is_answered_under_a_decision_that_holds_host_manage() {
        let (_temp, controller) = daemon().await;
        let caller = ActorId::new("device:test").expect("a principal");
        let answer = controller
            .read_method(&caller, &checkpoint_request(), true)
            .await;
        let result = match &answer {
            ControlFrame::Response(Response {
                outcome: Outcome::Ok(value),
                ..
            }) => value.to_typed::<BackupCheckpointResult>().ok(),
            _ => None,
        };
        assert_eq!(
            result.map(|answered| answered.checkpoint),
            Some(Nullable::null()),
            "a host with no setup has no checkpoint: {answer:?}"
        );
    }

    /// The box of an answer opens, with the secret half of the key the ask carried, under this
    /// host's own stored-envelope key, and holds the challenge of the ask, the endpoint this
    /// host's own identity serves and the answer. This daemon has no storage service, and answers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_box_of_an_answer_holds_the_challenge_the_hosts_own_endpoint_and_the_answer() {
        let (_temp, controller) = daemon().await;
        let caller = ActorId::new("device:test").expect("a principal");
        let (ask, reply) = fresh_ask();
        let answer = controller
            .read_method(&caller, &request_with(&ask), true)
            .await;
        let ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) = &answer
        else {
            panic!("the checkpoint is answered: {answer:?}");
        };
        let result: BackupCheckpointResult = value.to_typed().expect("an answer");
        let opened = kr_crypto::sealed::open_stored_envelope(
            &reply,
            controller.stored_envelope.public(),
            &result.proof.nonce,
            result.proof.ciphertext.as_slice(),
        )
        .expect("the box opens under the host's own key");
        let expected = SigningTranscript::from_object(
            HOST_CHECKPOINT_PROOF_DOMAIN,
            &HostCheckpointProof {
                challenge: ask.challenge,
                host_endpoint_id: controller.owner_authority().endpoint(),
                checkpoint: Nullable::null(),
            },
        )
        .expect("the bytes");
        assert_eq!(opened.expose(), expected.as_bytes());
    }

    /// An ask that lacks the challenge or the reply key, one that adds a member (an endpoint, which
    /// a host takes from its own identity and never from an ask), and one with no members are each
    /// refused as an invalid argument. The complete ask is answered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ask_with_a_member_missing_or_added_is_an_invalid_argument() {
        #[derive(serde::Serialize)]
        struct NoMembers {}
        #[derive(serde::Serialize)]
        struct OnlyTheChallenge {
            challenge: kr_protocol::scalars::Nonce256,
        }
        #[derive(serde::Serialize)]
        struct WithAnEndpoint {
            challenge: kr_protocol::scalars::Nonce256,
            reply_key: kr_protocol::scalars::StoredEnvelopeKey,
            host_endpoint_id: kr_protocol::scalars::EndpointKey,
        }

        let (_temp, controller) = daemon().await;
        let caller = ActorId::new("device:test").expect("a principal");
        let (ask, _) = fresh_ask();
        let refused = |answer: &ControlFrame| {
            matches!(
                answer,
                ControlFrame::Response(Response {
                    outcome: Outcome::Error(error),
                    ..
                }) if error.code == kr_protocol::error::ErrorCode::InvalidArgument
            )
        };
        let requests = [
            ("no members", request_with(&NoMembers {})),
            (
                "only the challenge",
                request_with(&OnlyTheChallenge {
                    challenge: ask.challenge,
                }),
            ),
            (
                "an endpoint beside both",
                request_with(&WithAnEndpoint {
                    challenge: ask.challenge,
                    reply_key: ask.reply_key,
                    host_endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([9; 32]),
                }),
            ),
        ];
        for (name, request) in requests {
            let answer = controller.read_method(&caller, &request, true).await;
            assert!(refused(&answer), "{name}: {answer:?}");
        }
        let answer = controller
            .read_method(&caller, &request_with(&ask), true)
            .await;
        assert!(
            matches!(
                &answer,
                ControlFrame::Response(Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "the complete ask is answered: {answer:?}"
        );
    }

    /// The setup is recorded while the registration it was admitted under is held standing: a
    /// withdrawal, or a refusal the authority feed raises, takes the lock this write is run under
    /// for writing, so it lands wholly before the check or wholly after the write and never in it.
    /// The write here asks that lock, as a withdrawal would.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_record_of_a_setup_is_written_while_its_registration_is_held_standing() {
        let (_temp, controller) = daemon().await;
        let revision = controller.policy().authority_revision();
        let connection_id = ConnectionId::new(kr_ipc::new_uuid());
        controller.admitted_write().insert(
            connection_id,
            AdmittedConnection::new(ActorId::new("local:test").expect("a principal"), revision),
        );
        let admission = SetupStands {
            controller: Arc::clone(&controller),
            carried: AdmittedMutation {
                connection_id,
                admitted_revision: revision,
                deadline: None,
            },
        };
        let mut withdrawable_in_the_write = None;

        admission
            .admitted(&mut || {
                withdrawable_in_the_write = Some(controller.commit_hold.try_write().is_ok());
                Ok(())
            })
            .expect("the registration stands");

        assert_eq!(
            withdrawable_in_the_write,
            Some(false),
            "a withdrawal waits for the write to end"
        );
        assert!(
            controller.commit_hold.try_write().is_ok(),
            "the hold is let go when the write has ended"
        );
    }
}
