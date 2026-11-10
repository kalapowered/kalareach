//! A spoken request that needs the person's confirmation on the phone's unlocked screen, from the
//! host's challenge to the request that carries the signature.
//!
//! The steps, in order, each of which can stop it and none of which can be skipped:
//!
//! 1. The challenge is compared with what this device sent and with the call ([`Challenge::check`]),
//!    and the phone's own clock must not say it has run out. Nobody is asked until both hold.
//! 2. The platform's ceremony asks the person, on a task of its own so that nothing waits for it.
//!    What it answers is used only for the confirmation it was started for.
//! 3. After the ceremony a capture proof is taken with a marker, and the news is read up to the
//!    marker, so that anything said while the person was being asked, which native code had told
//!    before the proof, has been read. The task that reads the proof raises the flag every write
//!    waits on when the proof shows what ends the call's authority, so no other request held for the
//!    connection's turn leaves before the owner has handled the message that tells it.
//! 4. Taint, the path to the host and the phone's clock are looked at once more, and only then is
//!    the challenge signed with the device's own key and the request sent, under the same action and
//!    with the same fragments, by the hand-over that sent the first: a fresh proof is taken just
//!    before the write and its age is held to through it.
//!
//! The first request was settled when the host answered it, so the signed one is composed after
//! that. It is composed once: a request whose answer is lost is asked about again with the request
//! as it was composed, on another connection, and never sent again as new.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use companion_platform::call::{CallFailure, CaptureProof};
use kr_client::pairing::owner::CeremonyOutcome;
use kr_client::services::voice_confirm::sign_voice_confirmation;
use kr_client::session::ComposedMutation;
use kr_protocol::method::Method;
use kr_protocol::voice::{VoiceConfirmationRequest, VoiceDelegateResult};
use tokio::time::Instant;

use super::{
    DELEGATION_CHALLENGE_MISMATCH, DELEGATION_CONFIRMATION, DELEGATION_CONFIRMATION_DROPPED,
    DELEGATION_CONFIRMATION_EXPIRED, DELEGATION_HOST_REFUSED, DELEGATION_LATE,
    DELEGATION_NO_CEREMONY, DELEGATION_NOT_CONFIRMED, DELEGATION_SESSION_NOT_NAMED, Handover,
    Internal, Owner, Record, SPEECH_TAINTED, Why, hand_over,
};
use crate::voice::confirm::{Challenge, Known, reason};

/// A challenge the person is being asked about.
pub(super) struct Confirming {
    challenge: Challenge,
    /// Which confirmation this is, so that a ceremony's answer or a proof is taken for the one it
    /// was asked for and for no later one.
    generation: u64,
    /// Cleared when the confirmation is dropped, however it is: the task that is to ask the person
    /// looks at it once more before it does.
    open: Arc<AtomicBool>,
}

impl Drop for Confirming {
    fn drop(&mut self) {
        self.open.store(false, Ordering::SeqCst);
    }
}

/// A confirmation whose ceremony is done and whose news is being read up to a marker.
pub(super) struct Sealing {
    id: String,
    generation: u64,
    /// The marker the proof answered, when it has.
    token: Option<u64>,
    /// What the proof's record showed, when it has.
    record: Option<Record>,
    /// When the confirmation is dropped as not drained.
    pub(super) until: Instant,
}

/// What the model is told of a confirmation that was stopped, for `why`.
fn dropped_words(why: Why) -> &'static str {
    match why {
        Why::LateFragment => DELEGATION_LATE,
        Why::NotConfirmed => DELEGATION_NOT_CONFIRMED,
        Why::NoCeremony => DELEGATION_NO_CEREMONY,
        Why::ChallengeMismatch => DELEGATION_CHALLENGE_MISMATCH,
        Why::ConfirmationExpired => DELEGATION_CONFIRMATION_EXPIRED,
        Why::SessionNotNamed => DELEGATION_SESSION_NOT_NAMED,
        why if why.taints() => SPEECH_TAINTED,
        _ => DELEGATION_CONFIRMATION_DROPPED,
    }
}

impl Owner {
    /// The host answered a delegation with a challenge, to `composed`, the request as it was made.
    pub(in crate::voice) fn on_challenge(
        &mut self,
        id: &str,
        result: VoiceDelegateResult,
        request: VoiceConfirmationRequest,
        composed: Option<ComposedMutation>,
    ) {
        if self.signed.contains(id) {
            // The request that carried the signature was answered with a challenge: the host did
            // not take the confirmation. The person is not asked a second time.
            self.unsettled.remove(id);
            self.set_row(id, "host_refused", Some("confirmation_not_taken"));
            self.tell_delegation(id, DELEGATION_HOST_REFUSED.to_owned());
            return;
        }
        if self.confirming.contains_key(id) {
            return;
        }
        // A challenge admits nothing: what the host holds of it is a claim it gave back.
        self.unsettled.remove(id);
        if let Some(why) = self.gate.taint() {
            self.cancel_row(id, why);
            return;
        }
        // The request was handed over on a connection whose path was lost since: nothing handed
        // over before a loss is carried on after it, whether or not the host is back by now.
        if self
            .sent_under
            .get(id)
            .is_some_and(|lost| lost.load(Ordering::SeqCst))
        {
            self.cancel_row(id, Why::HostLost);
            return;
        }
        let (Some(unsigned), Some(host), Some(descriptor)) =
            (composed, self.host.as_ref(), self.descriptor.as_ref())
        else {
            self.cancel_row(id, Why::NotComposed);
            return;
        };
        let challenge = Challenge {
            unsigned,
            result,
            request,
        };
        let known = Known {
            host_device_id: host.paired.host_device_id,
            device_id: host.paired.device_id,
            descriptor,
        };
        if let Err(mismatch) = challenge.check(&known) {
            tracing::warn!(?mismatch, "the host's challenge was not put to the person");
            self.cancel_row(id, Why::ChallengeMismatch);
            return;
        }
        let now = self.shared.confirmation_now_ms();
        let expires = challenge.request.expires_at_ms.get();
        if now >= expires {
            self.cancel_row(id, Why::ConfirmationExpired);
            return;
        }
        let generation = self.next_confirmation;
        self.next_confirmation += 1;
        let (ceremony, internal) = (Arc::clone(&self.shared.ceremony), self.internal_tx.clone());
        let (session, name) = (host.session.clone(), host.paired.name.clone());
        let (action, session_id) = (challenge.request.action, challenge.result.session_id.0);
        let (shared, open) = (Arc::clone(&self.shared), Arc::new(AtomicBool::new(true)));
        let still_open = Arc::clone(&open);
        self.set_row(id, "confirmation_required", None);
        self.tell_delegation(id, DELEGATION_CONFIRMATION.to_owned());
        self.confirming.insert(
            id.to_owned(),
            Confirming {
                challenge,
                generation,
                open,
            },
        );
        let id = id.to_owned();
        tokio::spawn(async move {
            let number = match session_id {
                Some(session_id) => {
                    let params = kr_protocol::session::SessionReadParams { session_id };
                    let read = session.read::<_, kr_protocol::session::SessionReadResult>(
                        Method::SessionRead,
                        &params,
                    );
                    match tokio::time::timeout(shared.timings.session_name_within, read).await {
                        // The number names the session the signature covers only when the host
                        // answered for that session.
                        Ok(Ok(read)) if read.session.session_id == session_id => {
                            Some(read.session.display_number.get())
                        }
                        _ => None,
                    }
                }
                None => None,
            };
            // The wait for the session's number took time: the person is asked only if the
            // confirmation is still open and the phone's clock does not say it has run out, and
            // for what is left of it.
            if !still_open.load(Ordering::SeqCst) {
                #[cfg(any(test, feature = "testing"))]
                shared.handled.ceremony(&id);
                return;
            }
            // A person is not asked to confirm what they cannot tell the target of: the dialog
            // names the session by the number the host gives it, and without one nobody is asked.
            let Some(number) = number else {
                let _ = internal.send(Internal::Unnamed { id, generation });
                return;
            };
            let now = shared.confirmation_now_ms();
            let outcome = if now >= expires {
                CeremonyOutcome::NotConfirmed
            } else {
                ceremony
                    .verify(
                        &reason(action, number, name.as_deref()),
                        Duration::from_millis(expires - now),
                    )
                    .await
            };
            let _ = internal.send(Internal::Ceremony {
                id,
                generation,
                outcome,
            });
        });
    }

    /// The session the confirmation is for could not be named to the person in time.
    pub(in crate::voice) fn on_unnamed(&mut self, id: &str, generation: u64) {
        if !self.is_current(id, generation) {
            return;
        }
        self.confirming.remove(id);
        self.cancel_row(id, Why::SessionNotNamed);
    }

    /// What the person's ceremony came to.
    pub(in crate::voice) fn on_ceremony(
        &mut self,
        id: &str,
        generation: u64,
        outcome: CeremonyOutcome,
    ) {
        if !self.is_current(id, generation) {
            return;
        }
        match outcome {
            CeremonyOutcome::NotConfirmed => {
                // A dialog that ended because the challenge ran out is the challenge's end.
                let ran_out = self.confirmation_ran_out(id);
                self.confirming.remove(id);
                self.cancel_row(
                    id,
                    if ran_out {
                        Why::ConfirmationExpired
                    } else {
                        Why::NotConfirmed
                    },
                );
            }
            CeremonyOutcome::Unavailable => {
                self.confirming.remove(id);
                self.cancel_row(id, Why::NoCeremony);
            }
            CeremonyOutcome::Confirmed => self.start_sealing(id, generation),
        }
    }

    /// Whether `generation` is the confirmation of the delegation `id` that is open now.
    fn is_current(&self, id: &str, generation: u64) -> bool {
        self.confirming
            .get(id)
            .is_some_and(|open| open.generation == generation)
    }

    /// The person confirmed: the news is read up to a marker before anything is signed.
    fn start_sealing(&mut self, id: &str, generation: u64) {
        if let Some(why) = self.gate.taint() {
            self.confirming.remove(id);
            self.cancel_row(id, why);
            return;
        }
        if self.confirmation_ran_out(id) {
            self.confirming.remove(id);
            self.cancel_row(id, Why::ConfirmationExpired);
            return;
        }
        let Some(call) = self.call.clone() else {
            self.confirming.remove(id);
            self.cancel_row(id, Why::NotComposed);
            return;
        };
        let (platform, internal, tainted) = (
            self.platform(),
            self.internal_tx.clone(),
            Arc::clone(&self.tainted),
        );
        self.sealing.push(Sealing {
            id: id.to_owned(),
            generation,
            token: None,
            record: None,
            until: Instant::now() + self.shared.timings.drain_within,
        });
        self.arm_collection();
        let id = id.to_owned();
        tokio::spawn(async move {
            let result = platform.capture_proof(&call, true).await;
            // What the proof shows of capture is acted on here, where it is read: a request that
            // waits for the connection's turn is stopped now, and not when the owner next handles a
            // message.
            if let Ok(proof) = &result
                && proof.call == call
                && Record::of(proof).ends_authority()
            {
                tainted.store(true, Ordering::SeqCst);
            }
            let _ = internal.send(Internal::SealProof {
                id,
                generation,
                result,
            });
        });
    }

    /// Whether the phone's own clock says the challenge of the delegation `id` has run out.
    fn confirmation_ran_out(&self, id: &str) -> bool {
        self.confirming.get(id).is_some_and(|open| {
            self.shared.confirmation_now_ms() >= open.challenge.request.expires_at_ms.get()
        })
    }

    /// Native code answered the proof a confirmation asked for after its ceremony.
    pub(in crate::voice) fn on_seal_proof(
        &mut self,
        id: &str,
        generation: u64,
        result: std::result::Result<CaptureProof, CallFailure>,
    ) {
        // What a proof of this call shows of capture taints the call at once, whoever asked for it.
        if let Ok(proof) = &result
            && Some(&proof.call) == self.call.as_ref()
        {
            let told = self.gate.note_record(Record::of(proof));
            self.after_gate(told);
        }
        let Some(position) = self
            .sealing
            .iter()
            .position(|sealing| sealing.id == id && sealing.generation == generation)
        else {
            return;
        };
        match result {
            Ok(proof) if Some(&proof.call) == self.call.as_ref() && proof.barrier.is_some() => {
                let sealing = &mut self.sealing[position];
                sealing.token = proof.barrier;
                sealing.record = Some(Record::of(&proof));
                self.try_seal();
            }
            _ => {
                self.sealing.remove(position);
                if self.is_current(id, generation) {
                    self.confirming.remove(id);
                    self.cancel_row(id, Why::NoProof);
                }
                self.arm_collection();
            }
        }
    }

    /// Signs and sends each confirmation whose proof's record and news up to its marker are both in
    /// hand: everything native code had told before the proof was read has been read.
    pub(in crate::voice) fn try_seal(&mut self) {
        let now = Instant::now();
        let mut ready = Vec::new();
        let mut index = 0;
        while index < self.sealing.len() {
            let sealing = &self.sealing[index];
            let read = matches!(
                (sealing.token, sealing.record),
                (Some(token), Some(_)) if self.barriers.contains(&token) && now < sealing.until
            );
            if read {
                ready.push(self.sealing.remove(index));
            } else {
                index += 1;
            }
        }
        for sealing in ready {
            self.finish_sealing(&sealing.id, sealing.generation);
        }
        self.arm_collection();
    }

    /// Drops each confirmation whose news was not read up to its marker in time.
    pub(in crate::voice) fn expire_sealing(&mut self) {
        let now = Instant::now();
        let mut late = Vec::new();
        self.sealing.retain(|sealing| {
            if now >= sealing.until {
                late.push((sealing.id.clone(), sealing.generation));
                false
            } else {
                true
            }
        });
        for (id, generation) in late {
            if self.is_current(&id, generation) {
                self.confirming.remove(&id);
                self.cancel_row(&id, Why::NotDrained);
            }
        }
    }

    /// The last look before the signature: taint, the path to the host and the phone's clock.
    fn finish_sealing(&mut self, id: &str, generation: u64) {
        if !self.is_current(id, generation) {
            return;
        }
        let Some(open) = self.confirming.remove(id) else {
            return;
        };
        if let Some(why) = self.gate.taint() {
            self.cancel_row(id, why);
        } else if self.tainted.load(Ordering::SeqCst) {
            // A proof showed a break that the owner has still to read: the gate will say which.
            self.cancel_row(id, Why::CaptureBreak);
        } else if self.unsent.load(Ordering::SeqCst) {
            self.cancel_row(id, Why::HostLost);
        } else if self.shared.confirmation_now_ms() >= open.challenge.request.expires_at_ms.get() {
            self.cancel_row(id, Why::ConfirmationExpired);
        } else {
            self.send_signed(id, &open.challenge);
        }
    }

    /// Signs the challenge and sends the delegation again with the signature on it, under the
    /// action it was first sent under.
    fn send_signed(&mut self, id: &str, challenge: &Challenge) {
        let (Some(host), Some(call)) = (self.host.clone(), self.call.clone()) else {
            self.cancel_row(id, Why::NotComposed);
            return;
        };
        let signed = self.reach.authorisation_key().ok().and_then(|key| {
            let proof = sign_voice_confirmation(&key, &challenge.request).ok()?;
            challenge.signed(proof)
        });
        let Some(params) = signed else {
            self.cancel_row(id, Why::NotComposed);
            return;
        };
        self.signed.insert(id.to_owned());
        self.set_row(id, "asking", None);
        self.unsettled.insert(id.to_owned());
        let handover = Handover {
            host,
            platform: self.platform(),
            call,
            action_id: Some(challenge.unsigned.action_id()),
            params,
            age_bound: self.shared.timings.proof_age,
            within: self.shared.timings.host_within,
            lost: Arc::clone(&self.unsent),
            tainted: Arc::clone(&self.tainted),
        };
        let (internal, id) = (self.internal_tx.clone(), id.to_owned());
        tokio::spawn(async move {
            let exchange = hand_over(handover).await;
            let _ = internal.send(Internal::Delivered {
                id,
                exchange: Box::new(exchange),
            });
        });
    }

    /// Stops every confirmation not yet sent, for `why`: what a ceremony or a proof then says of
    /// one is dropped, and the person and the model are told it was not done.
    pub(in crate::voice) fn cancel_confirmations(&mut self, why: Why) {
        self.sealing.clear();
        let open: Vec<String> = self.confirming.drain().map(|(id, _)| id).collect();
        for id in open {
            self.cancel_row(&id, why);
        }
    }

    /// The delegation `id` was dropped before a signed request was sent, for `why`.
    fn cancel_row(&self, id: &str, why: Why) {
        self.set_row(id, "cancelled", Some(why.word()));
        self.tell_delegation(id, dropped_words(why).to_owned());
    }
}
