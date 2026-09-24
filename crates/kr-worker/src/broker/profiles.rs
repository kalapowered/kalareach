//! Launch profiles, the stale-launch refusal and the one-process-per-conversation rule.
//!
//! Section 12 puts three separate obligations on a launch, and they are separate because each one
//! fails differently.
//!
//! * **The profile records what was actually resolved**: the executable, its distribution and
//!   version, the argument vector, the authentication state and the integration mode. A profile
//!   written after the launch would record what the host hoped for; this one is written first.
//! * **A stale launch is refused, never pasted.** "A button submits a launch intent only against
//!   the current idle-shell boundary. If an application takes the foreground before execution, the
//!   host rejects the stale launch. It must never paste a launch command into that application's
//!   input." A refusal is the whole answer, so there is no code path here that writes bytes.
//! * **One live execution per saved conversation.** "An adapter must not start a second agent
//!   process against the same saved conversation to obtain a remote interface."

use std::collections::BTreeMap;

use kr_protocol::broker::{LaunchProfile, LaunchRefusal};
use kr_protocol::ids::{ApplicationInstanceId, LaunchProfileId};
use kr_protocol::scalars::TimestampMs;

use crate::broker::error::{BrokerError, Result};

/// What occupies the terminal at one moment.
///
/// The launch is prepared against one of these and executed against another; if they differ, the
/// intent is stale. Comparing the mark rather than asking "is a program running" is what makes a
/// program that started and exited in between count as a change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForegroundMark {
    /// The application instance in the foreground, when one is.
    ///
    /// `None` is the idle root shell, which is the only boundary a launch may be submitted
    /// against.
    pub application_instance_id: Option<ApplicationInstanceId>,
    /// The root shell's command revision, which advances whenever a command is accepted.
    pub prompt_revision: u64,
}

impl ForegroundMark {
    /// The idle root shell at one prompt revision.
    #[must_use]
    pub const fn idle(prompt_revision: u64) -> Self {
        Self {
            application_instance_id: None,
            prompt_revision,
        }
    }

    /// Returns true when this mark is the idle root shell.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        self.application_instance_id.is_none()
    }
}

/// A launch that has been resolved and not yet executed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaunchIntent {
    /// The profile that will be run.
    pub profile: LaunchProfile,
    /// The boundary the intent was prepared against.
    pub prepared_against: ForegroundMark,
    /// The saved conversation this launch would resume, where it would resume one.
    pub saved_conversation: Option<String>,
}

/// The broker's launch profiles and the conversations they own.
#[derive(Debug, Default)]
pub struct ProfileStore {
    profiles: BTreeMap<LaunchProfileId, LaunchProfile>,
    /// Which instance owns the live execution of each saved conversation.
    conversations: BTreeMap<String, ApplicationInstanceId>,
    /// The profile each instance was launched under.
    instances: BTreeMap<ApplicationInstanceId, LaunchProfileId>,
}

impl ProfileStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the intent to execute a resolved profile, without recording anything.
    ///
    /// The caller writes the profile's record and only then keeps it with
    /// [`ProfileStore::keep`], so a preparation whose record could not be written leaves nothing
    /// behind, not even a replacement for a profile of the same identifier.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] when the boundary is not the idle root shell, because a
    /// launch intent is only ever submitted against that boundary.
    pub fn prepare(
        &self,
        profile: LaunchProfile,
        against: ForegroundMark,
        saved_conversation: Option<String>,
    ) -> Result<LaunchIntent> {
        if !against.is_idle() {
            return Err(BrokerError::Launch(LaunchRefusal::ForegroundChanged));
        }
        Ok(LaunchIntent {
            profile,
            prepared_against: against,
            saved_conversation,
        })
    }

    /// Keeps a profile whose record has been written.
    pub fn keep(&mut self, profile: LaunchProfile) {
        self.profiles.insert(profile.profile_id.clone(), profile);
    }

    /// Executes a prepared intent, or refuses it.
    ///
    /// The three refusals are distinct on purpose. A foreground change says an application is
    /// reading the terminal now, and pasting into it is exactly what section 12 forbids. A moved
    /// prompt says the shell has accepted something else since. A live conversation says another
    /// execution already owns what this launch would resume.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] with the refusal that applies.
    pub fn execute(
        &mut self,
        intent: &LaunchIntent,
        now: &ForegroundMark,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<LaunchProfile> {
        self.check_executable(intent, now, application_instance_id)?;
        if let Some(conversation) = intent.saved_conversation.as_ref() {
            self.conversations
                .insert(conversation.clone(), application_instance_id);
        }
        // Its record was written before this was called, with the instance it now runs as.
        self.keep(intent.profile.clone());
        self.instances
            .insert(application_instance_id, intent.profile.profile_id.clone());
        Ok(intent.profile.clone())
    }

    /// Answers every refusal an execution can make, without publishing anything.
    ///
    /// The caller writes the profile's record between this and [`ProfileStore::execute`], so a
    /// failed write leaves no reservation behind for a launch that never happened. An instance
    /// that was already launched is refused first: a second launch would take over its record.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::InvalidArgument`] when the instance was already launched, and
    /// [`BrokerError::Launch`] with the refusal that applies otherwise.
    pub fn check_executable(
        &self,
        intent: &LaunchIntent,
        now: &ForegroundMark,
        application_instance_id: ApplicationInstanceId,
    ) -> Result<()> {
        // One launch for one instance, decided under the broker's lock with the execution itself,
        // so two launches naming one instance cannot both go ahead.
        if self.instances.contains_key(&application_instance_id) {
            return Err(BrokerError::invalid(format!(
                "{application_instance_id} was already launched, and one instance runs one launch"
            )));
        }
        if !now.is_idle() {
            return Err(BrokerError::Launch(LaunchRefusal::ForegroundChanged));
        }
        if now.prompt_revision != intent.prepared_against.prompt_revision {
            return Err(BrokerError::Launch(LaunchRefusal::PromptMoved));
        }
        if let Some(conversation) = intent.saved_conversation.as_ref()
            && let Some(owner) = self.conversations.get(conversation)
        {
            return Err(BrokerError::Launch(
                LaunchRefusal::ConversationAlreadyLive {
                    application_instance_id: *owner,
                },
            ));
        }
        Ok(())
    }

    /// Records a manual launch the host detected rather than started.
    ///
    /// Section 12: "Manual launches remain valid and trigger the same detection and capability
    /// process." What a manual launch does not do is retroactively create a gateway, which is why
    /// the caller supplies the mode it actually observed.
    pub fn adopt(
        &mut self,
        profile: LaunchProfile,
        application_instance_id: ApplicationInstanceId,
        saved_conversation: Option<String>,
    ) {
        self.profiles
            .insert(profile.profile_id.clone(), profile.clone());
        if let Some(conversation) = saved_conversation {
            self.conversations
                .entry(conversation)
                .or_insert(application_instance_id);
        }
        self.instances
            .insert(application_instance_id, profile.profile_id);
    }

    /// Moves one instance's conversation reservation to the thread it has just selected.
    ///
    /// Section 12 lets a native `/new`, `/resume` or thread selection change the active
    /// conversation without changing the process. When that happens the reservation has to move
    /// with it: the conversation the instance left is free for another execution, and the one it
    /// took is not.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Launch`] when another live execution already owns the conversation
    /// being selected.
    pub fn select_conversation(
        &mut self,
        application_instance_id: ApplicationInstanceId,
        conversation: &str,
    ) -> Result<()> {
        if let Some(owner) = self.conversations.get(conversation)
            && *owner != application_instance_id
        {
            return Err(BrokerError::Launch(
                LaunchRefusal::ConversationAlreadyLive {
                    application_instance_id: *owner,
                },
            ));
        }
        self.conversations
            .retain(|_, owner| *owner != application_instance_id);
        self.conversations
            .insert(conversation.to_owned(), application_instance_id);
        Ok(())
    }

    /// Releases whatever conversation one instance owned, because it has selected none.
    pub fn leave_conversation(&mut self, application_instance_id: ApplicationInstanceId) {
        self.conversations
            .retain(|_, owner| *owner != application_instance_id);
    }

    /// Releases the conversation an instance owned, because the instance ended.
    pub fn release(&mut self, application_instance_id: ApplicationInstanceId) {
        self.conversations
            .retain(|_, owner| *owner != application_instance_id);
        self.instances.remove(&application_instance_id);
    }

    /// Returns the profile one instance was launched under.
    #[must_use]
    pub fn profile_of(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> Option<&LaunchProfile> {
        self.instances
            .get(&application_instance_id)
            .and_then(|profile_id| self.profiles.get(profile_id))
    }

    /// Returns true when an execution or an adoption holds this instance's identifier.
    #[must_use]
    pub fn holds(&self, application_instance_id: ApplicationInstanceId) -> bool {
        self.instances.contains_key(&application_instance_id)
    }

    /// Returns one profile.
    #[must_use]
    pub fn profile(&self, profile_id: &LaunchProfileId) -> Option<&LaunchProfile> {
        self.profiles.get(profile_id)
    }

    /// Returns every profile, oldest identifier first.
    pub fn iter(&self) -> impl Iterator<Item = &LaunchProfile> {
        self.profiles.values()
    }

    /// Returns which instance owns the live execution of one saved conversation.
    #[must_use]
    pub fn owner_of(&self, saved_conversation: &str) -> Option<ApplicationInstanceId> {
        self.conversations.get(saved_conversation).copied()
    }

    /// Restores profiles read back from the ledger.
    pub fn restore(&mut self, profiles: impl IntoIterator<Item = LaunchProfile>) {
        for profile in profiles {
            self.profiles.insert(profile.profile_id.clone(), profile);
        }
    }
}

/// One executed launch's hold on its instance, before the process it starts is registered.
///
/// [`crate::broker::Broker::execute_launch`] makes it, and it is the only thing that can register
/// the instance it reserved: [`crate::broker::Broker::register_launched`] consumes it. A
/// reservation dropped instead, because what the launch starts failed first, gives back what the
/// execution took, and only that: the instance's identifier and its conversation. Nothing else can
/// give them back, and nothing else can take them while it is held.
#[must_use = "a reservation that is dropped gives its instance back"]
#[derive(Debug)]
pub struct LaunchReservation<'a> {
    broker: &'a crate::broker::Broker,
    application_instance_id: ApplicationInstanceId,
    profile: LaunchProfile,
    held: bool,
}

impl<'a> LaunchReservation<'a> {
    pub(crate) const fn new(
        broker: &'a crate::broker::Broker,
        application_instance_id: ApplicationInstanceId,
        profile: LaunchProfile,
    ) -> Self {
        Self {
            broker,
            application_instance_id,
            profile,
            held: true,
        }
    }

    /// Returns the instance this launch reserved.
    #[must_use]
    pub const fn application_instance_id(&self) -> ApplicationInstanceId {
        self.application_instance_id
    }

    /// Returns the profile the launch runs under.
    #[must_use]
    pub const fn profile(&self) -> &LaunchProfile {
        &self.profile
    }

    /// Hands the reservation on to the registration that consumes it.
    pub(crate) fn into_parts(
        mut self,
    ) -> (
        &'a crate::broker::Broker,
        ApplicationInstanceId,
        LaunchProfile,
    ) {
        self.held = false;
        (
            self.broker,
            self.application_instance_id,
            self.profile.clone(),
        )
    }
}

impl Drop for LaunchReservation<'_> {
    fn drop(&mut self) {
        if self.held {
            self.broker.give_back_launch(self.application_instance_id);
        }
    }
}

/// A launched instance, registered, whose launch has not finished publishing itself.
///
/// It owns what the launch took (the instance, its profile's reservation, and whatever tokens and
/// capability records were made for the instance meanwhile) until [`RegisteredLaunch::commit`]. A
/// launch that fails after the instance was registered drops it, or calls
/// [`RegisteredLaunch::abandon`], and exactly those are given back; an instance another path
/// registered is never among them, because no other path can register an identifier this one
/// holds.
#[must_use = "a registered launch that is not committed gives everything back"]
#[derive(Debug)]
pub struct RegisteredLaunch<'a> {
    broker: &'a crate::broker::Broker,
    application_instance_id: ApplicationInstanceId,
    profile: LaunchProfile,
    committed: bool,
}

impl<'a> RegisteredLaunch<'a> {
    pub(crate) const fn new(
        broker: &'a crate::broker::Broker,
        application_instance_id: ApplicationInstanceId,
        profile: LaunchProfile,
    ) -> Self {
        Self {
            broker,
            application_instance_id,
            profile,
            committed: false,
        }
    }

    /// Returns the instance this launch registered.
    #[must_use]
    pub const fn application_instance_id(&self) -> ApplicationInstanceId {
        self.application_instance_id
    }

    /// Returns the profile the launch runs under.
    #[must_use]
    pub const fn profile(&self) -> &LaunchProfile {
        &self.profile
    }

    /// Keeps the instance: the launch has published everything it publishes, and the instance now
    /// ends only as an instance does.
    pub fn commit(mut self) -> LaunchProfile {
        self.committed = true;
        self.profile.clone()
    }

    /// Gives back everything the launch took.
    pub fn abandon(self) {
        drop(self);
    }
}

impl Drop for RegisteredLaunch<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.broker.give_back_launch(self.application_instance_id);
        }
    }
}

/// Builds a profile identifier that says when it was resolved.
///
/// # Errors
///
/// Returns [`BrokerError::InvalidArgument`] when the generated text is not a valid identifier,
/// which cannot happen for the shape this builds and is reported rather than ignored.
pub fn new_profile_id(resolved_at: TimestampMs) -> Result<LaunchProfileId> {
    LaunchProfileId::new(format!("lp-{}-{}", resolved_at.get(), kr_ipc::new_uuid()))
        .map_err(|error| BrokerError::invalid(format!("launch profile identifier: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::broker::{AuthenticationState, BinaryIdentity, IntegrationMode};
    use kr_protocol::ids::EnvironmentId;
    use kr_protocol::scalars::{Digest256, Uuid};

    fn profile(mode: IntegrationMode) -> LaunchProfile {
        LaunchProfile {
            profile_id: LaunchProfileId::new("lp-1").expect("valid"),
            environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
            binary: BinaryIdentity {
                resolved_path: "/usr/local/bin/codex".to_owned(),
                digest: Digest256::from_bytes([3; 32]),
                version: "0.9.1".to_owned(),
                distribution: "homebrew".to_owned(),
            },
            arguments: vec!["codex".to_owned(), "--resume".to_owned()],
            authentication: AuthenticationState::Authenticated,
            mode,
            resolved_at: TimestampMs::new(10),
        }
    }

    fn instance(byte: u8) -> ApplicationInstanceId {
        ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn a_profile_records_everything_section_twelve_names() {
        let profile = profile(IntegrationMode::Gateway);
        assert_eq!(profile.binary.resolved_path, "/usr/local/bin/codex");
        assert_eq!(profile.binary.version, "0.9.1");
        assert_eq!(profile.binary.distribution, "homebrew");
        assert_eq!(profile.arguments.len(), 2);
        assert_eq!(profile.authentication, AuthenticationState::Authenticated);
        assert!(profile.mode.uses_gateway());
    }

    #[test]
    fn an_application_taking_the_foreground_refuses_the_launch() {
        let mut store = ProfileStore::new();
        let intent = store
            .prepare(
                profile(IntegrationMode::Gateway),
                ForegroundMark::idle(4),
                None,
            )
            .expect("prepared against the idle prompt");
        let occupied = ForegroundMark {
            application_instance_id: Some(instance(9)),
            prompt_revision: 4,
        };
        let refusal = store
            .execute(&intent, &occupied, instance(2))
            .expect_err("a stale launch is refused");
        assert!(matches!(
            refusal,
            BrokerError::Launch(LaunchRefusal::ForegroundChanged)
        ));
    }

    #[test]
    fn a_prompt_that_moved_refuses_the_launch() {
        let mut store = ProfileStore::new();
        let intent = store
            .prepare(
                profile(IntegrationMode::Gateway),
                ForegroundMark::idle(4),
                None,
            )
            .expect("prepared");
        let refusal = store
            .execute(&intent, &ForegroundMark::idle(5), instance(2))
            .expect_err("a moved prompt is refused");
        assert!(matches!(
            refusal,
            BrokerError::Launch(LaunchRefusal::PromptMoved)
        ));
    }

    #[test]
    fn a_launch_is_never_prepared_against_an_occupied_terminal() {
        let store = ProfileStore::new();
        let occupied = ForegroundMark {
            application_instance_id: Some(instance(9)),
            prompt_revision: 4,
        };
        assert!(
            store
                .prepare(profile(IntegrationMode::Gateway), occupied, None)
                .is_err()
        );
    }

    #[test]
    fn a_saved_conversation_takes_one_live_execution() {
        let mut store = ProfileStore::new();
        let first = store
            .prepare(
                profile(IntegrationMode::Gateway),
                ForegroundMark::idle(4),
                Some("thread-7".to_owned()),
            )
            .expect("prepared");
        store
            .execute(&first, &ForegroundMark::idle(4), instance(2))
            .expect("the first launch runs");

        let second = store
            .prepare(
                profile(IntegrationMode::Gateway),
                ForegroundMark::idle(4),
                Some("thread-7".to_owned()),
            )
            .expect("prepared");
        let refusal = store
            .execute(&second, &ForegroundMark::idle(4), instance(3))
            .expect_err("a second process against the same conversation is refused");
        assert!(matches!(
            refusal,
            BrokerError::Launch(LaunchRefusal::ConversationAlreadyLive {
                application_instance_id
            }) if application_instance_id == instance(2)
        ));

        store.release(instance(2));
        store
            .execute(&second, &ForegroundMark::idle(4), instance(3))
            .expect("the conversation is free once its execution has ended");
    }

    #[test]
    fn a_thread_selection_moves_the_reservation_with_it() {
        let mut store = ProfileStore::new();
        let intent = store
            .prepare(
                profile(IntegrationMode::Gateway),
                ForegroundMark::idle(4),
                Some("thread-7".to_owned()),
            )
            .expect("prepared");
        store
            .execute(&intent, &ForegroundMark::idle(4), instance(2))
            .expect("the launch runs");
        assert_eq!(store.owner_of("thread-7"), Some(instance(2)));

        store
            .select_conversation(instance(2), "thread-8")
            .expect("the instance selected another conversation");
        assert_eq!(
            store.owner_of("thread-7"),
            None,
            "the conversation it left is free for another execution"
        );
        assert_eq!(store.owner_of("thread-8"), Some(instance(2)));

        // And the one it took is not available to anybody else.
        assert!(store.select_conversation(instance(3), "thread-8").is_err());
        store
            .select_conversation(instance(2), "thread-8")
            .expect("selecting the conversation it already owns is not a conflict");

        store.leave_conversation(instance(2));
        assert_eq!(store.owner_of("thread-8"), None);
    }

    #[test]
    fn a_manual_launch_is_adopted_with_the_mode_that_was_observed() {
        let mut store = ProfileStore::new();
        store.adopt(
            profile(IntegrationMode::NativeTerminal),
            instance(2),
            Some("thread-7".to_owned()),
        );
        assert_eq!(
            store
                .profile_of(instance(2))
                .expect("the profile is recorded")
                .mode,
            IntegrationMode::NativeTerminal,
            "detection after launch never retroactively creates a gateway"
        );
        assert_eq!(store.owner_of("thread-7"), Some(instance(2)));
    }
}
