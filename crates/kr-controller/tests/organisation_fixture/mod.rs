//! A host enrolled in an organisation on clocks a suite moves by hand, and the member devices,
//! leases and requests the suites that follow the organisation's policy through it share.
//!
//! The organisation is a stand-in that signs with real keys: it issues the leases and publishes
//! the chain, which is all the managed service does for the host. Each suite that includes this
//! module uses some of it, not all.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use kr_controller::service::{Clocks, WallClock};
use kr_crypto::keys::DeviceKeys;
use kr_protocol::account::{MembershipLease, PolicyAuthority};
use kr_protocol::confirmation::{ConfirmationSubject, OrganisationEnrolPlan};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::grant::OrganisationRequirement;
use kr_protocol::hostinfo::configuration::ConfigurationDocument;
use kr_protocol::ids::{AccountId, ActionId, AuthorityRevision, SessionEpoch, SessionId};
use kr_protocol::method::Method;
use kr_protocol::organisation::{
    MembershipPresentParams, MembershipPresentResult, OrganisationEnrolParams,
    OrganisationEnrolResult, OrganisationListParams, OrganisationListResult,
};
use kr_protocol::pairing::ProposedGrant;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Nullable, Uuid};
use kr_protocol::session::SessionCloseParams;
use kr_transport::clock::ManualClock;

use crate::net_support::pairing::{self as calls, Signer};
use crate::net_support::{self, Device, Host, RawDevice, pair_with, proposal};
use crate::organisation_support::{MINUTE_MS, Organisation, member};

pub const DAY_MS: u64 = 24 * 60 * MINUTE_MS;
pub const SERVED: &[ActionRight] = &[ActionRight::SessionView, ActionRight::SessionClose];
pub const VIEW_ONLY: &[ActionRight] = &[ActionRight::SessionView];

/// A daemon enrolled in an organisation, on clocks the suite moves.
pub struct Fixture {
    pub host: Host,
    pub owner: DeviceKeys,
    pub organisation: Organisation,
    pub revision: AuthorityRevision,
    pub continuous: ManualClock,
    pub moved: Arc<AtomicI64>,
}

impl Fixture {
    /// Starts a daemon with an owner device and enrols it through the owner's confirmation, the
    /// way a person does.
    pub async fn start() -> Self {
        let mut fixture = Self::start_unenrolled().await;
        fixture.enrol().await;
        fixture
    }

    /// Starts a daemon with an owner device, enrolled in nothing.
    pub async fn start_unenrolled() -> Self {
        Self::start_unenrolled_under(None).await
    }

    /// Starts a daemon on the network settings `settings`, with an owner device and enrolled in
    /// the organisation: a suite that restarts it and has it come back at the address it had names
    /// that address.
    pub async fn start_on(settings: kr_controller::service::net::config::NetworkSettings) -> Self {
        let mut fixture = Self::start_unenrolled_with(None, 0, Some(settings)).await;
        fixture.enrol().await;
        fixture
    }

    /// Starts a daemon that reads `document` as its configuration, with an owner device and
    /// enrolled in the organisation.
    pub async fn start_under(document: &ConfigurationDocument) -> Self {
        let mut fixture = Self::start_unenrolled_under(Some(document)).await;
        fixture.enrol().await;
        fixture
    }

    /// Starts a daemon with an owner device, enrolled in nothing, whose wall clock reads
    /// `wall_ms` when it starts and goes on from there, for a test that applies what an
    /// organisation signed at a time of its own.
    pub async fn start_unenrolled_at(wall_ms: u64) -> Self {
        let machine = i64::try_from(kr_ipc::now_ms().get()).expect("a moment");
        let offset = i64::try_from(wall_ms).expect("a moment") - machine;
        Self::start_unenrolled_offset(None, offset).await
    }

    /// Starts a daemon with an owner device, enrolled in nothing, that reads `document` as its
    /// configuration when it is given one.
    pub async fn start_unenrolled_under(document: Option<&ConfigurationDocument>) -> Self {
        Self::start_unenrolled_offset(document, 0).await
    }

    /// As [`Self::start_unenrolled_under`], with a wall clock moved by `offset` milliseconds from
    /// the machine's from the start.
    async fn start_unenrolled_offset(
        document: Option<&ConfigurationDocument>,
        offset: i64,
    ) -> Self {
        Self::start_unenrolled_with(document, offset, None).await
    }

    async fn start_unenrolled_with(
        document: Option<&ConfigurationDocument>,
        offset: i64,
        settings: Option<kr_controller::service::net::config::NetworkSettings>,
    ) -> Self {
        let owner = DeviceKeys::generate().expect("keys");
        let continuous = ManualClock::new();
        let moved = Arc::new(AtomicI64::new(offset));
        let clocks = clocks_over(&continuous, &moved);
        let host = match (document, settings) {
            (Some(document), _) => Host::start_with_document_clocks(&owner, document, clocks).await,
            (None, Some(settings)) => {
                Host::start_on_clocks_with_settings(&owner, clocks, settings).await
            }
            (None, None) => Host::start_on_clocks(&owner, clocks).await,
        };
        let now = kr_ipc::now_ms().get();
        let mut organisation = Organisation::new(0x21, now - 2 * DAY_MS);
        organisation.rotate(now - DAY_MS);
        Self {
            host,
            owner,
            organisation,
            revision: AuthorityRevision::new(0),
            continuous,
            moved,
        }
    }

    /// The owner enrols the host in the organisation from the chain it publishes now, on the
    /// confirmation of an owner device, and the fixture holds the revision the enrolment took.
    pub async fn enrol(&mut self) -> OrganisationEnrolResult {
        let enrolled = self.enrol_in(&self.organisation).await;
        self.revision = enrolled.enrolment_revision;
        enrolled
    }

    /// The owner enrols the host in `organisation` from the chain it publishes now, on the
    /// confirmation of an owner device.
    pub async fn enrol_in(&self, organisation: &Organisation) -> OrganisationEnrolResult {
        self.enrol_from(organisation.authority(self.now() - 1_000))
            .await
    }

    /// The owner enrols the host from `authority`, a chain an organisation published, on the
    /// confirmation of an owner device.
    pub async fn enrol_from(&self, authority: PolicyAuthority) -> OrganisationEnrolResult {
        let params = OrganisationEnrolParams { authority };
        let mut client = self.host.client().await;
        calls::confirm_subject(
            self.host.environment_id,
            &mut client,
            ConfirmationSubject::EnrolOrganisation(Box::new(params.clone())),
            &Signer::OwnerDevice(&self.owner),
        )
        .await
        .expect("the owner confirms the chain");
        let enrolled: OrganisationEnrolResult = calls::mutate_as(
            self.host.environment_id,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            Method::OrganisationEnrol,
            &params,
        )
        .await
        .expect("the host enrols");
        assert!(OrganisationEnrolPlan::of_authority(&params.authority).is_some());
        enrolled
    }

    /// The owner withdraws the host from `organisation_id` on the local socket, under `action`.
    pub async fn withdraw(
        &self,
        client: &mut kr_ipc::client::LocalClient,
        action: ActionId,
        organisation_id: kr_protocol::ids::OrganisationId,
    ) -> Result<kr_protocol::sharing::RevocationResult, ProtocolError> {
        calls::mutate_as(
            self.host.environment_id,
            client,
            action,
            Method::OrganisationWithdraw,
            &kr_protocol::organisation::OrganisationWithdrawParams { organisation_id },
        )
        .await
    }

    /// The owner makes the host exclusively organisation-managed, or ends that, on the local
    /// socket: an owner device signs the confirmation of exactly this change, then the change is
    /// asked for under `action`.
    pub async fn set_exclusive(
        &self,
        client: &mut kr_ipc::client::LocalClient,
        action: ActionId,
        exclusive: bool,
    ) -> Result<kr_protocol::organisation::OrganisationExclusiveSetResult, ProtocolError> {
        calls::confirm_subject(
            self.host.environment_id,
            client,
            ConfirmationSubject::SetExclusiveManagement { exclusive },
            &Signer::OwnerDevice(&self.owner),
        )
        .await?;
        calls::mutate_as(
            self.host.environment_id,
            client,
            action,
            Method::OrganisationExclusiveSet,
            &kr_protocol::organisation::OrganisationExclusiveSetParams { exclusive },
        )
        .await
    }

    /// The organisation signs a lease for the host's own key and the owner presents it at the local
    /// socket: what the host's local owner must do on an exclusively organisation-managed host
    /// before it is served anything but what recovers the host.
    pub async fn lease_the_local_owner(&self) -> MembershipPresentResult {
        self.try_to_lease_the_local_owner()
            .await
            .expect("the host takes the lease for its local owner")
    }

    /// As [`Self::lease_the_local_owner`], answering with the host's refusal where it refuses.
    pub async fn try_to_lease_the_local_owner(
        &self,
    ) -> Result<MembershipPresentResult, ProtocolError> {
        let listed = self.listed().await;
        let lease = self.organisation.lease(
            2,
            &member("owner"),
            listed.host_device.authorisation_key,
            self.now(),
            &[ActionRight::SessionView],
        );
        let mut client = self.host.client().await;
        calls::mutate_as(
            self.host.environment_id,
            &mut client,
            ActionId::new(kr_ipc::new_uuid()),
            Method::MembershipPresent,
            &MembershipPresentParams {
                lease,
                authority: Nullable::null(),
            },
        )
        .await
    }

    /// The authority revision the host's policy follows now.
    pub fn authority_revision(&self) -> AuthorityRevision {
        self.host.controller().policy().authority_revision()
    }

    /// Stops the daemon and starts another on the same tree, as a restart of the host does.
    pub async fn restart(self) -> Self {
        Self {
            host: self.host.restart().await,
            ..self
        }
    }

    /// Stops the daemon and starts another on the same tree in another boot of the machine,
    /// named by `boot`: the continuous clock counts from nothing, and the wall clock is whatever it
    /// was left at.
    pub async fn reboot(self, boot: u8) -> Self {
        let continuous = ManualClock::new();
        let mut stopped = self.host.shut_down().await;
        stopped.reboot(boot, clocks_over(&continuous, &self.moved));
        let settings = stopped.settings().clone();
        Self {
            host: stopped.start(settings).await,
            continuous,
            ..self
        }
    }

    /// The daemon's wall clock now, in UTC milliseconds.
    pub fn now(&self) -> u64 {
        kr_ipc::now_ms()
            .get()
            .saturating_add_signed(self.moved.load(Ordering::SeqCst))
    }

    /// Both clocks pass `by`, as time does.
    pub fn pass(&self, by: Duration) {
        self.pass_continuous(by);
        self.pass_wall(by);
    }

    /// Only the continuous clock passes `by`: a host that slept with its wall clock held.
    pub fn pass_continuous(&self, by: Duration) {
        self.continuous.advance(by);
    }

    /// Only the wall clock passes `by`: a clock set forward.
    pub fn pass_wall(&self, by: Duration) {
        self.moved.fetch_add(
            i64::try_from(by.as_millis()).expect("a short time"),
            Ordering::SeqCst,
        );
    }

    /// Pairs a device whose grant answers to the organisation, with the rights named.
    pub async fn member(&self, name: &str, rights: &[ActionRight]) -> Member {
        let device = Device::create().await;
        let grant = ProposedGrant {
            organisation: Nullable::some(OrganisationRequirement {
                organisation_id: self.organisation.organisation_id,
                policy_revision: self.revision,
            }),
            ..proposal(rights)
        };
        let record = pair_with(&self.host, &device, &self.owner, grant).await;
        Member {
            device,
            record,
            account: member(name),
        }
    }

    /// A lease signed by `revision` for `member`, issued now.
    pub fn lease(&self, revision: u64, member: &Member, rights: &[ActionRight]) -> MembershipLease {
        self.organisation
            .lease(revision, &member.account, member.key(), self.now(), rights)
    }

    /// Waits until the host owes no fence: the debt pass has retired what a restriction owed.
    pub async fn until_the_fence_is_retired(&self) {
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !self
            .host
            .controller()
            .sharing()
            .grants()
            .fence_owed()
            .expect("readable")
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "the fence the host owes was not retired"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// The owner reads what the host holds, on the owner's own local socket.
    pub async fn listed(&self) -> OrganisationListResult {
        let mut client = self.host.client().await;
        calls::read(
            &mut client,
            Method::OrganisationList,
            &OrganisationListParams::default(),
        )
        .await
        .expect("the owner reads the list")
    }
}

/// The daemon's clocks: `continuous`, and a wall clock that reads the machine's own moved by
/// `moved` milliseconds.
fn clocks_over(continuous: &ManualClock, moved: &Arc<AtomicI64>) -> Clocks {
    let read = Arc::clone(moved);
    Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: WallClock::from_fn(move || {
            kr_ipc::now_ms()
                .get()
                .saturating_add_signed(read.load(Ordering::SeqCst))
        }),
    }
}

/// A member's device: its keys, its pairing and the account it works as.
pub struct Member {
    pub device: Device,
    pub record: kr_controller::service::net::devices::DeviceRecord,
    pub account: AccountId,
}

impl Member {
    /// The authorisation key the device proves, which a lease for it names.
    pub fn key(&self) -> AuthorisationKey {
        *self.device.keys().authorisation.public()
    }

    /// A new connection of the device, with a fresh action window.
    pub async fn connect(&self, fixture: &Fixture) -> RawDevice {
        let raw = RawDevice::connect(&fixture.host, &self.device, &self.record).await;
        raw.claim();
        raw
    }

    /// Presents `lease` as [`Self::present`] does, and returns `None` when the host ended the
    /// connection instead of answering: a presentation whose fence withdraws the presenter may
    /// lose its answer to the withdrawal, though the lease is installed.
    pub async fn try_present(
        &self,
        fixture: &Fixture,
        raw: &RawDevice,
        lease: MembershipLease,
        authority: Option<PolicyAuthority>,
    ) -> Option<Result<MembershipPresentResult, ProtocolError>> {
        let answered = raw
            .try_mutate(
                Method::MembershipPresent,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(fixture.host.environment_id),
                &MembershipPresentParams {
                    lease,
                    authority: authority.map_or_else(Nullable::null, Nullable::some),
                },
            )
            .await?;
        Some(answered.map(|value| value.to_typed().expect("the answer of the method")))
    }

    /// Presents `lease`, and a chain when there is one, under a new action.
    pub async fn present(
        &self,
        fixture: &Fixture,
        raw: &RawDevice,
        lease: MembershipLease,
        authority: Option<PolicyAuthority>,
    ) -> Result<MembershipPresentResult, ProtocolError> {
        let value = raw
            .mutate(
                Method::MembershipPresent,
                ActionId::new(kr_ipc::new_uuid()),
                ActionTarget::environment(fixture.host.environment_id),
                &MembershipPresentParams {
                    lease,
                    authority: authority.map_or_else(Nullable::null, Nullable::some),
                },
            )
            .await?;
        Ok(value.to_typed().expect("the answer of the method"))
    }
}

/// Reads the host's identity, which every member with a lease may.
pub async fn read_host_info(raw: &RawDevice) -> Result<(), ProtocolError> {
    raw.read(Method::HostInfo, &()).await.map(|_| ())
}

/// Closes a session that does not exist, which only a device with `session.close` under a lease
/// gets as far as asking. It is refused for what is wrong with it, never for want of authority.
pub async fn close_a_session(fixture: &Fixture, raw: &RawDevice) -> ProtocolError {
    let session_id = SessionId::new(Uuid::from_bytes([0x5e; 16]));
    let target = ActionTarget {
        session_id: Nullable::some(session_id),
        session_epoch: Nullable::some(SessionEpoch::new(1)),
        ..ActionTarget::environment(fixture.host.environment_id)
    };
    net_support::refusal(
        raw.mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &SessionCloseParams { session_id },
        )
        .await,
    )
}

/// Closes a session that does not exist and asserts the host got as far as finding that out, which
/// it does for a device the lease serves and for no other.
pub async fn reaches_its_session(fixture: &Fixture, raw: &RawDevice) {
    let error = close_a_session(fixture, raw).await;
    assert_eq!(error.code, ErrorCode::UnknownSession, "{error:?}");
}

pub fn denied(error: &ProtocolError) -> bool {
    error.code == ErrorCode::PermissionDenied
}
