//! Rows an earlier build wrote, as this build reads them.
//!
//! A grant, a pairing proposal and a sharing preview used to name an approval by the upstream's
//! own text identifier. They name it by the broker's resource identity now, and nothing here reads
//! the earlier shape. The break is safe because every build wrote an empty set, which has the same
//! bytes under either element, while a set that names an approval by text names no resource of
//! this host. So for each of the six stored payloads, the row an earlier build wrote naming nothing
//! reads, and writes back, byte for byte; the row naming an approval by text admits nothing, and
//! its refusal names the table and the row. The one exception is a retained answer, which this
//! host keeps as the bytes it was and gives back unchanged to a retry of its action: this build's
//! typed read of it is what refuses it. Where a listing reads every row, one such row fails the
//! whole listing, which is the answer that withholds.
//!
//! The rows are `fixtures/earlier-rows/rows.json`, encoded by the earlier build with its own types.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.51 | every test here |

#![cfg(unix)]

mod net_support;

use std::path::Path;

use kr_controller::grants::{ActionClaim, ActionRecord, GrantDirectory, GrantRecord};
use kr_controller::service::net::devices::{DeviceDirectory, DeviceRecord};
use kr_crypto::keys::DeviceKeys;
use kr_pairing::platform::{InvitationStore as _, PairingCommitment};
use kr_protocol::error::ErrorCode;
use kr_protocol::grant::Grant;
use kr_protocol::ids::{
    ActionId, ActorId, AttemptId, DeviceId, DeviceKeyRevision, GrantId, InvitationId,
};
use kr_protocol::invitation::{InviteGrantKind, InviteMode, PairInviteParams, PairInviteResult};
use kr_protocol::method::Method;
use kr_protocol::pairing::{
    ClientBundle, DeviceName, DevicePlatform, DevicePublicKeys, OwnerConfirmationProof,
    ProposedGrant,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{AuthorisationKey, Digest256, EndpointKey, Nullable, TimestampMs, Uuid};
use kr_protocol::sharing::{GrantCreateResult, InvitationPreview};
use kr_transport::handshake::PairedDirectory as _;
use net_support::pairing::{self as calls, Signer};
use net_support::{Device, Host, pair_with, proposal};

/// The device the earlier rows name.
const DEVICE: [u8; 16] = [0xd1; 16];

/// The grant the earlier `grants` row holds.
const SHARED_GRANT: [u8; 16] = [0x62; 16];

/// The session invitation the earlier `session_invitations` row is.
const SESSION_INVITATION: [u8; 16] = [0x13; 16];

/// The device this host is, which issued the earlier grants.
const HOST: [u8; 16] = [0x0f; 16];

/// One stored payload in both of the earlier forms: naming nothing, and naming the approval `1` by
/// that text.
struct Earlier {
    empty: Vec<u8>,
    named: Vec<u8>,
}

fn earlier(key: &str) -> Earlier {
    let rows: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/earlier-rows/rows.json"))
            .expect("the earlier rows");
    let form = |name: &str| {
        let text = rows[key][name]
            .as_str()
            .unwrap_or_else(|| panic!("{key} has an {name} form"));
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal"))
            .collect::<Vec<u8>>()
    };
    Earlier {
        empty: form("empty"),
        named: form("named"),
    }
}

fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(bytes: &[u8]) -> T {
    kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)
        .expect("this build reads the row that names nothing")
}

fn encode<T: serde::Serialize>(value: &T) -> Vec<u8> {
    kr_cbor::to_canonical_vec(value).expect("encodes")
}

/// Whether a refusal names the table and the row it could not read.
fn names(refusal: &impl std::fmt::Display, table: &str, row: Uuid) -> bool {
    let text = refusal.to_string();
    text.contains(table) && text.contains(&row.to_string())
}

/// Reads one stored column the way an operator would, straight from the database.
fn stored(database: &Path, query: &str, key: Uuid) -> Vec<u8> {
    rusqlite::Connection::open(database)
        .expect("the registry opens")
        .query_row(query, rusqlite::params![key.as_bytes().as_slice()], |row| {
            row.get(0)
        })
        .expect("the row")
}

/// Puts an earlier build's payload into one stored row, as that build left it.
fn hold(database: &Path, statement: &str, key: Uuid, payload: &[u8]) {
    let changed = rusqlite::Connection::open(database)
        .expect("the registry opens")
        .execute(
            statement,
            rusqlite::params![key.as_bytes().as_slice(), payload],
        )
        .expect("the row is written");
    assert_eq!(changed, 1, "one row holds it");
}

/// A paired device's record, holding `grant`.
fn device_record(device: [u8; 16], transport: u8, grant: Grant) -> DeviceRecord {
    DeviceRecord {
        device_id: DeviceId::new(Uuid::from_bytes(device)),
        endpoint_id: EndpointKey::from_bytes([transport; 32]),
        device_key_revision: DeviceKeyRevision::new(1),
        authorisation: AuthorisationKey::from_bytes([transport.wrapping_add(1); 32]),
        stored_envelope: None,
        notification_preview: None,
        device_name: DeviceName::new("the studio mac".to_owned()).expect("a name"),
        platform: DevicePlatform::Macos,
        grant,
        paired_at_ms: TimestampMs::new(1_000),
        revoked_at_ms: None,
        committed_invitation_id: None,
        expired_at_ms: None,
    }
}

/// KR-REQ-10.51: a device row an earlier build wrote naming no approval is read as it was, the
/// device connects, and this build writes the same grant back to the same bytes.
#[test]
fn kr_req_10_51_an_earlier_device_row_that_names_nothing_reads_and_writes_back_unchanged() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let database = temp.path().join("registry.db");
    let directory = DeviceDirectory::open(&database).expect("the device table");
    let row = earlier("network_devices.grant");
    let grant: Grant = decode(&row.empty);
    let device = Uuid::from_bytes(DEVICE);

    directory
        .commit(&device_record(DEVICE, 0x31, grant.clone()))
        .expect("committed");
    assert_eq!(
        stored(
            &database,
            "SELECT grant FROM network_devices WHERE device_id = ?1",
            device
        ),
        row.empty,
        "this build writes the grant as the earlier build wrote it"
    );
    let read = directory
        .record_for_device(DeviceId::new(device))
        .expect("readable")
        .expect("the record");
    assert_eq!(read.grant, grant);
    assert_eq!(encode(&read.grant), row.empty);
    assert!(
        directory
            .paired_peer(&EndpointKey::from_bytes([0x31; 32]))
            .is_some(),
        "the device connects"
    );
}

/// KR-REQ-10.51: a device row whose grant names an approval by text grants nothing. The device
/// cannot connect, its record is refused with the table and the device named, and the device list
/// fails whole rather than leave it out, while another device's row still reads. The migration that
/// first records whether a host has an owner counts such a row as an owner device, as it counts any
/// row it cannot read, so an unreadable record never reopens the initial bootstrap; the control is
/// the row that names nothing, which holds no `host.manage` and is not counted.
#[test]
fn kr_req_10_51_an_earlier_device_row_naming_an_approval_by_text_admits_nothing() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let database = temp.path().join("registry.db");
    let directory = DeviceDirectory::open(&database).expect("the device table");
    let row = earlier("network_devices.grant");
    let device = Uuid::from_bytes(DEVICE);
    let other = [0xd2; 16];
    directory
        .commit(&device_record(other, 0x41, decode(&row.empty)))
        .expect("committed");
    directory
        .commit(&device_record(DEVICE, 0x31, decode(&row.empty)))
        .expect("committed");
    hold(
        &database,
        "UPDATE network_devices SET grant = ?2 WHERE device_id = ?1",
        device,
        &row.named,
    );

    let refused = directory
        .record_for_device(DeviceId::new(device))
        .expect_err("the grant names an approval by text");
    assert!(
        names(&refused, "network_devices", device),
        "the refusal names the table and the device: {refused}"
    );
    assert_eq!(refused.code(), ErrorCode::StorageUnavailable);
    assert!(
        directory
            .paired_peer(&EndpointKey::from_bytes([0x31; 32]))
            .is_none(),
        "the device cannot connect"
    );
    assert!(
        directory
            .paired_peer(&EndpointKey::from_bytes([0x41; 32]))
            .is_some(),
        "another device still connects"
    );
    let listed = directory
        .devices()
        .expect_err("the device list fails whole on the row");
    assert!(names(&listed, "network_devices", device), "{listed}");

    for (payload, counted) in [(&row.named, true), (&row.empty, false)] {
        let temp = tempfile::tempdir().expect("a directory on the internal disk");
        let database = temp.path().join("registry.db");
        let directory = DeviceDirectory::open(&database).expect("the device table");
        directory
            .commit(&device_record(DEVICE, 0x31, decode(&row.empty)))
            .expect("committed");
        hold(
            &database,
            "UPDATE network_devices SET grant = ?2 WHERE device_id = ?1",
            device,
            payload,
        );
        kr_controller::service::net::invitations::prepare(&directory).expect("the pairing tables");
        let owners: i64 = rusqlite::Connection::open(&database)
            .expect("the registry opens")
            .query_row(
                "SELECT COUNT(*) FROM host_owner WHERE how = 'migrated'",
                [],
                |row| row.get(0),
            )
            .expect("counted");
        assert_eq!(owners == 1, counted, "an unreadable row counts as an owner");
    }
}

/// KR-REQ-10.51: an owner confirmation is spent only by owner devices this host can read, and
/// spending one first lists them. So while one owner device's row names an approval by text, that
/// list fails whole, the refusal names the row, and no answer is spent: the answer the owner gave
/// while the row read issues nothing. Once the row is repaired, the same answer issues the
/// invitation, which is the control that nothing was spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_no_owner_confirmation_is_spent_while_an_owner_row_names_an_approval_by_text()
{
    let owner_keys = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner_keys).await;
    let environment = host.environment_id;
    let mut client = host.client().await;
    let owner = Signer::OwnerDevice(&owner_keys);
    let owner_device = host.owner.clone().expect("the owner device").device_id;
    let database = host.registry_database();
    let grant = proposal(&[ActionRight::SessionView]);
    let params = PairInviteParams {
        mode: InviteMode::Direct,
        grant_kind: InviteGrantKind::SessionInvitation,
        proposed_grant: grant.clone(),
    };

    calls::confirm_subject(
        environment,
        &mut client,
        kr_protocol::confirmation::ConfirmationSubject::IssueInvitation {
            mode: kr_protocol::invitation::InviteModeKind::Direct,
            rendezvous_origin: Nullable::null(),
            grant_kind: InviteGrantKind::SessionInvitation,
            proposed_grant: grant.clone(),
        },
        &owner,
    )
    .await
    .expect("answered while the owner's row reads");
    let owner_grant = stored(
        &database,
        "SELECT grant FROM network_devices WHERE device_id = ?1",
        owner_device.get(),
    );
    hold(
        &database,
        "UPDATE network_devices SET grant = ?2 WHERE device_id = ?1",
        owner_device.get(),
        &earlier("network_devices.grant").named,
    );
    let refused =
        calls::mutate::<_, PairInviteResult>(environment, &mut client, Method::PairInvite, &params)
            .await
            .expect_err("no owner device can be read");
    assert_eq!(refused.code, ErrorCode::StorageUnavailable, "{refused:?}");
    assert!(
        names(&refused.message, "network_devices", owner_device.get()),
        "{}",
        refused.message
    );

    hold(
        &database,
        "UPDATE network_devices SET grant = ?2 WHERE device_id = ?1",
        owner_device.get(),
        &owner_grant,
    );
    calls::mutate::<_, PairInviteResult>(environment, &mut client, Method::PairInvite, &params)
        .await
        .expect("the answer was not spent, and issues the invitation");
    host.stop().await;
}

/// `pairing_commitments.commitment`, as the host stores a commitment.
#[derive(serde::Serialize, serde::Deserialize)]
struct Commitment {
    invitation_id: InvitationId,
    attempt_id: AttemptId,
    device_id: DeviceId,
    grant: Grant,
    client_keys: DevicePublicKeys,
    client_bundle: Nullable<ClientBundle>,
    proposed_grant: ProposedGrant,
    verification_value: String,
    owner_confirmation: OwnerConfirmationProof,
    committed_at_ms: TimestampMs,
}

impl Commitment {
    fn of(commitment: PairingCommitment) -> Self {
        Self {
            invitation_id: commitment.invitation_id,
            attempt_id: commitment.attempt_id,
            device_id: commitment.device_id,
            grant: commitment.grant,
            client_keys: commitment.client_keys,
            client_bundle: Nullable(commitment.client_bundle),
            proposed_grant: commitment.proposed_grant,
            verification_value: commitment.verification_value,
            owner_confirmation: commitment.owner_confirmation,
            committed_at_ms: commitment.committed_at_ms,
        }
    }
}

/// KR-REQ-10.51: the records of a pairing an earlier build committed, naming no approval, read as
/// they were, and the invitation's proposal and the commitment encode to the same bytes in this
/// build. Named by text, each is refused with its table and the invitation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_an_earlier_pairings_records_read_unchanged_or_are_refused_by_name() {
    let owner_keys = DeviceKeys::generate().expect("keys");
    let host = Host::start(&owner_keys).await;
    let device = Device::create().await;
    let paired = pair_with(
        &host,
        &device,
        &owner_keys,
        proposal(&[ActionRight::SessionView]),
    )
    .await;
    let invitation = paired
        .committed_invitation_id
        .expect("the invitation it paired through");
    let database = host.registry_database();
    let rows = host.network().pairing().rows();
    let proposal_row = earlier("pairing_invitations.proposed_grant");
    let commitment_row = earlier("pairing_commitments.commitment");
    let hold_proposal = |payload: &[u8]| {
        hold(
            &database,
            "UPDATE pairing_invitations SET proposed_grant = ?2 WHERE invitation_id = ?1",
            invitation.get(),
            payload,
        );
    };
    let hold_commitment = |payload: &[u8]| {
        hold(
            &database,
            "UPDATE pairing_commitments SET commitment = ?2 WHERE invitation_id = ?1",
            invitation.get(),
            payload,
        );
    };

    hold_proposal(&proposal_row.empty);
    hold_commitment(&commitment_row.empty);
    let row = rows
        .row(invitation)
        .expect("readable")
        .expect("the invitation");
    assert_eq!(encode(&row.terms.proposed_grant), proposal_row.empty);
    let committed = rows
        .commitment(invitation)
        .expect("readable")
        .expect("the commitment");
    assert_eq!(encode(&Commitment::of(committed)), commitment_row.empty);

    hold_proposal(&proposal_row.named);
    let refused = rows
        .row(invitation)
        .expect_err("the proposal names an approval by text");
    assert!(
        names(&refused, "pairing_invitations", invitation.get()),
        "{refused}"
    );
    hold_proposal(&proposal_row.empty);
    hold_commitment(&commitment_row.named);
    let refused = rows
        .commitment(invitation)
        .expect_err("the commitment names an approval by text");
    assert!(
        names(&refused, "pairing_commitments", invitation.get()),
        "{refused}"
    );
    host.stop().await;
}

/// KR-REQ-10.51: a host starts by cancelling every invitation it left unfinished, and an
/// unfinished invitation whose proposal names an approval by text cannot be read, so the sweep
/// fails whole and names the row: the network does not start until the row is repaired, and
/// nothing can load the invitation to redeem it. The control is the same invitation naming
/// nothing, which the sweep cancels.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_an_unfinished_invitation_naming_an_approval_by_text_stops_the_start_up_sweep()
{
    let row = earlier("pairing_invitations.proposed_grant");
    for (payload, sweeps) in [(&row.named, false), (&row.empty, true)] {
        let owner_keys = DeviceKeys::generate().expect("keys");
        let host = Host::start(&owner_keys).await;
        let mut client = host.client().await;
        let open = calls::invite_direct(
            host.environment_id,
            &mut client,
            InviteGrantKind::SessionInvitation,
            &proposal(&[ActionRight::SessionView]),
            &Signer::OwnerDevice(&owner_keys),
        )
        .await
        .expect("an open invitation");
        hold(
            &host.registry_database(),
            "UPDATE pairing_invitations SET proposed_grant = ?2 WHERE invitation_id = ?1",
            open.invitation_id.get(),
            payload,
        );
        let rows = host.network().pairing().rows();
        let swept = kr_pairing::host::cancel_unfinished_invitations(rows);
        if sweeps {
            assert_eq!(swept.expect("the sweep runs"), vec![open.invitation_id]);
        } else {
            let refused = swept.expect_err("the sweep cannot read the row");
            assert!(
                names(&refused, "pairing_invitations", open.invitation_id.get()),
                "{refused}"
            );
            let refused = rows
                .load(open.invitation_id)
                .expect_err("nothing can load the invitation to redeem it");
            assert!(
                names(&refused, "pairing_invitations", open.invitation_id.get()),
                "{refused}"
            );
        }
        host.stop().await;
    }
}

/// A grant held in the store, shared through a session invitation.
fn record(grant: Grant) -> GrantRecord {
    GrantRecord {
        grant,
        session_id: Some(kr_protocol::ids::SessionId::new(Uuid::from_bytes(
            [0x53; 16],
        ))),
        issued_at_ms: 1_000,
        activated_at_ms: Some(1_000),
        revoked_at_ms: None,
        revoked_by_parent: None,
    }
}

/// KR-REQ-10.51: a grant row an earlier build wrote naming no approval reads as it was, and this
/// build writes it to the same bytes. Named by text, the grant permits nothing: its record is
/// refused with the table and the grant named, and every listing that would read it, the device's
/// and the host's, fails whole.
#[test]
fn kr_req_10_51_an_earlier_grant_row_reads_unchanged_or_permits_nothing() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let database = temp.path().join("grants.db");
    let directory = GrantDirectory::open(&database).expect("the grant store");
    let row = earlier("grants.grant");
    let grant: Grant = decode(&row.empty);
    let grant_id = GrantId::new(Uuid::from_bytes(SHARED_GRANT));

    directory
        .issue(&record(grant.clone()), || Ok(()))
        .expect("issued");
    assert_eq!(
        stored(
            &database,
            "SELECT grant FROM grants WHERE grant_id = ?1",
            grant_id.get()
        ),
        row.empty,
        "this build writes the grant as the earlier build wrote it"
    );
    assert_eq!(
        directory
            .record(grant_id)
            .expect("readable")
            .expect("the grant")
            .grant,
        grant
    );

    hold(
        &database,
        "UPDATE grants SET grant = ?2 WHERE grant_id = ?1",
        grant_id.get(),
        &row.named,
    );
    let refused = directory
        .record(grant_id)
        .expect_err("the grant names an approval by text");
    assert!(names(&refused, "grants", grant_id.get()), "{refused}");
    let device = DeviceId::new(Uuid::from_bytes(DEVICE));
    for refused in [
        directory
            .records_for_device(device)
            .map(|_| ())
            .expect_err("the device's grants"),
        directory.records().map(|_| ()).expect_err("every grant"),
    ] {
        assert!(names(&refused, "grants", grant_id.get()), "{refused}");
    }
}

/// KR-REQ-10.51: a session invitation an earlier build wrote naming no approval reads as it was,
/// its preview written to the same bytes. Named by text, it is refused with the table and the
/// invitation named, and it cannot be redeemed.
#[test]
fn kr_req_10_51_an_earlier_session_invitation_reads_unchanged_or_cannot_be_redeemed() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let database = temp.path().join("grants.db");
    let directory = GrantDirectory::open(&database).expect("the grant store");
    let row = earlier("session_invitations.preview");
    let preview: InvitationPreview = decode(&row.empty);
    let invitation = InvitationId::new(Uuid::from_bytes(SESSION_INVITATION));
    let grant: Grant = decode(&earlier("grants.grant").empty);
    let pending = GrantRecord {
        activated_at_ms: None,
        ..record(grant)
    };

    directory
        .issue_shared(
            &pending,
            &preview,
            DeviceId::new(Uuid::from_bytes(HOST)),
            kr_ipc::now_ms().get(),
            || Ok(()),
        )
        .expect("issued");
    assert_eq!(
        stored(
            &database,
            "SELECT preview FROM session_invitations WHERE invitation_id = ?1",
            invitation.get()
        ),
        row.empty,
        "this build writes the preview as the earlier build wrote it"
    );
    assert_eq!(
        directory
            .invitation(invitation)
            .expect("readable")
            .expect("the invitation")
            .preview,
        preview
    );

    hold(
        &database,
        "UPDATE session_invitations SET preview = ?2 WHERE invitation_id = ?1",
        invitation.get(),
        &row.named,
    );
    let refused = directory
        .invitation(invitation)
        .expect_err("the preview names an approval by text");
    assert!(
        names(&refused, "session_invitations", invitation.get()),
        "{refused}"
    );
    let refused = directory
        .redeem(
            invitation,
            DeviceId::new(Uuid::from_bytes(DEVICE)),
            kr_ipc::now_ms().get(),
        )
        .expect_err("it cannot be redeemed");
    assert!(
        names(&refused, "session_invitations", invitation.get()),
        "{refused}"
    );
}

/// KR-REQ-10.51: a retained answer to `grant.create` is kept as the bytes it was, and a retry of
/// that action is given them back unchanged, whichever form they have. The answer naming nothing
/// reads as this build's own result, byte for byte; the one naming an approval by text is refused
/// by this build's typed read, so a client that retries across the change cannot take a grant from
/// it.
#[test]
fn kr_req_10_51_a_retained_earlier_answer_goes_back_unchanged_and_names_nothing_readable() {
    let directory = GrantDirectory::in_memory().expect("the grant store");
    let row = earlier("authority_receipts.result");
    let actor = ActorId::new("device:the-studio-mac").expect("an actor");
    let digest = Digest256::from_bytes([0x71; 32]);

    for (byte, payload, reads) in [(0x01, &row.empty, true), (0x02, &row.named, false)] {
        let action = ActionId::new(Uuid::from_bytes([byte; 16]));
        let ActionClaim::Claimed { hold } = directory
            .claim_action(&actor, action, &digest, 1_000)
            .expect("claimed")
        else {
            panic!("a first claim");
        };
        directory
            .retain_result(&hold, payload, 1_000)
            .expect("retained");
        drop(hold);
        assert_eq!(
            directory
                .recorded_action(&actor, action, &digest)
                .expect("readable"),
            Some(ActionRecord::Answered {
                result: payload.clone()
            }),
            "a retry is given the answer it was given"
        );
        let typed =
            kr_cbor::from_canonical_slice::<GrantCreateResult>(payload, &kr_cbor::Limits::DEFAULT);
        assert_eq!(typed.is_ok(), reads, "{typed:?}");
        if let Ok(result) = typed {
            assert_eq!(&encode(&result), payload);
        }
    }
}
