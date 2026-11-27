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

/// A boot of the machine's own order counter, for a store that records where an access began.
fn boot() -> kr_controller::boots::BootClock {
    kr_controller::boots::BootClock::new(
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        kr_protocol::ids::BootEpoch::new(1),
    )
}

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
/// device connects, and this build writes the same grant to the same bytes and leaves them as they
/// were. A grant with no history cursor is read from the moment of the pairing.
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
    assert_eq!(
        read.grant,
        Grant {
            // The device was paired at the moment `device_record` gives it.
            history: grant.history.clone().from_start(1_000),
            ..grant
        }
    );
    assert_eq!(
        stored(
            &database,
            "SELECT grant FROM network_devices WHERE device_id = ?1",
            device
        ),
        row.empty,
        "reading the row leaves the bytes the earlier build wrote"
    );
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
/// build writes it to the same bytes and leaves them as they were. A grant with no history cursor
/// is read from the moment its invitation was redeemed. Named by text, the grant permits nothing:
/// its record is refused with the table and the grant named, and every listing that would read it,
/// the device's and the host's, fails whole.
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
    let read = directory
        .record(grant_id)
        .expect("readable")
        .expect("the grant");
    assert_eq!(
        read.grant,
        Grant {
            // The grant was redeemed at the moment `record` gives it.
            history: grant.history.clone().from_start(1_000),
            ..grant
        }
    );
    assert_eq!(
        stored(
            &database,
            "SELECT grant FROM grants WHERE grant_id = ?1",
            grant_id.get()
        ),
        row.empty,
        "reading the row leaves the bytes the earlier build wrote"
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
            &boot(),
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
            &boot(),
            || Ok(()),
            None,
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
                result: payload.clone(),
                reads: None
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

/// The device table as a registry at schema version 16 held it: an endpoint identity unique for
/// ever. `oldest` leaves out the five columns that were added to it later.
fn earlier_device_table(oldest: bool) -> String {
    let later = if oldest {
        ""
    } else {
        ", expired_at_ms INTEGER, committed_invitation_id BLOB, notification_preview BLOB,
           stored_envelope_key BLOB"
    };
    format!(
        "CREATE TABLE network_devices (
             device_id BLOB PRIMARY KEY NOT NULL,
             endpoint_id BLOB NOT NULL UNIQUE,
             device_key_revision INTEGER NOT NULL,
             authorisation_key BLOB NOT NULL,
             device_name TEXT NOT NULL,
             platform TEXT NOT NULL,
             grant_id BLOB NOT NULL,
             grant BLOB NOT NULL,
             paired_at_ms INTEGER NOT NULL,
             revoked_at_ms INTEGER{later}
         );
         CREATE INDEX network_devices_endpoint ON network_devices (endpoint_id);
         CREATE TRIGGER network_devices_authorisation_key_fixed
             BEFORE UPDATE OF authorisation_key ON network_devices
             WHEN NEW.authorisation_key IS NOT OLD.authorisation_key
         BEGIN
             SELECT RAISE(ABORT, 'a device''s authorisation key is fixed for its identity');
         END;"
    )
}

/// Makes the registry file a build that wrote schema version `version` left: a registry as this
/// build makes it, with its device table put back to the earlier shape and two rows in it, a live
/// one for endpoint `0x31` and a revoked one for endpoint `0x32`, each holding the earlier grant.
fn registry_left_at(path: &Path, version: i64, oldest: bool) {
    let environment = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16]));
    drop(kr_controller::registry::Registry::open(path, environment).expect("a registry"));
    let grant = earlier("network_devices.grant").empty;
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    connection
        .execute_batch("DROP INDEX network_devices_live_endpoint; DROP TABLE network_devices;")
        .expect("the table goes");
    connection
        .execute_batch(&earlier_device_table(oldest))
        .expect("the earlier table");
    for (device, endpoint, revoked) in [(0xa1_u8, 0x31_u8, None), (0xa2, 0x32, Some(5_i64))] {
        connection
            .execute(
                "INSERT INTO network_devices (device_id, endpoint_id, device_key_revision,
                     authorisation_key, device_name, platform, grant_id, grant, paired_at_ms,
                     revoked_at_ms)
                 VALUES (?1, ?2, 1, ?3, 'a phone', 'android', ?4, ?5, 1, ?6)",
                rusqlite::params![
                    [device; 16].as_slice(),
                    [endpoint; 32].as_slice(),
                    [endpoint.wrapping_add(1); 32].as_slice(),
                    [device; 16].as_slice(),
                    grant,
                    revoked,
                ],
            )
            .expect("an earlier row");
    }
    connection
        .execute("UPDATE schema_version SET version = ?1", [version])
        .expect("the version");
}

fn recorded_version(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .expect("the registry opens")
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("a version")
}

/// A device row as the migration case reads it: the device, its endpoint, when it was revoked and
/// its grant.
type DeviceRow = (Vec<u8>, Vec<u8>, Option<i64>, Vec<u8>);

/// What the file says of `network_devices` and what hangs on it, in a fixed order.
fn device_schema(path: &Path) -> Vec<(String, String, String)> {
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    let mut statement = connection
        .prepare(
            "SELECT type, name, COALESCE(sql, '') FROM sqlite_master
             WHERE tbl_name LIKE 'network_devices%' ORDER BY type, name",
        )
        .expect("the schema");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row")
}

fn open_registry(path: &Path) -> kr_controller::error::Result<kr_controller::registry::Registry> {
    let environment = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16]));
    kr_controller::registry::Registry::open(path, environment)
}

/// A registry at schema version 16, with the device table as it was, is brought to the version
/// this build writes in two steps, 16 to 18 and 18 to 19: both rows read back as they were, the
/// key stays fixed, the endpoint identity of a revoked row is free for a new record and that of a
/// live row is not, and the file's schema equals a new file's.
#[test]
fn a_registry_at_16_is_rebuilt_so_an_ended_endpoint_identity_is_free() {
    for oldest in [false, true] {
        let temp = tempfile::tempdir().expect("a directory on the internal disk");
        let path = temp.path().join("registry.db");
        registry_left_at(&path, 16, oldest);
        drop(open_registry(&path).expect("brought forward"));
        assert_eq!(
            recorded_version(&path),
            kr_controller::registry::SCHEMA_VERSION,
            "oldest shape {oldest}"
        );
        let connection = rusqlite::Connection::open(&path).expect("the registry opens");
        let rows: Vec<DeviceRow> = connection
            .prepare(
                "SELECT device_id, endpoint_id, revoked_at_ms, grant FROM network_devices
                 ORDER BY device_id",
            )
            .expect("a read")
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("every row");
        let grant = earlier("network_devices.grant").empty;
        assert_eq!(
            rows,
            vec![
                (
                    [0xa1; 16].to_vec(),
                    [0x31; 32].to_vec(),
                    None,
                    grant.clone()
                ),
                ([0xa2; 16].to_vec(), [0x32; 32].to_vec(), Some(5), grant),
            ],
            "oldest shape {oldest}: every row is carried across unchanged"
        );
        assert!(
            connection
                .execute("UPDATE network_devices SET authorisation_key = x'00'", [])
                .is_err(),
            "the key of a device stays fixed after the rebuild"
        );
        let insert = |device: u8, endpoint: u8| {
            connection.execute(
                "INSERT INTO network_devices (device_id, endpoint_id, device_key_revision,
                     authorisation_key, device_name, platform, grant_id, grant, paired_at_ms)
                 VALUES (?1, ?2, 1, x'01', 'a phone', 'android', ?1, x'', 2)",
                rusqlite::params![[device; 16].as_slice(), [endpoint; 32].as_slice()],
            )
        };
        assert!(
            insert(0xb1, 0x31).is_err(),
            "a live row still holds its endpoint identity"
        );
        assert!(insert(0xb2, 0x32).is_ok(), "a revoked row does not");
        assert!(
            device_schema(&path)
                .iter()
                .all(|(_, name, _)| name != "network_devices_superseded"),
            "no half of the rebuild is left behind"
        );
        // The migrated file's schema equals a new file's.
        let fresh = temp.path().join("fresh.db");
        drop(open_registry(&fresh).expect("a new registry"));
        assert_eq!(
            device_schema(&path),
            device_schema(&fresh),
            "oldest shape {oldest}"
        );
    }
}

/// The columns the early steps of the ladder add, each with the version its step brings the file
/// to. A file left at an earlier version lacks them.
const ADDED_BY_THE_EARLY_STEPS: &[(i64, &str, &str)] = &[
    (2, "reservations", "create_intent"),
    (2, "reservations", "claimed_key"),
    (2, "environment", "authority_revision"),
    (2, "workers", "acknowledged_revision"),
    (3, "environment", "fence_owed_revision"),
    (3, "environment", "accepted_revision"),
    (3, "environment", "accepted_document"),
    (4, "workers", "stated_source"),
    (6, "workers", "desktop_session_id"),
    (6, "workers", "login_generation"),
];

/// Takes from the file at `path` the columns that the steps after `version` add, so that the file
/// is left as a build that wrote `version` left it in those tables.
fn without_the_columns_added_after(path: &Path, version: i64) {
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    for (to, table, column) in ADDED_BY_THE_EARLY_STEPS {
        if version < *to {
            connection
                .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column};"))
                .unwrap_or_else(|error| panic!("{table}.{column} goes: {error}"));
        }
    }
}

/// Every version a registry can be left at with the earlier device table, from 1 to 16 (17 was
/// written by no release, and a registry at 18 or later has the rebuilt table), is
/// brought to the version this build writes with the device table rebuilt and both rows carried
/// across, and the file's device schema equals a new file's. The file is made as
/// `registry_left_at` makes it: a registry as this build makes it, its device table put back to
/// the earlier shape, its version set back to the version under test, and the columns that the
/// steps after that version add taken away, so the ladder runs from that version's arm to its end.
/// The other tables are those of this build, which every other step meets as `CREATE TABLE IF NOT
/// EXISTS` and as an update of rows.
#[test]
fn a_registry_left_at_any_earlier_version_is_brought_forward_to_the_shape_of_a_new_file() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let fresh = temp.path().join("fresh.db");
    drop(open_registry(&fresh).expect("a new registry"));
    for version in 1..=16 {
        for oldest in [false, true] {
            let path = temp.path().join(format!("from-{version}-{oldest}.db"));
            registry_left_at(&path, version, oldest);
            without_the_columns_added_after(&path, version);
            drop(open_registry(&path).unwrap_or_else(|error| {
                panic!("from version {version}, oldest shape {oldest}: {error}")
            }));
            assert_eq!(
                recorded_version(&path),
                kr_controller::registry::SCHEMA_VERSION,
                "from version {version}, oldest shape {oldest}"
            );
            assert_eq!(
                device_schema(&path),
                device_schema(&fresh),
                "from version {version}, oldest shape {oldest}: the schema is a new file's"
            );
            let rows: i64 = rusqlite::Connection::open(&path)
                .expect("the registry opens")
                .query_row("SELECT COUNT(*) FROM network_devices", [], |row| row.get(0))
                .expect("a count");
            assert_eq!(rows, 2, "from version {version}: both rows are carried");
        }
    }
}

/// A second open of a registry that was brought forward from 16 changes nothing: the device table
/// keeps its schema and its rows.
#[test]
fn a_registry_that_was_brought_forward_is_not_rebuilt_again() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_left_at(&path, 16, false);
    drop(open_registry(&path).expect("brought forward"));
    let (schema, count): (_, i64) = (
        device_schema(&path),
        rusqlite::Connection::open(&path)
            .expect("the registry opens")
            .query_row("SELECT COUNT(*) FROM network_devices", [], |row| row.get(0))
            .expect("a count"),
    );
    drop(open_registry(&path).expect("opened again"));
    assert_eq!(device_schema(&path), schema);
    assert_eq!(
        rusqlite::Connection::open(&path)
            .expect("the registry opens")
            .query_row("SELECT COUNT(*) FROM network_devices", [], |row| row.get(0))
            .ok(),
        Some(count)
    );
}

/// A rebuild that fails after it began leaves the file at its version, with the table it had and
/// every row in it, and the next open, once the fault is gone, brings it forward.
#[test]
fn a_rebuild_that_fails_leaves_the_registry_as_it_was() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_left_at(&path, 16, false);
    // The last statement of the rebuild makes an index of the table under this name, after the
    // rows were copied and the old table dropped: another table already holds the name.
    {
        let connection = rusqlite::Connection::open(&path).expect("the registry opens");
        connection
            .execute_batch(
                "DROP INDEX network_devices_endpoint;
                 CREATE TABLE in_the_way (endpoint BLOB);
                 CREATE INDEX network_devices_endpoint ON in_the_way (endpoint);",
            )
            .expect("the fault");
    }
    let before = device_schema(&path);
    assert!(open_registry(&path).is_err(), "the registry does not open");
    assert_eq!(recorded_version(&path), 16, "the version was not written");
    let after = device_schema(&path);
    assert!(
        after.iter().any(|(_, name, sql)| name == "network_devices"
            && sql.contains("endpoint_id BLOB NOT NULL UNIQUE")),
        "the earlier table is intact: {after:?}"
    );
    assert!(
        after
            .iter()
            .all(|(_, name, _)| name != "network_devices_superseded"),
        "the renamed table is not left behind"
    );
    assert_eq!(
        rusqlite::Connection::open(&path)
            .expect("the registry opens")
            .query_row("SELECT COUNT(*) FROM network_devices", [], |row| row
                .get::<_, i64>(0))
            .ok(),
        Some(2),
        "both rows are still there"
    );
    let _ = before;
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch("DROP INDEX network_devices_endpoint; DROP TABLE in_the_way;")
        .expect("the fault goes");
    drop(open_registry(&path).expect("brought forward once the fault is gone"));
    assert_eq!(
        recorded_version(&path),
        kr_controller::registry::SCHEMA_VERSION
    );
}

/// Every object of the file's schema, in a fixed order.
fn schema_of(path: &Path) -> Vec<(String, String, String)> {
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    let mut statement = connection
        .prepare("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
        .expect("the schema");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row")
}

/// No release wrote schema version 17, so a registry that records it is refused as such, and the
/// file is left exactly as it was: no writer brings a table or a column forward in it.
#[test]
fn a_registry_at_17_is_refused_as_a_version_no_release_wrote() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_left_at(&path, 17, false);
    let before = schema_of(&path);
    let error = match open_registry(&path) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a registry at 17 is refused"),
    };
    assert!(error.contains("no release wrote"), "{error}");
    assert_eq!(recorded_version(&path), 17, "nothing was changed");
    assert_eq!(
        schema_of(&path),
        before,
        "the refused file's schema is unchanged"
    );
}

/// A registry file as a release that did not make the two tables of version 21 left it: a registry
/// as this build makes it, with those tables gone and the version `version`.
fn registry_without_the_boot_tables_at(path: &Path, version: i64) {
    drop(open_registry(path).expect("a registry"));
    rusqlite::Connection::open(path)
        .expect("the registry opens")
        .execute_batch(&format!(
            "DROP TABLE boots; DROP TABLE grant_starts; UPDATE schema_version SET version = {version};"
        ))
        .expect("the two tables go and the version is put back");
}

/// What the file says of the two tables of version 21, in a fixed order.
fn boot_schema(path: &Path) -> Vec<(String, String, String)> {
    schema_of(path)
        .into_iter()
        .filter(|(_, name, _)| name == "boots" || name == "grant_starts")
        .collect()
}

/// KR-REQ-23.45: this build writes the registry at schema version 21 and reads through 22, and a
/// registry at 19 is brought to 21: both tables made, with the schema of a new file's, and the
/// version written after them, so a step that stops in the middle leaves the file at 19.
#[test]
fn a_registry_at_19_is_brought_to_21_with_the_two_boot_tables_and_the_version_last() {
    assert_eq!(kr_controller::registry::SCHEMA_VERSION, 21);
    assert_eq!(kr_controller::registry::READS_THROUGH_SCHEMA_VERSION, 22);
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let fresh = temp.path().join("fresh.db");
    drop(open_registry(&fresh).expect("a new registry"));
    let path = temp.path().join("from-19.db");
    registry_without_the_boot_tables_at(&path, 19);
    assert!(
        boot_schema(&path).is_empty(),
        "the file is as release 19 left it"
    );
    // An index that has the name of the second table is in the way: the step stops, and the
    // version is still the one the file had.
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch("CREATE INDEX grant_starts ON grants (grant_id);")
        .expect("the fault is made");
    assert!(
        open_registry(&path).is_err(),
        "a step that cannot make a table fails"
    );
    assert_eq!(
        recorded_version(&path),
        19,
        "the version is written after the tables, so a failed step leaves it"
    );
    rusqlite::Connection::open(&path)
        .expect("the registry opens")
        .execute_batch("DROP INDEX grant_starts;")
        .expect("the fault goes");
    let opened = open_registry(&path);
    assert!(
        opened.is_ok(),
        "brought forward once the fault is gone: {:?}",
        opened.err()
    );
    drop(opened);
    assert_eq!(recorded_version(&path), 21);
    assert_eq!(
        boot_schema(&path),
        boot_schema(&fresh),
        "the two tables are a new file's"
    );
    assert_eq!(boot_schema(&path).len(), 2);
}

/// KR-REQ-23.45: no release writes schema version 20, so a registry that records it is refused as
/// such, before a table is made: the file is left as it was, and neither boot table is in it.
#[test]
fn a_registry_at_20_is_refused_as_a_version_no_release_wrote_and_no_table_is_made() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_without_the_boot_tables_at(&path, 20);
    let before = schema_of(&path);
    let error = match open_registry(&path) {
        Err(error) => error.to_string(),
        Ok(_) => panic!("a registry at 20 is refused"),
    };
    assert!(error.contains("no release wrote"), "{error}");
    assert_eq!(recorded_version(&path), 20, "nothing was changed");
    assert_eq!(schema_of(&path), before, "no table was made in the file");
    assert!(boot_schema(&path).is_empty());
}

/// KR-REQ-23.45: a registry file that this build refuses is left byte for byte as it was, also when
/// it lacks a table that an ordinary writer makes as it opens the file: the version is read, and the
/// refusal made, before any table is. The file here is at 20, which no release wrote, at 17, which
/// none wrote either, and at 23, past what this build reads, and it lacks one ordinary table and
/// the clock table.
#[test]
fn a_refused_registry_that_lacks_an_ordinary_table_is_left_byte_for_byte_as_it_was() {
    for version in [20_i64, 17, 23] {
        let temp = tempfile::tempdir().expect("a directory on the internal disk");
        let path = temp.path().join("registry.db");
        drop(open_registry(&path).expect("a registry"));
        rusqlite::Connection::open(&path)
            .expect("the registry opens")
            .execute_batch(&format!(
                "DROP TABLE tombstones; DROP TABLE clock_continuity;
                 UPDATE schema_version SET version = {version};"
            ))
            .expect("the tables go and the version is put back");
        let before = std::fs::read(&path).expect("the file reads");
        let schema = schema_of(&path);
        assert!(
            schema.iter().all(|(_, name, _)| name != "tombstones"),
            "the file lacks an ordinary table"
        );
        let refusal = match open_registry(&path) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a registry at {version} is refused"),
        };
        assert!(
            refusal.contains(&format!("schema version {version}")),
            "{refusal}"
        );
        assert_eq!(
            std::fs::read(&path).expect("the file reads"),
            before,
            "the file refused at {version} is byte for byte as it was"
        );
        assert_eq!(
            schema_of(&path),
            schema,
            "no table was made in the file refused at {version}"
        );
        assert_eq!(recorded_version(&path), version);
    }
}

/// The journal mode a registry file is in before anything of the product looks at it.
#[derive(Clone, Copy, Debug)]
enum Journal {
    /// The rollback journal: the mode of a file no daemon has put into write-ahead mode.
    Rollback,
    /// Write-ahead logging: the mode a daemon leaves a file in.
    WriteAhead,
}

impl Journal {
    fn pragma(self) -> &'static str {
        match self {
            Self::Rollback => "DELETE",
            Self::WriteAhead => "WAL",
        }
    }

    /// The two bytes of a database file's header, at offsets 18 and 19, that record the mode.
    fn header(self) -> [u8; 2] {
        match self {
            Self::Rollback => [1, 1],
            Self::WriteAhead => [2, 2],
        }
    }
}

/// Which of the registry's two ways of being opened for writing a case asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opener {
    /// A daemon's start.
    Open,
    /// An update that brings a registry forward.
    BringForward,
}

/// The names in `directory`, in a fixed order.
fn listing(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .expect("the folder lists")
        .map(|entry| {
            entry
                .expect("an entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

/// The two header bytes of the file at `path` that record its journal mode.
fn journal_header(path: &Path) -> [u8; 2] {
    let bytes = std::fs::read(path).expect("the file reads");
    [bytes[18], bytes[19]]
}

/// A registry file at `version`, in `journal` mode, that lacks the clock table an ordinary writer
/// makes as it opens the file, with nothing beside it.
///
/// The product makes the tables of a new file once, and a connection of the case then drops the
/// clock table, sets the version and puts the file into the mode, before the case takes the bytes
/// it compares: the first look of the product at the file is the one under test. The file's header
/// and the folder are checked here, so a case that is red is red for the opener, not for its
/// fixture.
fn registry_in_mode(path: &Path, version: i64, journal: Journal) {
    drop(open_registry(path).expect("a registry"));
    let connection = rusqlite::Connection::open(path).expect("the registry opens");
    connection
        .execute_batch(&format!(
            "DROP TABLE clock_continuity; UPDATE schema_version SET version = {version};"
        ))
        .expect("the clock table goes and the version is put back");
    connection
        .pragma_update(None, "journal_mode", journal.pragma())
        .expect("the journal mode is set");
    drop(connection);
    assert_eq!(
        journal_header(path),
        journal.header(),
        "the file is in {journal:?} mode before anything of the product looks at it"
    );
    assert_eq!(
        listing(path.parent().expect("a folder")),
        [path.file_name().expect("a name").to_string_lossy()],
        "nothing is beside the file"
    );
}

/// KR-REQ-23.45: a registry file that this build refuses is left as it was in either journal mode:
/// the file's bytes, which include the two header bytes that record the mode, and the folder's
/// listing are the same after the refusal, so no table is made, no mode is set and no file is left
/// beside it. A daemon's start refuses 17 and 20, which no release wrote, and 23, past what this
/// build reads. An update that brings a registry forward refuses 17 and 20 the same way, and leaves
/// 23 for the reader to refuse in its own words.
#[test]
fn a_refused_registry_is_left_as_it_was_in_either_journal_mode() {
    let environment = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16]));
    let mut failures: Vec<String> = Vec::new();
    for journal in [Journal::Rollback, Journal::WriteAhead] {
        for version in [17_i64, 20, 23] {
            for opener in [Opener::Open, Opener::BringForward] {
                let temp = tempfile::tempdir().expect("a directory on the internal disk");
                let path = temp.path().join("registry.db");
                registry_in_mode(&path, version, journal);
                let schema = schema_of(&path);
                let bytes = std::fs::read(&path).expect("the file reads");
                let names = listing(temp.path());
                let outcome: Result<(), String> = match opener {
                    Opener::Open => open_registry(&path).map(drop).map_err(|e| e.to_string()),
                    Opener::BringForward => {
                        kr_controller::registry::Registry::bring_forward(&path, environment)
                            .map(|carried| assert!(carried.is_none(), "{carried:?}"))
                            .map_err(|e| e.to_string())
                    }
                };
                let what = format!("{opener:?} at {version} in {journal:?} mode");
                match (opener == Opener::Open || version != 23, outcome) {
                    (true, Err(refusal))
                        if refusal.contains(&format!("schema version {version}")) => {}
                    (false, Ok(())) => {}
                    (_, other) => {
                        failures.push(format!("{what}: not refused as it should be: {other:?}"))
                    }
                }
                if std::fs::read(&path).expect("the file reads") != bytes {
                    failures.push(format!("{what}: the file is not byte for byte as it was"));
                }
                if journal_header(&path) != journal.header() {
                    failures.push(format!("{what}: the journal mode is not as it was"));
                }
                if listing(temp.path()) != names {
                    failures.push(format!("{what}: the folder's listing changed"));
                }
                if schema_of(&path) != schema {
                    failures.push(format!("{what}: a table was made"));
                }
                if recorded_version(&path) != version {
                    failures.push(format!("{what}: the version was changed"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A file at a supported version opens as it always did: the mode is set to write-ahead, the
/// tables a new file has are all there, and the version is as it was.
#[test]
fn a_registry_in_the_rollback_mode_at_a_supported_version_opens_and_is_put_in_write_ahead_mode() {
    let other = tempfile::tempdir().expect("a directory on the internal disk");
    let fresh = other.path().join("fresh.db");
    drop(open_registry(&fresh).expect("a new registry"));
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_in_mode(
        &path,
        kr_controller::registry::SCHEMA_VERSION,
        Journal::Rollback,
    );
    let opened = open_registry(&path);
    assert!(
        opened.is_ok(),
        "a supported registry opens: {:?}",
        opened.err()
    );
    drop(opened);
    assert_eq!(
        journal_header(&path),
        Journal::WriteAhead.header(),
        "the open put the file into write-ahead mode"
    );
    assert_eq!(
        recorded_version(&path),
        kr_controller::registry::SCHEMA_VERSION
    );
    assert_eq!(
        schema_of(&path),
        schema_of(&fresh),
        "the clock table is made again: the file has the tables a new one has"
    );
}

/// A registry as a newer daemon leaves it when it stops hard: its file, and beside it a
/// write-ahead log that holds committed writes the file does not. Nothing else is beside them.
///
/// The case makes it with a connection of its own that keeps its log, and copies the file and the
/// log while that connection is open and idle: the copy is what a stop leaves, a log and no
/// shared-memory file. The writes the log holds are the version and the loss of the clock table.
fn registry_with_a_log(directory: &Path, version: i64) -> std::path::PathBuf {
    let made = directory.join("made.db");
    drop(open_registry(&made).expect("a registry"));
    let writer = rusqlite::Connection::open(&made).expect("a writer");
    writer
        .pragma_update(None, "wal_autocheckpoint", 0)
        .expect("no checkpoint");
    writer
        .execute_batch(&format!(
            "DROP TABLE clock_continuity; UPDATE schema_version SET version = {version};"
        ))
        .expect("writes that only the log holds");
    let left = directory.join("left.db");
    std::fs::copy(&made, &left).expect("the file is copied");
    std::fs::copy(directory.join("made.db-wal"), directory.join("left.db-wal"))
        .expect("the log is copied");
    drop(writer);
    assert!(
        std::fs::metadata(directory.join("left.db-wal"))
            .expect("a log")
            .len()
            > 0,
        "the log holds writes"
    );
    assert!(
        !directory.join("left.db-shm").exists(),
        "no shared-memory file, as after a stop"
    );
    left
}

/// The version, the schema's text and a digest over the rows of every table, as a read-only
/// connection reads them through the log.
fn what_a_reader_sees(path: &Path) -> (i64, Vec<(String, String, String)>, u64) {
    use std::hash::{DefaultHasher, Hash as _, Hasher as _};

    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("a read-only connection opens");
    let version = connection
        .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
        .expect("a version");
    let schema: Vec<(String, String, String)> = connection
        .prepare("SELECT type, name, COALESCE(sql, '') FROM sqlite_master ORDER BY type, name")
        .expect("the schema")
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("rows")
        .collect::<Result<_, _>>()
        .expect("every row");
    let mut digest = DefaultHasher::new();
    for (_, table, _) in schema
        .iter()
        .filter(|(kind, name, _)| kind == "table" && !name.starts_with("sqlite_"))
    {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{table}\""))
            .expect("a table reads");
        let columns = statement.column_count();
        let mut rows: Vec<String> = statement
            .query_map([], |row| {
                let mut text = String::new();
                for column in 0..columns {
                    let value: rusqlite::types::Value = row.get(column)?;
                    text.push_str(&format!("{value:?}|"));
                }
                Ok(text)
            })
            .expect("rows")
            .collect::<Result<_, _>>()
            .expect("every row");
        rows.sort();
        (table, rows).hash(&mut digest);
    }
    (version, schema, digest.finish())
}

/// KR-REQ-23.45: an update refuses a registry at 17 or 20 by its version, also in a folder that
/// cannot take the log and the index a write-ahead file makes as it is opened for writing: the look
/// that reads the version opens nothing for writing, so the refusal does not wait on that open.
#[test]
fn an_update_refuses_a_registry_at_17_or_20_by_its_version_in_a_folder_that_takes_no_new_file() {
    use std::os::unix::fs::PermissionsExt as _;

    let environment = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([7; 16]));
    for version in [17_i64, 20] {
        let temp = tempfile::tempdir().expect("a directory on the internal disk");
        let folder = temp.path().join("sealed");
        std::fs::create_dir(&folder).expect("a folder");
        let path = folder.join("registry.db");
        registry_in_mode(&path, version, Journal::WriteAhead);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o555))
            .expect("the folder is sealed");
        let sealed = std::fs::File::create(folder.join("probe")).is_err();
        let outcome = kr_controller::registry::Registry::bring_forward(&path, environment);
        // Unsealed before anything is asserted, so that the temporary folder can be removed.
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o755))
            .expect("the folder is open again");
        assert!(sealed, "the folder takes no new file");
        let refusal = outcome.expect_err("refused").to_string();
        assert!(
            refusal.contains(&format!("schema version {version}")),
            "refused by its version at {version}: {refusal}"
        );
    }
}

/// KR-REQ-23.45: a registry that a newer daemon left with a log that holds writes is refused, and
/// the refusal adds nothing to what the database's own recovery does: the version, the schema's
/// text and every table's rows, read through the log, are the same before and after. The log is the
/// only place that holds the version here, so the file alone would read as a supported registry.
#[test]
fn a_refused_registry_with_a_log_that_holds_writes_reads_the_same_after_the_refusal() {
    for version in [17_i64, 20, 23] {
        let temp = tempfile::tempdir().expect("a directory on the internal disk");
        let path = registry_with_a_log(temp.path(), version);
        let alone = kr_controller::registry::open_immutable(&path)
            .expect("the file alone reads")
            .query_row("SELECT version FROM schema_version", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("a version");
        assert_eq!(
            alone,
            kr_controller::registry::SCHEMA_VERSION,
            "the file alone records a supported version: the log holds the one under test"
        );
        let before = what_a_reader_sees(&path);
        assert_eq!(before.0, version, "read through the log");
        let refusal = match open_registry(&path) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a registry at {version} is refused"),
        };
        assert!(
            refusal.contains(&format!("schema version {version}")),
            "{refusal}"
        );
        assert_eq!(
            what_a_reader_sees(&path),
            before,
            "the refusal at {version} changed nothing a reader sees"
        );
    }
}

/// KR-REQ-23.45: a registry at 22 is the tables of 21 with the configuration document at its next
/// version, and this build opens it as it finds it: nothing is brought forward, no table is made
/// and no version is written.
#[test]
fn a_registry_at_22_is_opened_as_found() {
    let temp = tempfile::tempdir().expect("a directory on the internal disk");
    let path = temp.path().join("registry.db");
    registry_without_the_boot_tables_at(&path, 22);
    let before = schema_of(&path);
    let opened = open_registry(&path);
    assert!(opened.is_ok(), "a registry at 22 opens: {:?}", opened.err());
    drop(opened);
    assert_eq!(recorded_version(&path), 22, "no version was written");
    assert_eq!(schema_of(&path), before, "nothing was brought forward");
}
