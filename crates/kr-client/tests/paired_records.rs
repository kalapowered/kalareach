//! What a device keeps about the hosts it paired with, as an earlier build wrote it.
//!
//! A device keeps each host's proposed grant, and a proposed grant used to name an approval by the
//! upstream's own text identifier. It names it by the broker's resource identity now, and nothing
//! here reads the earlier shape. The break is safe because every build wrote an empty set, which
//! has the same bytes under either element. A record naming an approval by text is refused with
//! the file and the host or invitation it is for, and the whole file with it, which is the answer
//! that withholds. Text that happens to be a UUID reads, as a resource identity it never was; the
//! copy a device keeps authorises nothing, because the host holds the grant, and whether the device
//! manages the host is read from the rights alone.
//!
//! The files are `fixtures/earlier-records`, written by the earlier build's own store.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.51 | every test here |

use std::path::Path;

use kr_client::pairing::failure::FailureKind;
use kr_client::pairing::paired::PairedHosts;
use kr_protocol::ids::{DeviceId, InvitationId, PendingResourceId};
use kr_protocol::scalars::Uuid;

/// The host the earlier records name.
const HOST: [u8; 16] = [0x0f; 16];

/// The invitation the earlier waiting attempt answers.
const INVITATION: [u8; 16] = [0x11; 16];

fn earlier(form: &str, file: &str) -> Vec<u8> {
    std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/earlier-records")
            .join(form)
            .join(file),
    )
    .expect("the earlier record")
}

/// A store whose directory holds `file` as the earlier build wrote it in `form`.
fn holding(form: &str, file: &str) -> (tempfile::TempDir, PairedHosts) {
    let directory = tempfile::tempdir().expect("a directory on the internal disk");
    let records = directory.path().join("pairing");
    let store = PairedHosts::open(&records).expect("a store");
    kr_ipc::paths::write_owner_only_file(&records.join(file), &earlier(form, file))
        .expect("the earlier file");
    (directory, store)
}

fn written(store: &PairedHosts, file: &str) -> Vec<u8> {
    std::fs::read(store.directory().join(file)).expect("the file this build wrote")
}

/// KR-REQ-10.51: the paired hosts an earlier build kept, naming no approval, are read as they
/// were, and recording the same host again writes the file to the same bytes.
#[test]
fn kr_req_10_51_earlier_paired_hosts_that_name_nothing_read_and_write_back_unchanged() {
    let (_directory, store) = holding("empty", "hosts.json");
    let hosts = store.list().expect("the earlier hosts");
    assert_eq!(hosts.len(), 1);
    let host = hosts.into_iter().next().expect("one host");
    assert_eq!(host.host_device_id, DeviceId::new(Uuid::from_bytes(HOST)));
    assert!(host.proposed_grant.history.named_approvals.is_empty());
    store.record(host).expect("recorded again");
    assert_eq!(
        written(&store, "hosts.json"),
        earlier("empty", "hosts.json")
    );
}

/// KR-REQ-10.51: a paired host whose proposed grant names an approval by text is refused with the
/// file and the host named, and the whole list with it; a device cannot reach a host its records
/// cannot say it paired with.
#[test]
fn kr_req_10_51_an_earlier_paired_host_naming_an_approval_by_text_is_refused_by_name() {
    let (_directory, store) = holding("named", "hosts.json");
    let refused = store
        .list()
        .expect_err("the host names an approval by text");
    assert_eq!(refused.kind, FailureKind::StoreFailed);
    let said = refused.detail.as_str();
    assert!(
        said.contains("hosts.json") && said.contains(&Uuid::from_bytes(HOST).to_string()),
        "the refusal names the file and the host: {said}"
    );
    assert!(
        store
            .by_device(DeviceId::new(Uuid::from_bytes(HOST)))
            .is_err(),
        "nor is the host found by its identity"
    );
}

/// KR-REQ-10.51: text that happens to be a UUID reads as a resource identity with another meaning.
/// The copy authorises nothing: the host holds the grant, and whether this device manages the host
/// is read from the rights alone, which name `session.view` only.
#[test]
fn kr_req_10_51_an_earlier_uuid_shaped_text_reads_and_changes_no_right() {
    let (_directory, store) = holding("uuid", "hosts.json");
    let host = store
        .list()
        .expect("text that is a UUID reads")
        .into_iter()
        .next()
        .expect("one host");
    assert_eq!(
        host.proposed_grant
            .history
            .named_approvals
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![PendingResourceId::new(Uuid::from_bytes([0x52; 16]))]
    );
    assert!(!host.is_owner());
}

/// KR-REQ-10.51: a waiting attempt an earlier build kept, naming no approval, is read as it was and
/// kept again to the same bytes; one naming an approval by text is refused with the file and the
/// invitation named, and is not resumed; one naming text that is a UUID reads.
#[test]
fn kr_req_10_51_an_earlier_waiting_attempt_reads_unchanged_or_is_refused_by_name() {
    let (_directory, store) = holding("empty", "attempt.json");
    let attempt = store
        .waiting_attempt()
        .expect("the earlier attempt")
        .expect("one attempt");
    assert_eq!(
        attempt.invitation_id,
        InvitationId::new(Uuid::from_bytes(INVITATION))
    );
    store.keep_attempt(&attempt).expect("kept again");
    assert_eq!(
        written(&store, "attempt.json"),
        earlier("empty", "attempt.json")
    );

    let (_directory, store) = holding("named", "attempt.json");
    let refused = store
        .waiting_attempt()
        .expect_err("the attempt names an approval by text");
    assert_eq!(refused.kind, FailureKind::StoreFailed);
    let said = refused.detail.as_str();
    assert!(
        said.contains("attempt.json") && said.contains(&Uuid::from_bytes(INVITATION).to_string()),
        "the refusal names the file and the invitation: {said}"
    );

    let (_directory, store) = holding("uuid", "attempt.json");
    assert!(
        store
            .waiting_attempt()
            .expect("text that is a UUID reads")
            .is_some()
    );
}
