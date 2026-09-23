//! Collection keys: the wrap, the signed record and the rules between two records.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-20.11, the sync-collection half (the rule) | `removing_members_rotates_and_claims_no_retroactive_secrecy`, `a_drop_without_advancing_the_epoch_by_one_is_refused`, `removing_two_members_advances_the_epoch_once` |
//! | KR-REQ-18.05, part (a key reaches a member only through its own wrap) | `a_collection_key_wrap_opens_only_for_its_recipient_collection_and_epoch`, `a_wrap_opened_from_its_sender_side_is_refused` |

use kr_crypto::CryptoError;
use kr_crypto::envelope::{
    CollectionMembers, CollectionRecipient, CollectionRecordDraft, check_genesis, check_successor,
    issue_collection_key_record, open_collection_key, verify_collection_key_record,
    wrap_collection_key,
};
use kr_crypto::keys::{AuthorisationKeyPair, StoredEnvelopeKeyPair};
use kr_crypto::secret::{Secret, SymmetricKey};
use kr_protocol::collection_keys::{
    CollectionKeyRecord, CollectionKeyWrapContext, CollectionKeyWrapFormat,
};
use kr_protocol::ids::{SyncCollectionId, SyncKeyEpoch, SyncKeyRecordRevision};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_protocol::service::installation_id;

/// One installed device's two keys that membership is about.
struct Device {
    authorisation: AuthorisationKeyPair,
    envelope: StoredEnvelopeKeyPair,
}

impl Device {
    fn new() -> Self {
        Self {
            authorisation: AuthorisationKeyPair::generate().expect("an authorisation key"),
            envelope: StoredEnvelopeKeyPair::generate().expect("a stored-envelope key"),
        }
    }

    fn recipient(&self) -> CollectionRecipient {
        CollectionRecipient {
            authorisation: *self.authorisation.public(),
            stored_envelope: *self.envelope.public(),
        }
    }
}

fn collection() -> SyncCollectionId {
    SyncCollectionId::new(Uuid::from_bytes([0x4c; 16]))
}

fn fresh_key() -> SymmetricKey {
    Secret::random().expect("a random key")
}

fn context(epoch: u64, sender: &Device, recipient: &Device) -> CollectionKeyWrapContext {
    CollectionKeyWrapContext {
        format: CollectionKeyWrapFormat::V1,
        collection_id: collection(),
        key_epoch: SyncKeyEpoch::new(epoch),
        sender_key_id: sender.envelope.key_id(),
        recipient_key_id: recipient.envelope.key_id(),
    }
}

/// The record that creates the collection, issued by its home.
fn genesis(home: &Device, key: &SymmetricKey) -> CollectionKeyRecord {
    let draft = CollectionRecordDraft {
        collection_id: collection(),
        home: installation_id(home.authorisation.public()),
        key_epoch: SyncKeyEpoch::new(0),
        revision: SyncKeyRecordRevision::new(1),
        previous: None,
        issued_at_ms: TimestampMs::new(1),
        members: vec![home.recipient()],
    };
    issue_collection_key_record(&home.authorisation, &home.envelope, &draft, key)
        .expect("a first record")
}

/// A record that follows `previous`, issued by `issuer`, naming `members` at `epoch`.
fn successor(
    previous: &CollectionKeyRecord,
    issuer: &Device,
    members: &[&Device],
    epoch: u64,
    key: &SymmetricKey,
) -> CollectionKeyRecord {
    let draft = CollectionRecordDraft {
        collection_id: previous.payload.collection_id,
        home: previous.payload.home,
        key_epoch: SyncKeyEpoch::new(epoch),
        revision: SyncKeyRecordRevision::new(previous.payload.revision.get() + 1),
        previous: Some(previous.digest().expect("a digest")),
        issued_at_ms: TimestampMs::new(previous.payload.issued_at_ms.get() + 1),
        members: members.iter().map(|device| device.recipient()).collect(),
    };
    issue_collection_key_record(&issuer.authorisation, &issuer.envelope, &draft, key)
        .expect("a record")
}

/// Opens `member`'s wrap in `record` against `issuer`'s stored-envelope key.
fn open_as(
    record: &CollectionKeyRecord,
    member: &Device,
    issuer: &Device,
) -> kr_crypto::Result<SymmetricKey> {
    let entry = record
        .member(member.authorisation.public())
        .expect("the record names the member");
    open_collection_key(
        &member.envelope,
        issuer.envelope.public(),
        &entry.wrap,
        &entry.wrap.context,
    )
}

fn binding(result: kr_crypto::Result<()>) -> bool {
    matches!(result, Err(CryptoError::BindingMismatch { .. }))
}

#[test]
fn a_collection_key_wrap_opens_only_for_its_recipient_collection_and_epoch() {
    let (issuer, member, stranger) = (Device::new(), Device::new(), Device::new());
    let key = fresh_key();
    let wrap = wrap_collection_key(
        &issuer.envelope,
        member.envelope.public(),
        context(3, &issuer, &member),
        &key,
    )
    .expect("a wrap");

    // Its recipient opens it, against the issuer's key, and gets the key that was wrapped.
    let opened = open_collection_key(
        &member.envelope,
        issuer.envelope.public(),
        &wrap,
        &context(3, &issuer, &member),
    )
    .expect("the member opens its own wrap");
    assert!(opened.constant_time_eq(&key));

    // Another device's key does not open it, whatever context it claims.
    assert!(
        open_collection_key(
            &stranger.envelope,
            issuer.envelope.public(),
            &wrap,
            &context(3, &issuer, &stranger),
        )
        .is_err()
    );

    // Expecting it in another epoch or another collection fails before any key is used.
    assert!(matches!(
        open_collection_key(
            &member.envelope,
            issuer.envelope.public(),
            &wrap,
            &context(4, &issuer, &member),
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));
    let mut elsewhere = context(3, &issuer, &member);
    elsewhere.collection_id = SyncCollectionId::new(Uuid::from_bytes([0x4d; 16]));
    assert!(matches!(
        open_collection_key(
            &member.envelope,
            issuer.envelope.public(),
            &wrap,
            &elsewhere
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));

    // A wrap whose context is rewritten to another epoch does not authenticate: the context the
    // reader expects is inside the box.
    let mut moved = wrap.clone();
    moved.context = context(4, &issuer, &member);
    assert!(matches!(
        open_collection_key(
            &member.envelope,
            issuer.envelope.public(),
            &moved,
            &context(4, &issuer, &member),
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));

    // And a wrap cannot be sealed under a context that names other keys than the ones in use.
    assert!(matches!(
        wrap_collection_key(
            &issuer.envelope,
            member.envelope.public(),
            context(3, &issuer, &stranger),
            &key,
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));
}

#[test]
fn a_wrap_opened_from_its_sender_side_is_refused() {
    let (issuer, member) = (Device::new(), Device::new());
    let wrap = wrap_collection_key(
        &issuer.envelope,
        member.envelope.public(),
        context(0, &issuer, &member),
        &fresh_key(),
    )
    .expect("a wrap");

    // `crypto_box` has one shared secret for both directions, so the issuer holds what it takes to
    // decrypt this box against the member's public key. The context names the member as recipient,
    // and that is what refuses the issuer.
    assert!(matches!(
        open_collection_key(
            &issuer.envelope,
            member.envelope.public(),
            &wrap,
            &context(0, &issuer, &member),
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));
    // Claiming the context the other way round does not help either: it is not the wrap's own.
    assert!(matches!(
        open_collection_key(
            &issuer.envelope,
            member.envelope.public(),
            &wrap,
            &context(0, &member, &issuer),
        ),
        Err(CryptoError::BindingMismatch { .. })
    ));
}

#[test]
fn a_record_must_name_the_key_that_signed_it() {
    let (home, other) = (Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);
    let second = successor(&first, &home, &[&home, &other], 0, &key);
    verify_collection_key_record(&second, home.authorisation.public())
        .expect("its issuer signed it");

    // Verified under a key it does not name, it is refused before the signature is looked at.
    assert!(binding(verify_collection_key_record(
        &second,
        other.authorisation.public()
    )));

    // Naming another member as issuer does not make the record that member's: every wrap still
    // names the real issuer as its sender, so the record no longer holds together.
    let mut renamed = second.clone();
    renamed.payload.issuer_key_id = other.authorisation.key_id();
    assert!(binding(verify_collection_key_record(
        &renamed,
        other.authorisation.public()
    )));

    // A signature that is not over this payload does not verify.
    let mut altered = second.clone();
    altered.payload.issued_at_ms = TimestampMs::new(99);
    assert!(matches!(
        verify_collection_key_record(&altered, home.authorisation.public()),
        Err(CryptoError::Authentication { .. })
    ));

    // An issuer that is not among the members cannot issue at all.
    let draft = CollectionRecordDraft {
        collection_id: collection(),
        home: installation_id(home.authorisation.public()),
        key_epoch: SyncKeyEpoch::new(0),
        revision: SyncKeyRecordRevision::new(1),
        previous: None,
        issued_at_ms: TimestampMs::new(1),
        members: vec![other.recipient()],
    };
    assert!(matches!(
        issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key),
        Err(CryptoError::BindingMismatch { .. })
    ));
}

#[test]
fn a_genesis_record_lists_only_its_home_at_revision_one() {
    let (home, other) = (Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);
    check_genesis(&first).expect("the home's own first record");

    let draft = |home_id, epoch, members: Vec<CollectionRecipient>| CollectionRecordDraft {
        collection_id: collection(),
        home: home_id,
        key_epoch: SyncKeyEpoch::new(epoch),
        revision: SyncKeyRecordRevision::new(1),
        previous: None,
        issued_at_ms: TimestampMs::new(1),
        members,
    };
    let issue = |draft: &CollectionRecordDraft| {
        issue_collection_key_record(&home.authorisation, &home.envelope, draft, &key)
            .expect("a record")
    };
    let own = installation_id(home.authorisation.public());

    // Two members from the start: the home claims alone.
    let crowded = issue(&draft(own, 0, vec![home.recipient(), other.recipient()]));
    assert!(binding(check_genesis(&crowded)));
    // Another installation's namespace: nobody claims a home that is not their own.
    let squatted = issue(&draft(
        installation_id(other.authorisation.public()),
        0,
        vec![home.recipient()],
    ));
    assert!(binding(check_genesis(&squatted)));
    // A later epoch: a collection starts at the first.
    let late = issue(&draft(own, 1, vec![home.recipient()]));
    assert!(binding(check_genesis(&late)));
    // A record that follows another is not a first record.
    assert!(binding(check_genesis(&successor(
        &first,
        &home,
        &[&home],
        0,
        &key
    ))));
}

#[test]
fn a_drop_without_advancing_the_epoch_by_one_is_refused() {
    let (home, leaving) = (Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);
    let second = successor(&first, &home, &[&home, &leaving], 0, &key);
    check_successor(&first, &second).expect("an addition");

    // Dropping a member at the same epoch would leave it holding the key the others go on using.
    let kept_key = successor(&second, &home, &[&home], 0, &key);
    assert!(binding(check_successor(&second, &kept_key)));
    // Two epochs at once is not the next epoch.
    let skipped = successor(&second, &home, &[&home], 2, &fresh_key());
    assert!(binding(check_successor(&second, &skipped)));
    // The next epoch, with a new key, is.
    let rotated = successor(&second, &home, &[&home], 1, &fresh_key());
    check_successor(&second, &rotated).expect("a removal at the next epoch");
    // An epoch may also move on with nobody leaving: a new key is always allowed.
    let rekeyed = successor(&second, &home, &[&home, &leaving], 1, &fresh_key());
    check_successor(&second, &rekeyed).expect("a new key for the same members");
}

#[test]
fn removing_two_members_advances_the_epoch_once() {
    let (home, first_leaving, second_leaving) = (Device::new(), Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);
    let second = successor(
        &first,
        &home,
        &[&home, &first_leaving, &second_leaving],
        0,
        &key,
    );

    let mut members = CollectionMembers::of_record(&second);
    assert_eq!(members.key_epoch(), SyncKeyEpoch::new(0));
    let revocation = members
        .revoke(&[
            first_leaving.envelope.key_id(),
            second_leaving.envelope.key_id(),
        ])
        .expect("both are members");
    assert_eq!(
        revocation.removed,
        vec![
            first_leaving.envelope.key_id(),
            second_leaving.envelope.key_id()
        ]
    );
    assert!(revocation.rotates_object_keys);
    assert_eq!(
        members.key_epoch(),
        SyncKeyEpoch::new(1),
        "one step, not two"
    );
    assert_eq!(members.members(), &[home.recipient()]);

    // The record that says so follows the previous one and passes the rules between them.
    let draft = members
        .successor_draft(&second, TimestampMs::new(10))
        .expect("a draft");
    let third =
        issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &fresh_key())
            .expect("a record");
    check_successor(&second, &third).expect("two removals, one epoch step");

    // Naming nobody in the set changes nothing and reports nothing.
    assert!(members.revoke(&[first_leaving.envelope.key_id()]).is_none());
    assert_eq!(members.key_epoch(), SyncKeyEpoch::new(1));
}

#[test]
fn an_addition_keeps_the_epoch_and_every_member() {
    let (home, joining, another) = (Device::new(), Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);

    let mut members = CollectionMembers::of_record(&first);
    assert!(members.add(joining.recipient()));
    assert!(!members.add(joining.recipient()), "a member joins once");
    assert_eq!(members.key_epoch(), SyncKeyEpoch::new(0));
    let draft = members
        .successor_draft(&first, TimestampMs::new(5))
        .expect("a draft");
    let second = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key)
        .expect("a record");
    check_successor(&first, &second).expect("an addition at the same epoch");
    // The joining member's wrap carries the key already in use.
    assert!(
        open_as(&second, &joining, &home)
            .expect("its wrap")
            .constant_time_eq(&key)
    );

    // At the same epoch, a record may not replace a member with another...
    let replaced = successor(&second, &home, &[&home, &another], 0, &key);
    assert!(binding(check_successor(&second, &replaced)));
    // ...nor give an existing member another stored-envelope key.
    let mut rekeyed_member = CollectionMembers::of_record(&first);
    assert!(rekeyed_member.add(CollectionRecipient {
        authorisation: *joining.authorisation.public(),
        stored_envelope: *another.envelope.public(),
    }));
    let draft = rekeyed_member
        .successor_draft(&second, TimestampMs::new(6))
        .expect("a draft");
    let swapped = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key)
        .expect("a record");
    assert!(binding(check_successor(&second, &swapped)));
}

#[test]
fn a_broken_chain_or_a_skipped_revision_is_refused() {
    let (home, member, outsider) = (Device::new(), Device::new(), Device::new());
    let key = fresh_key();
    let first = genesis(&home, &key);
    let second = successor(&first, &home, &[&home, &member], 0, &key);
    check_successor(&first, &second).expect("the next record");

    // A skipped revision.
    let mut draft = CollectionMembers::of_record(&second)
        .successor_draft(&second, TimestampMs::new(9))
        .expect("a draft");
    draft.revision = SyncKeyRecordRevision::new(4);
    let skipped = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key)
        .expect("a record");
    assert!(binding(check_successor(&second, &skipped)));

    // A record that names another previous record.
    let mut draft = CollectionMembers::of_record(&second)
        .successor_draft(&second, TimestampMs::new(9))
        .expect("a draft");
    draft.previous = Some(Digest256::from_bytes([0x5e; 32]));
    let forked = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key)
        .expect("a record");
    assert!(binding(check_successor(&second, &forked)));

    // An issuer the previous record does not name, even one listing itself in the new one.
    let intruding = successor(&second, &outsider, &[&home, &member, &outsider], 0, &key);
    assert!(binding(check_successor(&second, &intruding)));

    // Another collection's record.
    let mut draft = CollectionMembers::of_record(&second)
        .successor_draft(&second, TimestampMs::new(9))
        .expect("a draft");
    draft.collection_id = SyncCollectionId::new(Uuid::from_bytes([0x4e; 16]));
    let elsewhere = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &key)
        .expect("a record");
    assert!(binding(check_successor(&second, &elsewhere)));

    // A member of the previous record may issue the next one.
    let by_member = successor(&second, &member, &[&home, &member], 0, &key);
    check_successor(&second, &by_member).expect("any member may issue");
}

#[test]
fn removing_members_rotates_and_claims_no_retroactive_secrecy() {
    let (home, staying, leaving) = (Device::new(), Device::new(), Device::new());
    let old_key = fresh_key();
    let first = genesis(&home, &old_key);
    let second = successor(&first, &home, &[&home, &staying, &leaving], 0, &old_key);

    let mut members = CollectionMembers::of_record(&second);
    let revocation = members
        .revoke(&[leaving.envelope.key_id()])
        .expect("a member");
    assert!(!revocation.claims_retroactive_secrecy());
    let sentence = revocation.describe_settings_sync();
    assert!(
        sentence.contains("stays readable to it"),
        "the sentence says what the removed device keeps: {sentence}"
    );

    let new_key = fresh_key();
    let draft = members
        .successor_draft(&second, TimestampMs::new(20))
        .expect("a draft");
    let third = issue_collection_key_record(&home.authorisation, &home.envelope, &draft, &new_key)
        .expect("a record");
    check_successor(&second, &third).expect("a removal at the next epoch");

    // The members who stay open the new key; the one who left has no wrap in the new record.
    assert!(
        open_as(&third, &staying, &home)
            .expect("its wrap")
            .constant_time_eq(&new_key)
    );
    assert!(
        !open_as(&third, &staying, &home)
            .expect("its wrap")
            .constant_time_eq(&old_key)
    );
    assert!(third.member(leaving.authorisation.public()).is_none());

    // And what it already had, it keeps: its wrap in the earlier record still opens the old key.
    assert!(
        open_as(&second, &leaving, &home)
            .expect("its old wrap")
            .constant_time_eq(&old_key)
    );
}
