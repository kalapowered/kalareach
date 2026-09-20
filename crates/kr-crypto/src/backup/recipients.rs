//! Who an archive is wrapped for, what revoking one of them does, and which old keys are kept.

use std::collections::BTreeMap;

use kr_protocol::ids::{BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{KeyId, StoredEnvelopeKey};

use crate::kdf::RecoveryRecipient;
use crate::secret::SymmetricKey;

/// What kind of collection an archive belongs to.
///
/// The distinction decides one thing: whether revoking a recipient has to rotate keys as well as
/// stop future wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CollectionKind {
    /// One owner writes it. Removing a recipient stops future wraps, and there is nothing else to
    /// take away: no other device was contributing content the removed one would go on reading.
    Owned,
    /// Several devices write to it, and its content keeps changing. Removing a recipient rotates
    /// the keys as well, because a device that kept reading what the others wrote after it left
    /// would have lost nothing by being removed.
    MutableShared,
}

/// Every recipient one archive's keys are wrapped for.
///
/// The recovery recipient is an ordinary member: section 20 has every new archive of a
/// recovery-enabled collection wrap its manifest key for it, and a producer holds only its public
/// key.
#[derive(Clone, Debug)]
pub struct ArchiveRecipients {
    kind: CollectionKind,
    keys: Vec<StoredEnvelopeKey>,
}

impl ArchiveRecipients {
    /// Builds an empty set for one kind of collection.
    #[must_use]
    pub const fn new(kind: CollectionKind) -> Self {
        Self {
            kind,
            keys: Vec::new(),
        }
    }

    /// Returns what kind of collection this is.
    #[must_use]
    pub const fn kind(&self) -> CollectionKind {
        self.kind
    }

    /// Adds one recipient. Returns false when it is already there.
    pub fn add(&mut self, key: StoredEnvelopeKey) -> bool {
        if self.contains(&crate::backup::recipient_key_id(&key)) {
            return false;
        }
        self.keys.push(key);
        true
    }

    /// Adds the recipient the owner's recovery seed derives.
    ///
    /// A producer registers the public key and nothing else, which is what keeps future archives
    /// recoverable without copying a device private key.
    pub fn add_recovery(&mut self, recovery: &RecoveryRecipient) -> bool {
        self.add(*recovery.public())
    }

    /// Returns true when the set names this recipient.
    #[must_use]
    pub fn contains(&self, key_id: &KeyId) -> bool {
        self.keys
            .iter()
            .any(|key| &crate::backup::recipient_key_id(key) == key_id)
    }

    /// Returns how many recipients are in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Returns true when nothing is in the set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Returns every recipient, in the order they were added.
    pub fn iter(&self) -> impl Iterator<Item = &StoredEnvelopeKey> {
        self.keys.iter()
    }

    /// Removes one recipient from every future key wrap.
    ///
    /// Returns `None` when the set does not name it. What it does *not* do is take anything back:
    /// see [`still_readable_after_revocation`].
    pub fn revoke(&mut self, key_id: &KeyId) -> Option<Revocation> {
        let position = self
            .keys
            .iter()
            .position(|key| &crate::backup::recipient_key_id(key) == key_id)?;
        self.keys.remove(position);
        Some(Revocation {
            removed: *key_id,
            rotates_object_keys: self.kind == CollectionKind::MutableShared,
        })
    }
}

/// What removing one recipient did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The recipient that is no longer wrapped for.
    pub removed: KeyId,
    /// Whether the next generation re-keys its objects, which a mutable shared collection does.
    pub rotates_object_keys: bool,
}

impl Revocation {
    /// Whether ciphertext staged before the revocation may still be uploaded.
    ///
    /// A rotation says no: that ciphertext is under a key the removed recipient holds a wrap for,
    /// so the object is staged again under a new key rather than resumed. A collection that is not
    /// mutable and shared keeps its staged bytes, because nothing it contains changed.
    #[must_use]
    pub const fn may_reuse_staged_ciphertext(&self) -> bool {
        !self.rotates_object_keys
    }

    /// Always false, and said rather than left to be assumed.
    ///
    /// Section 20: *a removed device may retain earlier keys; do not claim retroactive secrecy.*
    /// Revocation is prospective. A device that already held a wrap holds it still, and a copy of
    /// the ciphertext it already had stays readable to it for ever.
    #[must_use]
    pub const fn claims_retroactive_secrecy(&self) -> bool {
        false
    }

    /// The sentence a person is shown, which says what revocation does and what it does not.
    #[must_use]
    pub fn describe(&self) -> String {
        let rotation = if self.rotates_object_keys {
            " Its keys are rotated, so nothing written after this point is under a key that device holds."
        } else {
            ""
        };
        format!(
            "That device is removed from every future backup key wrap.{rotation} It keeps whatever \
             it already had: earlier backups it holds a key for stay readable to it, and removing \
             it does not make them secret again."
        )
    }
}

/// The generations a removed device can still read.
///
/// Every generation published before the revocation, because it already held their wraps. This is
/// the honest half of [`Revocation`] and it is computed rather than assumed, so a host that shows
/// a person what revocation did shows them this too.
#[must_use]
pub fn still_readable_after_revocation(
    published: &[BackupGeneration],
    revoked_at: BackupGeneration,
) -> Vec<BackupGeneration> {
    let mut readable: Vec<BackupGeneration> = published
        .iter()
        .copied()
        .filter(|generation| generation.get() < revoked_at.get())
        .collect();
    readable.sort_unstable_by_key(|generation| generation.get());
    readable.dedup_by_key(|generation| generation.get());
    readable
}

/// The object keys an owner keeps, held against the retained backup that needs them.
///
/// Section 20 keeps an old object key *only as needed to read retained backups*. A key here
/// therefore belongs to a generation, and no longer retaining that generation's backup is what
/// forgets its keys: [`Self::retain_only`] is the whole policy, so a host cannot keep a key by
/// having no route that removes it.
#[derive(Debug, Default)]
pub struct RetainedObjectKeys {
    generations: BTreeMap<u64, BTreeMap<BackupObjectId, SymmetricKey>>,
}

impl RetainedObjectKeys {
    /// Builds an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps one object key against the generation whose backup needs it.
    pub fn keep(
        &mut self,
        generation: BackupGeneration,
        object_id: BackupObjectId,
        key: SymmetricKey,
    ) {
        self.generations
            .entry(generation.get())
            .or_default()
            .insert(object_id, key);
    }

    /// Returns the key of one object of one generation.
    #[must_use]
    pub fn key(
        &self,
        generation: BackupGeneration,
        object_id: BackupObjectId,
    ) -> Option<&SymmetricKey> {
        self.generations
            .get(&generation.get())
            .and_then(|keys| keys.get(&object_id))
    }

    /// Returns every generation this ledger still holds keys for, oldest first.
    #[must_use]
    pub fn generations(&self) -> Vec<BackupGeneration> {
        self.generations
            .keys()
            .copied()
            .map(BackupGeneration::new)
            .collect()
    }

    /// Returns how many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.generations.values().map(BTreeMap::len).sum()
    }

    /// Returns true when nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every key of one generation. Returns how many were forgotten.
    ///
    /// The keys zeroise as they are dropped, so forgetting is not only losing the index to them.
    pub fn forget(&mut self, generation: BackupGeneration) -> usize {
        self.generations
            .remove(&generation.get())
            .map_or(0, |keys| keys.len())
    }

    /// Forgets every generation `retained` does not name. Returns how many keys were forgotten.
    ///
    /// This is the policy in one call: a host passes the backups it still retains, and every key
    /// kept for a backup it no longer retains goes.
    pub fn retain_only(&mut self, retained: &[BackupGeneration]) -> usize {
        let before = self.len();
        self.generations
            .retain(|generation, _| retained.iter().any(|kept| kept.get() == *generation));
        before - self.len()
    }
}
