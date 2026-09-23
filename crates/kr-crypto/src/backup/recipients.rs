//! Who an archive is wrapped for, what revoking one of them does, and which old keys are kept.

use std::collections::BTreeMap;

use kr_protocol::ids::{BackupGeneration, BackupObjectId};
use kr_protocol::scalars::{KeyId, StoredEnvelopeKey};

use crate::error::{CryptoError, Result};
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

/// Which key generation a collection's staged ciphertext belongs to.
///
/// It advances when a revocation rotates the keys of a mutable shared collection. A
/// [`crate::backup::StagedObject`] carries the rotation it was staged under, and
/// [`crate::backup::seal_archive`] refuses one from before the recipient set's current rotation.
/// That is what makes rotation a rule rather than a report: a caller cannot revoke a recipient and
/// then seal the ciphertext that revocation invalidated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyRotation(u64);

impl KeyRotation {
    /// The rotation a collection starts at.
    pub const INITIAL: Self = Self(0);

    /// Returns the recorded value, so a producer can keep it beside its staged ciphertext.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Builds a rotation from a recorded value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the rotation after this one, or nothing after the last.
    ///
    /// A rotation that stood still would be no rotation: the recipients a revocation removes would
    /// hold a wrap of the key the next generation is sealed under. So the last rotation has no
    /// successor, and a revocation that needs one is refused.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
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
    rotation: KeyRotation,
}

impl ArchiveRecipients {
    /// Builds an empty set for one kind of collection.
    #[must_use]
    pub const fn new(kind: CollectionKind) -> Self {
        Self {
            kind,
            keys: Vec::new(),
            rotation: KeyRotation::INITIAL,
        }
    }

    /// Builds a set a device read back from its own store, at the rotation it recorded.
    #[must_use]
    pub const fn restored(kind: CollectionKind, rotation: KeyRotation) -> Self {
        Self {
            kind,
            keys: Vec::new(),
            rotation,
        }
    }

    /// Returns the key rotation staged ciphertext must have been made under.
    #[must_use]
    pub const fn rotation(&self) -> KeyRotation {
        self.rotation
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

    /// Removes recipients from every future key wrap, in one step.
    ///
    /// Returns `None` when the set names none of them. A mutable shared collection advances its
    /// rotation once for the whole step, however many recipients leave in it: one new key replaces
    /// the one they all held. What it does *not* do is take anything back: see
    /// [`still_readable_after_revocation`].
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::RotationExhausted`] when a mutable shared collection is at its last
    /// rotation. The set is then left as it was: removing recipients without rotating would leave
    /// them a wrap of the next generation's key.
    pub fn revoke(&mut self, key_ids: &[KeyId]) -> Result<Option<Revocation>> {
        let mut removed: Vec<KeyId> = Vec::new();
        for key in &self.keys {
            let id = crate::backup::recipient_key_id(key);
            if key_ids.contains(&id) && !removed.contains(&id) {
                removed.push(id);
            }
        }
        if removed.is_empty() {
            return Ok(None);
        }
        let rotates_object_keys = self.kind == CollectionKind::MutableShared;
        // Advancing the rotation is the rotation. Every object staged before it is refused by
        // `seal_archive` and staged again under a new key when it is resumed, so the removed
        // recipients' wraps open nothing written after this point.
        let rotation = if rotates_object_keys {
            self.rotation.next().ok_or(CryptoError::RotationExhausted)?
        } else {
            self.rotation
        };
        self.keys
            .retain(|key| !removed.contains(&crate::backup::recipient_key_id(key)));
        self.rotation = rotation;
        Ok(Some(Revocation {
            removed,
            rotates_object_keys,
            rotation,
        }))
    }
}

/// What removing recipients did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revocation {
    /// The recipients that are no longer wrapped for, in the order they were in the set.
    pub removed: Vec<KeyId>,
    /// Whether the next generation re-keys its objects, which a mutable shared collection does.
    pub rotates_object_keys: bool,
    /// The rotation the collection is at now. Staged ciphertext from before it is refused.
    pub rotation: KeyRotation,
}

impl Revocation {
    /// Whether ciphertext staged before the revocation may still be uploaded.
    ///
    /// A rotation says no: that ciphertext is under a key the removed recipient holds a wrap for,
    /// so the object is staged again under a new key rather than resumed. A collection that is not
    /// mutable and shared keeps its staged bytes, because nothing it contains changed.
    ///
    /// It is a report of a rule that is already enforced, not the rule itself.
    /// [`crate::backup::seal_archive`] refuses an object from before
    /// [`ArchiveRecipients::rotation`] whatever a caller does with this answer.
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
        if self.removed.len() == 1 {
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
        } else {
            let rotation = if self.rotates_object_keys {
                " The keys are rotated, so nothing written after this point is under a key those devices hold."
            } else {
                ""
            };
            format!(
                "Those devices are removed from every future backup key wrap.{rotation} They keep \
                 whatever they already had: earlier backups they hold a key for stay readable to them, \
                 and removing them does not make those backups secret again."
            )
        }
    }

    /// The sentence a person is shown when devices leave a synchronised collection.
    ///
    /// A synchronised collection is mutable and shared, so removing a device always gives the
    /// remaining ones a new key. What the removed device already read stays readable to it, and
    /// the sentence says so rather than claiming a secrecy nothing can restore.
    #[must_use]
    pub fn describe_settings_sync(&self) -> String {
        if self.removed.len() == 1 {
            "That device no longer receives settings. Settings written from now on are sealed under \
             a new key it does not hold. What it already had stays readable to it: removing a device \
             does not make that secret again."
                .to_owned()
        } else {
            "Those devices no longer receive settings. Settings written from now on are sealed under \
             a new key they do not hold. What they already had stays readable to them: removing a \
             device does not make that secret again."
                .to_owned()
        }
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
