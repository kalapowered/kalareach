//! What a backup may carry, what a restore may put back, and what neither ever does.
//!
//! It lives here, beside the producer, because it is the rule that keeps the primitives from being
//! misused rather than a preference any one caller could hold differently. A device decides what to
//! put in an archive and a host decides what to take out of one, and if the two answered the
//! question separately they could answer it differently. They do not: both ask here.

/// A kind of material a backup or a restore may be asked to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Material {
    /// Session content and its history.
    SessionData,
    /// The device's own configuration: its settings, its profiles, its layout.
    DeviceConfiguration,
    /// The latest generation the owner verified for an archive.
    BackupGenerationCheckpoint,
    /// A reusable endpoint private key, which is a device's transport identity.
    EndpointPrivateKey,
    /// A reusable control-signing private key, which is a device's authority.
    ControlSigningPrivateKey,
    /// The notification extension's preview private key.
    NotificationPreviewPrivateKey,
    /// The recovery seed itself.
    RecoverySeed,
    /// A settings collection's key, at any epoch.
    SyncCollectionKey,
    /// One grant.
    Grant {
        /// Whether the grant had been revoked.
        revoked: bool,
    },
    /// The host's own grant and revocation authority.
    HostGrantAuthority,
}

impl Material {
    /// Returns the stable name a report uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionData => "session data",
            Self::DeviceConfiguration => "device configuration",
            Self::BackupGenerationCheckpoint => "a backup generation checkpoint",
            Self::EndpointPrivateKey => "a reusable endpoint private key",
            Self::ControlSigningPrivateKey => "a reusable control-signing private key",
            Self::NotificationPreviewPrivateKey => "the notification preview private key",
            Self::RecoverySeed => "the recovery seed",
            Self::SyncCollectionKey => "a settings collection key",
            Self::Grant { revoked: true } => "a revoked grant",
            Self::Grant { revoked: false } => "a grant",
            Self::HostGrantAuthority => "this host's grant and revocation authority",
        }
    }
}

/// Whether a piece of material may be carried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// It may.
    Allowed,
    /// It may not, for this reason.
    Refused {
        /// Why. It names what would go wrong rather than restating the rule.
        because: &'static str,
    },
}

impl Admission {
    /// Returns true when the material may be carried.
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// Returns the reason a refusal gave, when it was one.
    #[must_use]
    pub const fn because(self) -> Option<&'static str> {
        match self {
            Self::Allowed => None,
            Self::Refused { because } => Some(because),
        }
    }
}

/// Whether a backup may carry this material.
///
/// Section 20: *do not back up reusable endpoint/control private keys*. A backup that carried them
/// would be a backup that recreates a device's authority from a service object, which is exactly
/// what section 24 says a restore must not do.
///
/// A settings collection's key is refused as well. Settings come back through the archive's own
/// wraps, the recovery recipient's among them; the key the collection is sealed under reaches a
/// device only through that device's wrap in a key record, so a restored device reads the
/// collection again only once a member has authorised it.
#[must_use]
pub const fn may_back_up(material: Material) -> Admission {
    match material {
        Material::SessionData
        | Material::DeviceConfiguration
        | Material::BackupGenerationCheckpoint
        | Material::Grant { .. } => Admission::Allowed,
        Material::EndpointPrivateKey => Admission::Refused {
            because: "a reusable endpoint key in a backup is a device identity anybody who \
                      restores the backup can speak as",
        },
        Material::ControlSigningPrivateKey => Admission::Refused {
            because: "a reusable control key in a backup is host authority anybody who restores \
                      the backup can exercise",
        },
        Material::NotificationPreviewPrivateKey => Admission::Refused {
            because: "the notification extension's key belongs to the extension, which receives \
                      none of this material",
        },
        Material::RecoverySeed => Admission::Refused {
            because: "a seed inside the archive it unlocks protects nothing",
        },
        Material::SyncCollectionKey => Admission::Refused {
            because: "a settings collection key in an archive the recovery seed opens would make \
                      the seed a way into the collection, which a device joins only through its own \
                      wrap after the owner authorises it",
        },
        Material::HostGrantAuthority => Admission::Refused {
            because: "grants and revocation state have one host authority, which a restored copy \
                      would silently replace",
        },
    }
}

/// Whether a restore may put this material back.
///
/// Everything a backup refuses to carry, and one more: a grant that had been revoked. Restoring
/// one would hand back access its owner had taken away, from a copy made before they did.
#[must_use]
pub const fn may_restore(material: Material) -> Admission {
    match material {
        Material::Grant { revoked: true } => Admission::Refused {
            because: "that grant was revoked, and a restore that gave it back would undo the \
                      revocation from a copy made before it",
        },
        other => may_back_up(other),
    }
}

/// What a restore still cannot do, whatever it put back.
///
/// Section 20: *recovery restores data and device configuration, then requires fresh
/// owner-authorised host pairing*, and *if all authorised devices and local host access are lost,
/// recovery restores readable data but does not create remote-control authority*.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreLimits;

impl RestoreLimits {
    /// Always true: a restored device holds no pairing and has to be paired again by the owner.
    #[must_use]
    pub const fn requires_fresh_owner_authorised_pairing(self) -> bool {
        true
    }

    /// Always false: a restore returns readable data and no remote-control authority.
    #[must_use]
    pub const fn creates_remote_control_authority(self) -> bool {
        false
    }

    /// The sentence a restore shows once it has finished.
    #[must_use]
    pub fn describe(self) -> String {
        "Your data and this device's configuration are back. This device has no host access yet: \
         pair it with the host again, and confirm the pairing as the owner."
            .to_owned()
    }
}

/// Sorts a set of candidates into what is restored and what is refused, with each reason.
///
/// Every candidate is answered, including the ones that are refused, because a restore that
/// silently dropped a device's control key would look the same as one that never saw it.
#[must_use]
pub fn admit_for_restore(candidates: &[Material]) -> RestoreAdmissions {
    let mut restored = Vec::new();
    let mut refused = Vec::new();
    for material in candidates {
        match may_restore(*material) {
            Admission::Allowed => restored.push(*material),
            Admission::Refused { because } => refused.push((*material, because)),
        }
    }
    RestoreAdmissions {
        restored,
        refused,
        limits: RestoreLimits,
    }
}

/// What a restore put back, what it refused, and what it still cannot do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreAdmissions {
    /// The material that came back.
    pub restored: Vec<Material>,
    /// The material that did not, each with the reason.
    pub refused: Vec<(Material, &'static str)>,
    /// What a restore cannot create, whatever it restored.
    pub limits: RestoreLimits,
}

impl RestoreAdmissions {
    /// Returns true when the restore refused this material.
    #[must_use]
    pub fn refused_kind(&self, material: Material) -> bool {
        self.refused.iter().any(|(kind, _)| *kind == material)
    }
}
