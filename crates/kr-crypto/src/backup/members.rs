//! What a host archive's members are called, and how much of them a restore accepts.
//!
//! A host archive carries session exports and the host's configuration document, and a name says
//! which. The names are the whole convention: a producer writes them and a restore reads them, so
//! both ask here and cannot disagree. A name this module does not know is refused, so a producer
//! that starts carrying something new cannot have a restore put it back by accident.
//!
//! * `sessions/<uuid>.json` is one session export, the document `kr export` writes. The producer
//!   cuts it at [`MAX_SESSION_MEMBER_BYTES`] and says that it did.
//! * `host/configuration.json` is the host's configuration document.
//! * The reserved prefixes name material no restore puts back ([`may_restore`] refuses all of it,
//!   and [`may_back_up`] all of it but a revoked grant). A restore shows the table's reason for such
//!   a member instead of calling it unknown.
//!
//! [`may_back_up`]: crate::backup::may_back_up
//! [`may_restore`]: crate::backup::may_restore

use crate::backup::Material;

/// The directory of session exports.
pub const SESSION_MEMBER_PREFIX: &str = "sessions/";

/// What every session export's name ends with.
pub const SESSION_MEMBER_SUFFIX: &str = ".json";

/// The name of the host's configuration document.
pub const CONFIGURATION_MEMBER: &str = "host/configuration.json";

/// The most plaintext one session export may hold: 192 MiB.
pub const MAX_SESSION_MEMBER_BYTES: u64 = 192 << 20;

/// The most plaintext the configuration document may hold: 1 MiB.
pub const MAX_CONFIGURATION_MEMBER_BYTES: u64 = 1 << 20;

/// The most plaintext one restore accepts across all its members: 1.5 GiB.
pub const MAX_RESTORED_BYTES: u64 = 3 << 29;

/// The names under which a restore puts nothing back, and the material each would be.
const RESERVED: [(&str, Material); 7] = [
    ("keys/endpoint/", Material::EndpointPrivateKey),
    ("keys/control/", Material::ControlSigningPrivateKey),
    (
        "keys/notification-preview/",
        Material::NotificationPreviewPrivateKey,
    ),
    ("keys/collection/", Material::SyncCollectionKey),
    ("recovery/seed", Material::RecoverySeed),
    ("authority/", Material::HostGrantAuthority),
    ("grants/revoked/", Material::Grant { revoked: true }),
];

/// What kind of material a member of that name is, or nothing for a name this convention does not
/// know.
#[must_use]
pub fn member_material(name: &str) -> Option<Material> {
    if is_a_session_member(name) {
        return Some(Material::SessionData);
    }
    if name == CONFIGURATION_MEMBER {
        return Some(Material::DeviceConfiguration);
    }
    RESERVED
        .iter()
        .find(|(prefix, _)| name.starts_with(prefix))
        .map(|(_, material)| *material)
}

/// The most plaintext a member of this kind may hold, or nothing for a kind no member has.
#[must_use]
pub const fn member_cap(material: Material) -> Option<u64> {
    match material {
        Material::SessionData => Some(MAX_SESSION_MEMBER_BYTES),
        Material::DeviceConfiguration => Some(MAX_CONFIGURATION_MEMBER_BYTES),
        _ => None,
    }
}

/// Whether `name` is `sessions/` and a canonical lowercase identifier and `.json`.
fn is_a_session_member(name: &str) -> bool {
    let Some(identifier) = name
        .strip_prefix(SESSION_MEMBER_PREFIX)
        .and_then(|rest| rest.strip_suffix(SESSION_MEMBER_SUFFIX))
    else {
        return false;
    };
    identifier.len() == 36
        && identifier.char_indices().all(|(at, character)| match at {
            8 | 13 | 18 | 23 => character == '-',
            _ => character.is_ascii_digit() || ('a'..='f').contains(&character),
        })
}
