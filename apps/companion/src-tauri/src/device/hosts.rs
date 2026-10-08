//! The hosts this computer is paired with, as the page is shown them.

use kr_client::pairing::paired::PairedHost;
use kr_protocol::grant::GrantExpiry;
use serde::Serialize;

/// What a host is named by to the page: a digest of its identity, truncated.
///
/// A host's identity is not a secret, but nothing the page sends should be able to name a host this
/// application did not list, and a digest the page cannot compute without the identity is that.
#[must_use]
pub fn reference_of(host: &PairedHost) -> String {
    use sha2::Digest as _;

    let digest = sha2::Sha256::digest(
        [
            b"kalareach host reference".as_slice(),
            host.host_device_id.to_string().as_bytes(),
        ]
        .concat(),
    );
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The name a host is shown by when it gave none this computer could read.
pub const UNNAMED_HOST: &str = "your host";

/// One paired host, as the page lists it. It holds no key, no identifier and nothing the page
/// could build a request from: the reference below names the host to this application and to no
/// one else.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostRow {
    /// What the page names this host by when it asks to use it. It is made from the host's
    /// identity, so it is the same each time, and it says nothing of that identity.
    pub reference: String,
    /// True when this application's commands go to this host now.
    pub in_use: bool,
    /// The name the host gives people.
    pub name: String,
    /// True when this computer is an owner of the host.
    pub owner: bool,
    /// What this computer may do there, in words.
    pub authority: String,
    /// When this computer's grant on it ends, if it does.
    pub grant_expires_at_ms: Option<u64>,
    /// Whether this computer is in contact with the host now, for a host it keeps a connection
    /// to: the ones it is an owner of, which it watches for confirmations.
    pub in_contact: Option<bool>,
}

impl HostRow {
    /// The row for `host`, with its contact as this computer last saw it.
    #[must_use]
    pub fn of(host: &PairedHost, in_use: bool, in_contact: Option<bool>) -> Self {
        Self {
            reference: reference_of(host),
            in_use,
            name: host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned()),
            owner: host.is_owner(),
            authority: kr_client::pairing::owner::describe_rights(&host.proposed_grant.actions),
            grant_expires_at_ms: match host.proposed_grant.expiry {
                GrantExpiry::Never => None,
                GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
            },
            in_contact,
        }
    }
}
