//! The hosts this computer is paired with, as the page is shown them.

use kr_client::pairing::paired::PairedHost;
use kr_protocol::grant::GrantExpiry;
use serde::Serialize;

/// The name a host is shown by when it gave none this computer could read.
pub const UNNAMED_HOST: &str = "your host";

/// One paired host, as the page lists it. It holds no key, no identifier and nothing the page
/// could build a request from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostRow {
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
    pub fn of(host: &PairedHost, in_contact: Option<bool>) -> Self {
        Self {
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
