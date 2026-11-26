//! The hosts this computer is paired with, as the page is shown them.

use kr_client::pairing::paired::PairedHost;
use kr_protocol::grant::GrantExpiry;
use kr_protocol::scalars::EndpointKey;
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

/// What a host is shown by beside its name, so that two hosts with one name stay two: the first
/// eight bytes of a digest of its endpoint, as sixteen hexadecimal characters in four groups of four
/// (`3fa9-1c07-b2e4-77ab`).
///
/// The endpoint is the one the host's pairing record names, so the mark is the same whatever the
/// host is called and whatever its declared device identifier is. A person compares it to the mark
/// another screen shows; nothing uses it to authorise, match or find a host.
#[must_use]
pub fn mark_of(endpoint: &EndpointKey) -> String {
    use sha2::Digest as _;

    let digest =
        sha2::Sha256::digest([b"kalareach host mark".as_slice(), endpoint.as_bytes()].concat());
    digest[..8]
        .chunks(2)
        .map(|pair| {
            pair.iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

/// The name a host is shown by when it gave none this computer could read.
pub const UNNAMED_HOST: &str = "your host";

/// How this computer found its contact with a host it keeps watch on, the last time it looked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Contact {
    /// The host answered.
    In,
    /// The host could not be reached, or did not answer in time.
    Out,
    /// The host was reached, and this computer could not give it the lease its organisation signs
    /// for it, so it was asked nothing: the words say why.
    Refused(String),
}

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
    /// What tells this host from another of the same name: see [`mark_of`].
    pub mark: String,
    /// True when this computer is an owner of the host.
    pub owner: bool,
    /// What this computer may do there, in words.
    pub authority: String,
    /// When this computer's grant on it ends, if it does.
    pub grant_expires_at_ms: Option<u64>,
    /// Whether this computer is in contact with the host now, for a host it keeps a connection
    /// to: the ones it is an owner of, which it watches for confirmations.
    pub in_contact: Option<bool>,
    /// Why this computer could not use the host though it reached it: the words of what stopped
    /// the lease its organisation signs for it. A host that was reached and is refused is in
    /// contact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
}

impl HostRow {
    /// The row for `host`, with its contact as this computer last saw it.
    #[must_use]
    pub fn of(host: &PairedHost, in_use: bool, contact: Option<&Contact>) -> Self {
        Self {
            reference: reference_of(host),
            in_use,
            name: host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned()),
            mark: mark_of(&host.host_endpoint_id),
            owner: host.is_owner(),
            authority: kr_client::pairing::owner::describe_rights(
                &host.proposed_grant.actions,
                &host.proposed_grant.session_selector,
            ),
            grant_expires_at_ms: match host.proposed_grant.expiry {
                GrantExpiry::Never => None,
                GrantExpiry::At { expires_at_ms } => Some(expires_at_ms.get()),
            },
            in_contact: contact.map(|contact| !matches!(contact, Contact::Out)),
            refusal: match contact {
                Some(Contact::Refused(words)) => Some(words.clone()),
                _ => None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-20.12: the mark of an endpoint is a fixed value: the first eight bytes of the digest of
    /// the domain and the endpoint's bytes, in four groups of four lower-case hexadecimal
    /// characters. A different digest or a different cut shows here.
    #[test]
    fn the_mark_of_an_endpoint_is_a_fixed_value_in_four_groups() {
        assert_eq!(
            mark_of(&EndpointKey::from_bytes([0x42; 32])),
            "4885-5ba2-e7cf-e3f2"
        );
        assert_eq!(
            mark_of(&EndpointKey::from_bytes([0x43; 32])),
            "77bc-db3b-2424-b1f2"
        );
        assert_eq!(
            mark_of(&EndpointKey::from_bytes([0x00; 32])),
            "13eb-f438-3891-17ac"
        );
        for seed in 0..=u8::MAX {
            let mark = mark_of(&EndpointKey::from_bytes([seed; 32]));
            let groups: Vec<&str> = mark.split('-').collect();
            assert_eq!(groups.len(), 4, "{mark}");
            for group in groups {
                assert_eq!(group.len(), 4, "{mark}");
                assert!(
                    group
                        .chars()
                        .all(|each| each.is_ascii_digit() || ('a'..='f').contains(&each)),
                    "{mark}"
                );
            }
        }
    }

    /// KR-REQ-20.12: two endpoints that differ in one byte have two marks, and the same endpoint
    /// has the same mark each time.
    #[test]
    fn endpoints_that_differ_in_one_byte_have_two_marks() {
        let mut other = [0x42; 32];
        other[31] = 0x43;
        assert_ne!(
            mark_of(&EndpointKey::from_bytes([0x42; 32])),
            mark_of(&EndpointKey::from_bytes(other))
        );
        assert_eq!(
            mark_of(&EndpointKey::from_bytes(other)),
            mark_of(&EndpointKey::from_bytes(other))
        );
    }
}
