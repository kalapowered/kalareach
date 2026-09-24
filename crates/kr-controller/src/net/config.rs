//! What this host selected for its network, read from its configuration document.
//!
//! Section 17 is explicit that nothing is inherited: the relay map, the Pkarr publisher, the Pkarr
//! resolver and the DNS origin are four separate selections, and a service this configuration does
//! not name is a service this host does not use. There are no defaults here for the same reason
//! there are none in the transport: a KalaReach host that quietly fell back on somebody else's
//! relay would be routing a user's terminal through a service they never chose.
//!
//! Every selection is the `network` section of this host's configuration document
//! ([`NetworkSelection`]), which is validated with the rest of the document and reported by
//! `kr doctor` with its source. The daemon reads it once, when it starts, because that is when its
//! endpoint is built. No environment variable reaches any of it: section 26 keeps provider origins
//! and trust decisions out of reach of whatever a process happened to inherit.
//!
//! A daemon that selects nothing serves its local endpoint alone. That is a supported deployment,
//! not a degraded one: a host on the same machine as its clients needs no network at all.

use kr_protocol::hostinfo::configuration::{
    self, NETWORK_BIND_ADDRESS, NETWORK_PKARR_PUBLISHER_URL, NETWORK_PKARR_RESOLVER_URL,
    NETWORK_RELAY_TRUST_ANCHORS, NETWORK_RELAY_URLS, NetworkSelection,
};
use kr_transport::config::{EndpointConfig, Url};
use kr_transport::preauth::PreAuthLimits;
use kr_transport::scheduler::SendLimits;

use crate::error::{ControllerError, Result};

/// Everything this daemon's endpoint is built from.
#[derive(Clone, Debug, Default)]
pub struct NetworkSettings {
    /// The selected network services.
    pub endpoint: EndpointConfig,
    /// What one connection may hand the endpoint at once.
    pub send_limits: SendLimits,
    /// What an unpaired connection may do.
    pub preauth_limits: PreAuthLimits,
}

impl NetworkSettings {
    /// Builds the endpoint a configuration document's network section selects.
    ///
    /// Returns `None` when the section does not put this host on the network. Every other failure
    /// is a configuration error rather than a silent fallback: an owner who named a relay that
    /// cannot be used, or a certificate file that is not there, is told so when the daemon starts
    /// instead of finding out that the host is unreachable.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] naming the key whose value could not be used.
    pub fn from_selection(selection: &NetworkSelection) -> Result<Option<Self>> {
        if !selection.joins() {
            return Ok(None);
        }
        let mut settings = Self::default();
        if let Some(bind) = selection.bind_address() {
            settings.endpoint.bind_addr = Some(
                bind.parse()
                    .map_err(|error| invalid(NETWORK_BIND_ADDRESS.key, None, &error))?,
            );
        }
        for (index, relay) in selection.relay_urls().iter().enumerate() {
            settings.endpoint.relay_urls.push(
                relay
                    .parse()
                    .map_err(|error| invalid(NETWORK_RELAY_URLS.key, Some(index), &error))?,
            );
        }
        settings.endpoint.discovery.pkarr_publisher_url = url(
            selection.pkarr_publisher_url(),
            NETWORK_PKARR_PUBLISHER_URL.key,
        )?;
        settings.endpoint.discovery.pkarr_resolver_url = url(
            selection.pkarr_resolver_url(),
            NETWORK_PKARR_RESOLVER_URL.key,
        )?;
        settings.endpoint.discovery.dns_origin = selection.dns_origin().map(str::to_owned);
        settings.endpoint.relay_only = selection.relay_only();
        settings.endpoint.discovery.local_discovery = selection.local_discovery();
        settings.endpoint.discovery.mainline_dht = selection.mainline_dht();
        settings.endpoint.relay_ca_roots = read_trust_anchors(selection.relay_trust_anchors())?;
        Ok(Some(settings))
    }
}

/// Reads the extra trust anchors a self-hosted relay's certificate is verified against.
///
/// Each path names one DER-encoded certificate. The public anchors stay in force alongside
/// whatever this adds, so pinning a private authority adds trust rather than replacing it, and a
/// deployment whose relay presents a publicly issued certificate names none of these. A file that
/// cannot be read, or that is empty, is a configuration error rather than an anchor quietly left
/// out: a relay the owner pinned and this host then failed to trust would look like a relay that
/// is down.
fn read_trust_anchors(paths: &[String]) -> Result<Vec<Vec<u8>>> {
    let mut anchors = Vec::with_capacity(paths.len());
    for (index, path) in paths.iter().enumerate() {
        let der = std::fs::read(path)
            .map_err(|error| invalid(NETWORK_RELAY_TRUST_ANCHORS.key, Some(index), &error))?;
        if der.is_empty() {
            return Err(invalid(
                NETWORK_RELAY_TRUST_ANCHORS.key,
                Some(index),
                &"the file is empty",
            ));
        }
        anchors.push(der);
    }
    Ok(anchors)
}

fn url(value: Option<&str>, key: &str) -> Result<Option<Url>> {
    value
        .map(|value| value.parse().map_err(|error| invalid(key, None, &error)))
        .transpose()
}

/// The error a selection that cannot be used is reported with.
///
/// It names the key and, for a list, which entry. The value itself is the owner's own and may be
/// an address with a credential in it, so the reason is the parser's or the operating system's
/// sentence about it rather than a copy of it.
fn invalid(key: &str, index: Option<usize>, reason: &dyn std::fmt::Display) -> ControllerError {
    let what = match index {
        Some(index) => format!("{key} entry {}", index + 1),
        None => key.to_owned(),
    };
    ControllerError::InvalidArgument(format!(
        "{what} in this host's configuration document ({}) is not usable: {reason}",
        configuration::FILE_NAME
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Nullable;

    fn joined(selection: NetworkSelection) -> NetworkSelection {
        NetworkSelection {
            enabled: Nullable::some(true),
            ..selection
        }
    }

    #[test]
    fn a_missing_trust_anchor_is_a_configuration_error_rather_than_no_anchor() {
        let error = NetworkSettings::from_selection(&joined(NetworkSelection {
            relay_trust_anchors: Nullable::some(vec!["/nonexistent/relay-ca.der".to_owned()]),
            ..NetworkSelection::default()
        }))
        .expect_err("a refusal");
        assert!(
            error
                .to_string()
                .contains("network.relay_trust_anchors entry 1"),
            "{error}"
        );
    }

    #[test]
    fn a_section_that_does_not_join_selects_nothing_whatever_else_it_names() {
        let selection = NetworkSelection {
            relay_urls: Nullable::some(vec!["https://relay.example.com".to_owned()]),
            relay_trust_anchors: Nullable::some(vec!["/nonexistent/relay-ca.der".to_owned()]),
            ..NetworkSelection::default()
        };
        assert!(
            NetworkSettings::from_selection(&selection)
                .expect("nothing is read")
                .is_none()
        );
    }

    /// KR-REQ-26.14: a document that validates never stops the daemon over an address's syntax.
    ///
    /// Every address the configuration schema accepts is one the endpoint's own parser accepts,
    /// and one an invitation can carry once that parser has written it. The addresses the schema
    /// refuses are here too, so a rule loosened on one side and not the other fails this.
    #[test]
    fn every_address_the_document_accepts_is_one_the_endpoint_accepts() {
        use kr_protocol::hostinfo::configuration::ConfigurationDocument;

        // 252 bytes as written in the document, and 253 once the parser adds the path's `/`.
        let longest = format!(
            "https://{}.example",
            [
                "a".repeat(60),
                "a".repeat(60),
                "a".repeat(60),
                "a".repeat(53)
            ]
            .join(".")
        );
        assert_eq!(longest.len(), 252);
        let corpus = [
            "https://relay.example.com",
            "https://relay.example.com/",
            "https://relay.example.com:8443/relay/v1",
            "http://127.0.0.1:8080/pkarr",
            "http://[::1]:8080",
            "https://[2001:db8::1]",
            "https://a1.be",
            "https://relay.example.com/a-b_c.d~e",
            longest.as_str(),
            "https://resolver.example:99999",
            "https://resolver.example:0443",
            "http://127.1",
            "http://[0:0:0:0:0:0:0:1]",
            "https://xn--zz.example",
            "https://resolver.example/a/../b",
            "https://resolver.example/%70",
            "https://Relay.example.com",
        ];
        let mut accepted = 0;
        for address in corpus {
            let mut document = ConfigurationDocument::empty();
            document.network = joined(NetworkSelection {
                relay_urls: Nullable::some(vec![address.to_owned()]),
                pkarr_publisher_url: Nullable::some(address.to_owned()),
                pkarr_resolver_url: Nullable::some(address.to_owned()),
                ..NetworkSelection::default()
            });
            if configuration::validate(&document).is_err() {
                continue;
            }
            accepted += 1;
            let settings = NetworkSettings::from_selection(&document.network)
                .unwrap_or_else(|error| {
                    panic!("{address} validated and the endpoint refused it: {error}")
                })
                .expect("this host joins");
            settings
                .endpoint
                .to_network_config()
                .unwrap_or_else(|error| panic!("{address} does not fit an invitation: {error}"));
        }
        assert_eq!(
            accepted, 9,
            "the first nine addresses are the ones the schema accepts"
        );
    }

    #[test]
    fn every_selection_reaches_the_endpoint_it_builds() {
        let settings = NetworkSettings::from_selection(&joined(NetworkSelection {
            bind_address: Nullable::some("127.0.0.1:0".to_owned()),
            relay_urls: Nullable::some(vec!["https://relay.example.com".to_owned()]),
            pkarr_publisher_url: Nullable::some("https://discovery.example.com/pkarr".to_owned()),
            pkarr_resolver_url: Nullable::some("https://discovery.example.com/pkarr".to_owned()),
            dns_origin: Nullable::some("discovery.example.com".to_owned()),
            relay_only: Nullable::some(true),
            local_discovery: Nullable::some(true),
            mainline_dht: Nullable::some(true),
            ..NetworkSelection::default()
        }))
        .expect("a usable selection")
        .expect("this host joins");
        let endpoint = &settings.endpoint;
        assert_eq!(
            endpoint.bind_addr,
            Some("127.0.0.1:0".parse().expect("an address"))
        );
        assert_eq!(endpoint.relay_urls.len(), 1);
        assert!(endpoint.discovery.pkarr_publisher_url.is_some());
        assert!(endpoint.discovery.pkarr_resolver_url.is_some());
        assert_eq!(
            endpoint.discovery.dns_origin.as_deref(),
            Some("discovery.example.com")
        );
        assert!(endpoint.relay_only);
        assert!(endpoint.discovery.local_discovery);
        assert!(endpoint.discovery.mainline_dht);
        assert!(endpoint.relay_ca_roots.is_empty());
    }
}
