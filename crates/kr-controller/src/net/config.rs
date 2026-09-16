//! What this environment selected for its network, read from the environment it runs in.
//!
//! Section 17 is explicit that nothing is inherited: the relay map, the Pkarr publisher, the Pkarr
//! resolver and the DNS origin are four separate selections, and a service this configuration does
//! not name is a service this host does not use. There are no defaults here for the same reason
//! there are none in the transport: a KalaReach host that quietly fell back on somebody else's
//! relay would be routing a user's terminal through a service they never chose.
//!
//! A daemon that selects nothing serves its local endpoint alone. That is a supported deployment,
//! not a degraded one: a host on the same machine as its clients needs no network at all.
//!
//! | Variable | What it selects |
//! | --- | --- |
//! | `KR_NETWORK` | `1`, `true`, `yes` or `on` puts this daemon on the network |
//! | `KR_NETWORK_BIND` | The socket address the endpoint binds to |
//! | `KR_NETWORK_RELAYS` | The relay map, as comma-separated relay URLs |
//! | `KR_NETWORK_PKARR_PUBLISHER` | The Pkarr server this host publishes its signed record to |
//! | `KR_NETWORK_PKARR_RESOLVER` | The Pkarr server this host resolves peers from |
//! | `KR_NETWORK_DNS_ORIGIN` | The DNS origin this host resolves peers from |
//! | `KR_NETWORK_RELAY_CA` | DER certificate files, comma separated, trusted for a relay's HTTPS |
//! | `KR_NETWORK_LOCAL_DISCOVERY` | `1` selects local network discovery |
//! | `KR_NETWORK_MAINLINE` | `1` selects the public Mainline DHT |

use std::path::PathBuf;

use kr_transport::config::{EndpointConfig, Url};
use kr_transport::preauth::PreAuthLimits;
use kr_transport::scheduler::SendLimits;

use crate::error::{ControllerError, Result};

/// The environment variable that puts a daemon on the network.
pub const ENABLE: &str = "KR_NETWORK";

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
    /// Reads the selection from this process's environment.
    ///
    /// Returns `None` when the environment selects no network. Every other failure is a
    /// configuration error rather than a silent fallback: an operator who named a relay URL that
    /// does not parse gets told so at startup instead of finding out that the host is unreachable.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] naming the variable that could not be read.
    pub fn from_environment() -> Result<Option<Self>> {
        if !flag(ENABLE) {
            return Ok(None);
        }
        let mut settings = Self::default();
        if let Some(bind) = value("KR_NETWORK_BIND") {
            settings.endpoint.bind_addr = Some(
                bind.parse()
                    .map_err(|error| invalid("KR_NETWORK_BIND", &bind, &format!("{error}")))?,
            );
        }
        if let Some(relays) = value("KR_NETWORK_RELAYS") {
            for relay in relays.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                settings.endpoint.relay_urls.push(
                    relay.parse().map_err(|error| {
                        invalid("KR_NETWORK_RELAYS", relay, &format!("{error}"))
                    })?,
                );
            }
        }
        settings.endpoint.discovery.pkarr_publisher_url = url("KR_NETWORK_PKARR_PUBLISHER")?;
        settings.endpoint.discovery.pkarr_resolver_url = url("KR_NETWORK_PKARR_RESOLVER")?;
        settings.endpoint.discovery.dns_origin = value("KR_NETWORK_DNS_ORIGIN");
        settings.endpoint.discovery.local_discovery = flag("KR_NETWORK_LOCAL_DISCOVERY");
        settings.endpoint.discovery.mainline_dht = flag("KR_NETWORK_MAINLINE");
        if let Some(paths) = value("KR_NETWORK_RELAY_CA") {
            settings.endpoint.relay_ca_roots = read_trust_anchors(&paths)?;
        }
        Ok(Some(settings))
    }
}

/// Reads the extra trust anchors a self-hosted relay's certificate is verified against.
///
/// Each path names one DER-encoded certificate. The public anchors stay in force alongside
/// whatever this adds, so pinning a private authority adds trust rather than replacing it, and a
/// deployment whose relay presents a publicly issued certificate names none of these.
fn read_trust_anchors(paths: &str) -> Result<Vec<Vec<u8>>> {
    let mut anchors = Vec::new();
    for path in paths.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let der = std::fs::read(PathBuf::from(path))
            .map_err(|error| invalid("KR_NETWORK_RELAY_CA", path, &format!("{error}")))?;
        if der.is_empty() {
            return Err(invalid("KR_NETWORK_RELAY_CA", path, "the file is empty"));
        }
        anchors.push(der);
    }
    if anchors.is_empty() {
        return Err(invalid(
            "KR_NETWORK_RELAY_CA",
            paths,
            "no certificate path was named",
        ));
    }
    Ok(anchors)
}

fn value(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Ok(_) | Err(_) => None,
    }
}

fn url(name: &str) -> Result<Option<Url>> {
    value(name)
        .map(|value| {
            value
                .parse()
                .map_err(|error| invalid(name, &value, &format!("{error}")))
        })
        .transpose()
}

fn flag(name: &str) -> bool {
    value(name).is_some_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn invalid(name: &str, value: &str, reason: &str) -> ControllerError {
    ControllerError::InvalidArgument(format!("{name}={value} is not usable: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_trust_anchor_is_a_configuration_error_rather_than_no_anchor() {
        let error = read_trust_anchors("/nonexistent/relay-ca.der").expect_err("a refusal");
        assert!(error.to_string().contains("KR_NETWORK_RELAY_CA"));
    }

    #[test]
    fn naming_no_path_is_refused_rather_than_read_as_an_empty_selection() {
        assert!(read_trust_anchors(" , ").is_err());
    }
}
