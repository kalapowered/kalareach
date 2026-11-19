//! The methods that keep, and clear, the login this host's proxy asks for.
//!
//! The login is held in the host's secret store, under one item, for the proxy the configuration
//! document names. Only the daemon writes the store, so the command line sends the login to the
//! daemon over its local socket. No answer carries the login, and no method reads it back: a
//! change applies when the daemon starts again.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::delivery::SecretText;

/// Parameters of `network.proxy_login.set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkProxyLoginSetParams {
    /// The proxy the login is for, as an origin: a scheme, a host and a port, with no user name,
    /// no password and nothing after them. The host uses the login only while the document names
    /// this proxy.
    pub proxy: String,
    /// The login, as a user name, a colon and a password. It splits at the first colon.
    pub login: SecretText,
}

/// Parameters of `network.proxy_login.clear`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkProxyLoginClearParams {}

/// The result of `network.proxy_login.set` and `network.proxy_login.clear`. It carries no login.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkProxyLoginResult {
    /// Whether the change applies when the daemon starts again, which it always does: a daemon
    /// that is running keeps the login it started with.
    pub applies_at_next_start: bool,
}
