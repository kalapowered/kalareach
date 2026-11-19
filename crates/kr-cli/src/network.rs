//! `kr host network`: a host joins the service it uses, or leaves it, as one validated edit of its
//! configuration document.
//!
//! A host joins no network until its document says so (`docs/host/README.md`, "The network and the
//! voice broker"), and writing the relay map, the discovery servers and the service origins by hand
//! is what this command replaces. It asks a service for its own description of itself
//! ([`kr_client::services::description`]), checks it, and writes the eight settings a join owns
//! ([`ServiceSelection::KEYS`]) through the document's own writer, the one every other edit uses.
//! Nothing is compiled into the release but the origin of the managed service, which the product
//! pins already, and the daemon reads only the document, as it always did.
//!
//! The order of a join matters. The document is loaded first, and a document this build must not
//! rewrite, or cannot read, ends the command before any request is made, since the proxy the
//! request goes through is the document's to name and a document that cannot be read names none.
//! The request is made with nothing held. The writers' lock and the document's baseline are taken
//! only to write, and a document that moved while the service was asked is not written over.
//!
//! A join never overwrites a value the document already holds with another one. It names the
//! settings that differ, shows both values, and writes them only when the person says `--replace`.

use kr_client::services::description::{self, Description, Ignored, Trust, Unread};
use kr_client::services::matrix::Pins;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::delivery::SecretText;
use kr_protocol::hostinfo::configuration::{
    self, Change, ConfigurationDocument, Loaded, ServiceSelection,
};
use kr_protocol::hostinfo::export::ContentClass;
use kr_protocol::method::Method;
use kr_protocol::network_proxy::{
    NetworkProxyLoginClearParams, NetworkProxyLoginResult, NetworkProxyLoginSetParams,
};
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use kr_transport::proxy::{ProxyCredential, ProxyLoginKind};

use crate::cli::{EnvironmentSelector, NetworkArguments};
use crate::daemon::Daemon;
use crate::doctor::configuration::{WRITTEN, apply_over, document_path, load, refusal, validate};
use crate::error::{CliError, Result};
use crate::output::{self, Asked, Document, Request};
use crate::resolve::{self, KnownEnvironment};
use crate::stdout_line;

/// What a command did.
enum Action {
    /// It showed what the document selects.
    Showed,
    /// It joined a service. `revision` is the revision it wrote, or none when the document already
    /// held what the service described.
    Joined {
        revision: Option<u64>,
        description: Box<Description>,
    },
    /// It took the selection out. `revision` is none when the document held none.
    Cleared { revision: Option<u64> },
    /// It gave the control daemon a proxy login to keep.
    LoginStored,
    /// It had the control daemon remove the proxy login it kept.
    LoginCleared,
}

/// Runs `kr host network`.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a request the arguments or the document refuse and for a
/// description that is not accepted, each with nothing written, and [`CliError::Other`] when the
/// service cannot be had.
pub async fn run(paths: &HostPaths, arguments: &NetworkArguments, json: bool) -> Result<()> {
    let environment = resolve::select(paths, None)?;
    let loaded = load(&environment.paths);
    let action = if arguments.clear {
        clear(&environment.paths, &loaded)?
    } else if arguments.proxy_login {
        store_login(paths, arguments, &loaded, json).await?
    } else if arguments.proxy_logout {
        clear_login(paths).await?
    } else if arguments.join {
        join(&environment.paths, arguments, loaded, json).await?
    } else {
        show_needs_a_usable_document(&loaded)?;
        Action::Showed
    };
    present(&environment, &action, json);
    Ok(())
}

/// A document this build cannot read has nothing to show, and the command says why.
fn show_needs_a_usable_document(loaded: &Loaded) -> Result<()> {
    if loaded.document.is_none() && loaded.status.state.is_a_problem() {
        return Err(CliError::Usage(shown!(
            "this host's configuration document cannot be used: {}",
            Shown::sentence(&loaded.status.detail)
        )));
    }
    Ok(())
}

/// Takes the eight settings out.
fn clear(paths: &EnvironmentPaths, loaded: &Loaded) -> Result<Action> {
    configuration::editable(loaded).map_err(|refused| refusal(&refused))?;
    let held = loaded
        .document
        .as_ref()
        .is_some_and(ServiceSelection::held_by);
    if !held {
        return Ok(Action::Cleared { revision: None });
    }
    let change = Change::Network(None);
    validate(paths, &change)?;
    let writers = crate::barrier::hold_for_configuration(paths)?;
    let permit = crate::barrier::permit(&writers, &WRITTEN)?;
    let revision = apply_over(paths, &change, &permit, Some(loaded))?;
    Ok(Action::Cleared {
        revision: Some(revision),
    })
}

/// Reads the service's description and writes what it describes.
async fn join(
    paths: &EnvironmentPaths,
    arguments: &NetworkArguments,
    loaded: Loaded,
    json: bool,
) -> Result<Action> {
    // Before any request: a document that cannot be edited ends the command here.
    configuration::editable(&loaded).map_err(|refused| refusal(&refused))?;

    let origin = GatewayOrigin::new(
        arguments
            .service
            .as_deref()
            .unwrap_or(kr_client::services::account::ACCOUNT_ORIGIN),
    )
    .map_err(|_| {
        CliError::Usage(Shown::said(
            "--service takes the service's origin: an https address with no path, or an http \
             address on this machine",
        ))
    })?;
    let trust = trust(&origin, arguments)?;

    // The proxy is the document's to name, and only a document that can be used names one. A login
    // from the file goes to this one request and is kept nowhere.
    let proxy = proxy_of(&loaded, arguments.proxy_credential_file.as_deref(), json)?;
    let http = description::connect(&origin, proxy.as_ref()).map_err(unread)?;
    let body = match description::fetch(&http, &origin).await {
        Ok(body) => body,
        // A proxy that answers `HTTP/1.0 407` reads as a failed tunnel; one request through it
        // says which login failed.
        Err(Unread::Unreachable) => {
            return Err(unread(
                description::recheck(proxy.as_ref())
                    .await
                    .unwrap_or(Unread::Unreachable),
            ));
        }
        Err(why) => return Err(unread(why)),
    };
    let described = description::read(&body, &origin, &trust)
        .map_err(|refusal| CliError::Usage(Shown::said(refusal.sentence())))?;

    let empty = ConfigurationDocument::empty();
    let document = loaded.document.as_ref().unwrap_or(&empty);
    let comparison = described.selection().compare(document);
    let change = Change::Network(Some(described.selection().clone()));
    if !comparison.different.is_empty() {
        // A value the document would refuse is refused as that, before any value is shown or
        // `--replace` is suggested for an edit that would fail.
        validate(paths, &change)?;
        if !arguments.replace {
            if !json {
                show_differences(document, described.selection(), &comparison.different);
            }
            return Err(CliError::Usage(shown!(
                "this host's configuration already selects other values for {}; kr host network \
                 shows them, and --replace takes the service's instead",
                keys(&comparison.different)
            )));
        }
    }
    if comparison.is_current() {
        return Ok(Action::Joined {
            revision: None,
            description: Box::new(described),
        });
    }

    validate(paths, &change)?;
    let writers = crate::barrier::hold_for_configuration(paths)?;
    let permit = crate::barrier::permit(&writers, &WRITTEN)?;
    let revision = apply_over(paths, &change, &permit, Some(&loaded))?;
    Ok(Action::Joined {
        revision: Some(revision),
        description: Box::new(described),
    })
}

/// The proxy the document names, with the login the file holds when one is given.
///
/// A login sent to a proxy whose address is `http` goes in clear, which is said before anything is
/// sent.
fn proxy_of(
    loaded: &Loaded,
    credential_file: Option<&std::path::Path>,
    json: bool,
) -> Result<Option<ProxyUrl>> {
    let proxy = loaded
        .document
        .as_ref()
        .and_then(|document| document.network.proxy_url())
        .map(|text| text.parse::<ProxyUrl>())
        .transpose()
        .map_err(|_| unread(Unread::NoTransport))?;
    let Some(file) = credential_file else {
        return Ok(proxy);
    };
    let Some(proxy) = proxy else {
        return Err(CliError::Usage(Shown::said(
            "name the proxy in network.proxy_url first",
        )));
    };
    let (login, _) = login_of(file)?;
    if !json && proxy.as_url().scheme() == "http" {
        output::say(&Shown::said(
            "the login is sent in clear to the proxy, because the proxy's address is an http one",
        ));
    }
    Ok(Some(proxy.with_login(login)))
}

/// Reads a login from its file: the credential the transport holds, and the line the daemon is
/// given. Nothing the file held is printed or kept.
fn login_of(file: &std::path::Path) -> Result<(ProxyCredential, SecretText)> {
    let bytes = crate::destination::read_credential(file)?;
    let refused = || {
        CliError::Usage(shown!(
            "{}: the file must hold one line of a user name, a colon and a password, where the user \
             name is not empty and neither part has a control character or more than 255 bytes",
            crate::shown::named(file)
        ))
    };
    let credential = ProxyCredential::parse_line(&bytes).map_err(|_| refused())?;
    let line = std::str::from_utf8(bytes.expose()).map_err(|_| refused())?;
    let line = line
        .strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line);
    Ok((credential, SecretText::new(line).map_err(|_| refused())?))
}

/// Gives the control daemon the login in the file, for the proxy the document names.
async fn store_login(
    paths: &HostPaths,
    arguments: &NetworkArguments,
    loaded: &Loaded,
    json: bool,
) -> Result<Action> {
    let Some(file) = arguments.proxy_credential_file.as_deref() else {
        return Err(CliError::Usage(Shown::said(
            "--proxy-login takes the login in --proxy-credential-file",
        )));
    };
    // Read before the daemon is reached: a mistake in the file or the document is the person's to
    // fix, and nothing has been sent anywhere.
    let proxy = proxy_of(loaded, None, json)?
        .ok_or_else(|| CliError::Usage(Shown::said("name the proxy in network.proxy_url first")))?;
    let (_, line) = login_of(file)?;
    if !json && proxy.as_url().scheme() == "http" {
        output::say(&Shown::said(
            "the login is sent in clear to the proxy, because the proxy's address is an http one",
        ));
    }
    let mut daemon = Daemon::open(paths, &EnvironmentSelector { environment: None }).await?;
    let _: NetworkProxyLoginResult = daemon
        .mutate(
            Method::NetworkProxyLoginSet,
            &NetworkProxyLoginSetParams {
                proxy: proxy.to_string(),
                login: line,
            },
        )
        .await?;
    Ok(Action::LoginStored)
}

/// Has the control daemon remove the proxy login it keeps.
async fn clear_login(paths: &HostPaths) -> Result<Action> {
    let mut daemon = Daemon::open(paths, &EnvironmentSelector { environment: None }).await?;
    let _: NetworkProxyLoginResult = daemon
        .mutate(
            Method::NetworkProxyLoginClear,
            &NetworkProxyLoginClearParams::default(),
        )
        .await?;
    Ok(Action::LoginCleared)
}

/// What vouches for the description of the service at `origin`.
fn trust(origin: &GatewayOrigin, arguments: &NetworkArguments) -> Result<Trust> {
    if description::is_managed(origin) {
        if arguments.key.is_some() || arguments.unsigned {
            return Err(CliError::Usage(Shown::said(
                "the KalaReach service is verified under the key this build pins; --key and \
                 --unsigned are for a service you run",
            )));
        }
        return Ok(Trust::Pinned(Pins::production()));
    }
    match (arguments.key.as_deref(), arguments.unsigned) {
        (Some(key), false) => Pins::from_key_text(key).map(Trust::Pinned).ok_or_else(|| {
            CliError::Usage(Shown::said(
                "--key takes the public key the service signs its description with: 43 \
                 characters of unpadded base64url",
            ))
        }),
        (None, true) => Ok(Trust::TlsOnly),
        _ => Err(CliError::Usage(Shown::said(
            "a service you run is joined with --key <its public key>, which its description is \
             verified under, or with --unsigned, which takes its description on the connection \
             alone",
        ))),
    }
}

/// Why the description was not had, in words that carry nothing the service said.
fn unread(why: Unread) -> CliError {
    match why {
        Unread::Refused(status) => CliError::Other(shown!(
            "{} (status {})",
            Shown::said(why.sentence()),
            status
        )),
        // What this host's own document and arguments rule out is a refusal, not a service that
        // did not answer.
        Unread::NoTransport | Unread::ClearTextViaProxy => {
            CliError::Usage(Shown::said(why.sentence()))
        }
        // The login in the file is the one this command sent, so a refusal is of that file's.
        Unread::ProxyLogin(ProxyLoginKind::Needed) => CliError::Usage(Shown::said(
            "the proxy requires a sign-in: give a login with --proxy-credential-file <file>",
        )),
        Unread::ProxyLogin(ProxyLoginKind::Refused) => {
            CliError::Usage(Shown::said("the proxy refused the login in the file"))
        }
        why => CliError::Other(Shown::said(why.sentence())),
    }
}

/// The keys of the settings, as a person reads them.
fn keys(keys: &[&'static str]) -> Shown {
    Shown::joined(keys.iter().map(|key| Shown::said(key)), ", ")
}

/// What the document selects, text for each of the eight settings in [`ServiceSelection::KEYS`]
/// order: none when it selects nothing there.
fn held(document: &ConfigurationDocument) -> [Option<String>; 8] {
    let network = &document.network;
    let one = |value: Option<&str>| value.map(str::to_owned);
    let relays = network.relay_urls();
    [
        network.enabled.0.map(|on| on.to_string()),
        (!relays.is_empty()).then(|| relays.join(", ")),
        one(network.pkarr_publisher_url()),
        one(network.pkarr_resolver_url()),
        one(network.dns_origin()),
        one(document.authority.origin()),
        one(document.mailbox.origin()),
        one(document.relay.origin()),
    ]
}

/// What a description selects, in the same order.
fn described(selection: &ServiceSelection) -> [Option<String>; 8] {
    [
        Some("true".to_owned()),
        (!selection.relay_urls.is_empty()).then(|| selection.relay_urls.join(", ")),
        selection.pkarr_publisher_url.clone(),
        selection.pkarr_resolver_url.clone(),
        selection.dns_origin.clone(),
        selection.authority_origin.clone(),
        selection.mailbox_origin.clone(),
        selection.relay_origin.clone(),
    ]
}

/// Shows, for each setting that differs, what the document selects and what the service describes.
fn show_differences(
    document: &ConfigurationDocument,
    selection: &ServiceSelection,
    different: &[&'static str],
) {
    let (held, described) = (held(document), described(selection));
    for (index, key) in ServiceSelection::KEYS.iter().enumerate() {
        if !different.contains(key) {
            continue;
        }
        output::line(&stdout_line!(
            "{}: this host selects {}; the service describes {}",
            *key,
            setting(index, &held[index]),
            setting(index, &described[index])
        ));
    }
}

/// One of the eight settings as a person reads it: `none` where it is not held, the switch as the
/// word it is, and any other through the door `kr doctor` says a configured location by, which
/// shows an address by its parts and anything else by its class and length.
fn setting(index: usize, value: &Option<String>) -> Asked {
    match value.as_deref() {
        None => Asked::text(Request::Network, "none"),
        Some(value) if index == 0 => Asked::text(
            Request::Network,
            if value == "true" { "true" } else { "false" },
        ),
        Some(value) => output::configured(ContentClass::Location, value),
    }
}

/// Tells what happened and what the document now selects.
fn present(environment: &KnownEnvironment, action: &Action, json: bool) {
    let now = load(&environment.paths);
    let empty = ConfigurationDocument::empty();
    let document = now.document.as_ref().unwrap_or(&empty);
    let revision = match action {
        Action::Joined { revision, .. } | Action::Cleared { revision } => *revision,
        Action::Showed | Action::LoginStored | Action::LoginCleared => None,
    };
    if json {
        let mut shown = Document::new()
            .with("ok", true)
            .with("environment_id", output::said(&environment.environment_id))
            .with("document", Shown::root(&document_path(&environment.paths)))
            .with("changed", revision.is_some())
            .with("revision", now.revision())
            .with("network", selection_document(document));
        if matches!(action, Action::LoginStored | Action::LoginCleared) {
            shown.set("applies_at_next_start", true);
        }
        if let Action::Joined { description, .. } = action {
            shown.set("signed", description.signed());
            shown.set("ignored_members", description.ignored().count());
        }
        output::document(&shown);
        return;
    }
    match action {
        Action::Showed => {}
        Action::Joined {
            revision: None,
            description,
        } => {
            output::say(&Shown::said(
                "this host already selects what the service describes; nothing was written",
            ));
            note_description(description);
        }
        Action::Joined {
            revision: Some(revision),
            description,
        } => {
            output::say(&shown!(
                "this host's configuration now selects what the service describes (revision {})",
                *revision
            ));
            note_description(description);
        }
        Action::LoginStored => output::say(&Shown::said(
            "the proxy login is stored; the daemon uses it from its next start",
        )),
        Action::LoginCleared => output::say(&Shown::said(
            "the proxy login is cleared; the daemon sends none from its next start",
        )),
        Action::Cleared { revision: None } => output::say(&Shown::said(
            "this host's configuration selected none of what a join writes; nothing was written",
        )),
        Action::Cleared {
            revision: Some(revision),
        } => output::say(&shown!(
            "this host's configuration no longer selects a service (revision {})",
            *revision
        )),
    }
    for (key, value) in ServiceSelection::KEYS.iter().zip(held(document)) {
        match value {
            Some(value) if *key == ServiceSelection::KEYS[0] => {
                output::line(&stdout_line!(
                    "{}: {}",
                    *key,
                    if value == "true" { "true" } else { "false" }
                ));
            }
            Some(value) => output::line(&stdout_line!(
                "{}: {}",
                *key,
                output::configured(ContentClass::Location, &value)
            )),
            None => output::line(&stdout_line!("{}: none", *key)),
        }
    }
    if matches!(
        action,
        Action::Joined {
            revision: Some(_),
            ..
        } | Action::Cleared { revision: Some(_) }
    ) {
        output::say(&Shown::said(
            "this applies when the control daemon next starts; one that is running keeps what it \
             started with",
        ));
    }
}

/// What a person is told of the description that was read, beyond what the document now selects.
fn note_description(description: &Description) {
    if !description.signed() {
        output::say(&Shown::said(
            "the description was taken on the connection alone, so it is as trustworthy as that \
             connection and the service that answered it",
        ));
    }
    let ignored: &Ignored = description.ignored();
    if ignored.count() > 0 {
        // A signature does not cover the members this build does not read, so for a description
        // that was verified only how many there are is said, and not what they are called.
        if description.signed() {
            output::line(&stdout_line!(
                "the description names {} members this build does not read",
                ignored.count()
            ));
        } else {
            output::line(&stdout_line!(
                "the description names {} members this build does not read: {}",
                ignored.count(),
                Asked::text(Request::Network, &ignored.names().join(", "))
            ));
        }
    }
    match description.selection().relay_origin.as_deref() {
        None => {}
        Some(origin) if is_managed_text(origin) => output::say(&Shown::said(
            "relay leases are billed to the account this host is signed in as: kr account sign-in",
        )),
        Some(_) => output::say(&Shown::said(
            "this host asks for no relay lease from that service, since it presents its account \
             only to the KalaReach service",
        )),
    }
}

/// Whether text names the managed service.
fn is_managed_text(origin: &str) -> bool {
    GatewayOrigin::new(origin).is_ok_and(|origin| description::is_managed(&origin))
}

/// The eight settings as a document holds them.
fn selection_document(document: &ConfigurationDocument) -> Document {
    let network = &document.network;
    let place =
        |value: Option<&str>| value.map(|value| output::configured(ContentClass::Location, value));
    let places = |values: &[String]| {
        values
            .iter()
            .map(|value| output::configured(ContentClass::Location, value))
            .collect::<Vec<_>>()
    };
    Document::new()
        .with(configuration::NETWORK_ENABLED.key, network.enabled.0)
        .with(
            configuration::NETWORK_RELAY_URLS.key,
            places(network.relay_urls()),
        )
        .with(
            configuration::NETWORK_PKARR_PUBLISHER_URL.key,
            place(network.pkarr_publisher_url()),
        )
        .with(
            configuration::NETWORK_PKARR_RESOLVER_URL.key,
            place(network.pkarr_resolver_url()),
        )
        .with(
            configuration::NETWORK_DNS_ORIGIN.key,
            place(network.dns_origin()),
        )
        .with(
            configuration::AUTHORITY_ORIGIN.key,
            place(document.authority.origin()),
        )
        .with(
            configuration::MAILBOX_ORIGIN.key,
            place(document.mailbox.origin()),
        )
        .with(
            configuration::RELAY_ORIGIN.key,
            place(document.relay.origin()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The managed service's description is read only under the key this build pins. No case
    /// reaches this from outside: the commands name loopback services, since the managed origin is
    /// not one a test can stand in for, and the flags that would change it are refused before any
    /// request.
    #[test]
    fn the_managed_service_is_read_under_the_pinned_key() {
        let managed = GatewayOrigin::new(kr_client::services::account::ACCOUNT_ORIGIN)
            .expect("the managed origin");
        let arguments = NetworkArguments {
            join: true,
            service: None,
            key: None,
            unsigned: false,
            replace: false,
            clear: false,
            proxy_login: false,
            proxy_logout: false,
            proxy_credential_file: None,
        };
        assert!(matches!(trust(&managed, &arguments), Ok(Trust::Pinned(_))));
    }

    /// KR-REQ-10.02: the proxy login's flags combine as the command's help says. The file needs
    /// `--join` or `--proxy-login`; `--proxy-login` needs the file; the four modes exclude each
    /// other.
    #[test]
    fn the_proxy_login_flags_combine_only_as_the_command_says() {
        use clap::Parser as _;

        let parses = |line: &[&str]| {
            let mut arguments = vec!["kr", "host", "network"];
            arguments.extend_from_slice(line);
            crate::cli::Cli::try_parse_from(arguments).is_ok()
        };
        assert!(parses(&[
            "--proxy-login",
            "--proxy-credential-file",
            "login"
        ]));
        assert!(parses(&["--join", "--proxy-credential-file", "login"]));
        assert!(parses(&["--proxy-logout"]));
        assert!(!parses(&["--proxy-credential-file", "login"]));
        assert!(!parses(&["--proxy-login"]));
        assert!(!parses(&[
            "--proxy-login",
            "--join",
            "--proxy-credential-file",
            "login"
        ]));
        assert!(!parses(&[
            "--proxy-login",
            "--proxy-logout",
            "--proxy-credential-file",
            "login"
        ]));
        assert!(!parses(&["--proxy-logout", "--clear"]));
        assert!(!parses(&[
            "--clear",
            "--proxy-login",
            "--proxy-credential-file",
            "login"
        ]));
    }
}
