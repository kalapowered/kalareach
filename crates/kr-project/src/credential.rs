//! Remotes, providers and the approved credential brokers.
//!
//! Section 14 paragraph 2 states the rule in one sentence: network fetch and credential use name
//! the remote, the provider and the approved credential broker, and no credential appears in a
//! URL, a diagnostic or remote state. This module is where a caller's remote becomes a
//! [`RemoteSpecification`] that satisfies it, or a refusal that says which part of it does not.
//!
//! Four checks, in order, and each one refuses rather than repairs.
//!
//! 1. **The transport is one of three.** `https`, `ssh` and a local path on this host. Anything
//!    else — `git://`, `ext::`, `file://`, a bare `scheme::` that names a remote helper — is
//!    refused by name. The allowlist exists because the set of transports Git can be talked into
//!    using is not closed, and the restricted profile's `protocol.allow=never` then lets exactly
//!    the one validated transport back.
//! 2. **The URL carries no credential.** A password in the authority is refused outright, not
//!    stripped: a caller that sent one has a credential in its own state and needs to know. A bare
//!    user name is not a credential and is kept, because ssh needs it.
//! 3. **The provider is named.** It is the host name as this host resolved it, recorded beside the
//!    remote so a receipt says which service was reached.
//! 4. **The broker is approved.** A transport that needs authentication names a broker this host
//!    has, and the broker supplies a *program* Git will run for a credential. The host never sees
//!    the credential itself: the helper is the only thing that does, and it is resolved to an
//!    absolute path inside Git's own helper directory rather than found on a path.
//!
//! A local-path remote needs no broker and reaches no network, so it names none.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use kr_protocol::project::{MAX_REMOTE_URL_LEN, RemoteSpecification, RemoteTransport};

use crate::error::{ProjectError, Result};
use crate::git::GitProgram;

/// The name of the broker that reaches the operating system's own secret store.
pub const OS_SECRET_STORE: &str = "os-secret-store";

/// The credential helper program each platform's secret store is reached through.
///
/// Every one of them ships with Git and lives in Git's own helper directory, so the program is
/// resolved there rather than found on a path.
const PLATFORM_HELPERS: &[&str] = &[
    // Apple platforms.
    "git-credential-osxkeychain",
    // Windows.
    "git-credential-manager",
    "git-credential-wincred",
    // Linux and the other Unix systems.
    "git-credential-libsecret",
];

/// One approved credential broker: a name, and the programs it lends Git.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialBroker {
    name: String,
    helper: Option<PathBuf>,
    ssh_command: Option<OsString>,
}

impl CredentialBroker {
    /// Returns the broker's name, which is what a receipt and a diagnostic carry.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the credential helper program, when this broker has one.
    #[must_use]
    pub fn helper(&self) -> Option<&Path> {
        self.helper.as_deref()
    }

    /// Returns the ssh program, when this broker has one.
    #[must_use]
    pub fn ssh_command(&self) -> Option<&std::ffi::OsStr> {
        self.ssh_command.as_deref()
    }
}

/// The brokers this host has.
#[derive(Clone, Debug, Default)]
pub struct BrokerRegistry {
    brokers: Vec<CredentialBroker>,
}

impl BrokerRegistry {
    /// Discovers the brokers this host has, given the resolved Git program.
    ///
    /// The operating system's secret store is present when its helper is in Git's own helper
    /// directory. The ssh program is the one beside Git's own binary, configured to read no user
    /// configuration file and never to prompt, because a prompt cannot be answered by a process
    /// with no terminal and a `ProxyCommand` in a user's `~/.ssh/config` is a program this host did
    /// not grant.
    #[must_use]
    pub fn discover(git: &GitProgram) -> Self {
        let helper = PLATFORM_HELPERS
            .iter()
            .flat_map(|name| {
                // Windows needs the executable suffix; the other platforms have none.
                [
                    git.exec_path().join(name),
                    git.exec_path().join(format!("{name}.exe")),
                ]
            })
            .find(|candidate| candidate.is_file());
        let ssh = ssh_program(git);
        let ssh_command = ssh.map(|program| {
            let mut command = OsString::from("\"");
            command.push(program.as_os_str());
            // No user or system ssh configuration file, no interactive prompt, no agent
            // forwarding and no host-key question a process with no terminal cannot answer.
            // `-F` names the configuration file ssh reads, and this is the platform's empty
            // device: a `ProxyCommand` in the user's own `~/.ssh/config` is a program this host
            // did not grant, so no user or system file is read at all.
            command.push(if cfg!(windows) {
                "\" -F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no"
            } else {
                "\" -F /dev/null -o BatchMode=yes -o StrictHostKeyChecking=yes -o ForwardAgent=no"
            });
            command
        });
        let mut brokers = Vec::new();
        if helper.is_some() || ssh_command.is_some() {
            brokers.push(CredentialBroker {
                name: OS_SECRET_STORE.to_owned(),
                helper,
                ssh_command,
            });
        }
        Self { brokers }
    }

    /// Builds a registry from brokers a caller supplies.
    #[must_use]
    pub const fn from_brokers(brokers: Vec<CredentialBroker>) -> Self {
        Self { brokers }
    }

    /// Builds one broker, for a host whose brokers are configured rather than discovered.
    #[must_use]
    pub fn broker(
        name: impl Into<String>,
        helper: Option<PathBuf>,
        ssh_command: Option<OsString>,
    ) -> CredentialBroker {
        CredentialBroker {
            name: name.into(),
            helper,
            ssh_command,
        }
    }

    /// Returns the names of every broker this host has.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.brokers.iter().map(CredentialBroker::name).collect()
    }

    /// Returns the broker one name refers to.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::RemoteRejected`] when this host has no such broker.
    pub fn approved(&self, name: &str) -> Result<&CredentialBroker> {
        self.brokers
            .iter()
            .find(|broker| broker.name == name)
            .ok_or_else(|| ProjectError::RemoteRejected {
                detail: format!(
                    "{} is not an approved credential broker on this host; the approved ones \
                     are {}",
                    // The name is whatever the request carried, and this message is kept, so it
                    // goes through the same rule as any other text this host did not choose.
                    crate::git::redact(name),
                    if self.brokers.is_empty() {
                        "none".to_owned()
                    } else {
                        self.names().join(", ")
                    }
                ),
            })
    }

    /// Validates a caller's remote and returns the specification an operation runs under.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectError::RemoteRejected`] naming the rule the remote breaks.
    pub fn validate(&self, requested: &RemoteSpecification) -> Result<ValidatedRemote> {
        if requested.url.len() > MAX_REMOTE_URL_LEN {
            return Err(ProjectError::RemoteRejected {
                detail: format!(
                    "a remote URL is at most {MAX_REMOTE_URL_LEN} bytes and this one is {}",
                    requested.url.len()
                ),
            });
        }
        if requested.remote_name.is_empty()
            || !requested.remote_name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
        {
            return Err(ProjectError::RemoteRejected {
                detail: format!(
                    "{} is not a remote name; a remote name is letters, digits, hyphens and \
                     underscores",
                    crate::git::redact(&requested.remote_name)
                ),
            });
        }
        let parsed = parse_remote(&requested.url)?;
        if parsed.transport != requested.transport {
            return Err(ProjectError::RemoteRejected {
                detail: format!(
                    "the caller named the {:?} transport and this remote is the {:?} transport",
                    requested.transport, parsed.transport
                ),
            });
        }
        let broker = match parsed.transport {
            // A local path reaches no network and needs no credential, so it names no broker.
            RemoteTransport::LocalPath => {
                if !requested.credential_broker.is_empty() {
                    return Err(ProjectError::RemoteRejected {
                        detail:
                            "a local-path remote reaches no network, so it names no credential \
                                 broker"
                                .to_owned(),
                    });
                }
                None
            }
            RemoteTransport::Https | RemoteTransport::Ssh => {
                let broker = self.approved(&requested.credential_broker)?;
                match parsed.transport {
                    RemoteTransport::Https if broker.helper.is_none() => {
                        return Err(ProjectError::RemoteRejected {
                            detail: format!(
                                "the broker {} has no credential helper on this host, so an https \
                                 remote cannot be authenticated",
                                broker.name
                            ),
                        });
                    }
                    RemoteTransport::Ssh if broker.ssh_command.is_none() => {
                        return Err(ProjectError::RemoteRejected {
                            detail: format!(
                                "the broker {} has no ssh program on this host, so an ssh remote \
                                 cannot be reached",
                                broker.name
                            ),
                        });
                    }
                    _ => {}
                }
                Some(broker.clone())
            }
        };
        Ok(ValidatedRemote {
            specification: RemoteSpecification {
                remote_name: requested.remote_name.clone(),
                transport: parsed.transport,
                url: parsed.url,
                provider: parsed.provider,
                credential_broker: requested.credential_broker.clone(),
            },
            broker,
        })
    }
}

/// A remote this host will use, and the broker that authenticates it.
#[derive(Clone, Debug)]
pub struct ValidatedRemote {
    /// The remote as it is recorded and reported: no credential, provider named, broker named.
    pub specification: RemoteSpecification,
    /// The broker, when the transport needs one.
    pub broker: Option<CredentialBroker>,
}

impl ValidatedRemote {
    /// Returns the credential helper program Git runs, when there is one.
    #[must_use]
    pub fn credential_helper(&self) -> Option<&std::ffi::OsStr> {
        self.broker
            .as_ref()
            .and_then(CredentialBroker::helper)
            .map(Path::as_os_str)
    }

    /// Returns the ssh program Git runs, when the transport is ssh.
    #[must_use]
    pub fn ssh_command(&self) -> Option<&std::ffi::OsStr> {
        if matches!(self.specification.transport, RemoteTransport::Ssh) {
            self.broker.as_ref().and_then(CredentialBroker::ssh_command)
        } else {
            None
        }
    }
}

/// What a remote URL turned out to be, once this host had validated every part of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectRemote {
    /// The transport it names.
    pub transport: RemoteTransport,
    /// The URL as this host will pass it to Git: no password, nothing rewritten.
    pub url: String,
    /// The provider, which is the host name for a network transport and the empty string for a
    /// local path.
    pub provider: String,
}

/// Validates one remote URL and says what transport it is.
///
/// Public because it is the whole of the rule and the fixture tests read it directly.
///
/// # Errors
///
/// Returns [`ProjectError::RemoteRejected`] naming what is wrong with the URL.
pub fn parse_remote(url: &str) -> Result<ProjectRemote> {
    let trimmed = url.trim();
    if trimmed != url || trimmed.is_empty() {
        return Err(ProjectError::RemoteRejected {
            detail: "a remote URL has no surrounding space and is not empty".to_owned(),
        });
    }
    if trimmed
        .chars()
        .any(|character| character.is_control() || character == '\0')
    {
        return Err(ProjectError::RemoteRejected {
            detail: "a remote URL carries no control character".to_owned(),
        });
    }
    // A query or a fragment is how a token reaches a URL without going through the authority:
    // `https://host/repo.git?access_token=...`. Neither is part of a repository URL, so both are
    // refused before anything reads them, and nothing here repeats what one carried.
    if trimmed.contains('?') || trimmed.contains('#') {
        return Err(ProjectError::RemoteRejected {
            detail: "a remote URL carries no query and no fragment; a repository URL needs \
                     neither, and a credential travels in one"
                .to_owned(),
        });
    }
    // `<transport>::<address>` is how Git names a remote helper program, so it is refused before
    // anything else reads the string. The test is Git's own: a doubled colon whose prefix is a
    // transport name. An IPv6 URL's `::` sits after a `:/`, so it is not one of these.
    if let Some(colon) = trimmed.find(':')
        && trimmed[colon + 1..].starts_with(':')
        && !trimmed[..colon].is_empty()
        && trimmed[..colon].chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '-' | '.')
        })
    {
        return Err(ProjectError::RemoteRejected {
            detail: format!(
                "this remote names the helper program git-remote-{}, which this host does not run",
                &trimmed[..colon]
            ),
        });
    }
    // A local path next, because it is the one form that is not a URL at all.
    if Path::new(trimmed).is_absolute() && !trimmed.contains("://") {
        return Ok(ProjectRemote {
            transport: RemoteTransport::LocalPath,
            url: trimmed.to_owned(),
            provider: String::new(),
        });
    }
    // The `scp`-like form `user@host:path`, which is how ssh remotes are usually written. It is
    // recognised before the URL parser, because it is not a URL and the parser would read the
    // host as a scheme. Git's own rule for it is that the part before the first colon holds no
    // slash, which is what keeps a Windows drive letter and a relative path out of it.
    if !trimmed.contains("://")
        && let Some((authority, path)) = trimmed.split_once(':')
        && !authority.is_empty()
        && !authority.contains('/')
        && !path.is_empty()
        && !path.starts_with('/')
    {
        let (user, host) = authority
            .rsplit_once('@')
            .map_or((None, authority), |(user, host)| (Some(user), host));
        // A colon inside the user information, or an `@` in the path, is how a credential is
        // smuggled into this form: Git splits on the first colon, so `user:secret@host:path`
        // leaves the secret in the path it would store as the remote's URL.
        if user.is_some_and(|user| user.contains(':')) || path.contains('@') {
            return Err(ProjectError::RemoteRejected {
                detail: "a remote URL carries no credential; the approved credential broker \
                         supplies it"
                    .to_owned(),
            });
        }
        check_host(host)?;
        return Ok(ProjectRemote {
            transport: RemoteTransport::Ssh,
            url: trimmed.to_owned(),
            provider: host.to_ascii_lowercase(),
        });
    }
    // The refusal below names what is wrong and not the URL: a URL this host could not parse is
    // one it cannot redact either, and a malformed authority is exactly where a credential sits.
    let parsed = url::Url::parse(trimmed).map_err(|error| ProjectError::RemoteRejected {
        detail: format!("this remote is not a URL this host can read: {error}"),
    })?;
    let transport = match parsed.scheme() {
        "https" => RemoteTransport::Https,
        "ssh" => RemoteTransport::Ssh,
        other => {
            return Err(ProjectError::RemoteRejected {
                detail: format!(
                    "{other} is not a transport this host uses; it uses https, ssh and a local \
                     path on this host, and refuses every other transport rather than handing it \
                     to a remote helper"
                ),
            });
        }
    };
    if parsed.password().is_some() {
        return Err(ProjectError::RemoteRejected {
            detail: "a remote URL carries no credential; the approved credential broker supplies \
                     it"
            .to_owned(),
        });
    }
    if matches!(transport, RemoteTransport::Https) && !parsed.username().is_empty() {
        // An https remote's user name is what the broker's helper looks the credential up by, so
        // carrying one in the URL puts half a credential in the repository's own state.
        return Err(ProjectError::RemoteRejected {
            detail: "an https remote carries no user name in its URL; the approved credential \
                     broker supplies both halves"
                .to_owned(),
        });
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ProjectError::RemoteRejected {
            detail: "this remote names no host".to_owned(),
        })?;
    check_host(host)?;
    Ok(ProjectRemote {
        transport,
        url: trimmed.to_owned(),
        provider: host.to_ascii_lowercase(),
    })
}

/// Refuses a host name that is not one.
fn check_host(host: &str) -> Result<()> {
    if host.is_empty() {
        return Err(ProjectError::RemoteRejected {
            detail: "a remote URL names a host".to_owned(),
        });
    }
    if host.starts_with('-') || host.contains("..") || host.contains('/') {
        return Err(ProjectError::RemoteRejected {
            detail: format!("{} is not a host name", crate::git::redact(host)),
        });
    }
    Ok(())
}

/// Refuses a stored remote URL that is not one this host would have used.
///
/// Read back from the repository after a clone, so a credential cannot reach remote state by a
/// route the validation above did not cover: a URL rewrite, a helper, or a version of Git that
/// stored something other than what it was given. The refusal never repeats the credential.
///
/// # Errors
///
/// Returns [`ProjectError::RemoteRejected`] when the stored URL is not one this host would use.
pub fn require_no_credential(remote_name: &str, stored: &str) -> Result<()> {
    parse_remote(stored)
        .map(|_| ())
        .map_err(|error| ProjectError::RemoteRejected {
            detail: format!(
                "the remote {remote_name} was stored as a URL this host would not have used: \
                 {error}"
            ),
        })
}

/// Returns the ssh program beside Git's own binary, when there is one.
fn ssh_program(git: &GitProgram) -> Option<PathBuf> {
    let file_name = if cfg!(windows) { "ssh.exe" } else { "ssh" };
    let candidates = [
        git.program().parent().map(|dir| dir.join(file_name)),
        Some(git.exec_path().join(file_name)),
        // The usual absolute locations, so a host whose Git is installed somewhere unusual still
        // finds the system's own ssh rather than one on a path this service does not control.
        (!cfg!(windows)).then(|| PathBuf::from("/usr/bin").join(file_name)),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_credential_in_a_url_is_refused_rather_than_stripped() {
        // Stripping it would leave the caller believing the host holds a credential it does not.
        let refusal = parse_remote("https://user:secret@example.invalid/repository.git")
            .expect_err("a password in a URL is refused");
        assert!(
            refusal.to_string().contains("carries no credential"),
            "the refusal says why: {refusal}"
        );
        // And nothing about the refusal repeats the credential.
        assert!(!refusal.to_string().contains("secret"));
        let refusal = parse_remote("ssh://git:secret@example.invalid/repository.git")
            .expect_err("a password in an ssh URL is refused");
        assert!(!refusal.to_string().contains("secret"));
        let refusal = parse_remote("git:secret@example.invalid:repository.git")
            .expect_err("a password in the scp-like form is refused");
        assert!(!refusal.to_string().contains("secret"));
    }

    #[test]
    fn a_credential_in_a_query_or_a_fragment_is_refused_and_never_repeated() {
        // A token reaches a URL without going through the authority: this is the form a provider's
        // own documentation sometimes suggests, and it would be stored as the remote's URL.
        for url in [
            "https://example.invalid/repo.git?access_token=SECRET",
            "https://example.invalid/repo.git?private_token=SECRET&x=1",
            "https://example.invalid/repo.git#SECRET",
            "git@example.invalid:owner/repo.git?token=SECRET",
        ] {
            let refusal = parse_remote(url).expect_err("a query or a fragment is refused");
            assert!(
                !refusal.to_string().contains("SECRET"),
                "the refusal does not repeat it: {refusal}"
            );
        }
    }

    #[test]
    fn no_refusal_repeats_the_url_it_refused() {
        // A URL this host could not parse is one it could not redact either, and a malformed
        // authority is exactly where a credential sits. So a refusal names what is wrong rather
        // than what it was given.
        for url in [
            "https://user:SECRET@example.invalid:notaport/repo.git",
            "kr::https://user:SECRET@example.invalid/repo.git",
            "ftp://user:SECRET@example.invalid/repo.git",
            "https://SECRET@example.invalid/repo.git",
        ] {
            let refusal = parse_remote(url).expect_err("each of these is refused");
            assert!(
                !refusal.to_string().contains("SECRET"),
                "{url} is refused without repeating what it carried: {refusal}"
            );
        }
    }

    #[test]
    fn an_https_remote_carries_no_user_name_either() {
        let refusal = parse_remote("https://someone@example.invalid/repository.git")
            .expect_err("half a credential is still a credential");
        assert!(refusal.to_string().contains("user name"));
    }

    #[test]
    fn only_three_transports_are_used_and_a_remote_helper_is_never_reached() {
        assert_eq!(
            parse_remote("https://example.invalid/x.git")
                .expect("https is used")
                .transport,
            RemoteTransport::Https
        );
        assert_eq!(
            parse_remote("ssh://git@example.invalid/x.git")
                .expect("ssh is used")
                .transport,
            RemoteTransport::Ssh
        );
        assert_eq!(
            parse_remote("git@example.invalid:owner/x.git")
                .expect("the scp-like form is ssh")
                .transport,
            RemoteTransport::Ssh
        );
        // A local path is a path rather than a URL, so no helper is involved at all.
        let local = if cfg!(windows) {
            "C:\\repositories\\x"
        } else {
            "/repositories/x"
        };
        assert_eq!(
            parse_remote(local).expect("a local path is used").transport,
            RemoteTransport::LocalPath
        );
        // Everything else is refused by name rather than handed to `git-remote-<scheme>`.
        for refused in [
            "git://example.invalid/x.git",
            "ext::sh -c 'echo planted'",
            "file:///repositories/x",
            "http://example.invalid/x.git",
            "kr::example.invalid/x",
            "ftp://example.invalid/x",
            "transport::",
        ] {
            parse_remote(refused)
                .map(|parsed| parsed.transport)
                .expect_err(refused);
        }
        // An IPv6 host holds a doubled colon and is still a URL rather than a remote helper.
        assert_eq!(
            parse_remote("https://[::1]/x.git")
                .expect("an IPv6 host is a URL")
                .provider,
            "[::1]"
        );
    }

    #[test]
    fn a_provider_is_the_host_name_this_host_resolved() {
        assert_eq!(
            parse_remote("https://Example.Invalid/x.git")
                .expect("it parses")
                .provider,
            "example.invalid"
        );
        assert_eq!(
            parse_remote("git@Example.Invalid:x.git")
                .expect("it parses")
                .provider,
            "example.invalid"
        );
        // A local path reaches no provider.
        let local = if cfg!(windows) {
            "C:\\repositories\\x"
        } else {
            "/repositories/x"
        };
        assert_eq!(
            parse_remote(local).expect("it parses").provider,
            String::new()
        );
    }

    #[test]
    fn a_network_remote_names_an_approved_broker_and_an_unknown_one_is_refused() {
        let registry = BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
            OS_SECRET_STORE,
            Some(PathBuf::from(
                "/usr/libexec/git-core/git-credential-osxkeychain",
            )),
            Some(OsString::from("/usr/bin/ssh -F /dev/null")),
        )]);
        let good = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Https,
                url: "https://example.invalid/x.git".to_owned(),
                provider: String::new(),
                credential_broker: OS_SECRET_STORE.to_owned(),
            })
            .expect("an approved broker is accepted");
        assert_eq!(good.specification.provider, "example.invalid");
        assert_eq!(good.specification.credential_broker, OS_SECRET_STORE);
        assert!(good.credential_helper().is_some());
        // An https remote uses no ssh program.
        assert!(good.ssh_command().is_none());
        let refusal = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Https,
                url: "https://example.invalid/x.git".to_owned(),
                provider: String::new(),
                credential_broker: "somebody-elses-agent".to_owned(),
            })
            .expect_err("an unapproved broker is refused");
        assert!(
            refusal
                .to_string()
                .contains("not an approved credential broker")
        );
    }

    #[test]
    fn a_local_path_remote_names_no_broker_and_naming_one_is_refused() {
        let registry = BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
            OS_SECRET_STORE,
            Some(PathBuf::from(
                "/usr/libexec/git-core/git-credential-osxkeychain",
            )),
            None,
        )]);
        let local = if cfg!(windows) {
            "C:\\repositories\\x"
        } else {
            "/repositories/x"
        };
        let good = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::LocalPath,
                url: local.to_owned(),
                provider: String::new(),
                credential_broker: String::new(),
            })
            .expect("a local path needs no broker");
        assert!(good.broker.is_none());
        assert!(good.credential_helper().is_none());
        let refusal = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::LocalPath,
                url: local.to_owned(),
                provider: String::new(),
                credential_broker: OS_SECRET_STORE.to_owned(),
            })
            .expect_err("naming a broker for a local path is refused");
        assert!(refusal.to_string().contains("reaches no network"));
    }

    #[test]
    fn a_transport_the_caller_named_must_be_the_one_the_url_is() {
        let registry = BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
            OS_SECRET_STORE,
            Some(PathBuf::from(
                "/usr/libexec/git-core/git-credential-osxkeychain",
            )),
            Some(OsString::from("/usr/bin/ssh")),
        )]);
        let refusal = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Ssh,
                url: "https://example.invalid/x.git".to_owned(),
                provider: String::new(),
                credential_broker: OS_SECRET_STORE.to_owned(),
            })
            .expect_err("a mismatch is refused");
        assert!(refusal.to_string().contains("transport"));
    }

    #[test]
    fn a_broker_with_no_program_for_the_transport_is_refused_rather_than_tried() {
        let registry = BrokerRegistry::from_brokers(vec![BrokerRegistry::broker(
            OS_SECRET_STORE,
            None,
            Some(OsString::from("/usr/bin/ssh")),
        )]);
        let refusal = registry
            .validate(&RemoteSpecification {
                remote_name: "origin".to_owned(),
                transport: RemoteTransport::Https,
                url: "https://example.invalid/x.git".to_owned(),
                provider: String::new(),
                credential_broker: OS_SECRET_STORE.to_owned(),
            })
            .expect_err("no helper means no https");
        assert!(refusal.to_string().contains("no credential helper"));
    }
}
