//! The managed service clients this daemon holds for its whole life, built in one place.
//!
//! One function builds them, from the configuration document the daemon read when it started, the
//! host's account and the host's keys: the storage and backup manifest clients its carrier uploads
//! through, the relay lease service, and the managed inference broker. The carrier, the relay lease
//! keeper and the voice actions take their client from the set, and `kr doctor` says which of the
//! four services a host can hold the set has a client of. The account slot is a view of the account
//! the host signs in with, which keeps a client of its own for its sign-in, and the clients of the
//! authority feed, the mailbox and delivery are built where those start, from their own
//! configuration. A fork that points one of the services at its own infrastructure changes this
//! function.
//!
//! What stays out is a client that fixes a signer or an account for one operation: the owner's
//! setup of the backups signs the bundle with a key made for that write and enrols the writer with
//! the owner's, and presents the account that was signed in when it began.

use std::sync::Arc;

use kr_client::services::{ManagedService, ServiceClients};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::hostinfo::configuration::{self, Selection};
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::service::GatewayOrigin;
use kr_voice::broker::ManagedVoiceService;

use super::Controller;
use crate::account::HostAccount;
use crate::backup::binding::Binding;
use crate::config::Started;
use crate::error::{ControllerError, Result};

/// The storage service this host uploads its backups to, and what it signs and presents there.
pub(super) struct StorageParts<'a> {
    /// The storage service's origin.
    pub origin: &'a GatewayOrigin,
    /// The key only this host holds that signs its uploads.
    pub writer: &'a AuthorisationKeyPair,
    /// The record of the account the backups belong to, which the account's token is held to.
    pub binding: Arc<Binding>,
}

/// What the daemon's clients are built from.
pub(super) struct ClientParts<'a> {
    /// The host's own sign-in to the managed account service.
    pub account: &'a Arc<HostAccount>,
    /// The key the host signs the relay lease service's requests with.
    pub host_key: &'a AuthorisationKeyPair,
    /// The storage service, when the configuration document selects one.
    pub storage: Option<StorageParts<'a>>,
}

/// The origin a selection of the configuration document names, or why it cannot be used.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] naming the selection.
pub(super) fn selected_origin(selection: &Selection, origin: &str) -> Result<GatewayOrigin> {
    GatewayOrigin::new(origin).map_err(|error| {
        ControllerError::NotConfigured(format!(
            "{} in this host's configuration document ({}) is not usable: {error}",
            selection.key,
            configuration::FILE_NAME,
        ))
    })
}

impl Controller {
    /// Builds the clients this daemon holds, from the services its configuration document
    /// selects. A slot of a service it selects none of stays empty, and a host with no slot full
    /// is a complete host.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::NotConfigured`] when a selected storage or relay lease service
    /// cannot be reached: its origin is not usable, or the proxy the document selects is not, or
    /// no transport to it can be built. A managed inference broker that cannot be reached is
    /// reported on standard error and left out, so that the host still starts.
    pub(super) fn build_service_clients(
        started: &Started,
        parts: &ClientParts<'_>,
    ) -> Result<ServiceClients> {
        let mut clients = ServiceClients::none();
        clients.account = parts.account.account_service();
        if let Some(storage) = &parts.storage {
            let tokens = parts
                .account
                .bound_tokens_for(storage.origin.as_str(), Arc::clone(&storage.binding));
            let held = crate::backup::runtime::managed_clients(
                storage.origin,
                Self::outbound_of(started)?.proxy()?,
                storage.writer,
                &tokens,
            )?;
            clients.storage = held.storage;
            clients.backup_manifest = held.backup_manifest;
        }
        if let Some(origin) = started.relay.origin() {
            let origin = selected_origin(&configuration::RELAY_ORIGIN, origin)?;
            clients.relay_leases = Some(crate::relay_leases::managed_service(
                &origin,
                Self::outbound_of(started)?.proxy()?,
                Arc::new(crate::push::sender::HostSigner::new(parts.host_key.clone())),
            )?);
        }
        clients.managed_inference = Self::managed_voice_provider(started, parts.account);
        Ok(clients)
    }

    /// The managed broker the configuration document names, reached over a transport of its own
    /// through the proxy that document selects, or none where it names none.
    ///
    /// A host that cannot reach the broker it names still starts: the transport is built on its
    /// first use and says why when it cannot be, and a broker the document names wrongly is a
    /// document the daemon refused before it got here. What is reported here is what leaves a
    /// device with no broker where the document names one.
    fn managed_voice_provider(
        started: &Started,
        account: &Arc<HostAccount>,
    ) -> Option<Arc<dyn ManagedVoiceService>> {
        let origin = started.voice.broker_origin()?;
        let unavailable = |reason: &dyn std::fmt::Display| {
            eprintln!("kr-controller: managed voice is not attached: {reason}");
        };
        let origin_unusable = |error: &dyn std::fmt::Display| {
            unavailable(&format_args!(
                "voice.broker_origin in this host's configuration document is not usable: {error}"
            ));
        };
        let gateway = GatewayOrigin::new(origin)
            .inspect_err(|error| origin_unusable(error))
            .ok()?;
        // A proxy the document selects and this host cannot read is never gone around; the error
        // names `network.proxy_url` itself.
        let proxy = Self::outbound_of(started)
            .and_then(|route| route.proxy().map(|proxy| proxy.cloned()))
            .inspect_err(|error| unavailable(error))
            .ok()?;
        let transport = Arc::new(crate::managed_transport::ManagedTransport::new(
            gateway,
            proxy,
            crate::managed_transport::VOICE_DEADLINES,
        ));
        crate::voice::VoiceModule::managed_provider(origin, transport, account.tokens_for(origin))
            .inspect_err(|error| origin_unusable(error))
            .ok()
    }

    /// What `kr doctor` says of the managed services: which of the four a host can hold this
    /// daemon holds a client of, and what to do instead for each it does not.
    ///
    /// Registering a phone for push is the phone's, so a host lists no such service. This explains
    /// and decides nothing: a host that holds none is a complete host, so the check is never a
    /// warning or a failure, and it says nothing of what an account is entitled to, which the
    /// service answers when a client calls it.
    pub(super) fn managed_services_check(&self) -> DoctorCheck {
        let mut sentence = Sentence::new();
        let mut every = true;
        let held = self
            .clients
            .availability()
            .into_iter()
            .filter(|report| report.service != ManagedService::Push);
        for (position, report) in held.enumerate() {
            if position > 0 {
                sentence = sentence.stated("; ");
            }
            sentence = sentence.stated(report.service.as_str());
            if report.configured {
                sentence = sentence.stated(": configured");
            } else {
                every = false;
                sentence = sentence
                    .stated(": not configured, you can ")
                    .stated(report.service.alternative());
            }
        }
        DoctorCheck::new(
            "managed-services",
            "The managed services this host uses",
            if every {
                DoctorStatus::Ok
            } else {
                DoctorStatus::NotApplicable
            },
            sentence.stated(". Each is optional: this host does the rest without it."),
            None,
        )
    }
}
