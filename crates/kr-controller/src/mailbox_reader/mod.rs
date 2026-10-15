//! The host reading its own mailbox.
//!
//! The mailbox service holds sealed items for a recipient until the recipient says it has stored
//! them. Most of what it holds is for devices, which read their own. What reaches a host's mailbox
//! is what a remote owner's device addresses to the host: an announcement, beside a change it
//! published to the host's authority feed, that the feed changed. The announcement carries nothing
//! of what changed. The feed is the record and the host polls it, so an announcement saves the
//! latency of the poll and is worth nothing else: a host that never sees one still learns every
//! revocation from the feed, and an announcement that is forged, replayed or lost changes nothing
//! the feed does not already say.
//!
//! # Where the host reads
//!
//! A feed places the announcement in the mailbox of its own service, so the host reads the mailbox
//! at the service `authority.origin` names, and only when it selects one. `mailbox.origin` names
//! where the host places the objects of its notifications, which is another choice: a host may put
//! those in one service and read its feed at another.
//!
//! # What the host takes from the mailbox
//!
//! An item is taken only if it opens against the stored-envelope key of a device this host has
//! paired and whose pairing is in force (a device that is revoked, or whose grant has run out and
//! the end is on record, is no sender), under the rules of section 20 ([`kr_crypto::envelope`]):
//! the routing record outside the envelope is untrusted and must match what the box authenticated,
//! the expiry must not have passed at the moment the item is opened, and an identifier the host has
//! accepted before is refused. Anything else is dropped. An item that opens but is not an
//! announcement that the feed changed is taken off the service and does nothing: the mailbox
//! carries no keystroke, command, decision or closure, and nothing the host reads from it executes
//! anything. A payload that bears authority is refused here whatever it says, because this host
//! takes its authority from its feed and from its own records.
//!
//! # What is durable, and in which order
//!
//! The identifier of an item the host accepted is written down ([`record::Record`]) before the host
//! acts on the item, and the host acknowledges a page to the service only after every accepted item
//! on it is written down. A host that stops between the two reads the item again and refuses it as
//! a replay, and then acknowledges it. An acknowledgement whose answer was lost is made again by
//! the next pass for the same reason. No item the host accepted leaves the service before it is on
//! record; an item the host dropped leaves it without a record, because nothing it could be
//! replayed to do is done. An identifier is forgotten a day after the item would have expired.
//!
//! # When the host asks
//!
//! When the daemon starts and every [`POLL_INTERVAL`] after that. A service that asks to be left
//! alone is left alone for as long as it asked.

pub mod record;

use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::time::Duration;

use kr_client::error::ClientError;
use kr_client::services::mailbox::MailboxClient;
use kr_client::services::{
    HttpDeadlines, HttpService, ServiceHttp, ServiceSigner, managed_response_limits,
};
use kr_crypto::envelope::{PairedSenders, open_delivered_envelope};
use kr_crypto::keys::StoredEnvelopeKeyPair;
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::export::Sentence;
use kr_protocol::hostinfo::{DoctorCheck, DoctorStatus};
use kr_protocol::mailbox::MailboxPayloadType;
use kr_protocol::service::GatewayOrigin;
use kr_transport::config::ProxyUrl;
use kr_transport::reconnect::Backoff;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::error::{ControllerError, Result};
use crate::quiet::{Quiet, Timer};
use crate::service::Controller;
use crate::service::net::devices::DeviceDirectory;
use record::Record;

/// The deadlines the mailbox service's exchanges are made under. A read answers a page of items,
/// which is larger than the feed's answers.
pub const MAILBOX_DEADLINES: HttpDeadlines = HttpDeadlines {
    connect: Duration::from_secs(5),
    read: Duration::from_secs(15),
    total: Duration::from_secs(30),
};

/// How often the host reads its mailbox when nothing asked for a pass sooner. It is shorter than
/// the poll of the authority feed, which is what an announcement exists to beat.
pub const POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The most pages one pass reads before it waits, so a mailbox that fills as fast as it is read
/// does not hold the pass for ever.
const MOST_PAGES: usize = 16;

/// The mailbox client for `origin`, signing as the host.
///
/// # Errors
///
/// Returns [`ControllerError::NotConfigured`] when the transport cannot be built, which is a fault
/// in this machine's TLS configuration rather than in the service.
pub fn managed_client(
    origin: &GatewayOrigin,
    proxy: Option<&ProxyUrl>,
    signer: Arc<dyn ServiceSigner>,
) -> Result<MailboxClient> {
    let http: Arc<dyn ServiceHttp> = Arc::new(
        HttpService::through(
            origin.clone(),
            MAILBOX_DEADLINES,
            managed_response_limits(),
            proxy,
        )
        .map_err(|error| {
            ControllerError::NotConfigured(format!(
                "{} in this host's configuration document ({}) names a service no transport \
                 reaches: {error}",
                kr_protocol::hostinfo::configuration::AUTHORITY_ORIGIN.key,
                kr_protocol::hostinfo::configuration::FILE_NAME,
            ))
        })?,
    );
    Ok(MailboxClient::new(origin.clone(), http, signer).leaving_delays_to_the_caller())
}

/// Why a pass stopped before it had read the mailbox through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stopped {
    /// The service could not be reached, asked for a delay, or answered something this client
    /// cannot read.
    Unreachable,
    /// The service turned a request back for a reason only the owner can change.
    Refused(ErrorCode),
    /// This host could not read its devices or write its record. The service is not at fault.
    Local,
}

impl Stopped {
    fn of(error: &ClientError, quiet: &Quiet) -> Self {
        match error {
            ClientError::Refused {
                error: refused,
                retry_after_seconds,
                ..
            } => {
                if let Some(seconds) = retry_after_seconds {
                    quiet.owe(Duration::from_secs(*seconds));
                }
                match refused.code {
                    code @ (ErrorCode::PermissionDenied
                    | ErrorCode::InvalidArgument
                    | ErrorCode::HostNotConfigured) => Self::Refused(code),
                    _ => Self::Unreachable,
                }
            }
            _ => Self::Unreachable,
        }
    }

    fn local(error: &ControllerError) -> Self {
        eprintln!(
            "kr-controller: the host could not read its devices or use its mailbox record: {error}"
        );
        Self::Local
    }
}

/// What the reader has seen, for `kr doctor`.
#[derive(Debug, Default)]
struct Observed {
    /// When a pass last read the mailbox through, in UTC milliseconds on this host's clock.
    read_at_ms: Option<u64>,
    /// How the last pass ended, when it did not read the mailbox through.
    stopped: Option<Stopped>,
    /// Items accepted, items accepted and ignored because they are not announcements that the
    /// feed changed, and items dropped, since the daemon started.
    announcements: u64,
    ignored: u64,
    dropped: u64,
}

/// What the reader shares with the daemon.
struct Shared {
    client: MailboxClient,
    origin: String,
    key: StoredEnvelopeKeyPair,
    record: Arc<Record>,
    quiet: Quiet,
    /// How many times the reader has begun to wait between two passes.
    passes: watch::Sender<u64>,
    observed: Mutex<Observed>,
    running: OnceLock<Running>,
}

/// What the reader was given when the daemon started it.
struct Running {
    controller: Weak<Controller>,
    devices: Arc<DeviceDirectory>,
}

impl Shared {
    fn observed(&self) -> std::sync::MutexGuard<'_, Observed> {
        self.observed.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs `body` on the record where a blocking call may wait.
    async fn on_record<T: Send + 'static>(
        &self,
        body: impl FnOnce(&Record) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let record = Arc::clone(&self.record);
        tokio::task::spawn_blocking(move || body(&record))
            .await
            .map_err(|_| {
                ControllerError::registry("the mailbox replay record could not be reached")
            })?
    }
}

/// The host's reader of its own mailbox.
pub struct MailboxReader {
    shared: Arc<Shared>,
    timer: Arc<dyn Timer>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for MailboxReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MailboxReader")
            .field("origin", &self.shared.origin)
            .finish_non_exhaustive()
    }
}

impl MailboxReader {
    /// Builds the reader of the mailbox at `origin`, which is addressed by `key`'s public half and
    /// claimed by the credential `client` signs with. Nothing runs and nothing is sent until
    /// [`Self::run`].
    #[must_use]
    pub fn new(
        client: MailboxClient,
        origin: &GatewayOrigin,
        key: StoredEnvelopeKeyPair,
        record: Record,
        timer: Arc<dyn Timer>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                client,
                origin: origin.as_str().to_owned(),
                key,
                record: Arc::new(record),
                quiet: Quiet::new(Arc::clone(&timer)),
                passes: watch::channel(0).0,
                observed: Mutex::default(),
                running: OnceLock::new(),
            }),
            timer,
            task: Mutex::new(None),
        }
    }

    /// Starts the reader for a daemon whose paired devices are the ones in `devices`. It does
    /// nothing the second time.
    pub fn run(&self, controller: &Arc<Controller>, devices: Arc<DeviceDirectory>) {
        if self
            .shared
            .running
            .set(Running {
                controller: Arc::downgrade(controller),
                devices,
            })
            .is_err()
        {
            return;
        }
        let task = tokio::spawn(drive(Arc::clone(&self.shared), Arc::clone(&self.timer)));
        *self.task.lock().unwrap_or_else(PoisonError::into_inner) = Some(task);
    }

    /// A count that changes each time the reader begins to wait between two passes: after every
    /// pass, whether it read the mailbox through, stopped on a fault or stopped at the page limit,
    /// and after a wait that made no pass because the service had asked to be left alone.
    #[must_use]
    pub fn passes(&self) -> watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// The record of the items this host accepted.
    #[must_use]
    pub fn record(&self) -> &Arc<Record> {
        &self.shared.record
    }

    /// What `kr doctor` says of the reader.
    #[must_use]
    pub fn doctor_check(&self, controller: &Controller) -> DoctorCheck {
        let observed = self.shared.observed();
        let now = controller.wall_now_ms();
        let read = match observed.read_at_ms {
            Some(at) => Sentence::new()
                .stated("it was last read ")
                .number(now.saturating_sub(at) / 1000)
                .stated(" seconds ago"),
            None => Sentence::new().stated("it has not been read yet"),
        };
        // The announcement is a hint beside the feed, so what a reader that cannot read costs the
        // host depends on whether the feed is still read.
        let feed = if controller
            .authority_feed()
            .status()
            .removed_at_ms
            .0
            .is_some()
        {
            "; the authority feed was removed, so no revocation reaches this host from it"
        } else {
            "; this host still reads its authority feed at the feed's own poll"
        };
        let reads = Sentence::new().stated("this host reads its own mailbox");
        let (status, detail, remedy): (DoctorStatus, Sentence, Option<&'static str>) =
            match observed.stopped {
                Some(Stopped::Unreachable) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(", which could not be reached; ")
                        .sentence(&read)
                        .stated(feed),
                    Some("This host asks again by itself."),
                ),
                Some(Stopped::Refused(_)) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(", which turned a request back; ")
                        .sentence(&read)
                        .stated(feed),
                    Some(
                        "Check that this host's clock is right and that `authority.origin` in the \
                         configuration document names a service that accepts this host. A mailbox \
                         that another key has claimed stays claimed, so a host whose \
                         authorisation key changed is refused there for good, and the authority \
                         feed it reads is the one its new key addresses. This host asks again by \
                         itself.",
                    ),
                ),
                Some(Stopped::Local) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(
                            ", but could not read its devices or write its record of the items \
                             it has accepted; ",
                        )
                        .sentence(&read)
                        .stated(feed),
                    Some(
                        "This host accepts nothing it cannot write down, and asks again by \
                         itself. Check the daemon's state directory for space and permissions.",
                    ),
                ),
                None => (DoctorStatus::Ok, reads.stated("; ").sentence(&read), None),
            };
        let detail = detail
            .stated("; ")
            .number(observed.announcements)
            .stated(" announcement(s) taken, ")
            .number(observed.ignored)
            .stated(" ignored, ")
            .number(observed.dropped)
            .stated(" dropped since this daemon started");
        DoctorCheck::new(
            "mailbox-reader",
            "This host reads its own mailbox",
            status,
            detail,
            remedy,
        )
    }

    /// What `kr doctor` says of a host that selects no authority feed.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "mailbox-reader",
            "This host reads its own mailbox",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no authority feed is selected, so this host reads no mailbox, nothing is \
                 announced to it, and it learns no remote revocation",
            ),
            None,
        )
    }
}

impl Drop for MailboxReader {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

/// What the reader does for as long as the daemon lives.
async fn drive(shared: Arc<Shared>, timer: Arc<dyn Timer>) {
    let mut backoff = Backoff::default();
    loop {
        let Some(running) = shared.running.get() else {
            return;
        };
        let Some(controller) = running.controller.upgrade() else {
            return;
        };
        let wait = if let Some(left) = shared.quiet.left() {
            // The service asked to be left alone, and every question to it waits.
            left
        } else {
            match pass(&shared, running, &controller).await {
                Ok(()) => {
                    backoff = Backoff::default();
                    POLL_INTERVAL
                }
                Err(stopped) => {
                    shared.observed().stopped = Some(stopped);
                    backoff
                        .next_delay()
                        .max(shared.quiet.left().unwrap_or_default())
                }
            }
        };
        drop(controller);
        // The wait is asked for before the pass is counted, so whoever sees the count change finds
        // the reader waiting.
        let sleeping = timer.sleep(wait);
        shared.passes.send_modify(|passes| *passes += 1);
        sleeping.await;
    }
}

/// One pass: read the mailbox page by page, take what opens, write each accepted identifier down,
/// act on what was taken, and tell the service what is stored.
async fn pass(
    shared: &Arc<Shared>,
    running: &Running,
    controller: &Arc<Controller>,
) -> std::result::Result<(), Stopped> {
    let now = controller.wall_now_ms();
    let devices = Arc::clone(&running.devices);
    let senders = tokio::task::spawn_blocking(move || -> Result<PairedSenders> {
        let mut senders = PairedSenders::new();
        for device in devices.devices()? {
            if device.is_paired()
                && let Some(key) = device.stored_envelope
            {
                senders.pair(key);
            }
        }
        Ok(senders)
    })
    .await
    .map_err(|_| Stopped::Local)?
    .map_err(|error| Stopped::local(&error))?;
    // The record is the source of truth for what has been accepted: the ledger is read from it for
    // each pass, so an identifier that was not written down is not one the pass remembers.
    let mut ledger = shared
        .on_record(move |record| record.ledger(now))
        .await
        .map_err(|error| Stopped::local(&error))?;

    let mut read_through = false;
    for _ in 0..MOST_PAGES {
        let page = shared
            .client
            .read_as(&shared.key, None)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        let Some(last) = page.items.last().map(|item| item.sequence.get()) else {
            read_through = true;
            break;
        };
        let mut announced = false;
        let mut unwritten = None;
        for item in &page.items {
            // Read for each item: the expiry is judged at the moment the item is opened, not at
            // the moment the pass began, which may be a page of exchanges ago.
            let opened = open_delivered_envelope(
                &shared.key,
                &senders,
                &mut ledger,
                &item.envelope,
                controller.wall_now_ms(),
                // Authority comes to this host from its feed and its own records. An item that
                // claims some in its payload is refused whoever sealed it.
                |_| {
                    Err(kr_crypto::CryptoError::BindingMismatch {
                        what: "a payload that bears authority, which this host does not take from \
                               its mailbox",
                    })
                },
            );
            match opened {
                Ok(plaintext) => {
                    // Written down before anything is done with it, and before the service is
                    // told it may remove the item.
                    let id = plaintext.envelope_id;
                    let until = kr_protocol::mailbox::replay_id_retained_until_ms(
                        plaintext.expires_at_ms.get(),
                    );
                    if let Err(error) = shared
                        .on_record(move |record| record.remember(id, until))
                        .await
                    {
                        unwritten = Some(Stopped::local(&error));
                        break;
                    }
                    if plaintext.payload_type == MailboxPayloadType::AuthorityFeedChange {
                        announced = true;
                        shared.observed().announcements += 1;
                    } else {
                        shared.observed().ignored += 1;
                    }
                }
                Err(_) => shared.observed().dropped += 1,
            }
        }
        // The announcement says the feed changed, and the carrier reads it now rather than at its
        // next poll. What is on record is acted on even when a later item on the page could not
        // be written down: that item is read again, and nothing is acknowledged until it is.
        if announced && let Some(feed) = controller.feed_runtime() {
            feed.wake();
        }
        if let Some(stopped) = unwritten {
            return Err(stopped);
        }
        // Everything on the page is written down or dropped, so the service may remove it.
        shared
            .client
            .acknowledge(shared.key.public(), last)
            .await
            .map_err(|error| Stopped::of(&error, &shared.quiet))?;
        if !page.more {
            read_through = true;
            break;
        }
    }
    let mut observed = shared.observed();
    observed.stopped = None;
    if read_through {
        observed.read_at_ms = Some(now);
    }
    Ok(())
}
