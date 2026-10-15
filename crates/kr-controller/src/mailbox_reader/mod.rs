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
//! # What the host takes from the mailbox
//!
//! An item is taken only if it opens against the stored-envelope key of a device this host has
//! paired and has not unpaired, under the rules of section 20 ([`kr_crypto::envelope`]): the
//! routing record outside the envelope is untrusted and must match what the box authenticated, the
//! expiry must not have passed, and an identifier the host has accepted before is refused. Anything
//! else is dropped. An item that opens but is not an announcement that the feed changed is taken
//! off the service and does nothing: the mailbox carries no keystroke, command, decision or
//! closure, and nothing the host reads from it executes anything. A payload that bears authority is
//! refused here whatever it says, because this host takes its authority from its feed and from its
//! own records.
//!
//! # What is durable, and in which order
//!
//! The identifier of an item the host accepted is written down ([`record::Record`]) before the host
//! acts on the item, and the host acknowledges an item to the service only after that write. A host
//! that stops between the two reads the item again and refuses it as a replay, and then
//! acknowledges it. An acknowledgement whose answer was lost is made again by the next pass for the
//! same reason. Nothing the service holds is removed before the host has it written down, and an
//! identifier is forgotten a day after the item would have expired.
//!
//! # When the host asks
//!
//! When the daemon starts, every [`POLL_INTERVAL`] after that, and when a pass is asked for. A
//! service that asks to be left alone is left alone for as long as it asked.

pub mod record;

use std::sync::atomic::{AtomicU64, Ordering};
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
use tokio::sync::{Notify, watch};
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
                kr_protocol::hostinfo::configuration::MAILBOX_ORIGIN.key,
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
        eprintln!("kr-controller: the host could not use its mailbox record: {error}");
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
    wake: Notify,
    /// How many passes have been asked for, by whoever needs to know the reader has looked since.
    requested: AtomicU64,
    /// The newest request count that a pass which began after the request was made has finished.
    completed: watch::Sender<u64>,
    /// How many passes have finished.
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
                wake: Notify::new(),
                requested: AtomicU64::new(0),
                completed: watch::channel(0).0,
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

    /// Asks for a pass now, without waiting for it.
    pub fn wake(&self) {
        self.shared.wake.notify_one();
    }

    /// A count of the passes the reader has finished, which changes each time one ends.
    #[must_use]
    pub fn passes(&self) -> watch::Receiver<u64> {
        self.shared.passes.subscribe()
    }

    /// The record of the items this host accepted.
    #[must_use]
    pub fn record(&self) -> &Arc<Record> {
        &self.shared.record
    }

    /// Waits until the reader has finished a pass that began after this call, so that whatever
    /// was true when it was made is what the pass read. For a suite that arranges the world and
    /// then needs the reader to have looked at it.
    #[cfg(feature = "testing")]
    pub async fn after_a_pass(&self) {
        let ticket = self.shared.requested.fetch_add(1, Ordering::SeqCst) + 1;
        let mut completed = self.shared.completed.subscribe();
        self.shared.wake.notify_one();
        while *completed.borrow_and_update() < ticket {
            if completed.changed().await.is_err() {
                return;
            }
        }
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
        let reads = Sentence::new().stated("this host reads its own mailbox");
        let (status, detail, remedy): (DoctorStatus, Sentence, Option<&'static str>) =
            match observed.stopped {
                Some(Stopped::Unreachable) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(", which could not be reached; ")
                        .sentence(&read),
                    Some(
                        "This host asks again by itself. A remote owner's revocation still \
                         reaches it from its authority feed: the mailbox only announces it.",
                    ),
                ),
                Some(Stopped::Refused(_)) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(
                            ", which turned a request back: another key may hold the mailbox, \
                                 or this host's key is not one it accepts; ",
                        )
                        .sentence(&read),
                    Some(
                        "Check `mailbox.origin` in the configuration document. This host asks \
                         again by itself, and a remote owner's revocation still reaches it from \
                         its authority feed.",
                    ),
                ),
                Some(Stopped::Local) => (
                    DoctorStatus::Warning,
                    reads
                        .stated(", but could not use its record of the items it has accepted; ")
                        .sentence(&read),
                    Some(
                        "This host reads nothing it cannot write down, and tries again by itself.",
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

    /// What `kr doctor` says of a host that selects no mailbox service.
    #[must_use]
    pub fn unconfigured_check() -> DoctorCheck {
        DoctorCheck::new(
            "mailbox-reader",
            "This host reads its own mailbox",
            DoctorStatus::NotApplicable,
            Sentence::new().stated(
                "no mailbox service is selected, so nothing is announced to this host; it learns \
                 a remote owner's revocation from its authority feed at the next poll",
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
        // Every request made before this point is answered by the pass that follows it.
        let target = shared.requested.load(Ordering::SeqCst);
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
        shared.completed.send_replace(target);
        shared.passes.send_modify(|passes| *passes += 1);
        // Interest in a wake is registered before the count of questions is read again, so a
        // question asked in between is either seen by the read or wakes the wait: none is lost.
        let woken = shared.wake.notified();
        tokio::pin!(woken);
        woken.as_mut().enable();
        if shared.requested.load(Ordering::SeqCst) > target {
            continue;
        }
        tokio::select! {
            () = &mut woken => {}
            () = timer.sleep(wait) => {}
        }
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

    let mut announced = false;
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
        for item in &page.items {
            let opened = open_delivered_envelope(
                &shared.key,
                &senders,
                &mut ledger,
                &item.envelope,
                now,
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
                    shared
                        .on_record(move |record| record.remember(id, until))
                        .await
                        .map_err(|error| Stopped::local(&error))?;
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
        if announced && let Some(feed) = controller.feed_runtime() {
            // The announcement says the feed changed, and the carrier reads it now rather than at
            // its next poll. It is made once the identifiers are on record and before the service
            // is told, so that an acknowledgement the service does not hear costs the hint nothing:
            // the item is read again and refused as a replay.
            feed.wake();
        }
        announced = false;
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
