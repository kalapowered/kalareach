//! The attention inboxes of the hosts this device is paired with and is not using.
//!
//! The primary mobile surface is an inbox across hosts and sessions (section 13). The phone's
//! commands go to one host, the one in use, whose inbox the page reads like any other read. The
//! other hosts are read here: one authorised connection to each, opened as the device the host made
//! it, for the host alone, and kept while it answers. Each visit reads the whole inbox and the
//! session numbers the rows are named by, and ends within [`VISIT_WITHIN`], so a host that takes the
//! connection and answers nothing is out of contact for that pass and holds up no other.
//!
//! What a visit finds is the owner's ([`crate::contact`]): the contact with each host, since when
//! contact was lost, the inbox last read and the connection it was read over are held there, and
//! each visit commits its outcome as it ends. A host that cannot be reached, or does not answer in
//! time, is out of contact: that says nothing of what its sessions are doing, and the loss has the
//! moment this device noted it. A host that answers and refuses is in contact, and is not that: it
//! is shown as having refused, with the request of the visit it refused (the connection, who it is,
//! the opening of its session, or its inbox) and the refusal it sent, and no loss of contact is
//! noted for it. A host that is out of its offline-validity bound refuses all of them alike, so the
//! words it gives cannot say which. So is a host of a member's device that cannot be given the lease
//! its organisation signs for it, because the device is signed out or is not a member: the refusal
//! is the reason in words, and the host is asked nothing.
//!
//! A pass answers with what the owner holds of each host it visited, read together, and checks the
//! account each read was made for. Nothing is written to disk: a run that has just started has no
//! loss to report, and says only that contact is not there.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use kr_client::ClientError;
use kr_client::organisation::lease_is_refused;
use kr_client::pairing::link::{LinkError, Presentation};
use kr_client::pairing::paired::PairedHost;
use kr_protocol::attention::{AttentionReadParams, AttentionReadResult};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{DeviceId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Nullable, U64};
use kr_protocol::session::{DisplayNumber, SessionListParams, SessionListResult};
use serde::Serialize;
use serde::ser::SerializeStruct as _;

use crate::connection::{Asked, Connection, Unanswered, Unopened};
use crate::contact::{
    Admit, Begin, Committed, ContactOwner, Found, Outcome, Row, StoredRead, VisitTicket,
};
use crate::device::Device;
use crate::error::CommandError;

/// How long one visit to a host may take, from connecting to the end of its answer. A host that has
/// not answered by then is out of contact until the next pass.
pub const VISIT_WITHIN: Duration = Duration::from_secs(10);

/// The most items one page of a host's inbox is asked for.
const PAGE_ITEMS: u64 = 200;

/// The most pages one read of an inbox follows: sixteen pages hold every item a host retains.
const MAX_PAGES: usize = 16;

/// How many times a pass retires the reads whose account has left and looks again before it hands
/// on a row with its read left out.
const RETIREMENTS: usize = 3;

/// A session of a host, by the number the host gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NumberedSession {
    /// The session.
    pub session_id: SessionId,
    /// The number the host shows for it.
    pub display_number: DisplayNumber,
}

/// What a pass found of one host: the inbox the owner holds of it, when it holds one. How contact
/// with the host stands is the owner's publication's, in `others`.
#[derive(Clone, Debug)]
pub struct HostInbox {
    /// The host, by the reference the pairing screen lists it under.
    pub reference: String,
    /// The name the host gives people.
    pub name: String,
    /// The page may show an inbox of this host only under this epoch.
    pub inbox_epoch: u64,
    read: Option<Arc<StoredRead>>,
}

impl HostInbox {
    fn of(row: &Row) -> Self {
        Self {
            reference: row.reference.clone(),
            name: row.name.clone(),
            inbox_epoch: row.inbox_epoch,
            read: row.read.clone(),
        }
    }

    /// The order the inbox was read in, among every read of every host.
    #[must_use]
    pub fn read_serial(&self) -> Option<u64> {
        self.read.as_ref().map(|read| read.serial())
    }

    /// When the inbox was read, as this device's clock says, when it was.
    #[must_use]
    pub fn read_at_ms(&self) -> Option<u64> {
        self.read.as_ref().map(|read| read.read_at_ms())
    }

    /// The host's inbox, when it was read.
    #[must_use]
    pub fn result(&self) -> Option<&AttentionReadResult> {
        self.read.as_ref().map(|read| read.result())
    }

    /// The host's sessions by number, when its inbox was read.
    #[must_use]
    pub fn sessions(&self) -> &[NumberedSession] {
        self.read.as_ref().map_or(&[], |read| read.sessions())
    }
}

impl Serialize for HostInbox {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut row = serializer.serialize_struct("HostInbox", 7)?;
        row.serialize_field("reference", &self.reference)?;
        row.serialize_field("name", &self.name)?;
        row.serialize_field("inbox_epoch", &self.inbox_epoch)?;
        row.serialize_field("read_serial", &self.read_serial())?;
        row.serialize_field("read_at_ms", &self.read_at_ms())?;
        row.serialize_field("result", &self.result())?;
        row.serialize_field("sessions", self.sessions())?;
        row.end()
    }
}

/// What a pass answers: the rows, and the revision of the owner they were read at.
#[derive(Clone, Debug, Serialize)]
pub struct InboxHosts {
    /// The revision the owner stood at when the rows were read.
    pub revision: u64,
    /// One row for each host visited that is still one of the others, in the order the pairing
    /// screen lists them.
    pub hosts: Vec<HostInbox>,
}

/// Visits the hosts this device is paired with and is not using, and answers with what the owner
/// holds of each.
#[derive(Debug)]
pub struct InboxDesk {
    owner: Arc<ContactOwner>,
    /// Where a suite has paused the desk's passes and visits.
    #[cfg(feature = "testing")]
    pauses: testing::Pauses,
}

/// A desk of an owner of its own: the seam of a suite that builds the desk itself. The application's
/// desk is made with the owner its state holds.
#[cfg(feature = "testing")]
impl Default for InboxDesk {
    fn default() -> Self {
        Self::with_owner(Arc::new(ContactOwner::new()))
    }
}

/// A connection a visit holds. It closes its session when it is dropped, whether the visit ended,
/// failed or was cut off by [`VISIT_WITHIN`]: the record is another owner of a read's origin, so
/// dropping the future that holds a connection would not release it. Only an accepted commit gives
/// the connection to the record.
struct VisitConnection(Option<Arc<Connection>>);

impl VisitConnection {
    fn new(connection: Arc<Connection>) -> Self {
        Self(Some(connection))
    }

    fn connection(&self) -> &Arc<Connection> {
        self.0.as_ref().expect("a held connection is present")
    }

    /// The record has the connection: it is no longer this guard's to close.
    fn handed_over(mut self) {
        self.0 = None;
    }
}

impl Drop for VisitConnection {
    fn drop(&mut self) {
        if let Some(connection) = self.0.take() {
            connection.session().close();
        }
    }
}

/// What one visit to a host came to.
enum Visited {
    /// The host answered with its inbox.
    Read(VisitConnection, AttentionReadResult, Vec<NumberedSession>),
    /// The host answered, and a second page conflict left no complete inbox.
    Answered(VisitConnection),
    /// The host answered and refused the request named.
    Refused(Asked, CommandError),
    /// The host could not be reached or did not answer.
    Unreached,
}

/// Why a read of an inbox ended without it.
enum Missed {
    /// The host answered the request named with an error.
    Refused(Asked, CommandError),
    /// The host did not answer, or the answer was no reply to the question.
    Unreached,
}

impl From<Unopened> for Missed {
    fn from(unopened: Unopened) -> Self {
        match Outcome::of(&unopened) {
            Outcome::Refused { refusal, request } => Self::Refused(request, refusal),
            Outcome::InContact | Outcome::Lost => Self::Unreached,
        }
    }
}

impl From<Missed> for Visited {
    fn from(missed: Missed) -> Self {
        match missed {
            Missed::Refused(asked, refusal) => Self::Refused(asked, refusal),
            Missed::Unreached => Self::Unreached,
        }
    }
}

impl InboxDesk {
    /// A desk that keeps what its visits find in `owner`.
    #[must_use]
    pub fn with_owner(owner: Arc<ContactOwner>) -> Self {
        Self {
            owner,
            #[cfg(feature = "testing")]
            pauses: testing::Pauses::default(),
        }
    }

    /// Visits every paired host that is not the one in use, all at once, each over a connection of
    /// its own, and answers with what the owner holds of each, in the order the pairing screen lists
    /// them. A host this device forgot, or began to use, while it was visited is not among them. A
    /// read made for an account that has left by the time the answer is ready is retired, and not
    /// handed on.
    pub async fn visit(self: &Arc<Self>, device: &Arc<Device>) -> InboxHosts {
        let Ok(listed) = device.pairing().hosts.list() else {
            return InboxHosts {
                revision: self.owner.revision(),
                hosts: Vec::new(),
            };
        };
        let in_use = device.host_in_use().map(|host| host.host_device_id);
        let hosts: Vec<PairedHost> = listed
            .iter()
            .filter(|host| Some(host.host_device_id) != in_use)
            .cloned()
            .collect();
        self.reconcile(device, &listed);
        #[cfg(feature = "testing")]
        self.at_the_pass().await;
        let visits: Vec<_> = hosts
            .iter()
            .cloned()
            .map(|host| {
                let (desk, device) = (Arc::clone(self), Arc::clone(device));
                tauri::async_runtime::spawn(async move { desk.visit_one(&device, &host).await })
            })
            .collect();
        for visit in visits {
            let _ = visit.await;
        }
        let ids: Vec<DeviceId> = hosts.iter().map(|host| host.host_device_id).collect();
        self.answer(&ids).await
    }

    /// Lets go of the record of a host that is no longer listed, once the pairing it belongs to is
    /// found to be gone. A record that changed meanwhile, or is the one in use, is left alone. A
    /// pairing that cannot be read now decides nothing.
    fn reconcile(&self, device: &Device, listed: &[PairedHost]) {
        let present: BTreeSet<DeviceId> = listed.iter().map(|host| host.host_device_id).collect();
        for record in self.owner.paired_records() {
            if present.contains(&record.host) {
                continue;
            }
            if let Ok(now) = device.paired_as(record.host)
                && now != Some(record.pairing)
            {
                drop(self.owner.remove_record(&record));
            }
        }
    }

    /// What the owner holds of `hosts` now, with every read checked against the account it was made
    /// for. A read whose connection this device ended is retired, and the owner is read again; after
    /// three rounds a row that still fails is handed on without its read: an unchecked read is never
    /// returned.
    async fn answer(&self, hosts: &[DeviceId]) -> InboxHosts {
        let mut records = self.owner.records(hosts);
        for round in 0..=RETIREMENTS {
            let failing: Vec<(usize, CommandError)> = records
                .rows
                .iter()
                .enumerate()
                .filter_map(|(at, row)| {
                    let read = row.read.as_ref()?;
                    read.origin()
                        .ended_by_this_device()
                        .map(|refusal| (at, refusal))
                })
                .collect();
            if failing.is_empty() {
                break;
            }
            #[cfg(feature = "testing")]
            if round == 0 {
                self.at_the_check().await;
            }
            if round == RETIREMENTS {
                for (at, _) in failing {
                    records.rows[at].clear_read();
                }
                break;
            }
            for (at, refusal) in failing {
                drop(self.owner.retire_read(&records.rows[at], refusal));
            }
            records = self.owner.records(hosts);
        }
        InboxHosts {
            revision: records.revision,
            hosts: records.rows.iter().map(HostInbox::of).collect(),
        }
    }

    /// One visit to `host`. It writes nothing unless the owner takes it in as a visit to a host that
    /// is one of the others and is still the pairing it was listed under, at its start and just
    /// before its commit.
    async fn visit_one(&self, device: &Arc<Device>, host: &PairedHost) {
        let fence = self.owner.fence();
        if !still_paired_as(device, host.host_device_id, host.device_id) {
            return;
        }
        let target = crate::hosts::target_of(host);
        let (ticket, gate) = match self.owner.admit(&target, fence).value {
            Admit::Admitted { ticket, gate } => (ticket, gate),
            Admit::Stale => return,
            Admit::Mismatch { ticket } => {
                // The record is of another pairing: it is replaced only when the pairing the host
                // was listed under is still the one this device has.
                if !still_paired_as(device, host.host_device_id, host.device_id) {
                    return;
                }
                #[cfg(feature = "testing")]
                self.at_the_replace(host.host_device_id).await;
                match self.owner.replace(&ticket, &target, fence).value {
                    Admit::Admitted { ticket, gate } => (ticket, gate),
                    Admit::Mismatch { .. } | Admit::Stale => return,
                }
            }
        };
        #[cfg(feature = "testing")]
        self.at_the_admission(host.host_device_id);
        let _turn = gate.lock().await;
        let retained = match self.owner.begin_visit(&ticket).value {
            Begin::Go(retained) => retained,
            Begin::Refused => return,
        };
        let visited = tokio::time::timeout(
            VISIT_WITHIN,
            read_host(device, host, retained.map(VisitConnection::new)),
        )
        .await
        .unwrap_or(Visited::Unreached);
        #[cfg(feature = "testing")]
        self.at_the_visit(host.host_device_id).await;
        // A re-pair since the visit began is refused here, and nothing is committed over the old
        // pairing. One that comes after this check and before the commit can still commit one read
        // over it; the next visit finds another pairing and replaces the record.
        if !still_paired_as(device, host.host_device_id, host.device_id) {
            drop(visited);
            drop(self.owner.discard(&ticket));
            return;
        }
        self.commit(&ticket, visited);
    }

    /// Hands what a visit found to the owner. The connection a visit holds goes to the record only
    /// when the owner accepts the commit; otherwise it closes with the guard.
    fn commit(&self, ticket: &VisitTicket, visited: Visited) {
        let (found, held) = match visited {
            Visited::Read(connection, result, sessions) => (
                Found::Inbox {
                    connection: Arc::clone(connection.connection()),
                    result,
                    sessions,
                },
                Some(connection),
            ),
            Visited::Answered(connection) => (
                Found::Answered {
                    connection: Arc::clone(connection.connection()),
                },
                Some(connection),
            ),
            Visited::Refused(request, refusal) => (Found::Refused { refusal, request }, None),
            Visited::Unreached => (Found::Lost, None),
        };
        let committed = self.owner.commit_visit(ticket, found);
        if matches!(committed.value, Committed::Accepted)
            && let Some(connection) = held
        {
            connection.handed_over();
        }
    }
}

/// Whether this device is paired with `host` as `pairing` now. A pairing list that cannot be read
/// verifies nothing.
fn still_paired_as(device: &Device, host: DeviceId, pairing: DeviceId) -> bool {
    device.paired_as(host).ok().flatten() == Some(pairing)
}

/// Reads `host`'s inbox over the connection held, or over a fresh one when there is none or it no
/// longer answers. A refusal on the connection held is the host's answer, unless it may be the end
/// of the lease, and a fresh connection is not made to ask again.
///
/// A host that answers a member's device only while it holds the lease its organisation signed
/// stops answering the connection held when that lease ends, and nothing keeps the lease of a host
/// that is not in use fresh. So the lease is presented again over the connection when the one the
/// host holds is due to be replaced, which asks the organisation's service for a new one, and not
/// before: each presentation is a row the host keeps. A host that refuses a read as not permitted
/// may have lost the lease, and is given the lease the device holds, or a new one if the host
/// refuses that, before the read is made once more.
///
/// A connection is bound to the account signed in when it was dialled, and ends when that account
/// signs out or another signs in ([`crate::bound`]). A pass decides once, at its end, whether its
/// connection is still that account's: if not, nothing it read is published, the connection is
/// closed, a kept one is replaced by a fresh one (which is refused with the words when no account
/// is signed in, and is the new account's otherwise), and a fresh one shows the words. The answer
/// of [`InboxDesk::visit`] asks again as it returns, since it waits for the slowest host.
async fn read_host(
    device: &Arc<Device>,
    host: &PairedHost,
    held: Option<VisitConnection>,
) -> Visited {
    if let Some(held) = held {
        let read = read_kept(device, host, held.connection()).await;
        if held.connection().ended_by_this_device().is_none() {
            match read {
                Ok(Some((result, sessions))) => return Visited::Read(held, result, sessions),
                Ok(None) => return Visited::Answered(held),
                // The connection held closes with its guard.
                Err(Missed::Refused(asked, refusal)) => return Visited::Refused(asked, refusal),
                Err(Missed::Unreached) => {}
            }
        }
        drop(held);
    }
    let connection = match Connection::visited(device, host).await {
        Ok(connection) => VisitConnection::new(Arc::new(connection)),
        Err(unopened) => return Missed::from(unopened).into(),
    };
    let read = read_over(connection.connection()).await;
    if let Some(refusal) = connection.connection().ended_by_this_device() {
        return Visited::Refused(Asked::Connection, refusal);
    }
    match read {
        Ok(Some((result, sessions))) => Visited::Read(connection, result, sessions),
        Ok(None) => Visited::Answered(connection),
        Err(missed) => missed.into(),
    }
}

/// Reads the inbox over a connection kept from an earlier visit.
async fn read_kept(
    device: &Arc<Device>,
    host: &PairedHost,
    connection: &Connection,
) -> Result<Option<(AttentionReadResult, Vec<NumberedSession>)>, Missed> {
    present(device, host, connection, Presentation::IfDue).await?;
    match read_over(connection).await {
        Err(Missed::Refused(_, refusal)) if lease_is_refused(refusal.code, &refusal.message) => {
            // The lease the host holds ended on its clock before this device's said it was due, or
            // the host lost it: it is presented again at once, whatever the lease is due.
            present(device, host, connection, Presentation::First).await?;
            read_over(connection).await
        }
        read => read,
    }
}

/// Presents, over `connection`, what the host needs of this device before it answers, as
/// `presentation` says: the lease of a member's device, and nothing for a host whose grant answers
/// to no organisation.
async fn present(
    device: &Arc<Device>,
    host: &PairedHost,
    connection: &Connection,
    presentation: Presentation,
) -> Result<(), Missed> {
    let pairing = device.pairing();
    let identity = pairing.paired_identity_for(host);
    pairing
        .link
        .present_membership(
            &connection.session(),
            &host.credentials(),
            &identity,
            presentation,
        )
        .await
        .map_err(|error| match error {
            LinkError::Refused(refusal) | LinkError::Declined(refusal) => {
                Missed::Refused(Asked::Connection, CommandError::from(refusal))
            }
            LinkError::Lost(_) | LinkError::Configuration(_) | LinkError::Selection(_) => {
                Missed::Unreached
            }
            // The host's refusal of the connection is told by its cause, as a first call on the
            // connection tells it.
            other => Unopened::of_link(other).into(),
        })
}

/// Reads the whole inbox and the session numbers over `connection`. `Ok(None)` when the host
/// answered and an item went between two pages twice: there is no complete inbox, and the host is in
/// contact.
async fn read_over(
    connection: &Connection,
) -> Result<Option<(AttentionReadResult, Vec<NumberedSession>)>, Missed> {
    let session = connection.session();
    let result = match pages(&session).await? {
        Some(result) => result,
        // An item went between two pages: the inbox is read again from its start, once.
        None => match pages(&session).await? {
            Some(result) => result,
            None => return Ok(None),
        },
    };
    // A host that answers its inbox and refuses its session list (a guest's grant may) still gave
    // its inbox: the rows then say "a session" for want of its number.
    let listed: Result<SessionListResult, ClientError> = session
        .read(
            Method::SessionList,
            &SessionListParams {
                environment_id: Nullable::null(),
                include_closed: false,
            },
        )
        .await;
    let sessions = match listed {
        Ok(listed) => listed
            .sessions
            .iter()
            .map(|each| NumberedSession {
                session_id: each.session_id,
                display_number: each.display_number,
            })
            .collect(),
        Err(error) => match Unanswered::of(error) {
            // The host refused its session list: its answer, and the rows say "a session".
            Err(_) => Vec::new(),
            // Anything else is the connection failing, and the inbox read beside it is not
            // published.
            Ok(silence) => return Err(Unopened::lost(silence).into()),
        },
    };
    Ok(Some((result, sessions)))
}

/// One walk over the inbox's pages, each continuing after the last item of the one before, until
/// the host says there is no more or the bound is reached. `Ok(None)` when a page continued after
/// an item the host no longer holds.
async fn pages(session: &kr_client::Session) -> Result<Option<AttentionReadResult>, Missed> {
    let mut after = Nullable::null();
    let mut items = Vec::new();
    let mut last: Option<AttentionReadResult> = None;
    for _ in 0..MAX_PAGES {
        let read: Result<AttentionReadResult, ClientError> = session
            .read(
                Method::AttentionRead,
                &AttentionReadParams {
                    session_id: Nullable::null(),
                    include_acknowledged: false,
                    max_items: U64::new(PAGE_ITEMS),
                    after: after.clone(),
                },
            )
            .await;
        let page = match read {
            Ok(page) => page,
            Err(ClientError::Host(refusal)) if refusal.code == ErrorCode::DraftConflict => {
                return Ok(None);
            }
            Err(error) => return Err(Unopened::of_read(Asked::AttentionRead, error).into()),
        };
        let more = page.more;
        let next = page.items.last().map(|item| item.key.clone());
        items.extend(page.items.iter().cloned());
        last = Some(page);
        match (more, next) {
            (true, Some(key)) => after = Nullable::some(key),
            _ => break,
        }
    }
    Ok(last.map(|mut page| {
        page.items = items;
        page
    }))
}

/// Seams the application's own suites act through.
#[cfg(feature = "testing")]
pub mod testing {
    use std::sync::{Mutex, PoisonError};

    use kr_protocol::ids::DeviceId;
    use tokio::sync::{mpsc, oneshot};

    use super::InboxDesk;
    use crate::connection::Asked;
    use crate::contact::{ContactOwner, HostContact};
    use crate::error::CommandError;
    use crate::inbox::HostInbox;
    use std::sync::Arc;

    /// Where a host stood when it was last visited, by the one mapping every case reads: an inbox
    /// that was read is `Read` (in contact, with a result), a refusal is `Refused`, and a loss is
    /// `OutOfContact`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum HostInboxState {
        /// The host answered, and the result is its inbox.
        Read,
        /// The host answered and refused. It is in contact: the refusal is what it said.
        Refused,
        /// The host could not be reached or did not answer in time.
        OutOfContact,
    }

    /// What the owner holds of the contact with a host, in the terms of [`HostInboxState`].
    #[derive(Clone, Debug)]
    pub struct Seen {
        /// Where the host stood.
        pub state: HostInboxState,
        /// What the host refused with, when it did.
        pub refusal: Option<CommandError>,
        /// What the visit asked when the host refused, when it did.
        pub refused_request: Option<Asked>,
        /// Since when this device has not been in contact with the host, when it has not.
        pub since_ms: Option<u64>,
    }

    /// A pass held after it listed the hosts and before it began a visit to any of them, until it is
    /// released.
    #[derive(Debug)]
    pub struct PassHold {
        release: oneshot::Sender<()>,
    }

    impl PassHold {
        /// Lets the pass go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// A visit held after its read ended and before the visit is checked and its outcome applied,
    /// until it is released.
    #[derive(Debug)]
    pub struct VisitHold {
        /// The host the visit is to.
        pub host: DeviceId,
        release: oneshot::Sender<()>,
    }

    impl VisitHold {
        /// Lets the visit go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// A pass held after it read the owner's records and found a read to retire, before it retires
    /// any, until it is released.
    #[derive(Debug)]
    pub struct CheckHold {
        release: oneshot::Sender<()>,
    }

    impl CheckHold {
        /// Lets the pass go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// A visit held after the host's record was found to be of another pairing and verified again,
    /// before it is replaced, until it is released.
    #[derive(Debug)]
    pub struct ReplaceHold {
        /// The host the visit is to.
        pub host: DeviceId,
        release: oneshot::Sender<()>,
    }

    impl ReplaceHold {
        /// Lets the visit go on.
        pub fn release(self) {
            let _ = self.release.send(());
        }
    }

    /// Every place a task of the desk can be paused at.
    #[derive(Debug, Default)]
    pub(super) struct Pauses {
        passes: Mutex<Option<mpsc::UnboundedSender<PassHold>>>,
        visits: Mutex<Option<mpsc::UnboundedSender<VisitHold>>>,
        checks: Mutex<Option<mpsc::UnboundedSender<CheckHold>>>,
        replaces: Mutex<Option<mpsc::UnboundedSender<ReplaceHold>>>,
        admissions: Mutex<Option<mpsc::UnboundedSender<DeviceId>>>,
    }

    impl InboxDesk {
        /// Hands every pass that has listed its hosts to the returned receiver, held before it
        /// begins any visit, until it is released.
        #[must_use]
        pub fn watch_passes(&self) -> mpsc::UnboundedReceiver<PassHold> {
            let (watching, passes) = mpsc::unbounded_channel();
            *self
                .pauses
                .passes
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            passes
        }

        /// Hands every visit whose read has ended to the returned receiver, held before the visit is
        /// checked and its outcome applied, until it is released. Visits are held in the order they
        /// reach the place and may be released in any order.
        #[must_use]
        pub fn watch_visits(&self) -> mpsc::UnboundedReceiver<VisitHold> {
            let (watching, visits) = mpsc::unbounded_channel();
            *self
                .pauses
                .visits
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            visits
        }

        /// Hands every pass that found a read to retire to the returned receiver, held before it
        /// retires any, until it is released.
        #[must_use]
        pub fn watch_checks(&self) -> mpsc::UnboundedReceiver<CheckHold> {
            let (watching, checks) = mpsc::unbounded_channel();
            *self
                .pauses
                .checks
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            checks
        }

        /// Hands every visit that found a record of another pairing to the returned receiver, held
        /// after it verified the pairing again and before it replaces the record, until it is
        /// released.
        #[must_use]
        pub fn watch_replaces(&self) -> mpsc::UnboundedReceiver<ReplaceHold> {
            let (watching, replaces) = mpsc::unbounded_channel();
            *self
                .pauses
                .replaces
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            replaces
        }

        /// Tells the returned receiver the host of each visit that has been admitted and now waits
        /// for its turn, so that a case knows a visitor stands behind the visit that holds it. Nothing
        /// is held.
        #[must_use]
        pub fn watch_admissions(&self) -> mpsc::UnboundedReceiver<DeviceId> {
            let (watching, admissions) = mpsc::unbounded_channel();
            *self
                .pauses
                .admissions
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(watching);
            admissions
        }

        pub(super) fn at_the_admission(&self, host: DeviceId) {
            let watching = self
                .pauses
                .admissions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let _ = watching.send(host);
            }
        }

        pub(super) async fn at_the_check(&self) {
            let watching = self
                .pauses
                .checks
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let (release, released) = oneshot::channel();
                if watching.send(CheckHold { release }).is_ok() {
                    let _ = released.await;
                }
            }
        }

        pub(super) async fn at_the_replace(&self, host: DeviceId) {
            let watching = self
                .pauses
                .replaces
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let (release, released) = oneshot::channel();
                if watching.send(ReplaceHold { host, release }).is_ok() {
                    let _ = released.await;
                }
            }
        }

        /// The owner the desk keeps what its visits find in.
        #[must_use]
        pub fn owner(&self) -> &Arc<ContactOwner> {
            &self.owner
        }

        /// What the desk's owner holds of the contact with the host a row is of, as a suite reads it.
        #[must_use]
        pub fn seen(&self, row: &HostInbox) -> Seen {
            let contact = self
                .owner
                .snapshot()
                .others
                .iter()
                .find(|other| other.reference == row.reference)
                .map(|other| other.contact.clone());
            match contact {
                Some(HostContact::InContact) if row.result().is_some() => Seen {
                    state: HostInboxState::Read,
                    refusal: None,
                    refused_request: None,
                    since_ms: None,
                },
                Some(HostContact::Refused { refusal, request }) => Seen {
                    state: HostInboxState::Refused,
                    refusal: Some(refusal),
                    refused_request: Some(request),
                    since_ms: None,
                },
                Some(HostContact::OutOfContact { since_ms, .. }) => Seen {
                    state: HostInboxState::OutOfContact,
                    refusal: None,
                    refused_request: None,
                    since_ms: Some(since_ms),
                },
                other => {
                    panic!("a host a pass answered for holds an outcome a case knows: {other:?}")
                }
            }
        }

        pub(super) async fn at_the_pass(&self) {
            let watching = self
                .pauses
                .passes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let (release, released) = oneshot::channel();
                if watching.send(PassHold { release }).is_ok() {
                    let _ = released.await;
                }
            }
        }

        pub(super) async fn at_the_visit(&self, host: DeviceId) {
            let watching = self
                .pauses
                .visits
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            if let Some(watching) = watching {
                let (release, released) = oneshot::channel();
                if watching.send(VisitHold { host, release }).is_ok() {
                    let _ = released.await;
                }
            }
        }
    }
}

#[cfg(all(test, feature = "testing"))]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::contact::tests::connection_of_an_account;
    use crate::contact::{HostContact, Target};

    fn host(byte: u8) -> DeviceId {
        DeviceId::new(Uuid::from_bytes([byte; 16]))
    }

    fn a() -> Target {
        Target::Paired {
            host: host(5),
            pairing: host(6),
            reference: "reference-5".to_owned(),
            name: "host 5".to_owned(),
        }
    }

    /// A host of a later release lists an item of the receipt rule and one of the results gap rule.
    /// The page is decoded as every page is, and each item keeps its rule's word, so the read is not
    /// refused over an item this release cannot say why it was raised.
    ///
    /// The page is this release's own shape, with items of a rule it has always had; the later words
    /// replace the rule and the key of each as text, so the words are all that differs.
    #[test]
    fn a_page_that_holds_an_item_of_each_rule_a_later_release_raises_is_decoded() {
        use kr_cbor::{CanonicalMap, CanonicalValue};
        use kr_protocol::attention::{
            AttentionItem, AttentionKey, AttentionLevel, AttentionRouting, AttentionRule,
            AttentionSource, NotificationState,
        };
        use kr_protocol::scalars::TimestampMs;

        let later = ["attention.receipt_uncertain", "attention.receipts_gap"];
        let item = |subject: &str| AttentionItem {
            key: AttentionKey::of(AttentionRule::CommandFailed, subject).expect("a key"),
            rule: AttentionRule::CommandFailed,
            source: AttentionSource::Receipts,
            level: AttentionLevel::Notable,
            session_id: Nullable::some(SessionId::new(Uuid::from_bytes([1; 16]))),
            summary: Nullable::null(),
            trusted: true,
            routing: AttentionRouting::OwnerPolicy,
            occurrences: U64::new(1),
            first_seen_ms: TimestampMs::new(1_763_000_000_000),
            last_seen_ms: TimestampMs::new(1_763_000_000_000),
            notification: NotificationState::Delivered,
            awaiting_delivery: false,
            acknowledged: false,
            uncertain: false,
            revision: U64::new(1),
            automation: Nullable::null(),
        };
        let page = AttentionReadResult {
            items: vec![
                item("~0123456789abcdef0123456789abcdef"),
                item("~fedcba9876543210fedcba9876543210"),
            ],
            more: false,
            dropped: U64::new(0),
            gaps: Vec::new(),
            quiet_hours: Nullable::null(),
            quiet_now: false,
            quiet_hours_provable: true,
        };
        let CanonicalValue::Map(root) =
            kr_cbor::to_canonical_value(&page).expect("the page encodes")
        else {
            panic!("a page is a map");
        };
        let entries = root
            .entries()
            .iter()
            .map(|(name, value)| match (name.as_str(), value) {
                ("items", CanonicalValue::Array(items)) => {
                    let renamed = items.iter().zip(later).map(|(held, word)| {
                        let CanonicalValue::Map(fields) = held else {
                            panic!("an item is a map");
                        };
                        let fields =
                            fields
                                .entries()
                                .iter()
                                .map(|(field, value)| match field.as_str() {
                                    "rule" => (field.clone(), CanonicalValue::text(word)),
                                    "key" => (
                                        field.clone(),
                                        CanonicalValue::text(format!(
                                            "{word}|~0123456789abcdef0123456789abcdef"
                                        )),
                                    ),
                                    _ => (field.clone(), value.clone()),
                                });
                        CanonicalValue::Map(CanonicalMap::from_entries(fields).expect("an item"))
                    });
                    (name.clone(), CanonicalValue::Array(renamed.collect()))
                }
                _ => (name.clone(), value.clone()),
            });
        let bytes = kr_cbor::encode(&CanonicalValue::Map(
            CanonicalMap::from_entries(entries).expect("a page"),
        ));
        let decoded =
            kr_protocol::wire::decode::<AttentionReadResult>(&bytes, &kr_cbor::Limits::DEFAULT);
        let words: Vec<&str> = decoded
            .iter()
            .flat_map(|page| page.items.iter())
            .map(|item| item.rule.as_str())
            .collect();
        assert_eq!(
            words,
            later,
            "a page with an item of each rule a later release raises is decoded: {:?}",
            decoded.as_ref().err()
        );
    }

    /// A visit to A that found a whole inbox over a connection of an account that has left, and
    /// committed it: the flag says when the account leaves.
    fn read_over(owner: &ContactOwner, byte: u8) -> Arc<std::sync::atomic::AtomicBool> {
        let target = a();
        let fence = owner.fence();
        let Admit::Admitted { ticket, .. } = owner.admit(&target, fence).value else {
            panic!("the visit is admitted");
        };
        let Begin::Go(_) = owner.begin_visit(&ticket).value else {
            panic!("the visit begins");
        };
        let (connection, _, left) = connection_of_an_account(byte);
        let committed = owner.commit_visit(
            &ticket,
            Found::Inbox {
                connection: Arc::new(connection),
                result: AttentionReadResult {
                    items: Vec::new(),
                    more: false,
                    dropped: U64::new(0),
                    gaps: Vec::new(),
                    quiet_hours: Nullable::null(),
                    quiet_now: false,
                    quiet_hours_provable: false,
                },
                sessions: Vec::new(),
            },
        );
        assert!(matches!(committed.value, Committed::Accepted));
        left
    }

    /// The first pass finds the read of A over a connection whose account has left, and is held
    /// before it retires it; another visit then replaces that read with one over another connection
    /// of the same account, and the pass goes on: the read it returns passed the check, so there is
    /// none, and the host's contact is the account's refusal.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_pass_returns_no_unchecked_read_when_an_overlapping_visit_replaces_the_one_being_retired()
     {
        let owner = Arc::new(ContactOwner::new());
        let first = read_over(&owner, 10);
        first.store(true, std::sync::atomic::Ordering::SeqCst);
        let desk = Arc::new(InboxDesk::with_owner(Arc::clone(&owner)));
        let mut checks = desk.watch_checks();
        let answering = tokio::spawn({
            let desk = Arc::clone(&desk);
            async move { desk.answer(&[host(5)]).await }
        });
        let hold = tokio::time::timeout(Duration::from_secs(30), checks.recv())
            .await
            .expect("the pass reaches the check")
            .expect("a hold");
        // Another visit completes a read over another connection of the account, before the pass
        // retires the first.
        let second = read_over(&owner, 11);
        second.store(true, std::sync::atomic::Ordering::SeqCst);
        hold.release();
        let answered = answering.await.expect("the pass ran");
        let row = &answered.hosts[0];
        assert!(
            row.result().is_none() && row.read_serial().is_none(),
            "the second read was not checked: {row:?}"
        );
        assert!(
            answered.hosts.iter().all(|row| {
                row.read
                    .as_ref()
                    .is_none_or(|read| read.origin().ended_by_this_device().is_none())
            }),
            "every read returned passed the check"
        );
        let others = owner.snapshot().visible.others;
        assert!(
            matches!(
                others[0].contact,
                HostContact::Refused {
                    request: Asked::Connection,
                    ..
                }
            ),
            "{:?}",
            others[0].contact
        );
        assert!(!owner.holds_resources_of(host(5)));
    }
}
