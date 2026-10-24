//! The attention inboxes of the hosts this device is paired with and is not using.
//!
//! The primary mobile surface is an inbox across hosts and sessions (section 13). The phone's
//! commands go to one host, the one in use, whose inbox the page reads like any other read. The
//! other hosts are read here: one authorised connection to each, opened as the device the host made
//! it, for the host alone, and kept while it answers. Each visit reads the whole inbox and the
//! session numbers the rows are named by, and ends within [`VISIT_WITHIN`], so a host that takes the
//! connection and answers nothing is out of contact for that pass and holds up no other.
//!
//! What a host answers is shown as the host's. A host that cannot be reached, or does not answer
//! in time, is out of contact: that says nothing of what its sessions are doing, and the answer
//! carries only since when contact has been lost, which this device noted itself. A host that
//! answers and refuses is in contact, and is not that: it is shown as having refused, with the
//! refusal it sent, and no loss of contact is noted for it. So is a host of a member's device that
//! cannot be given the lease its organisation signs for it, because the device is signed out or is
//! not a member: the refusal is the reason in words, and the host is asked nothing.
//!
//! Nothing is written to disk. Which connections are open and since when contact was lost are the
//! memory of this run; a run that has just started has no loss to report, and says only that
//! contact is not there.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
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

use crate::connection::{Connection, Unopened};
use crate::device::Device;
use crate::device::hosts::{UNNAMED_HOST, reference_of};
use crate::error::CommandError;

/// How long one visit to a host may take, from connecting to the end of its answer. A host that has
/// not answered by then is out of contact until the next pass.
pub const VISIT_WITHIN: Duration = Duration::from_secs(10);

/// The most items one page of a host's inbox is asked for.
const PAGE_ITEMS: u64 = 200;

/// The most pages one read of an inbox follows: sixteen pages hold every item a host retains.
const MAX_PAGES: usize = 16;

/// Where one host stood when it was last visited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostInboxState {
    /// The host answered, and the result is its inbox.
    Read,
    /// The host answered and refused. It is in contact: the refusal is what it said.
    Refused,
    /// The host could not be reached or did not answer in time.
    OutOfContact,
}

/// A session of a host, by the number the host gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NumberedSession {
    /// The session.
    pub session_id: SessionId,
    /// The number the host shows for it.
    pub display_number: DisplayNumber,
}

/// What a visit to one host found.
#[derive(Clone, Debug, Serialize)]
pub struct HostInbox {
    /// The host, by the reference the pairing screen lists it under.
    pub reference: String,
    /// The name the host gives people.
    pub name: String,
    /// Where the host stood.
    pub state: HostInboxState,
    /// When the inbox was read, as this device's clock says, when it was.
    pub read_at_ms: Option<u64>,
    /// Since when this device has not been in contact with the host, as its own clock says, when it
    /// was not at this visit.
    pub lost_since_ms: Option<u64>,
    /// What the host refused with, when it answered and refused.
    pub refusal: Option<CommandError>,
    /// The host's inbox, when it was read.
    pub result: Option<AttentionReadResult>,
    /// The host's sessions by number, when its inbox was read.
    pub sessions: Vec<NumberedSession>,
}

/// The connections kept to the hosts visited, and since when contact with each has been lost.
#[derive(Debug, Default)]
pub struct InboxDesk {
    kept: Mutex<BTreeMap<DeviceId, Kept>>,
}

/// What is kept of one host between visits.
#[derive(Debug, Default)]
struct Kept {
    /// One visit to the host at a time: a visit that starts while another is under way waits for
    /// it, and then reads over the connection it kept.
    gate: Arc<tokio::sync::Mutex<()>>,
    /// The connection to the host, while it answers.
    connection: Option<Arc<Connection>>,
    /// Since when contact has been lost, while it is.
    lost_since_ms: Option<u64>,
}

/// The result of one successful visit: the connection that answered, the inbox and the numbers.
type Read = (Arc<Connection>, AttentionReadResult, Vec<NumberedSession>);

/// A host's row, with the connection its inbox was read over when the row carries a read.
struct Found {
    inbox: HostInbox,
    read_over: Option<Arc<Connection>>,
}

/// What one visit to a host came to.
enum Visited {
    /// The host answered with its inbox.
    Read(Read),
    /// The host answered and refused.
    Refused(CommandError),
    /// The host could not be reached or did not answer.
    Unreached,
}

/// Why a read of an inbox ended without it.
enum Missed {
    /// The host answered with an error.
    Refused(CommandError),
    /// The host did not answer, or the answer was no reply to the question.
    Unreached,
}

impl From<Unopened> for Missed {
    fn from(unopened: Unopened) -> Self {
        match unopened {
            Unopened::Refused(refusal) => Self::Refused(refusal),
            Unopened::Unreached(_) => Self::Unreached,
        }
    }
}

impl From<Missed> for Visited {
    fn from(missed: Missed) -> Self {
        match missed {
            Missed::Refused(refusal) => Self::Refused(refusal),
            Missed::Unreached => Self::Unreached,
        }
    }
}

impl InboxDesk {
    /// Visits every paired host that is not the one in use, all at once, and answers with what each
    /// said, in the order the pairing screen lists them. A host this device forgot, or began to use,
    /// while it was visited is not among them, and neither is a host whose inbox was read for an
    /// account that has left by the time the answer is ready.
    pub async fn visit(self: &Arc<Self>, device: &Arc<Device>) -> Vec<HostInbox> {
        let in_use = device.host_in_use().map(|host| host.host_device_id);
        let hosts: Vec<PairedHost> = device
            .pairing()
            .hosts
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|host| Some(host.host_device_id) != in_use)
            .collect();
        // A host this device forgot, or began to use, keeps no connection here.
        let present: BTreeSet<DeviceId> = hosts.iter().map(|host| host.host_device_id).collect();
        let gone: Vec<Kept> = {
            let mut kept = self.kept();
            let left: Vec<DeviceId> = kept
                .keys()
                .filter(|host| !present.contains(host))
                .copied()
                .collect();
            left.iter().filter_map(|host| kept.remove(host)).collect()
        };
        for each in gone {
            if let Some(connection) = each.connection {
                connection.session().close();
            }
        }
        let visits: Vec<_> = hosts
            .into_iter()
            .map(|host| {
                let (desk, device) = (Arc::clone(self), Arc::clone(device));
                tauri::async_runtime::spawn(async move { desk.visit_one(&device, &host).await })
            })
            .collect();
        let mut found = Vec::new();
        for visit in visits {
            if let Ok(Some(each)) = visit.await {
                found.push(each);
            }
        }
        // The answer waits for the slowest host, so an account may have left since the pass that
        // read a host ended. What was read for it is not handed on.
        found
            .into_iter()
            .filter(|each| {
                each.read_over
                    .as_ref()
                    .is_none_or(|connection| connection.ended_by_this_device().is_none())
            })
            .map(|each| each.inbox)
            .collect()
    }

    /// Lets go of the connection kept to `host`, because this device no longer pairs with it.
    pub fn forgotten(&self, host: DeviceId) {
        let dropped = self.kept().remove(&host);
        if let Some(connection) = dropped.and_then(|kept| kept.connection) {
            connection.session().close();
        }
    }

    /// One visit to `host`. `None` when this device forgot the host, or began to use it, while it
    /// was visited: it is no longer a host to report.
    async fn visit_one(&self, device: &Arc<Device>, host: &PairedHost) -> Option<Found> {
        let gate = Arc::clone(&self.kept().entry(host.host_device_id).or_default().gate);
        let _turn = gate.lock().await;
        let now = device.pairing().clock.wall_clock_ms();
        let held = self
            .kept()
            .entry(host.host_device_id)
            .or_default()
            .connection
            .take();
        let outcome = tokio::time::timeout(VISIT_WITHIN, read_host(device, host, held))
            .await
            .unwrap_or(Visited::Unreached);
        let mut found = HostInbox {
            reference: reference_of(host),
            name: host.name.clone().unwrap_or_else(|| UNNAMED_HOST.to_owned()),
            state: HostInboxState::OutOfContact,
            read_at_ms: None,
            lost_since_ms: None,
            refusal: None,
            result: None,
            sessions: Vec::new(),
        };
        let mut read_over = None;
        // A host this device forgot, or began to use, while it was visited is let go of, and keeps
        // nothing here.
        let in_use = device.host_in_use().map(|using| using.host_device_id);
        let paired = device
            .pairing()
            .hosts
            .list()
            .unwrap_or_default()
            .iter()
            .any(|each| each.host_device_id == host.host_device_id);
        let mut kept = self.kept();
        if !paired || in_use == Some(host.host_device_id) {
            if let Visited::Read((connection, ..)) = outcome {
                connection.session().close();
            }
            kept.remove(&host.host_device_id);
            return None;
        }
        let entry = kept.entry(host.host_device_id).or_default();
        match outcome {
            Visited::Read((connection, result, sessions)) => {
                entry.connection = Some(Arc::clone(&connection));
                read_over = Some(connection);
                entry.lost_since_ms = None;
                found.state = HostInboxState::Read;
                found.read_at_ms = Some(now);
                found.result = Some(result);
                found.sessions = sessions;
            }
            Visited::Refused(refusal) => {
                // The host answered, so contact is not lost, and the connection it refused is not
                // kept: the next visit asks again from the start.
                entry.connection = None;
                entry.lost_since_ms = None;
                found.state = HostInboxState::Refused;
                found.refusal = Some(refusal);
            }
            Visited::Unreached => {
                // The connection that failed, or that the bound cut short, is not kept.
                entry.connection = None;
                found.lost_since_ms = Some(*entry.lost_since_ms.get_or_insert(now));
            }
        }
        Some(Found {
            inbox: found,
            read_over,
        })
    }

    fn kept(&self) -> MutexGuard<'_, BTreeMap<DeviceId, Kept>> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }
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
    held: Option<Arc<Connection>>,
) -> Visited {
    if let Some(connection) = held {
        let read = read_kept(device, host, &connection).await;
        if connection.ended_by_this_device().is_none() {
            match read {
                Ok((result, sessions)) => return Visited::Read((connection, result, sessions)),
                Err(Missed::Refused(refusal)) => {
                    connection.session().close();
                    return Visited::Refused(refusal);
                }
                Err(Missed::Unreached) => {}
            }
        }
        connection.session().close();
    }
    let connection = match Connection::visited(device, host).await {
        Ok(connection) => Arc::new(connection),
        Err(unopened) => return Missed::from(unopened).into(),
    };
    let read = read_over(&connection).await;
    if let Some(refusal) = connection.ended_by_this_device() {
        connection.session().close();
        return Visited::Refused(refusal);
    }
    match read {
        Ok((result, sessions)) => Visited::Read((connection, result, sessions)),
        Err(missed) => {
            connection.session().close();
            missed.into()
        }
    }
}

/// Reads the inbox over a connection kept from an earlier visit.
async fn read_kept(
    device: &Arc<Device>,
    host: &PairedHost,
    connection: &Connection,
) -> Result<(AttentionReadResult, Vec<NumberedSession>), Missed> {
    present(device, host, connection, Presentation::IfDue).await?;
    match read_over(connection).await {
        Err(Missed::Refused(refusal)) if lease_is_refused(refusal.code, &refusal.message) => {
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
    let identity = pairing.candidate.paired_identity(host.device_id);
    pairing
        .link
        .present_membership(&connection.session(), host, &identity, presentation)
        .await
        .map_err(|error| match error {
            LinkError::Refused(refusal) | LinkError::Membership(refusal) => {
                Missed::Refused(CommandError::from(refusal))
            }
            LinkError::Lost(_) | LinkError::Configuration(_) => Missed::Unreached,
        })
}

/// Reads the whole inbox and the session numbers over `connection`.
async fn read_over(
    connection: &Connection,
) -> Result<(AttentionReadResult, Vec<NumberedSession>), Missed> {
    let session = connection.session();
    let result = match pages(&session).await? {
        Some(result) => result,
        // An item went between two pages: the inbox is read again from its start, once.
        None => pages(&session).await?.ok_or(Missed::Unreached)?,
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
        // The host refused its session list: its answer, and the rows say "a session".
        Err(ClientError::Host(_)) => Vec::new(),
        // Anything else is the connection failing, and the inbox read beside it is not published.
        Err(other) => return Err(Unopened::of_read(other).into()),
    };
    Ok((result, sessions))
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
            Err(error) => return Err(Unopened::of_read(error).into()),
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
