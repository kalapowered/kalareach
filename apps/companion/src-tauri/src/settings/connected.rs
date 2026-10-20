//! What drafts sync can learn of a host: which sessions it holds, and where its privacy mode
//! stands, through the connection this application holds to it.
//!
//! Only the host the application is connected to can be asked. It is asked whether it holds a
//! session, which is how a draft comes to be known as that host's, and it is asked where its privacy
//! mode stands. A host says that in `host.info`, to every device it is paired with. A host of an
//! earlier build does not, and tells it only to a device the host gave the right to manage it, in
//! the answer to `privacy.status`. Everything else is a host this device cannot read, and its drafts
//! stay on this device ([`HostPrivacy::Unreadable`], [`Holds::Unknown`]).

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use kr_client::pairing::link::LinkError;
use kr_client::{ClientError, Session};
use kr_protocol::error::ErrorCode;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::ids::{EnvironmentId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::privacy::{PrivacyReport, PrivacyStatusParams};
use kr_protocol::rights::ActionRight;
use kr_protocol::session::{SessionReadParams, SessionReadResult};
use kr_protocol::sharing::{DeviceListParams, DeviceListResult};
use tauri::{AppHandle, Manager as _, Runtime};

use super::drafts::{Holds, HostLists, HostPrivacy, Hosts};
use crate::commands::NoParams;
use crate::connection::{Connection, Replacer, Standing};
use crate::drafts::DraftHost;
use crate::error::CommandError;
use crate::state::AppState;

/// How long the host is given to say where privacy mode stands.
pub(crate) const ANSWER_WITHIN: Duration = Duration::from_secs(10);

/// One connection to one host: a reconnection to the same host is another. The session is held
/// weakly, so its address is not given to another while the cache names it.
type Link = (EnvironmentId, Weak<Session>);

/// The hosts this application is connected to.
pub struct ConnectedHosts<R: Runtime> {
    app: AppHandle<R>,
    /// The sessions the host of one connection said it does not hold, so that a draft of another
    /// host is not asked about again for as long as this application keeps that connection.
    not_held: Mutex<(Option<Link>, BTreeSet<SessionId>)>,
}

impl<R: Runtime> ConnectedHosts<R> {
    /// The hosts of `app`.
    #[must_use]
    pub fn new(app: AppHandle<R>) -> Self {
        Self {
            app,
            not_held: Mutex::new((None, BTreeSet::new())),
        }
    }

    fn remember_not_held(
        &self,
        environment: EnvironmentId,
        over: &Arc<Session>,
        session: SessionId,
    ) {
        let mut held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !is_link(held.0.as_ref(), environment, over) {
            *held = (Some((environment, Arc::downgrade(over))), BTreeSet::new());
        }
        held.1.insert(session);
    }

    fn known_not_held(
        &self,
        environment: EnvironmentId,
        over: &Arc<Session>,
        session: SessionId,
    ) -> bool {
        let held = self
            .not_held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        is_link(held.0.as_ref(), environment, over) && held.1.contains(&session)
    }
}

/// Whether a refusal says the host will answer no question now, and not only this one.
fn refuses_everything(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::RateLimited
            | ErrorCode::EnvironmentUnavailable
            | ErrorCode::UpstreamUnavailable
            | ErrorCode::StorageUnavailable
    )
}

/// Whether `link` is the connection `over` makes to the host of `environment`.
fn is_link(link: Option<&Link>, environment: EnvironmentId, over: &Arc<Session>) -> bool {
    link.is_some_and(|(held, session)| {
        *held == environment
            && session
                .upgrade()
                .is_some_and(|open| Arc::ptr_eq(&open, over))
    })
}

/// The host a connection is to: the environment its sessions live in, and what it is called.
fn host_of(connection: &Connection) -> DraftHost {
    let name = match connection.standing() {
        Standing::Owner => Some("this computer".to_owned()),
        Standing::Paired { host, .. } => host.name.clone(),
    };
    DraftHost {
        environment: connection.environment_id(),
        name,
    }
}

fn unreadable(reason: impl Into<String>) -> HostPrivacy {
    HostPrivacy::Unreadable {
        reason: reason.into(),
    }
}

/// What a host that is changing its privacy mode is read as: private, until a later answer says
/// otherwise.
const HOST_IS_CHANGING: &str = "the host is changing its privacy mode";

/// Why a host of an earlier build cannot be read by a device that does not manage it, and what to
/// do about it.
const EARLIER_BUILD: &str =
    "the host is of an earlier build that answers only a device that manages it; update the host";

/// What the seam does with the answer to `host.info`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Choice {
    /// The host said where its privacy mode stands.
    Known(HostPrivacy),
    /// The host of an earlier build said nothing of it in `host.info`, and this device may ask
    /// `privacy.status`.
    AskStatus,
    /// This device cannot read it, and the host's drafts are treated as private.
    Unreadable(String),
}

/// Decides, from what `host.info` came to, how this device reads a host's privacy mode.
///
/// `told` is the host's answer, or why there was none. `manages` says whether this device holds
/// the right to manage the host, which `privacy.status` asks for and `host.info` does not. A
/// branch that reads a host as off where it is not lets drafts leave this device, so each of the
/// others stays closed: a host that is changing, one that did not answer, and one that tells
/// nothing to a device that cannot ask.
///
/// Goes once no retained level is below 0.77: every host then sends the member, and the branch
/// for an answer without it, with the request it leads to, is removed.
pub(crate) fn choose(told: Result<HostInfoResult, String>, manages: bool) -> Choice {
    match told {
        Err(reason) => Choice::Unreadable(reason),
        Ok(info) => match info.privacy {
            Some(state) if state.changing => Choice::Unreadable(HOST_IS_CHANGING.to_owned()),
            Some(state) if state.enabled => Choice::Known(HostPrivacy::On {
                generation: state.generation.get(),
            }),
            Some(state) => Choice::Known(HostPrivacy::Off {
                generation: state.generation.get(),
            }),
            None if manages => Choice::AskStatus,
            None => Choice::Unreadable(EARLIER_BUILD.to_owned()),
        },
    }
}

/// What a host said when asked for its devices.
pub(crate) enum Listing {
    /// Its list.
    Listed(DeviceListResult),
    /// It answered that this device may not list its devices, as a host does once the grant that
    /// gave the right has run out or been revoked. Such a host is not this computer's to ask, and
    /// is not one that failed to answer.
    Refused,
    /// It did not answer in time, could not be reached, or refused for a reason that says nothing
    /// of its devices.
    Silent,
    /// The connection it was asked over has ended, which says nothing of the host: a connection
    /// that was replaced while a caller still held a copy of it.
    Ended,
}

impl Listing {
    /// What a refusal with `code` says. Only the refusal to list the host's devices to this
    /// computer is an answer about them. A host that refuses for another reason, such as a protocol
    /// this computer does not speak or a limit it has reached, may be the one that lists a device,
    /// so it counts as one that did not answer.
    fn of_refusal(code: ErrorCode) -> Self {
        if code == ErrorCode::PermissionDenied {
            Self::Refused
        } else {
            Self::Silent
        }
    }

    /// What a failed connection to a host says. A host that does not find this computer paired
    /// answers the hello as it would an unpaired peer, which this computer ends itself, so it
    /// reads as a connection lost, as a host that is asleep does.
    pub(crate) fn of_link(error: &LinkError) -> Self {
        match error {
            LinkError::Refused(refusal) => Self::of_refusal(refusal.code),
            _ => Self::Silent,
        }
    }
}

/// What a host lists as its devices, asked over `session`.
pub(crate) async fn listed(session: &Arc<Session>) -> Listing {
    let params = DeviceListParams {
        include_revoked: true,
    };
    let asked = tokio::time::timeout(
        ANSWER_WITHIN,
        session.read::<_, DeviceListResult>(Method::DeviceList, &params),
    )
    .await;
    listing_of(asked)
}

/// What the host lists of its devices, asked as a question about the connection: a refusal of it
/// raises nothing on the session, however late it arrives, since it is the answer.
async fn listed_unsignalled(session: &Arc<Session>) -> Listing {
    let params = DeviceListParams {
        include_revoked: true,
    };
    let asked = tokio::time::timeout(
        ANSWER_WITHIN,
        session.read_unsignalled::<_, DeviceListResult>(Method::DeviceList, &params),
    )
    .await;
    listing_of(asked)
}

fn listing_of(
    asked: std::result::Result<
        std::result::Result<DeviceListResult, ClientError>,
        tokio::time::error::Elapsed,
    >,
) -> Listing {
    match asked {
        Ok(Ok(list)) => Listing::Listed(list),
        Ok(Err(ClientError::Host(refused))) => Listing::of_refusal(refused.code),
        Ok(Err(ClientError::ConnectionEnded)) => Listing::Ended,
        Ok(Err(_)) | Err(_) => Listing::Silent,
    }
}

/// What the host on this computer lists of its devices, asked over the connection this application
/// holds to it.
///
/// A revocation withdraws the connections the host admitted before it, and the host answers every
/// request on one with a refusal that says to open a new connection. It does not close it, so a
/// connection that is held and not asked for what it is refused goes on being refused. When the
/// host refuses this connection, it is asked again over another; when that lists, the refused
/// connection was withdrawn, and `replace` puts the other in its place and ends it. A connection
/// that has ended, because a caller held a copy of one that was replaced, is asked about the same
/// way. What a fresh connection is answered is the host's word; one that cannot be opened says
/// nothing of the host.
pub(crate) async fn listed_replacing(connection: &Connection, replace: &Replacer) -> Listing {
    if !matches!(connection.standing(), Standing::Owner) {
        return listed(&connection.session()).await;
    }
    let listing = listed_unsignalled(&connection.session()).await;
    if !matches!(listing, Listing::Refused | Listing::Ended) {
        return listing;
    }
    match tokio::time::timeout(ANSWER_WITHIN, connection.another()).await {
        Ok(Ok(fresh)) => {
            let listing = listed(&fresh.session()).await;
            if matches!(listing, Listing::Listed(_)) {
                replace(&connection.session(), fresh);
            }
            listing
        }
        _ => Listing::Silent,
    }
}

impl<R: Runtime> Hosts for ConnectedHosts<R> {
    fn device_lists(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostLists> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let mut found = HostLists::default();
            let mut asked = None;
            if let Ok(connection) = state.connection() {
                // The connection this application holds to a host is asked over, when the right
                // to list the host's devices is the one it holds. A host that is not this
                // computer's to manage lists nothing to it, and its silence means nothing.
                let owns = match connection.standing() {
                    Standing::Owner => true,
                    Standing::Paired { rights, .. } => rights.contains(&ActionRight::HostManage),
                };
                if owns {
                    match listed_replacing(&connection, &state.replacer()).await {
                        Listing::Listed(list) => found.lists.push(list),
                        Listing::Refused => found.refused = true,
                        Listing::Silent | Listing::Ended => found.silent = true,
                    }
                }
                if let Standing::Paired { host, .. } = connection.standing() {
                    asked = Some(host.host_device_id);
                }
            }
            // The other hosts this computer owns, each on a connection made for the question and
            // let go after it. They are asked at the same time, so that a host that is asleep
            // keeps the others waiting for one wait and not for each.
            // A computer whose pairing records cannot be opened knows of no other host to ask.
            let Ok(device) = state.device() else {
                return found;
            };
            let visits: Vec<_> = device
                .owner_hosts()
                .into_iter()
                .filter(|host| asked != Some(host.host_device_id))
                .map(|host| {
                    let device = Arc::clone(&device);
                    tauri::async_runtime::spawn(async move {
                        let pairing = device.pairing();
                        let identity = pairing.candidate.paired_identity(host.device_id);
                        let visit = async {
                            match pairing.link.connect_paired(&host, &identity).await {
                                Ok(session) => listed(&Arc::new(session)).await,
                                Err(error) => Listing::of_link(&error),
                            }
                        };
                        tokio::time::timeout(ANSWER_WITHIN, visit)
                            .await
                            .unwrap_or(Listing::Silent)
                    })
                })
                .collect();
            for visit in visits {
                match visit.await {
                    Ok(Listing::Listed(list)) => found.lists.push(list),
                    Ok(Listing::Refused) => found.refused = true,
                    Ok(Listing::Silent | Listing::Ended) | Err(_) => found.silent = true,
                }
            }
            found
        })
    }

    fn holds(
        &self,
        session: SessionId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Holds> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let Ok(connection) = state.connection() else {
                return Holds::Unknown;
            };
            let host = host_of(&connection);
            let over = connection.session();
            if self.known_not_held(host.environment, &over, session) {
                return Holds::NotHere;
            }
            let asked = tokio::time::timeout(
                ANSWER_WITHIN,
                over.read::<_, SessionReadResult>(
                    Method::SessionRead,
                    &SessionReadParams {
                        session_id: session,
                    },
                ),
            )
            .await;
            match asked {
                // A session that has closed is still the host's: the draft was written for it.
                Ok(Ok(_)) => Holds::Here(host),
                Ok(Err(ClientError::Host(refused))) => match refused.code {
                    ErrorCode::SessionClosed => Holds::Here(host),
                    ErrorCode::UnknownSession => {
                        self.remember_not_held(host.environment, &over, session);
                        Holds::NotHere
                    }
                    // A host too busy or unavailable to say asks for no more questions; one that
                    // refuses to say about this session, or cannot reach that session's worker,
                    // may still say about another.
                    code if refuses_everything(code) => Holds::Unknown,
                    _ => Holds::Refused,
                },
                Ok(Err(_)) | Err(_) => Holds::Unknown,
            }
        })
    }

    fn privacy(
        &self,
        environment: EnvironmentId,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HostPrivacy> + Send + '_>> {
        Box::pin(async move {
            let state = self.app.state::<AppState>();
            let Ok(connection) = state.connection() else {
                return unreadable("this computer is not connected to a host");
            };
            if connection.environment_id() != environment {
                return unreadable("this computer is not connected to that host");
            }
            let manages = match connection.standing() {
                Standing::Owner => true,
                Standing::Paired { rights, .. } => rights.contains(&ActionRight::HostManage),
            };
            let told = match tokio::time::timeout(
                ANSWER_WITHIN,
                connection
                    .session()
                    .read::<_, HostInfoResult>(Method::HostInfo, &NoParams {}),
            )
            .await
            {
                Err(_) => Err("the host did not say where privacy mode stands in time".to_owned()),
                Ok(Err(error)) => Err(CommandError::from(error).message),
                Ok(Ok(info)) => Ok(info),
            };
            match choose(told, manages) {
                Choice::Known(state) => state,
                Choice::Unreadable(reason) => unreadable(reason),
                Choice::AskStatus => status_of(&connection).await,
            }
        })
    }
}

/// Where a host of an earlier build says its privacy mode stands, in the answer to
/// `privacy.status`, which it gives only a device it gave the right to manage it.
async fn status_of(connection: &Connection) -> HostPrivacy {
    let asked = tokio::time::timeout(
        ANSWER_WITHIN,
        connection
            .session()
            .read::<_, PrivacyReport>(Method::PrivacyStatus, &PrivacyStatusParams {}),
    )
    .await;
    match asked {
        Err(_) => unreadable("the host did not say where privacy mode stands in time"),
        Ok(Err(error)) => {
            let error = CommandError::from(error);
            if error.code == ErrorCode::PermissionDenied {
                unreadable("the host does not let this device read its privacy mode")
            } else {
                unreadable(error.message)
            }
        }
        Ok(Ok(report)) if report.enabled => HostPrivacy::On {
            generation: report.generation.get(),
        },
        Ok(Ok(report)) => HostPrivacy::Off {
            generation: report.generation.get(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::hostinfo::HostPrivacyState;
    use kr_protocol::scalars::{Nullable, TimestampMs, U64, Uuid};

    /// What a host answers to `host.info`, saying `privacy` of its privacy mode.
    fn info(privacy: Option<HostPrivacyState>) -> HostInfoResult {
        HostInfoResult {
            build_id: kr_protocol::ids::BuildId::new("kr/0.1.0+test").expect("a build identifier"),
            protocol_version: kr_protocol::hello::ProtocolVersion::new(1, 0),
            environment_id: EnvironmentId::new(Uuid::from_bytes([3; 16])),
            generation: kr_protocol::ids::ControllerGeneration::new(1),
            boot_identity: kr_protocol::identity::BootIdentity {
                source: kr_protocol::identity::BootIdentitySource::BootTime,
                value: kr_protocol::scalars::Bytes::new(vec![1, 2, 3, 4]),
            },
            started_at_ms: TimestampMs::new(1),
            live_sessions: U64::new(0),
            session_limit: U64::new(8),
            default_worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            power: kr_protocol::desktop::SleepInhibitionState {
                holder: Nullable::null(),
                ..kr_protocol::desktop::SleepInhibitionState::off(
                    kr_protocol::desktop::InhibitionMechanism::None,
                    kr_protocol::desktop::PowerSource::Unknown,
                )
            },
            machine: None,
            privacy,
        }
    }

    fn says(enabled: bool, generation: u64, changing: bool) -> Option<HostPrivacyState> {
        Some(HostPrivacyState {
            enabled,
            generation: U64::new(generation),
            changing,
        })
    }

    /// A host that says where its privacy mode stands is read as it says, whatever right this
    /// device holds, and a host that says it is changing is read as private, because an answer
    /// that reads a host as off where it is not lets drafts leave this device.
    #[test]
    fn a_host_that_says_where_its_privacy_mode_stands_is_read_as_it_says() {
        for manages in [false, true] {
            assert_eq!(
                choose(Ok(info(says(false, 4, false))), manages),
                Choice::Known(HostPrivacy::Off { generation: 4 }),
                "the control"
            );
            assert_eq!(
                choose(Ok(info(says(true, 5, false))), manages),
                Choice::Known(HostPrivacy::On { generation: 5 })
            );
            assert!(
                matches!(
                    choose(Ok(info(says(false, 4, true))), manages),
                    Choice::Unreadable(_)
                ),
                "a host that is changing is not read as off"
            );
        }
    }

    /// A host of an earlier build says nothing in `host.info`: a device that manages it asks
    /// `privacy.status`, and one that does not cannot read it. Neither reads it as off.
    #[test]
    fn a_host_that_says_nothing_is_asked_where_the_right_allows_and_otherwise_unread() {
        assert_eq!(choose(Ok(info(None)), true), Choice::AskStatus);
        assert!(matches!(
            choose(Ok(info(None)), false),
            Choice::Unreadable(_)
        ));
    }

    /// A host that did not answer, or refused, is unread, whatever right this device holds.
    #[test]
    fn a_host_that_did_not_answer_is_unread() {
        for manages in [false, true] {
            assert_eq!(
                choose(Err("it did not answer".to_owned()), manages),
                Choice::Unreadable("it did not answer".to_owned())
            );
        }
    }

    /// A session whose worker cannot be reached is refused as unavailable, and that says nothing of
    /// the host's other sessions; a host that is rate limited answers none.
    #[test]
    fn a_session_that_cannot_be_reached_does_not_end_the_questions_about_the_others() {
        assert!(!refuses_everything(ErrorCode::ResourceUnavailable));
        assert!(!refuses_everything(ErrorCode::PermissionDenied));
        assert!(refuses_everything(ErrorCode::RateLimited));
        assert!(refuses_everything(ErrorCode::EnvironmentUnavailable));
    }

    /// A host that refuses to list its devices to this computer has answered. One that refuses for
    /// another reason, or whose connection ends, has not: it may be the host that lists a device.
    #[test]
    fn only_a_refusal_to_list_the_hosts_devices_is_an_answer() {
        let refused = |code| LinkError::Refused(kr_protocol::error::ProtocolError::new(code, "no"));
        assert!(matches!(
            Listing::of_link(&refused(ErrorCode::PermissionDenied)),
            Listing::Refused
        ));
        for code in [
            ErrorCode::UnsupportedSchema,
            ErrorCode::RateLimited,
            ErrorCode::EnvironmentUnavailable,
        ] {
            assert!(
                matches!(Listing::of_link(&refused(code)), Listing::Silent),
                "{code} says nothing of the host's devices"
            );
        }
        assert!(matches!(
            Listing::of_link(&LinkError::Lost("gone".to_owned())),
            Listing::Silent
        ));
    }
}
