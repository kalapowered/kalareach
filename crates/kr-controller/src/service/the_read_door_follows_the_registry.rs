//! The local read door decides each read's ingress through the registry, as the write door does.
//!
//! A request that arrives on the local socket names a method, and the registry says which ingress
//! classes may reach it. The door refuses a method the registry does not list for the local socket,
//! and a version it does not implement, before any handler is asked, with the words the write door
//! uses. These cases send every such method over a real local connection, so a read whose registry
//! row leaves out the local socket needs no guard of its own at the switch.

use kr_ipc::client::LocalClient;
use kr_protocol::actor::ActorIngress;
use kr_protocol::authority::EffectClass;
use kr_protocol::envelope::{ControlFrame, Outcome, ParamsValue, Request};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::RequestId;
use kr_protocol::method::{LocalHold, Method, MethodName, MethodVersion, local_hold};

use super::Controller;
use super::stopped_on_the_local_socket::{Serving, serving};

/// The reads whose registry row leaves out the local socket. The walk over the table finds every
/// such method; naming these keeps the walk from passing over an empty set.
const READS_NOT_ON_THE_LOCAL_SOCKET: [Method; 9] = [
    Method::BackupCheckpoint,
    Method::GrantHeld,
    Method::SessionOpen,
    Method::TransferStreams,
    Method::VoiceContext,
    Method::VoicePrepare,
    Method::MailboxRead,
    Method::StorageObjectRead,
    Method::StorageStatus,
];

/// The sentence a method that the registry does not list for the local socket is refused with.
fn not_reachable(method: Method) -> String {
    format!("{} is not reachable from a local caller", method.as_str())
}

/// Whether the registry lists `method` for a caller on the local socket.
fn is_listed_for_the_local_socket(method: Method) -> bool {
    method.entry().ingress.contains(&ActorIngress::LocalIpc)
}

/// A read of `method` at `version` with no parameters.
fn a_request(method: MethodName, version: MethodVersion) -> Request {
    Request {
        request_id: RequestId::new(900),
        method,
        method_version: version,
        params: ParamsValue::empty(),
    }
}

/// Sends `method` at `version` with no parameters as a read on a connection of its own, and returns
/// what the daemon answered.
async fn asked(daemon: &Serving, method: Method, version: MethodVersion) -> Outcome {
    asked_on(&mut daemon.client().await, method.into(), version).await
}

/// Sends `method` at `version` with no parameters as a read on `client`, and returns what the
/// daemon answered.
async fn asked_on(client: &mut LocalClient, method: MethodName, version: MethodVersion) -> Outcome {
    let request = a_request(method, version);
    let request_id = request.request_id;
    client
        .send(&ControlFrame::Request(request))
        .await
        .expect("the request is written");
    loop {
        let frame = tokio::time::timeout(std::time::Duration::from_secs(60), client.recv())
            .await
            .expect("the daemon answers within the bound of a hang")
            .expect("the connection stays open until the answer");
        if let ControlFrame::Response(response) = frame
            && response.request_id == request_id
        {
            return response.outcome;
        }
    }
}

/// KR-REQ-20.12: a method that the registry does not list for the local socket is refused at the
/// read door with the sentence the write door gives it, whatever its effect and whatever
/// handler would have answered it. The walk covers every row of the table, so a read added later
/// with another ingress is held without a guard of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_method_the_registry_does_not_list_for_the_local_socket_is_refused_at_the_read_door()
{
    let daemon = serving().await;
    let unlisted: Vec<Method> = Method::ALL
        .iter()
        .copied()
        .filter(|method| !is_listed_for_the_local_socket(*method))
        .collect();
    for read in READS_NOT_ON_THE_LOCAL_SOCKET {
        assert!(
            read.entry().effect == EffectClass::Read && unlisted.contains(&read),
            "{} is a read the registry does not list for the local socket",
            read.as_str()
        );
    }

    let mut answered_otherwise = Vec::new();
    for method in unlisted.iter().copied() {
        let answer = asked(&daemon, method, MethodVersion::V1).await;
        let refused = matches!(
            &answer,
            Outcome::Error(error)
                if error.code == ErrorCode::PermissionDenied
                    && error.message == not_reachable(method)
        );
        if !refused {
            answered_otherwise.push((method.as_str(), answer));
        }
    }
    assert!(
        answered_otherwise.is_empty(),
        "each of these is answered otherwise than with `<method> is not reachable from a local \
         caller`: {answered_otherwise:#?}"
    );
}

/// Guard: the door refuses what the registry leaves out and nothing else. Every read the registry
/// lists for the local socket is asked, and none is refused with the door's sentence.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_the_registry_lists_for_the_local_socket_is_not_refused_by_the_door() {
    let daemon = serving().await;
    let listed: Vec<Method> = Method::ALL
        .iter()
        .copied()
        .filter(|method| {
            method.entry().effect == EffectClass::Read && is_listed_for_the_local_socket(*method)
        })
        .collect();
    assert!(
        listed.contains(&Method::HostInfo) && listed.contains(&Method::HistoryPage),
        "the walk reaches the reads this daemon serves to its owner"
    );

    let mut refused_by_the_door = Vec::new();
    for method in listed.iter().copied() {
        let answer = asked(&daemon, method, MethodVersion::V1).await;
        let refused = matches!(
            &answer,
            Outcome::Error(error) if error.message == not_reachable(method)
        );
        if refused {
            refused_by_the_door.push(method.as_str());
        }
    }
    assert!(
        refused_by_the_door.is_empty(),
        "the registry lists these for the local socket, and the door refused them: \
         {refused_by_the_door:?}"
    );
}

/// KR-REQ-20.12: a read at a version the registry does not implement is refused at the read door,
/// as a write is, in both arms of the door: the one that serves a read from its handler, and the
/// one that releases an answer under a privacy fence. The reads the catalogue answers are refused
/// by the door with the write door's code too, and not by the catalogue's own check of the version.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listed_read_at_another_version_is_refused_as_a_write_is() {
    let daemon = serving().await;
    // `host.info` is answered by the daemon's own handler; `history.page` is released under a
    // privacy fence; `plugin.list` is answered by the catalogue, which refuses another version
    // itself with `UnsupportedSchema`.
    for method in [Method::HostInfo, Method::HistoryPage, Method::PluginList] {
        let answer = asked(&daemon, method, MethodVersion(2)).await;
        assert!(
            matches!(
                &answer,
                Outcome::Error(error)
                    if error.code == ErrorCode::InvalidArgument
                        && error.message
                            == format!("{} is not implemented at version 2", method.as_str())
            ),
            "{} at version 2 is refused as a write is: {answer:?}",
            method.as_str()
        );
    }
    // The same read at the version the registry implements is not refused for its version.
    let answer = asked(&daemon, Method::HostInfo, MethodVersion::V1).await;
    assert!(
        !matches!(
            &answer,
            Outcome::Error(error) if error.message.contains("is not implemented at version")
        ),
        "host.info at version 1 is not refused for its version: {answer:?}"
    );
}

/// KR-REQ-20.12: a name the registry does not hold is left to the read switch, which refuses it
/// with its own words, as the write door refuses an unknown name before it asks the registry. The
/// door's sentence says a method is not reachable from a local caller, which is not what is wrong
/// with a name that no method has.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_the_registry_does_not_hold_keeps_the_read_switchs_refusal() {
    let daemon = serving().await;
    let name = MethodName::new("host.not_in_the_registry").expect("a well-formed name");
    assert!(name.method().is_none(), "the registry holds no such method");

    let answer = asked_on(&mut daemon.client().await, name, MethodVersion::V1).await;
    assert!(
        matches!(
            &answer,
            Outcome::Error(error)
                if error.code == ErrorCode::PermissionDenied
                    && error.message == "the method is not in the registry"
        ),
        "a name the registry does not hold is refused with the read switch's words: {answer:?}"
    );
}

/// KR-REQ-20.12: the local owner's lease is asked before the registry, as the write door asks
/// them. On a host that is exclusively organisation-managed whose owner holds no lease, a held
/// read that the registry would also refuse, for its version, is answered with the lease's
/// refusal, in both arms of the door.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_local_owners_lease_is_asked_before_the_registry() {
    let daemon = serving().await;
    let mut client = daemon.client().await;
    daemon
        .controller()
        .policy
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .set_exclusively_managed(true);

    // `session.read` is served by the door's plain arm and `history.page` by the arm that releases
    // an answer under a privacy fence; both are held to the lease and listed for the local socket.
    for (method, released) in [(Method::SessionRead, false), (Method::HistoryPage, true)] {
        assert_eq!(
            local_hold(method),
            LocalHold::Held,
            "{} is held to the local owner's lease",
            method.as_str()
        );
        assert!(
            is_listed_for_the_local_socket(method),
            "{} is listed for the local socket, so the version is all the registry would refuse",
            method.as_str()
        );
        assert_eq!(
            Controller::releases(&a_request(method.into(), MethodVersion(2))),
            released,
            "{} is served by the arm this case means it to meet",
            method.as_str()
        );

        let answer = asked_on(&mut client, method.into(), MethodVersion(2)).await;
        assert!(
            matches!(
                &answer,
                Outcome::Error(error)
                    if error.code == ErrorCode::PermissionDenied
                        && error.message.contains("membership lease is not live")
            ),
            "{} at version 2 is refused for the lease before it is refused for its version: \
             {answer:?}",
            method.as_str()
        );
    }
}
