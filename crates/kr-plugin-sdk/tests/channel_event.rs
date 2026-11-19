//! What the host sends to an application as an event: the routed method, which the table places,
//! and the members of the caller's own, which go at the places the caller names.
//!
//! A Channels application is told what a person typed by a notification that has no identifier
//! and expects no reply. The table alone writes it, so the method is the one a publisher routed
//! and qualified, at the place the table reads methods from, and a caller cannot move it. These
//! cases write events through the public interface another crate uses.

use kr_plugin_sdk::connector::{
    ConnectorManifest, EventError, FieldPath, FieldSegment, Route, RouteDirection,
};
use kr_plugin_sdk::example;
use kr_plugin_sdk::ids::MethodName;
use serde_json::json;

/// The wire method of the Channels surface's notification that carries a message.
const CHANNEL_EVENT: &str = "notifications/claude/channel";

fn method(text: &str) -> MethodName {
    MethodName::new(text).expect("a valid method name")
}

fn path(names: &[&str]) -> FieldPath {
    FieldPath {
        segments: names
            .iter()
            .map(|name| FieldSegment::Member {
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

/// The example table with the Channels notification routed from the host to the application.
fn channels() -> ConnectorManifest {
    let mut table = example::example_connector_table();
    table.routes.push(Route {
        method: method("channel.event"),
        wire_name: CHANNEL_EVENT.to_owned(),
        direction: RouteDirection::HostToUpstream,
    });
    table
}

/// Turns the event's route toward `direction`.
fn route_toward(table: &mut ConnectorManifest, direction: RouteDirection) {
    table
        .routes
        .iter_mut()
        .find(|route| route.method == method("channel.event"))
        .expect("the event is routed")
        .direction = direction;
}

/// KR-REQ-12.26: the table writes the event from the routed method and the members it is given:
/// the method is the route's wire name at the table's own method path, each member is at its own
/// place, and every value is the one given.
#[test]
fn kr_req_12_26_the_table_writes_a_channel_event_from_its_route_and_the_members_it_is_given() {
    let table = channels();
    let content = path(&["params", "content"]);
    let meta = path(&["params", "meta"]);
    let sender = json!({"sender": "paired_device", "sender_id": "03204de92e11fc8c"});

    let event = table
        .event(
            &method("channel.event"),
            &[
                (&content, json!("Please run the tests")),
                (&meta, sender.clone()),
            ],
        )
        .expect("an event");
    assert_eq!(
        event,
        json!({
            "method": CHANNEL_EVENT,
            "params": {"content": "Please run the tests", "meta": sender},
        })
    );

    let mut moved = channels();
    moved.method_path = path(&["envelope", "kind"]);
    let event = moved
        .event(&method("channel.event"), &[(&content, json!("hi"))])
        .expect("an event");
    assert_eq!(
        event,
        json!({"envelope": {"kind": CHANNEL_EVENT}, "params": {"content": "hi"}})
    );

    let awkward = "say \"yes\"\nthen \u{1F600} and \\ done";
    let event = table
        .event(&method("channel.event"), &[(&content, json!(awkward))])
        .expect("an event");
    let frame = serde_json::to_vec(&event).expect("an event encodes");
    let read: serde_json::Value = serde_json::from_slice(&frame).expect("a frame reads back");
    assert_eq!(read["params"]["content"], json!(awkward));

    let empty = table
        .event(
            &method("channel.event"),
            &[(&content, json!("")), (&meta, json!({}))],
        )
        .expect("an event");
    assert_eq!(
        empty,
        json!({"method": CHANNEL_EVENT, "params": {"content": "", "meta": {}}})
    );
}

/// KR-REQ-12.26: an event is written only for a method the table routes from the host to the
/// application. A method it does not list, and one that only the application sends, are refused.
#[test]
fn kr_req_12_26_an_event_is_written_only_for_a_method_the_table_routes_toward_the_application() {
    let content = path(&["params", "content"]);
    let table = channels();

    let unlisted = table.event(&method("channel.unlisted"), &[(&content, json!("hi"))]);
    assert!(
        matches!(&unlisted, Err(EventError::NotRouted { method }) if method.as_str() == "channel.unlisted"),
        "{unlisted:?}"
    );
    assert!(matches!(
        table.event(&method("credential.read"), &[(&content, json!("hi"))]),
        Err(EventError::NotRouted { .. })
    ));

    let mut both = channels();
    route_toward(&mut both, RouteDirection::Bidirectional);
    assert!(
        both.event(&method("channel.event"), &[(&content, json!("hi"))])
            .is_ok()
    );

    let mut backwards = channels();
    route_toward(&mut backwards, RouteDirection::UpstreamToHost);
    assert!(matches!(
        backwards.event(&method("channel.event"), &[(&content, json!("hi"))]),
        Err(EventError::NotRouted { .. })
    ));
}

/// An event is built from members and writes each place once: a path with an index or no
/// segment, a place written twice, a place inside a value already written, and the method's own
/// place are refused, so a member cannot change the method.
#[test]
fn an_event_is_built_from_members_and_writes_each_place_once() {
    let table = channels();
    let route = method("channel.event");
    let content = path(&["params", "content"]);

    let indexed = FieldPath {
        segments: vec![
            FieldSegment::Member {
                name: "params".to_owned(),
            },
            FieldSegment::Index { index: 0 },
        ],
    };
    assert!(matches!(
        table.event(&route, &[(&indexed, json!("hi"))]),
        Err(EventError::Unwritable { .. })
    ));

    let nothing = FieldPath { segments: vec![] };
    assert!(matches!(
        table.event(&route, &[(&nothing, json!("hi"))]),
        Err(EventError::Unwritable { .. })
    ));

    assert!(matches!(
        table.event(
            &route,
            &[(&content, json!("one")), (&content, json!("two"))]
        ),
        Err(EventError::Unwritable { .. })
    ));

    let inside = path(&["params", "content", "part"]);
    assert!(matches!(
        table.event(&route, &[(&content, json!("one")), (&inside, json!("two"))]),
        Err(EventError::Unwritable { .. })
    ));
    assert!(matches!(
        table.event(&route, &[(&inside, json!("two")), (&content, json!("one"))]),
        Err(EventError::Unwritable { .. })
    ));

    let place = path(&["method"]);
    assert!(matches!(
        table.event(&route, &[(&place, json!("other/method"))]),
        Err(EventError::Unwritable { .. })
    ));
    let inside_method = path(&["method", "name"]);
    assert!(matches!(
        table.event(&route, &[(&inside_method, json!("other"))]),
        Err(EventError::Unwritable { .. })
    ));
}
