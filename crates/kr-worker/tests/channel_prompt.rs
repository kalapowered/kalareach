//! What a channel writes for one message: the shape a package declares, and the frame built from it.
//!
//! The package is the one the channel cases serve, read from a layout the store would extract.
//! Each arm of the shape's derivation changes one thing about it and expects no shape at all,
//! because a channel whose package does not declare a whole shape carries no message.

use kr_plugin_sdk::connector::{ConnectorManifest, FieldPath, FieldSegment, RouteDirection};
use kr_plugin_sdk::effect::{ActionDeclaration, ActionImplementation, ParameterKind};
use kr_protocol::actor::ActorIngress;
use kr_protocol::ids::{ActorId, DeviceId, GrantId};
use kr_protocol::scalars::Uuid;
use kr_worker::broker::channel_fixture::Package;
use kr_worker::broker::channel_prompt::{
    CHANNEL_EVENT_WIRE_NAME, ChannelEventShape, NO_SENDER, PromptSender,
};

fn path(segments: &[&str]) -> FieldPath {
    FieldPath {
        segments: segments
            .iter()
            .map(|name| FieldSegment::Member {
                name: (*name).to_owned(),
            })
            .collect(),
    }
}

fn the_owner() -> PromptSender {
    PromptSender {
        actor_id: ActorId::new("device-1").expect("an actor"),
        ingress: ActorIngress::LocalIpc,
        device_id: None,
        grant_id: None,
    }
}

/// The package's own actions and table, which a derivation reads, to change one thing in.
fn declared() -> (Package, Vec<ActionDeclaration>, ConnectorManifest) {
    let package = Package::laid_out();
    let actions = package.connector.manifest().actions.clone();
    let table = package.connector.table().clone();
    (package, actions, table)
}

fn prompt_action(actions: &mut [ActionDeclaration]) -> &mut ActionDeclaration {
    actions
        .iter_mut()
        .find(|action| action.id.as_str() == "prompt.send")
        .expect("the package declares the prompt action")
}

fn bindings(action: &mut ActionDeclaration) -> &mut Vec<kr_plugin_sdk::effect::ParameterBinding> {
    let ActionImplementation::UpstreamMethod { bindings, .. } = &mut action.implementation else {
        panic!("the prompt action is an upstream method");
    };
    bindings
}

/// KR-REQ-12.26: the shape of a channel's message comes from the package's own declaration of the
/// action that delivers a prompt: its text is at `params.content`, the host's members are at
/// `params.meta`, and a message may hold as many characters as the text parameter declares.
#[test]
fn a_channel_event_shape_comes_from_the_packages_declared_prompt_action() {
    let package = Package::laid_out();
    let shape = ChannelEventShape::of(&package.connector).expect("the package declares a shape");
    assert_eq!(shape.max_characters(), 8000, "the declared maximum");
    let frame = shape.frame("", &the_owner()).expect("a frame");
    let frame: serde_json::Value = serde_json::from_slice(&frame).expect("a frame is JSON");
    assert_eq!(frame["method"], CHANNEL_EVENT_WIRE_NAME);
    assert_eq!(
        frame["params"]["content"], "",
        "the text is at params.content"
    );
    assert!(
        frame["params"]["meta"].is_object(),
        "the host's members are at params.meta: {frame}"
    );
}

/// KR-REQ-12.26: a package that does not declare a whole shape has none, and so carries no
/// message. Each arm changes one thing about the package's own declaration: no prompt action,
/// two of them, a text bound anywhere but `params.content`, a text bound inside the host's own
/// members, a binding through an array element, two bindings, a text parameter that is optional
/// or not text, a wire name the forwarder does not carry, a route that runs towards the host, and
/// a method that is not at `method`. The route toward the host is tried on the derivation
/// directly, because the package's own validation refuses it before a derivation can be asked.
#[test]
fn a_package_without_a_writable_prompt_shape_has_no_event_shape() {
    let (_package, actions, table) = declared();
    assert!(
        ChannelEventShape::derive(&actions, &table).is_some(),
        "the package as declared has a shape"
    );
    let channel_event_route = |table: &mut ConnectorManifest| {
        table
            .routes
            .iter()
            .position(|route| route.wire_name == CHANNEL_EVENT_WIRE_NAME)
            .expect("the table routes the channel event")
    };

    // No prompt action.
    let mut changed = actions.clone();
    changed.retain(|action| action.id.as_str() != "prompt.send");
    assert!(
        ChannelEventShape::derive(&changed, &table).is_none(),
        "no prompt action"
    );

    // Two prompt actions.
    let mut changed = actions.clone();
    let mut second = prompt_action(&mut changed).clone();
    second.id = kr_plugin_sdk::ids::ActionName::new("prompt.send-again").expect("a name");
    changed.push(second);
    assert!(
        ChannelEventShape::derive(&changed, &table).is_none(),
        "two prompt actions"
    );

    // A binding anywhere but `params.content`, inside the host's own members, through an array
    // element, and one that is the place of the method.
    for (name, field) in [
        ("params.other", path(&["params", "other"])),
        ("params.meta.sender", path(&["params", "meta", "sender"])),
        ("params.meta", path(&["params", "meta"])),
        (
            "an array element",
            FieldPath {
                segments: vec![
                    FieldSegment::Member {
                        name: "params".to_owned(),
                    },
                    FieldSegment::Index { index: 0 },
                ],
            },
        ),
        ("method", path(&["method"])),
    ] {
        let mut changed = actions.clone();
        bindings(prompt_action(&mut changed))[0].field = field;
        assert!(
            ChannelEventShape::derive(&changed, &table).is_none(),
            "a binding at {name}"
        );
    }

    // Two bindings.
    let mut changed = actions.clone();
    let first = bindings(prompt_action(&mut changed))[0].clone();
    bindings(prompt_action(&mut changed)).push(kr_plugin_sdk::effect::ParameterBinding {
        field: path(&["params", "extra"]),
        ..first
    });
    assert!(
        ChannelEventShape::derive(&changed, &table).is_none(),
        "two bindings"
    );

    // A text parameter that is optional, and one that is not text.
    let mut changed = actions.clone();
    prompt_action(&mut changed).parameters.parameters[0].required = false;
    assert!(
        ChannelEventShape::derive(&changed, &table).is_none(),
        "an optional text parameter"
    );
    let mut changed = actions.clone();
    prompt_action(&mut changed).parameters.parameters[0].kind = ParameterKind::Boolean {};
    assert!(
        ChannelEventShape::derive(&changed, &table).is_none(),
        "a parameter that is not text"
    );

    // A wire name the forwarder does not carry.
    let mut changed = table.clone();
    let at = channel_event_route(&mut changed);
    changed.routes[at].wire_name = "notifications/other".to_owned();
    assert!(
        ChannelEventShape::derive(&actions, &changed).is_none(),
        "another wire name"
    );

    // A route that runs towards the host.
    let mut changed = table.clone();
    let at = channel_event_route(&mut changed);
    changed.routes[at].direction = RouteDirection::UpstreamToHost;
    assert!(
        ChannelEventShape::derive(&actions, &changed).is_none(),
        "a route toward the host"
    );

    // A method the table writes anywhere but `method`.
    let mut changed = table.clone();
    changed.method_path = path(&["verb"]);
    assert!(
        ChannelEventShape::derive(&actions, &changed).is_none(),
        "a method path that is not `method`"
    );
}

/// KR-REQ-12.26: the frame a message goes out in names the text and the host's own sender
/// members, and nothing else: the method as the forwarder reads it, the text as typed (quotes, a
/// new line and a backslash come back as they were), and `sender` and `sender_id` of the facts
/// the host verified. A sender the host cannot name has no frame.
#[test]
fn a_prepared_event_names_content_and_the_hosts_own_sender_members() {
    let package = Package::laid_out();
    let shape = ChannelEventShape::of(&package.connector).expect("the package declares a shape");
    let frame = shape.frame("hello", &the_owner()).expect("a frame");
    assert_eq!(
        String::from_utf8(frame).expect("UTF-8"),
        concat!(
            r#"{"method":"notifications/claude/channel","params":{"content":"hello","#,
            r#""meta":{"sender":"local_user","sender_id":"03204de92e11fc8c"}}}"#
        )
    );

    let text = "say \"hi\"\nand a \\ backslash";
    let frame = shape.frame(text, &the_owner()).expect("a frame");
    let frame: serde_json::Value = serde_json::from_slice(&frame).expect("a frame is JSON");
    assert_eq!(
        frame["params"]["content"], text,
        "the text comes back as typed"
    );
    let meta = frame["params"]["meta"]
        .as_object()
        .expect("meta is an object");
    let mut members: Vec<&str> = meta.keys().map(String::as_str).collect();
    members.sort_unstable();
    assert_eq!(
        members,
        ["sender", "sender_id"],
        "only the host's own members"
    );

    let phone = PromptSender {
        actor_id: ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: ActorIngress::PairedDevice,
        device_id: Some(DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Some(GrantId::new(Uuid::from_bytes([8; 16]))),
    };
    let frame = shape.frame("hello", &phone).expect("a frame");
    let frame: serde_json::Value = serde_json::from_slice(&frame).expect("a frame is JSON");
    assert_eq!(frame["params"]["meta"]["sender"], "paired_device");
    assert_eq!(frame["params"]["meta"]["sender_id"], "8dea4a0a91fb8dda");

    let unverified = PromptSender {
        ingress: ActorIngress::Workflow,
        ..the_owner()
    };
    let refusal = shape
        .frame("hello", &unverified)
        .expect_err("no sender, no frame");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(refusal.to_string().contains(NO_SENDER), "{refusal}");
}
