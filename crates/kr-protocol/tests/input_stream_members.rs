//! What the terminal-input stream adds to the messages a worker and a controller exchange.
//!
//! Three requests carry the position of the typing that must come before them, two of them also
//! ask for the count of bytes a lease's end discarded, and two answers carry that count. Each
//! member is absent from the wire unless it is used, so a message that uses none is byte for byte
//! what a build before the members wrote and reads, and a build before them, whose messages are
//! closed, never meets one. The worker's input lane has a role, two opening frames and three
//! events of its own. The wire values are written by hand, member by member.

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::attachment::{SessionDetachParams, SessionDetachResult};
use kr_protocol::envelope::{ControlEvent, ControlFrame, ParamsValue};
use kr_protocol::ids::{AttachmentId, ConnectionId, InputLeaseEpoch};
use kr_protocol::input::{InputBarrier, InputLeaseResult, InputReleaseParams};
use kr_protocol::local::{
    ControllerConnectionRole, InputLane, InputLaneReady, LaneCredit, LaneEnded, LaneLaunch,
    LaneWindow,
};
use kr_protocol::method::Method;
use kr_protocol::retained::strip_input_lane_members;
use kr_protocol::root::ShellLaunchParams;
use kr_protocol::scalars::{Nullable, U64, Uuid};
use kr_protocol::wire::WireMessage;

fn map(members: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    let mut map = CanonicalMap::new();
    for (name, value) in members {
        map.insert(name.to_owned(), value).expect("a new member");
    }
    CanonicalValue::Map(map)
}

fn number(value: u64) -> CanonicalValue {
    CanonicalValue::integer(value.into()).expect("a number")
}

fn text(value: &str) -> CanonicalValue {
    CanonicalValue::Text(value.to_owned())
}

fn id(fill: u8) -> CanonicalValue {
    CanonicalValue::Bytes(vec![fill; 16])
}

fn bytes_of(value: &CanonicalValue) -> Vec<u8> {
    kr_cbor::encode(value)
}

/// Reads a message from the wire value, and writes the value back as the same bytes.
fn round_trips<T: WireMessage>(wire: &CanonicalValue) -> T {
    let read: T = ParamsValue::new(wire.clone())
        .to_typed()
        .expect("the wire value reads");
    let written = ParamsValue::from_typed(&read).expect("it writes");
    assert_eq!(
        bytes_of(written.as_value()),
        bytes_of(wire),
        "the value is written back as the bytes it was read from"
    );
    read
}

fn is_refused<T: WireMessage>(wire: CanonicalValue) -> bool {
    ParamsValue::new(wire).to_typed::<T>().is_err()
}

fn barrier_wire(launch: CanonicalValue) -> CanonicalValue {
    map(vec![
        ("attachment_id", id(0x61)),
        ("epoch", number(3)),
        ("count", number(12)),
        ("launch", launch),
    ])
}

fn barrier() -> InputBarrier {
    InputBarrier {
        attachment_id: AttachmentId::new(Uuid::from_bytes([0x61; 16])),
        epoch: InputLeaseEpoch::new(3),
        count: U64::new(12),
        launch: Nullable::some(9),
    }
}

/// The request the build before the members writes, and the same request with them.
struct Request {
    method: Method,
    old: CanonicalValue,
    new: CanonicalValue,
}

fn with(old: &CanonicalValue, extra: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    let CanonicalValue::Map(members) = old else {
        panic!("a map");
    };
    let mut all = members.clone();
    for (name, value) in extra {
        all.insert(name.to_owned(), value).expect("a new member");
    }
    CanonicalValue::Map(all)
}

fn requests() -> Vec<Request> {
    let release = map(vec![
        ("session_id", id(0x51)),
        ("attachment_id", id(0x61)),
        ("epoch", number(3)),
    ]);
    let detach = map(vec![("attachment_id", id(0x61))]);
    let launch = map(vec![
        ("session_id", id(0x51)),
        (
            "command",
            map(vec![("arguments", CanonicalValue::Array(vec![text("ls")]))]),
        ),
        ("expected_prompt_generation", number(4)),
        ("expected_buffer_revision", number(5)),
    ]);
    vec![
        Request {
            method: Method::InputRelease,
            new: with(
                &release,
                vec![
                    ("after_input", barrier_wire(number(9))),
                    ("fenced_report", CanonicalValue::Bool(true)),
                ],
            ),
            old: release,
        },
        Request {
            method: Method::SessionDetach,
            new: with(
                &detach,
                vec![
                    ("after_input", barrier_wire(CanonicalValue::Null)),
                    ("fenced_report", CanonicalValue::Bool(true)),
                ],
            ),
            old: detach,
        },
        Request {
            method: Method::ShellLaunch,
            new: with(&launch, vec![("after_input", barrier_wire(number(9)))]),
            old: launch,
        },
    ]
}

/// A request that uses none of the members is the request a build before them writes: it reads
/// with the members unset and is written back as the same bytes. This is the old wire, unchanged.
#[test]
fn a_request_without_the_members_is_the_old_wire() {
    let [release, detach, launch]: [Request; 3] = requests().try_into().ok().expect("three");
    let read: InputReleaseParams = round_trips(&release.old);
    assert!(read.after_input.is_none());
    assert!(!read.fenced_report);
    let read: SessionDetachParams = round_trips(&detach.old);
    assert!(read.after_input.is_none());
    assert!(!read.fenced_report);
    let read: ShellLaunchParams = round_trips(&launch.old);
    assert!(read.after_input.is_none());
}

/// With the members, a request is written with them as the plan states them, and a member that is
/// false or none is not written at all.
#[test]
fn a_request_with_the_members_writes_them() {
    let [release, detach, launch]: [Request; 3] = requests().try_into().ok().expect("three");
    let read: InputReleaseParams = round_trips(&release.new);
    assert_eq!(read.after_input, Some(barrier()));
    assert!(read.fenced_report);
    let read: SessionDetachParams = round_trips(&detach.new);
    assert_eq!(
        read.after_input.map(|found| found.launch),
        Some(Nullable::null())
    );
    assert!(read.fenced_report);
    let read: ShellLaunchParams = round_trips(&launch.new);
    assert_eq!(read.after_input, Some(barrier()));

    // `fenced_report` set to false is the member absent, not `false`.
    let mut unset = read_release(&release.new);
    unset.fenced_report = false;
    let CanonicalValue::Map(written) = ParamsValue::from_typed(&unset)
        .expect("it writes")
        .into_value()
    else {
        panic!("a map");
    };
    assert!(written.get("fenced_report").is_none());
    assert!(written.get("after_input").is_some());
}

fn read_release(wire: &CanonicalValue) -> InputReleaseParams {
    ParamsValue::new(wire.clone()).to_typed().expect("it reads")
}

/// The barrier names the attachment, the epoch, the count of frames and the launch, and is closed.
#[test]
fn the_barrier_is_closed_and_names_every_member() {
    let with_null = round_trips::<InputBarrier>(&barrier_wire(CanonicalValue::Null));
    assert_eq!(with_null.launch, Nullable::null());
    assert_eq!(
        round_trips::<InputBarrier>(&barrier_wire(number(9))),
        barrier()
    );
    assert!(is_refused::<InputBarrier>(with(
        &barrier_wire(number(9)),
        vec![("cancel", CanonicalValue::Bool(true))]
    )));
    for missing in ["attachment_id", "epoch", "count", "launch"] {
        let CanonicalValue::Map(whole) = barrier_wire(number(9)) else {
            panic!("a map");
        };
        let mut kept = CanonicalMap::new();
        for (name, value) in whole.into_entries() {
            if name != missing {
                kept.insert(name, value).expect("a new member");
            }
        }
        assert!(
            is_refused::<InputBarrier>(CanonicalValue::Map(kept)),
            "a barrier without {missing} is refused"
        );
    }
}

/// A member that states its default is refused, as every optional member of the wire is: it would
/// write back as different bytes, and the encoding of a message has one form.
#[test]
fn a_member_stated_at_its_default_is_refused() {
    let [release, ..]: [Request; 3] = requests().try_into().ok().expect("three");
    assert!(is_refused::<InputReleaseParams>(with(
        &release.old,
        vec![("fenced_report", CanonicalValue::Bool(false))]
    )));
    assert!(is_refused::<InputReleaseParams>(with(
        &release.old,
        vec![("after_input", CanonicalValue::Null)]
    )));
    let answer = map(vec![(
        "lease",
        map(vec![
            ("epoch", number(3)),
            ("holder", CanonicalValue::Null),
            ("connection_id", CanonicalValue::Null),
            ("next_sequence", number(0)),
        ]),
    )]);
    assert!(is_refused::<InputLeaseResult>(with(
        &answer,
        vec![("fenced_bytes", CanonicalValue::Null)]
    )));
}

/// A launch has no count of discarded bytes to ask for, and a position that is not a barrier is
/// refused, as an unknown member of a closed request always was.
#[test]
fn the_requests_stay_closed() {
    let [_, _, launch]: [Request; 3] = requests().try_into().ok().expect("three");
    assert!(is_refused::<ShellLaunchParams>(with(
        &launch.old,
        vec![("fenced_report", CanonicalValue::Bool(true))]
    )));
    assert!(is_refused::<ShellLaunchParams>(with(
        &launch.old,
        vec![("after_input", number(1))]
    )));
}

/// The two answers that carry the count: an answer without it is what a worker before the member
/// wrote, and reads with the count unknown; with it, the count is written.
#[test]
fn an_answer_carries_the_count_only_when_it_has_one() {
    let lease = map(vec![
        ("epoch", number(3)),
        ("holder", CanonicalValue::Null),
        ("connection_id", CanonicalValue::Null),
        ("next_sequence", number(0)),
    ]);
    let release_old = map(vec![("lease", lease)]);
    let read: InputLeaseResult = round_trips(&release_old);
    assert_eq!(read.fenced_bytes, None);
    let release_new = with(&release_old, vec![("fenced_bytes", number(512))]);
    let read: InputLeaseResult = round_trips(&release_new);
    assert_eq!(read.fenced_bytes, Some(U64::new(512)));

    let detach_old = map(vec![
        ("attachment_id", id(0x61)),
        (
            "geometry",
            map(vec![
                ("owner", CanonicalValue::Null),
                ("epoch", number(1)),
                (
                    "dimensions",
                    map(vec![("columns", number(80)), ("rows", number(24))]),
                ),
            ]),
        ),
        ("remaining", number(0)),
    ]);
    let read: SessionDetachResult = round_trips(&detach_old);
    assert_eq!(read.fenced_bytes, None);
    let detach_new = with(&detach_old, vec![("fenced_bytes", number(0))]);
    let read: SessionDetachResult = round_trips(&detach_new);
    assert_eq!(read.fenced_bytes, Some(U64::ZERO));
}

/// A worker that does not state the input lane is sent the old shape: the strip takes out exactly
/// the members that it does not know, and leaves everything else of the request as it was.
#[test]
fn the_strip_gives_a_worker_before_the_lane_the_old_wire() {
    for request in requests() {
        let stripped = strip_input_lane_members(request.method, &ParamsValue::new(request.new));
        assert_eq!(
            bytes_of(stripped.as_value()),
            bytes_of(&request.old),
            "{} is stripped to the old wire",
            request.method.as_str()
        );
        let unchanged =
            strip_input_lane_members(request.method, &ParamsValue::new(request.old.clone()));
        assert_eq!(bytes_of(unchanged.as_value()), bytes_of(&request.old));
    }
    // A method that carries none of the members is passed as it is.
    let other = ParamsValue::new(with(
        &map(vec![("session_id", id(0x51))]),
        vec![("after_input", barrier_wire(number(1)))],
    ));
    assert_eq!(strip_input_lane_members(Method::SessionRead, &other), other);
}

fn frame_wire(key: &str, members: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    map(vec![(key, map(members))])
}

/// The lane's role is a new value of the role union; the old values keep their wire strings.
#[test]
fn the_input_lane_has_a_role_and_the_others_keep_theirs() {
    assert_eq!(ControllerConnectionRole::ProxyInput.as_str(), "proxy_input");
    for (role, wire) in [
        (ControllerConnectionRole::Authority, "authority"),
        (ControllerConnectionRole::Proxy, "proxy"),
        (ControllerConnectionRole::Attention, "attention"),
        (ControllerConnectionRole::Descriptions, "descriptions"),
        (ControllerConnectionRole::Checks, "checks"),
        (ControllerConnectionRole::ProxyInput, "proxy_input"),
    ] {
        let frame = map(vec![("controller_role", text(wire))]);
        let read: ControlFrame = round_trips(&frame);
        assert_eq!(read, ControlFrame::ControllerRole(role));
    }
}

/// The two frames that bind a lane, and the three events a lane receives.
#[test]
fn the_lane_frames_and_events_read_from_the_wire() {
    let lane = frame_wire(
        "input_lane",
        vec![("proxy_connection", id(0x71)), ("attachment_id", id(0x61))],
    );
    let read: ControlFrame = round_trips(&lane);
    assert_eq!(
        read,
        ControlFrame::InputLane(InputLane {
            proxy_connection: ConnectionId::new(Uuid::from_bytes([0x71; 16])),
            attachment_id: AttachmentId::new(Uuid::from_bytes([0x61; 16])),
        })
    );
    let ready = frame_wire(
        "input_lane_ready",
        vec![
            ("epoch", number(3)),
            ("holder", CanonicalValue::Bool(true)),
            ("frames", number(64)),
            ("bytes", number(524_288)),
        ],
    );
    let read: ControlFrame = round_trips(&ready);
    assert_eq!(
        read,
        ControlFrame::InputLaneReady(InputLaneReady {
            epoch: InputLeaseEpoch::new(3),
            holder: true,
            frames: 64,
            bytes: U64::new(524_288),
        })
    );

    let event = |name: &str, members: Vec<(&str, CanonicalValue)>| {
        map(vec![("event", map(vec![(name, map(members))]))])
    };
    let window = |ended: CanonicalValue| {
        event(
            "input_window",
            vec![
                ("epoch", number(3)),
                ("holder", CanonicalValue::Bool(false)),
                ("frames", number(0)),
                ("bytes", number(0)),
                ("ended", ended),
            ],
        )
    };
    let read: ControlFrame = round_trips(&window(CanonicalValue::Null));
    assert_eq!(
        read,
        ControlFrame::Event(ControlEvent::InputWindow(LaneWindow {
            epoch: InputLeaseEpoch::new(3),
            holder: false,
            frames: 0,
            bytes: U64::ZERO,
            ended: Nullable::null(),
        }))
    );
    let ended = map(vec![("epoch", number(3)), ("fenced_bytes", number(512))]);
    let read: ControlFrame = round_trips(&window(ended));
    assert_eq!(
        read,
        ControlFrame::Event(ControlEvent::InputWindow(LaneWindow {
            epoch: InputLeaseEpoch::new(3),
            holder: false,
            frames: 0,
            bytes: U64::ZERO,
            ended: Nullable::some(LaneEnded {
                epoch: InputLeaseEpoch::new(3),
                fenced_bytes: U64::new(512),
            }),
        }))
    );
    let credit = event(
        "input_credit",
        vec![
            ("epoch", number(3)),
            ("frames", number(2)),
            ("bytes", number(1006)),
        ],
    );
    let read: ControlFrame = round_trips(&credit);
    assert_eq!(
        read,
        ControlFrame::Event(ControlEvent::InputCredit(LaneCredit {
            epoch: InputLeaseEpoch::new(3),
            frames: 2,
            bytes: U64::new(1006),
        }))
    );
    let launch = event(
        "input_launch_reserved",
        vec![("attachment_id", id(0x61)), ("launch", number(9))],
    );
    let read: ControlFrame = round_trips(&launch);
    assert_eq!(
        read,
        ControlFrame::Event(ControlEvent::InputLaunchReserved(LaneLaunch {
            attachment_id: AttachmentId::new(Uuid::from_bytes([0x61; 16])),
            launch: 9,
        }))
    );
}

/// The lane's messages are closed, and the count of bytes a lease's end discarded is a plain
/// number in the window event's `ended` member as in the answer.
#[test]
fn the_lane_messages_refuse_what_they_have_no_place_for() {
    let ended = |fenced_bytes: CanonicalValue| {
        map(vec![("epoch", number(3)), ("fenced_bytes", fenced_bytes)])
    };
    assert!(!is_refused::<LaneEnded>(ended(number(0))));
    assert!(is_refused::<LaneEnded>(ended(CanonicalValue::Null)));
    assert!(is_refused::<LaneEnded>(with(
        &ended(number(0)),
        vec![("reason", text("takeover"))]
    )));
    assert!(is_refused::<InputLane>(with(
        &map(vec![
            ("proxy_connection", id(0x71)),
            ("attachment_id", id(0x61))
        ]),
        vec![("epoch", number(1))]
    )));
    assert!(is_refused::<InputLaneReady>(map(vec![
        ("epoch", number(3)),
        ("holder", CanonicalValue::Bool(true)),
        ("frames", number(64)),
    ])));
}

/// The messages that existed before the lane keep their bytes.
#[test]
fn the_events_before_the_lane_keep_their_bytes() {
    let keepalive =
        ParamsValue::from_typed(&ControlFrame::Event(ControlEvent::Keepalive)).expect("it writes");
    assert_eq!(
        bytes_of(keepalive.as_value()),
        bytes_of(&map(vec![("event", text("keepalive"))]))
    );
}
