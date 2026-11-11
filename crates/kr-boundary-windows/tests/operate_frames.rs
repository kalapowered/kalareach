//! The frames of one invocation against real bytes: the exact encoding of each frame, every
//! field's bound at, under and over, fields the protocol does not name, repeated fields, frames cut
//! short and the two frame limits.

use std::io::{Cursor, Read};

use kr_boundary_windows::frame::invocation::{
    Arg, Cleanup, ConfigurationState, Dots, EndedBy, Format, Identity, InvocationId,
    InvocationReply, InvocationRequest, LeftoverClass, LineEndings, MAX_ARGUMENTS, MAX_COUNT,
    MAX_DETAIL_BYTES, MAX_DIRECTORY_UNITS, MAX_FORMAT_PARTS, MAX_FORMAT_TEXT_BYTES,
    MAX_IDENTITY_BYTES, MAX_MESSAGE_BYTES, MAX_NAME_BYTES, MAX_NOTE_BYTES, MAX_NOTES,
    MAX_OID_BYTES, MAX_OPERATE_FRAME, MAX_PATH_BYTES, MAX_PIPE_NAME_BYTES, MAX_REF_NAME_BYTES,
    MAX_REV_BYTES, MAX_WORD_BYTES, NamedFormat, Notes, OperateRequest, Part, Placeholder,
    RefusedKind, printable, read_reply, read_request, write_reply, write_request,
};
use kr_boundary_windows::frame::{Class, FieldError, FrameError, MAX_FRAME};
use serde_json::{Value, json};

fn wire(body: &[u8]) -> Vec<u8> {
    let mut frame = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
    frame.extend_from_slice(body);
    frame
}

fn request(arguments: Vec<Arg>) -> OperateRequest {
    OperateRequest {
        protocol_version: 1,
        class: Class::Checkout,
        directory: r"C:\Users\person\project".to_owned(),
        command: kr_boundary_windows::frame::invocation::Command::Log,
        arguments,
        identity: Identity {
            name: "A Person".to_owned(),
            email: "person@example.com".to_owned(),
        },
        line_endings: LineEndings::Input,
    }
}

/// What a reader makes of a request that the type allows but its bounds do not, written without
/// the writer's own check.
fn read_unchecked(request: &OperateRequest) -> Result<InvocationRequest, FrameError> {
    let body = serde_json::to_vec(&InvocationRequest::Operate(request.clone())).unwrap();
    read_request(&mut Cursor::new(wire(&body)))
}

fn read_json(value: &Value) -> Result<InvocationRequest, FrameError> {
    read_request(&mut Cursor::new(wire(value.to_string().as_bytes())))
}

fn operate_json() -> Value {
    json!({
        "request": "operate",
        "protocol_version": 1,
        "class": "checkout",
        "directory": "C:\\Users\\person\\project",
        "command": "log",
        "arguments": [],
        "identity": { "name": "A Person", "email": "person@example.com" },
        "line_endings": "input"
    })
}

#[test]
fn the_bounds_are_these_numbers() {
    assert_eq!(MAX_OPERATE_FRAME, 1_048_576);
    assert_eq!(MAX_FRAME, 16_384);
    assert_eq!(MAX_ARGUMENTS, 512);
    assert_eq!(MAX_PATH_BYTES, 240);
    assert_eq!(MAX_NAME_BYTES, 200);
    assert_eq!(MAX_REF_NAME_BYTES, 211);
    assert_eq!(MAX_REV_BYTES, 240);
    assert_eq!(MAX_OID_BYTES, 64);
    assert_eq!(MAX_MESSAGE_BYTES, 8192);
    assert_eq!(MAX_COUNT, 1000);
    assert_eq!(MAX_WORD_BYTES, 64);
    assert_eq!(MAX_FORMAT_PARTS, 64);
    assert_eq!(MAX_FORMAT_TEXT_BYTES, 256);
    assert_eq!(MAX_IDENTITY_BYTES, 200);
    assert_eq!(MAX_DIRECTORY_UNITS, 32_767);
    assert_eq!(MAX_DETAIL_BYTES, 200);
    assert_eq!(MAX_PIPE_NAME_BYTES, 256);
    assert_eq!(MAX_NOTES, 64);
    assert_eq!(MAX_NOTE_BYTES, 200);
}

#[test]
fn an_operate_request_is_encoded_as_these_bytes() {
    let request = request(vec![
        Arg::Word("--oneline".to_owned()),
        Arg::Count(5),
        Arg::Range {
            left: "main".to_owned(),
            right: "topic".to_owned(),
            dots: Dots::Three,
        },
        Arg::Format(Format::Custom(vec![
            Part::Placeholder(Placeholder::CommitHashShort),
            Part::Text(" by ".to_owned()),
            Part::Placeholder(Placeholder::AuthorName),
            Part::Placeholder(Placeholder::Percent),
        ])),
        Arg::Format(Format::Named(NamedFormat::Fuller)),
        Arg::Word("--".to_owned()),
        Arg::Path("src/lib.rs".to_owned()),
    ]);
    let mut sent = Vec::new();
    write_request(&mut sent, &InvocationRequest::Operate(request.clone())).unwrap();
    let expected = concat!(
        r#"{"request":"operate","protocol_version":1,"class":"checkout","#,
        r#""directory":"C:\\Users\\person\\project","command":"log","arguments":["#,
        r#"{"type":"word","value":"--oneline"},"#,
        r#"{"type":"count","value":5},"#,
        r#"{"type":"range","value":{"left":"main","right":"topic","dots":"three"}},"#,
        r#"{"type":"format","value":{"custom":[{"placeholder":"%h"},{"text":" by "},"#,
        r#"{"placeholder":"%an"},{"placeholder":"%%"}]}},"#,
        r#"{"type":"format","value":{"named":"fuller"}},"#,
        r#"{"type":"word","value":"--"},{"type":"path","value":"src/lib.rs"}],"#,
        r#""identity":{"name":"A Person","email":"person@example.com"},"line_endings":"input"}"#
    );
    assert_eq!(&sent[4..], expected.as_bytes());
    assert_eq!(
        u32::from_le_bytes(sent[..4].try_into().unwrap()) as usize,
        expected.len()
    );
    assert_eq!(
        read_request(&mut Cursor::new(sent)).unwrap(),
        InvocationRequest::Operate(request)
    );
}

#[test]
fn every_kind_of_argument_and_every_command_survives_a_round_trip() {
    use kr_boundary_windows::frame::invocation::Command::*;
    for command in [
        RevParse, Status, Diff, Log, Add, Checkout, Commit, UpdateRef,
    ] {
        let mut sent = request(vec![
            Arg::Path("a/b".to_owned()),
            Arg::Rev("HEAD~2".to_owned()),
            Arg::Name("feature/x".to_owned()),
            Arg::RefName("refs/heads/main".to_owned()),
            Arg::Oid("0123456789abcdef0123456789abcdef01234567".to_owned()),
            Arg::Message("subject\n\nbody".to_owned()),
            Arg::Count(0),
            Arg::Word("--porcelain=v2".to_owned()),
            Arg::Range {
                left: "a".to_owned(),
                right: "b".to_owned(),
                dots: Dots::Two,
            },
            Arg::Format(Format::Named(NamedFormat::Oneline)),
        ]);
        sent.command = command;
        let message = InvocationRequest::Operate(sent);
        let mut wire = Vec::new();
        write_request(&mut wire, &message).unwrap();
        assert_eq!(read_request(&mut Cursor::new(wire)).unwrap(), message);
    }
    for line_endings in [
        LineEndings::Unset,
        LineEndings::True,
        LineEndings::False,
        LineEndings::Input,
        LineEndings::Unknown,
    ] {
        let mut sent = request(vec![]);
        sent.line_endings = line_endings;
        sent.class = Class::Connect;
        let message = InvocationRequest::Operate(sent);
        let mut wire = Vec::new();
        write_request(&mut wire, &message).unwrap();
        assert_eq!(read_request(&mut Cursor::new(wire)).unwrap(), message);
    }
}

#[test]
fn a_cancel_request_carries_an_invocation_and_nothing_else() {
    let id = InvocationId::from_bytes([0xAB; 16]);
    assert_eq!(id.as_str(), "abababababababababababababababab");
    let mut sent = Vec::new();
    write_request(
        &mut sent,
        &InvocationRequest::Cancel {
            invocation: id.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        &sent[4..],
        br#"{"request":"cancel","invocation":"abababababababababababababababab"}"#
    );
    assert_eq!(
        read_request(&mut Cursor::new(sent)).unwrap(),
        InvocationRequest::Cancel { invocation: id }
    );
    for bad in [
        "",
        "abab",
        "ABABABABABABABABABABABABABABABAB",
        "zbababababababababababababababab",
        "abababababababababababababababab0",
    ] {
        let body = json!({ "request": "cancel", "invocation": bad });
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn no_field_names_a_handle_a_process_a_token_a_program_a_variable_or_an_option() {
    for name in [
        "handle",
        "pid",
        "process",
        "token",
        "program",
        "path_to_git",
        "env",
        "environment",
        "variable",
        "config",
        "c",
        "-c",
        "option",
        "extra",
    ] {
        let mut body = operate_json();
        body[name] = json!(1);
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "request field {name}"
        );

        let mut body = operate_json();
        body["identity"][name] = json!("x");
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "identity field {name}"
        );

        let mut body = operate_json();
        body["arguments"] = json!([{ "type": "word", "value": "--", name: 1 }]);
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "argument field {name}"
        );

        let body = json!({
            "request": "cancel",
            "invocation": "abababababababababababababababab",
            name: 1
        });
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "cancel field {name}"
        );
    }
    // The same holds inside a range and a format, and for a type the protocol does not name.
    let mut body = operate_json();
    body["arguments"] = json!([{
        "type": "range",
        "value": { "left": "a", "right": "b", "dots": "two", "handle": 7 }
    }]);
    assert!(matches!(read_json(&body), Err(FrameError::Malformed(_))));
    let mut body = operate_json();
    body["arguments"] = json!([{ "type": "handle", "value": 7 }]);
    assert!(matches!(read_json(&body), Err(FrameError::Malformed(_))));
    let mut body = operate_json();
    body["command"] = json!("config");
    assert!(matches!(read_json(&body), Err(FrameError::Malformed(_))));
    let mut body = operate_json();
    body["request"] = json!("run");
    assert!(matches!(read_json(&body), Err(FrameError::Malformed(_))));
    // A placeholder outside the list is not a part.
    for placeholder in ["%aN", "%d", "%(describe)", "%x41", "%G?", "%an "] {
        let mut body = operate_json();
        body["arguments"] = json!([{
            "type": "format",
            "value": { "custom": [{ "placeholder": placeholder }] }
        }]);
        assert!(
            matches!(read_json(&body), Err(FrameError::Malformed(_))),
            "{placeholder}"
        );
    }
}

#[test]
fn a_field_that_appears_twice_is_a_parse_error() {
    let whole = br#"{"request":"operate","protocol_version":1,"class":"checkout","directory":"C:\\t","command":"log","arguments":[],"identity":{"name":"n","email":"e"},"line_endings":"input"}"#;
    let ok = read_request(&mut Cursor::new(wire(whole))).unwrap();
    assert!(matches!(ok, InvocationRequest::Operate(_)));
    let repeats: [(&str, &str); 4] = [
        (
            r#""directory":"C:\\t","#,
            r#""directory":"C:\\t","directory":"D:\\u","#,
        ),
        (r#""command":"log","#, r#""command":"log","command":"add","#),
        (r#""name":"n","#, r#""name":"n","name":"m","#),
        (
            r#"{"request":"operate","#,
            r#"{"request":"operate","request":"cancel","#,
        ),
    ];
    for (find, replace) in repeats {
        let text = std::str::from_utf8(whole)
            .unwrap()
            .replacen(find, replace, 1);
        assert_ne!(text.as_bytes(), whole.as_slice());
        assert!(
            matches!(
                read_request(&mut Cursor::new(wire(text.as_bytes()))),
                Err(FrameError::Malformed(_))
            ),
            "{find}"
        );
    }
    let twice = br#"{"request":"cancel","invocation":"abababababababababababababababab","invocation":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"}"#;
    assert!(matches!(
        read_request(&mut Cursor::new(wire(twice))),
        Err(FrameError::Malformed(_))
    ));
}

fn too_long(error: FrameError, field: &str) -> bool {
    matches!(error, FrameError::Field(FieldError::TooLong { field: found, .. }) if found == field)
}

#[test]
fn every_text_argument_may_be_as_long_as_its_bound_and_no_longer() {
    type Make = fn(String) -> Arg;
    let table: [(&str, usize, Make); 7] = [
        ("path", MAX_PATH_BYTES, Arg::Path),
        ("revision", MAX_REV_BYTES, Arg::Rev),
        ("name", MAX_NAME_BYTES, Arg::Name),
        ("reference name", MAX_REF_NAME_BYTES, Arg::RefName),
        ("object identifier", MAX_OID_BYTES, Arg::Oid),
        ("message", MAX_MESSAGE_BYTES, Arg::Message),
        ("word", MAX_WORD_BYTES, Arg::Word),
    ];
    for (field, max, make) in table {
        for length in [1, max / 2, max - 1, max] {
            let sent = request(vec![make("x".repeat(length))]);
            assert!(read_unchecked(&sent).is_ok(), "{field} of {length}");
            write_request(&mut Vec::new(), &InvocationRequest::Operate(sent)).unwrap();
        }
        let over = request(vec![make("x".repeat(max + 1))]);
        let error = read_unchecked(&over).unwrap_err();
        assert!(too_long(error, field), "{field} of {}", max + 1);
        let error = write_request(&mut Vec::new(), &InvocationRequest::Operate(over)).unwrap_err();
        assert!(too_long(error, field), "{field} written over");
    }
    // A bound counts bytes, not characters.
    let wide = request(vec![Arg::Path("é".repeat(MAX_PATH_BYTES / 2))]);
    assert!(read_unchecked(&wide).is_ok());
    let wider = request(vec![Arg::Path("é".repeat(MAX_PATH_BYTES / 2 + 1))]);
    assert!(too_long(read_unchecked(&wider).unwrap_err(), "path"));
}

#[test]
fn a_range_bounds_each_of_its_revisions() {
    let range = |left: usize, right: usize| {
        request(vec![Arg::Range {
            left: "a".repeat(left),
            right: "b".repeat(right),
            dots: Dots::Two,
        }])
    };
    assert!(read_unchecked(&range(MAX_REV_BYTES, MAX_REV_BYTES)).is_ok());
    assert!(too_long(
        read_unchecked(&range(MAX_REV_BYTES + 1, 1)).unwrap_err(),
        "revision"
    ));
    assert!(too_long(
        read_unchecked(&range(1, MAX_REV_BYTES + 1)).unwrap_err(),
        "revision"
    ));
}

#[test]
fn a_count_is_at_most_a_thousand() {
    for count in [0, 1, MAX_COUNT - 1, MAX_COUNT] {
        assert!(read_unchecked(&request(vec![Arg::Count(count)])).is_ok());
    }
    let error = read_unchecked(&request(vec![Arg::Count(MAX_COUNT + 1)])).unwrap_err();
    assert!(too_long(error, "count"));
    let mut body = operate_json();
    body["arguments"] = json!([{ "type": "count", "value": -1 }]);
    assert!(matches!(read_json(&body), Err(FrameError::Malformed(_))));
}

#[test]
fn a_request_carries_at_most_so_many_arguments() {
    let words = |count: usize| request(vec![Arg::Word("-q".to_owned()); count]);
    assert!(read_unchecked(&words(MAX_ARGUMENTS)).is_ok());
    let error = read_unchecked(&words(MAX_ARGUMENTS + 1)).unwrap_err();
    assert!(matches!(
        error,
        FrameError::Field(FieldError::TooMany {
            field: "arguments",
            ..
        })
    ));
}

#[test]
fn a_custom_format_has_bounded_parts_and_text_that_cannot_spell_a_placeholder() {
    let custom = |parts: Vec<Part>| request(vec![Arg::Format(Format::Custom(parts))]);
    let placeholders = |count: usize| vec![Part::Placeholder(Placeholder::Subject); count];
    assert!(read_unchecked(&custom(placeholders(MAX_FORMAT_PARTS))).is_ok());
    let error = read_unchecked(&custom(placeholders(MAX_FORMAT_PARTS + 1))).unwrap_err();
    assert!(matches!(
        error,
        FrameError::Field(FieldError::TooMany {
            field: "format parts",
            ..
        })
    ));
    let text = |length: usize| custom(vec![Part::Text("t".repeat(length))]);
    assert!(read_unchecked(&text(MAX_FORMAT_TEXT_BYTES)).is_ok());
    assert!(too_long(
        read_unchecked(&text(MAX_FORMAT_TEXT_BYTES + 1)).unwrap_err(),
        "format text"
    ));
    for bad in [
        "50%",
        "%an",
        "%(describe)",
        "a\nb",
        "a\0b",
        "tab\there",
        "\u{7f}",
    ] {
        let error = read_unchecked(&custom(vec![Part::Text(bad.to_owned())])).unwrap_err();
        assert!(
            matches!(
                error,
                FrameError::Field(FieldError::Form {
                    field: "format text"
                })
            ),
            "{bad:?}"
        );
    }
    assert!(read_unchecked(&custom(vec![Part::Text("é and text".to_owned())])).is_ok());
}

#[test]
fn the_identity_is_single_line_text_of_at_most_two_hundred_bytes() {
    let with = |name: String, email: String| {
        let mut sent = request(vec![]);
        sent.identity = Identity { name, email };
        sent
    };
    let at = "n".repeat(MAX_IDENTITY_BYTES);
    assert!(read_unchecked(&with(at.clone(), at.clone())).is_ok());
    let over = "n".repeat(MAX_IDENTITY_BYTES + 1);
    assert!(too_long(
        read_unchecked(&with(over.clone(), "e".to_owned())).unwrap_err(),
        "identity name"
    ));
    assert!(too_long(
        read_unchecked(&with("n".to_owned(), over)).unwrap_err(),
        "identity email"
    ));
    for bad in [
        "two\nlines",
        "nul\0",
        "tab\t",
        "esc\u{1b}[0m",
        "\u{7f}",
        "c1\u{85}",
    ] {
        for (name, email) in [(bad, "e"), ("n", bad)] {
            let error = read_unchecked(&with(name.to_owned(), email.to_owned())).unwrap_err();
            assert!(
                matches!(error, FrameError::Field(FieldError::Form { .. })),
                "{bad:?}"
            );
        }
    }
}

#[test]
fn the_directory_is_a_path_of_the_platforms_length() {
    let with = |directory: String| {
        let mut sent = request(vec![]);
        sent.directory = directory;
        sent
    };
    assert!(read_unchecked(&with("C".repeat(MAX_DIRECTORY_UNITS))).is_ok());
    assert!(too_long(
        read_unchecked(&with("C".repeat(MAX_DIRECTORY_UNITS + 1))).unwrap_err(),
        "directory"
    ));
    // The limit counts UTF-16 units: a character outside the basic plane takes two.
    assert!(read_unchecked(&with("\u{1F600}".repeat(MAX_DIRECTORY_UNITS / 2))).is_ok());
    assert!(too_long(
        read_unchecked(&with("\u{1F600}".repeat(MAX_DIRECTORY_UNITS / 2 + 1))).unwrap_err(),
        "directory"
    ));
    for bad in ["", "C:\\a\0b"] {
        let error = read_unchecked(&with(bad.to_owned())).unwrap_err();
        assert!(
            matches!(
                error,
                FrameError::Field(FieldError::Form { field: "directory" })
            ),
            "{bad:?}"
        );
    }
}

/// A reader that counts the bytes it hands out.
struct Counting<'a> {
    inner: Cursor<&'a [u8]>,
    taken: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buffer)?;
        self.taken += count;
        Ok(count)
    }
}

#[test]
fn an_operate_frame_may_take_a_megabyte_and_every_other_frame_sixteen_kilobytes() {
    // The largest request the tables allow: 256 paths of 240 bytes, a message of 8 KiB and the
    // options. Its frame is over the ordinary limit and inside the operate limit.
    let mut arguments = vec![Arg::Message("m".repeat(MAX_MESSAGE_BYTES))];
    arguments.extend((0..256).map(|_| Arg::Path("p".repeat(MAX_PATH_BYTES))));
    arguments.extend((0..20).map(|_| Arg::Word("--untracked-files=normal".to_owned())));
    let full = InvocationRequest::Operate(request(arguments));
    let mut sent = Vec::new();
    write_request(&mut sent, &full).unwrap();
    assert!(sent.len() - 4 > MAX_FRAME, "{} bytes", sent.len());
    assert!(sent.len() - 4 < MAX_OPERATE_FRAME);
    assert_eq!(read_request(&mut Cursor::new(sent)).unwrap(), full);

    // The same bytes are refused as any other frame.
    let body = serde_json::to_vec(&full).unwrap();
    let mut other = Vec::new();
    assert!(matches!(
        kr_boundary_windows::frame::write(&mut other, &full),
        Err(FrameError::TooLong(length)) if length == body.len()
    ));
    assert!(other.is_empty());

    // An operate frame over its own limit is refused before its body is read.
    let over = vec![b'x'; MAX_OPERATE_FRAME + 1];
    let bytes = wire(&over);
    let mut counting = Counting {
        inner: Cursor::new(&bytes),
        taken: 0,
    };
    assert!(matches!(
        read_request(&mut counting),
        Err(FrameError::TooLong(length)) if length == MAX_OPERATE_FRAME + 1
    ));
    assert_eq!(counting.taken, 4);

    // A frame of exactly the operate limit is read in full and then refused as no request.
    let at = wire(&vec![b' '; MAX_OPERATE_FRAME]);
    assert!(matches!(
        read_request(&mut Cursor::new(at)),
        Err(FrameError::Malformed(_))
    ));

    // A cancel request padded past the ordinary limit is too long, not only malformed.
    let mut padded =
        br#"{"request":"cancel","invocation":"abababababababababababababababab"}"#.to_vec();
    padded.extend(std::iter::repeat_n(b' ', MAX_FRAME));
    assert!(matches!(
        read_request(&mut Cursor::new(wire(&padded))),
        Err(FrameError::TooLong(_))
    ));
    // At the ordinary limit it is read.
    let mut at =
        br#"{"request":"cancel","invocation":"abababababababababababababababab"}"#.to_vec();
    let fill = MAX_FRAME - at.len();
    at.extend(std::iter::repeat_n(b' ', fill));
    assert!(read_request(&mut Cursor::new(wire(&at))).is_ok());
}

#[test]
fn a_frame_may_be_written_at_its_limit_and_no_longer() {
    // A JSON string of n letters takes n + 2 bytes.
    let mut sent = Vec::new();
    kr_boundary_windows::frame::write(&mut sent, &"x".repeat(MAX_FRAME - 2)).unwrap();
    assert_eq!(sent.len(), 4 + MAX_FRAME);
    assert!(matches!(
        kr_boundary_windows::frame::write(&mut Vec::new(), &"x".repeat(MAX_FRAME - 1)),
        Err(FrameError::TooLong(length)) if length == MAX_FRAME + 1
    ));

    // An operate request of exactly the operate limit: messages of 8 KiB, and a last one whose
    // length makes the frame exactly as long as the limit allows.
    let size = |arguments: &[Arg]| {
        serde_json::to_vec(&InvocationRequest::Operate(request(arguments.to_vec())))
            .unwrap()
            .len()
    };
    let mut arguments = Vec::new();
    while size(&arguments) + 8192 + 40 < MAX_OPERATE_FRAME {
        arguments.push(Arg::Message("m".repeat(MAX_MESSAGE_BYTES)));
    }
    // A message of n letters adds n bytes to the frame, so the last one is the difference.
    arguments.push(Arg::Message(String::new()));
    let empty = size(&arguments);
    arguments.pop();
    let length = MAX_OPERATE_FRAME - empty;
    assert!(length <= MAX_MESSAGE_BYTES, "{length}");
    arguments.push(Arg::Message("m".repeat(length)));
    let at = InvocationRequest::Operate(request(arguments.clone()));
    let mut sent = Vec::new();
    write_request(&mut sent, &at).unwrap();
    assert_eq!(sent.len(), 4 + MAX_OPERATE_FRAME);
    assert_eq!(read_request(&mut Cursor::new(sent)).unwrap(), at);
    arguments.push(Arg::Word("-".to_owned()));
    let over = InvocationRequest::Operate(request(arguments));
    assert!(matches!(
        write_request(&mut Vec::new(), &over),
        Err(FrameError::TooLong(_))
    ));
}

#[test]
fn a_frame_cut_short_is_a_failure_and_a_closed_connection_is_a_close() {
    let mut sent = Vec::new();
    write_request(&mut sent, &InvocationRequest::Operate(request(vec![]))).unwrap();
    assert!(matches!(
        read_request(&mut Cursor::new(Vec::<u8>::new())),
        Err(FrameError::Closed)
    ));
    for cut in [1, 2, 3, 4, 5, sent.len() / 2, sent.len() - 1] {
        let result = read_request(&mut Cursor::new(sent[..cut].to_vec()));
        assert!(matches!(result, Err(FrameError::Io(_))), "cut at {cut}");
    }
    let mut cancel = Vec::new();
    write_reply(
        &mut cancel,
        &InvocationReply::refused(RefusedKind::Busy, "busy"),
    )
    .unwrap();
    assert!(matches!(
        read_reply(&mut Cursor::new(cancel[..cancel.len() - 1].to_vec())),
        Err(FrameError::Io(_))
    ));
}

fn replies() -> Vec<InvocationReply> {
    let mut all = vec![
        InvocationReply::Accepted {
            invocation: InvocationId::from_bytes([7; 16]),
            stdout_pipe: r"\\.\pipe\KalaReachBoundary-07070707070707070707070707070707-out"
                .to_owned(),
            stderr_pipe: r"\\.\pipe\KalaReachBoundary-07070707070707070707070707070707-err"
                .to_owned(),
        },
        InvocationReply::Finished {
            exit: None,
            ended_by: EndedBy::Disconnect,
            cleanup: Cleanup::Uncertain,
            configuration: ConfigurationState::Changed {
                name: "core.autocrlf".to_owned(),
            },
            notes: Notes::default(),
            replaced_protected: 0,
        },
    ];
    for kind in [
        RefusedKind::Authentication,
        RefusedKind::Busy,
        RefusedKind::Leftover,
        RefusedKind::Operation,
        RefusedKind::Configuration,
        RefusedKind::Repository,
        RefusedKind::Admission,
        RefusedKind::Transport,
        RefusedKind::Limit,
        RefusedKind::Maintenance,
    ] {
        all.push(InvocationReply::refused(kind, "a reason"));
    }
    for ended_by in [
        EndedBy::Exit,
        EndedBy::ClientExit,
        EndedBy::Disconnect,
        EndedBy::Cancel,
        EndedBy::Deadline,
        EndedBy::Stop,
    ] {
        all.push(InvocationReply::Finished {
            exit: Some(128),
            ended_by,
            cleanup: Cleanup::Clean,
            configuration: ConfigurationState::Same,
            notes: Notes::bounded(["shared read of a.txt"]),
            replaced_protected: 3,
        });
    }
    for class in [
        LeftoverClass::Tree,
        LeftoverClass::Repository,
        LeftoverClass::Uncertain,
        LeftoverClass::Root,
    ] {
        all.push(InvocationReply::Finished {
            exit: Some(0),
            ended_by: EndedBy::Exit,
            cleanup: Cleanup::Failed {
                object: r"src\lib.rs".to_owned(),
                class,
            },
            configuration: ConfigurationState::Same,
            notes: Notes::default(),
            replaced_protected: 0,
        });
    }
    all
}

#[test]
fn every_reply_survives_a_round_trip() {
    for reply in replies() {
        let mut sent = Vec::new();
        write_reply(&mut sent, &reply).unwrap();
        assert_eq!(read_reply(&mut Cursor::new(sent)).unwrap(), reply);
    }
}

#[test]
fn the_replies_are_encoded_as_these_bytes() {
    let encoded = |reply: &InvocationReply| {
        let mut sent = Vec::new();
        write_reply(&mut sent, reply).unwrap();
        String::from_utf8(sent[4..].to_vec()).unwrap()
    };
    assert_eq!(
        encoded(&replies()[0]),
        concat!(
            r#"{"answer":"accepted","invocation":"07070707070707070707070707070707","#,
            r#""stdout_pipe":"\\\\.\\pipe\\KalaReachBoundary-07070707070707070707070707070707-out","#,
            r#""stderr_pipe":"\\\\.\\pipe\\KalaReachBoundary-07070707070707070707070707070707-err"}"#
        )
    );
    assert_eq!(
        encoded(&InvocationReply::refused(RefusedKind::Repository, "HEAD")),
        r#"{"answer":"refused","kind":"repository","detail":"HEAD"}"#
    );
    assert_eq!(
        encoded(&replies()[1]),
        concat!(
            r#"{"answer":"finished","exit":null,"ended_by":"disconnect","cleanup":"uncertain","#,
            r#""configuration":{"changed":{"name":"core.autocrlf"}},"#,
            r#""notes":{"items":[],"cut":0},"replaced_protected":0}"#
        )
    );
    let failed = InvocationReply::Finished {
        exit: Some(1),
        ended_by: EndedBy::ClientExit,
        cleanup: Cleanup::Failed {
            object: "a".to_owned(),
            class: LeftoverClass::Repository,
        },
        configuration: ConfigurationState::Same,
        notes: Notes::bounded(["n"]),
        replaced_protected: 2,
    };
    assert_eq!(
        encoded(&failed),
        concat!(
            r#"{"answer":"finished","exit":1,"ended_by":"client-exit","#,
            r#""cleanup":{"failed":{"object":"a","class":"repository"}},"#,
            r#""configuration":"same","notes":{"items":["n"],"cut":0},"replaced_protected":2}"#
        )
    );
}

#[test]
fn a_reply_with_a_field_the_protocol_does_not_name_is_refused() {
    for body in [
        json!({ "answer": "refused", "kind": "busy", "detail": "d", "handle": 1 }),
        json!({ "answer": "accepted", "invocation": "abababababababababababababababab",
                "stdout_pipe": "o", "stderr_pipe": "e", "pid": 4 }),
        json!({ "answer": "finished", "exit": 0, "ended_by": "exit", "cleanup": "clean",
                "configuration": "same", "notes": { "items": [], "cut": 0, "more": 1 },
                "replaced_protected": 0 }),
        json!({ "answer": "finished", "exit": 0, "ended_by": "exit", "cleanup": "clean",
                "configuration": "same", "notes": { "items": [], "cut": 0 } }),
        json!({ "answer": "refused", "kind": "unknown-kind", "detail": "d" }),
        json!({ "answer": "finished", "exit": 0, "ended_by": "exit",
                "cleanup": { "failed": { "object": "a", "class": "tree", "extra": 1 } },
                "configuration": "same", "notes": { "items": [], "cut": 0 },
                "replaced_protected": 0 }),
        json!({ "answer": "finished", "exit": 0, "ended_by": "exit", "cleanup": "clean",
                "configuration": { "changed": { "name": "n", "extra": 1 } },
                "notes": { "items": [], "cut": 0 }, "replaced_protected": 0 }),
    ] {
        assert!(
            matches!(
                read_reply(&mut Cursor::new(wire(body.to_string().as_bytes()))),
                Err(FrameError::Malformed(_))
            ),
            "{body}"
        );
    }
}

#[test]
fn a_refusal_is_printable_text_of_at_most_two_hundred_bytes() {
    let refused = |text: &str| {
        let InvocationReply::Refused { detail, .. } =
            InvocationReply::refused(RefusedKind::Operation, text)
        else {
            unreachable!()
        };
        detail
    };
    assert_eq!(refused("a\tb\nc\u{1b}[31md\0e"), "a?b?c?[31md?e");
    assert_eq!(refused("naïve").len(), "naïve".len());
    assert!(refused("naïve").bytes().all(|byte| byte.is_ascii()));
    assert_eq!(
        refused(&"x".repeat(MAX_DETAIL_BYTES)).len(),
        MAX_DETAIL_BYTES
    );
    assert_eq!(
        refused(&"x".repeat(MAX_DETAIL_BYTES + 1)).len(),
        MAX_DETAIL_BYTES
    );
    assert_eq!(printable("abc", 2), "ab");
    assert_eq!(printable("a~ \u{7f}\u{1f}", 10), "a~ ??");
    // A peer's reply that is over the limit or not printable is refused on reading, and our own
    // writer will not send it.
    for detail in [
        "x".repeat(MAX_DETAIL_BYTES + 1),
        "line\nbreak".to_owned(),
        "é".to_owned(),
    ] {
        let reply = InvocationReply::Refused {
            kind: RefusedKind::Busy,
            detail,
        };
        assert!(write_reply(&mut Vec::new(), &reply).is_err());
        let body = serde_json::to_vec(&reply).unwrap();
        assert!(matches!(
            read_reply(&mut Cursor::new(wire(&body))),
            Err(FrameError::Field(_))
        ));
    }
    let at = InvocationReply::Refused {
        kind: RefusedKind::Busy,
        detail: "x".repeat(MAX_DETAIL_BYTES),
    };
    write_reply(&mut Vec::new(), &at).unwrap();
}

#[test]
fn a_reply_names_are_bounded_in_every_text() {
    let finished = |object: String, name: String| InvocationReply::Finished {
        exit: Some(0),
        ended_by: EndedBy::Exit,
        cleanup: Cleanup::Failed {
            object,
            class: LeftoverClass::Tree,
        },
        configuration: ConfigurationState::Changed { name },
        notes: Notes::default(),
        replaced_protected: 0,
    };
    let at = "x".repeat(MAX_DETAIL_BYTES);
    let over = "x".repeat(MAX_DETAIL_BYTES + 1);
    assert!(finished(at.clone(), at.clone()).check().is_ok());
    assert!(finished(over.clone(), at.clone()).check().is_err());
    assert!(finished(at.clone(), over).check().is_err());
    assert!(finished("tab\t".to_owned(), at).check().is_err());
    let pipes = |out: String, err: String| InvocationReply::Accepted {
        invocation: InvocationId::from_bytes([1; 16]),
        stdout_pipe: out,
        stderr_pipe: err,
    };
    let at = "p".repeat(MAX_PIPE_NAME_BYTES);
    let over = "p".repeat(MAX_PIPE_NAME_BYTES + 1);
    assert!(pipes(at.clone(), at.clone()).check().is_ok());
    assert!(pipes(over.clone(), at.clone()).check().is_err());
    assert!(pipes(at.clone(), over).check().is_err());
    assert!(pipes("o\n".to_owned(), at.clone()).check().is_err());
    assert!(pipes(at, "e\n".to_owned()).check().is_err());
}

#[test]
fn a_note_a_peer_sends_is_checked_like_one_made_here() {
    let finished = |notes: Vec<String>| InvocationReply::Finished {
        exit: Some(0),
        ended_by: EndedBy::Exit,
        cleanup: Cleanup::Clean,
        configuration: ConfigurationState::Same,
        notes: Notes {
            items: notes,
            cut: 0,
        },
        replaced_protected: 0,
    };
    assert!(finished(vec!["n".repeat(MAX_NOTE_BYTES)]).check().is_ok());
    assert!(
        finished(vec!["n".repeat(MAX_NOTE_BYTES + 1)])
            .check()
            .is_err()
    );
    assert!(
        finished(vec!["a".to_owned(), "two\nlines".to_owned()])
            .check()
            .is_err()
    );
    assert!(finished(vec!["\u{e9}".to_owned()]).check().is_err());
    let body = serde_json::to_vec(&finished(vec!["x".repeat(MAX_NOTE_BYTES + 1)])).unwrap();
    assert!(matches!(
        read_reply(&mut Cursor::new(wire(&body))),
        Err(FrameError::Field(_))
    ));
}

#[test]
fn notes_are_bounded_and_carry_a_mark_for_what_was_cut() {
    let none = Notes::bounded(Vec::<String>::new());
    assert_eq!((none.items.len(), none.cut), (0, 0));

    let few = Notes::bounded(["one", "two"]);
    assert_eq!(few.items, ["one", "two"]);
    assert_eq!(few.cut, 0);

    let at = vec!["n".repeat(MAX_NOTE_BYTES); MAX_NOTES];
    let full = Notes::bounded(&at);
    assert_eq!(full.items.len(), MAX_NOTES);
    assert_eq!(full.cut, 0);
    assert!(full.items.iter().all(|note| note.len() == MAX_NOTE_BYTES));

    let many = Notes::bounded(vec!["n".to_owned(); MAX_NOTES + 5]);
    assert_eq!(many.items.len(), MAX_NOTES);
    assert_eq!(many.cut, 5);

    let long = Notes::bounded([&"x".repeat(MAX_NOTE_BYTES + 50), "short"]);
    assert_eq!(long.items[0].len(), MAX_NOTE_BYTES);
    assert_eq!(long.items[1], "short");
    assert_eq!(long.cut, 1);

    let dirty = Notes::bounded(["a\nb"]);
    assert_eq!(dirty.items, ["a?b"]);
    assert_eq!(dirty.cut, 0);
}

#[test]
fn the_notes_have_exactly_the_room_of_fourteen_kilobytes_of_json() {
    // Each note of 179 letters and 21 quotation marks takes 224 bytes of JSON with its quotes,
    // its escapes and its comma, so 64 of them take exactly 14 KiB and all stay.
    let note = format!("{}{}", "n".repeat(179), "\"".repeat(21));
    assert_eq!(note.len(), MAX_NOTE_BYTES);
    let exact = Notes::bounded(vec![note.as_str(); MAX_NOTES]);
    assert_eq!(exact.items.len(), MAX_NOTES);
    assert_eq!(exact.cut, 0);
    // One byte more in the last note and it no longer fits.
    let mut notes = vec![note.clone(); MAX_NOTES - 1];
    notes.push(format!("{}{}", "n".repeat(178), "\"".repeat(22)));
    let over = Notes::bounded(&notes);
    assert_eq!((over.items.len(), over.cut), (MAX_NOTES - 1, 1));
    // Notes of 200 quotation marks take 403 bytes each, so 35 fill the room.
    let hostile = Notes::bounded(vec!["\"".repeat(MAX_NOTE_BYTES); MAX_NOTES]);
    assert_eq!(hostile.items.len(), 35);
    assert_eq!(hostile.cut, 29);
}

#[test]
fn a_result_with_every_note_at_its_limit_and_every_character_escaped_still_fits_a_frame() {
    // A quotation mark takes two bytes of JSON, so the notes' own bound is what keeps the frame
    // inside the ordinary limit.
    let hostile = vec!["\"".repeat(MAX_NOTE_BYTES); MAX_NOTES];
    let notes = Notes::bounded(&hostile);
    assert!(
        notes.cut > 0,
        "the frame has room for fewer than {MAX_NOTES}"
    );
    assert!(notes.items.len() < MAX_NOTES);
    let mut reply = InvocationReply::Finished {
        exit: Some(u32::MAX),
        ended_by: EndedBy::ClientExit,
        cleanup: Cleanup::Failed {
            object: "\"".repeat(MAX_DETAIL_BYTES),
            class: LeftoverClass::Repository,
        },
        configuration: ConfigurationState::Changed {
            name: "\\".repeat(MAX_DETAIL_BYTES),
        },
        notes,
        replaced_protected: u32::MAX,
    };
    let mut sent = Vec::new();
    write_reply(&mut sent, &reply).unwrap();
    assert!(sent.len() - 4 <= MAX_FRAME);
    assert_eq!(read_reply(&mut Cursor::new(sent)).unwrap(), reply);
    // More notes than the bound are refused when a peer sends them.
    if let InvocationReply::Finished { notes, .. } = &mut reply {
        notes.items = vec!["n".to_owned(); MAX_NOTES + 1];
    }
    assert!(matches!(
        reply.check(),
        Err(FieldError::TooMany { field: "notes", .. })
    ));
}
