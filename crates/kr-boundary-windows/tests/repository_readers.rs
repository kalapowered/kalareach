//! The five readers: their fixed lines, their deadlines and the contract their output keeps.

use std::time::Duration;

use kr_boundary_windows::frame::invocation::{MAX_REF_NAME_BYTES, RefusedKind};
use kr_boundary_windows::operation::Writes;
use kr_boundary_windows::repository::readers::{
    Argument, Entry, MAX_BLOB_BYTES, MAX_BLOB_TOTAL_BYTES, MAX_BLOBS, MAX_LISTING_BYTES,
    MAX_LISTING_RECORDS, MAX_SYMBOLIC_TARGET_BYTES, MODE_GITLINK, Output, READERS,
    RULE_READER_ARGUMENT, RULE_READER_BOUNDS, RULE_READER_COUNT, RULE_READER_DEADLINE,
    RULE_READER_EXIT, RULE_READER_FRAMING, RULE_READER_MISSING, RULE_UNRESOLVED, Reader, Symbolic,
    attributes_entries, blob_request, form, parse_r1, parse_r2, parse_r3, parse_r4, parse_r5,
    reader_line,
};

const OID: &str = "0123456789abcdef0123456789abcdef01234567";
const OID2: &str = "fedcba9876543210fedcba9876543210fedcba98";

fn out(exit: u32, stdout: &[u8]) -> Output<'_> {
    Output {
        exit: Some(exit),
        stdout,
    }
}

const DEADLINE: Output<'static> = Output {
    exit: None,
    stdout: b"",
};

fn strings(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

/// The rule of a refusal, which is of kind `operation`.
fn rule<T: std::fmt::Debug>(
    result: Result<T, kr_boundary_windows::refusal::Refusal>,
) -> &'static str {
    let refusal = result.expect_err("refused");
    assert_eq!(refusal.kind, RefusedKind::Operation, "{refusal}");
    refusal.rule
}

#[test]
fn the_five_forms_are_these_lines_with_these_deadlines() {
    let table = [
        (
            Reader::R1,
            "R1",
            vec!["rev-parse", "--verify", "--end-of-options"],
            Argument::Revision,
            vec![0],
            10,
        ),
        (
            Reader::R2,
            "R2",
            vec!["symbolic-ref", "-q"],
            Argument::RefName,
            vec![0, 1],
            10,
        ),
        (
            Reader::R3,
            "R3",
            vec!["ls-tree", "-r", "-z", "--full-tree"],
            Argument::Oid,
            vec![0],
            30,
        ),
        (
            Reader::R4,
            "R4",
            vec!["ls-files", "-z", "--stage"],
            Argument::Nothing,
            vec![0],
            30,
        ),
        (
            Reader::R5,
            "R5",
            vec!["cat-file", "--batch"],
            Argument::Nothing,
            vec![0],
            60,
        ),
    ];
    assert_eq!(READERS.len(), 5);
    for (reader, name, argv, argument, results, seconds) in table {
        let own = form(reader);
        assert_eq!(own.reader, reader);
        assert_eq!(own.name, name);
        assert_eq!(own.argv, argv);
        assert_eq!(own.argument, argument);
        assert_eq!(own.results, results);
        assert_eq!(own.deadline, Duration::from_secs(seconds));
        assert!(
            READERS
                .iter()
                .any(|candidate| candidate.reader == reader && candidate.name == name)
        );
    }
}

#[test]
fn the_bounds_are_these_numbers() {
    assert_eq!(MAX_LISTING_BYTES, 1_048_576);
    assert_eq!(MAX_LISTING_RECORDS, 100_000);
    assert_eq!(MAX_BLOBS, 4096);
    assert_eq!(MAX_BLOB_BYTES, 1_048_576);
    assert_eq!(MAX_BLOB_TOTAL_BYTES, 4 * 1_048_576);
    assert_eq!(MAX_SYMBOLIC_TARGET_BYTES, 1024);
    assert_eq!(MODE_GITLINK, 0o160_000);
}

#[test]
fn a_reader_line_is_its_fixed_words_and_its_argument_and_it_never_writes() {
    for (reader, argument, expected) in [
        (
            Reader::R1,
            Some("HEAD"),
            vec!["rev-parse", "--verify", "--end-of-options", "HEAD^{commit}"],
        ),
        (
            Reader::R1,
            Some("refs/heads/main"),
            vec![
                "rev-parse",
                "--verify",
                "--end-of-options",
                "refs/heads/main^{commit}",
            ],
        ),
        (
            Reader::R1,
            Some("refs/tags/v1"),
            vec![
                "rev-parse",
                "--verify",
                "--end-of-options",
                "refs/tags/v1^{commit}",
            ],
        ),
        (
            Reader::R1,
            Some(OID),
            vec![
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{OID}^{{commit}}"),
            ],
        ),
        (
            Reader::R1,
            Some("refs/heads/a~2^"),
            vec![
                "rev-parse",
                "--verify",
                "--end-of-options",
                "refs/heads/a~2^^{commit}",
            ],
        ),
        (
            Reader::R2,
            Some("refs/heads/a/b"),
            vec!["symbolic-ref", "-q", "refs/heads/a/b"],
        ),
        (
            Reader::R3,
            Some(OID),
            vec!["ls-tree", "-r", "-z", "--full-tree", OID],
        ),
        (Reader::R4, None, vec!["ls-files", "-z", "--stage"]),
        (Reader::R5, None, vec!["cat-file", "--batch"]),
    ] {
        let line = reader_line(reader, argument)
            .unwrap_or_else(|r| panic!("{reader:?} {argument:?}: {r}"));
        assert_eq!(line.argv, strings(&expected), "{reader:?} {argument:?}");
        assert_eq!(line.writes, Writes::No);
        assert!(line.checks.is_empty());
    }
}

#[test]
fn a_reader_refuses_an_argument_outside_its_form() {
    let long = format!("refs/heads/{}", "n".repeat(MAX_REF_NAME_BYTES - 10));
    assert_eq!(long.len(), MAX_REF_NAME_BYTES + 1);
    let at = format!("refs/heads/{}", "n".repeat(MAX_REF_NAME_BYTES - 11));
    assert!(reader_line(Reader::R2, Some(&at)).is_ok());
    let cases: Vec<(Reader, Option<&str>)> = vec![
        (Reader::R1, None),
        (Reader::R1, Some("main")),
        (Reader::R1, Some("")),
        (Reader::R1, Some("-x")),
        (Reader::R1, Some("refs/remotes/o/a")),
        (Reader::R1, Some("refs/heads/")),
        (Reader::R1, Some("HEAD@{1}")),
        (Reader::R1, Some("HEAD^^^^^")),
        (Reader::R1, Some("refs/heads/a..b")),
        (Reader::R1, Some("0123456789ABCDEF0123456789abcdef01234567")),
        (Reader::R2, None),
        (Reader::R2, Some("a")),
        (Reader::R2, Some("HEAD")),
        (Reader::R2, Some("refs/tags/a")),
        (Reader::R2, Some("refs/heads/")),
        (Reader::R2, Some("refs/heads/a b")),
        (Reader::R2, Some(&long)),
        (Reader::R3, None),
        (Reader::R3, Some("HEAD")),
        (Reader::R3, Some(&OID[..39])),
        (Reader::R3, Some("0123456789ABCDEF0123456789abcdef01234567")),
        (Reader::R4, Some("HEAD")),
        (Reader::R4, Some("")),
        (Reader::R5, Some(OID)),
    ];
    for (reader, argument) in cases {
        let refusal = reader_line(reader, argument).expect_err(&format!("{reader:?} {argument:?}"));
        assert_eq!(
            refusal.rule, RULE_READER_ARGUMENT,
            "{reader:?} {argument:?}"
        );
        assert_eq!(refusal.kind, RefusedKind::Operation);
        assert!(
            refusal.detail().contains(form(reader).name),
            "{}",
            refusal.detail()
        );
    }
}

// R1

#[test]
fn r1_answers_one_identifier_and_a_line_feed() {
    let answer = format!("{OID}\n");
    assert_eq!(parse_r1(&out(0, answer.as_bytes()), "main").unwrap(), OID);
}

#[test]
fn r1_refuses_any_exit_code_but_zero_as_an_unresolved_revision_and_names_it() {
    for code in [1, 2, 128, 255, 3_221_225_781] {
        let refusal = parse_r1(
            &out(code, b"fatal: Needed a single revision\n"),
            "refs/heads/nope",
        )
        .unwrap_err();
        assert_eq!(refusal.rule, RULE_UNRESOLVED, "{code}");
        assert_eq!(refusal.kind, RefusedKind::Operation);
        assert_eq!(refusal.detail(), "unresolved refs/heads/nope");
    }
}

#[test]
fn r1_refuses_a_deadline_and_output_that_is_not_one_identifier() {
    assert_eq!(rule(parse_r1(&DEADLINE, "main")), RULE_READER_DEADLINE);
    let good = format!("{OID}\n");
    let cases: Vec<Vec<u8>> = vec![
        vec![],
        b"\n".to_vec(),
        OID.as_bytes().to_vec(),
        format!("{OID}\r\n").into_bytes(),
        format!("{OID}\n\n").into_bytes(),
        format!("{OID}\n{OID2}\n").into_bytes(),
        format!("{}\n", OID.to_uppercase().replace('0', "A")).into_bytes(),
        format!("{} \n", OID).into_bytes(),
        format!("{}\n", &OID[..39]).into_bytes(),
        format!("{OID}0\n").into_bytes(),
        format!(" {OID}\n").into_bytes(),
        b"main\n".to_vec(),
        [good.as_bytes(), b"\0"].concat(),
        vec![0xff; 41],
    ];
    for stdout in cases {
        assert_eq!(
            rule(parse_r1(&out(0, &stdout), "main")),
            RULE_READER_FRAMING,
            "{stdout:?}"
        );
    }
    // The refusal says which reader and never what it printed.
    let refusal = parse_r1(&out(0, b"SECRET\n"), "main").unwrap_err();
    assert!(refusal.detail().contains("R1"), "{}", refusal.detail());
    assert!(!refusal.detail().contains("SECRET"));
}

// R2

#[test]
fn r2_has_two_results_a_symbolic_reference_and_one_that_is_not() {
    assert_eq!(parse_r2(&out(1, b"")).unwrap(), Symbolic::No);
    assert_eq!(
        parse_r2(&out(0, b"refs/heads/main\n")).unwrap(),
        Symbolic::Yes
    );
    let longest = format!(
        "refs/heads/{}\n",
        "n".repeat(MAX_SYMBOLIC_TARGET_BYTES - 11)
    );
    assert_eq!(longest.len(), MAX_SYMBOLIC_TARGET_BYTES + 1);
    assert_eq!(
        parse_r2(&out(0, longest.as_bytes())).unwrap(),
        Symbolic::Yes
    );
}

#[test]
fn r2_refuses_what_is_not_one_of_its_two_results() {
    assert_eq!(rule(parse_r2(&DEADLINE)), RULE_READER_DEADLINE);
    for code in [2, 128, 255] {
        assert_eq!(rule(parse_r2(&out(code, b""))), RULE_READER_EXIT, "{code}");
        assert_eq!(
            rule(parse_r2(&out(code, b"refs/heads/a\n"))),
            RULE_READER_EXIT,
            "{code}"
        );
    }
    // A reference that is not symbolic prints nothing.
    assert_eq!(
        rule(parse_r2(&out(1, b"refs/heads/a\n"))),
        RULE_READER_FRAMING
    );
    assert_eq!(rule(parse_r2(&out(1, b"\n"))), RULE_READER_FRAMING);
    // A symbolic one prints the reference it names, as one line.
    for stdout in [
        &b""[..],
        b"\n",
        b"refs/heads/a",
        b"refs/heads/a\n\n",
        b"refs/heads/a\nrefs/heads/b\n",
        b"refs/heads/a\0\n",
        b"\n\n",
    ] {
        assert_eq!(
            rule(parse_r2(&out(0, stdout))),
            RULE_READER_FRAMING,
            "{stdout:?}"
        );
    }
    let over = format!(
        "refs/heads/{}\n",
        "n".repeat(MAX_SYMBOLIC_TARGET_BYTES - 10)
    );
    assert_eq!(over.len(), MAX_SYMBOLIC_TARGET_BYTES + 2);
    assert_eq!(
        rule(parse_r2(&out(0, over.as_bytes()))),
        RULE_READER_FRAMING
    );
}

// R3 and R4

fn r3_record(mode: &str, kind: &str, oid: &str, path: &str) -> Vec<u8> {
    format!("{mode} {kind} {oid}\t{path}\0").into_bytes()
}

fn r4_record(mode: &str, oid: &str, stage: &str, path: &str) -> Vec<u8> {
    format!("{mode} {oid} {stage}\t{path}\0").into_bytes()
}

fn entry(mode: u32, oid: &str, stage: u8, path: &[u8]) -> Entry {
    Entry {
        mode,
        oid: oid.to_owned(),
        stage,
        path: path.to_vec(),
    }
}

#[test]
fn r3_reads_every_record_of_a_listing_and_an_empty_listing_is_a_listing_of_none() {
    assert_eq!(parse_r3(&out(0, b"")).unwrap(), vec![]);
    let listing = [
        r3_record("100644", "blob", OID, "a.txt"),
        r3_record("100755", "blob", OID2, "dir/run.sh"),
        r3_record("120000", "blob", OID, "link"),
        r3_record("160000", "commit", OID2, "sub"),
        r3_record("100644", "blob", OID, "a b\tc\nd"),
        r3_record("100644", "blob", OID, ".gitattributes"),
    ]
    .concat();
    assert_eq!(
        parse_r3(&out(0, &listing)).unwrap(),
        vec![
            entry(0o100_644, OID, 0, b"a.txt"),
            entry(0o100_755, OID2, 0, b"dir/run.sh"),
            entry(0o120_000, OID, 0, b"link"),
            entry(0o160_000, OID2, 0, b"sub"),
            entry(0o100_644, OID, 0, b"a b\tc\nd"),
            entry(0o100_644, OID, 0, b".gitattributes"),
        ]
    );
    // A path may hold bytes that are not text.
    let mut raw = b"100644 blob ".to_vec();
    raw.extend(OID.as_bytes());
    raw.extend(b"\t\xff\xfe\0");
    assert_eq!(parse_r3(&out(0, &raw)).unwrap()[0].path, b"\xff\xfe");
}

#[test]
fn r3_refuses_a_deadline_an_exit_code_and_a_record_that_does_not_frame() {
    assert_eq!(rule(parse_r3(&DEADLINE)), RULE_READER_DEADLINE);
    for code in [1, 2, 128] {
        assert_eq!(rule(parse_r3(&out(code, b""))), RULE_READER_EXIT, "{code}");
    }
    let good = r3_record("100644", "blob", OID, "a");
    // A cut record: the last record does not end.
    let mut cut = good.clone();
    cut.pop();
    assert_eq!(rule(parse_r3(&out(0, &cut))), RULE_READER_FRAMING);
    assert_eq!(rule(parse_r3(&out(0, &good[..10]))), RULE_READER_FRAMING);
    let cases: Vec<Vec<u8>> = vec![
        b"\0".to_vec(),
        [good.clone(), b"\0".to_vec()].concat(),
        r3_record("100644", "blob", OID, ""),
        format!("100644 blob {OID} a\0").into_bytes(),
        format!("100644 blob {OID}\0").into_bytes(),
        format!("100644 {OID}\ta\0").into_bytes(),
        format!("100644 blob extra {OID}\ta\0").into_bytes(),
        format!("100644  blob {OID}\ta\0").into_bytes(),
        r3_record("100664", "blob", OID, "a"),
        r3_record("040000", "tree", OID, "a"),
        r3_record("100644", "tree", OID, "a"),
        r3_record("100644", "commit", OID, "a"),
        r3_record("160000", "blob", OID, "a"),
        r3_record("12", "blob", OID, "a"),
        r3_record("", "blob", OID, "a"),
        r3_record("100644", "", OID, "a"),
        r3_record("100644", "blob", &OID.to_uppercase().replace('0', "A"), "a"),
        r3_record("100644", "blob", &OID[..39], "a"),
        r3_record("100644", "blob", "", "a"),
        r3_record("1006440", "blob", OID, "a"),
        r3_record("+100644", "blob", OID, "a"),
        r3_record("100644", "BLOB", OID, "a"),
    ];
    for listing in cases {
        assert_eq!(
            rule(parse_r3(&out(0, &listing))),
            RULE_READER_FRAMING,
            "{:?}",
            String::from_utf8_lossy(&listing)
        );
    }
    // A refusal names the reader and never the path.
    let refusal = parse_r3(&out(
        0,
        &r3_record("100644", "blob", "SECRET", "SECRET-PATH"),
    ))
    .unwrap_err();
    assert!(refusal.detail().contains("R3"));
    assert!(!refusal.detail().contains("SECRET"));
}

/// A listing of exactly `size` bytes, made of valid records.
fn r3_listing_of(size: usize) -> Vec<u8> {
    let fixed = r3_record("100644", "blob", OID, "").len();
    let mut listing = Vec::new();
    let mut index = 0;
    while listing.len() < size {
        let room = size - listing.len();
        let path = format!("f{index}");
        let record = if room < fixed + 600 {
            r3_record("100644", "blob", OID, &"p".repeat(room - fixed))
        } else {
            r3_record("100644", "blob", OID, &path)
        };
        listing.extend(record);
        index += 1;
    }
    assert_eq!(listing.len(), size);
    listing
}

#[test]
fn a_listing_is_bounded_in_bytes_and_in_records() {
    let at = r3_listing_of(MAX_LISTING_BYTES);
    assert!(parse_r3(&out(0, &at)).unwrap().len() > 10_000);
    let mut over = at.clone();
    over.push(0);
    assert_eq!(rule(parse_r3(&out(0, &over))), RULE_READER_BOUNDS);
    // The bound is on the bytes, before any framing is read.
    assert_eq!(
        rule(parse_r3(&out(0, &vec![b'x'; MAX_LISTING_BYTES + 1]))),
        RULE_READER_BOUNDS
    );
    assert_eq!(
        rule(parse_r4(&out(0, &vec![b'x'; MAX_LISTING_BYTES + 1]))),
        RULE_READER_BOUNDS
    );
    assert_eq!(
        rule(parse_r3(&out(0, &vec![b'x'; MAX_LISTING_BYTES]))),
        RULE_READER_FRAMING
    );
    // The count is checked before any record is read: 100,000 empty records are records, the next
    // one is over the bound.
    let at_count = vec![0u8; MAX_LISTING_RECORDS];
    assert_eq!(rule(parse_r3(&out(0, &at_count))), RULE_READER_FRAMING);
    assert_eq!(rule(parse_r4(&out(0, &at_count))), RULE_READER_FRAMING);
    let over_count = vec![0u8; MAX_LISTING_RECORDS + 1];
    assert_eq!(rule(parse_r3(&out(0, &over_count))), RULE_READER_BOUNDS);
    assert_eq!(rule(parse_r4(&out(0, &over_count))), RULE_READER_BOUNDS);
}

#[test]
fn r4_reads_every_record_of_the_index_with_its_stage() {
    assert_eq!(parse_r4(&out(0, b"")).unwrap(), vec![]);
    let listing = [
        r4_record("100644", OID, "0", "a.txt"),
        r4_record("100755", OID2, "0", "run.sh"),
        r4_record("120000", OID, "0", "link"),
        r4_record("160000", OID2, "0", "sub"),
        r4_record("100644", OID, "1", "conflict"),
        r4_record("100644", OID, "2", "conflict"),
        r4_record("100644", OID, "3", "conflict"),
        r4_record("100644", OID, "0", "a b\tc"),
    ]
    .concat();
    assert_eq!(
        parse_r4(&out(0, &listing)).unwrap(),
        vec![
            entry(0o100_644, OID, 0, b"a.txt"),
            entry(0o100_755, OID2, 0, b"run.sh"),
            entry(0o120_000, OID, 0, b"link"),
            entry(0o160_000, OID2, 0, b"sub"),
            entry(0o100_644, OID, 1, b"conflict"),
            entry(0o100_644, OID, 2, b"conflict"),
            entry(0o100_644, OID, 3, b"conflict"),
            entry(0o100_644, OID, 0, b"a b\tc"),
        ]
    );
}

#[test]
fn r4_refuses_a_deadline_an_exit_code_and_a_record_that_does_not_frame() {
    assert_eq!(rule(parse_r4(&DEADLINE)), RULE_READER_DEADLINE);
    for code in [1, 2, 128] {
        assert_eq!(rule(parse_r4(&out(code, b""))), RULE_READER_EXIT, "{code}");
    }
    let good = r4_record("100644", OID, "0", "a");
    let mut cut = good.clone();
    cut.pop();
    assert_eq!(rule(parse_r4(&out(0, &cut))), RULE_READER_FRAMING);
    let cases: Vec<Vec<u8>> = vec![
        b"\0".to_vec(),
        r4_record("100644", OID, "0", ""),
        r4_record("100644", OID, "4", "a"),
        r4_record("100644", OID, "00", "a"),
        r4_record("100644", OID, "", "a"),
        r4_record("100644", OID, "x", "a"),
        r4_record("100644", OID, "-1", "a"),
        r4_record("100664", OID, "0", "a"),
        r4_record("040000", OID, "0", "a"),
        r4_record("100644", &OID[..39], "0", "a"),
        r4_record("100644", &OID.to_uppercase().replace('0', "A"), "0", "a"),
        format!("100644 {OID} 0 a\0").into_bytes(),
        format!("100644 {OID}\ta\0").into_bytes(),
        format!("100644 blob {OID} 0\ta\0").into_bytes(),
        format!("100644 {OID} 0 0\ta\0").into_bytes(),
    ];
    for listing in cases {
        assert_eq!(
            rule(parse_r4(&out(0, &listing))),
            RULE_READER_FRAMING,
            "{:?}",
            String::from_utf8_lossy(&listing)
        );
    }
}

#[test]
fn the_entries_named_gitattributes_are_picked_in_every_spelling_windows_reads() {
    let named = [
        ".gitattributes",
        "a/.gitattributes",
        "a/b/c/.gitattributes",
        ".GITATTRIBUTES",
        "x/.GitAttributes",
        ".gitattributes.",
        ".gitattributes ",
        ".gitattributes. . ",
        "GITATT~1",
        "gitatt~1",
        "d/gitatt~12",
    ];
    let other = [
        ".gitattributesx",
        "x.gitattributes",
        "gitattributes",
        ".gitattribute",
        "gitatt~",
        "gitatt~x",
        "gitatt~1x",
        ".gitattributes/y",
        ".gitattributes/.gitignore",
        "a",
        "",
        ".",
        "..",
        " .gitattributes",
        "gitatt1",
        ".gitattributes.x",
    ];
    let entries: Vec<Entry> = named
        .iter()
        .chain(&other)
        .map(|path| entry(0o100_644, OID, 0, path.as_bytes()))
        .collect();
    let picked: Vec<&[u8]> = attributes_entries(&entries)
        .into_iter()
        .map(|entry| entry.path.as_slice())
        .collect();
    let want: Vec<&[u8]> = named.iter().map(|path| path.as_bytes()).collect();
    assert_eq!(picked, want);
    // A symbolic link is read as a file; a gitlink is no file.
    let kinds = [
        entry(0o120_000, OID, 0, b".gitattributes"),
        entry(0o100_755, OID, 0, b"d/.gitattributes"),
        entry(MODE_GITLINK, OID, 0, b".gitattributes"),
        entry(0o100_644, OID, 2, b"c/.gitattributes"),
    ];
    let picked = attributes_entries(&kinds);
    assert_eq!(picked.len(), 3);
    assert!(picked.iter().all(|entry| entry.mode != MODE_GITLINK));
    assert!(attributes_entries(&[]).is_empty());
}

// R5

fn answer(oid: &str, content: &[u8]) -> Vec<u8> {
    let mut bytes = format!("{oid} blob {}\n", content.len()).into_bytes();
    bytes.extend(content);
    bytes.push(b'\n');
    bytes
}

#[test]
fn r5_is_asked_for_each_identifier_on_a_line() {
    assert_eq!(blob_request(&[]).unwrap(), b"");
    assert_eq!(
        blob_request(&strings(&[OID, OID2])).unwrap(),
        format!("{OID}\n{OID2}\n").into_bytes()
    );
    let many = vec![OID.to_owned(); MAX_BLOBS];
    assert_eq!(blob_request(&many).unwrap().len(), MAX_BLOBS * 41);
    let over = vec![OID.to_owned(); MAX_BLOBS + 1];
    assert_eq!(rule(blob_request(&over)), RULE_READER_BOUNDS);
    for bad in [
        "",
        "main",
        &OID[..39],
        "0123456789ABCDEF0123456789abcdef01234567",
        "x\n",
    ] {
        assert_eq!(
            rule(blob_request(&strings(&[OID, bad]))),
            RULE_READER_ARGUMENT,
            "{bad:?}"
        );
    }
}

#[test]
fn r5_answers_each_blob_in_order_with_its_bytes_whatever_they_are() {
    let requested = strings(&[OID, OID2, OID]);
    let blobs: [&[u8]; 3] = [b"* text=auto\n", b"", b"line\n\nwith \0 nul and blob 5\n"];
    let stdout: Vec<u8> = [
        answer(OID, blobs[0]),
        answer(OID2, blobs[1]),
        answer(OID, blobs[2]),
    ]
    .concat();
    assert_eq!(parse_r5(&requested, &out(0, &stdout)).unwrap(), blobs);
    assert_eq!(parse_r5(&[], &out(0, b"")).unwrap(), Vec::<&[u8]>::new());
}

#[test]
fn r5_refuses_a_deadline_an_exit_code_and_a_missing_object() {
    let requested = strings(&[OID]);
    let good = answer(OID, b"x");
    assert_eq!(
        rule(parse_r5(
            &requested,
            &Output {
                exit: None,
                stdout: &good
            }
        )),
        RULE_READER_DEADLINE
    );
    for code in [1, 128] {
        assert_eq!(
            rule(parse_r5(&requested, &out(code, &good))),
            RULE_READER_EXIT,
            "{code}"
        );
    }
    let missing = format!("{OID} missing\n");
    assert_eq!(
        rule(parse_r5(&requested, &out(0, missing.as_bytes()))),
        RULE_READER_MISSING
    );
    // A missing answer after good ones is as much a failure.
    let two = strings(&[OID, OID2]);
    let stdout = [answer(OID, b"x"), format!("{OID2} missing\n").into_bytes()].concat();
    assert_eq!(rule(parse_r5(&two, &out(0, &stdout))), RULE_READER_MISSING);
}

#[test]
fn r5_refuses_a_count_that_differs() {
    let two = strings(&[OID, OID2]);
    let one = answer(OID, b"x");
    assert_eq!(rule(parse_r5(&two, &out(0, &one))), RULE_READER_COUNT);
    assert_eq!(rule(parse_r5(&two, &out(0, b""))), RULE_READER_COUNT);
    let three = [answer(OID, b"x"), answer(OID2, b"y"), answer(OID, b"z")].concat();
    assert_eq!(rule(parse_r5(&two, &out(0, &three))), RULE_READER_COUNT);
    assert_eq!(rule(parse_r5(&[], &out(0, &one))), RULE_READER_COUNT);
    let trailing = [answer(OID, b"x"), b"\n".to_vec()].concat();
    assert_eq!(
        rule(parse_r5(&strings(&[OID]), &out(0, &trailing))),
        RULE_READER_COUNT
    );
}

#[test]
fn r5_refuses_bytes_that_do_not_frame_to_the_sizes() {
    let requested = strings(&[OID]);
    let header = |text: &str| format!("{OID} {text}\n").into_bytes();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("cut header", format!("{OID} blob 1").into_bytes()),
        ("only the oid", format!("{OID}\n").into_bytes()),
        ("no size", header("blob")),
        ("empty size", header("blob ")),
        ("signed size", [header("blob +1"), b"x\n".to_vec()].concat()),
        (
            "negative size",
            [header("blob -1"), b"x\n".to_vec()].concat(),
        ),
        (
            "size with text",
            [header("blob 1x"), b"x\n".to_vec()].concat(),
        ),
        (
            "extra word",
            [header("blob 1 extra"), b"x\n".to_vec()].concat(),
        ),
        ("tree", [header("tree 1"), b"x\n".to_vec()].concat()),
        ("commit", [header("commit 1"), b"x\n".to_vec()].concat()),
        (
            "another oid",
            [format!("{OID2} blob 1\n").into_bytes(), b"x\n".to_vec()].concat(),
        ),
        (
            "short content",
            [header("blob 5"), b"xx\n".to_vec()].concat(),
        ),
        (
            "long content",
            [header("blob 1"), b"xxx\n".to_vec()].concat(),
        ),
        (
            "no final line feed",
            [header("blob 1"), b"x".to_vec()].concat(),
        ),
        (
            "wrong final byte",
            [header("blob 1"), b"xy".to_vec()].concat(),
        ),
        (
            "content cut at the size",
            [header("blob 3"), b"abc".to_vec()].concat(),
        ),
        ("ambiguous", header("ambiguous")),
        (
            "a header with a carriage return",
            [format!("{OID} blob 1\r\n").into_bytes(), b"x\n".to_vec()].concat(),
        ),
    ];
    for (name, stdout) in cases {
        assert_eq!(
            rule(parse_r5(&requested, &out(0, &stdout))),
            RULE_READER_FRAMING,
            "{name}"
        );
    }
    // Answers out of order are not matched to the wrong request.
    let two = strings(&[OID, OID2]);
    let swapped = [answer(OID2, b"y"), answer(OID, b"x")].concat();
    assert_eq!(rule(parse_r5(&two, &out(0, &swapped))), RULE_READER_FRAMING);
    // A refusal names the reader and never the bytes.
    let refusal = parse_r5(&requested, &out(0, b"SECRET")).unwrap_err();
    assert!(refusal.detail().contains("R5"));
    assert!(!refusal.detail().contains("SECRET"));
}

#[test]
fn r5_bounds_one_blob_and_all_of_them() {
    let requested = strings(&[OID]);
    let at = vec![b'a'; MAX_BLOB_BYTES];
    assert_eq!(
        parse_r5(&requested, &out(0, &answer(OID, &at))).unwrap()[0].len(),
        MAX_BLOB_BYTES
    );
    // The size in the header is judged before the content is looked for.
    let header = format!("{OID} blob {}\n", MAX_BLOB_BYTES + 1);
    assert_eq!(
        rule(parse_r5(&requested, &out(0, header.as_bytes()))),
        RULE_READER_BOUNDS
    );
    let over = answer(OID, &vec![b'a'; MAX_BLOB_BYTES + 1]);
    assert_eq!(
        rule(parse_r5(&requested, &out(0, &over))),
        RULE_READER_BOUNDS
    );
    let huge = format!("{OID} blob 99999999999999999999999\n");
    assert_eq!(
        rule(parse_r5(&requested, &out(0, huge.as_bytes()))),
        RULE_READER_BOUNDS
    );

    // Four blobs of the limit are the total's limit; one byte more is over it.
    let four = vec![OID.to_owned(); 4];
    let stdout: Vec<u8> = (0..4).flat_map(|_| answer(OID, &at)).collect();
    assert_eq!(parse_r5(&four, &out(0, &stdout)).unwrap().len(), 4);
    assert_eq!(MAX_BLOB_TOTAL_BYTES, 4 * MAX_BLOB_BYTES);
    let five = vec![OID.to_owned(); 5];
    let stdout: Vec<u8> = (0..4)
        .flat_map(|_| answer(OID, &at))
        .chain(answer(OID, b"x"))
        .collect();
    assert_eq!(rule(parse_r5(&five, &out(0, &stdout))), RULE_READER_BOUNDS);
    // The total is judged on sizes, so a header alone can exceed it.
    let stdout: Vec<u8> = (0..4)
        .flat_map(|_| answer(OID, &at))
        .chain(format!("{OID} blob 1\n").into_bytes())
        .collect();
    assert_eq!(rule(parse_r5(&five, &out(0, &stdout))), RULE_READER_BOUNDS);
    // More blobs requested than the bound allows.
    let many = vec![OID.to_owned(); MAX_BLOBS + 1];
    assert_eq!(rule(parse_r5(&many, &out(0, b""))), RULE_READER_BOUNDS);
    let at_count = vec![OID.to_owned(); MAX_BLOBS];
    let stdout: Vec<u8> = (0..MAX_BLOBS).flat_map(|_| answer(OID, b"")).collect();
    assert_eq!(
        parse_r5(&at_count, &out(0, &stdout)).unwrap().len(),
        MAX_BLOBS
    );
}
