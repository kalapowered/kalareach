//! The attribute scan against attributes files as repositories write them and as a hostile one
//! could.

use kr_boundary_windows::frame::invocation::RefusedKind;
use kr_boundary_windows::repository::attributes::{
    BUILT_IN_DIFF_DRIVERS, BUILT_IN_MERGE_VALUES, MAX_ATTRIBUTES_BYTES, RULE_DIFF, RULE_FILTER,
    RULE_MACRO, RULE_MERGE, RULE_SIZE, scan_attributes,
};

fn rule(text: &str) -> &'static str {
    let refusal = scan_attributes(text.as_bytes()).expect_err(text);
    assert_eq!(refusal.kind, RefusedKind::Repository, "{text:?}");
    refusal.rule
}

fn allowed(text: &str) {
    if let Err(refusal) = scan_attributes(text.as_bytes()) {
        panic!("{text:?} was refused: {refusal}");
    }
}

#[test]
fn files_that_select_no_driver_are_allowed() {
    allowed("");
    allowed("\n\n  \n\t\n");
    allowed("# a comment\n");
    allowed("# filter=lfs is only a comment\n   # diff=foo\n");
    allowed("* text=auto\n");
    allowed("*.png binary\n*.txt eol=lf\n*.sh text eol=lf");
    allowed("*.md working-tree-encoding=UTF-16 ident export-subst -text\n");
    allowed("*.rs diff=rust merge=union\n");
    allowed("*.dat -diff -merge -filter\n");
    allowed("*.dat !diff !merge !filter\n");
    allowed("*.dat diff merge\n");
    allowed("*.dat merge=text\n*.bin merge=binary\n");
    allowed("*.c diff=cpp\r\n*.h diff=cpp\r\n");
    allowed("  \t*.c \t diff=cpp   text\t\n");
    allowed("\"a file name.txt\" text\n");
    allowed("src/**/*.rs linguist-language=Rust\n");
    // Attribute names are case-sensitive, so these are not the three.
    allowed("*.x Filter=lfs FILTER=lfs Diff=x DIFF=x Merge=x MERGE=x\n");
    allowed("*.x filters=lfs differ=x merged=x my-filter=lfs diff-x=y\n");
    // A macro name is not a macro definition when it is not first on its line.
    allowed("*.x [attr]y\n");
}

#[test]
fn a_pattern_is_not_an_attribute() {
    // These patterns are spelled like attributes and select nothing.
    allowed("filter text\n");
    allowed("diff=x text\n");
    allowed("merge=x text\n");
    allowed("filter=lfs\n");
}

#[test]
fn every_built_in_diff_driver_is_allowed_and_no_other_name_is() {
    // The built-in hunk-header patterns the attribute manual of Git for Windows 2.55.0.windows.5
    // lists, in its order.
    let expected = [
        "ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain",
        "golang", "html", "java", "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php",
        "python", "ruby", "rust", "scheme", "tex",
    ];
    assert_eq!(BUILT_IN_DIFF_DRIVERS, expected);
    for name in expected {
        allowed(&format!("*.x diff={name}\n"));
    }
    for name in [
        "", "lfs", "foo", "CPP", "Cpp", "cpp2", "c", "default", "word", "textconv", "ada2", "xml",
    ] {
        assert_eq!(rule(&format!("*.x diff={name}\n")), RULE_DIFF, "{name:?}");
    }
    assert_eq!(BUILT_IN_MERGE_VALUES, ["text", "binary", "union"]);
    for name in BUILT_IN_MERGE_VALUES {
        allowed(&format!("*.x merge={name}\n"));
    }
    for name in [
        "", "lfs", "ours", "theirs", "Text", "BINARY", "union2", "driver", "custom",
    ] {
        assert_eq!(rule(&format!("*.x merge={name}\n")), RULE_MERGE, "{name:?}");
    }
}

#[test]
fn a_filter_is_refused_with_any_value_and_when_set() {
    for attribute in [
        "filter=lfs",
        "filter=x",
        "filter=",
        "filter=lfs=more",
        "filter",
        "-filter=lfs",
        "!filter=lfs",
    ] {
        assert_eq!(
            rule(&format!("*.bin {attribute}\n")),
            RULE_FILTER,
            "{attribute:?}"
        );
    }
}

#[test]
fn a_driver_is_not_selected_by_a_negated_attribute_that_carries_a_value() {
    assert_eq!(rule("*.x -diff=cpp\n"), RULE_DIFF);
    assert_eq!(rule("*.x !diff=cpp\n"), RULE_DIFF);
    assert_eq!(rule("*.x -merge=text\n"), RULE_MERGE);
    assert_eq!(rule("*.x !merge=union\n"), RULE_MERGE);
}

#[test]
fn a_macro_definition_is_refused_wherever_it_starts_a_line() {
    assert_eq!(rule("[attr]mine diff=cpp\n"), RULE_MACRO);
    assert_eq!(rule("[attr]binary -diff -merge -text\n"), RULE_MACRO);
    assert_eq!(rule("[attr]x\n"), RULE_MACRO);
    assert_eq!(rule("  \t[attr]mine text\n"), RULE_MACRO);
    assert_eq!(rule("*.x text\n[attr]mine text\n"), RULE_MACRO);
    assert_eq!(rule("\r[attr]mine text"), RULE_MACRO);
    // The first of two refusing things on a line is the one named.
    assert_eq!(rule("[attr]mine filter=lfs"), RULE_MACRO);
}

#[test]
fn the_scan_reads_a_line_as_git_could_and_more() {
    // Any byte up to the space can end a piece, so none of these hides an attribute.
    for separator in [
        "\t", "\r", "\x0b", "\x0c", "\0", "\x01", "\x1f", "\x7f", "  ",
    ] {
        let line = format!("*.x{separator}filter=lfs\n");
        assert_eq!(rule(&line), RULE_FILTER, "{separator:?}");
        let line = format!("*.x text{separator}diff=foo\n");
        assert_eq!(rule(&line), RULE_DIFF, "{separator:?}");
    }
    // A quoted pattern is scanned as well, so a quote that Git would not close hides nothing.
    assert_eq!(rule("\"a\\q filter=lfs\"\n"), RULE_FILTER);
    assert_eq!(rule("\"a b\" filter=lfs\n"), RULE_FILTER);
    // An attribute may follow the closing quotation mark with no space, and a quoted pattern that
    // is spelled like an attribute is read as one: the scan refuses both.
    assert_eq!(rule("\"x\"filter=lfs\n"), RULE_FILTER);
    assert_eq!(rule("\"a b\"diff=foo\n"), RULE_DIFF);
    assert_eq!(rule("\"filter=lfs\" text\n"), RULE_FILTER);
    assert_eq!(rule("a\"filter=lfs\n"), RULE_FILTER);
    assert_eq!(rule("\"a\" \"b\" diff=foo\n"), RULE_DIFF);
    // Only a line feed ends a line, so a carriage return does not hide the next line's driver.
    assert_eq!(rule("*.x text\rfilter=lfs\n"), RULE_FILTER);
    // Bytes that are not text do not stop the scan.
    let bytes = b"*.x \xff\xfe text\n*.y filter=lfs\n";
    assert_eq!(scan_attributes(bytes).unwrap_err().rule, RULE_FILTER);
}

#[test]
fn a_refusal_names_the_rule_and_the_line_and_never_what_the_file_held() {
    let text = "# first\n* text=auto\nsecret/path/name.dat -text filter=secretdriver\nlater\n";
    let refusal = scan_attributes(text.as_bytes()).unwrap_err();
    assert_eq!(refusal.rule, RULE_FILTER);
    assert!(refusal.detail().contains("line 3"), "{refusal}");
    assert!(!refusal.detail().contains("secret"), "{refusal}");
    let refusal = scan_attributes(b"secret/path *.dat diff=secretdriver\n").unwrap_err();
    assert!(!refusal.detail().contains("secret"), "{refusal}");
    let refusal = scan_attributes(b"[attr]secretmacro diff=cpp\n").unwrap_err();
    assert!(!refusal.detail().contains("secret"), "{refusal}");
    // The text says what the person loses and never tells them to remove a key.
    let refusal = scan_attributes(b"*.bin filter=lfs\n").unwrap_err();
    assert!(refusal.detail().contains("not support"), "{refusal}");
    assert!(
        !refusal.detail().to_lowercase().contains("remove"),
        "{refusal}"
    );
}

#[test]
fn the_first_refusing_line_is_the_one_named() {
    let refusal = scan_attributes(b"*.a diff=nope\n*.b filter=lfs\n").unwrap_err();
    assert_eq!(refusal.rule, RULE_DIFF);
    assert!(refusal.detail().contains("line 1"));
    let refusal = scan_attributes(b"*.a text\n\n*.b merge=ours filter=lfs\n").unwrap_err();
    assert_eq!(refusal.rule, RULE_MERGE);
    assert!(refusal.detail().contains("line 3"));
}

#[test]
fn a_file_may_be_a_megabyte_and_no_more() {
    let mut at = b"* text=auto\n".to_vec();
    at.resize(MAX_ATTRIBUTES_BYTES, b'#');
    assert!(scan_attributes(&at).is_ok());
    // A driver at the very end of a file of the limit's size is still seen.
    let line = b"\n*.x filter=lfs";
    let mut last = vec![b'#'; MAX_ATTRIBUTES_BYTES - line.len()];
    last.extend_from_slice(line);
    assert_eq!(last.len(), MAX_ATTRIBUTES_BYTES);
    assert_eq!(scan_attributes(&last).unwrap_err().rule, RULE_FILTER);
    at.push(b'#');
    assert_eq!(scan_attributes(&at).unwrap_err().rule, RULE_SIZE);
}
