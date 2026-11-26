//! `local_path`: the form of the text that names a project folder is checked before anything is
//! opened. Every form but a path on a local drive is refused, and the names of an accepted path are
//! single names.

use kr_boundary_windows::local_path::{MAX_NAME_UNITS, parse};

fn names(text: &str) -> Vec<String> {
    parse(text)
        .unwrap_or_else(|| panic!("{text:?} is a path on a local drive"))
        .names
        .iter()
        .map(|name| String::from_utf16(name).unwrap())
        .collect()
}

#[test]
fn a_path_on_a_local_drive_is_taken_apart_into_its_names() {
    let path = parse(r"c:\work\Some One\project").expect("a drive path");
    assert_eq!(path.drive, 'C', "the drive's letter is in capitals");
    assert_eq!(
        names(r"C:\work\Some One\project"),
        ["work", "Some One", "project"]
    );
    assert!(
        parse(r"C:\").unwrap().names.is_empty(),
        "the root has no name"
    );
    assert_eq!(names(r"C:\a\b\"), ["a", "b"], "one trailing backslash");
    assert_eq!(
        names(r"\\?\C:\a\b"),
        ["a", "b"],
        "the verbatim spelling of the same path"
    );
    assert_eq!(names(r"C:\PROGRA~1\x"), ["PROGRA~1", "x"], "a short name");
    assert_eq!(names("C:\\a\u{1F600}"), ["a\u{1F600}"]);
    assert_eq!(
        names(&format!(r"C:\{}", "n".repeat(MAX_NAME_UNITS))).len(),
        1
    );
}

#[test]
fn every_form_but_a_path_on_a_local_drive_is_refused() {
    let refused = [
        // A share, a host with a port, and the verbatim forms of both.
        r"\\host\share\x",
        r"\\localhost\C$\x",
        r"\\host@8080\share\x",
        r"\\host@SSL@443\DavWWWRoot\x",
        r"\\?\UNC\host\share\x",
        // A pipe, a device and a name in the object namespace.
        r"\\.\pipe\x",
        r"\\.\C:\x",
        r"\\.\GLOBALROOT\Device\HarddiskVolume3\x",
        r"\\?\GLOBALROOT\Device\HarddiskVolume3\x",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\x",
        r"\Device\HarddiskVolume3\x",
        r"\??\C:\x",
        // A text that is relative to something.
        r"\x",
        r"x",
        r"x\y",
        r".\x",
        r"..\x",
        r"C:",
        r"C:x",
        r"C:x\y",
        r"\\?\C:",
        r"\\?\C:x",
        // The verbatim spelling gets the same checks of its names: the system does no clean-up of a
        // verbatim path, so a dot name, an empty name and a name that ends in a dot or a space are
        // refused there too.
        r"\\?\C:\a\.\b",
        r"\\?\C:\a\..\b",
        r"\\?\C:\a\..",
        r"\\?\C:\\x",
        r"\\?\C:\a\\b",
        r"\\?\C:\a.",
        r"\\?\C:\a\b ",
        r"\\?\C:\a\b:stream",
        r"\\?\C:/a",
        r"\\?\c:",
        r"1:\x",
        r"CC:\x",
        r"C::\x",
        // A name that is not one name.
        r"C:\\x",
        r"C:\\",
        "C:/x",
        r"C:\a/b",
        r"C:\a\.\b",
        r"C:\a\..\b",
        r"C:\a\.",
        r"C:\a\..",
        r"C:\a:stream",
        r"C:\a\b:$DATA",
        r"C:\a\*",
        r"C:\a\b?",
        "C:\\a\\\"b\"",
        r"C:\a\<b>",
        r"C:\a\b|c",
        "C:\\a\\b\tc",
        "C:\\a\\b\u{1}",
        r"C:\a\b.",
        r"C:\a\b ",
        r"C:\a\b...",
        // A name over the bound.
        &format!(r"C:\{}", "n".repeat(MAX_NAME_UNITS + 1)),
        &format!("C:\\{}", "\u{1F600}".repeat(MAX_NAME_UNITS / 2 + 1)),
        // Nothing at all.
        "",
        r"\\",
        r"\\?\",
    ];
    for text in refused {
        assert_eq!(parse(text), None, "{text:?} is refused");
    }
}
