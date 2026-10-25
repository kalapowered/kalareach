//! A Windows release's `.zip` archive, read before any signature is checked.
//!
//! The archive is hostile until its manifest has been verified, and the manifest is inside it. Each
//! case here builds an archive with one fault a host must not follow, writes it byte by byte so that
//! nothing the zip library would refuse to write stands in the way, and holds the reading to refusing
//! it before it writes anything (or, for an entry whose size is a lie, to writing no more than the
//! entry says). The control is an archive of the same shape without the fault, which is read whole
//! and every file of it is as it was packed.

#![cfg(windows)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

use kr_cli::update::archive::{Limits, unpack};

/// The top directory every archive here is under.
const TOP: &str = "kalareach-x86_64-pc-windows-msvc-0.1.0+aaaaaaaaaaaa";

/// One entry of an archive as it is written, nothing about it checked.
struct Member {
    name: String,
    /// The bytes as stored in the archive: the file itself, or its deflated form.
    stored: Vec<u8>,
    /// What the entry says the file holds, and the checksum it says the file has.
    declared_size: u32,
    crc: u32,
    method: u16,
    flags: u16,
    /// The file's mode in the high half, as an archive made on Unix writes it.
    external: u32,
}

impl Member {
    fn stored(name: impl Into<String>, data: &[u8]) -> Self {
        Self {
            name: name.into(),
            stored: data.to_vec(),
            declared_size: u32::try_from(data.len()).expect("small"),
            crc: crc32(data),
            method: 0,
            flags: 0,
            external: 0o100_644 << 16,
        }
    }

    fn deflated(name: impl Into<String>, data: &[u8]) -> Self {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).expect("compresses");
        Self {
            method: 8,
            stored: encoder.finish().expect("compressed"),
            ..Self::stored(name, data)
        }
    }

    fn directory(name: impl Into<String>) -> Self {
        Self {
            external: 0o040_755 << 16,
            ..Self::stored(name, b"")
        }
    }

    /// An entry whose mode says it is a symbolic link.
    fn link(name: impl Into<String>, target: &str) -> Self {
        Self {
            external: 0o120_777 << 16,
            ..Self::stored(name, target.as_bytes())
        }
    }
}

/// The checksum a zip entry carries.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// An archive of `members`, in the order given, written as a zip is: a local header and the data of
/// each, then the central directory, then its end.
fn archive_of(members: &[Member]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut offsets = Vec::new();
    for member in members {
        offsets.push(u32::try_from(bytes.len()).expect("small"));
        bytes.extend_from_slice(&0x0403_4b50_u32.to_le_bytes());
        bytes.extend_from_slice(&20_u16.to_le_bytes());
        bytes.extend_from_slice(&member.flags.to_le_bytes());
        bytes.extend_from_slice(&member.method.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0x21, 0]);
        bytes.extend_from_slice(&member.crc.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(member.stored.len())
                .expect("small")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&member.declared_size.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(member.name.len())
                .expect("short")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&0_u16.to_le_bytes());
        bytes.extend_from_slice(member.name.as_bytes());
        bytes.extend_from_slice(&member.stored);
    }
    let directory_at = u32::try_from(bytes.len()).expect("small");
    for (member, offset) in members.iter().zip(&offsets) {
        bytes.extend_from_slice(&0x0201_4b50_u32.to_le_bytes());
        // Made on Unix, so the high half of the external attributes is a mode.
        bytes.extend_from_slice(&((3_u16 << 8) | 20).to_le_bytes());
        bytes.extend_from_slice(&20_u16.to_le_bytes());
        bytes.extend_from_slice(&member.flags.to_le_bytes());
        bytes.extend_from_slice(&member.method.to_le_bytes());
        bytes.extend_from_slice(&[0, 0, 0x21, 0]);
        bytes.extend_from_slice(&member.crc.to_le_bytes());
        bytes.extend_from_slice(
            &u32::try_from(member.stored.len())
                .expect("small")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&member.declared_size.to_le_bytes());
        bytes.extend_from_slice(
            &u16::try_from(member.name.len())
                .expect("short")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&[0; 2 + 2 + 2 + 2]);
        bytes.extend_from_slice(&member.external.to_le_bytes());
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(member.name.as_bytes());
    }
    let directory_len = u32::try_from(bytes.len()).expect("small") - directory_at;
    bytes.extend_from_slice(&0x0605_4b50_u32.to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    let count = u16::try_from(members.len()).expect("few");
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&count.to_le_bytes());
    bytes.extend_from_slice(&directory_len.to_le_bytes());
    bytes.extend_from_slice(&directory_at.to_le_bytes());
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes
}

/// A directory of this case's own, with a staging directory in it, and the archive written beside.
struct Case {
    root: tempfile::TempDir,
}

impl Case {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("a directory"),
        }
    }

    fn staging(&self) -> PathBuf {
        let staging = self.root.path().join("staging");
        std::fs::create_dir_all(&staging).expect("a staging directory");
        staging
    }

    /// Reads `bytes` as a release archive within `limits`.
    fn read(
        &self,
        bytes: &[u8],
        limits: &Limits,
    ) -> Result<(PathBuf, kr_cli::update::release::Written), String> {
        let archive = self.root.path().join("release.zip");
        std::fs::write(&archive, bytes).expect("the archive is written");
        let file = std::fs::File::open(&archive).expect("opens");
        unpack(file, &archive, &self.staging(), limits).map_err(|error| error.to_string())
    }

    /// Every file and directory under the staging directory.
    fn staged(&self) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let mut pending = vec![self.staging()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory)
                .expect("a directory")
                .flatten()
            {
                found.push(entry.path());
                if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    pending.push(entry.path());
                }
            }
        }
        found
    }
}

/// A release's files, as the packer writes them: one entry for each, under the top directory.
fn release() -> Vec<Member> {
    vec![
        Member::deflated(format!("{TOP}/bin/kr.exe"), &b"MZ a program".repeat(40)),
        Member::stored(format!("{TOP}/release.json"), b"{\"signed\":{}}"),
        Member::deflated(format!("{TOP}/share/update-root.json"), b"{}"),
    ]
}

/// KR-REQ-26.06: the control. An archive of a release's shape, stored and deflated entries both, is
/// read whole: every file is as it was packed, and what was written is what the reading reports.
#[test]
fn an_archive_of_a_releases_shape_is_read_whole() {
    let case = Case::new();
    let (directory, written) = case
        .read(&archive_of(&release()), &Limits::DEFAULT)
        .expect("a release is read");
    assert_eq!(directory, case.staging().join(TOP));
    assert_eq!(
        std::fs::read(directory.join("bin/kr.exe")).expect("a program"),
        b"MZ a program".repeat(40)
    );
    assert_eq!(
        std::fs::read(directory.join("share/update-root.json")).expect("a file"),
        b"{}"
    );
    let mut names: Vec<_> = written.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["bin/kr.exe", "release.json", "share/update-root.json"]
    );
    assert_eq!(written["release.json"].0, 13);
}

/// KR-REQ-26.06: an archive that is more than a release is, or that no zip reader would take, is
/// refused before a byte is written: too many entries, too many bytes in all, a file larger than any
/// a release holds, a file that is not a zip, nothing at all.
#[test]
fn an_archive_beyond_the_bounds_of_a_release_is_refused_before_anything_is_written() {
    let many: Vec<Member> = (0..6)
        .map(|index| Member::stored(format!("{TOP}/bin/f{index}.exe"), b"x"))
        .collect();
    let eight = vec![
        Member::stored(format!("{TOP}/a.bin"), &[1; 8]),
        Member::stored(format!("{TOP}/b.bin"), &[2; 8]),
    ];
    let big = vec![Member::stored(format!("{TOP}/big.bin"), &[3; 8])];
    for (name, bytes, limits) in [
        (
            "entries",
            archive_of(&many),
            Limits {
                entries: 5,
                ..Limits::DEFAULT
            },
        ),
        (
            "total",
            archive_of(&eight),
            Limits {
                total_bytes: 12,
                ..Limits::DEFAULT
            },
        ),
        (
            "one file",
            archive_of(&big),
            Limits {
                entry_bytes: 4,
                ..Limits::DEFAULT
            },
        ),
        (
            "not a zip",
            b"this is not an archive at all".to_vec(),
            Limits::DEFAULT,
        ),
        ("empty", archive_of(&[]), Limits::DEFAULT),
    ] {
        let case = Case::new();
        assert!(case.read(&bytes, &limits).is_err(), "{name} is refused");
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
    // The controls: the same archives within the limits are read.
    for (name, bytes) in [
        ("entries", archive_of(&many)),
        ("total", archive_of(&eight)),
    ] {
        let case = Case::new();
        assert!(
            case.read(&bytes, &Limits::DEFAULT).is_ok(),
            "{name} is read within the bounds"
        );
    }
}

/// KR-REQ-26.06: an entry that is not a file or a directory, or that a release does not use, is
/// refused before a byte is written: a symbolic link, a name written twice, an encrypted entry, one
/// compressed in a way a release is not.
#[test]
fn an_entry_that_is_a_link_a_duplicate_or_unreadable_is_refused_before_anything_is_written() {
    let mut encrypted = Member::stored(format!("{TOP}/bin/kr.exe"), b"x");
    encrypted.flags = 1;
    let mut bzip = Member::stored(format!("{TOP}/bin/kr.exe"), b"x");
    bzip.method = 12;
    let mut unknown = Member::stored(format!("{TOP}/bin/kr.exe"), b"x");
    unknown.method = 99;
    for (name, members) in [
        (
            "a link",
            vec![
                Member::stored(format!("{TOP}/release.json"), b"{}"),
                Member::link(format!("{TOP}/bin/kr.exe"), "C:/Windows/System32/cmd.exe"),
            ],
        ),
        (
            "the same name twice",
            vec![
                Member::stored(format!("{TOP}/release.json"), b"{}"),
                Member::stored(format!("{TOP}/release.json"), b"{\"other\":1}"),
            ],
        ),
        ("an encrypted entry", vec![encrypted]),
        ("bzip2", vec![bzip]),
        ("an unknown method", vec![unknown]),
    ] {
        let case = Case::new();
        assert!(
            case.read(&archive_of(&members), &Limits::DEFAULT).is_err(),
            "{name} is refused"
        );
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
}

/// KR-REQ-26.06: a name that leaves the release, or that Windows would read as another, is refused
/// before a byte is written: an absolute path, a drive, a share, a separator that is not the
/// archive's, a parent, a device, a data stream, a name that ends in a dot, two names that are one
/// where case does not matter, a name that is a file and a directory, a second top directory, a file
/// where the top directory goes.
#[test]
fn a_name_that_leaves_the_release_or_that_windows_reads_as_another_is_refused() {
    let file = |name: &str| Member::stored(name, b"x");
    for (name, members) in [
        ("absolute", vec![file(&format!("/{TOP}/bin/kr.exe"))]),
        ("a drive", vec![file("C:/Windows/System32/kr.exe")]),
        (
            "a share",
            vec![file(&format!("//server/share/{TOP}/kr.exe"))],
        ),
        ("a backslash", vec![file(&format!("{TOP}\\bin\\kr.exe"))]),
        ("a parent", vec![file(&format!("{TOP}/../escape.exe"))]),
        (
            "a parent inside",
            vec![file(&format!("{TOP}/bin/../../escape.exe"))],
        ),
        ("a device", vec![file(&format!("{TOP}/bin/nul.exe"))]),
        (
            "a device in a directory",
            vec![file(&format!("{TOP}/AUX/kr.exe"))],
        ),
        (
            "a data stream",
            vec![file(&format!("{TOP}/bin/kr.exe:evil"))],
        ),
        ("a trailing dot", vec![file(&format!("{TOP}/bin/kr.exe."))]),
        (
            "a trailing space",
            vec![file(&format!("{TOP}/bin/kr.exe "))],
        ),
        (
            "one name in two cases",
            vec![
                file(&format!("{TOP}/bin/kr.exe")),
                file(&format!("{TOP}/BIN/KR.EXE")),
            ],
        ),
        (
            "a file and a directory",
            vec![
                file(&format!("{TOP}/bin")),
                file(&format!("{TOP}/bin/kr.exe")),
            ],
        ),
        (
            "a directory and a file",
            vec![
                Member::directory(format!("{TOP}/bin/")),
                file(&format!("{TOP}/bin")),
            ],
        ),
        (
            "two top directories",
            vec![file(&format!("{TOP}/bin/kr.exe")), file("other/bin/kr.exe")],
        ),
        ("a file for the top directory", vec![file(TOP)]),
        ("an empty part", vec![file(&format!("{TOP}//kr.exe"))]),
    ] {
        let case = Case::new();
        assert!(
            case.read(&archive_of(&members), &Limits::DEFAULT).is_err(),
            "{name} is refused"
        );
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
}

/// KR-REQ-26.06: an entry that says it holds fewer bytes than its data inflates to writes no more
/// than it says, whatever the reading then makes of it: the file a release is later held to is the
/// one the entry described, and the data past that is never written.
#[test]
fn an_entry_that_inflates_beyond_what_it_says_writes_no_more_than_it_says() {
    let honest = b"A".repeat(1024);
    let mut lying = Member::deflated(format!("{TOP}/bin/kr.exe"), &honest);
    lying.declared_size = 4;
    let case = Case::new();
    let outcome = case.read(
        &archive_of(&[lying, Member::stored(format!("{TOP}/release.json"), b"{}")]),
        &Limits::DEFAULT,
    );
    let largest = case
        .staged()
        .iter()
        .filter_map(|path| std::fs::metadata(path).ok())
        .filter(std::fs::Metadata::is_file)
        .map(|about| about.len())
        .max()
        .unwrap_or(0);
    assert!(
        largest <= 4,
        "no file is larger than its entry says: {largest} bytes, and the reading said {outcome:?}"
    );
}

/// Nothing is written outside the staging directory by an archive that names a place beyond it.
#[test]
fn nothing_is_written_beside_the_staging_directory() {
    let case = Case::new();
    let escape = case.root.path().join("escape.exe");
    for name in [
        format!("{TOP}/../../escape.exe"),
        format!("../escape.exe"),
        format!("{TOP}/..\\..\\escape.exe"),
    ] {
        let _ = case.read(
            &archive_of(&[Member::stored(name, b"escaped")]),
            &Limits::DEFAULT,
        );
        assert!(
            !Path::new(&escape).exists(),
            "nothing escaped the staging directory"
        );
    }
}
