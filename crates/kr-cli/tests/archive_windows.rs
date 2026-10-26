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
    /// Extra data the entry carries in the archive's directory.
    extra: Vec<u8>,
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
            extra: Vec::new(),
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

/// Four bytes whose checksum is `target`. The checksum of a four-byte message takes every value
/// exactly once, and the message is found by undoing the four steps of the checksum from its end,
/// each step's table index being known by the top byte of the state it leaves.
fn four_bytes_with_checksum(target: u32) -> [u8; 4] {
    let table: Vec<u32> = (0..256_u32)
        .map(|index| {
            (0..8).fold(index, |crc, _| {
                if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                }
            })
        })
        .collect();
    let mut state = !target;
    let mut indexes = [0_usize; 4];
    for step in (0..4).rev() {
        let index = table
            .iter()
            .position(|entry| entry >> 24 == state >> 24)
            .expect("every top byte is in the table");
        indexes[step] = index;
        state = (state ^ table[index]) << 8;
    }
    let mut bytes = [0_u8; 4];
    let mut crc = u32::MAX;
    for (byte, index) in bytes.iter_mut().zip(indexes) {
        *byte = u8::try_from(index ^ usize::try_from(crc & 0xff).expect("a byte")).expect("a byte");
        crc = table[index] ^ (crc >> 8);
    }
    assert_eq!(crc32(&bytes), target, "the bytes have the checksum asked");
    bytes
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
        bytes.extend_from_slice(
            &u16::try_from(member.extra.len())
                .expect("short")
                .to_le_bytes(),
        );
        bytes.extend_from_slice(&[0; 2 + 2 + 2]);
        bytes.extend_from_slice(&member.external.to_le_bytes());
        bytes.extend_from_slice(&offset.to_le_bytes());
        bytes.extend_from_slice(member.name.as_bytes());
        bytes.extend_from_slice(&member.extra);
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
        // Owner-only, as the store's own staging directory is: the reader refuses to make a
        // directory under one that is not.
        kr_ipc::paths::create_private_directory(&staging).expect("a staging directory");
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
        outcome.is_err(),
        "an entry that lies about its size is refused"
    );
    assert!(
        largest <= 4,
        "no file is larger than its entry says: {largest} bytes, and the reading said {outcome:?}"
    );
}

/// KR-REQ-26.06: a name the rules would keep every prefix of is refused by its length and its depth
/// before the rules see it, and an archive whose directory takes more bytes than a release's does
/// is refused before the directory is read: one long name must not take memory that grows with the
/// square of its parts, and nothing is written for any of them.
#[test]
fn a_name_too_long_or_too_deep_and_a_directory_too_large_are_refused_before_they_are_kept() {
    let deep = vec!["a"; 40].join("/");
    let long = "b".repeat(2000);
    for (name, members, limits) in [
        (
            "a name of 65,535 bytes",
            vec![Member::directory(format!("{TOP}/{}", "x/".repeat(32_000)))],
            Limits::DEFAULT,
        ),
        (
            "a name beyond the bytes",
            vec![Member::stored(format!("{TOP}/{long}"), b"x")],
            Limits::DEFAULT,
        ),
        (
            "a name beyond the depth",
            vec![Member::stored(format!("{TOP}/{deep}"), b"x")],
            Limits::DEFAULT,
        ),
        (
            "a directory beyond the bytes",
            vec![
                Member::stored(format!("{TOP}/one.bin"), b"x"),
                Member::stored(format!("{TOP}/two.bin"), b"x"),
            ],
            Limits {
                directory_bytes: 100,
                ..Limits::DEFAULT
            },
        ),
    ] {
        let case = Case::new();
        assert!(
            case.read(&archive_of(&members), &limits).is_err(),
            "{name} is refused"
        );
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
}

/// KR-REQ-26.06: the parser is shown one end record and the directory that record names, as a
/// release archive has them, and an archive that gives it another record to follow is refused
/// before it sees the archive: a comment after the end record, bytes after it, a 64-bit form, a
/// count that the directory does not hold, a size that does not reach the end record. The control
/// is the same archive without the fault, which is read.
#[test]
fn an_archive_with_more_than_one_way_to_read_its_end_is_refused_before_the_parser_sees_it() {
    let members = release();
    let good = archive_of(&members);
    let end = good.len() - 22;
    let patched = |change: &dyn Fn(&mut Vec<u8>)| {
        let mut bytes = good.clone();
        change(&mut bytes);
        bytes
    };
    let cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "a comment after the end record",
            patched(&|bytes| {
                bytes[end + 20] = 3;
                bytes.extend_from_slice(b"abc");
            }),
        ),
        (
            "bytes after the end record",
            patched(&|bytes| bytes.push(0)),
        ),
        (
            "a 64-bit count",
            patched(&|bytes| bytes[end + 8..end + 12].copy_from_slice(&[0xff; 4])),
        ),
        (
            "a count the directory does not hold",
            patched(&|bytes| {
                let count = u16::from_le_bytes([bytes[end + 10], bytes[end + 11]]) + 1;
                bytes[end + 8..end + 10].copy_from_slice(&count.to_le_bytes());
                bytes[end + 10..end + 12].copy_from_slice(&count.to_le_bytes());
            }),
        ),
        (
            "a size that does not reach the end record",
            patched(&|bytes| {
                let size = u32::from_le_bytes([
                    bytes[end + 12],
                    bytes[end + 13],
                    bytes[end + 14],
                    bytes[end + 15],
                ]) - 4;
                bytes[end + 12..end + 16].copy_from_slice(&size.to_le_bytes());
            }),
        ),
    ];
    for (name, bytes) in &cases {
        let case = Case::new();
        assert!(
            case.read(bytes, &Limits::DEFAULT).is_err(),
            "{name} is refused"
        );
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
    let case = Case::new();
    assert!(
        case.read(&good, &Limits::DEFAULT).is_ok(),
        "the archive without the fault is read"
    );
}

/// KR-REQ-26.06: a release whose directory happens to spell the signature of an end record is read.
/// The directory carries each file's checksum, and the checksum of a file can be the four bytes of
/// the signature; the parser takes the last end record of the archive first, so such a release is
/// no different from any other, and refusing it would refuse a valid release for no fault of its.
#[test]
fn a_release_whose_directory_spells_an_end_record_is_read() {
    let signature = u32::from_le_bytes(*b"PK\x05\x06");
    let spelling = four_bytes_with_checksum(signature);
    let mut members = release();
    members.push(Member::stored(format!("{TOP}/share/spelling"), &spelling));
    let archive = archive_of(&members);
    assert!(
        archive.windows(4).any(|window| window == b"PK\x05\x06")
            && archive
                .windows(4)
                .filter(|window| *window == b"PK\x05\x06")
                .count()
                > 1,
        "the directory holds the signature beside the end record's own"
    );
    let case = Case::new();
    let (directory, written) = case
        .read(&archive, &Limits::DEFAULT)
        .expect("a release whose checksum spells the signature is read");
    assert_eq!(
        std::fs::read(directory.join("share/spelling")).expect("the file"),
        spelling
    );
    assert_eq!(written.len(), 4);
}

/// The extra data of an entry that makes the parser give up on the directory it is in and take
/// another end record: a Unicode path field whose checksum is wrong, then a 64-bit end record, its
/// locator and an end record of its own, which name a directory of many entries. `at` is where in
/// the archive the extra data begins.
fn extra_data_with_a_fallback(at: u64) -> Vec<u8> {
    let unicode_name = b"kr.exe";
    let mut extra = 0x7075_u16.to_le_bytes().to_vec();
    extra.extend_from_slice(
        &u16::try_from(1 + 4 + unicode_name.len())
            .expect("short")
            .to_le_bytes(),
    );
    extra.push(1);
    extra.extend_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
    extra.extend_from_slice(unicode_name);
    let record_64_at = at + extra.len() as u64;
    extra.extend_from_slice(b"PK\x06\x06");
    extra.extend_from_slice(&44_u64.to_le_bytes());
    extra.extend_from_slice(&[45, 0, 45, 0]);
    extra.extend_from_slice(&[0; 8]);
    extra.extend_from_slice(&5_000_000_u64.to_le_bytes());
    extra.extend_from_slice(&5_000_000_u64.to_le_bytes());
    extra.extend_from_slice(&1_u64.to_le_bytes());
    extra.extend_from_slice(&0_u64.to_le_bytes());
    extra.extend_from_slice(b"PK\x06\x07");
    extra.extend_from_slice(&0_u32.to_le_bytes());
    extra.extend_from_slice(&record_64_at.to_le_bytes());
    extra.extend_from_slice(&1_u32.to_le_bytes());
    extra.extend_from_slice(b"PK\x05\x06");
    extra.extend_from_slice(&[0; 4]);
    extra.extend_from_slice(&[0xff; 4]);
    extra.extend_from_slice(&[0xff; 8]);
    extra.extend_from_slice(&0_u16.to_le_bytes());
    extra
}

/// KR-REQ-26.06: a name or the extra data of an entry that holds the signature of an end record, of
/// its 64-bit form or of that form's locator is refused before the parser runs. The parser gives up
/// on a directory whose entry it cannot read and takes an earlier end record, here one the archive's
/// writer set inside an entry's extra data, and sizes what it keeps for the entries that record
/// counts before anything checks them. The control is the same extra data without the signatures,
/// which is read; a signature in a checksum or a size is not refused (see the case that reads it).
#[test]
fn a_signature_in_a_name_or_in_extra_data_is_refused_before_the_parser_runs() {
    let first = |extra: Vec<u8>| {
        let mut members = release();
        members[0].extra = extra;
        archive_of(&members)
    };
    // Where the directory starts, and so where the first entry's extra data does.
    let placeholder = first(vec![0; extra_data_with_a_fallback(0).len()]);
    let directory = placeholder
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .expect("a directory");
    let extra_at = (directory + 46 + release()[0].name.len()) as u64;
    let harmless = {
        let mut extra = 0xAAAA_u16.to_le_bytes().to_vec();
        let filler = extra_data_with_a_fallback(0).len() - 4;
        extra.extend_from_slice(&u16::try_from(filler).expect("short").to_le_bytes());
        extra.extend(std::iter::repeat_n(b'x', filler));
        extra
    };
    let mut named = release();
    named.push(Member::stored(
        format!("{TOP}/share/PK\x05\x06"),
        b"a name that holds a signature",
    ));
    let refused: Vec<(&str, Vec<u8>)> = vec![
        (
            "an end record set inside an entry's extra data",
            first(extra_data_with_a_fallback(extra_at)),
        ),
        ("an end record in a name", archive_of(&named)),
    ];
    for (name, bytes) in &refused {
        let case = Case::new();
        let error = case
            .read(bytes, &Limits::DEFAULT)
            .expect_err("the archive is refused");
        assert!(
            error.contains("end record"),
            "{name} is refused for the signature, before the parser: {error}"
        );
        assert!(case.staged().is_empty(), "{name}: nothing was written");
    }
    let case = Case::new();
    assert!(
        case.read(&first(harmless), &Limits::DEFAULT).is_ok(),
        "extra data of the same size without a signature is read"
    );
}

/// Nothing is written outside the staging directory by an archive that names a place beyond it.
#[test]
fn nothing_is_written_beside_the_staging_directory() {
    let case = Case::new();
    let escape = case.root.path().join("escape.exe");
    for name in [
        format!("{TOP}/../../escape.exe"),
        "../escape.exe".to_owned(),
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
