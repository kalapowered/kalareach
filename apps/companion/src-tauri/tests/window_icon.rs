//! The icons the bundle declares, checked in the form the runtime loads them in.
//!
//! The window icon is not decoded by an image library at startup: the build step embeds the raw
//! samples of the first PNG in `bundle.icon`, and the runtime reads them as one byte per channel.
//! A PNG with sixteen bits per channel carries twice the bytes the runtime expects, so the window
//! refuses the icon and the application fails to start. Nothing else in the build says so, which is
//! why these tests read the files themselves.

use std::path::{Path, PathBuf};

/// Portable Network Graphics header fields, as the first chunk of the file states them.
struct Header {
    width: u32,
    height: u32,
    bits_per_channel: u8,
    colour_type: u8,
}

const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
/// Red, green, blue and alpha, one sample each.
const TRUE_COLOUR_WITH_ALPHA: u8 = 6;

/// The bytes an image header occupies: the signature, the chunk's length and name, and its fields.
const HEADER_BYTES: usize = 26;

fn header_of(bytes: &[u8], what: &str) -> Header {
    assert!(
        bytes.starts_with(&SIGNATURE),
        "{what} does not begin with the PNG signature"
    );
    assert!(
        bytes.len() >= HEADER_BYTES,
        "{what} is {} bytes, too short to hold an image header",
        bytes.len()
    );
    assert!(&bytes[12..16] == b"IHDR", "{what} does not begin with IHDR");
    let field = |at: usize| u32::from_be_bytes(bytes[at..at + 4].try_into().expect("four bytes"));
    Header {
        width: field(16),
        height: field(20),
        bits_per_channel: bytes[24],
        colour_type: bytes[25],
    }
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|error| panic!("{} could not be read: {error}", path.display()))
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The icon paths the bundle declares, in the order it declares them.
fn declared_icons() -> Vec<String> {
    let text = std::fs::read_to_string(crate_root().join("tauri.conf.json"))
        .expect("the application configuration can be read");
    let configuration: serde_json::Value =
        serde_json::from_str(&text).expect("the application configuration is valid JSON");
    configuration["bundle"]["icon"]
        .as_array()
        .expect("the bundle declares its icons")
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .expect("each declared icon is a path")
                .to_owned()
        })
        .collect()
}

#[test]
fn every_declared_png_carries_one_byte_per_channel() {
    let declared = declared_icons();
    let images: Vec<&String> = declared
        .iter()
        .filter(|path| path.ends_with(".png"))
        .collect();
    assert!(
        !images.is_empty(),
        "the bundle declares at least one PNG for the window icon"
    );
    for path in images {
        let header = header_of(&read(&crate_root().join(path)), path);
        assert_eq!(
            header.bits_per_channel, 8,
            "{path} stores {} bits per channel; the runtime reads one byte per channel and \
             refuses the icon at startup",
            header.bits_per_channel
        );
        assert_eq!(
            header.colour_type, TRUE_COLOUR_WITH_ALPHA,
            "{path} is not true colour with alpha, so its samples are not four per pixel"
        );
    }
}

#[test]
fn a_declared_png_is_the_size_its_name_states() {
    for path in declared_icons()
        .iter()
        .filter(|path| path.ends_with(".png"))
    {
        let name = path.rsplit('/').next().expect("a file name");
        let Some(stem) = name.strip_suffix(".png") else {
            continue;
        };
        let (stem, scale) = match stem.split_once('@') {
            Some((stem, "2x")) => (stem, 2),
            Some(_) => panic!("{name} states a scale this bundle does not use"),
            None => (stem, 1),
        };
        let Some((width, height)) = stem.split_once('x') else {
            continue;
        };
        let (Ok(width), Ok(height)) = (width.parse::<u32>(), height.parse::<u32>()) else {
            continue;
        };
        let header = header_of(&read(&crate_root().join(path)), path);
        assert_eq!(
            (header.width, header.height),
            (width * scale, height * scale),
            "{name} is {}x{}",
            header.width,
            header.height
        );
    }
}

/// One frame's bytes, or the reason the directory does not describe a frame.
///
/// Every field is read through a checked range, so a file that names a frame it does not contain
/// is reported as the malformed file it is rather than ending the run somewhere further along.
fn frame_at(bytes: &[u8], index: usize) -> Result<&[u8], String> {
    let start = 6 + 16 * index;
    let entry = bytes
        .get(start..start + 16)
        .ok_or_else(|| format!("the directory ends before entry {index}"))?;
    let length = u32::from_le_bytes(entry[8..12].try_into().expect("four bytes")) as usize;
    let offset = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes")) as usize;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("entry {index} names a range past the end of any file"))?;
    bytes.get(offset..end).ok_or_else(|| {
        format!("entry {index} names bytes {offset}..{end}, past the end of the file")
    })
}

/// The smallest device-independent bitmap header an icon frame can carry.
const BITMAP_HEADER: usize = 40;

#[test]
fn every_frame_of_the_windows_icon_carries_one_byte_per_channel() {
    for path in declared_icons()
        .iter()
        .filter(|path| path.ends_with(".ico"))
    {
        let bytes = read(&crate_root().join(path));
        let directory = bytes
            .get(0..6)
            .unwrap_or_else(|| panic!("{path} is too short to hold an icon directory"));
        assert_eq!(
            (directory[0], directory[1], directory[2], directory[3]),
            (0, 0, 1, 0),
            "{path} does not begin with an icon directory"
        );
        let count = u16::from_le_bytes([directory[4], directory[5]]) as usize;
        assert!(count > 0, "{path} holds no frames");
        for frame in 0..count {
            let what = format!("frame {frame} of {path}");
            let payload =
                frame_at(&bytes, frame).unwrap_or_else(|reason| panic!("{path}: {reason}"));
            if payload.starts_with(&SIGNATURE) {
                let header = header_of(payload, &what);
                assert_eq!(
                    header.bits_per_channel, 8,
                    "{what} is not one byte per channel"
                );
                assert_eq!(
                    header.colour_type, TRUE_COLOUR_WITH_ALPHA,
                    "{what} is not true colour with alpha"
                );
                continue;
            }
            // The other form a frame takes is a device-independent bitmap, whose own header states
            // its depth and which the loader converts. It still has to be a header.
            let stated = payload
                .get(0..4)
                .map(|size| u32::from_le_bytes(size.try_into().expect("four bytes")) as usize);
            assert_eq!(
                stated,
                Some(BITMAP_HEADER),
                "{what} is neither a PNG nor a bitmap header"
            );
            assert!(
                payload.len() > BITMAP_HEADER,
                "{what} is a bitmap header with no pixels after it"
            );
        }
    }
}
