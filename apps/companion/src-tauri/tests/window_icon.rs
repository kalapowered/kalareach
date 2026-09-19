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

fn header_of(bytes: &[u8], what: &str) -> Header {
    assert!(
        bytes.starts_with(&SIGNATURE),
        "{what} does not begin with the PNG signature"
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

#[test]
fn every_frame_of_the_windows_icon_carries_one_byte_per_channel() {
    for path in declared_icons()
        .iter()
        .filter(|path| path.ends_with(".ico"))
    {
        let bytes = read(&crate_root().join(path));
        let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
        assert!(count > 0, "{path} holds no frames");
        for frame in 0..count {
            let entry = &bytes[6 + 16 * frame..6 + 16 * frame + 16];
            let length = u32::from_le_bytes(entry[8..12].try_into().expect("four bytes")) as usize;
            let offset = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes")) as usize;
            let payload = &bytes[offset..offset + length];
            if !payload.starts_with(&SIGNATURE) {
                // A frame stored as a device-independent bitmap carries its depth in its own
                // header, and the loader converts it.
                continue;
            }
            let what = format!("frame {frame} of {path}");
            let header = header_of(payload, &what);
            assert_eq!(
                header.bits_per_channel, 8,
                "{what} is not one byte per channel"
            );
        }
    }
}
