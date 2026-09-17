//! Previews: the bounded decoder as `upload.finish` uses it.
//!
//! Requirement row closed here: KR-REQ-14.13. The client presentation is a separate task; what is
//! covered here is the decoder, its four limits, and what publishing does when it refuses.

mod support;

use kr_protocol::scalars::U64;
use kr_protocol::transfer::{
    MAX_PREVIEW_DECODE_BYTES, MAX_PREVIEW_FRAME_BYTES, MAX_PREVIEW_PIXELS,
    MAX_PREVIEW_THUMBNAIL_BYTES, PREVIEW_THUMBNAIL_EDGES, PreviewFormat,
};
use support::{Harness, digest, png};

fn encoded(width: u32, height: u32, format: image::ImageFormat) -> Vec<u8> {
    let mut image = image::RgbaImage::new(width, height);
    for (index, pixel) in image.pixels_mut().enumerate() {
        let shade = u8::try_from(index % 251).unwrap_or(0);
        *pixel = image::Rgba([shade, 255 - shade, shade / 2, 255]);
    }
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut out, format)
        .expect("encodes");
    out.into_inner()
}

/// KR-REQ-14.13: the four decoded formats produce a bounded thumbnail on the published handle.
#[test]
fn the_decoded_formats_publish_with_a_bounded_preview() {
    let harness = Harness::create();
    for (format, media_type, expected) in [
        (image::ImageFormat::Png, "image/png", PreviewFormat::Png),
        (image::ImageFormat::Jpeg, "image/jpeg", PreviewFormat::Jpeg),
        (
            image::ImageFormat::Gif,
            "image/gif",
            PreviewFormat::GifFirstFrame,
        ),
    ] {
        let bytes = encoded(640, 480, format);
        let handle = harness.publish(&bytes, media_type, "photo");
        let preview = handle
            .preview
            .as_ref()
            .unwrap_or_else(|| panic!("{media_type} should decode"));
        assert_eq!(preview.source_format, expected);
        assert_eq!(preview.source_width, U64::new(640));
        assert_eq!(preview.source_height, U64::new(480));
        assert!(preview.width.get() <= u64::from(PREVIEW_THUMBNAIL_EDGES[0]));
        assert!(preview.height.get() <= u64::from(PREVIEW_THUMBNAIL_EDGES[0]));
        assert!(preview.thumbnail.len() as u64 <= MAX_PREVIEW_THUMBNAIL_BYTES);
        assert!(
            handle.presented_as_image,
            "{media_type} decoded, so it may be offered as a model image"
        );
        assert_eq!(handle.content_digest, digest(&bytes));
    }
}

/// KR-REQ-14.13: the specification's four numbers are the decoder's four numbers.
#[test]
fn the_decoders_limits_are_the_documented_ones() {
    assert_eq!(MAX_PREVIEW_PIXELS, 40_000_000);
    assert_eq!(MAX_PREVIEW_DECODE_BYTES, 256 * 1024 * 1024);
    assert_eq!(MAX_PREVIEW_THUMBNAIL_BYTES, 16 * 1024 * 1024);
    assert_eq!(PREVIEW_THUMBNAIL_EDGES[0], 512);
}

/// KR-REQ-14.13: an image above the pixel limit publishes as a file, and the original is untouched.
#[test]
fn an_image_above_the_pixel_limit_publishes_as_a_file() {
    let harness = Harness::create();
    // A complete one-pixel GIF whose logical screen descriptor declares 65535 by 65535.
    let mut bytes = encoded(1, 1, image::ImageFormat::Gif);
    bytes[6..10].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
    let handle = harness.publish(&bytes, "image/gif", "huge.gif");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
    assert_eq!(handle.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(handle.content_digest, digest(&bytes));

    // The file itself is exactly what was uploaded.
    let staged = std::fs::read_dir(harness.service.staging().complete().display_path())
        .expect("reads the completed area")
        .next()
        .expect("one published payload")
        .expect("a directory entry")
        .path();
    assert_eq!(std::fs::read(&staged).expect("reads the payload"), bytes);
}

/// KR-REQ-14.13: HTML and SVG stay files.
#[test]
fn html_and_svg_stay_files() {
    let harness = Harness::create();
    let html = br#"<!doctype html><html><body><img src="x"></body></html>"#;
    let begun = harness
        .begin(html, "text/html", "page.html")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, html)
        .expect("sends every chunk");
    let finished = harness
        .finish(begun.transfer_id, html)
        .expect("publishes the attachment");
    assert!(finished.handle.preview.as_ref().is_none());
    assert!(!finished.handle.presented_as_image);
    assert!(
        finished
            .preview_unavailable
            .0
            .as_deref()
            .unwrap_or_default()
            .contains("text/html"),
        "the refusal names the media type"
    );

    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="8"></svg>"#;
    let handle = harness.publish(svg, "image/svg+xml", "drawing.svg");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);

    // An SVG declared as something else is still not an image this decoder renders.
    let handle = harness.publish(svg, "application/octet-stream", "drawing.svg");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
}

/// KR-REQ-14.13: a failed preview keeps the original file and reports why.
#[test]
fn a_failed_preview_keeps_the_original_file_and_says_why() {
    let harness = Harness::create();
    let mut bytes = png(64, 64);
    bytes.truncate(40);
    let begun = harness
        .begin(&bytes, "image/png", "truncated.png")
        .expect("reserves the upload");
    harness
        .send_all(begun.transfer_id, &bytes)
        .expect("sends every chunk");
    let finished = harness
        .finish(begun.transfer_id, &bytes)
        .expect("publishes the attachment anyway");
    assert!(finished.handle.preview.as_ref().is_none());
    assert!(!finished.handle.presented_as_image);
    assert!(
        finished.preview_unavailable.as_ref().is_some(),
        "the reply says why there is no preview"
    );
    assert_eq!(finished.handle.content_digest, digest(&bytes));
    let staged = std::fs::read_dir(harness.service.staging().complete().display_path())
        .expect("reads the completed area")
        .next()
        .expect("one published payload")
        .expect("a directory entry")
        .path();
    assert_eq!(std::fs::read(&staged).expect("reads the payload"), bytes);
}

/// KR-REQ-14.13: a format the decoder does not handle transfers as a file.
#[test]
fn an_unsupported_format_transfers_as_a_file() {
    let harness = Harness::create();
    // A TIFF header: a real image format whose decoder is not compiled in.
    let handle = harness.publish(b"II\x2a\x00\x08\x00\x00\x00", "image/tiff", "scan.tiff");
    assert!(handle.preview.as_ref().is_none());
    assert!(
        !handle.presented_as_image,
        "an unsupported format is never presented as a supported model image"
    );

    let handle = harness.publish(b"plain text, nothing more", "text/plain", "notes.txt");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
}

/// KR-REQ-14.13: only the first frame of an animated GIF is decoded.
#[test]
fn only_the_first_frame_of_an_animated_gif_is_decoded() {
    use image::codecs::gif::{GifEncoder, Repeat};
    use image::{Delay, Frame, RgbaImage};

    let harness = Harness::create();
    let mut bytes = Vec::new();
    {
        let mut encoder = GifEncoder::new(std::io::Cursor::new(&mut bytes));
        encoder.set_repeat(Repeat::Infinite).expect("sets the loop");
        for shade in [40_u8, 200] {
            let mut frame = RgbaImage::new(32, 32);
            for pixel in frame.pixels_mut() {
                *pixel = image::Rgba([shade, shade, shade, 255]);
            }
            encoder
                .encode_frame(Frame::from_parts(
                    frame,
                    0,
                    0,
                    Delay::from_numer_denom_ms(100, 1),
                ))
                .expect("encodes a frame");
        }
    }
    let handle = harness.publish(&bytes, "image/gif", "animation.gif");
    let preview = handle.preview.as_ref().expect("a first-frame preview");
    assert_eq!(preview.source_format, PreviewFormat::GifFirstFrame);
    assert_eq!(preview.source_width, U64::new(32));
    assert_eq!(preview.source_height, U64::new(32));
    // The first frame is the dark one, so the thumbnail is the dark one.
    let decoded = image::load_from_memory(preview.thumbnail.as_slice())
        .expect("the thumbnail decodes")
        .to_rgba8();
    let first = decoded.get_pixel(0, 0);
    assert!(
        first[0] < 128,
        "the preview is the first frame, not a later one: {first:?}"
    );
}

/// Returns a PNG of pseudo-random pixels, which is an image no encoder compresses.
fn noise(width: u32, height: u32) -> Vec<u8> {
    let mut image = image::RgbaImage::new(width, height);
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for pixel in image.pixels_mut() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bytes = state.to_le_bytes();
        *pixel = image::Rgba([bytes[0], bytes[1], bytes[2], 255]);
    }
    let mut out = std::io::Cursor::new(Vec::new());
    image::DynamicImage::ImageRgba8(image)
        .write_to(&mut out, image::ImageFormat::Png)
        .expect("encodes a PNG");
    out.into_inner()
}

/// KR-REQ-14.13: a thumbnail that will not encode inside the frame budget is re-encoded at a
/// smaller edge rather than sent oversized or dropped.
#[test]
fn an_incompressible_image_steps_down_until_its_thumbnail_fits_a_frame() {
    let harness = Harness::create();
    let bytes = noise(512, 512);

    let handle = harness.publish(&bytes, "image/png", "noise.png");

    let preview = handle.preview.as_ref().expect("a preview was produced");
    assert_eq!(preview.source_width, U64::new(512));
    assert_eq!(preview.source_height, U64::new(512));
    assert!(
        preview.thumbnail.as_slice().len() as u64 <= MAX_PREVIEW_FRAME_BYTES,
        "the encoded thumbnail is {} bytes, above the frame budget",
        preview.thumbnail.as_slice().len()
    );
    assert!(
        preview.width.get() < u64::from(PREVIEW_THUMBNAIL_EDGES[0]),
        "an image this incompressible cannot have been kept at the largest edge"
    );
    assert!(
        PREVIEW_THUMBNAIL_EDGES
            .iter()
            .any(|edge| u64::from(*edge) == preview.width.get()),
        "the edge that was used is one of the declared ones, and {} is not",
        preview.width.get()
    );
    assert!(handle.presented_as_image);
}

/// KR-REQ-14.13: an image inside the pixel limit whose decode would want more than the budget is
/// refused before anything is allocated, and publishes as a file.
#[test]
fn an_image_within_the_pixel_limit_but_above_the_decode_budget_is_refused() {
    let harness = Harness::create();
    // Thirty-six million pixels: inside the forty-million limit, and above the 256 MiB budget once
    // a decoder is charged for the pixels it writes and the buffer it writes them through.
    let mut bytes = encoded(1, 1, image::ImageFormat::Gif);
    bytes[6..10].copy_from_slice(&[0x70, 0x17, 0x70, 0x17]);

    let handle = harness.publish(&bytes, "image/gif", "wide.gif");

    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
    assert_eq!(handle.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(handle.content_digest, digest(&bytes));
}

/// KR-REQ-14.13: a GIF whose first frame is far larger than its logical screen is refused on the
/// frame, which is the buffer a decoder would actually allocate.
#[test]
fn a_gif_frame_larger_than_its_screen_is_refused() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GIF89a");
    // A one-pixel logical screen, no global colour table.
    bytes.extend_from_slice(&[0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // One image descriptor declaring eight thousand by six thousand: forty-eight million pixels.
    bytes.push(0x2c);
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&8000_u16.to_le_bytes());
    bytes.extend_from_slice(&6000_u16.to_le_bytes());
    bytes.push(0x00);
    // The smallest well-formed image data, then the trailer.
    bytes.extend_from_slice(&[0x02, 0x02, 0x4c, 0x01, 0x00, 0x3b]);

    let refusal =
        kr_transfer::preview::generate(&mut std::io::Cursor::new(bytes.clone()), "image/gif")
            .expect_err("the frame is above the pixel limit");

    assert!(
        matches!(
            refusal,
            kr_transfer::preview::PreviewRefusal::TooManyPixels { pixels, .. }
                if pixels == 48_000_000
        ),
        "the refusal names the frame's own pixel count: {refusal}"
    );

    // And publishing it produces a file with no preview, with the bytes untouched.
    let harness = Harness::create();
    let handle = harness.publish(&bytes, "image/gif", "screen.gif");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
    assert_eq!(handle.content_digest, digest(&bytes));
}

/// KR-REQ-14.13: a WebP publishes without a preview, and says so, rather than reaching a decoder
/// whose allocation this host cannot bound.
///
/// The bytes below are a *small* lossless WebP: a sixteen-by-sixteen canvas, well inside the pixel
/// charge, and forty-odd bytes, well inside the encoded-input limit. Neither of those bounds would
/// have stopped it. What makes it dangerous is the field after the header, which says the number of
/// Huffman groups comes from the entropy image rather than from the canvas, and that is the
/// allocation no bound on pixels can reach. Nothing decodes it: the decoder is not compiled in, and
/// the refusal comes from the twelve-byte container signature before any decoder is built.
#[test]
fn a_webp_publishes_without_a_preview_and_says_why() {
    let harness = Harness::create();
    // The VP8L bitstream, least significant bit first: the 0x2f signature, width - 1 and height - 1
    // in fourteen bits each (sixteen by sixteen), no alpha, version 0, no transform, no colour
    // cache, the meta-Huffman bit set, and the largest `huffman_bits` the field holds.
    let lossless = [0x2f, 0x0f, 0xc0, 0x03, 0x00, 0x3c];
    let mut payload = Vec::new();
    payload.extend_from_slice(b"VP8L");
    payload.extend_from_slice(&(lossless.len() as u32).to_le_bytes());
    payload.extend_from_slice(&lossless);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&((payload.len() + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(b"WEBP");
    bytes.extend_from_slice(&payload);
    assert!(
        bytes.len() < 64,
        "the file is small enough that no size bound would refuse it"
    );

    let refusal =
        kr_transfer::preview::generate(&mut std::io::Cursor::new(bytes.clone()), "image/webp")
            .expect_err("this host does not decode WebP");

    assert!(
        matches!(
            refusal,
            kr_transfer::preview::PreviewRefusal::FormatWithheld { .. }
        ),
        "the refusal names the format rather than the bytes: {refusal}"
    );
    assert!(
        refusal
            .to_string()
            .starts_with("no preview for this format"),
        "and says so in the words a client shows: {refusal}"
    );

    // The transfer itself succeeds: a file with no preview is still an attachment.
    let handle = harness.publish(&bytes, "image/webp", "shot.webp");
    assert!(handle.preview.as_ref().is_none());
    assert!(!handle.presented_as_image);
    assert_eq!(handle.byte_len, U64::new(bytes.len() as u64));
    assert_eq!(handle.content_digest, digest(&bytes));
    let staged = std::fs::read_dir(harness.service.staging().complete().display_path())
        .expect("reads the completed area")
        .next()
        .expect("one published payload")
        .expect("a directory entry")
        .path();
    assert_eq!(
        std::fs::read(&staged).expect("reads the payload"),
        bytes,
        "the file is exactly what was uploaded"
    );
}
