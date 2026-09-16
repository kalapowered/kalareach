//! Previews: the bounded decoder as `upload.finish` uses it.
//!
//! Requirement row closed here: KR-REQ-14.13. The client presentation is a separate task; what is
//! covered here is the decoder, its four limits, and what publishing does when it refuses.

mod support;

use kr_protocol::scalars::U64;
use kr_protocol::transfer::{
    MAX_PREVIEW_DECODE_BYTES, MAX_PREVIEW_PIXELS, MAX_PREVIEW_THUMBNAIL_BYTES,
    PREVIEW_THUMBNAIL_EDGE, PreviewFormat,
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
fn the_four_supported_formats_publish_with_a_bounded_preview() {
    let harness = Harness::create();
    for (format, media_type, expected) in [
        (image::ImageFormat::Png, "image/png", PreviewFormat::Png),
        (image::ImageFormat::Jpeg, "image/jpeg", PreviewFormat::Jpeg),
        (image::ImageFormat::WebP, "image/webp", PreviewFormat::Webp),
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
        assert!(preview.width.get() <= u64::from(PREVIEW_THUMBNAIL_EDGE));
        assert!(preview.height.get() <= u64::from(PREVIEW_THUMBNAIL_EDGE));
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
    assert_eq!(PREVIEW_THUMBNAIL_EDGE, 512);
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
