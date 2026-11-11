//! The text form of a file key: only the printed form parses.

use kr_boundary_windows::filekey::FileKey;

#[test]
fn only_the_printed_form_of_a_key_parses() {
    let key = FileKey::ntfs(0xabcd, 0x0123_4567_89ab_cdef);
    let printed = key.to_string();
    assert_eq!(printed, "000000000000abcd:efcdab89674523010000000000000000");
    assert_eq!(printed.parse::<FileKey>().unwrap(), key);
    let full = FileKey {
        volume_serial: u64::MAX,
        file_id: [0xff; 16],
    };
    assert_eq!(full.to_string().parse::<FileKey>().unwrap(), full);

    let (volume, id) = printed.split_once(':').unwrap();
    for (what, text) in [
        (
            "capitals in the volume",
            format!("{}:{id}", volume.to_uppercase()),
        ),
        (
            "capitals in the identifier",
            format!("{volume}:{}", id.to_uppercase()),
        ),
        ("a sign", format!("+{}:{id}", &volume[1..])),
        ("leading zeros past the width", format!("0{volume}:{id}")),
        (
            "a short volume",
            format!("{}:{id}", volume.trim_start_matches('0')),
        ),
        ("no colon", format!("{volume}{id}")),
        ("a short identifier", format!("{volume}:{}", &id[2..])),
        ("an empty text", String::new()),
    ] {
        assert!(text.parse::<FileKey>().is_err(), "{what}: {text}");
    }
}
