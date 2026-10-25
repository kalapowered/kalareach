//! Seeded streams of hostile terminal output.
//!
//! A stream is a run of atoms: text, malformed UTF-8, every C0 and C1 byte, control sequences,
//! control strings ended in every way a string can end, tmux envelopes nested past the bound, and
//! the queries, side effects and graphics the engine must never let through. A failing stream is its
//! seed.
//!
//! The generator tags an atom with what it knows the atom to be, from its own tables and not from
//! the engine's class table: a check that read the engine's answer back would pass whatever the
//! engine did.

/// xorshift64*, short enough to read and good enough to pick atoms with.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64, salt: u64) -> Self {
        let mut rng = Self(seed.wrapping_mul(salt) | 1);
        for _ in 0..4 {
            rng.next();
        }
        rng
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    pub fn index(&mut self, bound: usize) -> usize {
        usize::try_from(self.below(bound as u64)).unwrap_or(0)
    }

    pub fn chance(&mut self, one_in: u64) -> bool {
        self.below(one_in) == 0
    }

    pub fn byte(&mut self, low: u8, count: u8) -> u8 {
        low + u8::try_from(self.below(u64::from(count))).unwrap_or(0)
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.index(items.len())]
    }
}

/// What the generator knows an atom to be, when it is one of the three things that must never
/// reach a physical terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    /// A question the engine answers itself.
    Query,
    /// A clipboard write, a notification, a progress report or a bell.
    SideEffect,
    /// A sixel or kitty graphics string, which the profile withholds.
    Graphics,
}

/// The bytes one tagged atom occupies.
#[derive(Clone, Copy, Debug)]
pub struct Mark {
    pub start: usize,
    pub end: usize,
    pub tag: Tag,
}

/// One generated stream.
pub struct Stream {
    pub seed: u64,
    pub bytes: Vec<u8>,
    pub marks: Vec<Mark>,
}

#[derive(Default)]
struct Out {
    bytes: Vec<u8>,
    marks: Vec<Mark>,
}

impl Out {
    fn tagged(&mut self, tag: Tag, bytes: &[u8]) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(bytes);
        self.marks.push(Mark {
            start,
            end: self.bytes.len(),
            tag,
        });
    }
}

/// Questions the engine answers, each as the bytes of one atom. The 7-bit forms end the string
/// themselves; the last three are the 8-bit introducers.
pub const QUERIES: &[&[u8]] = &[
    b"\x1b[c",
    b"\x1b[0c",
    b"\x1b[>c",
    b"\x1b[=c",
    b"\x1bZ",
    b"\x1b[5n",
    b"\x1b[6n",
    b"\x1b[?6n",
    b"\x1b[?15n",
    b"\x1b[4$p",
    b"\x1b[?7$p",
    b"\x1b[?2026$p",
    b"\x1b[18t",
    b"\x1b[14t",
    b"\x1b[19t",
    b"\x1b[11t",
    b"\x1bP$qm\x1b\\",
    b"\x1bP$qr\x1b\\",
    b"\x1bP+q544e\x1b\\",
    b"\x1b]4;1;?\x1b\\",
    b"\x1b]10;?\x07",
    b"\x1b]11;?\x1b\\",
    b"\x1b[>0q",
    b"\x1b[?u",
    b"\x1b]52;c;?\x1b\\",
    b"\x9b6n",
    b"\x9bc",
    b"\x9d11;?\x1b\\",
];

/// Queries made of a control sequence with nothing in it that ends a string, for the places a
/// query sits inside the tail of a string.
pub const CSI_QUERIES_ESC: &[&[u8]] = &[b"\x1b[6n", b"\x1b[c", b"\x1b[5n", b"\x1b[>0q"];
pub const CSI_QUERIES_C1: &[&[u8]] = &[b"\x9b6n", b"\x9bc", b"\x9b5n"];

/// Things that leave the terminal: a bell, a clipboard write (valid and not), a notification in
/// three conventions and a progress report.
const SIDE_EFFECTS: &[&[u8]] = &[
    b"\x07",
    b"\x1b]52;c;aGVsbG8=\x07",
    b"\x1b]52;p;aGVsbG8=\x1b\\",
    b"\x1b]52;c;not base64\x07",
    b"\x1b]9;build done\x07",
    b"\x1b]9;4;1;50\x07",
    b"\x1b]99;i=1:p=title;Title\x1b\\",
    b"\x1b]777;notify;Title;Body\x07",
];

/// Graphics strings, which the profile withholds whole.
const GRAPHICS: &[&[u8]] = &[
    b"\x1bPq\"1;1;4;4#0;2;0;0;0#0~~~~\x1b\\",
    b"\x1b_Ga=T,f=24,s=1,v=1;AAAA\x1b\\",
    b"\x1b_Gi=1,a=q;\x1b\\",
];

const SCALARS: &[&str] = &[
    "a",
    "Z",
    " ",
    "\u{e9}",
    "\u{4e2d}",
    "\u{1f469}\u{200d}\u{1f4bb}",
    "e\u{301}",
    "\u{fffd}",
    "\u{85}",
    "\u{9b}",
    "\u{9c}",
    "\u{7f}",
    "\u{200d}",
    "\u{301}",
];

const MALFORMED: &[&[u8]] = &[
    b"\xc0\xaf",
    b"\xe0\x80\xaf",
    b"\xed\xa0\x80",
    b"\xf4\x90\x80\x80",
    b"\xf8",
    b"\xff",
    b"\xfe",
    b"\xc1\xbf",
    b"\x80",
    b"\xbf",
    b"\xe2\x82",
    b"\xf0\x9f\x91",
    b"\xf0\x80\x80\x80",
];

const OSC_BODIES: &[&str] = &[
    "0;a title \u{e9}",
    "1;icon",
    "2;window",
    "4;1;rgb:12/34/56",
    "7;file:///tmp/dir",
    "8;;https://example.com/a",
    "8;id=1;http://x.example/",
    "8;;",
    "10;rgb:ff/00/00",
    "11;rgb:00/00/ff",
    "12;rgb:00/ff/00",
    "104",
    "110",
    "133;A",
    "133;B",
    "133;C",
    "133;D;0",
    "633;A",
    "1337;SetUserVar=a=YQ==",
    "6666;x",
    ";",
];

/// Control sequences that change the screen, written with a marker, a count of numeric parameters
/// and the intermediates and final, so that a stream builds a screen the checks can tell apart.
const CSI_KNOWN: &[(&str, u64, &str)] = &[
    ("", 2, "H"),
    ("", 1, "J"),
    ("", 1, "K"),
    ("", 1, "L"),
    ("", 1, "M"),
    ("", 1, "P"),
    ("", 1, "@"),
    ("", 1, "X"),
    ("", 1, "S"),
    ("", 1, "T"),
    ("", 1, "A"),
    ("", 1, "B"),
    ("", 1, "C"),
    ("", 1, "D"),
    ("", 1, "E"),
    ("", 1, "F"),
    ("", 1, "G"),
    ("", 1, "d"),
    ("", 1, "I"),
    ("", 1, "Z"),
    ("", 1, "g"),
    ("", 1, "b"),
    ("", 2, "r"),
    ("", 2, "s"),
    ("", 0, "s"),
    ("", 0, "u"),
    ("", 1, "h"),
    ("", 1, "l"),
    ("", 1, " q"),
    ("", 0, "!p"),
    ("?", 1, "h"),
    ("?", 1, "l"),
];

/// Modes the screen reacts to, for the `h` and `l` that carry one.
const MODES: &[u64] = &[
    1, 3, 4, 5, 6, 7, 12, 20, 25, 45, 47, 66, 69, 1000, 1004, 1006, 1047, 1048, 1049, 2004, 2026,
];

/// Renditions, including the colon and semicolon spellings of a direct colour.
const SGR: &[&str] = &[
    "",
    "0",
    "1",
    "3",
    "4",
    "7",
    "9",
    "22",
    "27",
    "1;31",
    "38;2;1;2;3",
    "38:2::1:2:3",
    "48;5;200",
    "4:3",
    "58;2;9;8;7",
    "39",
    "49",
    "90",
    "107",
];

fn digits(rng: &mut Rng, out: &mut Vec<u8>, longest: u64) {
    for _ in 0..=rng.below(longest) {
        out.push(rng.byte(b'0', 10));
    }
}

fn known_csi(rng: &mut Rng, out: &mut Vec<u8>) {
    if rng.chance(4) {
        out.extend_from_slice(rng.pick(SGR).as_bytes());
        out.push(b'm');
        return;
    }
    let (marker, count, tail) = *rng.pick(CSI_KNOWN);
    out.extend_from_slice(marker.as_bytes());
    for index in 0..count {
        if index > 0 {
            out.push(b';');
        }
        let number = if tail == "h" || tail == "l" {
            *rng.pick(MODES)
        } else {
            rng.below(30)
        };
        out.extend_from_slice(number.to_string().as_bytes());
    }
    out.extend_from_slice(tail.as_bytes());
}

fn csi(rng: &mut Rng, out: &mut Vec<u8>) {
    let eight_bit = rng.chance(6);
    if eight_bit {
        out.push(0x9b);
    } else {
        out.extend_from_slice(b"\x1b[");
    }
    if rng.chance(3) {
        known_csi(rng, out);
        return;
    }
    if rng.chance(3) {
        out.push(*rng.pick(b"?<=>"));
    }
    for _ in 0..rng.below(7) {
        let longest = if rng.chance(40) { 300 } else { 5 };
        digits(rng, out, longest);
        out.push(*rng.pick(b";;:"));
        if rng.chance(20) {
            out.push(*rng.pick(&[0x00, 0x07, 0x08, 0x0a, 0x0d, 0x1b, 0x18, 0x1a]));
        }
    }
    for _ in 0..rng.below(4) {
        out.push(rng.byte(0x20, 16));
    }
    out.push(rng.byte(0x40, 0x3f));
}

fn payload(rng: &mut Rng, out: &mut Vec<u8>, length: u64) {
    for _ in 0..length {
        let byte = match rng.below(12) {
            0 => rng.byte(0x80, 0x20),
            1 => 0x1b,
            2 => *rng.pick(&[0x00, 0x07, 0x18, 0x1a, 0x0a, 0x0d]),
            3 => *rng.pick(b"[]\\;:?"),
            _ => rng.byte(0x20, 0x5f),
        };
        out.push(byte);
    }
}

/// The ways a control string ends, and one way it does not.
fn ender(rng: &mut Rng, out: &mut Vec<u8>) {
    match rng.below(10) {
        0..=3 => out.extend_from_slice(b"\x1b\\"),
        4 | 5 => out.push(0x07),
        6 => out.push(0x18),
        7 => out.push(0x1a),
        8 => out.push(0x9c),
        // ESC then something that is not a backslash, and nothing at all.
        _ => {
            if rng.chance(2) {
                out.push(0x1b);
                out.push(*rng.pick(b"[]A_cN"));
            }
        }
    }
}

fn string(rng: &mut Rng, out: &mut Vec<u8>) {
    let (open, eight_bit, kind): (&[u8], u8, u8) = match rng.below(7) {
        0..=2 => (b"\x1b]", 0x9d, b']'),
        3 => (b"\x1bP", 0x90, b'P'),
        4 => (b"\x1b_", 0x9f, b'_'),
        5 => (b"\x1b^", 0x9e, b'^'),
        _ => (b"\x1bX", 0x98, b'X'),
    };
    if rng.chance(8) {
        out.push(eight_bit);
    } else {
        out.extend_from_slice(open);
    }
    if kind == b']' {
        out.extend_from_slice(rng.pick(OSC_BODIES).as_bytes());
        if rng.chance(2) {
            out.push(b';');
            let length = rng.below(40);
            payload(rng, out, length);
        }
    } else {
        let length = rng.below(40);
        payload(rng, out, length);
    }
    ender(rng, out);
}

/// A tmux passthrough envelope, with its escapes doubled, nested up to depth 7 where the bound is 4.
fn tmux(rng: &mut Rng, out: &mut Vec<u8>, depth: u32) {
    let mut inner = Vec::new();
    match rng.below(7) {
        0 => csi(rng, &mut inner),
        1 => inner.extend_from_slice(rng.pick(QUERIES)),
        2 | 3 if depth < 7 => tmux(rng, &mut inner, depth + 1),
        4 => string(rng, &mut inner),
        5 => inner.extend_from_slice(rng.pick(SIDE_EFFECTS)),
        _ => inner.extend_from_slice(b"\x1b[31mred"),
    }
    out.extend_from_slice(if rng.chance(10) {
        &b"\x90tmux;"[..]
    } else {
        &b"\x1bPtmux;"[..]
    });
    for byte in inner {
        out.push(byte);
        if byte == 0x1b {
            out.push(0x1b);
        }
    }
    if !rng.chance(12) {
        out.extend_from_slice(b"\x1b\\");
    }
}

fn atom(rng: &mut Rng, out: &mut Out) {
    match rng.below(26) {
        0..=2 | 24 => {
            for _ in 0..=rng.below(30) {
                let byte = rng.byte(0x20, 0x5f);
                out.bytes.push(byte);
            }
        }
        3 | 4 => {
            for _ in 0..=rng.below(6) {
                out.bytes.extend_from_slice(rng.pick(SCALARS).as_bytes());
            }
        }
        5 | 6 => out.bytes.extend_from_slice(rng.pick(MALFORMED)),
        7 => out.bytes.push(rng.byte(0x80, 0x20)),
        8 => out.bytes.push(rng.byte(0x00, 0x20)),
        9..=12 => csi(rng, &mut out.bytes),
        13 | 14 => string(rng, &mut out.bytes),
        15 => tmux(rng, &mut out.bytes, 1),
        16..=18 => out.tagged(Tag::Query, rng.pick(QUERIES)),
        19 | 20 => out.tagged(Tag::SideEffect, rng.pick(SIDE_EFFECTS)),
        21 => out.tagged(Tag::Graphics, rng.pick(GRAPHICS)),
        22 => {
            out.bytes.push(0x1b);
            out.bytes.push(*rng.pick(b"78cDEHMNOZ=>()*+#%"));
        }
        23 => out.bytes.extend_from_slice(b"\r\n"),
        _ => out
            .bytes
            .extend_from_slice(b"text \x1b[1mbold\x1b[m \xe4\xb8\xad"),
    }
}

/// The stream a seed names.
pub fn stream(seed: u64) -> Stream {
    let mut rng = Rng::new(seed, 0x9e37_79b9_7f4a_7c15);
    let mut out = Out::default();
    for _ in 0..=rng.below(40) {
        atom(&mut rng, &mut out);
    }
    Stream {
        seed,
        bytes: out.bytes,
        marks: out.marks,
    }
}

/// How a read is cut: the whole stream at once, a byte at a time, and two random widths.
pub const SPLITS: u64 = 4;

/// The offsets at which the stream's reads end.
pub fn cuts(seed: u64, length: usize, how: u64) -> Vec<usize> {
    let mut rng = Rng::new(seed, 0xd1b5_4a32_d192_ed03);
    let mut at = Vec::new();
    let mut position = 0usize;
    while position < length {
        let step = match how {
            0 => length,
            1 => 1,
            2 => 1 + rng.index(97),
            _ => 1 + rng.index(4096),
        };
        position = (position + step).min(length);
        at.push(position);
    }
    at
}

// ------------------------------------------------------------------- oversized control strings

/// How the string ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// `ESC \`.
    St,
    /// BEL, which ends an OSC string only.
    Bel,
    /// CAN.
    Can,
    /// Nothing: the stream ends inside the string.
    Open,
}

/// Which string, and whether it is past its bound.
#[derive(Clone, Copy, Debug)]
pub struct Shape {
    pub family: Family,
    pub past_bound: bool,
    pub end: End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// OSC 52, bounded at 1 MiB.
    Osc52,
    /// Any other OSC, bounded at 64 KiB.
    Osc,
    Dcs,
    Apc,
    Pm,
    Tmux,
}

impl Family {
    pub const ALL: [Self; 6] = [
        Self::Osc52,
        Self::Osc,
        Self::Dcs,
        Self::Apc,
        Self::Pm,
        Self::Tmux,
    ];

    pub fn is_osc(self) -> bool {
        matches!(self, Self::Osc52 | Self::Osc)
    }

    pub fn bound(self) -> usize {
        if self == Self::Osc52 {
            1024 * 1024
        } else {
            64 * 1024
        }
    }

    fn open(self) -> &'static [u8] {
        match self {
            Self::Osc52 => b"\x1b]52;c;",
            Self::Osc => b"\x1b]2;",
            Self::Dcs => b"\x1bP1|",
            Self::Apc => b"\x1b_G",
            Self::Pm => b"\x1b^",
            Self::Tmux => b"\x1bPtmux;",
        }
    }
}

/// An oversized (or just inside its bound) string with queries around it, and what the engine must
/// do with each.
pub struct Oversized {
    pub stream: Stream,
    /// Where the string starts.
    pub string_at: u64,
    /// The offsets of the queries outside the string, which are the only ones answered.
    pub answered: Vec<u64>,
    /// The offsets of the queries in the string's tail, which must never act.
    pub inside: Vec<u64>,
    /// Whether the string is complete and inside its bound, so a clipboard write in it happens.
    pub writes: bool,
}

const BASE64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Builds a stream of a query, one control string and queries in each form after it.
///
/// A string past its bound is discarded in constant memory, and nothing in it acts: not a control
/// sequence introduced by `ESC`, not a raw 0x9b, not the text of a sequence without its introducer.
/// What follows the string is outside it when the string ended, and inside it when it did not.
/// Within bound, only a string that ends is built, so every query after it is outside.
pub fn oversized(seed: u64, shape: Shape) -> Oversized {
    assert!(
        shape.past_bound || shape.end != End::Open,
        "a string inside its bound is built ended"
    );
    assert!(
        shape.end != End::Bel || shape.family.is_osc(),
        "only an OSC string ends at BEL"
    );
    let mut rng = Rng::new(seed, 0xa24b_aed4_963e_e407);
    let mut bytes = Vec::new();
    let mut answered = Vec::new();
    let mut inside = Vec::new();

    // A query before the string is answered whatever follows.
    answered.push(0);
    bytes.extend_from_slice(b"\x1b[c");

    let string_at = bytes.len() as u64;
    bytes.extend_from_slice(shape.family.open());
    let bound = shape.family.bound();
    let filler = if shape.past_bound {
        bound + 1 + rng.index(5000)
    } else {
        // A multiple of four, so an OSC 52 payload is whole base64.
        (bound - 128 - rng.index(4096)) / 4 * 4
    };
    // The filler holds nothing that ends or restarts a string: no ESC, BEL, CAN, SUB or raw ST, and
    // no `;` that would split an OSC into parts. OSC 52 gets base64, which a write needs.
    let base64 = shape.family == Family::Osc52;
    for _ in 0..filler {
        bytes.push(if base64 {
            BASE64[rng.index(BASE64.len())]
        } else {
            rng.byte(b'A', 26)
        });
    }
    if shape.past_bound {
        for _ in 0..4 {
            inside.push(bytes.len() as u64);
            bytes.extend_from_slice(if rng.chance(2) {
                rng.pick(CSI_QUERIES_ESC)
            } else {
                rng.pick(CSI_QUERIES_C1)
            });
            bytes.extend_from_slice(b"AB");
        }
        // Introducers without their escape, and every raw introducer, as payload.
        bytes.extend_from_slice(b"[6n?$p");
        bytes.extend_from_slice(&[0x9b, 0x9d, 0x90, 0x98, 0x9e, 0x9f]);
    }
    match shape.end {
        End::St => bytes.extend_from_slice(b"\x1b\\"),
        End::Bel => bytes.push(0x07),
        End::Can => bytes.push(0x18),
        End::Open => {}
    }
    let ended = shape.end != End::Open;

    // An open string swallows what follows, and an ST or BEL inside a query would end it, so the
    // queries after an open string have none.
    let forms: [&[u8]; 3] = [b"\x1b[6n", b"\x9b6n", b"\x1b]52;c;?\x1b\\"];
    for _ in 0..3 {
        let form = *rng.pick(&forms);
        let query = if ended || form.len() <= 4 {
            form
        } else {
            b"\x1b[5n"
        };
        if ended {
            answered.push(bytes.len() as u64);
        } else {
            inside.push(bytes.len() as u64);
        }
        bytes.extend_from_slice(query);
    }
    bytes.extend_from_slice(b" tail");

    Oversized {
        stream: Stream {
            seed,
            bytes,
            marks: Vec::new(),
        },
        string_at,
        answered,
        inside,
        writes: shape.family == Family::Osc52
            && !shape.past_bound
            && matches!(shape.end, End::St | End::Bel),
    }
}

// -------------------------------------------------------------------------------- query floods

/// A stream of queries and a little text, longer than the lane's queue and budget hold.
pub struct Flood {
    pub stream: Stream,
    /// The bytes that are not queries, which are forwarded.
    pub text: Vec<u8>,
}

pub fn flood(seed: u64, queries: usize) -> Flood {
    let mut rng = Rng::new(seed, 0xc13f_a9a9_02a6_328f);
    let mut bytes = Vec::new();
    let mut text = Vec::new();
    for _ in 0..queries {
        // The three queries that end in a string would join the text in the lexer's eyes only if the
        // text carried an escape, and it does not.
        bytes.extend_from_slice(rng.pick(QUERIES));
        if rng.chance(5) {
            bytes.extend_from_slice(b"hello");
            text.extend_from_slice(b"hello");
        }
    }
    Flood {
        stream: Stream {
            seed,
            bytes,
            marks: Vec::new(),
        },
        text,
    }
}
