//! The conformance corpus: the cases the fixtures are built from.
//!
//! Section 8 requires generated fixtures rather than prose alone, and section 21 names the
//! acceptance rows they serve. The cases live here, in the crate, so the generator that writes
//! `fixtures/terminal/` and the tests that check the engine against those files are looking at the
//! same list. A case is an input and the row of the class table or the acceptance requirement it
//! exists to pin; what the engine does with it is recorded, not asserted twice.

use serde_json::{Value, json};

use crate::budget::GridSize;
use crate::engine::{Engine, EngineConfig};
use crate::event::{Event, EventKind};
use crate::lane::LaneGate;
use crate::sideeffect::{LeaseHolder, SideEffectDestination, SideEffectKind};

/// One lexer or engine case.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    /// Stable identifier.
    pub id: &'static str,
    /// The requirement or class-table row the case pins.
    pub covers: &'static str,
    /// The bytes fed to the engine.
    pub input: &'static [u8],
}

/// One case that is about what ends up on the canonical grid.
#[derive(Debug, Clone, Copy)]
pub struct GridCase {
    /// Stable identifier.
    pub id: &'static str,
    /// The requirement the case pins.
    pub covers: &'static str,
    /// Grid columns.
    pub cols: u32,
    /// Grid rows.
    pub rows: u32,
    /// The bytes fed to the engine.
    pub input: &'static [u8],
}

/// A control sequence whose prelude passes the retention bound.
///
/// The parser keeps its framing state and the span length and stops retaining bytes, so a stream of
/// digits after `CSI` cannot make it allocate.
pub const OVERSIZED_PRELUDE: &[u8] = b"\x1b[\
1111111111111111111111111111111111111111111111111111111111111111\
1111111111111111111111111111111111111111111111111111111111111111\
1111111111111111111111111111111111111111111111111111111111111111\
1111111111111111111111111111111111111111111111111111111111111111m";

/// The class-table cases, in the order of the rows in section 8.
pub const CLASS_CASES: &[Case] = &[
    Case { id: "text_ascii", covers: "KR-REQ-08.16 row text", input: b"hello" },
    Case { id: "text_cjk", covers: "KR-REQ-08.16 row text", input: "\u{4e2d}\u{6587}".as_bytes() },
    Case { id: "c0_display", covers: "KR-REQ-08.16 row BS HT LF VT FF CR", input: b"a\x08\x09\x0b\x0c\x0d" },
    Case { id: "c0_nul_del", covers: "KR-REQ-08.16 named C0 exceptions", input: b"a\x00\x7f" },
    Case { id: "c0_unclassified", covers: "KR-REQ-08.37 unknown control", input: b"\x01\x16" },
    Case { id: "bel", covers: "KR-REQ-08.17 row BEL", input: b"\x07" },
    Case { id: "enq", covers: "KR-REQ-08.21 answerback withheld", input: b"\x05" },
    Case { id: "ris", covers: "KR-REQ-08.18 row RIS", input: b"\x1bc" },
    Case { id: "decstr", covers: "KR-REQ-08.18 row DECSTR", input: b"\x1b[!p" },
    Case { id: "keypad", covers: "KR-REQ-08.18 row DECKPAM DECKPNM", input: b"\x1b=\x1b>" },
    Case { id: "tabs", covers: "KR-REQ-08.18 row HTS TBC", input: b"\x1bH\x1b[3g" },
    Case { id: "ansi_modes", covers: "KR-REQ-08.19 row SM RM 4 and 20", input: b"\x1b[4h\x1b[4l\x1b[20h" },
    Case { id: "dec_modes_tracked", covers: "KR-REQ-08.19 row DEC modes", input: b"\x1b[?1h\x1b[?5h\x1b[?6h\x1b[?7l\x1b[?8h\x1b[?12l\x1b[?25l\x1b[?45h\x1b[?66h\x1b[?67h\x1b[?69h" },
    Case { id: "dec_modes_mouse", covers: "KR-REQ-08.19 row DEC mouse modes", input: b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1004h\x1b[?1005h\x1b[?1006h\x1b[?1007h" },
    Case { id: "dec_modes_buffers", covers: "KR-REQ-08.19 row buffer switches", input: b"\x1b[?1047h\x1b[?1048h\x1b[?1049h\x1b[?1049l" },
    Case { id: "dec_modes_input", covers: "KR-REQ-08.19 row bracketed paste and meta", input: b"\x1b[?2004h\x1b[?2026h\x1b[?1034h" },
    Case { id: "deccolm_set", covers: "KR-REQ-08.20 row DEC mode 3", input: b"\x1b[?3h" },
    Case { id: "deccolm_reset", covers: "KR-REQ-08.20 row DEC mode 3", input: b"\x1b[?3l" },
    Case { id: "window_resize_request", covers: "KR-REQ-08.20 row CSI t resize", input: b"\x1b[8;24;80t" },
    Case { id: "window_maximise", covers: "KR-REQ-08.20 row CSI t resize", input: b"\x1b[9;1t" },
    Case { id: "da1", covers: "KR-ACC-001 KR-REQ-08.21 row DA1", input: b"\x1b[c" },
    Case { id: "da1_zero", covers: "KR-ACC-001 KR-REQ-08.21 row DA1", input: b"\x1b[0c" },
    Case { id: "da2", covers: "KR-REQ-08.21 row DA2", input: b"\x1b[>c" },
    Case { id: "da3", covers: "KR-REQ-08.21 row DA3", input: b"\x1b[=c" },
    Case { id: "decid", covers: "KR-REQ-08.21 row DA1", input: b"\x1bZ" },
    Case { id: "dsr_status", covers: "KR-REQ-08.21 row DSR", input: b"\x1b[5n" },
    Case { id: "cpr", covers: "KR-REQ-08.21 row CPR", input: b"\x1b[6n" },
    Case { id: "decxcpr", covers: "KR-REQ-08.21 row CPR", input: b"\x1b[?6n" },
    Case { id: "dsr_printer", covers: "KR-REQ-08.21 row DSR", input: b"\x1b[?15n" },
    Case { id: "decrqm_ansi", covers: "KR-REQ-08.21 row DECRQM", input: b"\x1b[4$p" },
    Case { id: "decrqm_dec", covers: "KR-REQ-08.21 row DECRQM", input: b"\x1b[?7$p" },
    Case { id: "decrqss_sgr", covers: "KR-REQ-08.35 row DECRQSS", input: b"\x1bP$qm\x1b\\" },
    Case { id: "decrqss_unknown", covers: "KR-REQ-08.35 row DECRQSS", input: b"\x1bP$qZZ\x1b\\" },
    Case { id: "modify_other_keys_set", covers: "KR-REQ-08.22 row modifyOtherKeys", input: b"\x1b[>4;2m" },
    Case { id: "modify_other_keys_query", covers: "KR-REQ-08.22 row modifyOtherKeys", input: b"\x1b[?4m" },
    Case { id: "kitty_push", covers: "KR-REQ-08.22 row Kitty keyboard", input: b"\x1b[>1u" },
    Case { id: "kitty_set", covers: "KR-REQ-08.22 row Kitty keyboard", input: b"\x1b[=5;1u" },
    Case { id: "kitty_pop", covers: "KR-REQ-08.22 row Kitty keyboard", input: b"\x1b[<1u" },
    Case { id: "kitty_query", covers: "KR-REQ-08.22 row Kitty keyboard", input: b"\x1b[?u" },
    Case { id: "mode_2027_set", covers: "KR-REQ-08.23 row DEC mode 2027", input: b"\x1b[?2027h" },
    Case { id: "mode_2027_query", covers: "KR-REQ-08.23 row DEC mode 2027", input: b"\x1b[?2027$p" },
    Case { id: "mode_2048_set", covers: "KR-REQ-08.24 row DEC mode 2048", input: b"\x1b[?2048h" },
    Case { id: "mode_2048_query", covers: "KR-REQ-08.24 row DEC mode 2048", input: b"\x1b[?2048$p" },
    Case { id: "xtversion", covers: "KR-REQ-08.25 row XTVERSION", input: b"\x1b[>q" },
    Case { id: "mode_9001_set", covers: "KR-REQ-08.26 row DEC mode 9001", input: b"\x1b[?9001h" },
    Case { id: "mode_9001_query", covers: "KR-REQ-08.26 row DEC mode 9001", input: b"\x1b[?9001$p" },
    Case { id: "title_set", covers: "KR-REQ-08.27 row OSC 0 1 2", input: b"\x1b]0;first\x07\x1b]2;second\x1b\\" },
    Case { id: "title_stack", covers: "KR-REQ-08.27 row CSI 22 23 t", input: b"\x1b]2;one\x07\x1b[22t\x1b]2;two\x07\x1b[23t" },
    Case { id: "title_stack_underflow", covers: "KR-REQ-08.27 virtualised stack", input: b"\x1b[23t\x1b[23t\x1b[23t" },
    Case { id: "osc7_cwd", covers: "KR-REQ-08.28 row OSC 7", input: b"\x1b]7;file://host/tmp\x1b\\" },
    Case { id: "osc8_hyperlink", covers: "KR-ACC-002 KR-REQ-08.29 row OSC 8", input: b"\x1b]8;;https://example.invalid/\x1b\\link\x1b]8;;\x1b\\" },
    Case { id: "palette_set", covers: "KR-REQ-08.30 row OSC 4", input: b"\x1b]4;1;rgb:ff/00/00\x1b\\" },
    Case { id: "palette_query", covers: "KR-REQ-08.30 row OSC 4", input: b"\x1b]4;1;?\x1b\\" },
    Case { id: "dynamic_colour_set", covers: "KR-REQ-08.30 row OSC 10-19", input: b"\x1b]11;#102030\x1b\\" },
    Case { id: "dynamic_colour_query", covers: "KR-REQ-08.30 row OSC 10-19", input: b"\x1b]11;?\x1b\\" },
    Case { id: "palette_reset", covers: "KR-REQ-08.30 row OSC 104-119", input: b"\x1b]104\x1b\\\x1b]110\x1b\\" },
    Case { id: "osc9_notification", covers: "KR-REQ-08.31 row OSC 9", input: b"\x1b]9;build finished\x1b\\" },
    Case { id: "osc9_progress", covers: "KR-REQ-08.31 row OSC 9", input: b"\x1b]9;4;1;40\x1b\\" },
    Case { id: "osc99_notification", covers: "KR-REQ-08.31 row OSC 99", input: b"\x1b]99;i=1:d=0;body\x1b\\" },
    Case { id: "osc777_notification", covers: "KR-REQ-08.31 row OSC 777", input: b"\x1b]777;notify;title;body\x1b\\" },
    Case { id: "osc777_unknown", covers: "KR-REQ-08.31 unknown subcommand", input: b"\x1b]777;precmd\x1b\\" },
    Case { id: "osc52_write", covers: "KR-ACC-024 KR-REQ-08.32 row OSC 52", input: b"\x1b]52;c;c2VjcmV0\x1b\\" },
    Case { id: "osc52_read", covers: "KR-REQ-08.32 row OSC 52", input: b"\x1b]52;c;?\x1b\\" },
    Case { id: "osc133_prompt", covers: "KR-REQ-08.33 row OSC 133", input: b"\x1b]133;A\x1b\\\x1b]133;B\x1b\\" },
    Case { id: "osc133_unknown", covers: "KR-REQ-08.33 unknown extension", input: b"\x1b]133;Z;anything\x1b\\" },
    Case { id: "osc633_shell", covers: "KR-REQ-08.33 row OSC 633", input: b"\x1b]633;A\x1b\\\x1b]633;E;ls -l\x1b\\" },
    Case { id: "osc633_unknown", covers: "KR-REQ-08.33 unknown extension", input: b"\x1b]633;Zork\x1b\\" },
    Case { id: "osc1337_metadata", covers: "KR-REQ-08.34 row OSC 1337", input: b"\x1b]1337;CurrentDir=/tmp\x1b\\\x1b]1337;SetMark\x1b\\" },
    Case { id: "osc1337_file", covers: "KR-REQ-08.34 file subcommand", input: b"\x1b]1337;File=name=YQ==:AAAA\x1b\\" },
    Case { id: "xtgettcap_known", covers: "KR-REQ-08.35 row XTGETTCAP", input: b"\x1bP+q544e\x1b\\" },
    Case { id: "xtgettcap_unknown", covers: "KR-REQ-08.35 row XTGETTCAP", input: b"\x1bP+q7a7a7a\x1b\\" },
    Case { id: "sixel", covers: "KR-REQ-08.36 row sixel", input: b"\x1bP0;0;0q#0;2;0;0;0#0~~@@vv@@~~@@~~$\x1b\\" },
    Case { id: "kitty_graphics", covers: "KR-REQ-08.36 row APC Kitty graphics", input: b"\x1b_Gf=24,s=1,v=1,a=T;AAAA\x1b\\" },
    Case { id: "privacy_message", covers: "KR-REQ-08.37 row other strings", input: b"\x1b^private\x1b\\" },
    Case { id: "unknown_osc", covers: "KR-REQ-08.37 row other OSC", input: b"\x1b]6666;x\x1b\\" },
    Case { id: "unknown_csi_final", covers: "KR-REQ-08.37 unknown CSI final", input: b"\x1b[1~" },
    Case { id: "unknown_esc", covers: "KR-REQ-08.37 unknown ESC", input: b"\x1bV" },
    Case { id: "unknown_dec_mode", covers: "KR-REQ-08.37 unknown DEC mode", input: b"\x1b[?77h" },
    Case { id: "cursor_shape", covers: "KR-REQ-08.16 row DECSCUSR", input: b"\x1b[4 q" },
    Case { id: "selective_erase_attribute", covers: "KR-REQ-08.16 row DECSCA", input: b"\x1b[1\"q" },
    Case { id: "charsets", covers: "KR-REQ-08.16 row DEC character sets", input: b"\x1b(0lqk\x1b(B" },
    Case { id: "cursor_and_erase", covers: "KR-REQ-08.16 row cursor and erasure", input: b"\x1b[2J\x1b[H\x1b[5A\x1b[3C\x1b[K\x1b[2L\x1b[1M\x1b[4X" },
    Case { id: "scrolling_and_sgr", covers: "KR-REQ-08.16 row scrolling and SGR", input: b"\x1b[2S\x1b[1T\x1b[1;31;48;5;20m" },
    Case { id: "saved_cursor_and_margins", covers: "KR-REQ-08.16 row saved cursors and margins", input: b"\x1b7\x1b[2;20r\x1b[?69h\x1b[3;40s\x1b8" },
    Case { id: "tmux_passthrough", covers: "KR-REQ-08.12 tmux passthrough", input: b"\x1bPtmux;\x1b\x1b[31mred\x1b\\" },
    Case { id: "dec_mode_colon_sublist", covers: "KR-REQ-08.20 malformed mode parameters", input: b"\x1b[?3:7h" },
    Case { id: "dec_mode_mixed_with_9001", covers: "KR-REQ-08.26 combined mode request", input: b"\x1b[?9001;1049h" },
    Case { id: "modify_other_keys_unknown_resource", covers: "KR-REQ-08.22 unqualified resource", input: b"\x1b[>2;1m" },
    Case { id: "kitty_unqualified_flags", covers: "KR-REQ-08.22 unqualified flags", input: b"\x1b[>16u" },
    Case { id: "tab_clear_unsupported", covers: "KR-REQ-08.18 unsupported TBC variant", input: b"\x1b[2g" },
    Case { id: "charset_g2_designation", covers: "KR-REQ-08.16 unsupported designation", input: b"\x1b*0" },
    Case { id: "esc_extra_intermediates", covers: "KR-REQ-08.16 extra intermediates", input: b"\x1b($B" },
    Case { id: "title_with_semicolons", covers: "KR-REQ-08.27 title payload", input: b"\x1b]2;one;two;three\x07" },
    Case { id: "palette_mixed_operations", covers: "KR-REQ-08.30 mixed colour request", input: b"\x1b]4;1;#ff0000;2;?\x1b\\" },
    Case { id: "dynamic_colour_list", covers: "KR-REQ-08.30 dynamic colour list", input: b"\x1b]10;#112233;#445566\x1b\\" },
    Case { id: "tektronix_colour", covers: "KR-REQ-08.30 unqualified colour selector", input: b"\x1b]15;?\x1b\\" },
    Case { id: "osc9_unknown_subcommand", covers: "KR-REQ-08.31 unknown subcommand", input: b"\x1b]9;7;x\x1b\\" },
    Case { id: "osc133_unknown_property", covers: "KR-REQ-08.33 unknown property", input: b"\x1b]133;P;Secret=1\x1b\\" },
];

/// The byte-policy and fuzzing cases named by KR-ACC-024.
pub const BYTE_POLICY_CASES: &[Case] = &[
    Case {
        id: "raw_c1_csi",
        covers: "KR-ACC-024 KR-REQ-08.46 raw C1 introducer",
        input: b"\x9b31m",
    },
    Case {
        id: "raw_c1_osc",
        covers: "KR-ACC-024 KR-REQ-08.46 raw C1 introducer",
        input: b"\x9d2;title\x07",
    },
    Case {
        id: "raw_c1_index",
        covers: "KR-ACC-024 KR-REQ-08.46 raw C1 control",
        input: b"\x84",
    },
    Case {
        id: "raw_c1_unassigned",
        covers: "KR-ACC-024 KR-REQ-08.46 unassigned C1",
        input: b"\x91\x99",
    },
    Case {
        id: "raw_c1_stray_st",
        covers: "KR-ACC-024 KR-REQ-08.46 stray ST",
        input: b"\x9c",
    },
    Case {
        id: "encoded_c1_scalar",
        covers: "KR-ACC-024 KR-REQ-08.45 encoded C1 scalar",
        input: b"\xc2\x9b31m",
    },
    Case {
        id: "overlong_two_byte",
        covers: "KR-ACC-024 KR-REQ-08.45 overlong",
        input: b"\xc0\xaf",
    },
    Case {
        id: "overlong_three_byte",
        covers: "KR-ACC-024 KR-REQ-08.45 overlong",
        input: b"\xe0\x80\xaf",
    },
    Case {
        id: "surrogate",
        covers: "KR-ACC-024 KR-REQ-08.45 surrogate",
        input: b"\xed\xa0\x80",
    },
    Case {
        id: "out_of_range",
        covers: "KR-ACC-024 KR-REQ-08.45 out of range",
        input: b"\xf4\x90\x80\x80",
    },
    Case {
        id: "invalid_lead",
        covers: "KR-ACC-024 KR-REQ-08.45 invalid lead",
        input: b"\xf8\xff",
    },
    Case {
        id: "isolated_continuation",
        covers: "KR-ACC-024 KR-REQ-08.45 isolated continuation",
        input: b"a\xa9b",
    },
    Case {
        id: "truncated_scalar",
        covers: "KR-ACC-024 KR-REQ-08.45 truncated scalar",
        input: b"\xe2\x82A",
    },
    Case {
        id: "continuation_not_c1",
        covers: "KR-ACC-024 KR-REQ-08.45 continuation inside a scalar",
        input: "\u{00dc}".as_bytes(),
    },
    Case {
        id: "st_inside_title",
        covers: "KR-ACC-024 raw 0x9C is not a terminator",
        input: b"\x1b]2;\xc3\x9cber\x1b\\",
    },
    Case {
        id: "csi_aborted_by_esc",
        covers: "KR-ACC-024 abandoned sequence",
        input: b"\x1b[1;2\x1b[31m",
    },
    Case {
        id: "osc_aborted_by_can",
        covers: "KR-ACC-024 cancelled string",
        input: b"\x1b]2;part\x18rest",
    },
    Case {
        id: "csi_ignored_prelude",
        covers: "KR-ACC-024 ill-formed prelude",
        input: b"\x1b[ 1m",
    },
    Case {
        id: "passthrough_depth_two",
        covers: "KR-ACC-024 nested passthrough",
        input: b"\x1bPtmux;\x1b\x1bPtmux;\x1b\x1b\x1b\x1b[31m\x1b\x1b\\\x1b\\",
    },
    Case {
        id: "title_payload_with_raw_c1",
        covers: "KR-ACC-024 raw C1 inside a payload",
        input: b"\x1b]2;x\x9c\x9b6n\x07",
    },
    Case {
        id: "title_payload_with_c0",
        covers: "KR-ACC-024 control scalar inside a payload",
        input: b"\x1b]2;x\x0cy\x07",
    },
    Case {
        id: "escape_doubling_outside_tmux",
        covers: "KR-ACC-024 escape doubling is tmux only",
        input: b"\x1b]2;x\x1b\x1b]52;c;c2VjcmV0\x07",
    },
    Case {
        id: "c0_inside_control_sequence",
        covers: "KR-ACC-024 embedded control byte",
        input: b"\x1b[5\x00;3H",
    },
    Case {
        id: "oversized_sequence_prelude",
        covers: "KR-ACC-024 bounded retention",
        input: OVERSIZED_PRELUDE,
    },
];

/// The cases that prove the query broker is the only responder.
pub const BROKER_CASES: &[Case] = &[
    Case {
        id: "da1",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[c",
    },
    Case {
        id: "da2",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[>c",
    },
    Case {
        id: "da3",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[=c",
    },
    Case {
        id: "dsr_status",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[5n",
    },
    Case {
        id: "cpr_after_output",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[3;7Hxy\x1b[6n",
    },
    Case {
        id: "decxcpr",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[6;2H\x1b[?6n",
    },
    Case {
        id: "decrqm_autowrap",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[?7$p",
    },
    Case {
        id: "decrqm_after_reset",
        covers: "KR-ACC-001 KR-REQ-08.05",
        input: b"\x1b[?7l\x1b[?7$p",
    },
    Case {
        id: "decrqm_grapheme",
        covers: "KR-REQ-08.23",
        input: b"\x1b[?2027$p",
    },
    Case {
        id: "decrqm_inband_resize",
        covers: "KR-REQ-08.24",
        input: b"\x1b[?2048$p",
    },
    Case {
        id: "decrqm_deccolm",
        covers: "KR-REQ-08.20",
        input: b"\x1b[?3$p",
    },
    Case {
        id: "geometry_text_area",
        covers: "KR-REQ-08.21 CSI 18 t",
        input: b"\x1b[18t",
    },
    Case {
        id: "geometry_screen",
        covers: "KR-REQ-08.21 CSI 19 t",
        input: b"\x1b[19t",
    },
    Case {
        id: "geometry_pixels",
        covers: "KR-REQ-08.21 CSI 14 t",
        input: b"\x1b[14t",
    },
    Case {
        id: "window_state",
        covers: "KR-REQ-08.21 CSI 11 t",
        input: b"\x1b[11t",
    },
    Case {
        id: "decrqss_sgr_plain",
        covers: "KR-REQ-08.35",
        input: b"\x1bP$qm\x1b\\",
    },
    Case {
        id: "decrqss_sgr_after_attributes",
        covers: "KR-REQ-08.35",
        input: b"\x1b[1;4;31mx\x1bP$qm\x1b\\",
    },
    Case {
        id: "decrqss_margins",
        covers: "KR-REQ-08.35",
        input: b"\x1b[3;12r\x1bP$qr\x1b\\",
    },
    Case {
        id: "decrqss_cursor_style",
        covers: "KR-REQ-08.35",
        input: b"\x1b[4 q\x1bP$q q\x1b\\",
    },
    Case {
        id: "decrqss_conformance_level",
        covers: "KR-REQ-08.35",
        input: b"\x1bP$q\"p\x1b\\",
    },
    Case {
        id: "xtgettcap_name",
        covers: "KR-REQ-08.35 TN",
        input: b"\x1bP+q544e\x1b\\",
    },
    Case {
        id: "xtgettcap_colors",
        covers: "KR-REQ-08.35 colors",
        input: b"\x1bP+q636f6c6f7273\x1b\\",
    },
    Case {
        id: "xtgettcap_multiple",
        covers: "KR-REQ-08.35 several names",
        input: b"\x1bP+q544e;5463;7a7a\x1b\\",
    },
    Case {
        id: "colour_index_query",
        covers: "KR-REQ-08.30",
        input: b"\x1b]4;2;?\x1b\\",
    },
    Case {
        id: "colour_index_after_change",
        covers: "KR-REQ-08.30",
        input: b"\x1b]4;2;rgb:12/34/56\x1b\\\x1b]4;2;?\x1b\\",
    },
    Case {
        id: "foreground_query",
        covers: "KR-REQ-08.30",
        input: b"\x1b]10;?\x07",
    },
    Case {
        id: "background_query",
        covers: "KR-REQ-08.30",
        input: b"\x1b]11;?\x1b\\",
    },
    Case {
        id: "xtversion",
        covers: "KR-REQ-08.25",
        input: b"\x1b[>0q",
    },
    Case {
        id: "kitty_keyboard_query",
        covers: "KR-REQ-08.22",
        input: b"\x1b[>5u\x1b[?u",
    },
    Case {
        id: "modify_other_keys_query",
        covers: "KR-REQ-08.22",
        input: b"\x1b[>4;2m\x1b[?4m",
    },
    Case {
        id: "clipboard_read_default",
        covers: "KR-REQ-08.32",
        input: b"\x1b]52;c;?\x1b\\",
    },
    Case {
        id: "cpr_under_origin_mode",
        covers: "KR-ACC-001 KR-REQ-08.21",
        input: b"\x1b[3;12r\x1b[?6h\x1b[H\x1b[6n",
    },
    Case {
        id: "xtgettcap_unprintable_name",
        covers: "KR-REQ-08.35 bounded failure reply",
        input: b"\x1bP+q0d0a41424321\x1b\\",
    },
];

/// The width-model cases section 8 names for direct qualification.
pub const WIDTH_CASES: &[GridCase] = &[
    GridCase {
        id: "cjk_pair",
        covers: "KR-REQ-08.39 CJK width",
        cols: 10,
        rows: 3,
        input: "\u{4e2d}\u{6587}ab".as_bytes(),
    },
    GridCase {
        id: "cjk_at_right_margin",
        covers: "KR-REQ-08.39 wide cell at the margin",
        cols: 5,
        rows: 3,
        input: "abcd\u{4e2d}e".as_bytes(),
    },
    GridCase {
        id: "combining_marks",
        covers: "KR-REQ-08.39 combining marks add no cells",
        cols: 10,
        rows: 3,
        input: "e\u{0301}a\u{0308}\u{0323}z".as_bytes(),
    },
    GridCase {
        id: "ambiguous_is_narrow",
        covers: "KR-REQ-08.39 ambiguous characters are one cell",
        cols: 10,
        rows: 3,
        input: "\u{00b1}\u{2018}\u{2019}x".as_bytes(),
    },
    GridCase {
        id: "emoji_then_ascii_left_margin",
        covers: "KR-REQ-08.39 emoji followed by ASCII",
        cols: 10,
        rows: 3,
        input: "\u{1f469}\u{200d}\u{1f4bb}AB".as_bytes(),
    },
    GridCase {
        id: "emoji_then_ascii_right_margin",
        covers: "KR-REQ-08.39 emoji at the right margin",
        cols: 6,
        rows: 3,
        input: "abcd\u{1f469}\u{200d}\u{1f4bb}E".as_bytes(),
    },
    GridCase {
        id: "delayed_wrap",
        covers: "KR-REQ-08.39 delayed wrap",
        cols: 5,
        rows: 3,
        input: b"abcdeX",
    },
    GridCase {
        id: "delayed_wrap_then_cr",
        covers: "KR-REQ-08.39 delayed wrap cancelled",
        cols: 5,
        rows: 3,
        input: b"abcde\rZ",
    },
    GridCase {
        id: "bottom_row_scrolling",
        covers: "KR-REQ-08.39 bottom-row scrolling",
        cols: 5,
        rows: 3,
        input: b"one\r\ntwo\r\nthree\r\nfour",
    },
    GridCase {
        id: "autowrap_disabled",
        covers: "KR-REQ-08.39 autowrap off",
        cols: 5,
        rows: 3,
        input: b"\x1b[?7labcdefgh",
    },
    GridCase {
        id: "emoji_modifier",
        covers: "KR-REQ-08.39 an emoji modifier is its own cell",
        cols: 10,
        rows: 3,
        input: "\u{1f44d}\u{1f3fb}X".as_bytes(),
    },
    GridCase {
        id: "regional_indicators",
        covers: "KR-REQ-08.39 a regional-indicator pair is two cells",
        cols: 10,
        rows: 3,
        input: "\u{1f1ff}\u{1f1e6}X".as_bytes(),
    },
    GridCase {
        id: "keycap_sequence",
        covers: "KR-REQ-08.39 a keycap sequence is one cell",
        cols: 10,
        rows: 3,
        input: "1\u{fe0f}\u{20e3}X".as_bytes(),
    },
    GridCase {
        id: "combining_mark_at_the_right_margin",
        covers: "KR-REQ-08.39 a mark joins the cell in the last column",
        cols: 5,
        rows: 3,
        input: "abcde\u{0301}f".as_bytes(),
    },
];

/// The snapshot cases section 27 names: mid-output and at an alternate-screen transition.
pub const SNAPSHOT_CASES: &[GridCase] = &[
    GridCase {
        id: "mid_output",
        covers: "KR-REQ-08.40 snapshot mid-output",
        cols: 12,
        rows: 4,
        input: b"line one\r\nline two\r\npart",
    },
    GridCase {
        id: "alternate_entry",
        covers: "KR-REQ-08.40 alternate-screen transition",
        cols: 12,
        rows: 4,
        input: b"primary\r\n\x1b[?1049h\x1b[2J\x1b[Halternate",
    },
    GridCase {
        id: "alternate_exit",
        covers: "KR-REQ-08.40 alternate-screen transition",
        cols: 12,
        rows: 4,
        input: b"primary\r\n\x1b[?1049halt\x1b[?1049l",
    },
    GridCase {
        id: "hyperlink_rows",
        covers: "KR-ACC-002 hyperlink ranges survive",
        cols: 24,
        rows: 3,
        input: b"see \x1b]8;;https://example.invalid/\x1b\\here\x1b]8;;\x1b\\ now",
    },
    GridCase {
        id: "mid_escape_sequence",
        covers: "KR-REQ-08.40 parser-ground boundary",
        cols: 12,
        rows: 4,
        input: b"text\x1b[1;3",
    },
    GridCase {
        id: "soft_reset_from_alternate",
        covers: "KR-REQ-08.18 DECSTR returns the primary screen",
        cols: 12,
        rows: 4,
        input: b"primary\r\n\x1b[?1049halt\x1b[!p",
    },
    GridCase {
        id: "alternate_holds_primary_content",
        covers: "KR-REQ-08.40 both buffers are restored",
        cols: 12,
        rows: 3,
        // A shell leaves three rows behind, a full-screen application takes the alternate buffer
        // and draws over it. The snapshot carries what the application is showing and what the
        // shell left, so leaving the application puts the session back where it was.
        input: b"one\r\ntwo\r\nthree\r\n\x1b[?1049h\x1b[2J\x1b[Hediting",
    },
    GridCase {
        id: "saved_cursors_both_buffers",
        covers: "KR-REQ-08.40 saved cursors of both buffers",
        cols: 12,
        rows: 3,
        // A save in each buffer, with a different rendition and a different G1 designation, so a
        // restoration that carried only positions would be visibly wrong.
        input: b"\x1b)0\x1b[1;31m\x1b[2;4H\x1b7\x1b[?1047h\x1b)B\x1b[42m\x1b[3;2H\x1b7",
    },
    GridCase {
        id: "pending_wrap_at_margin",
        covers: "KR-REQ-08.40 pending wrap",
        cols: 4,
        rows: 3,
        // The cursor sits in the final column with the wrap deferred: the same coordinates as a
        // row with space left, and the next character goes somewhere else.
        input: b"abcd",
    },
    GridCase {
        id: "scrollback_keeps_columns",
        covers: "KR-REQ-08.39 a scrolled row keeps its columns",
        cols: 8,
        rows: 2,
        // An emoji sequence and a Hangul syllable built from jamo, each of which the library's own
        // clustering would fold into one cell, scrolled off the screen so the row is compacted.
        input: "\u{1f469}\u{200d}\u{1f4bb}\u{1100}\u{1161}\r\nb\r\nc".as_bytes(),
    },
];

/// Records the rows of one buffer.
fn row_values(rows: &[crate::grid::GridRow]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            json!({
                "stable_id": row.stable_id,
                "soft_wrapped": row.soft_wrapped,
                "text": row.runs.iter().map(|run| run.text.as_str()).collect::<String>(),
                "cells": row.runs.iter().map(|run| run.cells).sum::<u32>(),
            })
        })
        .collect()
}

/// Records one saved cursor, including the rendition and the character sets saved with it.
fn saved_cursor_value(saved: &crate::snapshot::SavedCursor) -> Value {
    json!({
        "buffer": format!("{:?}", saved.buffer),
        "col": saved.col,
        "row": saved.row,
        "pending_wrap": saved.pending_wrap,
        "origin_mode": saved.origin_mode,
        "style": saved.style,
        "charsets": {
            "g0": saved.charsets.g0,
            "g1": saved.charsets.g1,
            "shift_out": saved.charsets.shift_out,
        },
        "hyperlink": saved.hyperlink,
        "rendition": {
            "foreground": format!("{:?}", saved.rendition.foreground),
            "background": format!("{:?}", saved.rendition.background),
            "bold": saved.rendition.bold,
            "italic": saved.rendition.italic,
            "underline": format!("{:?}", saved.rendition.underline),
            "reverse": saved.rendition.reverse,
        },
    })
}

/// Runs one case through a fresh engine and records what happened.
#[must_use]
pub fn summarise(case: &Case) -> Value {
    summarise_with(case.input, GridSize::new(80, 24))
}

/// Runs bytes through a fresh engine of `size` and records what happened.
#[must_use]
pub fn summarise_with(input: &[u8], size: GridSize) -> Value {
    let mut engine = Engine::new(EngineConfig {
        size,
        ..EngineConfig::DEFAULT
    })
    .unwrap_or_else(|error| panic!("engine: {error}"));
    engine.set_lease_holder(LeaseHolder::none());

    let mut lexer = crate::lexer::Lexer::new();
    let mut events = Vec::new();
    lexer.feed(input, &mut events);
    lexer.close(&mut events);

    let outcome = engine.feed(input, 0);
    let closing = engine.close(0);
    let responses = engine.lane_mut().drain(LaneGate::default(), 1 << 20, 0);

    let event_values: Vec<Value> = events.iter().map(event_value).collect();
    let forward: Vec<Value> = outcome
        .forward
        .iter()
        .chain(closing.forward.iter())
        .map(|span| json!([span.start(), span.end()]))
        .collect();
    let side_effects: Vec<Value> = outcome
        .side_effects
        .iter()
        .chain(closing.side_effects.iter())
        .map(|effect| {
            json!({
                "kind": side_effect_name(&effect.kind),
                "destination": match effect.destination {
                    SideEffectDestination::Attachment { .. } => "attachment",
                    SideEffectDestination::HostEvent => "host-event",
                },
                "at": effect.at,
            })
        })
        .collect();
    let diagnostics: Vec<Value> = outcome
        .diagnostics
        .iter()
        .chain(closing.diagnostics.iter())
        .map(|diagnostic| json!({ "kind": diagnostic.kind.id(), "at": diagnostic.at }))
        .collect();
    let refusals: Vec<Value> = outcome
        .refusals
        .iter()
        .chain(closing.refusals.iter())
        .map(|refusal| json!(format!("{refusal:?}")))
        .collect();

    json!({
        "input": hex(input),
        "events": event_values,
        "forward": forward,
        "projection_required_at": outcome.projection_required_at,
        "responses": responses.iter().map(|r| hex(r.bytes())).collect::<Vec<_>>(),
        "side_effects": side_effects,
        "refusals": refusals,
        "diagnostics": diagnostics,
        "grid_writes": engine.grid().writer_log().bytes,
        "grid_unrecognised": engine.grid().unrecognised(),
        "ground_after": engine.at_ground(),
    })
}

/// Runs a grid case and records the resulting screen.
#[must_use]
pub fn summarise_grid(case: &GridCase) -> Value {
    let mut engine = Engine::new(EngineConfig {
        size: GridSize::new(case.cols, case.rows),
        ..EngineConfig::DEFAULT
    })
    .unwrap_or_else(|error| panic!("engine: {error}"));
    engine.feed(case.input, 0);
    let viewport = crate::snapshot::Viewport {
        top_row: 0,
        rows: case.rows,
        left_col: 0,
        cols: case.cols,
    };
    let (snapshot, _) = engine.snapshot(viewport, 0);
    let rows = row_values(&snapshot.rows);
    let inactive = row_values(&snapshot.inactive_rows);
    // The rows above the screen, so a case can show that a row keeps its columns after it has
    // scrolled and the grid has compacted it.
    let newest = snapshot.rows.first().map_or(0, |row| row.stable_id);
    let history = usize::try_from(newest - snapshot.oldest_retained_row).unwrap_or(0);
    let history = row_values(
        &engine
            .grid()
            .history_rows(snapshot.oldest_retained_row, history),
    );
    json!({
        "input": hex(case.input),
        "cols": case.cols,
        "rows": case.rows,
        "active_buffer": format!("{:?}", snapshot.active_buffer),
        "projection_generation": snapshot.projection_generation,
        "output_cursor": snapshot.output_cursor,
        "cursor": json!({
            "col": snapshot.cursor.col,
            "row": snapshot.cursor.row,
            "visible": snapshot.cursor.visible,
            "pending_wrap": snapshot.cursor.pending_wrap,
        }),
        "saved_cursors": snapshot
            .saved_cursors
            .iter()
            .map(|saved| saved.as_ref().map_or(Value::Null, saved_cursor_value))
            .collect::<Vec<_>>(),
        "screen": rows,
        "inactive_screen": inactive,
        "history": history,
        "hyperlinks": snapshot.hyperlinks.iter().map(|link| json!({
            "row": link.row,
            "start_col": link.start_col,
            "end_col": link.end_col,
            "uri": link.uri,
        })).collect::<Vec<_>>(),
        "grid_writes": engine.grid().writer_log().bytes,
        "grid_unrecognised": engine.grid().unrecognised(),
        "at_ground": engine.at_ground(),
    })
}

fn event_value(event: &Event) -> Value {
    json!({
        "kind": kind_name(&event.kind),
        "class": event.class.letter().to_string(),
        "disposition": format!("{:?}", event.disposition),
        "span": [event.span.start(), event.span.end()],
        "bytes": hex(event.raw()),
        "ground_after": event.ground_after,
        "passthrough_depth": event.passthrough_depth,
        "eight_bit": event.eight_bit_introducer,
    })
}

/// The stable name of an event kind, used in fixtures.
#[must_use]
pub fn kind_name(kind: &EventKind) -> String {
    match kind {
        EventKind::Text { .. } => "text".to_owned(),
        EventKind::Replacement { cause, .. } => format!("replacement:{cause:?}"),
        EventKind::Control { .. } => "control".to_owned(),
        EventKind::Esc { .. } => "esc".to_owned(),
        EventKind::Csi { .. } => "csi".to_owned(),
        EventKind::CsiIgnored { .. } => "csi-ignored".to_owned(),
        EventKind::Osc { .. } => "osc".to_owned(),
        EventKind::Dcs { .. } => "dcs".to_owned(),
        EventKind::OtherString { family, .. } => format!("string:{family:?}"),
        EventKind::Discarded { family, cause, .. } => format!("discarded:{family:?}:{cause:?}"),
    }
}

fn side_effect_name(kind: &SideEffectKind) -> &'static str {
    match kind {
        SideEffectKind::Bell => "bell",
        SideEffectKind::Notification { .. } => "notification",
        SideEffectKind::Progress { .. } => "progress",
        SideEffectKind::ClipboardWrite { .. } => "clipboard-write",
        SideEffectKind::ClipboardRead { .. } => "clipboard-read",
    }
}

/// Lowercase hex, the form every fixture uses for bytes.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Decodes the hex form fixtures use.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "two hex digits are at most 0xff"
        )]
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}
