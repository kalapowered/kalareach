//! Writes the terminal conformance fixtures, or checks that the committed ones are current.
//!
//! Run with no arguments to write `fixtures/terminal/`, and with `--check` to fail when a committed
//! file differs from what the engine produces now. Continuous integration runs the second form, so
//! a change in behaviour has to arrive together with the fixture that records it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kr_term::conformance::{
    ADMISSION_CASES, AdmissionCase, BROKER_CASES, BYTE_POLICY_CASES, CLASS_CASES, Case, GridCase,
    SNAPSHOT_CASES, WIDTH_CASES, hex, summarise, summarise_admission, summarise_grid,
};
use kr_term::profile::{CAPABILITIES, DA1_PARAMS, DA2_PARAMS, WITHHELD};
use kr_term::terminfo;
use kr_term::unicode::{LIBRARY, UnicodeModel};
use serde_json::{Value, json};

fn main() -> ExitCode {
    let check = std::env::args().any(|arg| arg == "--check");
    let root = fixtures_root();
    let files = [
        ("classes.json", classes()),
        ("byte-policy.json", byte_policy()),
        ("broker.json", broker()),
        ("width.json", width()),
        ("snapshot.json", snapshot()),
        ("admission.json", admission()),
        ("profile.json", profile()),
        ("terminfo-xterm-256color.json", terminfo_database()),
    ];
    let mut stale = Vec::new();
    for (name, value) in files {
        let path = root.join(name);
        let rendered = render(&value);
        if check {
            match std::fs::read_to_string(&path) {
                Ok(current) if current == rendered => {}
                Ok(_) => stale.push(format!("{} differs", path.display())),
                Err(error) => stale.push(format!("{}: {error}", path.display())),
            }
        } else if let Err(error) = std::fs::write(&path, &rendered) {
            eprintln!("{}: {error}", path.display());
            return ExitCode::FAILURE;
        }
    }
    if stale.is_empty() {
        if check {
            println!("terminal fixtures are current");
        }
        return ExitCode::SUCCESS;
    }
    for line in &stale {
        eprintln!("{line}");
    }
    eprintln!("run `cargo run -p kr-term --bin kr-term-fixtures` and commit the result");
    ExitCode::FAILURE
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).unwrap_or_default();
    text.push('\n');
    text
}

fn fixtures_root() -> PathBuf {
    // The crate directory is `<workspace>/crates/kr-term`.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
}

fn case_entry(case: &Case) -> Value {
    let mut value = summarise(case);
    if let Some(object) = value.as_object_mut() {
        object.insert("id".to_owned(), json!(case.id));
        object.insert("covers".to_owned(), json!(case.covers));
    }
    value
}

fn grid_entry(case: &GridCase) -> Value {
    let mut value = summarise_grid(case);
    if let Some(object) = value.as_object_mut() {
        object.insert("id".to_owned(), json!(case.id));
        object.insert("covers".to_owned(), json!(case.covers));
    }
    value
}

fn classes() -> Value {
    json!({
        "name": "classes",
        "profile": "kr-vt/1",
        "description": "One case per row of the section 8 sequence-class table. `class` is the \
                        normative letter, `disposition` is what direct mode may do with the \
                        original bytes, and `forward` lists the spans a direct attachment sends \
                        onwards.",
        "cases": CLASS_CASES.iter().map(case_entry).collect::<Vec<_>>(),
    })
}

fn byte_policy() -> Value {
    json!({
        "name": "byte-policy",
        "profile": "kr-vt/1",
        "description": "KR-ACC-024. Raw 8-bit C1, malformed UTF-8, nested tmux passthrough, \
                        oversized control strings and abandoned sequences. No case forwards bytes \
                        a physical terminal could read as an unclassified introducer, and no case \
                        lets a query or a side effect escape.",
        "cases": BYTE_POLICY_CASES.iter().map(case_entry).collect::<Vec<_>>(),
    })
}

fn broker() -> Value {
    json!({
        "name": "broker",
        "profile": "kr-vt/1",
        "description": "KR-ACC-001. Every query and the exact bytes the worker answers with. \
                        `forward` is empty in every case: no query reaches an attached terminal.",
        "cases": BROKER_CASES.iter().map(case_entry).collect::<Vec<_>>(),
    })
}

fn width() -> Value {
    json!({
        "name": "width",
        "profile": "kr-vt/1",
        "unicode": {
            "width_table_generation": UnicodeModel::KR_VT_1.width_table_generation,
            "ambiguous_are_wide": UnicodeModel::KR_VT_1.ambiguous_are_wide,
            "grapheme_clustering": UnicodeModel::KR_VT_1.grapheme_clustering,
            "library_revision": LIBRARY.revision,
        },
        "description": "The pinned width model: CJK, combining marks, ambiguous characters, \
                        multi-codepoint emoji followed by ASCII at both margins, delayed wrap and \
                        bottom-row scrolling.",
        "cases": WIDTH_CASES.iter().map(grid_entry).collect::<Vec<_>>(),
    })
}

fn snapshot() -> Value {
    json!({
        "name": "snapshot",
        "profile": "kr-vt/1",
        "description": "Snapshots taken mid-output and at alternate-screen transitions, with the \
                        hyperlink ranges a reconnection restores as inert metadata.",
        "cases": SNAPSHOT_CASES.iter().map(grid_entry).collect::<Vec<_>>(),
    })
}

fn admission_entry(case: &AdmissionCase) -> Value {
    let mut value = summarise_admission(case);
    if let Some(object) = value.as_object_mut() {
        object.insert("id".to_owned(), json!(case.id));
        object.insert("covers".to_owned(), json!(case.covers));
    }
    value
}

fn admission() -> Value {
    let limits = kr_term::budget::BudgetLimits::DEFAULT;
    let grid = kr_term::grid::GridConfig::DEFAULT;
    json!({
        "name": "admission",
        "profile": "kr-vt/1",
        "description": "Geometry admission against the session budget. A geometry is checked \
                        against the three dimension constraints first, and then against what both \
                        screen buffers can hold at that size. The 262,144-cell maximum is a \
                        dimension bound; the budget decides which of those grids a session can \
                        actually be given.",
        "budget": {
            "session_bytes": limits.session_bytes,
            "row_cache_bytes": limits.row_cache_bytes,
            "cell_slot_bytes": kr_term::budget::CELL_OVERHEAD_BYTES,
            "cell_content_bytes": kr_term::budget::cell_content_bytes(grid.cell_bytes as u64),
            "cell_text_bytes": grid.cell_bytes,
            "cell_attribute_bytes": kr_term::grid::CELL_ATTRIBUTE_BYTES,
            "cell_text_heap_bytes": kr_term::grid::CELL_TEXT_HEAP_BYTES,
            "row_slot_bytes": kr_term::grid::ROW_SLOT_BYTES,
            "scrollback_rows": grid.scrollback_rows,
            "link_envelope_bytes": limits.link_envelope(),
            "title_bytes": kr_term::title::MAX_RESIDENT_BYTES,
            "alert_bytes": kr_term::grid::ALERT_LIST_BYTES,
        },
        "cases": ADMISSION_CASES.iter().map(admission_entry).collect::<Vec<_>>(),
    })
}

fn profile() -> Value {
    json!({
        "name": "profile",
        "profile": "kr-vt/1",
        "description": "What kr-vt/1 advertises, what it refuses, and the exact identity bytes. \
                        Nothing here describes a physical terminal.",
        "term": kr_term::profile::TERM,
        "identity": kr_term::profile::XTVERSION_IDENTITY,
        "device_attributes": {
            "primary": DA1_PARAMS,
            "secondary": DA2_PARAMS,
            "tertiary_unit_id": kr_term::profile::DA3_UNIT_ID,
        },
        "capabilities": CAPABILITIES.iter().map(|c| c.name()).collect::<Vec<_>>(),
        "withheld": WITHHELD.iter().map(|w| json!({
            "feature": w.feature,
            "reason": w.reason,
        })).collect::<Vec<_>>(),
        "tracked_dec_modes": kr_term::classify::TRACKED_DEC_MODES,
        "tracked_ansi_modes": kr_term::classify::TRACKED_ANSI_MODES,
        "limits": {
            "control_string_bytes": kr_term::lexer::LexLimits::DEFAULT.max_control_string,
            "osc52_string_bytes": kr_term::lexer::LexLimits::DEFAULT.max_osc52_string,
            "passthrough_depth": kr_term::lexer::LexLimits::DEFAULT.max_passthrough_depth,
            "response_lane_queue_bytes": kr_term::lane::LaneLimits::DEFAULT.max_queue_bytes,
            "responses_per_second": kr_term::lane::LaneLimits::DEFAULT.responses_per_second,
            "row_cache_bytes": kr_term::budget::BudgetLimits::DEFAULT.row_cache_bytes,
            "session_bytes": kr_term::budget::BudgetLimits::DEFAULT.session_bytes,
            "history_page_rows": kr_term::budget::BudgetLimits::DEFAULT.history_page_rows,
            "history_page_bytes": kr_term::budget::BudgetLimits::DEFAULT.history_page_bytes,
            "max_cols": kr_term::budget::MAX_COLS,
            "max_rows": kr_term::budget::MAX_ROWS,
            "max_cells": kr_term::budget::MAX_CELLS,
        },
        "grid_library": {
            "repository": LIBRARY.repository,
            "revision": LIBRARY.revision,
            "upstream": LIBRARY.upstream,
            "upstream_revision": LIBRARY.upstream_revision,
            "notes": LIBRARY.notes,
            "direct_mode_constraints": LIBRARY.direct_mode_constraints,
            "qualified_additions": LIBRARY.qualified_additions.iter().map(|addition| json!({
                "state": addition.state,
                "reason": addition.reason,
            })).collect::<Vec<_>>(),
            "required_patch": LIBRARY.required_patch.iter().map(|addition| json!({
                "state": addition.state,
                "reason": addition.reason,
            })).collect::<Vec<_>>(),
        },
    })
}

fn terminfo_database() -> Value {
    let coverage: Vec<Value> = terminfo::coverage()
        .into_iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "direction": format!("{:?}", entry.direction).to_lowercase(),
                "expansion": hex(&entry.expansion),
                "classes": entry.classes.iter().map(ToString::to_string).collect::<Vec<_>>(),
                "checked": entry.checked,
                "refused": entry.refused,
                "supported": entry.supported,
            })
        })
        .collect();
    json!({
        "name": "terminfo-xterm-256color",
        "profile": "kr-vt/1",
        "description": "The private, pinned terminfo database the managed environment supplies, \
                        and the class every advertised output capability lands in. A capability \
                        whose sequence would be consumed with a diagnostic is not advertised.",
        "terminal_name": terminfo::TERMINAL_NAME,
        "booleans": terminfo::booleans(),
        "numbers": terminfo::numbers().iter().map(|(name, value)| json!({
            "name": name,
            "value": value,
        })).collect::<Vec<_>>(),
        "strings": terminfo::strings().iter().map(|cap| json!({
            "name": cap.name,
            "direction": format!("{:?}", cap.direction).to_lowercase(),
            "value": hex(cap.value.as_bytes()),
            "arguments": cap.arguments.iter().map(|argument| match argument {
                terminfo::Param::Number(value) => json!({ "number": value }),
                terminfo::Param::Text(text) => json!({ "text": text }),
            }).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "coverage": coverage,
    })
}
