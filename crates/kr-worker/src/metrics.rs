//! What a session's worker reports about itself: the terminal parse faults of its session and the
//! failures of the adapters it brokers.
//!
//! The declaration of both metrics, their closed labels and the report they are carried in are
//! `kr_protocol::metrics`. This module is only the worker's side of them: which of the terminal
//! engine's diagnostics are a parse fault and of which class, and the report a worker gives of
//! everything it has counted. Totals are read, never recomputed from a stream, so reading them
//! twice gives the same answer.

use kr_protocol::metrics::{Environment, Fault, MetricsReport, ParseFault};
use kr_protocol::scalars::U64;
use kr_term::diag::DiagnosticKind;

/// The class of parse fault one of the engine's diagnostics is, where it is one.
///
/// A parse fault is bytes a program wrote that the parser could not make sense of. The match has
/// no wildcard, so a diagnostic added to the engine has to be placed here, as a fault or as
/// nothing, before this builds.
#[must_use]
pub const fn fault_of(kind: DiagnosticKind) -> Option<Fault> {
    match kind {
        DiagnosticKind::UnclassifiedSequence => Some(Fault::UnknownControl),
        DiagnosticKind::OversizedControlString | DiagnosticKind::PassthroughTooDeep => {
            Some(Fault::OversizedFrame)
        }
        DiagnosticKind::AbandonedControlString => Some(Fault::UnterminatedSequence),
        DiagnosticKind::MalformedUtf8 => Some(Fault::InvalidEncoding),
        // A raw eight-bit control is a valid way to write the control the profile handles.
        DiagnosticKind::RawC1Control
        // A well-formed sequence whose parameter named more than the grid has, as a program
        // that moves the cursor a screen's width writes at every prompt.
        | DiagnosticKind::ParameterReduced
        // The profile has no raster graphics, and says so when a program draws one: a program
        // using a feature this terminal lacks, which is not a malformed sequence.
        | DiagnosticKind::ImageSequenceDisabled
        // A well-formed request this host does not grant a program.
        | DiagnosticKind::PhysicalWindowRequest
        // A well-formed query this host answers on the terminal's behalf.
        | DiagnosticKind::QueryAnswered
        // The host shedding load; not a fault in what the program wrote.
        | DiagnosticKind::ResponseLaneDegraded
        // A well-formed effect with nowhere to go, kept as a host event.
        | DiagnosticKind::SideEffectWithoutDestination
        // A clipboard write the host refused: its size, its policy or a payload that is not
        // base64, which the diagnostic does not tell apart, so none is counted as a fault.
        | DiagnosticKind::ClipboardWriteRejected
        // A well-formed pop of a stack that was already empty.
        | DiagnosticKind::TitleStackUnderflow
        // The host's own bound on what it keeps resident.
        | DiagnosticKind::ResidentStateTruncated => None,
    }
}

/// The report of a session's parse faults, from the engine's running totals by kind.
///
/// Totals are cumulative, so the report is built whole from them and a second call over the same
/// totals is the same report.
#[must_use]
pub fn parse_faults(totals: &[(DiagnosticKind, u64)], environment: Environment) -> MetricsReport {
    let mut by_class: std::collections::BTreeMap<Fault, u64> = std::collections::BTreeMap::new();
    for (kind, count) in totals {
        if let Some(fault) = fault_of(*kind) {
            let held = by_class.entry(fault).or_default();
            *held = held.saturating_add(*count);
        }
    }
    MetricsReport {
        terminal_parse_fault: by_class
            .into_iter()
            .filter(|(_, count)| *count > 0)
            .map(|(fault, count)| ParseFault {
                fault,
                environment,
                count: U64::new(count),
            })
            .collect(),
        ..MetricsReport::default()
    }
}
