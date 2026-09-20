//! The voice control socket and return path.
//!
//! Section 15 paragraph 6 requires a dedicated control socket to the managed service:
//! `wss://{broker_origin}{control_path}`.
//!
//! Hard constraints:
//! 1. **Zero raw provider control events**: The client sends only the six allowed [`VoiceCommand`]s
//!    (`mute`, `unmute`, `instructions`, `thinking`, `commentary`, `close`). Raw provider events
//!    (`session.update`, `response.create`, etc.) are excluded at the type boundary.
//! 2. **Bounded context requests**: Maximum frame size of 4096 bytes (`VOICE_CONTROL_FRAME_BYTES`)
//!    and maximum context append of 500 UTF-8 bytes (`VOICE_CONTEXT_BYTES`).
//! 3. **Heartbeat**: Sent every 20 seconds (`{"type":"heartbeat"}`).
//! 4. **Admission is not execution**: Append acknowledgement (`context_admitted`) indicates provider
//!    admission, never host action execution or audio playback.
//! 5. **Host delegation**: A delegation announced by the provider is submitted to the **host**
//!    via `voice.delegate`, never to the broker.

use kr_client::services::voice::{
    VOICE_CONTEXT_BYTES, VOICE_CONTROL_FRAME_BYTES, VoiceCommand, VoiceContextFrame,
    VoiceControlEvent, read_control_event,
};
use serde::{Deserialize, Serialize};

use crate::error::{CommandError, Result};

/// The default heartbeat interval in seconds.
pub const HEARTBEAT_INTERVAL_SECONDS: u64 = 20;

/// How many delegation identifiers one call keeps.
///
/// The provider writes these and a call is metered in minutes, so the set a call can have heard is
/// small. A bound means a stream of announcements cannot grow this process without limit.
pub const MAX_KNOWN_DELEGATIONS: usize = 256;

/// The heartbeat frame sent every 20 seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoiceHeartbeatFrame {
    /// The string literal `"heartbeat"`.
    #[serde(rename = "type")]
    pub frame_type: &'static str,
}

impl Default for VoiceHeartbeatFrame {
    fn default() -> Self {
        Self {
            frame_type: "heartbeat",
        }
    }
}

/// Validates and constructs an outbound context frame.
///
/// `known_delegations` is what this call has actually been told about. A frame that names a
/// delegation this call never saw is refused here rather than sent: a delegation identifier is
/// correlation data the provider wrote, and answering one that was never announced would let a
/// name invented anywhere reach the service as though the call had heard it.
///
/// # Errors
///
/// Returns an error if the frame exceeds 4096 bytes, if the append content exceeds 500 UTF-8 bytes,
/// if the command does not match content expectations, if the identifier is invalid, or if the
/// frame names a delegation this call has not seen.
pub fn validate_context_frame(
    id: &str,
    command: VoiceCommand,
    delegation_id: Option<String>,
    content: Option<String>,
    known_delegations: &[String],
) -> Result<VoiceContextFrame> {
    if id.trim().is_empty() || id.len() > 128 {
        return Err(CommandError::invalid(
            "context request requires a valid identifier",
        ));
    }

    if let Some(ref named) = delegation_id
        && !known_delegations.iter().any(|known| known == named)
    {
        return Err(CommandError::invalid(
            "that delegation was never announced on this call",
        ));
    }

    if let Some(ref text) = content
        && text.len() > VOICE_CONTEXT_BYTES
    {
        return Err(CommandError::invalid(format!(
            "context append exceeds bound: {} > {VOICE_CONTEXT_BYTES} UTF-8 bytes",
            text.len()
        )));
    }

    let frame = VoiceContextFrame::new(id, command, delegation_id, content)
        .map_err(|error| CommandError::invalid(error.to_string()))?;

    let serialized = serde_json::to_string(&frame).map_err(|error| {
        CommandError::local_failure(format!("failed to serialize frame: {error}"))
    })?;

    if serialized.len() > VOICE_CONTROL_FRAME_BYTES {
        return Err(CommandError::invalid(format!(
            "frame size exceeds maximum bound: {} > {VOICE_CONTROL_FRAME_BYTES} bytes",
            serialized.len()
        )));
    }

    Ok(frame)
}

/// Handler for inbound events received on the control socket.
#[derive(Debug, Default)]
pub struct ControlSocketHandler {
    /// Active call identifier once ready.
    pub call_id: Option<String>,
    /// Remaining metered seconds if reported by broker.
    pub remaining_seconds: Option<u64>,
    /// Active delegation keys known to the broker.
    pub known_delegations: Vec<String>,
    /// Elapsed metered call time in seconds.
    pub metered_seconds: u64,
    /// Whether the voice session has closed.
    pub is_closed: bool,
    /// Reason string if the call closed.
    pub close_reason: Option<String>,
}

impl ControlSocketHandler {
    /// Creates a new socket handler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes an incoming raw JSON control frame.
    ///
    /// Unknown event types are dropped by type; valid known frames update state or yield actions.
    pub fn handle_event(&mut self, value: &serde_json::Value) -> Option<VoiceControlEvent> {
        let event = read_control_event(value)?;

        match &event {
            VoiceControlEvent::Ready {
                call_id,
                delegations,
            } => {
                self.call_id = Some(call_id.clone());
                // The service lists these oldest first, so a list longer than the bound keeps its
                // end. Keeping the beginning would drop exactly the delegations a reconnecting
                // call is most likely to be asked about, and the membership check would then
                // refuse a result for one the call really did hear.
                let keep = delegations.len().saturating_sub(MAX_KNOWN_DELEGATIONS);
                self.known_delegations = delegations[keep..].to_vec();
            }
            VoiceControlEvent::HeartbeatAcknowledged { remaining_seconds } => {
                self.remaining_seconds = Some(*remaining_seconds);
            }
            VoiceControlEvent::Usage { seconds, .. } => {
                self.metered_seconds = *seconds;
            }
            VoiceControlEvent::Closed {
                reason, seconds, ..
            } => {
                self.is_closed = true;
                self.close_reason = Some(reason.clone());
                self.metered_seconds = *seconds;
            }
            VoiceControlEvent::Delegation { delegation_id, .. } => {
                if !self.known_delegations.contains(delegation_id) {
                    if self.known_delegations.len() >= MAX_KNOWN_DELEGATIONS {
                        self.known_delegations.remove(0);
                    }
                    self.known_delegations.push(delegation_id.clone());
                }
            }
            VoiceControlEvent::ContextAccepted { .. }
            | VoiceControlEvent::ContextAdmitted { .. }
            | VoiceControlEvent::ContextRefused { .. }
            | VoiceControlEvent::Notice { .. }
            | VoiceControlEvent::Unknown { .. } => {}
        }

        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::voice::VOICE_ADMISSION_NOTE;
    use serde_json::json;

    #[test]
    fn heartbeat_frame_serializes_to_expected_wire_format() {
        let heartbeat = VoiceHeartbeatFrame::default();
        let serialized = serde_json::to_value(heartbeat).expect("serializes");
        assert_eq!(serialized, json!({ "type": "heartbeat" }));
    }

    #[test]
    fn context_request_validation_enforces_bounds() {
        // Valid thinking frame with short content.
        let valid = validate_context_frame(
            "req_1",
            VoiceCommand::Thinking,
            None,
            Some("context data".to_owned()),
            &[],
        );
        assert!(valid.is_ok());

        // Oversized content (> 500 bytes) is refused.
        let overlong = "x".repeat(VOICE_CONTEXT_BYTES + 1);
        let invalid =
            validate_context_frame("req_2", VoiceCommand::Thinking, None, Some(overlong), &[]);
        assert!(invalid.is_err());

        // Mute carrying text is refused (only Instructions, Thinking, Commentary carry text).
        let mute_with_text = validate_context_frame(
            "req_3",
            VoiceCommand::Mute,
            None,
            Some("text".to_owned()),
            &[],
        );
        assert!(mute_with_text.is_err());

        // Instructions without text is refused.
        let empty_instructions =
            validate_context_frame("req_4", VoiceCommand::Instructions, None, None, &[]);
        assert!(empty_instructions.is_err());
    }

    #[test]
    fn a_delegation_the_call_never_heard_is_refused() {
        // KR-REQ-15.17 and section 15 paragraph 7: a delegation identifier is correlation data the
        // provider announced. One this call never saw cannot be answered.
        let invented = validate_context_frame(
            "req_5",
            VoiceCommand::Commentary,
            Some("del_invented".to_owned()),
            Some("done".to_owned()),
            &["del_1".to_owned()],
        );
        assert!(
            invented.is_err(),
            "an unannounced delegation must be refused"
        );

        let announced = validate_context_frame(
            "req_6",
            VoiceCommand::Commentary,
            Some("del_1".to_owned()),
            Some("done".to_owned()),
            &["del_1".to_owned()],
        );
        assert!(
            announced.is_ok(),
            "the delegation this call heard is allowed"
        );
    }

    #[test]
    fn the_handler_bounds_what_one_call_remembers() {
        let mut handler = ControlSocketHandler::new();
        let announced = MAX_KNOWN_DELEGATIONS + 20;
        for index in 0..announced {
            let read = handler.handle_event(&json!({
                "type": "delegation",
                "delegationId": format!("del_{index}"),
                "offsetMs": index
            }));
            assert!(
                matches!(read, Some(VoiceControlEvent::Delegation { .. })),
                "the announcement must parse, or this test bounds an empty list"
            );
        }

        // The bound holds, and what it keeps is the end: the delegations most recently announced
        // are the ones a result is most likely to answer.
        assert_eq!(handler.known_delegations.len(), MAX_KNOWN_DELEGATIONS);
        assert_eq!(
            handler.known_delegations.last().map(String::as_str),
            Some(format!("del_{}", announced - 1).as_str())
        );
        assert!(!handler.known_delegations.contains(&"del_0".to_owned()));
    }

    #[test]
    fn a_reconnection_keeps_the_newest_delegations_it_is_given() {
        let mut handler = ControlSocketHandler::new();
        // The service lists them oldest first.
        let listed: Vec<String> = (0..(MAX_KNOWN_DELEGATIONS + 5))
            .map(|index| format!("del_{index}"))
            .collect();
        let read = handler.handle_event(&json!({
            "type": "ready",
            "callId": "call_1",
            "delegations": listed
        }));
        assert!(matches!(read, Some(VoiceControlEvent::Ready { .. })));

        assert_eq!(handler.known_delegations.len(), MAX_KNOWN_DELEGATIONS);
        assert_eq!(
            handler.known_delegations.last().map(String::as_str),
            Some(format!("del_{}", MAX_KNOWN_DELEGATIONS + 4).as_str())
        );
        assert!(!handler.known_delegations.contains(&"del_0".to_owned()));
    }

    #[test]
    fn control_event_handling_and_unknown_event_dropping() {
        let mut handler = ControlSocketHandler::new();

        // Ready event.
        let ready_val = json!({
            "type": "ready",
            "callId": "call_123",
            "delegations": ["del_1"]
        });
        let ev = handler.handle_event(&ready_val);
        assert!(matches!(ev, Some(VoiceControlEvent::Ready { .. })));
        assert_eq!(handler.call_id.as_deref(), Some("call_123"));
        assert_eq!(handler.known_delegations, vec!["del_1"]);

        // Context admitted note is exact.
        let admitted_val = json!({
            "type": "context_admitted",
            "id": "req_1",
            "note": VOICE_ADMISSION_NOTE
        });
        let ev = handler.handle_event(&admitted_val);
        assert!(matches!(
            ev,
            Some(VoiceControlEvent::ContextAdmitted { .. })
        ));

        // Unknown event type is parsed as Unknown and dropped safely without panicking.
        let unknown_val = json!({
            "type": "custom_provider_event",
            "raw": "foo"
        });
        let ev = handler.handle_event(&unknown_val);
        assert!(matches!(ev, Some(VoiceControlEvent::Unknown { .. })));
    }
}
