//! Deterministic JSON Schema and method-table generation.
//!
//! Rust is canonical. The TypeScript package is generated from the schema this module produces, so
//! a change to a Rust type flows to the schema, and from the schema to TypeScript. Both steps have
//! a `--check` mode that fails when the committed output no longer matches, which is what keeps
//! the two languages from drifting.
//!
//! The output is byte stable: every object is a sorted map, the indentation is fixed and each file
//! ends with one newline.

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings, json_schema};
use serde_json::{Map, Value, json};

use crate::account::{MembershipLease, PolicyAuthority};
use crate::actor::ActorEnvelope;
use crate::archive::{ArchiveDescriptor, RecoveryBundle, RecoveryKit, SignedArchiveManifest};
use crate::authority::MethodEntry;
use crate::envelope::{ControlFrame, MutationRequest, Notification, Request, Response};
use crate::error::ProtocolError;
use crate::frame::StreamHeader;
use crate::grant::Grant;
use crate::hello::{ActionWindow, ClientOffer, ConnectReply, HelloReply, HostSelection};
use crate::ids;
use crate::ids::SessionRef;
use crate::mailbox::{EnvelopePlaintext, SealedEnvelope};
use crate::method::{Method, REGISTRY};
use crate::pairing::{
    AuthorityRevisionRecord, DirectChallenge, DirectRedeemProof, GenerationCheckpoint,
    OwnerConfirmationProof, OwnerConfirmationRequest, PairFinishRequest, PairStatus, ProposedGrant,
    RevocationAcknowledgement, RevocationRequest, SignedClientBundle, SignedHostBundle,
};
use crate::push::{
    PushDeliveryAck, PushDeliveryCredential, PushDeliveryRequest, PushInstallationBinding,
    PushRegistrationAnswer, PushRegistrationChallenge, PushSenderRecord, PushSenderRenewal,
    PushSenderRevocation,
};
use crate::receipt::{Receipt, ReceiptResponse};
use crate::relay::{
    RelayConsumptionAck, RelayConsumptionReport, RelayLeaseAck, RelayLeaseRequest,
    SignedRelayConsumptionReceipt, SignedRelayInstanceRegistration,
};
use crate::service::ServiceRequestSignature;

/// The generated JSON Schema bundle.
pub const SCHEMA_FILE_NAME: &str = "kalareach-protocol.schema.json";

/// The generated method and authority table.
pub const METHOD_AUTHORITY_FILE_NAME: &str = "method-authority.json";

/// Adds one root type to the bundle.
macro_rules! roots {
    ($generator:ident, $properties:ident, $($name:literal => $type:ty),+ $(,)?) => {
        $(
            let schema = $generator.subschema_for::<$type>();
            $properties.insert($name.to_owned(), schema.to_value());
        )+
    };
}

/// Builds the JSON Schema bundle for every root protocol message.
///
/// The bundle is one document: a root object whose properties name the root messages and whose
/// `$defs` hold every referenced type exactly once. One document means the generated TypeScript is
/// one module with no duplicated interfaces.
#[must_use]
pub fn protocol_schema() -> Value {
    let mut generator: SchemaGenerator = SchemaSettings::draft2020_12().into_generator();
    let mut properties = Map::new();
    roots! {
        generator, properties,
        "action_window" => ActionWindow,
        "actor_envelope" => ActorEnvelope,
        "archive_descriptor" => ArchiveDescriptor,
        "authority_revision_record" => AuthorityRevisionRecord,
        "client_offer" => ClientOffer,
        "connect_reply" => ConnectReply,
        "control_frame" => ControlFrame,
        "direct_challenge" => DirectChallenge,
        "direct_redeem_proof" => DirectRedeemProof,
        "envelope_plaintext" => EnvelopePlaintext,
        "generation_checkpoint" => GenerationCheckpoint,
        "grant" => Grant,
        "hello_reply" => HelloReply,
        "host_selection" => HostSelection,
        "membership_lease" => MembershipLease,
        "method_entry" => MethodEntry,
        "mutation_request" => MutationRequest,
        "notification" => Notification,
        "owner_confirmation_proof" => OwnerConfirmationProof,
        "owner_confirmation_request" => OwnerConfirmationRequest,
        "pair_finish_request" => PairFinishRequest,
        "pair_status" => PairStatus,
        "policy_authority" => PolicyAuthority,
        "proposed_grant" => ProposedGrant,
        "protocol_error" => ProtocolError,
        "push_delivery_ack" => PushDeliveryAck,
        "push_delivery_credential" => PushDeliveryCredential,
        "push_delivery_request" => PushDeliveryRequest,
        "push_installation_binding" => PushInstallationBinding,
        "push_registration_answer" => PushRegistrationAnswer,
        "push_registration_challenge" => PushRegistrationChallenge,
        "push_sender_record" => PushSenderRecord,
        "push_sender_renewal" => PushSenderRenewal,
        "push_sender_revocation" => PushSenderRevocation,
        "receipt" => Receipt,
        "receipt_response" => ReceiptResponse,
        "relay_consumption_ack" => RelayConsumptionAck,
        "relay_consumption_report" => RelayConsumptionReport,
        "relay_lease_ack" => RelayLeaseAck,
        "relay_lease_request" => RelayLeaseRequest,
        "recovery_bundle" => RecoveryBundle,
        "recovery_kit" => RecoveryKit,
        "request" => Request,
        "response" => Response,
        "revocation_acknowledgement" => RevocationAcknowledgement,
        "revocation_request" => RevocationRequest,
        "sealed_envelope" => SealedEnvelope,
        "service_request_signature" => ServiceRequestSignature,
        "session_ref" => SessionRef,
        "signed_archive_manifest" => SignedArchiveManifest,
        "signed_client_bundle" => SignedClientBundle,
        "signed_host_bundle" => SignedHostBundle,
        "signed_relay_consumption_receipt" => SignedRelayConsumptionReceipt,
        "signed_relay_instance_registration" => SignedRelayInstanceRegistration,
        "stream_header" => StreamHeader,
    }
    properties.insert(
        "identifiers".to_owned(),
        identifier_vocabulary(&mut generator).to_value(),
    );
    let definitions = generator.take_definitions(true);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "KalaReach protocol",
        "description": "Generated from the Rust wire types in crates/kr-protocol. Rust is canonical: edit the Rust types and regenerate. Every property below names one root message; $defs holds the referenced types.",
        "type": "object",
        "properties": Value::Object(properties),
        "$defs": Value::Object(definitions.into_iter().collect()),
    })
}

/// Registers every public identifier so consumers get a named type for each one.
///
/// Most identifiers are reachable from a root message, but not all of them are, and a consumer
/// that has to hand-write `WorkspaceId` has already lost the guarantee this package exists to
/// give. The synthetic root below names them all; the fields are optional because it is a
/// vocabulary, not a message.
fn identifier_vocabulary(generator: &mut SchemaGenerator) -> Schema {
    let mut properties = Map::new();
    macro_rules! vocabulary {
        ($($name:literal => $type:ty),+ $(,)?) => {
            $(properties.insert($name.to_owned(), generator.subschema_for::<$type>().to_value());)+
        };
    }
    vocabulary! {
        // The scalars every identifier is built from.
        "raw_uuid" => crate::scalars::Uuid,
        "raw_u64" => crate::scalars::U64,
        "raw_bytes" => crate::scalars::Bytes,
        "raw_timestamp_ms" => crate::scalars::TimestampMs,
        "raw_duration_ms" => crate::scalars::DurationMs,
        // The identity and object model.
        "account_id" => ids::AccountId,
        "action_id" => ids::ActionId,
        "action_window_id" => ids::ActionWindowId,
        "actor_id" => ids::ActorId,
        "agent_binding_revision" => ids::AgentBindingRevision,
        "agent_thread_id" => ids::AgentThreadId,
        "agent_turn_id" => ids::AgentTurnId,
        "application_instance_id" => ids::ApplicationInstanceId,
        "approval_request_id" => ids::ApprovalRequestId,
        "archive_id" => ids::ArchiveId,
        "attachment_id" => ids::AttachmentId,
        "attachment_ordinal" => ids::AttachmentOrdinal,
        "attempt_id" => ids::AttemptId,
        "authority_revision" => ids::AuthorityRevision,
        "backup_generation" => ids::BackupGeneration,
        "backup_object_id" => ids::BackupObjectId,
        "boot_epoch" => ids::BootEpoch,
        "build_id" => ids::BuildId,
        "capability_id" => ids::CapabilityId,
        "capability_revision" => ids::CapabilityRevision,
        "causal_root_id" => ids::CausalRootId,
        "collapse_id" => ids::CollapseId,
        "change_set_id" => ids::ChangeSetId,
        "change_set_version" => ids::ChangeSetVersion,
        "clock_epoch" => ids::ClockEpoch,
        "confirmation_id" => ids::ConfirmationId,
        "connection_id" => ids::ConnectionId,
        "controller_generation" => ids::ControllerGeneration,
        "desktop_session_id" => ids::DesktopSessionId,
        "device_id" => ids::DeviceId,
        "device_key_revision" => ids::DeviceKeyRevision,
        "diagnostic_id" => ids::DiagnosticId,
        "draft_id" => ids::DraftId,
        "draft_revision" => ids::DraftRevision,
        "envelope_id" => ids::EnvelopeId,
        "environment_id" => ids::EnvironmentId,
        "event_sequence" => ids::EventSequence,
        "event_type" => ids::EventType,
        "geometry_epoch" => ids::GeometryEpoch,
        "grant_id" => ids::GrantId,
        "input_lease_epoch" => ids::InputLeaseEpoch,
        "input_sequence" => ids::InputSequence,
        "installation_id" => ids::InstallationId,
        "invitation_id" => ids::InvitationId,
        "machine_id" => ids::MachineId,
        "notification_id" => ids::NotificationId,
        "organisation_id" => ids::OrganisationId,
        "pairing_sequence" => ids::PairingSequence,
        "payer_authorisation_id" => ids::PayerAuthorisationId,
        "plugin_id" => ids::PluginId,
        "policy_key_revision" => ids::PolicyKeyRevision,
        "project_repository_id" => ids::ProjectRepositoryId,
        "push_registration_id" => ids::PushRegistrationId,
        "push_sender_record_id" => ids::PushSenderRecordId,
        "push_sender_revision" => ids::PushSenderRevision,
        "question_id" => ids::QuestionId,
        "question_revision" => ids::QuestionRevision,
        "relay_instance_id" => ids::RelayInstanceId,
        "relay_lease_id" => ids::RelayLeaseId,
        "relay_lease_revision" => ids::RelayLeaseRevision,
        "relay_receipt_sequence" => ids::RelayReceiptSequence,
        "relay_region" => ids::RelayRegion,
        "relay_registration_revision" => ids::RelayRegistrationRevision,
        "relay_reservation_id" => ids::RelayReservationId,
        "remote_dispatch_lease_id" => ids::RemoteDispatchLeaseId,
        "repository_generation" => ids::RepositoryGeneration,
        "request_id" => ids::RequestId,
        "revocation_request_id" => ids::RevocationRequestId,
        "session_epoch" => ids::SessionEpoch,
        "session_id" => ids::SessionId,
        "source_event_handle" => ids::SourceEventHandle,
        "stream_cursor" => ids::StreamCursor,
        "stream_id" => ids::StreamId,
        "transfer_id" => ids::TransferId,
        "workflow_id" => ids::WorkflowId,
        "workflow_run_id" => ids::WorkflowRunId,
        "workspace_id" => ids::WorkspaceId,
    }
    json_schema!({
        "type": "object",
        "description": "Every identifier in the identity and object model. This is a vocabulary rather than a message: it exists so each identifier has one named type.",
        "properties": Value::Object(properties)
    })
}

/// Builds the method and authority table as data.
///
/// Consumers that are not written in Rust read this file instead of re-deriving the table. Any
/// method that is not listed here is denied.
#[must_use]
pub fn method_authority_table() -> Value {
    json!({
        "description": "One exhaustive authority entry per method. Anything not listed is denied. Generated from crates/kr-protocol; do not edit by hand.",
        "method_count": REGISTRY.len(),
        "unlisted_methods_are_denied": true,
        "methods": REGISTRY,
    })
}

/// Returns every generated file as a name and its exact contents.
///
/// # Panics
///
/// Panics when a generated document cannot be serialised, which would mean a schema type is
/// malformed rather than a runtime condition.
#[must_use]
pub fn generated_files() -> Vec<(&'static str, String)> {
    vec![
        (SCHEMA_FILE_NAME, render(&protocol_schema())),
        (
            METHOD_AUTHORITY_FILE_NAME,
            render(&method_authority_table()),
        ),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

/// Returns the schema name every method uses, for cross-checking the table against the enum.
#[must_use]
pub fn method_names() -> Vec<&'static str> {
    Method::ALL.iter().map(|method| method.as_str()).collect()
}

/// Returns the schema of one type, for tests that assert a single shape.
#[must_use]
pub fn schema_for<T: JsonSchema>() -> Value {
    SchemaSettings::draft2020_12()
        .into_generator()
        .into_root_schema_for::<T>()
        .to_value()
}
