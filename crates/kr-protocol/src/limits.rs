//! Protocol defaults.
//!
//! These are the configurable resource limits of sections 9, 10, 14 and 23, not subscription
//! restrictions. A self-hosted owner can change the configurable ones; the framing bounds are part
//! of the wire contract and are enforced before allocation.

use crate::scalars::DurationMs;

/// Maximum size of a stream header, in bytes.
///
/// Each stream first supplies this bounded header declaring its kind and associated authorised
/// resource. It is validated against the established control connection before any data frame.
pub const MAX_STREAM_HEADER_LEN: usize = 1024;

/// Maximum size of a complete control frame, in bytes.
///
/// Every frame bound below covers the complete frame, its four-byte length prefix included. The
/// attachment allowance says so outright ("1 MiB of chunk data plus at most 4 KiB of encoded
/// metadata/framing"), and counting the prefix everywhere keeps each payload inside the maximum
/// message size as well.
pub const MAX_CONTROL_FRAME_LEN: usize = 1024 * 1024;

/// Maximum number of parts one snapshot of plugin admissions, or one worker's report on it, is cut
/// into.
///
/// Each part is one control frame. A snapshot that needs more is refused by name where it is built,
/// and the worker it was for keeps the admissions it holds.
pub const MAX_ADMISSION_PARTS: u32 = 64;

/// Maximum encoded size of one record in a snapshot of plugin admissions or a report on it, in
/// bytes: one admitted package, one release state or one live binding.
///
/// A part holds whole records, and every record's members have bounds of their own that keep it
/// inside this, so the cut into parts never meets a record that cannot fit a frame.
pub const MAX_ADMISSION_RECORD_BYTES: usize = 128 * 1024;

/// Maximum size of a path an admitted package names (its directory, its forwarder, its
/// component), in bytes.
pub const MAX_ADMITTED_PATH_BYTES: usize = 4096;

/// Maximum size of the free text in one record of a worker's report (why it refused a package, or
/// why a component stands where it does), in bytes; longer text is cut at a character boundary and
/// marked as cut.
pub const MAX_REPORT_DETAIL_BYTES: usize = 1024;

/// Maximum size of a complete input frame, in bytes.
pub const MAX_INPUT_FRAME_LEN: usize = 64 * 1024;

/// Maximum size of one attachment chunk, in bytes.
pub const MAX_ATTACHMENT_CHUNK_LEN: usize = 1024 * 1024;

/// Maximum size of the encoded metadata and framing around an attachment chunk, in bytes.
pub const MAX_ATTACHMENT_METADATA_LEN: usize = 4 * 1024;

/// Maximum size of a complete attachment frame, in bytes.
///
/// This larger bound cannot be selected on a control stream.
pub const MAX_ATTACHMENT_FRAME_LEN: usize = MAX_ATTACHMENT_CHUNK_LEN + MAX_ATTACHMENT_METADATA_LEN;

/// Maximum outstanding mutations per device and session.
pub const MAX_OUTSTANDING_MUTATIONS: usize = 8;

/// Maximum concurrent attachments per host.
pub const MAX_CONCURRENT_ATTACHMENTS: usize = 32;

/// Maximum queued bytes per peer before a slow client is resynchronised.
pub const MAX_SEND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// Default maximum live or creating sessions per environment.
pub const DEFAULT_MAX_SESSIONS_PER_ENVIRONMENT: usize = 128;

/// Default requested time to live for an ordinary mutation.
pub const DEFAULT_MUTATION_TTL: DurationMs = DurationMs::new(120_000);

/// Maximum requested time to live for an ordinary mutation. The host may shorten it further.
pub const MAX_MUTATION_TTL: DurationMs = DurationMs::new(300_000);

/// Maximum validity of a host-issued action window.
pub const MAX_ACTION_WINDOW: DurationMs = DurationMs::new(300_000);

/// Maximum validity of a worker-held remote dispatch lease, on the suspend-aware continuous clock.
pub const MAX_REMOTE_DISPATCH_LEASE: DurationMs = DurationMs::new(5_000);

/// How long de-duplication records are retained.
pub const DEDUPLICATION_RETENTION: DurationMs = DurationMs::new(30 * 24 * 60 * 60 * 1000);

/// Network keepalive interval while a connection is active.
pub const KEEPALIVE_INTERVAL: DurationMs = DurationMs::new(10_000);

/// Inactivity threshold before the transport is declared unavailable.
pub const INACTIVITY_THRESHOLD: DurationMs = DurationMs::new(30_000);

/// Shortest reconnect backoff.
pub const RECONNECT_BACKOFF_MIN: DurationMs = DurationMs::new(250);

/// Longest reconnect backoff.
pub const RECONNECT_BACKOFF_MAX: DurationMs = DurationMs::new(30_000);

/// Lifetime of a pairing invitation.
pub const INVITATION_LIFETIME: DurationMs = DurationMs::new(300_000);

/// Failed client-confirmation tags permitted per invitation.
pub const MAX_PAIRING_CONFIRMATION_FAILURES: u32 = 5;

/// Default lifetime of a session invitation grant.
pub const DEFAULT_SESSION_INVITATION_TTL: DurationMs = DurationMs::new(60 * 60 * 1000);

/// Maximum lifetime the issuer may select for a session invitation grant.
pub const MAX_SESSION_INVITATION_TTL: DurationMs = DurationMs::new(30 * 24 * 60 * 60 * 1000);

/// How long an unread mailbox item is retained.
pub const MAILBOX_ITEM_LIFETIME: DurationMs = DurationMs::new(24 * 60 * 60 * 1000);

/// Maximum mailbox items per device.
pub const MAX_MAILBOX_ITEMS: usize = 1000;

/// Maximum mailbox bytes per device.
pub const MAX_MAILBOX_BYTES: usize = 32 * 1024 * 1024;

/// Upload chunk size returned by `upload.begin`.
pub const UPLOAD_CHUNK_LEN: usize = 1024 * 1024;

/// Default maximum size of one uploaded file.
pub const DEFAULT_MAX_UPLOAD_FILE_LEN: u64 = 2 * 1024 * 1024 * 1024;

/// Default maximum staged upload bytes per environment.
pub const DEFAULT_MAX_STAGED_UPLOAD_LEN: u64 = 8 * 1024 * 1024 * 1024;

/// Default concurrent transfers per device.
pub const DEFAULT_MAX_CONCURRENT_TRANSFERS: usize = 2;
