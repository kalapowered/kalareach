//! One session's attention sources, as the environment's attention store reads them.
//!
//! The store is the control daemon's, and it keeps none of a session's text: an item names the
//! record its text comes from. What a session holds for it is its question ledger and its host
//! events, in the session's own journal, and this module is how the daemon reads them: a page of
//! the records past where the store has read, and the text of records the store names when it
//! serves them. The same reads serve a live session over its worker's attention connection and a
//! closed one from its journal file.
//!
//! # What is served as text
//!
//! A record's text is served only while privacy mode is off and only when the record came after
//! its source's head in the privacy record, which the journal writes in the same transaction as
//! every privacy transition. So nothing written before privacy mode was enabled, or while it was
//! on, is served again once a transition has been recorded, live or from a closed session's
//! journal, and a journal whose privacy record is missing serves no text at all. Text is clipped
//! to what an item carries.
//!
//! # Fingerprints
//!
//! An application's notification without an identifier is one condition with every other that
//! says the same thing, and the store knows what it says by a fingerprint rather than by its text:
//! a keyed digest under a key the store derives for the session and names in each request, sent
//! whether or not the text is. So an item's identity does not change with whether its text is
//! served, nobody without the key can test a guess at withheld text against it, and the session
//! keeps no key of its own: key material belongs in the operating system's protected stores, not
//! in a journal.

use kr_protocol::attention::{
    AttentionHostRecord, AttentionHostSlice, AttentionQuestionRecord, AttentionQuestionSlice,
    AttentionRecordText, AttentionSource, AttentionSourcePage, AttentionSourcesRequest,
    AttentionTextAnswer, AttentionTextRequest, MAX_ATTENTION_SOURCE_RECORDS,
    MAX_ATTENTION_SUMMARY_LEN, MAX_ATTENTION_TEXT_RECORDS,
};
use kr_protocol::scalars::{Digest256, Nullable, U64};

use crate::error::{Result, WorkerError};
use crate::journal::{HostEvent, Journal, PrivacyRecord};

/// What one record costs a page beyond its text, as a generous estimate of its encoded size.
const RECORD_OVERHEAD: usize = 192;

/// The kind a notification is recorded under.
const NOTIFICATION: &str = "notification";

/// Whether a record's text is served now, under the privacy record read after it.
///
/// Only while privacy mode is off, and only for a record that came after its source's head at the
/// last transition. Without a privacy record, nothing is.
#[must_use]
pub fn serves(privacy: Option<&PrivacyRecord>, source: AttentionSource, sequence: u64) -> bool {
    let Some(privacy) = privacy else {
        return false;
    };
    if privacy.enabled {
        return false;
    }
    match source {
        AttentionSource::Questions => sequence > privacy.questions_head,
        AttentionSource::HostEvents => sequence > privacy.host_events_head,
        _ => false,
    }
}

/// Returns one page of the session's attention source records past the cursors `request` names.
///
/// The reads are made in order, each a statement of its own: the question ledger's head and its
/// records after the cursor, then the host events' head and theirs, then the privacy record,
/// which decides which records carry text. `built_at_boot_ms` is the caller's reading of the
/// continuous clock, taken before the first of them. A page carries at most `request.max_records`
/// records from each source and, text included, about `max_bytes` in all; what it leaves out is
/// read by the next request.
///
/// # Errors
///
/// Returns [`WorkerError::JournalUnavailable`] when a source cannot be read. A page is never
/// answered from part of the sources.
pub fn page(
    journal: &Journal,
    request: &AttentionSourcesRequest,
    built_at_boot_ms: u64,
    max_bytes: usize,
) -> Result<AttentionSourcePage> {
    let limit = usize::try_from(
        request
            .max_records
            .get()
            .clamp(1, MAX_ATTENTION_SOURCE_RECORDS),
    )
    .unwrap_or(1);
    let mut budget = max_bytes;

    let questions_head = journal.question_events_head()?;
    let questions = journal.question_events_after(request.questions_after.get(), limit)?;
    let host_events_head = journal.host_events_head()?;
    let host_events = journal.host_events_after(request.host_events_after.get(), limit)?;
    let privacy = journal.read_privacy()?;
    let key = request.fingerprint_key.expose();

    let mut question_records = Vec::new();
    for (sequence, event) in questions {
        if sequence > questions_head {
            break;
        }
        let text = serves(privacy.as_ref(), AttentionSource::Questions, sequence)
            .then(|| clip(&event.question.question));
        if !spend(&mut budget, text.as_deref(), question_records.is_empty()) {
            break;
        }
        question_records.push(AttentionQuestionRecord {
            sequence: U64::new(sequence),
            kind: event.kind,
            question_id: event.question.question_id,
            session_id: event.question.session_id,
            verified: event.question.source.session_member,
            pending_since_ms: event.pending_since_ms,
            recorded_at_ms: event.recorded_at_ms,
            text: Nullable(text),
        });
    }

    let mut host_records = Vec::new();
    for (sequence, event) in host_events {
        if sequence > host_events_head {
            break;
        }
        let text = serves(privacy.as_ref(), AttentionSource::HostEvents, sequence)
            .then(|| clip(&event.detail));
        if !spend(&mut budget, text.as_deref(), host_records.is_empty()) {
            break;
        }
        host_records.push(host_record(sequence, &event, text, key));
    }

    Ok(AttentionSourcePage {
        request_id: request.request_id,
        built_at_boot_ms: U64::new(built_at_boot_ms),
        questions: AttentionQuestionSlice {
            head: U64::new(questions_head),
            records: question_records,
        },
        host_events: AttentionHostSlice {
            head: U64::new(host_events_head),
            records: host_records,
        },
        privacy_generation: Nullable(privacy.map(|privacy| U64::new(privacy.generation))),
    })
}

/// Answers the text of each record `request` names, under the privacy record read after them.
///
/// A record the session no longer holds, or whose text it does not serve now, is answered with
/// none.
///
/// # Errors
///
/// Returns [`WorkerError::InvalidArgument`] for a request naming more than
/// [`MAX_ATTENTION_TEXT_RECORDS`] records, and [`WorkerError::JournalUnavailable`] when a record
/// cannot be read.
pub fn texts(journal: &Journal, request: &AttentionTextRequest) -> Result<AttentionTextAnswer> {
    if request.records.len() > usize::try_from(MAX_ATTENTION_TEXT_RECORDS).unwrap_or(usize::MAX) {
        return Err(WorkerError::InvalidArgument(format!(
            "a text request names at most {MAX_ATTENTION_TEXT_RECORDS} records"
        )));
    }
    let mut read = Vec::with_capacity(request.records.len());
    for record in &request.records {
        let sequence = record.sequence.get();
        let text = match record.source {
            AttentionSource::Questions => journal
                .question_event(sequence)?
                .map(|event| event.question.question),
            AttentionSource::HostEvents => journal.host_event(sequence)?.map(|event| event.detail),
            _ => None,
        };
        read.push((record.source, sequence, text));
    }
    // After the records, so a transition committed while they were being read withholds them.
    let privacy = journal.read_privacy()?;
    Ok(AttentionTextAnswer {
        request_id: request.request_id,
        privacy_generation: Nullable(privacy.map(|privacy| U64::new(privacy.generation))),
        texts: read
            .into_iter()
            .map(|(source, sequence, text)| AttentionRecordText {
                source,
                sequence: U64::new(sequence),
                text: Nullable(
                    text.filter(|_| serves(privacy.as_ref(), source, sequence))
                        .map(|text| clip(&text)),
                ),
            })
            .collect(),
    })
}

/// Returns the keyed digest of what a notification said, under a fingerprint key.
#[must_use]
pub fn fingerprint(key: &[u8; 32], said: &str) -> Digest256 {
    let key = kr_crypto::secret::SymmetricKey::from_bytes(*key);
    Digest256::from_bytes(*kr_crypto::kdf::hmac_sha256(&key, said.as_bytes()).as_bytes())
}

fn host_record(
    sequence: u64,
    event: &HostEvent,
    text: Option<String>,
    key: &[u8; 32],
) -> AttentionHostRecord {
    let notification = event.kind == NOTIFICATION;
    AttentionHostRecord {
        sequence: U64::new(sequence),
        notification,
        recorded_at_ms: event.recorded_at_ms,
        text: Nullable(text),
        fingerprint: Nullable(notification.then(|| fingerprint(key, &event.detail))),
    }
}

/// Takes one record's cost from what the page has left, and answers whether it fits.
///
/// The first record of a source always fits, so a page always moves each source that has
/// something to read.
fn spend(budget: &mut usize, text: Option<&str>, first: bool) -> bool {
    let cost = RECORD_OVERHEAD + text.map_or(0, str::len);
    if cost > *budget && !first {
        return false;
    }
    *budget = budget.saturating_sub(cost);
    true
}

/// Clips text to what an attention item carries, at a character boundary.
fn clip(text: &str) -> String {
    if text.len() <= MAX_ATTENTION_SUMMARY_LEN {
        return text.to_owned();
    }
    let mut end = MAX_ATTENTION_SUMMARY_LEN;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
