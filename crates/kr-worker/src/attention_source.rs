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
//! A question's wording is its creation's. Every later transition of the question carries the
//! question again, and serving the wording from one of those would serve text written before a
//! privacy transition under the one after it; so only the record that created a question carries
//! its text, and that record's place decides whether it is served.
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
use kr_protocol::question::QuestionEventKind;
use kr_protocol::scalars::{Digest256, Nullable, U64};

use crate::error::{Result, WorkerError};
use crate::journal::{HostEvent, Journal, PrivacyRecord};

/// What a record list's length can add to a page beyond its size when the list was empty.
const LIST_SLACK: usize = 8;

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
/// records from each source and, encoded, at most `max_bytes`; what it leaves out is read by the
/// next request. A page with records to carry always carries one, so the reading moves on; a
/// caller whose frame cannot hold even that is told so by measuring the page.
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
    let questions_head = journal.question_events_head()?;
    let questions = journal.question_events_after(request.questions_after.get(), limit)?;
    let host_events_head = journal.host_events_head()?;
    let host_events = journal.host_events_after(request.host_events_after.get(), limit)?;
    let privacy = journal.read_privacy()?;
    let key = request.fingerprint_key.expose();

    let mut page = AttentionSourcePage {
        request_id: request.request_id,
        built_at_boot_ms: U64::new(built_at_boot_ms),
        questions: AttentionQuestionSlice {
            head: U64::new(questions_head),
            records: Vec::new(),
        },
        host_events: AttentionHostSlice {
            head: U64::new(host_events_head),
            records: Vec::new(),
        },
        privacy_generation: Nullable(privacy.map(|privacy| U64::new(privacy.generation))),
        // The journal does not hold the output; a live worker fills this in from its session.
        output_floor: Nullable::null(),
    };
    // The frame that carries the page, with the output position a live worker adds to it, and
    // room for each list's length to grow.
    let mut used = frame_size(&page)
        .saturating_add(measure(&U64::new(u64::MAX)))
        .saturating_add(2 * LIST_SLACK);

    for (sequence, event) in questions {
        if sequence > questions_head {
            break;
        }
        let record = question_record(
            sequence,
            &event,
            serves(privacy.as_ref(), AttentionSource::Questions, sequence),
        );
        if !fits(
            &mut used,
            measure(&record),
            max_bytes,
            carries_nothing(&page),
        ) {
            break;
        }
        page.questions.records.push(record);
    }

    for (sequence, event) in host_events {
        if sequence > host_events_head {
            break;
        }
        let text = serves(privacy.as_ref(), AttentionSource::HostEvents, sequence)
            .then(|| clip(&event.detail));
        let record = host_record(sequence, &event, text, key);
        if !fits(
            &mut used,
            measure(&record),
            max_bytes,
            carries_nothing(&page),
        ) {
            break;
        }
        page.host_events.records.push(record);
    }

    Ok(page)
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
            // Only the record that created a question carries its wording.
            AttentionSource::Questions => journal
                .question_event(sequence)?
                .filter(|event| event.kind == QuestionEventKind::Created)
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

/// Returns the record of one question transition, as a page carries it.
///
/// `served` is whether the record's text is served now. Only the record that created a question
/// carries its wording; every later one carries the question's identity and what happened to it,
/// and nothing else of it: not the caller's token, not the answer.
#[must_use]
pub fn question_record(
    sequence: u64,
    event: &kr_protocol::question::QuestionEvent,
    served: bool,
) -> AttentionQuestionRecord {
    let text = (served && event.kind == QuestionEventKind::Created)
        .then(|| clip(&event.question.question));
    AttentionQuestionRecord {
        sequence: U64::new(sequence),
        kind: event.kind,
        question_id: event.question.question_id,
        session_id: event.question.session_id,
        verified: event.question.source.session_member,
        pending_since_ms: event.pending_since_ms,
        recorded_at_ms: event.recorded_at_ms,
        text: Nullable(text),
    }
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

/// Cuts records from the end of a page until the frame that carries it fits `max_bytes`, and
/// answers whether it does.
///
/// Host events go before questions, and each source keeps the records nearest its cursor, so what
/// is cut is read by the next request. A page that had records keeps at least one: if one record
/// does not fit, the page does not fit.
#[must_use]
pub fn fit(page: &mut AttentionSourcePage, max_bytes: usize) -> bool {
    loop {
        if frame_size(page) <= max_bytes {
            return true;
        }
        if page.questions.records.len() + page.host_events.records.len() <= 1 {
            return false;
        }
        if page.host_events.records.pop().is_none() {
            page.questions.records.pop();
        }
    }
}

/// Returns the encoded size of the frame that carries a page.
fn frame_size(page: &AttentionSourcePage) -> usize {
    measure(&kr_protocol::envelope::ControlFrame::AttentionSourcePage(
        Box::new(page.clone()),
    ))
}

/// Adds one record's encoded size to what the page uses, and answers whether it fits.
///
/// A page that carries nothing yet always takes its first record, so the reading moves on.
fn fits(used: &mut usize, cost: usize, max_bytes: usize, nothing_yet: bool) -> bool {
    let after = used.saturating_add(cost);
    if after > max_bytes && !nothing_yet {
        return false;
    }
    *used = after;
    true
}

fn carries_nothing(page: &AttentionSourcePage) -> bool {
    page.questions.records.is_empty() && page.host_events.records.is_empty()
}

/// Returns the encoded size of a value, as a frame carries it.
#[must_use]
pub fn measure<T: serde::Serialize>(value: &T) -> usize {
    crate::snapshot::wire::measure(value).map_or(usize::MAX, |cost| cost.bytes)
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
