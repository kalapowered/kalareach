//! Context selection: the bounded default, the exclusions, the cap and the secondary stripping.
//!
//! Section 15 ¶12 states the default: session description, current working directory, active
//! application, pending decision summaries and the last twenty semantic messages, capped at eight
//! thousand text tokens. File contents, environment variables, raw terminal scrollback and
//! attachment bytes are excluded unless the person selects them.
//!
//! # The history bound is checked twice
//!
//! The host filters, at `Surface::VoiceContext`, under a viewer scope built from the requesting
//! device's grant. That is section 10's "enforced once in shared host-side filtering", and this
//! module does not filter a second time in that sense: it does not decide what the surface may
//! see. What it does is refuse to carry an item whose timestamp is outside the very grant it was
//! handed. A host that passed the wrong scope, or gathered before it filtered, does not get that
//! mistake past this crate, and the refusal is counted as withheld rather than hidden.
//!
//! # Stripping is secondary
//!
//! [`SecretPatterns`] replaces the shapes an operator configured. Section 15 ¶12 is explicit that
//! this is a secondary measure and that filtering does not prove the remaining content holds no
//! secrets, so every selection carries that sentence and the count of what was replaced.
//!
//! # Project text is data
//!
//! Everything selected here is project text. The separation from application-authored instructions
//! is in the types: [`Selection`] produces
//! [`VoiceContextSelection`](kr_protocol::voice::VoiceContextSelection), and instructions are
//! [`VoiceInstructions`](kr_protocol::voice::VoiceInstructions), which this module cannot produce
//! and never touches.

use kr_protocol::grant::Grant;
use kr_protocol::scalars::{CanonicalSet, TimestampMs, U64};
use kr_protocol::voice::{
    VOICE_CONTEXT_MESSAGE_COUNT, VOICE_CONTEXT_TOKEN_CAP, VOICE_DISCLOSURE, VOICE_STRIPPING_NOTE,
    VoiceContextClass, VoiceContextProvenance, VoiceContextSelection, VoiceSelectedContent,
    VoiceWithheld,
};

use crate::seams::{ContextItem, GatheredContext, SelectedItem};

/// What one selection came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// The bounded projection the paired client receives.
    pub selection: VoiceContextSelection,
    /// Where it came from.
    pub provenance: VoiceContextProvenance,
    /// What was kept out, by reason.
    pub withheld: Vec<VoiceWithheld>,
    /// What the person is told about who can read it.
    pub disclosure: Vec<String>,
}

/// The reason an item outside the grant's history bound is reported under.
const OUTSIDE_BOUND: &str = "outside the grant's history lower bound";

/// The reason an item dropped by the token cap is reported under.
const OVER_CAP: &str = "beyond the 8,000-token context cap";

/// The reason a class the person did not select is reported under.
const NOT_SELECTED: &str = "a content class this call did not select";

/// A conservative estimate of the text tokens a string costs.
///
/// The host cannot run the provider's encoder, so it counts something that does not
/// under-estimate for ordinary prose: one token per four characters, rounded up, and at least one
/// per whitespace-separated word. The cap is then enforced by dropping whole items rather than by
/// trusting the figure to the token, so an estimate that is a little high costs a message and an
/// estimate that is a little low still cannot run away with the budget.
#[must_use]
pub fn text_tokens(text: &str) -> u32 {
    let characters = u32::try_from(text.chars().count()).unwrap_or(u32::MAX);
    let words = u32::try_from(text.split_whitespace().count()).unwrap_or(u32::MAX);
    characters.div_ceil(4).max(words)
}

/// The secret shapes an operator has configured.
///
/// Held as literal prefixes and assignment names rather than as patterns compiled at runtime: an
/// operator configuring this is naming the credentials their organisation issues, and a shape
/// nobody can read is a shape nobody can check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretPatterns {
    prefixes: Vec<SecretPrefix>,
    assignment_names: Vec<String>,
}

/// One credential shape: a literal prefix followed by a run of credential characters.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SecretPrefix {
    prefix: String,
    least_tail: usize,
}

impl Default for SecretPatterns {
    /// The shapes this host replaces when an operator has configured nothing else.
    ///
    /// Deliberately a short list of well-known issued-credential prefixes and the assignment names
    /// that carry a secret in configuration and in shell history. It is not an attempt to
    /// recognise every secret, which is why the note beside every selection says so.
    fn default() -> Self {
        Self {
            prefixes: [
                ("sk-", 20),
                ("ghp_", 20),
                ("gho_", 20),
                ("github_pat_", 20),
                ("xoxb-", 10),
                ("xoxp-", 10),
                ("AKIA", 16),
                ("ASIA", 16),
                ("AIza", 20),
                ("Bearer ", 16),
                ("-----BEGIN ", 8),
            ]
            .into_iter()
            .map(|(prefix, least_tail)| SecretPrefix {
                prefix: prefix.to_owned(),
                least_tail,
            })
            .collect(),
            assignment_names: [
                "password",
                "passwd",
                "secret",
                "token",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "private_key",
                "authorization",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        }
    }
}

/// What replaces a run this host recognised.
pub const REDACTION: &str = "[redacted]";

impl SecretPatterns {
    /// Builds a pattern set from an operator's own configuration.
    ///
    /// `prefixes` are literal starts followed by at least `least_tail` credential characters;
    /// `assignment_names` are the names whose value is replaced in `name=value` and `name: value`.
    #[must_use]
    pub fn new(prefixes: Vec<(String, usize)>, assignment_names: Vec<String>) -> Self {
        Self {
            prefixes: prefixes
                .into_iter()
                .map(|(prefix, least_tail)| SecretPrefix { prefix, least_tail })
                .collect(),
            assignment_names: assignment_names
                .into_iter()
                .map(|name| name.to_lowercase())
                .collect(),
        }
    }

    /// A set that replaces nothing, for a host whose operator turned stripping off.
    ///
    /// It changes what is replaced and not what the note says: the note is about what filtering
    /// establishes, which is the same whether or not anything matched.
    #[must_use]
    pub fn none() -> Self {
        Self {
            prefixes: Vec::new(),
            assignment_names: Vec::new(),
        }
    }

    /// Replaces every run this set recognises, and returns the text and how many went.
    #[must_use]
    pub fn strip(&self, text: &str) -> (String, u32) {
        let mut replaced = 0u32;
        let stripped = self.strip_prefixes(text, &mut replaced);
        let stripped = self.strip_assignments(&stripped, &mut replaced);
        (stripped, replaced)
    }

    fn strip_prefixes(&self, text: &str, replaced: &mut u32) -> String {
        let mut out = String::with_capacity(text.len());
        let characters: Vec<char> = text.chars().collect();
        let mut index = 0usize;
        'outer: while index < characters.len() {
            for pattern in &self.prefixes {
                let prefix: Vec<char> = pattern.prefix.chars().collect();
                if characters[index..].starts_with(&prefix) {
                    let mut end = index + prefix.len();
                    while end < characters.len() && is_credential_character(characters[end]) {
                        end += 1;
                    }
                    if end - index - prefix.len() >= pattern.least_tail {
                        out.push_str(REDACTION);
                        *replaced = replaced.saturating_add(1);
                        index = end;
                        continue 'outer;
                    }
                }
            }
            out.push(characters[index]);
            index += 1;
        }
        out
    }

    fn strip_assignments(&self, text: &str, replaced: &mut u32) -> String {
        if self.assignment_names.is_empty() {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        for (position, line) in text.split_inclusive('\n').enumerate() {
            let _ = position;
            out.push_str(&self.strip_assignment_line(line, replaced));
        }
        out
    }

    fn strip_assignment_line(&self, line: &str, replaced: &mut u32) -> String {
        // Offsets are found in the line itself, matched case-insensitively character by character.
        // Searching a lower-cased copy and slicing the original with its offsets is wrong: case
        // folding changes byte lengths for some characters, so an offset from the copy can land
        // inside a character of the original and the slice panics.
        let mut best: Option<(usize, usize)> = None;
        for name in &self.assignment_names {
            for (start, _) in line.char_indices() {
                let Some(after) = matches_name(line, start, name) else {
                    continue;
                };
                // The name has to stand on its own, so `tokens` does not match `token`.
                if line[..start]
                    .chars()
                    .next_back()
                    .is_some_and(is_name_character)
                {
                    continue;
                }
                let separator = line[after..]
                    .char_indices()
                    .find(|(_, character)| !character.is_whitespace());
                if let Some((offset, character)) = separator
                    && matches!(character, '=' | ':')
                {
                    let value_from = after + offset + character.len_utf8();
                    if best.is_none_or(|(existing, _)| start < existing) {
                        best = Some((start, value_from));
                    }
                }
            }
        }
        match best {
            Some((_, value_from)) => {
                let value = &line[value_from..];
                let trailing_newline = value.ends_with('\n');
                let body = value.trim();
                if body.is_empty() {
                    return line.to_owned();
                }
                *replaced = replaced.saturating_add(1);
                let mut out = String::with_capacity(line.len());
                out.push_str(&line[..value_from]);
                out.push(' ');
                out.push_str(REDACTION);
                if trailing_newline {
                    out.push('\n');
                }
                out
            }
            None => line.to_owned(),
        }
    }
}

/// Whether `name` appears at `start` in `line`, ignoring case, and where it ends.
///
/// Compared character by character against the line's own characters, so every offset this returns
/// is an offset into the line rather than into a converted copy of it.
fn matches_name(line: &str, start: usize, name: &str) -> Option<usize> {
    let mut wanted = name.chars();
    let mut end = start;
    for held in line[start..].chars() {
        let Some(wanted) = wanted.next() else { break };
        if !held.to_lowercase().eq(wanted.to_lowercase()) {
            return None;
        }
        end += held.len_utf8();
    }
    wanted.next().is_none().then_some(end)
}

fn is_credential_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '+' | '/' | '=')
}

fn is_name_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Selects the bounded context of section 15 ¶12 from what the host gathered.
///
/// `grant` is the requesting device's, and is the only scope this selection uses. An item outside
/// its history lower bound is dropped and counted; a class the person did not select is dropped
/// and counted; and the cap is applied last, over the whole selection.
#[must_use]
pub fn select_context(
    gathered: &GatheredContext,
    grant: &Grant,
    selected_classes: &CanonicalSet<VoiceContextClass>,
    patterns: &SecretPatterns,
) -> Selection {
    let lower_bound = grant.history.lower_bound_ms.0.map(TimestampMs::get);
    let mut budget = Budget::new(VOICE_CONTEXT_TOKEN_CAP);
    let mut outside = 0u64;
    let mut over_cap = 0u64;
    let mut not_selected = 0u64;
    let mut stripped_total = 0u32;
    let mut from_ms = u64::MAX;
    let mut to_ms = 0u64;

    let admit = |item: &ContextItem,
                 outside: &mut u64,
                 over_cap: &mut u64,
                 stripped_total: &mut u32,
                 budget: &mut Budget,
                 from_ms: &mut u64,
                 to_ms: &mut u64|
     -> Option<String> {
        // The bound the host already applied, applied again to what it handed over. A grant with
        // no lower bound sees no retained history at all, which is the strictest reading and the
        // one section 10 states.
        let Some(bound) = lower_bound else {
            *outside += 1;
            return None;
        };
        if item.produced_at_ms < bound {
            *outside += 1;
            return None;
        }
        let (text, replaced) = patterns.strip(&item.text);
        if !budget.take(text_tokens(&text)) {
            *over_cap += 1;
            return None;
        }
        *stripped_total = stripped_total.saturating_add(replaced);
        *from_ms = (*from_ms).min(item.produced_at_ms);
        *to_ms = (*to_ms).max(item.produced_at_ms);
        Some(text)
    };

    let single = |item: Option<&ContextItem>,
                  outside: &mut u64,
                  over_cap: &mut u64,
                  stripped_total: &mut u32,
                  budget: &mut Budget,
                  from_ms: &mut u64,
                  to_ms: &mut u64|
     -> String {
        item.and_then(|item| {
            admit(
                item,
                outside,
                over_cap,
                stripped_total,
                budget,
                from_ms,
                to_ms,
            )
        })
        .unwrap_or_default()
    };

    let session_description = single(
        gathered.session_description.as_ref(),
        &mut outside,
        &mut over_cap,
        &mut stripped_total,
        &mut budget,
        &mut from_ms,
        &mut to_ms,
    );
    let working_directory = single(
        gathered.working_directory.as_ref(),
        &mut outside,
        &mut over_cap,
        &mut stripped_total,
        &mut budget,
        &mut from_ms,
        &mut to_ms,
    );
    let active_application = single(
        gathered.active_application.as_ref(),
        &mut outside,
        &mut over_cap,
        &mut stripped_total,
        &mut budget,
        &mut from_ms,
        &mut to_ms,
    );

    let mut pending_decisions = Vec::new();
    for item in &gathered.pending_decisions {
        if let Some(text) = admit(
            item,
            &mut outside,
            &mut over_cap,
            &mut stripped_total,
            &mut budget,
            &mut from_ms,
            &mut to_ms,
        ) {
            pending_decisions.push(text);
        }
    }

    // The last twenty, oldest first. Taking the tail before the cap is deliberate: an older
    // message that the cap would have room for is still not one of the last twenty.
    let messages = gathered.recent_messages.len();
    let keep_from = messages.saturating_sub(VOICE_CONTEXT_MESSAGE_COUNT as usize);
    let mut recent_messages = Vec::new();
    for item in &gathered.recent_messages[keep_from..] {
        if let Some(text) = admit(
            item,
            &mut outside,
            &mut over_cap,
            &mut stripped_total,
            &mut budget,
            &mut from_ms,
            &mut to_ms,
        ) {
            recent_messages.push(text);
        }
    }

    let mut selected: Vec<VoiceSelectedContent> = Vec::new();
    for SelectedItem { class, item } in &gathered.selected {
        if !selected_classes.contains(class) {
            // Excluded until the person selects it. A host that offered it anyway is not the
            // person selecting it.
            not_selected += 1;
            continue;
        }
        if let Some(text) = admit(
            item,
            &mut outside,
            &mut over_cap,
            &mut stripped_total,
            &mut budget,
            &mut from_ms,
            &mut to_ms,
        ) {
            selected.push(VoiceSelectedContent {
                class: *class,
                text,
            });
        }
    }

    let mut withheld: Vec<VoiceWithheld> = gathered
        .withheld
        .iter()
        .map(|run| VoiceWithheld {
            reason: run.reason.clone(),
            count: U64::new(run.count),
        })
        .collect();
    for (reason, count) in [
        (OUTSIDE_BOUND, outside),
        (OVER_CAP, over_cap),
        (NOT_SELECTED, not_selected),
    ] {
        if count > 0 {
            withheld.push(VoiceWithheld {
                reason: reason.to_owned(),
                count: U64::new(count),
            });
        }
    }

    // An empty selection still names an interval, and naming the moment nothing was read is
    // honest: a zero-to-zero interval says the selection rests on nothing.
    let (from_ms, to_ms) = if from_ms > to_ms {
        (0, 0)
    } else {
        (from_ms, to_ms)
    };

    Selection {
        selection: VoiceContextSelection {
            session_description,
            working_directory,
            active_application,
            pending_decisions,
            recent_messages,
            selected,
            text_tokens: budget.spent(),
            truncated: over_cap > 0,
            secrets_stripped: stripped_total,
            stripping_note: VOICE_STRIPPING_NOTE.to_owned(),
        },
        provenance: VoiceContextProvenance {
            from_ms: TimestampMs::new(from_ms),
            to_ms: TimestampMs::new(to_ms),
            resources: gathered.resources.clone(),
        },
        withheld,
        disclosure: VOICE_DISCLOSURE
            .iter()
            .map(|line| (*line).to_owned())
            .collect(),
    }
}

/// The token budget, spent whole item by whole item.
#[derive(Debug)]
struct Budget {
    cap: u32,
    spent: u32,
}

impl Budget {
    const fn new(cap: u32) -> Self {
        Self { cap, spent: 0 }
    }

    /// Takes `tokens` from the budget, or refuses and leaves the budget alone.
    fn take(&mut self, tokens: u32) -> bool {
        let Some(after) = self.spent.checked_add(tokens) else {
            return false;
        };
        if after > self.cap {
            return false;
        }
        self.spent = after;
        true
    }

    const fn spent(&self) -> u32 {
        self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
    use kr_protocol::ids::{AuthorityRevision, DeviceId, EnvironmentId, GrantId};
    use kr_protocol::rights::ActionRight;
    use kr_protocol::scalars::{Nullable, Uuid};

    fn grant(lower_bound_ms: Option<u64>) -> Grant {
        Grant {
            grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
            parent_grant_id: Nullable::null(),
            issuer_device_id: DeviceId::new(Uuid::from_bytes([0xf0; 16])),
            recipient_device_id: DeviceId::new(Uuid::from_bytes([0xf1; 16])),
            authority_revision: AuthorityRevision::new(1),
            environment_selector: EnvironmentSelector::These {
                environment_ids: [EnvironmentId::new(Uuid::from_bytes([0xe0; 16]))]
                    .into_iter()
                    .collect(),
            },
            session_selector: SessionSelector::Any,
            actions: [ActionRight::SessionView, ActionRight::VoiceUse]
                .into_iter()
                .collect(),
            history: HistoryScope {
                lower_bound_ms: Nullable(lower_bound_ms.map(TimestampMs::new)),
                include_live_screen: true,
                named_questions: CanonicalSet::from_iter([]),
                named_approvals: CanonicalSet::from_iter([]),
            },
            expiry: GrantExpiry::Never,
            organisation: Nullable::null(),
        }
    }

    fn gathered() -> GatheredContext {
        GatheredContext {
            session_description: Some(ContextItem::new("building the voice coordinator", 2_000)),
            working_directory: Some(ContextItem::new("/work/kalareach", 2_000)),
            active_application: Some(ContextItem::new("an editor", 2_000)),
            pending_decisions: vec![ContextItem::new("apply the diff to main?", 2_100)],
            recent_messages: (0..25)
                .map(|index| ContextItem::new(format!("message {index}"), 2_000 + index))
                .collect(),
            selected: vec![SelectedItem {
                class: VoiceContextClass::FileContents,
                item: ContextItem::new("the file the person chose", 2_200),
            }],
            resources: vec!["session:1".to_owned()],
            withheld: Vec::new(),
        }
    }

    #[test]
    fn the_default_selection_is_the_five_things_section_fifteen_names() {
        let selection = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert_eq!(
            selection.selection.session_description,
            "building the voice coordinator"
        );
        assert_eq!(selection.selection.working_directory, "/work/kalareach");
        assert_eq!(selection.selection.active_application, "an editor");
        assert_eq!(selection.selection.pending_decisions.len(), 1);
        assert_eq!(
            selection.selection.recent_messages.len(),
            VOICE_CONTEXT_MESSAGE_COUNT as usize,
            "the last twenty and no more"
        );
        assert_eq!(selection.selection.recent_messages[0], "message 5");
    }

    #[test]
    fn an_excluded_class_stays_out_until_the_person_selects_it() {
        let excluded = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(excluded.selection.selected.is_empty());
        assert!(
            excluded
                .withheld
                .iter()
                .any(|run| run.reason == NOT_SELECTED)
        );

        let chosen = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &[VoiceContextClass::FileContents].into_iter().collect(),
            &SecretPatterns::default(),
        );
        assert_eq!(chosen.selection.selected.len(), 1);
        assert_eq!(
            chosen.selection.selected[0].class,
            VoiceContextClass::FileContents
        );
    }

    #[test]
    fn content_older_than_the_grants_bound_never_reaches_the_selection() {
        // Few enough that the tail-of-twenty keeps every one of them, so what drops the old
        // message is the bound rather than its position.
        let mut gathered = gathered();
        gathered.recent_messages.truncate(3);
        gathered
            .recent_messages
            .insert(0, ContextItem::new("from before the bound", 10));
        let selection = select_context(
            &gathered,
            &grant(Some(2_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(
            !selection
                .selection
                .recent_messages
                .iter()
                .any(|text| text == "from before the bound")
        );
        assert!(
            selection
                .withheld
                .iter()
                .any(|run| run.reason == OUTSIDE_BOUND && run.count.get() > 0)
        );
    }

    #[test]
    fn a_grant_with_no_retained_history_selects_nothing() {
        let selection = select_context(
            &gathered(),
            &grant(None),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(selection.selection.session_description.is_empty());
        assert!(selection.selection.recent_messages.is_empty());
        assert_eq!(selection.selection.text_tokens, 0);
    }

    #[test]
    fn the_cap_stops_a_selection_and_says_it_was_cut() {
        let long = "word ".repeat(4_000);
        let gathered = GatheredContext {
            recent_messages: vec![
                ContextItem::new(long.clone(), 3_000),
                ContextItem::new(long, 3_001),
            ],
            ..gathered()
        };
        let selection = select_context(
            &gathered,
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(selection.selection.text_tokens <= VOICE_CONTEXT_TOKEN_CAP);
        assert!(selection.selection.truncated);
        assert!(selection.withheld.iter().any(|run| run.reason == OVER_CAP));
    }

    #[test]
    fn a_recognised_credential_is_replaced_and_counted() {
        let patterns = SecretPatterns::default();
        let (text, replaced) =
            patterns.strip("run it with sk-abcdefghijklmnopqrstuvwxyz0123 please");
        assert!(!text.contains("abcdefghijklmnop"), "{text}");
        assert!(text.contains(REDACTION));
        assert_eq!(replaced, 1);

        let (text, replaced) = patterns.strip("export API_KEY=hunter2-and-more\n");
        assert!(!text.contains("hunter2"), "{text}");
        assert_eq!(replaced, 1);

        // A name that only looks like one is left alone.
        let (text, replaced) = patterns.strip("tokens: 42\n");
        assert_eq!(text, "tokens: 42\n");
        assert_eq!(replaced, 0);
    }

    #[test]
    fn text_whose_case_folding_changes_its_length_is_stripped_rather_than_breaking() {
        // `İ` lower-cases to two characters, so an offset taken from a lower-cased copy would land
        // inside the following character. Every one of these has to come back, replaced or not.
        let patterns = SecretPatterns::default();
        for line in [
            "İ token=é\n",
            "TOKEN: héllo-wörld\n",
            "ﬁle token = value\n",
            "İİİ nothing here\n",
            "Token=İ\n",
        ] {
            let (text, _) = patterns.strip(line);
            assert!(!text.is_empty(), "{line}");
        }
        let (text, replaced) = patterns.strip("İ token=é\n");
        assert!(text.contains(REDACTION), "{text}");
        assert_eq!(replaced, 1);
    }

    #[test]
    fn stripping_never_claims_the_remainder_is_clean() {
        let selection = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(
            selection
                .selection
                .stripping_note
                .contains("does not prove")
        );
        assert_eq!(
            selection.selection.secrets_stripped, 0,
            "nothing matched, which is not a claim that nothing is there"
        );
    }

    #[test]
    fn a_selection_names_the_interval_and_the_resources_it_read() {
        let selection = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert_eq!(selection.provenance.from_ms.get(), 2_000);
        assert!(selection.provenance.to_ms.get() >= 2_100);
        assert_eq!(selection.provenance.resources, vec!["session:1".to_owned()]);
    }

    #[test]
    fn a_selection_states_what_the_operator_can_see() {
        let selection = select_context(
            &gathered(),
            &grant(Some(1_000)),
            &CanonicalSet::from_iter([]),
            &SecretPatterns::default(),
        );
        assert!(
            selection
                .disclosure
                .iter()
                .any(|line| line.contains("transcripts"))
        );
    }

    #[test]
    fn the_token_estimate_never_reads_as_free() {
        assert_eq!(text_tokens(""), 0);
        assert!(text_tokens("a b c d") >= 4);
        assert!(text_tokens(&"x".repeat(400)) >= 100);
    }
}
