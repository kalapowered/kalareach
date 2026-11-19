//! The sentences the model is told, which live in one table.

use kr_protocol::voice_host::VoiceNote;

/// The files that may name a sentence for the model, and the constants of each that are not one:
/// the four the person reads, and the header that frames a context selection.
const SOURCES: [(&str, &str, &[&str]); 4] = [
    (
        "owner.rs",
        include_str!("../owner.rs"),
        &[
            "SPEECH_TAINTED_PERSON",
            "REQUESTS_UNSETTLED",
            "HOST_NOT_REACHED",
            "STANDING_WORDS",
        ],
    ),
    ("owner/ceremony.rs", include_str!("ceremony.rs"), &[]),
    (
        "voice_control.rs",
        include_str!("../../../../../../crates/kr-client/src/services/voice_control.rs"),
        &[],
    ),
    (
        "voice_pacing.rs",
        include_str!("../../../../../../crates/kr-client/src/services/voice_pacing.rs"),
        &["START_CONTEXT_HEADER"],
    ),
];

/// Every `const NAME: &str` item of the source, which a test module's own items are not.
fn string_constants(source: &str) -> Vec<String> {
    let product = source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(source);
    product
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let line = line.strip_prefix("pub(super) ").unwrap_or(line);
            let line = line.strip_prefix("pub(crate) ").unwrap_or(line);
            let line = line.strip_prefix("pub ").unwrap_or(line);
            let rest = line.strip_prefix("const ")?;
            let (name, kind) = rest.split_once(':')?;
            kind.trim_start()
                .starts_with("&str")
                .then(|| name.trim().to_owned())
        })
        .collect()
}

#[test]
fn no_model_sentence_constant_is_left_outside_the_note_table_in_the_device_and_the_managed_control()
{
    for (file, source, allowed) in SOURCES {
        let found = string_constants(source);
        let stray: Vec<&String> = found
            .iter()
            .filter(|name| !allowed.contains(&name.as_str()))
            .collect();
        assert!(
            stray.is_empty(),
            "{file} keeps {} sentence constant(s) outside the note table: {stray:?}",
            stray.len()
        );
    }
}

#[test]
fn each_note_variant_has_the_base_constants_words() {
    let base: [(VoiceNote, &str); 21] = [
        (
            VoiceNote::HostActionsUnavailable,
            "In this version the phone cannot act on the person's computer. If the person asks for something to be done there, say that nothing can be done from this call. Do not say or imply that anything was done.",
        ),
        (
            VoiceNote::HostActionsAvailable,
            "The phone can ask the person's computer to read some things when the person says so clearly. What you are told about each such request is all that is known of it: do not say or imply that anything was done that you were not told was done.",
        ),
        (
            VoiceNote::DelegationRefused,
            "Nothing was done on the person's computer: what was said could not be used as a request. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationNotSent,
            "Nothing was done on the person's computer: the request was not sent. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationUnknown,
            "It is not known whether this was done on the person's computer. Do not say it was done and do not say it was not. Say that it is not known.",
        ),
        (
            VoiceNote::DelegationAdmitted,
            "The person's computer accepted the request. Whether it was carried out is not known. Do not say it was done.",
        ),
        (
            VoiceNote::DelegationConfirmation,
            "This needs the person's confirmation on the phone's unlocked screen, which the phone is asking for now. Nothing was done yet. Do not say it was done.",
        ),
        (
            VoiceNote::DelegationNotConfirmed,
            "The person did not confirm it on the phone, so nothing was done. Say so, and say it can be asked for again.",
        ),
        (
            VoiceNote::DelegationNoCeremony,
            "Nothing was done: this phone cannot ask the person to confirm on its unlocked screen. Say so.",
        ),
        (
            VoiceNote::DelegationChallengeMismatch,
            "Nothing was done: what the computer asked the person to confirm was not what was said, so the person was not asked. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationConfirmationExpired,
            "Nothing was done: this phone's clock says the confirmation ran out. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationSessionNotNamed,
            "Nothing was done: this phone could not read the session's number from the person's computer, so the person was not asked. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationConfirmationDropped,
            "Nothing was done: the confirmation was not sent. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::DelegationHostRefused,
            "The person's computer refused the request. Nothing was done. Say so.",
        ),
        (
            VoiceNote::DelegationLate,
            "More was said that belongs to this request after it was read, so the request is not carried out. Say so, and ask the person to say it again.",
        ),
        (
            VoiceNote::SpeechTainted,
            "This call can no longer act on what the person says: part of it may not have been heard or recorded here. Nothing is done on the person's computer from this call. Say so if asked.",
        ),
        (
            VoiceNote::DelegationPerformed,
            "The person's computer read it. Say what it reports:",
        ),
        (
            VoiceNote::NothingWasDone,
            "Nothing was done on the person's computer: this version does not act on spoken requests. Say so.",
        ),
        (
            VoiceNote::HostLost,
            "The phone has lost contact with the person's computer. The call goes on, but nothing can be read from or done on the computer until it is back. Do not say or imply that anything was done there.",
        ),
        (
            VoiceNote::HostBack,
            "The phone is in contact with the person's computer again. Nothing was done there while it was away.",
        ),
        (
            VoiceNote::HostBackAccepting,
            "The phone is in contact with the person's computer again.",
        ),
    ];
    for (note, words) in base {
        assert_eq!(
            note.words(),
            words,
            "{note:?} changed the words the model is told"
        );
    }
    let named: std::collections::BTreeSet<_> = base.iter().map(|(note, _)| *note).collect();
    assert_eq!(
        named.len(),
        VoiceNote::ALL.len(),
        "every variant has a base sentence"
    );
}
