//! Which package, if any, an agent word that the host does not compile in is declared by.

use kr_plugin_sdk::skill_target::{COMPILED_WORDS, SkillTarget};

/// One admitted package's declaration, read from its verified connector table.
#[derive(Clone, Debug)]
pub(crate) struct Declaration {
    /// What it declares.
    pub(crate) target: SkillTarget,
}

/// What the declarations say of one word.
#[derive(Debug)]
pub(crate) enum Pick<'a> {
    /// One of the six compiled words: the compiled layout is used and no declaration is served.
    Compiled,
    /// Exactly one admitted package declares it.
    One(&'a Declaration),
    /// No admitted package declares it.
    Nobody,
    /// More than one admitted package declares it, so none is served.
    Taken,
}

/// Picks the declaration of `word` from the declarations of the admitted packages that hold the
/// capability. A declaration that names a compiled word is never served over the compiled layout.
pub(crate) fn pick<'a>(word: &str, declarations: &'a [Declaration]) -> Pick<'a> {
    if COMPILED_WORDS.contains(&word) {
        return Pick::Compiled;
    }
    let mut found = declarations
        .iter()
        .filter(|declaration| declaration.target.word == word);
    match (found.next(), found.next()) {
        (None, _) => Pick::Nobody,
        (Some(only), None) => Pick::One(only),
        (Some(_), Some(_)) => Pick::Taken,
    }
}

/// The refusal of a word that more than one admitted package declares.
const TAKEN: &str =
    "{word} is named by more than one package this host admits, so it installs for none of them";

/// The declaration that serves `word`: the one admitted package's, none for a word the host
/// compiles in or one nobody declares (the installer then refuses it by name), and the refusal
/// where more than one package declares it.
pub(crate) fn served(
    word: &str,
    declarations: &[Declaration],
) -> Result<Option<SkillTarget>, String> {
    match pick(word, declarations) {
        Pick::One(declaration) => Ok(Some(declaration.target.clone())),
        Pick::Compiled | Pick::Nobody => Ok(None),
        Pick::Taken => Err(TAKEN.replace("{word}", word)),
    }
}

/// The refusal when the admissions changed while the packages were read.
const ADMISSIONS_MOVED: &str =
    "the packages this host admits changed while this request was read; ask again";

/// Whether the admissions are the ones the packages were read under: `now` is the revision read
/// again just before the dispatch marker, none where it could not be read in time. A request
/// whose admissions moved is refused before the marker; what is left is the time between this
/// read and the registration of the action.
pub(crate) fn admissions_held(read_at: u64, now: Option<u64>) -> Result<(), &'static str> {
    match now {
        Some(revision) if revision == read_at => Ok(()),
        _ => Err(ADMISSIONS_MOVED),
    }
}
