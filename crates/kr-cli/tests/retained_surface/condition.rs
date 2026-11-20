//! The condition rule: which code a configuration without `test` can compile.
//!
//! Product code is what some supported configuration with `test` false builds. A configuration is
//! one of five platforms, each with its own `unix`, `windows`, `mobile`, `desktop`, `target_os`,
//! `target_family` and `target_vendor`, and one value for every other atom the source uses
//! (`feature = "..."`, `debug_assertions`, `target_arch = "..."` and the rest of `FREE`). `cfg` is read by structure: `all`, `any`, `not`,
//! a name, a name with a string. A place is read when some configuration enables every `cfg`
//! around it; a predicate on an atom outside this set, or a `cfg_attr` that would add a `cfg` or a
//! `path`, is an error and is never skipped.

use std::collections::BTreeSet;
use std::rc::Rc;

use quote::ToTokens as _;
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Ident, Lit, LitBool, Meta, Token};

/// A supported platform with the atoms that depend on it.
struct Platform {
    unix: bool,
    windows: bool,
    mobile: bool,
    os: &'static str,
    family: &'static str,
    vendor: &'static str,
}

/// The platforms the product is built for: the desktop systems and the two the companion ships
/// on. `desktop` is the one that is not `mobile`.
const PLATFORMS: [Platform; 5] = [
    Platform {
        unix: true,
        windows: false,
        mobile: false,
        os: "macos",
        family: "unix",
        vendor: "apple",
    },
    Platform {
        unix: true,
        windows: false,
        mobile: false,
        os: "linux",
        family: "unix",
        vendor: "unknown",
    },
    Platform {
        unix: false,
        windows: true,
        mobile: false,
        os: "windows",
        family: "windows",
        vendor: "pc",
    },
    Platform {
        unix: true,
        windows: false,
        mobile: true,
        os: "ios",
        family: "unix",
        vendor: "apple",
    },
    Platform {
        unix: true,
        windows: false,
        mobile: true,
        os: "android",
        family: "unix",
        vendor: "unknown",
    },
];

/// The atoms that any configuration may set either way, with or without a value.
const FREE: [&str; 7] = [
    "debug_assertions",
    "feature",
    "target_arch",
    "target_feature",
    "target_pointer_width",
    "target_endian",
    "target_env",
];

/// The most free atoms one place may hold: each adds a doubling to the configurations tried.
const MOST_FREE: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Predicate {
    Always(bool),
    Test,
    Unix,
    Windows,
    Mobile,
    Desktop,
    Os(String),
    Family(String),
    Vendor(String),
    Free(String),
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
}

/// The conditions around a place, all of which must hold.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Condition(Rc<Vec<Predicate>>);

impl Condition {
    /// The condition of a target that Cargo builds only with these features.
    pub fn requiring(features: &[String]) -> Self {
        Self(Rc::new(
            features
                .iter()
                .map(|feature| Predicate::Free(format!("feature={feature}")))
                .collect(),
        ))
    }

    /// The condition under which some one of the `visits` holds: the conditions a file is reached
    /// under, one for each declaration that reaches it.
    pub fn any_of(visits: &[Self]) -> Self {
        if visits.iter().any(|visit| visit.0.is_empty()) {
            return Self::default();
        }
        match visits {
            [one] => one.clone(),
            _ => Self(Rc::new(vec![Predicate::Any(
                visits
                    .iter()
                    .map(|visit| Predicate::All((*visit.0).clone()))
                    .collect(),
            )])),
        }
    }

    /// The conditions of a place whose attributes are `attrs` inside this one: `None` where no
    /// configuration enables them all. `at` names the file for the error.
    pub fn within(&self, attrs: &[Attribute], at: &str) -> Result<Option<Self>, String> {
        let mut added = Vec::new();
        let mut sets = None;
        for attribute in attrs {
            if attribute.path().is_ident("cfg") {
                let meta = attribute
                    .parse_args_with(parse_meta)
                    .map_err(|_| unreadable(at, &attribute.to_token_stream().to_string()))?;
                added.push(predicate(&meta, at)?);
            } else if attribute.path().is_ident("cfg_attr") {
                let listed = attribute
                    .parse_args_with(parse_metas)
                    .map_err(|_| unreadable(at, &attribute.to_token_stream().to_string()))?;
                let adds = sets_path_or_condition(&listed);
                if adds && sets.is_none() {
                    sets = Some(format!(
                        "{at}: the scan does not read a cfg_attr that sets a path or a condition ({})",
                        attribute.to_token_stream()
                    ));
                }
            }
        }
        // A predicate that already holds around the place adds nothing, so a condition that a
        // cycle of declarations carries again is the one it had.
        added.retain(|predicate| !self.0.contains(predicate));
        if added.is_empty() {
            return match sets {
                Some(error) => Err(error),
                None => Ok(Some(self.clone())),
            };
        }
        let mut all = (*self.0).clone();
        all.extend(added);
        // What no configuration builds is not read, whatever else is written on it.
        if !enabled(&all, at)? {
            return Ok(None);
        }
        match sets {
            Some(error) => Err(error),
            None => Ok(Some(Self(Rc::new(all)))),
        }
    }
}

impl Condition {
    /// Whether `attrs` carry `#[name]` in some configuration without `test` that this condition
    /// allows: written as it is, or added by a `cfg_attr` whose predicate some such configuration
    /// enables. A predicate the rule cannot read is its error.
    pub fn carries(&self, attrs: &[Attribute], name: &str, at: &str) -> Result<bool, String> {
        for attribute in attrs {
            if attribute.path().is_ident(name) {
                return Ok(true);
            }
            if attribute.path().is_ident("cfg_attr") {
                let listed = attribute
                    .parse_args_with(parse_metas)
                    .map_err(|_| unreadable(at, &attribute.to_token_stream().to_string()))?;
                if self.added_by(&listed, name, &mut Vec::new(), at)? {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Whether the `cfg_attr` whose arguments are `listed`, under the predicates `guards` of the
    /// `cfg_attr`s around it, adds `#[name]` where some configuration enables all of them.
    fn added_by(
        &self,
        listed: &Punctuated<Meta, Token![,]>,
        name: &str,
        guards: &mut Vec<Meta>,
        at: &str,
    ) -> Result<bool, String> {
        let mut parts = listed.iter();
        let Some(guard) = parts.next() else {
            return Ok(false);
        };
        guards.push(guard.clone());
        let mut found = false;
        for meta in parts {
            if meta.path().is_ident(name) {
                let all: Vec<&Meta> = guards.iter().collect();
                let tested: Attribute = syn::parse_quote!(#[cfg(all(#(#all),*))]);
                found = self.within(&[tested], at)?.is_some();
            } else if let Meta::List(list) = meta
                && list.path.is_ident("cfg_attr")
            {
                let inner = list
                    .parse_args_with(parse_metas)
                    .map_err(|_| unreadable(at, &meta.to_token_stream().to_string()))?;
                found = self.added_by(&inner, name, guards, at)?;
            }
            if found {
                break;
            }
        }
        guards.pop();
        Ok(found)
    }
}

/// Whether the attributes a `cfg_attr` adds (after its predicate) set a path or a condition,
/// looking into a `cfg_attr` it holds.
fn sets_path_or_condition(listed: &Punctuated<Meta, Token![,]>) -> bool {
    listed.iter().skip(1).any(|meta| match meta {
        Meta::List(list) if list.path.is_ident("cfg_attr") => list
            .parse_args_with(parse_metas)
            .map_or(true, |inner| sets_path_or_condition(&inner)),
        _ => ["cfg", "path"]
            .iter()
            .any(|name| meta.path().is_ident(name)),
    })
}

fn unreadable(at: &str, text: &str) -> String {
    format!("{at}: the scan cannot read the condition {text}")
}

/// One meta item as a `cfg` writes it. `syn` takes no `true` or `false` as the outermost path of a
/// meta item, and a predicate may be either.
fn parse_meta(input: ParseStream) -> syn::Result<Meta> {
    if input.peek(LitBool) {
        let flag: LitBool = input.parse()?;
        let name = if flag.value { "true" } else { "false" };
        return Ok(Meta::Path(Ident::new(name, flag.span()).into()));
    }
    input.parse()
}

/// The meta items of a list, each read by `parse_meta`.
fn parse_metas(input: ParseStream) -> syn::Result<Punctuated<Meta, Token![,]>> {
    Punctuated::parse_terminated_with(input, parse_meta)
}

fn predicate(meta: &Meta, at: &str) -> Result<Predicate, String> {
    let bad = || unreadable(at, &meta.to_token_stream().to_string());
    match meta {
        Meta::Path(path) => {
            let name = path.get_ident().ok_or_else(bad)?.to_string();
            match name.as_str() {
                "test" => Ok(Predicate::Test),
                "unix" => Ok(Predicate::Unix),
                "windows" => Ok(Predicate::Windows),
                "mobile" => Ok(Predicate::Mobile),
                "desktop" => Ok(Predicate::Desktop),
                "true" => Ok(Predicate::Always(true)),
                "false" => Ok(Predicate::Always(false)),
                other if FREE.contains(&other) && other != "feature" => Ok(Predicate::Free(name)),
                _ => Err(bad()),
            }
        }
        Meta::NameValue(pair) => {
            let name = pair.path.get_ident().ok_or_else(bad)?.to_string();
            let Expr::Lit(literal) = &pair.value else {
                return Err(bad());
            };
            let Lit::Str(value) = &literal.lit else {
                return Err(bad());
            };
            let value = value.value();
            match name.as_str() {
                "target_os" => Ok(Predicate::Os(value)),
                "target_family" => Ok(Predicate::Family(value)),
                "target_vendor" => Ok(Predicate::Vendor(value)),
                other if FREE.contains(&other) => Ok(Predicate::Free(format!("{name}={value}"))),
                _ => Err(bad()),
            }
        }
        Meta::List(list) => {
            let name = list.path.get_ident().ok_or_else(bad)?.to_string();
            let inner = list
                .parse_args_with(parse_metas)
                .map_err(|_| bad())?
                .iter()
                .map(|meta| predicate(meta, at))
                .collect::<Result<Vec<_>, _>>()?;
            match name.as_str() {
                "all" => Ok(Predicate::All(inner)),
                "any" => Ok(Predicate::Any(inner)),
                "not" if inner.len() == 1 => Ok(Predicate::Not(Box::new(
                    inner.into_iter().next().expect("one predicate"),
                ))),
                _ => Err(bad()),
            }
        }
    }
}

fn free_atoms(predicate: &Predicate, out: &mut BTreeSet<String>) {
    match predicate {
        Predicate::Free(name) => {
            out.insert(name.clone());
        }
        Predicate::All(inner) | Predicate::Any(inner) => {
            inner.iter().for_each(|inner| free_atoms(inner, out));
        }
        Predicate::Not(inner) => free_atoms(inner, out),
        _ => {}
    }
}

fn holds(predicate: &Predicate, platform: &Platform, set: &BTreeSet<&String>) -> bool {
    match predicate {
        Predicate::Always(value) => *value,
        Predicate::Test => false,
        Predicate::Unix => platform.unix,
        Predicate::Windows => platform.windows,
        Predicate::Mobile => platform.mobile,
        Predicate::Desktop => !platform.mobile,
        Predicate::Os(value) => platform.os == value,
        Predicate::Family(value) => platform.family == value,
        Predicate::Vendor(value) => platform.vendor == value,
        Predicate::Free(name) => set.contains(name),
        Predicate::All(inner) => inner.iter().all(|inner| holds(inner, platform, set)),
        Predicate::Any(inner) => inner.iter().any(|inner| holds(inner, platform, set)),
        Predicate::Not(inner) => !holds(inner, platform, set),
    }
}

/// Whether some configuration with `test` false makes every predicate true.
fn enabled(predicates: &[Predicate], at: &str) -> Result<bool, String> {
    let mut atoms = BTreeSet::new();
    predicates
        .iter()
        .for_each(|predicate| free_atoms(predicate, &mut atoms));
    if atoms.len() > MOST_FREE {
        return Err(unreadable(at, "(more atoms than the scan tries together)"));
    }
    let atoms: Vec<&String> = atoms.iter().collect();
    for platform in &PLATFORMS {
        for bits in 0..(1_u32 << atoms.len()) {
            let set: BTreeSet<&String> = atoms
                .iter()
                .enumerate()
                .filter(|(at, _)| bits >> at & 1 == 1)
                .map(|(_, atom)| *atom)
                .collect();
            if predicates
                .iter()
                .all(|predicate| holds(predicate, platform, &set))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
