//! The condition rule: which code a configuration without `test` can compile, for the digests' index.
//!
//! `cfg` is read by structure (`all`, `any`, `not`, `true`, `false`, a name, a name with a string)
//! with three values. `test` is false, and every other name or name with a string is unknown. A
//! place is skipped when one `cfg` around it is false, and read otherwise, so `all(test, unix)` and
//! `not(not(test))` are skipped, and `any(test, feature = "testing")`, `not(test)` and `windows` are
//! read. An unknown predicate reads as product code: the file list and the digests keep a place that
//! a configuration may not build, and never drop one that some configuration builds. A predicate that does not parse is an error, whatever
//! else is written on the place (`#[cfg(test)] #[cfg(not())]` is one). A `cfg_attr` that would add a
//! `path` is an error too, unless a `cfg` on the same place is false: that place is skipped.

use quote::ToTokens as _;
use syn::parse::ParseStream;
use syn::punctuated::Punctuated;
use syn::{Attribute, Expr, Ident, Lit, LitBool, Meta, Token};

/// What a predicate comes to when `test` is false and every other name is not known.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Value {
    True,
    False,
    Unknown,
}

/// Whether product code can be in a place whose attributes are `attrs`: `false` where one `cfg`
/// around it is false. `at` names the file for the error.
pub fn enabled(attrs: &[Attribute], at: &str) -> Result<bool, String> {
    let mut product = true;
    let mut sets = None;
    for attribute in attrs {
        if attribute.path().is_ident("cfg") {
            let meta = attribute
                .parse_args_with(parse_one)
                .map_err(|_| unreadable(at, &attribute.to_token_stream().to_string()))?;
            product &= value(&meta, at)? != Value::False;
        } else if attribute.path().is_ident("cfg_attr") {
            let listed = attribute
                .parse_args_with(parse_metas)
                .map_err(|_| unreadable(at, &attribute.to_token_stream().to_string()))?;
            if sets.is_none() && sets_path(&listed) {
                sets = Some(format!(
                    "{at}: the file list does not read a cfg_attr that sets a path ({})",
                    attribute.to_token_stream()
                ));
            }
        }
    }
    // What no configuration builds is not read, whatever else is written on it.
    match (product, sets) {
        (false, _) => Ok(false),
        (true, Some(error)) => Err(error),
        (true, None) => Ok(true),
    }
}

/// Whether the attributes a `cfg_attr` adds (after its predicate) set a path, looking into a
/// `cfg_attr` it holds.
fn sets_path(listed: &Punctuated<Meta, Token![,]>) -> bool {
    listed.iter().skip(1).any(|meta| match meta {
        Meta::List(list) if list.path.is_ident("cfg_attr") => list
            .parse_args_with(parse_metas)
            .map_or(true, |inner| sets_path(&inner)),
        _ => meta.path().is_ident("path"),
    })
}

fn unreadable(at: &str, text: &str) -> String {
    format!("{at}: the condition {text} cannot be read")
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

/// The one predicate of a `cfg`, with the comma that may follow it.
fn parse_one(input: ParseStream) -> syn::Result<Meta> {
    let meta = parse_meta(input)?;
    if input.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(meta)
}

fn value(meta: &Meta, at: &str) -> Result<Value, String> {
    let bad = || unreadable(at, &meta.to_token_stream().to_string());
    match meta {
        Meta::Path(path) => {
            let name = path.get_ident().ok_or_else(bad)?.to_string();
            Ok(match name.as_str() {
                "test" | "false" => Value::False,
                "true" => Value::True,
                _ => Value::Unknown,
            })
        }
        Meta::NameValue(pair) => {
            pair.path.get_ident().ok_or_else(bad)?;
            let Expr::Lit(literal) = &pair.value else {
                return Err(bad());
            };
            let Lit::Str(_) = &literal.lit else {
                return Err(bad());
            };
            Ok(Value::Unknown)
        }
        Meta::List(list) => {
            let name = list.path.get_ident().ok_or_else(bad)?.to_string();
            let inner = list
                .parse_args_with(parse_metas)
                .map_err(|_| bad())?
                .iter()
                .map(|meta| value(meta, at))
                .collect::<Result<Vec<_>, _>>()?;
            match name.as_str() {
                "all" => Ok(if inner.contains(&Value::False) {
                    Value::False
                } else if inner.iter().all(|value| *value == Value::True) {
                    Value::True
                } else {
                    Value::Unknown
                }),
                "any" => Ok(if inner.contains(&Value::True) {
                    Value::True
                } else if inner.iter().all(|value| *value == Value::False) {
                    Value::False
                } else {
                    Value::Unknown
                }),
                "not" if inner.len() == 1 => Ok(match inner[0] {
                    Value::True => Value::False,
                    Value::False => Value::True,
                    Value::Unknown => Value::Unknown,
                }),
                _ => Err(bad()),
            }
        }
    }
}
