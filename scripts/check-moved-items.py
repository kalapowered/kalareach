#!/usr/bin/env python3
"""Checks that each commit in a range moves Rust items between modules and changes nothing else.

    check-moved-items.py <base> <head> [--mount <file>=<module path>]...
    check-moved-items.py --self-test

A split of a large file into modules should change only where each item is written. For every
commit after <base> up to <head>, the check reads each Rust file the commit changes, as it was
before and as it is after, and places every item in its module: top-level items, the members of
every impl block, and the items of inline modules, an out-of-line module's file standing for its
inline body. A file's module is found from its crate root through the `mod` declarations; a file
loaded through a `#[path]` attribute is named with `--mount`
(`crates/kr-controller/src/net/mod.rs=crate::service::net`), and the check confirms each placing.

Each item from before is paired with one item after: the same kind, name and impl header, in the
same module once the modules the commit adds are set aside. The two are compared token by token.
Whitespace and line breaks do not count, nor does the whitespace inside a comment, and a string
literal is compared by its value, so a line continuation whose next line lost its indentation
passes. A raw literal, and one whose value holds a newline, is compared by its bytes. Only these
differences pass, and each one is printed:

* `pub(super)` on an item, or on a field of a struct, that was private, where the item moved into
  a direct child of its module. That is the scope the item had.
* A path that names the same item: from a module one level down (`super::devices` written as
  `super::super::devices`), or to where the commit moved the item (`super::recorded_create`
  written as `super::create::recorded_create`).
* A trailing comma added or dropped before the `)`, `]`, `}` or `>` that closes a call, a parameter
  or generic list, an array, a struct literal or pattern, or a `use` tree, or inside the input of
  `vec!`, `assert!`, `assert_eq!`, `assert_ne!`, `format!` or `matches!`. Never one that makes or
  unmakes a tuple of one element, and never inside an attribute or the input of another macro.

Inside an attribute, and inside the input of any macro but the standard ones whose input is
expressions and format strings (`vec!`, `format!`, `matches!`, the `assert` and `print` families,
`write!`, `panic!` and the like) and tokio's `join!` and `try_join!` (which match their input as
`expr` fragments and never stringify it), a path or a string literal is compared by its text: such a
macro can see the text (`stringify!`). A path rewritten inside an `assert!` condition is printed as
such, since the assertion's failure message quotes the condition.

Every item keeps its attributes and docs, and the conditions it is compiled under: an impl
block's attributes are part of what pairs its members. A module the commit adds is private and has
nothing but docs, on its declaration and at the top of its file, and its docs repeat no line of its
old module's own docs. A module declaration never moves, since a `#[path]` is read from where it
is written. An item that moves carries no derive or attribute
macro other than the standard derives, serde's two and `tokio::test`, and uses nothing that reads
where it is written (`module_path!`, `file!`, `line!`, `column!`, the `include` macros,
`type_name`, `Location::caller`, `#[track_caller]`). Every public item that moves out of a module is
re-exported there with `pub use`, so its public path stays.

Imports are compared binding by binding, each by the item it names. A module split from another
imports only what that module imported, each name bound to the same item, and that module's own
items under their own names from where they now are. The module the items came from keeps its
bindings, drops some, or binds one of its moved items privately (or re-exports a public one). A
test module keeps every binding. A binding under a `cfg` carries the union of the conditions of
the code in its module that names it, and one that unconditional code names has no condition;
each such binding is printed beside that code. A name the Rust prelude also has, and that the old
module bound to something else (`Result`), is bound the same way in every module that names it.

Anything else fails. For each commit the output lists every item (kind, name, from, to, status)
and every binding of the modules the commit changes; the last line says whether the range passed.
Only Python's standard library is used.
"""

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

# --------------------------------------------------------------------------------------- tokens


@dataclass
class Token:
    kind: str  # ident, lifetime, str, char, num, punct, doc, comment
    text: str
    line: int


class CheckError(Exception):
    pass


IDENT_START = re.compile(r"[A-Za-z_\u0080-\U0010ffff]")
IDENT_REST = re.compile(r"[A-Za-z0-9_\u0080-\U0010ffff]*")
NUMBER = re.compile(r"[0-9][0-9A-Za-z_]*(?:\.(?![.A-Za-z_])[0-9A-Za-z_]*)?")
RAW_STRING = re.compile(r"(?:br|cr|r)(#*)\"")
RAW_PREFIX = re.compile(r"^[bc]?r#*\"")


def lex(text):
    toks = []
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
            continue
        if c in " \t\r﻿":
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            body = text[i:j].rstrip()
            doc = (body.startswith("///") and not body.startswith("////")) or body.startswith("//!")
            toks.append(Token("doc" if doc else "comment", body, line))
            i = j
            continue
        if text.startswith("/*", i):
            depth, j = 0, i
            while j < n:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                else:
                    j += 1
            if depth:
                raise CheckError(f"an unterminated block comment at line {line}")
            body = text[i:j]
            doc = (
                body.startswith("/**") and not body.startswith("/***") and body != "/**/"
            ) or body.startswith("/*!")
            toks.append(Token("doc" if doc else "comment", body, line))
            line += body.count("\n")
            i = j
            continue
        m = RAW_STRING.match(text, i)
        if m:
            close = '"' + m.group(1)
            j = text.find(close, m.end())
            if j < 0:
                raise CheckError(f"an unterminated raw string at line {line}")
            j += len(close)
            m2 = IDENT_REST.match(text, j)
            j = m2.end()
            toks.append(Token("str", text[i:j], line))
            line += text.count("\n", i, j)
            i = j
            continue
        if c == '"' or (c in "bc" and text.startswith('"', i + 1)):
            j = i + (1 if c == '"' else 2)
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            j += 1
            m2 = IDENT_REST.match(text, j)
            j = m2.end()
            toks.append(Token("str", text[i:j], line))
            line += text.count("\n", i, j)
            i = j
            continue
        if c == "b" and text.startswith("'", i + 1):
            j = i + 2
            while text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            toks.append(Token("char", text[i : j + 1], line))
            i = j + 1
            continue
        if c == "'":
            if text.startswith("\\", i + 1):
                j = i + 2
                while text[j] != "'":
                    j += 2 if text[j] == "\\" else 1
                toks.append(Token("char", text[i : j + 1], line))
                i = j + 1
                continue
            if i + 2 < n and text[i + 2] == "'":
                toks.append(Token("char", text[i : i + 3], line))
                i += 3
                continue
            m2 = IDENT_REST.match(text, i + 1)
            toks.append(Token("lifetime", text[i : m2.end()], line))
            i = m2.end()
            continue
        if (
            c == "r"
            and text.startswith("#", i + 1)
            and i + 2 < n
            and IDENT_START.match(text[i + 2])
        ):
            m2 = IDENT_REST.match(text, i + 2)
            toks.append(Token("ident", text[i : m2.end()], line))
            i = m2.end()
            continue
        if IDENT_START.match(c):
            m2 = IDENT_REST.match(text, i)
            toks.append(Token("ident", text[i : m2.end()], line))
            i = m2.end()
            continue
        if c.isdigit():
            m2 = NUMBER.match(text, i)
            toks.append(Token("num", text[i : m2.end()], line))
            i = m2.end()
            continue
        toks.append(Token("punct", c, line))
        i += 1
    return toks


ESCAPES = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def decode_string(text):
    """A non-raw string literal's prefix, value and suffix."""
    j = 1 if text[0] in "bc" else 0
    close = j + 1
    while text[close] != '"':
        close += 2 if text[close] == "\\" else 1
    body, out, k = text[j + 1 : close], [], 0
    while k < len(body):
        ch = body[k]
        if ch != "\\":
            out.append(ch)
            k += 1
            continue
        nxt = body[k + 1]
        if nxt in "\r\n":
            k += 1
            while k < len(body) and body[k] in " \t\r\n":
                k += 1
        elif nxt in ESCAPES:
            out.append(ESCAPES[nxt])
            k += 2
        elif nxt == "x":
            out.append(chr(int(body[k + 2 : k + 4], 16)))
            k += 4
        elif nxt == "u":
            end = body.index("}", k)
            out.append(chr(int(body[k + 3 : end].replace("_", ""), 16)))
            k = end + 1
        else:
            raise CheckError(f"an unknown escape in {text[:40]!r}")
    return text[:j], "".join(out), text[close + 1 :]


def key(tok):
    """What two tokens must share to be the same token."""
    if tok.kind == "comment":
        return ("comment", " ".join(tok.text.split()))
    if tok.kind == "str":
        if RAW_PREFIX.match(tok.text):
            return ("str", tok.text)
        prefix, value, suffix = decode_string(tok.text)
        if "\n" in value:
            return ("str", tok.text)
        return ("str-value", prefix, value, suffix)
    return (tok.kind, tok.text)


FORMAT_NAME = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)(?::[^{}]*)?\}")


def format_names(tok):
    """The names a string literal interpolates, when it is a format string (`{name}`)."""
    if RAW_PREFIX.match(tok.text):
        body = tok.text[tok.text.index('"') + 1 : tok.text.rindex('"')]
    else:
        body = decode_string(tok.text)[1]
    return FORMAT_NAME.findall(body.replace("{{", "").replace("}}", ""))


def field_or_method(toks, k):
    """Whether toks[k] follows a single `.` (a field or a method), not a range's `..`."""
    return k > 0 and is_punct(toks[k - 1], ".") and not (k > 1 and is_punct(toks[k - 2], "."))


def in_macro_input(toks, parent, k):
    g = parent[k]
    while g >= 0:
        if g >= 2 and is_punct(toks[g - 1], "!") and toks[g - 2].kind == "ident":
            return True
        g = parent[g]
    return False


def is_punct(tok, text):
    return tok.kind == "punct" and tok.text == text


def brackets(toks):
    """For each token, the index of its partner bracket and of the innermost enclosing opener."""
    partner = [-1] * len(toks)
    parent = [-1] * len(toks)
    stack = []
    for i, t in enumerate(toks):
        parent[i] = stack[-1] if stack else -1
        if t.kind == "punct" and t.text in "([{":
            stack.append(i)
        elif t.kind == "punct" and t.text in ")]}":
            if not stack:
                raise CheckError(f"an unbalanced {t.text!r} at line {t.line}")
            o = stack.pop()
            partner[o], partner[i] = i, o
            parent[i] = stack[-1] if stack else -1
    if stack:
        raise CheckError(f"an unclosed {toks[stack[-1]].text!r} at line {toks[stack[-1]].line}")
    return partner, parent


# ---------------------------------------------------------------------------------------- items

KEYWORDS = {
    "as",
    "async",
    "await",
    "break",
    "const",
    "continue",
    "crate",
    "dyn",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "gen",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
    "yield",
    "box",
}
BRACE_BODY = {
    "fn",
    "struct",
    "union",
    "enum",
    "trait",
    "impl",
    "mod",
    "extern-block",
    "macro_rules",
    "macro",
}


@dataclass
class Item:
    kind: str
    name: str
    first: int  # the first token, its docs, attributes and comments included
    head: int  # the visibility, or the first qualifier or keyword
    end: int  # one past the last token
    vis: str = ""
    vis_end: int = 0
    kw: int = 0
    body: tuple = None  # (open, close) of a brace body
    parens: tuple = None  # (open, close) of a tuple struct's fields
    header: str = ""
    inner: tuple = None  # (lo, hi) of a body's inner attributes and docs
    attrs: list = field(default_factory=list)  # (lo, hi) of each outer attribute
    children: list = field(default_factory=list)


def attr_at(toks, i):
    return (
        is_punct(toks[i], "#")
        and i + 1 < len(toks)
        and (
            is_punct(toks[i + 1], "[")
            or (is_punct(toks[i + 1], "!") and i + 2 < len(toks) and is_punct(toks[i + 2], "["))
        )
    )


def inner_prefix(toks, lo, hi, partner):
    """The inner attributes and docs a module or impl body starts with: (lo, hi)."""
    k, last = lo, lo
    while k < hi:
        t = toks[k]
        if t.kind == "doc" and (t.text.startswith("//!") or t.text.startswith("/*!")):
            k += 1
            last = k
        elif t.kind == "comment":
            k += 1
        elif attr_at(toks, k) and is_punct(toks[k + 1], "!"):
            k = partner[k + 2] + 1
            last = k
        else:
            break
    return (lo, last)


def visibility(toks, i, partner):
    if toks[i].kind == "ident" and toks[i].text == "pub":
        if (
            is_punct(toks[i + 1], "(")
            and toks[i + 2].kind == "ident"
            and toks[i + 2].text in ("crate", "super", "self", "in")
        ):
            close = partner[i + 1]
            inside = "".join(
                t.text if t.kind == "punct" else " " + t.text for t in toks[i + 2 : close]
            )
            return "pub(" + inside.strip().replace(" ::", "::") + ")", close + 1
        return "pub", i + 1
    return "", i


def parse_items(toks, lo, hi, partner):
    items = []
    i = lo
    while i < hi:
        first, attrs = i, []
        while i < hi:
            t = toks[i]
            if t.kind in ("doc", "comment"):
                i += 1
            elif attr_at(toks, i) and is_punct(toks[i + 1], "["):
                close = partner[i + 1]
                attrs.append((i, close + 1))
                i = close + 1
            else:
                break
        if i >= hi:
            items.append(Item("trivia", "", first, hi, hi))
            break
        head = i
        vis, i = visibility(toks, i, partner)
        vis_end = i
        while toks[i].kind == "ident":
            w, nxt = toks[i].text, toks[i + 1]
            if w in ("async", "unsafe", "default", "safe") and nxt.kind == "ident":
                i += 1
            elif (
                w == "const"
                and nxt.kind == "ident"
                and nxt.text in ("fn", "unsafe", "async", "extern")
            ):
                i += 1
            elif w == "extern" and nxt.kind == "str" and not is_punct(toks[i + 2], "{"):
                i += 2
            else:
                break
        kw, t = i, toks[i]
        kind, name = t.text, ""
        if t.kind == "ident" and t.text in (
            "fn",
            "struct",
            "union",
            "enum",
            "trait",
            "mod",
            "type",
        ):
            name = toks[i + 1].text
        elif t.kind == "ident" and t.text in ("const", "static"):
            name = toks[i + 2].text if toks[i + 1].text == "mut" else toks[i + 1].text
        elif t.kind == "ident" and t.text in ("impl", "use"):
            pass
        elif t.kind == "ident" and t.text == "extern":
            if toks[i + 1].text == "crate":
                kind, name = "extern-crate", toks[i + 2].text
            else:
                kind = "extern-block"
        elif t.kind == "ident" and t.text == "macro_rules" and is_punct(toks[i + 1], "!"):
            kind, name = "macro_rules", toks[i + 2].text
        elif t.kind == "ident":
            k = i
            while (
                toks[k].kind == "ident"
                and is_punct(toks[k + 1], ":")
                and is_punct(toks[k + 2], ":")
            ):
                k += 3
            if toks[k].kind == "ident" and is_punct(toks[k + 1], "!"):
                kind, name = "macro", toks[k].text
            else:
                raise CheckError(f"no item at line {t.line}: {t.text!r}")
        else:
            raise CheckError(f"no item at line {t.line}: {t.text!r}")
        j, body, parens = i + 1, None, None
        while j < hi:
            u = toks[j]
            if u.kind == "punct" and u.text == ";":
                j += 1
                break
            if u.kind == "punct" and u.text == "{":
                if kind in BRACE_BODY:
                    body = (j, partner[j])
                    j = partner[j] + 1
                    if kind in ("macro", "macro_rules") and j < hi and is_punct(toks[j], ";"):
                        j += 1
                    break
                j = partner[j] + 1
                continue
            if u.kind == "punct" and u.text in "([":
                if kind == "macro" and is_punct(toks[j - 1], "!"):
                    body = (j, partner[j])
                    j = partner[j] + 1
                    if j < hi and is_punct(toks[j], ";"):
                        j += 1
                    break
                if kind == "struct" and u.text == "(" and parens is None:
                    parens = (j, partner[j])
                j = partner[j] + 1
                continue
            j += 1
        item = Item(kind, name, first, head, j, vis, vis_end, kw, body, parens, attrs=attrs)
        if kind == "impl":
            item.header = " ".join(x.text for x in toks[head : body[0]])
        if body is not None and kind in ("impl", "mod"):
            item.inner = inner_prefix(toks, body[0] + 1, body[1], partner)
            item.children = parse_items(toks, item.inner[1], body[1], partner)
        items.append(item)
        i = j
    return items


def attr_path(toks, lo, hi):
    """The path of the attribute toks[lo:hi] (`#[...]` or `#![...]`)."""
    k = lo + (3 if is_punct(toks[lo + 1], "!") else 2)
    parts = []
    while k < hi and (toks[k].kind == "ident" or is_punct(toks[k], ":")):
        parts.append(toks[k].text)
        k += 1
    return "".join(parts), k


def cfg_of(toks, lo, hi):
    """The predicate of a `#[cfg(...)]` attribute, as text, or None."""
    path, k = attr_path(toks, lo, hi)
    if path != "cfg":
        return None
    return predicate_text(toks[k + 1 : hi - 2])


def predicate_text(toks):
    out = ""
    for t in toks:
        if t.kind == "punct":
            out += t.text + (" " if t.text == "," else "")
        elif out and out[-1] not in "( ,":
            out += " " + t.text
        else:
            out += t.text
    return out.replace(" = ", "=").replace(" =", "=").replace("= ", "=")


def split_predicates(pred):
    """`all(a, b)` as {a, b}; anything else as itself."""
    if pred.startswith("all(") and pred.endswith(")"):
        return set(top_level_parts(pred[4:-1]))
    return {pred}


def alternatives(pred):
    """A predicate as a set of conjunctions (each a frozenset of simple predicates)."""
    if pred.startswith("any(") and pred.endswith(")"):
        out = set()
        for part in top_level_parts(pred[4:-1]):
            out |= alternatives(part)
        return out
    if pred.startswith("all(") and pred.endswith(")"):
        result = {frozenset()}
        for part in top_level_parts(pred[4:-1]):
            result = {a | b for a in result for b in alternatives(part)}
        return result
    return {frozenset([pred])}


def expanded(conjunction):
    """A conjunction of predicates (each possibly `any(..)` or `all(..)`) as alternatives."""
    result = {frozenset()}
    for pred in conjunction:
        result = {a | b for a in result for b in alternatives(pred)}
    return result


def top_level_parts(text):
    parts, depth, cur = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def minimal(alts):
    """A union of conjunctions without the ones another one implies."""
    alts = set(alts)
    return {a for a in alts if not any(b < a for b in alts)}


def show_condition(alts):
    alts = minimal(alts)
    if frozenset() in alts:
        return "always"

    def conj(c):
        return sorted(c)[0] if len(c) == 1 else "all(" + ", ".join(sorted(c)) + ")"

    parts = sorted(conj(c) for c in alts)
    return parts[0] if len(parts) == 1 else "any(" + ", ".join(parts) + ")"


# ----------------------------------------------------------------------------------- use trees


@dataclass
class Binding:
    name: str  # the bound name, or "_"
    path: tuple  # the path as written
    vis: str
    conds: set  # alternatives, {frozenset()} when unconditional
    other_attrs: list
    item: Item


def use_bindings(toks, item, partner):
    """Every name a `use` item binds."""
    conds, others = {frozenset()}, []
    for lo, hi in item.attrs:
        pred = cfg_of(toks, lo, hi)
        if pred is None:
            others.append(" ".join(t.text for t in toks[lo:hi]))
        else:
            conds = {a | b for a in conds for b in alternatives(pred)}
    k = item.kw + 1
    out = []

    def tree(k, prefix):
        path = list(prefix)
        if is_punct(toks[k], ":") and is_punct(toks[k + 1], ":"):
            path.append("")  # a leading `::`
            k += 2
        while True:
            t = toks[k]
            if is_punct(t, "{"):
                close = partner[k]
                j = k + 1
                while j < close:
                    j = tree(j, path)
                    if is_punct(toks[j], ","):
                        j += 1
                return close + 1
            if is_punct(t, "*"):
                out.append(Binding("*", tuple(path) + ("*",), item.vis, conds, others, item))
                return k + 1
            if t.kind != "ident":
                raise CheckError(f"an unreadable use tree at line {t.line}")
            if is_punct(toks[k + 1], ":") and is_punct(toks[k + 2], ":"):
                path.append(t.text)
                k += 3
                continue
            name, full = t.text, tuple(path) + (t.text,)
            if t.text == "self":
                name, full = path[-1], tuple(path)
            k += 1
            if toks[k].kind == "ident" and toks[k].text == "as":
                name = toks[k + 1].text
                k += 2
            out.append(Binding(name, full, item.vis, conds, others, item))
            return k

    tree(k, [])
    return out


# ------------------------------------------------------------------------------------ modules


@dataclass
class Module:
    path: tuple
    file: str
    toks: list
    partner: list
    parent: list
    items: list
    inner: tuple
    directory: str  # where its child modules' files are
    decl: Item = None  # its declaration, in its parent
    conds: frozenset = frozenset()  # the conditions it is compiled under (a conjunction)
    _bindings: dict = None

    def bindings(self):
        if self._bindings is None:
            self._bindings = {}
            for it in self.items:
                if it.kind == "use":
                    for b in use_bindings(self.toks, it, self.partner):
                        self._bindings.setdefault(b.name, []).append(b)
        return self._bindings

    def item_names(self):
        return {it.name for it in self.items if it.kind not in ("use", "impl", "trivia", "macro")}


class State:
    """The crate sources at one commit (or an in-memory crate in the self-test)."""

    def __init__(self, label, read, mounts):
        self.label = label
        self.read = read
        self.mounts = mounts  # file -> module path
        self.files = {}
        self.modules = {}

    def parsed(self, path):
        if path not in self.files:
            text = self.read(path)
            if text is None:
                self.files[path] = None
            else:
                toks = lex(text)
                partner, parent = brackets(toks)
                items = parse_items(toks, 0, len(toks), partner)
                self.files[path] = (toks, partner, parent, items)
        return self.files[path]

    def module(self, root, mpath):
        """The module at `mpath` in the crate whose source root is `root`, or None."""
        cache_key = (root, mpath)
        if not mpath or mpath[0] != "crate":
            return None
        if cache_key in self.modules:
            return self.modules[cache_key]
        result = None
        if mpath == ("crate",):
            for name in ("lib.rs", "main.rs"):
                f = os.path.join(root, name) if not root.endswith(".rs") else root
                p = self.parsed(f)
                if p is not None:
                    toks, partner, parent, items = p
                    lo, hi = inner_prefix(toks, 0, len(toks), partner)
                    result = Module(
                        mpath, f, toks, partner, parent, items, (lo, hi), os.path.dirname(f)
                    )
                    break
        else:
            up = self.module(root, mpath[:-1])
            decl = None
            if up is not None:
                for it in up.items:
                    if it.kind == "mod" and it.name == mpath[-1]:
                        decl = it
                        break
            if decl is not None:
                conds = set(up.conds)
                path_attr = None
                for lo, hi in decl.attrs:
                    pred = cfg_of(up.toks, lo, hi)
                    if pred is not None:
                        conds |= split_predicates(pred)
                    elif attr_path(up.toks, lo, hi)[0] == "path":
                        path_attr = decode_string(up.toks[hi - 2].text)[1]
                if decl.body is not None:
                    result = Module(
                        mpath,
                        up.file,
                        up.toks,
                        up.partner,
                        up.parent,
                        decl.children,
                        decl.inner,
                        os.path.join(up.directory, mpath[-1]),
                        decl,
                    )
                else:
                    if path_attr is not None:
                        if up.decl is not None and up.decl.body is not None:
                            raise CheckError(f"a #[path] inside an inline module: {mpath}")
                        candidates = [
                            os.path.normpath(os.path.join(os.path.dirname(up.file), path_attr))
                        ]
                    else:
                        candidates = [
                            os.path.join(up.directory, mpath[-1] + ".rs"),
                            os.path.join(up.directory, mpath[-1], "mod.rs"),
                        ]
                    for f in candidates:
                        p = self.parsed(f)
                        if p is not None:
                            toks, partner, parent, items = p
                            lo, hi = inner_prefix(toks, 0, len(toks), partner)
                            base = os.path.basename(f)
                            directory = (
                                os.path.dirname(f)
                                if base == "mod.rs"
                                else os.path.join(os.path.dirname(f), base[:-3])
                            )
                            result = Module(
                                mpath, f, toks, partner, parent, items, (lo, hi), directory, decl
                            )
                            break
                if result is not None:
                    result.conds = frozenset(conds)
        self.modules[cache_key] = result
        return result

    def place(self, path):
        """The crate root and module path of a Rust file, confirmed through its declarations."""
        if "/src/" in "/" + path:
            idx = ("/" + path).rindex("/src/")
            root = path[: idx + 3] if idx > 0 else "src"
        else:
            return path, ("crate",)
        guess = None
        for mfile, mpath in self.mounts.items():
            if path == mfile:
                guess = mpath
            elif os.path.basename(mfile) == "mod.rs" and path.startswith(
                os.path.dirname(mfile) + "/"
            ):
                rest = path[len(os.path.dirname(mfile)) + 1 :]
                parts = rest[:-3].split("/")
                if parts[-1] == "mod":
                    parts = parts[:-1]
                guess = mpath + tuple(parts)
        if guess is None:
            rel = path[len(root) + 1 :]
            if rel in ("lib.rs", "main.rs"):
                guess = ("crate",)
            else:
                parts = rel[:-3].split("/")
                if parts[-1] == "mod":
                    parts = parts[:-1]
                guess = ("crate",) + tuple(parts)
        mod = self.module(root, guess)
        if mod is None or mod.file != path or mod.decl is not None and mod.decl.body is not None:
            raise CheckError(
                f"{path} is not the module {'::'.join(guess)} at {self.label}; "
                "name the module it is loaded as with --mount"
            )
        return root, guess


def absolute(segments, module):
    """A path that starts with `crate`, `super` or `self`, from `module`, as an absolute path."""
    if not segments:
        return None
    if segments[0] == "crate":
        return ("crate",) + tuple(segments[1:])
    if segments[0] == "self":
        return tuple(module) + tuple(segments[1:])
    if segments[0] == "super":
        k, base = 0, list(module)
        while k < len(segments) and segments[k] == "super":
            if len(base) < 2:
                return None
            base.pop()
            k += 1
        return tuple(base) + tuple(segments[k:])
    return None


def binding_target(b, module, state, root):
    """Where a binding points: an absolute path, or an external path starting with `::`."""
    segs = [s for s in b.path if s != ""]
    abs_path = absolute(segs, module.path)
    if abs_path is not None:
        return abs_path
    if b.path and b.path[0] == "":
        return ("::",) + tuple(segs)
    first = segs[0]
    if first in module.item_names() or state.module(root, module.path + (first,)) is not None:
        return tuple(module.path) + tuple(segs)
    return ("::",) + tuple(segs)


def canonical(state, root, path, depth=0):
    """The item an absolute path names, following imports: (item path, what follows it)."""
    if not path or path[0] != "crate":
        return (tuple(path), ())
    j = 1
    while j < len(path):
        mod = state.module(root, tuple(path[:j]))
        if mod is None:
            return (tuple(path[:j]), tuple(path[j:]))
        name = path[j]
        if state.module(root, tuple(path[: j + 1])) is not None:
            j += 1
            continue
        found = mod.bindings().get(name)
        if found and depth < 30:
            target = binding_target(found[0], mod, state, root)
            return canonical(state, root, tuple(target) + tuple(path[j + 1 :]), depth + 1)
        return (tuple(path[: j + 1]), tuple(path[j + 1 :]))
    return (tuple(path), ())


# ------------------------------------------------------------------------------------ entries


@dataclass
class Entry:
    """An item placed in its module."""

    module: object  # Module
    item: Item
    chain: tuple  # the impl headers it sits in
    key: tuple = None
    conds: frozenset = frozenset()


def collect(state, root, mod, out, bindings_out):
    """Every item of `mod` and of its inline modules, as entries."""
    bindings_out[mod.path] = mod
    for it in mod.items:
        if it.kind == "use":
            continue
        out.append(Entry(mod, it, ()))
        if it.kind == "mod" and it.body is not None:
            collect(state, root, state.module(root, mod.path + (it.name,)), out, bindings_out)
        elif it.kind == "impl":
            for ch in it.children:
                out.append(Entry(mod, ch, (it,)))


def item_conditions(toks, item):
    conds = set()
    for lo, hi in item.attrs:
        pred = cfg_of(toks, lo, hi)
        if pred is not None:
            conds |= split_predicates(pred)
    return conds


def entry_label(e):
    if e.chain:
        hdr = e.chain[0].header
        ty = hdr.split(" for ")[-1].replace("impl ", "").split(" where ")[0]
        return f"{e.item.kind} {ty.replace(' ', '')}::{e.item.name}"
    if e.item.kind == "impl":
        return "impl " + e.item.header.replace("impl ", "", 1)
    return f"{e.item.kind} {e.item.name}" if e.item.name else e.item.kind


def show(path):
    if path and path[0] == "::":
        return "::" + "::".join(path[1:])
    return "::".join(path)


# --------------------------------------------------------------------------------- comparison

COMMA_MACROS = {"vec", "assert", "assert_eq", "assert_ne", "format", "matches"}
PLACE_MACROS = {"module_path", "file", "line", "column", "include", "include_str", "include_bytes"}
PLACE_NAMES = {"type_name", "type_name_of_val", "track_caller"}
ALLOWED_ATTRS = {
    "cfg",
    "allow",
    "expect",
    "warn",
    "deny",
    "must_use",
    "doc",
    "inline",
    "cold",
    "test",
    "ignore",
    "should_panic",
    "non_exhaustive",
    "repr",
    "deprecated",
    "serde",
    "derive",
    "tokio::test",
    "rustfmt::skip",
}
ALLOWED_DERIVES = {
    "Debug",
    "Clone",
    "Copy",
    "PartialEq",
    "Eq",
    "PartialOrd",
    "Ord",
    "Hash",
    "Default",
    "serde::Serialize",
    "serde::Deserialize",
    "Serialize",
    "Deserialize",
}
PRELUDE = {
    "Copy",
    "Send",
    "Sized",
    "Sync",
    "Unpin",
    "Drop",
    "Fn",
    "FnMut",
    "FnOnce",
    "AsyncFn",
    "AsyncFnMut",
    "AsyncFnOnce",
    "drop",
    "Box",
    "ToOwned",
    "Clone",
    "PartialEq",
    "PartialOrd",
    "Eq",
    "Ord",
    "AsRef",
    "AsMut",
    "Into",
    "From",
    "Default",
    "Iterator",
    "Extend",
    "IntoIterator",
    "DoubleEndedIterator",
    "ExactSizeIterator",
    "Option",
    "Some",
    "None",
    "Result",
    "Ok",
    "Err",
    "String",
    "ToString",
    "Vec",
    "TryFrom",
    "TryInto",
    "FromIterator",
    "Future",
    "IntoFuture",
    "size_of",
    "size_of_val",
    "align_of",
    "align_of_val",
    "bool",
    "char",
    "str",
    "u8",
    "u16",
    "u32",
    "u64",
    "u128",
    "usize",
    "i8",
    "i16",
    "i32",
    "i64",
    "i128",
    "isize",
    "f32",
    "f64",
}


class Pair:
    def __init__(self, before, after, check):
        self.b, self.a, self.check = before, after, check
        self.notes = []

    def moved_to_child(self):
        return (
            tuple(self.a.module.path[:-1]) == tuple(self.b.module.path)
            and self.a.module.path != self.b.module.path
        )


def path_bounds(toks, i):
    s = i
    if is_punct(toks[s], ":"):
        if s >= 1 and is_punct(toks[s - 1], ":"):
            s -= 1
        s -= 1
    if s < 0 or toks[s].kind != "ident":
        return None
    while (
        s >= 3
        and is_punct(toks[s - 1], ":")
        and is_punct(toks[s - 2], ":")
        and toks[s - 3].kind == "ident"
    ):
        s -= 3
    e = s + 1
    while (
        e + 2 < len(toks)
        and is_punct(toks[e], ":")
        and is_punct(toks[e + 1], ":")
        and toks[e + 2].kind == "ident"
    ):
        e += 3
    return s, e


def relative_start(toks, i):
    """Whether toks[i] (`super` or `self`) starts a path."""
    after = i + 2 < len(toks) and is_punct(toks[i + 1], ":") and is_punct(toks[i + 2], ":")
    before = i >= 2 and is_punct(toks[i - 1], ":") and is_punct(toks[i - 2], ":")
    return after and not before


def macro_name(toks, open_idx):
    """The macro whose input the group opened at `open_idx` is, or None."""
    if open_idx >= 2 and is_punct(toks[open_idx - 1], "!") and toks[open_idx - 2].kind == "ident":
        return toks[open_idx - 2].text
    return None


def in_attribute(toks, open_idx):
    return (
        is_punct(toks[open_idx], "[")
        and open_idx >= 1
        and (
            is_punct(toks[open_idx - 1], "#")
            or (
                is_punct(toks[open_idx - 1], "!")
                and open_idx >= 2
                and is_punct(toks[open_idx - 2], "#")
            )
        )
    )


EXPRESSION_MACROS = COMMA_MACROS | {
    "print",
    "println",
    "eprint",
    "eprintln",
    "write",
    "writeln",
    "panic",
    "unreachable",
    "todo",
    "unimplemented",
    "format_args",
    "debug_assert",
    "debug_assert_eq",
    "debug_assert_ne",
    "join",
    "try_join",
}


def opaque(toks, parent, k):
    """Why toks[k] is compared by its text, or None: it is in an attribute, or in the input of a
    macro other than the standard expression macros."""
    g = parent[k]
    while g >= 0:
        if in_attribute(toks, g):
            return "an attribute"
        name = macro_name(toks, g)
        if name is not None and name not in EXPRESSION_MACROS:
            return f"the input of {name}!"
        g = parent[g]
    return None


def quoted_condition(toks, parent, k):
    """The assertion macro whose condition toks[k] is in, or None: its failure message quotes the
    condition."""
    g = parent[k]
    while g >= 0:
        name = macro_name(toks, g)
        if name in ("assert", "debug_assert"):
            if not any(is_punct(toks[j], ",") and parent[j] == g for j in range(g + 1, k)):
                return name
            return None
        g = parent[g]
    return None


def closes_call_generics(toks, partner, j):
    """Whether the `>` at toks[j] closes a turbofish (`::<..>`) or a function's generic list."""
    if j >= 1 and toks[j - 1].kind == "punct" and toks[j - 1].text in "-=":
        return False  # `->` or `=>`
    depth, k = 0, j
    while k >= 0:
        t = toks[k]
        if t.kind == "punct":
            if t.text in ")]}":
                k = partner[k] - 1
                continue
            if t.text in "([{;":
                return False
            if t.text == ">" and not (
                k >= 1 and toks[k - 1].kind == "punct" and toks[k - 1].text in "-="
            ):
                depth += 1
            elif t.text == "<":
                depth -= 1
                if depth == 0:
                    turbofish = k >= 2 and is_punct(toks[k - 1], ":") and is_punct(toks[k - 2], ":")
                    fn_generics = (
                        k >= 2
                        and toks[k - 1].kind == "ident"
                        and toks[k - 2].kind == "ident"
                        and toks[k - 2].text == "fn"
                    )
                    return turbofish or fn_generics
        k -= 1
    return False


def comma_allowed(toks, partner, parent, ci):
    """Whether the trailing comma toks[ci] may come or go: (ok, what it closes)."""
    close = ci + 1
    closer = toks[close].text
    g = parent[ci]
    # every group around it: no attribute, and no macro input but the listed macros'
    h = g
    while h >= 0:
        if in_attribute(toks, h):
            return False, "an attribute"
        name = macro_name(toks, h)
        if name is not None and name not in COMMA_MACROS:
            return False, f"the input of {name}!"
        h = parent[h]
    if closer == ">":
        return True, "a generic list"
    if g < 0 or partner[g] != close:
        return False, "no group"
    if closer in "]}":
        return True, "an array or list" if closer == "]" else "a brace list"
    # a parenthesised group: a call or a list, or a tuple
    prev = toks[g - 1] if g >= 1 else None
    if prev is not None and macro_name(toks, g) is not None:
        return True, f"the input of {macro_name(toks, g)}!"
    called = prev is not None and (
        (prev.kind == "ident" and (prev.text not in KEYWORDS or prev.text == "Self"))
        or (is_punct(prev, ">") and closes_call_generics(toks, partner, g - 1))
        or is_punct(prev, ")")
        or (is_punct(prev, "]") and not in_attribute(toks, partner[g - 1]))
    )
    if called:
        return True, "a call or parameter list"
    depth_commas = sum(1 for k in range(g + 1, ci) if is_punct(toks[k], ",") and parent[k] == g)
    if depth_commas >= 1:
        return True, "a tuple of several elements"
    return False, "a tuple of one element"


def compare(pair, b_lo, b_hi, a_lo, a_hi, vis_points=()):
    """Compares toks_b[b_lo:b_hi] with toks_a[a_lo:a_hi]; returns None or the first difference."""
    check = pair.check
    bm, am = pair.b.module, pair.a.module
    bt, at = bm.toks, am.toks
    moved = tuple(bm.path) != tuple(am.path)
    i, k = b_lo, a_lo
    while i < b_hi or k < a_hi:
        if (
            i < b_hi
            and k < a_hi
            and key(bt[i]) == key(at[k])
            and not (
                bt[i].kind == "str"
                and bt[i].text != at[k].text
                and (opaque(bt, bm.parent, i) or opaque(at, am.parent, k))
            )
        ):
            # a relative path written the same way from another module
            if (
                moved
                and bt[i].kind == "ident"
                and bt[i].text in ("super", "self")
                and relative_start(bt, i)
            ):
                pb, pa = path_bounds(bt, i), path_bounds(at, k)
                sb = [t.text for t in bt[pb[0] : pb[1] : 3]]
                sa = [t.text for t in at[pa[0] : pa[1] : 3]]
                if sb == sa and pb[1] <= b_hi and pa[1] <= a_hi:
                    if not check.same_item(sb, bm, sa, am):
                        return (
                            f"the path {'::'.join(sb)} at line {bt[i].line} -> {at[k].line} names "
                            "another item from the module it moved to"
                        )
                    i, k = pb[1], pa[1]
                    continue
            i += 1
            k += 1
            continue
        # pub(super) where the item or a field was private
        if (
            k + 3 < a_hi
            and at[k].kind == "ident"
            and at[k].text == "pub"
            and is_punct(at[k + 1], "(")
            and at[k + 2].text == "super"
            and is_punct(at[k + 3], ")")
            and i in vis_points
        ):
            if pair.moved_to_child():
                pair.notes.append(("vis", f"pub(super) from private at line {at[k].line}"))
                k += 4
                continue
            return (
                f"pub(super) added at line {at[k].line}, "
                "but the item did not move into a direct child"
            )
        # a trailing comma
        if (
            i < b_hi
            and is_punct(bt[i], ",")
            and i + 1 < b_hi
            and bt[i + 1].kind == "punct"
            and bt[i + 1].text in ")]}>"
            and k < a_hi
            and key(at[k]) == key(bt[i + 1])
        ):
            ok, what = comma_allowed(bt, bm.partner, bm.parent, i)
            if ok:
                pair.notes.append(
                    (
                        "comma",
                        f"dropped before {bt[i + 1].text!r} closing {what} "
                        f"(line {bt[i].line} -> {at[k].line})",
                    )
                )
                i += 1
                continue
            return f"a trailing comma dropped in {what} at line {bt[i].line} -> {at[k].line}"
        if (
            k < a_hi
            and is_punct(at[k], ",")
            and k + 1 < a_hi
            and at[k + 1].kind == "punct"
            and at[k + 1].text in ")]}>"
            and i < b_hi
            and key(bt[i]) == key(at[k + 1])
        ):
            ok, what = comma_allowed(at, am.partner, am.parent, k)
            if ok:
                pair.notes.append(
                    (
                        "comma",
                        f"added before {at[k + 1].text!r} closing {what} "
                        f"(line {bt[i].line} -> {at[k].line})",
                    )
                )
                k += 1
                continue
            return f"a trailing comma added in {what} at line {bt[i].line} -> {at[k].line}"
        # a path to the same item
        if i < b_hi and k < a_hi:
            pb, pa = path_bounds(bt, i), path_bounds(at, k)
            if pb and pa and i - pb[0] == k - pa[0] and pb[1] <= b_hi and pa[1] <= a_hi:
                sb = [t.text for t in bt[pb[0] : pb[1] : 3]]
                sa = [t.text for t in at[pa[0] : pa[1] : 3]]
                same = check.same_item(sb, bm, sa, am)
                where = opaque(bt, bm.parent, pb[0]) or opaque(at, am.parent, pa[0])
                if same and where:
                    return (
                        f"the path {'::'.join(sb)} became {'::'.join(sa)} "
                        f"at line {bt[pb[0]].line} -> "
                        f"{at[pa[0]].line} inside {where}, which can see its text"
                    )
                if same:
                    quoted = quoted_condition(at, am.parent, pa[0])
                    note = (
                        f"; inside {quoted}!'s condition, which its failure message quotes"
                        if quoted
                        else ""
                    )
                    pair.notes.append(
                        (
                            "path",
                            f"{'::'.join(sb)} -> {'::'.join(sa)} "
                            f"(line {bt[pb[0]].line} -> {at[pa[0]].line}; {same}{note})",
                        )
                    )
                    i, k = pb[1], pa[1]
                    continue
        if i < b_hi and k < a_hi and bt[i].kind == "str" and key(bt[i]) == key(at[k]):
            where = opaque(bt, bm.parent, i) or opaque(at, am.parent, k)
            return (
                f"a string literal's text changed at line {bt[i].line} -> {at[k].line} "
                f"inside {where}, "
                "which can see its text"
            )
        bl = bt[i].line if i < b_hi else bt[b_hi - 1].line
        al = at[k].line if k < a_hi else at[a_hi - 1].line
        bs = " ".join(t.text for t in bt[max(b_lo, i - 3) : min(b_hi, i + 4)])
        as_ = " ".join(t.text for t in at[max(a_lo, k - 3) : min(a_hi, k + 4)])
        return f"tokens differ at line {bl} -> {al}: `{bs}` became `{as_}`"
    return None


def field_starts(toks, item, partner):
    """Where each field of a struct starts (its visibility or name), for `pub(super)`."""
    out = set()
    for group in (item.body, item.parens):
        if group is None or item.kind != "struct":
            continue
        k, expect = group[0] + 1, True
        while k < group[1]:
            t = toks[k]
            if expect:
                if t.kind in ("doc", "comment"):
                    k += 1
                    continue
                if attr_at(toks, k):
                    k = partner[k + 1] + 1
                    continue
                out.add(k)
                expect = False
            if t.kind == "punct" and t.text in "([{":
                k = partner[k] + 1
                continue
            if is_punct(t, "<"):
                depth = 1
                k += 1
                while k < group[1] and depth:
                    if is_punct(toks[k], "<"):
                        depth += 1
                    elif is_punct(toks[k], ">") and not is_punct(toks[k - 1], "-"):
                        depth -= 1
                    elif toks[k].kind == "punct" and toks[k].text in "([{":
                        k = partner[k]
                    k += 1
                continue
            if is_punct(t, ","):
                expect = True
            k += 1
    return out


class Commit:
    """One commit's check: the pairing, the comparisons and the import rules."""

    def __init__(self, before, after, base, changed, out):
        self.before, self.after, self.base = before, after, base
        self.changed = changed  # [(path, status)]
        self.out = out
        self.problems = []
        self.moves = {}  # before item path -> after item path

    def fail(self, text):
        self.problems.append(text)
        self.out(f"   FAIL {text}")

    # -------- resolution
    def same_item(self, sb, bm, sa, am):
        ab, aa = absolute(sb, bm.path), absolute(sa, am.path)
        if ab is None or aa is None:
            return None
        cb = canonical(self.before, self.root, ab)
        ca = canonical(self.after, self.root, aa)
        moved = self.moves.get(cb[0], cb[0])
        if moved == ca[0] and cb[1] == ca[1]:
            return "the same item " + show(ca[0] + ca[1])
        return None

    # -------- the run
    def run(self):
        entries_b, entries_a, mods_b, mods_a = [], [], {}, {}
        roots = set()
        for path, status in self.changed:
            for state, entries, mods in (
                (self.before, entries_b, mods_b),
                (self.after, entries_a, mods_a),
            ):
                if state.read(path) is None:
                    continue
                root, mpath = state.place(path)
                roots.add(root)
                collect(state, root, state.module(root, mpath), entries, mods)
        if not roots:
            self.out("   no Rust file changed")
            return
        if len(roots) > 1:
            self.fail(f"the commit changes more than one crate: {sorted(roots)}")
            return
        self.root = roots.pop()
        root = self.root
        new_modules = sorted(p for p in mods_a if self.before.module(root, p) is None)
        gone_modules = sorted(p for p in mods_b if self.after.module(root, p) is None)
        for p in gone_modules:
            self.fail(f"the module {show(p)} is gone")
        split = self.split = lambda p: self.base.module(root, p) is None  # a module the range made
        for p in new_modules:
            self.out(f"   new module {show(p)} ({mods_a[p].file})")

        def stripped(path):
            j = len(path)
            while j > 1 and self.before.module(root, tuple(path[:j])) is None:
                j -= 1
            return tuple(path[:j])

        for entries in (entries_b, entries_a):
            for e in entries:
                chain = tuple(key_text(e.module.toks, c) for c in e.chain)
                e.key = (
                    stripped(e.module.path),
                    chain,
                    e.item.kind,
                    key_text(e.module.toks, e.item) if e.item.kind == "impl" else e.item.name,
                )
                conds = set(e.module.conds)
                for c in e.chain:
                    conds |= item_conditions(e.module.toks, c)
                conds |= item_conditions(e.module.toks, e.item)
                e.conds = frozenset(conds)

        # pair: impl blocks group by key; everything else one to one
        by_key_b, by_key_a = {}, {}
        for e in entries_b:
            by_key_b.setdefault(e.key, []).append(e)
        for e in entries_a:
            by_key_a.setdefault(e.key, []).append(e)
        pairs = []
        for k in sorted(set(by_key_b) | set(by_key_a), key=lambda x: (x[0], x[1], x[2], str(x[3]))):
            bs, as_ = by_key_b.get(k, []), by_key_a.get(k, [])
            if k[2] == "impl":
                if not bs or not as_:
                    e = (bs or as_)[0]
                    shown = " ".join(
                        t.text
                        for t in e.module.toks[e.item.first : e.item.body[0]]
                        if t.kind not in ("doc", "comment")
                    )
                    self.fail(
                        f"`{shown}` in {show(k[0])}: "
                        f"{'added' if not bs else 'removed'} without a partner "
                        "with the same header and attributes"
                    )
                    continue
                for a in as_:
                    pairs.append(Pair(bs[0], a, self))
                continue
            if k[2] == "mod" and not bs and len(as_) == 1:
                mod_path = as_[0].module.path + (as_[0].item.name,)
                if mod_path in new_modules or self.before.module(root, mod_path) is None:
                    continue  # a new module's declaration, checked below
            if len(bs) != len(as_):
                what = f"{k[2]} {k[3]}" + (f" in {k[1][0]}" if k[1] else "")
                self.fail(f"{what} in {show(k[0])}: {len(bs)} before and {len(as_)} after")
                continue
            for b, a in zip(bs, as_):
                pairs.append(Pair(b, a, self))
        for p in pairs:
            if (
                p.b.item.kind
                in ("fn", "struct", "enum", "union", "trait", "const", "static", "type")
                and not p.b.chain
            ):
                self.moves[tuple(p.b.module.path) + (p.b.item.name,)] = tuple(p.a.module.path) + (
                    p.a.item.name,
                )
        counts = {}
        for p in pairs:
            status = self.compare_pair(p)
            counts[status] = counts.get(status, 0) + 1
        self.new_modules(new_modules, mods_a)
        self.imports(mods_b, mods_a, split)
        self.out("   items: " + ", ".join(f"{n} {s}" for s, n in sorted(counts.items())))

    # -------- one pair
    def compare_pair(self, p):
        b, a = p.b, p.a
        bi, ai = b.item, a.item
        label = entry_label(b)
        frm, to = show(b.module.path), show(a.module.path)
        moved = b.module.path != a.module.path
        problem = None
        if b.conds != a.conds:
            problem = (
                f"it was compiled under {show_condition(expanded(b.conds))} and is now under "
                f"{show_condition(expanded(a.conds))}"
            )
        elif bi.kind == "impl":
            problem = compare(p, bi.first, bi.body[0], ai.first, ai.body[0])
        elif bi.kind == "mod":
            if moved:
                problem = "a module declaration moved (a #[path] is read from where it is written)"
            else:
                problem = compare(p, bi.first, bi.kw + 2, ai.first, ai.kw + 2)
                if problem is None:
                    mb = self.before.module(self.root, tuple(b.module.path) + (bi.name,))
                    ma = self.after.module(self.root, tuple(a.module.path) + (ai.name,))
                    if mb is None or ma is None:
                        problem = "the module's body is missing"
                    else:
                        inner = Pair(Entry(mb, bi, ()), Entry(ma, ai, ()), self)
                        problem = compare(inner, mb.inner[0], mb.inner[1], ma.inner[0], ma.inner[1])
                        if problem:
                            problem = "its inner attributes or docs: " + problem
        else:
            points = set()
            if bi.vis == "" and not (b.chain and " for " in b.chain[0].header):
                points.add(bi.head)
            points |= {
                s
                for s in field_starts(b.module.toks, bi, b.module.partner)
                if not (b.module.toks[s].kind == "ident" and b.module.toks[s].text == "pub")
            }
            problem = compare(p, bi.first, bi.end, ai.first, ai.end, points)
        if problem is None and moved and bi.kind != "mod":
            problem = self.placement(p)
        status = "moved" if moved else "kept"
        if any(kind != "vis" for kind, _ in p.notes) and problem is None:
            status += ", rewritten"
        self.out(f"   {status:<16} {label:<56} {frm}" + (f" -> {to}" if moved else ""))
        for kind, text in p.notes:
            self.out(f"      {kind}: {text}")
        if problem:
            self.fail(f"{label} ({frm} -> {to}): {problem}")
            return "failed"
        return status

    def placement(self, p):
        """What an item that moved may not carry."""
        toks, it = p.b.module.toks, p.b.item
        k, end = it.first, (it.body[0] if it.kind == "impl" else it.end)
        while k < end:
            t = toks[k]
            if attr_at(toks, k):
                open_ = k + (2 if is_punct(toks[k + 1], "!") else 1)
                close = p.b.module.partner[open_]
                path, j = attr_path(toks, k, close + 1)
                if path not in ALLOWED_ATTRS:
                    return f"it carries the attribute #[{path}] (line {t.line})"
                if path == "derive":
                    for part in top_level_parts("".join(x.text for x in toks[j + 1 : close - 1])):
                        if part not in ALLOWED_DERIVES:
                            return f"it derives {part} (line {t.line})"
                k = close + 1
                continue
            if (
                t.kind == "ident"
                and t.text in PLACE_MACROS
                and k + 1 < end
                and is_punct(toks[k + 1], "!")
            ):
                return f"it uses {t.text}! (line {t.line})"
            if t.kind == "ident" and t.text in PLACE_NAMES:
                return f"it uses {t.text} (line {t.line})"
            if (
                t.kind == "ident"
                and t.text == "Location"
                and k + 3 < end
                and toks[k + 3].text == "caller"
            ):
                return f"it uses Location::caller (line {t.line})"
            k += 1
        return None

    # -------- modules the commit adds
    def new_modules(self, new_modules, mods_a):
        for p in new_modules:
            mod = mods_a[p]
            decl = mod.decl
            if decl is None:
                self.fail(f"the module {show(p)} has no declaration")
                continue
            up = self.after.module(self.root, p[:-1])
            if decl.vis:
                self.fail(f"the new module {show(p)} is declared {decl.vis}")
            for lo, hi in decl.attrs:
                self.fail(
                    f"the new module {show(p)} is declared with "
                    f"{' '.join(t.text for t in up.toks[lo:hi])}"
                )
            if decl.body is not None:
                self.fail(f"the new module {show(p)} is inline")
            lo, hi = mod.inner
            for t in mod.toks[lo:hi]:
                if t.kind not in ("doc", "comment"):
                    self.fail(f"the new module {show(p)} starts with an attribute at line {t.line}")
                    break
            old = self.base.module(self.root, p[:-1])
            if old is not None:
                old_docs = {
                    t.text.strip() for t in old.toks[old.inner[0] : old.inner[1]] if t.kind == "doc"
                }
                old_docs -= {"//!", "/*!*/"}
                for t in mod.toks[lo:hi]:
                    if t.kind == "doc" and t.text.strip() in old_docs:
                        self.fail(
                            f"the new module {show(p)} repeats its old module's docs "
                            f"at line {t.line}"
                        )
                        break

    # -------- imports
    def imports(self, mods_b, mods_a, split):
        root = self.root
        for path in sorted(mods_a):
            mod_a = mods_a[path]
            mod_b = mods_b.get(path) or self.before.module(root, path)
            if split(path):
                self.split_imports(mod_a)
            elif "test" in mod_a.conds:
                self.test_imports(mod_b, mod_a)
            else:
                self.origin_imports(mod_b, mod_a)
        # every public item that moved out of a module is re-exported there
        for frm, to in sorted(self.moves.items()):
            if frm[:-1] == to[:-1]:
                continue
            origin = self.after.module(root, frm[:-1])
            target = self.after.module(root, to[:-1])
            if origin is None or target is None:
                continue
            item = next(
                (it for it in target.items if it.name == to[-1] and it.kind not in ("use", "impl")),
                None,
            )
            if item is None or item.vis != "pub":
                continue
            bound = [
                b
                for b in origin.bindings().get(frm[-1], [])
                if b.vis == "pub"
                and canonical(self.after, root, binding_target(b, origin, self.after, root))[0]
                == to
            ]
            if not bound:
                self.fail(
                    f"the public {item.kind} {show(frm)} moved to {show(to)} "
                    "without a pub use at its old path"
                )

    def target(self, state, mod, b):
        return canonical(state, self.root, binding_target(b, mod, state, self.root))

    def split_imports(self, mod):
        root = self.root
        origin_path = mod.path[:-1]
        old = self.base.module(root, origin_path)
        old_names = old.item_names() if old else set()
        old_targets = {}
        if old:
            for name, bs in old.bindings().items():
                for b in bs:
                    old_targets.setdefault(name, []).append(self.target(self.base, old, b))
        own = mod.item_names()
        bound = {}
        tally = {}
        for name, bs in sorted(mod.bindings().items()):
            for b in bs:
                t = self.target(self.after, mod, b)
                bound[name] = t
                where = f"{show(mod.path)}: use {'::'.join(x for x in b.path if x)}" + (
                    f" as {name}" if name != b.path[-1] else ""
                )
                if b.vis:
                    self.fail(f"{where} is {b.vis}")
                if b.other_attrs:
                    self.fail(f"{where} carries {b.other_attrs}")
                if name == "*":
                    self.fail(f"{where} is a glob")
                    continue
                if name == "_":
                    ok = any(t in ts for ts in old_targets.values())
                    reason = "of the old module's traits, unnamed"
                elif t in old_targets.get(name, []):
                    ok, reason = True, "bound as the old module bound them"
                else:
                    home = t[0][:-1]
                    ok = (
                        t[1] == ()
                        and t[0][-1] == name
                        and name in old_names
                        and (home == origin_path or (home[:-1] == origin_path and self.split(home)))
                    )
                    reason = "of the old module's own items, from where they are now"
                if not ok:
                    self.fail(
                        f"{where} names {show(t[0] + t[1])}, "
                        f"which the old module did not bind to {name}"
                    )
                    continue
                tally[reason] = tally.get(reason, 0) + 1
                self.condition(mod, b, where, reason)
        self.out(
            f"      imports of {show(mod.path)}: "
            + (", ".join(f"{n} {r}" for r, n in sorted(tally.items())) or "none")
        )
        kept = set(bound.values())
        left = sorted(
            n for n, ts in old_targets.items() if n != "_" and not any(t in kept for t in ts)
        )
        if left:
            self.out(
                f"      not kept from the old module's imports ({len(left)}): {', '.join(left)}"
            )
        self.prelude(mod, old)

    def prelude(self, mod, old):
        """A name the prelude also has, which the old module bound, is bound the same way here."""
        if old is None:
            return
        own = mod.item_names()
        bound = mod.bindings()
        for name in sorted(PRELUDE & (set(old.bindings()) | old.item_names())):
            if name in own or not self.names(mod, name):
                continue
            if name in old.item_names():
                want = [(self.moves.get(tuple(old.path) + (name,), tuple(old.path) + (name,)), ())]
            else:
                want = [self.target(self.base, old, b) for b in old.bindings()[name]]
            have = [self.target(self.after, mod, b) for b in bound.get(name, [])]
            if not any(h in want for h in have):
                self.fail(
                    f"{show(mod.path)} names {name}, which the old module bound, without binding "
                    f"it the same way"
                )

    def names(self, mod, name, kind=None):
        """The code in `mod` that names `name`: [(label, conditions)]."""
        users = []
        entries = []
        for it in mod.items:
            if it.kind in ("use", "trivia"):
                continue
            if it.kind == "impl":
                entries.append((it, ()))
                for ch in it.children:
                    entries.append((ch, (it,)))
            elif it.kind == "mod" and it.body is not None:
                continue
            else:
                entries.append((it, ()))
        toks = mod.toks
        for it, chain in entries:
            base_conds = set(mod.conds) | item_conditions(toks, it)
            for c in chain:
                base_conds |= item_conditions(toks, c)
            inner = inner_cfgs(toks, mod.partner, mod.parent, it)
            found = set()
            for k in range(it.first, it.body[0] if it.kind == "impl" else it.end):
                t = toks[k]
                if (
                    t.kind == "str"
                    and in_macro_input(toks, mod.parent, k)
                    and name in format_names(t)
                ):
                    conds = set(base_conds)
                    for lo, hi, preds in inner:
                        if lo <= k < hi:
                            conds |= preds
                    found.add(frozenset(conds))
                    continue
                if t.kind != "ident" or t.text != name:
                    continue
                if field_or_method(toks, k):
                    continue
                if k > 1 and is_punct(toks[k - 1], ":") and is_punct(toks[k - 2], ":"):
                    continue
                nxt = toks[k + 1] if k + 1 < len(toks) else None
                path_next = (
                    nxt is not None
                    and is_punct(nxt, ":")
                    and k + 2 < len(toks)
                    and is_punct(toks[k + 2], ":")
                )
                if kind == "module" and not path_next:
                    continue
                if nxt is not None and is_punct(nxt, ":") and not path_next:
                    continue
                conds = set(base_conds)
                for lo, hi, preds in inner:
                    if lo <= k < hi:
                        conds |= preds
                found.add(frozenset(conds))
            label = entry_label(Entry(mod, it, chain))
            for conds in sorted(found, key=sorted):
                users.append((label, conds))
        return users

    def condition(self, mod, b, where, reason):
        kind = (
            "module"
            if b.path
            and self.after.module(self.root, self.target(self.after, mod, b)[0]) is not None
            else None
        )
        users = self.names(mod, b.name, kind) if b.name != "_" else []
        have = minimal(b.conds)
        if not users:
            if have != {frozenset()}:
                self.fail(f"{where} is under {show_condition(have)}, but no code here names it")
            return
        want = minimal(set().union(*[expanded(u[1]) for u in users]))
        if have != want:
            self.fail(
                f"{where} is under {show_condition(have)}, but the code that names it is under "
                f"{show_condition(want)}: "
                + "; ".join(f"{l} [{show_condition(expanded(c))}]" for l, c in users)
            )
            return
        if have != {frozenset()}:
            self.out(
                f"      import {where} [{show_condition(have)}] ({reason}), named by: "
                + "; ".join(f"{l} [{show_condition(expanded(c))}]" for l, c in users)
            )

    def origin_imports(self, mod_b, mod_a):
        """A module that was there before the range: keep, drop, or bind a moved item."""
        root = self.root
        old = self.base.module(root, mod_a.path)
        old_names = old.item_names() if old else set()
        before = {}
        if mod_b is not None:
            for name, bs in mod_b.bindings().items():
                for b in bs:
                    before.setdefault(name, []).append((b, self.target(self.before, mod_b, b)))
        after_names = set()
        for name, bs in sorted(mod_a.bindings().items()):
            for b in bs:
                after_names.add(name)
                t = self.target(self.after, mod_a, b)
                shown = "::".join(x for x in b.path if x) + (
                    f" as {name}" if name != b.path[-1] else ""
                )
                where = f"{show(mod_a.path)}: {b.vis + ' ' if b.vis else ''}use {shown}"
                kept = [
                    bb
                    for bb, tt in before.get(name, [])
                    if bb.vis == b.vis
                    and bb.other_attrs == b.other_attrs
                    and (self.moves.get(tt[0], tt[0]), tt[1]) == t
                ]
                if kept:
                    if kept[0].path != b.path:
                        self.out(
                            f"      import {where}: rewritten to the same item {show(t[0] + t[1])}"
                        )
                    if minimal(kept[0].conds) != minimal(b.conds):
                        self.out(
                            f"      import {where}: from {show_condition(kept[0].conds)} to "
                            f"{show_condition(b.conds)}"
                        )
                    if minimal(b.conds) != {frozenset()} or minimal(kept[0].conds) != minimal(
                        b.conds
                    ):
                        self.condition(mod_a, b, where, "kept")
                    continue
                home = t[0][:-1]
                moved_item = (
                    t[1] == ()
                    and t[0][-1] == name
                    and name in old_names
                    and home[:-1] == tuple(mod_a.path)
                    and self.base.module(root, home) is None
                )
                if not moved_item or b.other_attrs:
                    self.fail(
                        f"{where} is new, and names {show(t[0] + t[1])}, "
                        "not an item moved out of here"
                    )
                    continue
                item_vis = self.item_vis(t[0])
                if b.vis not in ("", item_vis if item_vis == "pub" else ""):
                    self.fail(f"{where} is {b.vis}, but the item is {item_vis or 'private'}")
                    continue
                self.out(
                    f"      import {where}: {'re-exports' if b.vis else 'binds'} "
                    f"the moved item {show(t[0])}"
                )
                self.condition(mod_a, b, where, "a moved item")
        self.prelude(mod_a, old)
        dropped = sorted(set(before) - after_names)
        if dropped:
            self.out(f"      imports dropped from {show(mod_a.path)}: {', '.join(dropped)}")

    def test_imports(self, mod_b, mod_a):
        before, after = [], []
        for mod, state, out in ((mod_b, self.before, before), (mod_a, self.after, after)):
            if mod is None:
                continue
            for name, bs in mod.bindings().items():
                for b in bs:
                    t = self.target(state, mod, b)
                    if state is self.before:
                        t = (self.moves.get(t[0], t[0]), t[1])
                    out.append(
                        (name, b.vis, show_condition(b.conds), tuple(b.other_attrs), t, b.path)
                    )
        bs = sorted(x[:5] for x in before)
        as_ = sorted(x[:5] for x in after)
        if bs != as_:
            self.fail(
                f"the test module {show(mod_a.path)} changed its imports: "
                f"{sorted(set(bs) - set(as_))} became {sorted(set(as_) - set(bs))}"
            )
            return
        self.out(
            f"      imports of the test module {show(mod_a.path)}: "
            f"{len(after)} kept, each naming the same item"
        )
        for x, y in zip(sorted(before), sorted(after)):
            if x[5] != y[5]:
                self.out(
                    f"      import {show(mod_a.path)}: {'::'.join(p for p in x[5] if p)} -> "
                    f"{'::'.join(p for p in y[5] if p)} (the same item {show(y[4][0] + y[4][1])})"
                )

    def item_vis(self, path):
        mod = self.after.module(self.root, path[:-1])
        if mod is None:
            return None
        for it in mod.items:
            if it.name == path[-1] and it.kind not in ("use", "impl"):
                return it.vis
        return None


def inner_cfgs(toks, partner, parent, item):
    """The `#[cfg]` attributes inside an item's body, each with the tokens it governs."""
    out = []
    lo = item.body[0] + 1 if item.body else item.first
    k = lo
    while k < item.end:
        if attr_at(toks, k) and is_punct(toks[k + 1], "["):
            close = partner[k + 1]
            pred = cfg_of(toks, k, close + 1)
            if pred is not None and k > item.head:
                g = parent[k]
                end_ = partner[g] if g >= 0 else item.end
                j = close + 1
                while j < end_:
                    t = toks[j]
                    if t.kind == "punct" and t.text in "([{":
                        if (
                            is_punct(t, "{")
                            and j >= 2
                            and is_punct(toks[j - 1], ">")
                            and is_punct(toks[j - 2], "=")
                        ):
                            j = partner[j] + 1
                            break
                        j = partner[j] + 1
                        continue
                    if t.kind == "punct" and t.text in ",;":
                        break
                    j += 1
                out.append((close + 1, j, split_predicates(pred)))
            k = close + 1
            continue
        k += 1
    return out


def key_text(toks, item):
    if item.kind == "impl":
        attrs = " ".join(str(key(t)) for lo, hi in item.attrs for t in toks[lo:hi])
        return attrs + " || " + " ".join(str(key(t)) for t in toks[item.head : item.body[0]])
    return item.name


# ------------------------------------------------------------------------------------------ git


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo, *args], check=True, capture_output=True, text=True
    ).stdout


def git_reader(repo, rev):
    cache = {}

    def read(path):
        if path not in cache:
            r = subprocess.run(
                ["git", "-C", repo, "cat-file", "blob", f"{rev}:{path}"], capture_output=True
            )
            cache[path] = r.stdout.decode("utf-8") if r.returncode == 0 else None
        return cache[path]

    return read


def run_range(repo, base, head, mounts, out):
    commits = git(repo, "rev-list", "--reverse", "--first-parent", f"{base}..{head}").split()
    base_state = State(base[:12], git_reader(repo, base), mounts)
    failed = 0
    for c in commits:
        subject = git(repo, "log", "-1", "--format=%s", c).strip()
        out(f"== commit {c[:12]} {subject}")
        changed = []
        for line in git(repo, "diff", "--name-status", "--no-renames", f"{c}^", c).splitlines():
            status, path = line.split("\t", 1)
            if path.endswith(".rs"):
                changed.append((path, status))
        for path, status in changed:
            out(f"   file {status} {path}")
        commit = Commit(
            State(c[:12] + "^", git_reader(repo, c + "^"), mounts),
            State(c[:12], git_reader(repo, c), mounts),
            base_state,
            changed,
            out,
        )
        try:
            commit.run()
        except CheckError as error:
            commit.fail(str(error))
        if commit.problems:
            failed += 1
            out(f"   result: FAILED ({len(commit.problems)} problems)")
        else:
            out("   result: passed")
    verdict = "passed" if not failed else f"FAILED in {failed} of {len(commits)} commits"
    out(f"check-moved-items {base[:12]}..{head[:12]}: {len(commits)} commits, {verdict}")
    return 0 if not failed else 1


# ------------------------------------------------------------------------------------ self-test

SELF_BASE = {
    "src/lib.rs": "pub mod service;\n",
    "src/net/mod.rs": "pub mod dispatch;\n\npub fn reach() -> u32 {\n    super::LIMIT\n}\n",
    "src/net/dispatch.rs": "use super::reach;\n\npub fn relay() -> u32 {\n    reach()\n}\n",
    "src/service.rs": '''//! The service.

use std::sync::Arc;

use crate::error::Result;

#[path = "net/mod.rs"]
pub mod net;

/// How many there are.
pub const LIMIT: u32 = 4;

const MESSAGE: &str = "one line \\
    continued";

/// The controller.
pub struct Controller {
    count: u32,
}

impl Controller {
    /// Starts it.
    pub fn start() -> Self {
        Controller { count: LIMIT }
    }

    fn helper(&self) -> u32 {
        self.count
    }
}

#[cfg(feature = "testing")]
impl Controller {
    fn armed(&self) -> bool {
        self.count > 0
    }
}

fn pair() -> (u8,) {
    (1,)
}

fn label() -> &'static str {
    stringify!(self::MESSAGE)
}

fn parse(value: &str) -> Result<Arc<str>> {
    let pair = (value.len(), MESSAGE.len());
    let first = (pair.0);
    report!(first, pair.1);
    Ok(Arc::from(value))
}

fn announce() -> usize {
    parse("x").map(|text| text.len()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::Controller;

    #[test]
    fn starts() {
        let text = "a \\
                    b";
        assert_eq!(
            super::Controller::start().helper(),
            super::LIMIT,
        );
        assert!(!text.is_empty());
        report!("a \\
                    b");
    }
}
''',
}

SELF_GOOD = {
    "src/service.rs": '''//! The service.

use std::sync::Arc;

use crate::error::Result;

#[path = "net/mod.rs"]
pub mod net;

mod helpers;

use helpers::parse;
pub use helpers::LIMIT;

const MESSAGE: &str = "one line \\
    continued";

/// The controller.
pub struct Controller {
    count: u32,
}

impl Controller {
    /// Starts it.
    pub fn start() -> Self {
        Controller { count: LIMIT }
    }
}

#[cfg(feature = "testing")]
impl Controller {
    fn armed(&self) -> bool {
        self.count > 0
    }
}

fn pair() -> (u8,) {
    (1,)
}

fn label() -> &'static str {
    stringify!(self::MESSAGE)
}

fn announce() -> usize {
    parse("x").map(|text| text.len()).unwrap_or_default()
}

#[cfg(test)]
mod tests;
''',
    "src/service/helpers.rs": '''//! What the controller reads with.

use std::sync::Arc;

use super::{Controller, MESSAGE};
use crate::error::Result;

/// How many there are.
pub const LIMIT: u32 = 4;

impl Controller {
    pub(super) fn helper(&self) -> u32 {
        self.count
    }
}

pub(super) fn parse(value: &str) -> Result<Arc<str>> {
    let pair = (value.len(), MESSAGE.len(),);
    let first = (pair.0);
    report!(first, pair.1);
    Ok(Arc::from(value))
}
''',
    "src/service/tests.rs": '''use super::Controller;

#[test]
fn starts() {
    let text = "a \\
                b";
    assert_eq!(super::Controller::start().helper(), super::LIMIT);
    assert!(!text.is_empty());
    report!("a \\
                    b");
}
''',
}

# each defect: (what it is, the file it changes, the text replaced, its replacement)
SELF_DEFECTS = [
    (
        "a changed token",
        "src/service/helpers.rs",
        "        self.count\n",
        "        self.count + 0\n",
    ),
    (
        "a widened visibility",
        "src/service/helpers.rs",
        "pub(super) fn helper",
        "pub(crate) fn helper",
    ),
    ("a dropped visibility", "src/service/helpers.rs", "pub const LIMIT", "const LIMIT"),
    (
        "pub(super) on an item that did not need a move",
        "src/service.rs",
        "const MESSAGE",
        "pub(super) const MESSAGE",
    ),
    (
        "a changed import source",
        "src/service/helpers.rs",
        "use std::sync::Arc;",
        "use alloc::sync::Arc;",
    ),
    (
        "an import whose condition differs from its user's",
        "src/service/helpers.rs",
        "use std::sync::Arc;",
        "#[cfg(test)]\nuse std::sync::Arc;",
    ),
    (
        "a changed macro input",
        "src/service/helpers.rs",
        "report!(first, pair.1);",
        "report!(first, pair.1,);",
    ),
    (
        "a tuple of one element made",
        "src/service/helpers.rs",
        "let first = (pair.0);",
        "let first = (pair.0,);",
    ),
    (
        "a changed literal",
        "src/service.rs",
        "one line \\\n    continued",
        "one line \\\n    continues",
    ),
    ("a dropped cfg", "src/service.rs", "#[cfg(test)]\nmod tests;", "mod tests;"),
    (
        "an extra cfg on a new module",
        "src/service.rs",
        "mod helpers;",
        "#[cfg(test)]\nmod helpers;",
    ),
    ("a moved #[path] mount", "src/service.rs", '#[path = "net/mod.rs"]\npub mod net;\n', ""),
    (
        "a public item moved without its re-export",
        "src/service.rs",
        "pub use helpers::LIMIT;",
        "use helpers::LIMIT;",
    ),
    (
        "a prelude name left to the prelude",
        "src/service/helpers.rs",
        "use crate::error::Result;\n",
        "",
    ),
    (
        "a new module that repeats its old module's docs",
        "src/service/helpers.rs",
        "//! What the controller reads with.\n",
        "//! What the controller reads with.\n\n//! The service.\n",
    ),
    (
        "a tuple of one element unmade in a return type",
        "src/service.rs",
        "fn pair() -> (u8,)",
        "fn pair() -> (u8)",
    ),
    (
        "an impl's condition dropped",
        "src/service.rs",
        "#[cfg(feature = \"testing\")]\nimpl Controller",
        "impl Controller",
    ),
    (
        "a literal re-indented in another macro's input",
        "src/service/tests.rs",
        'report!("a \\\n                    b");',
        'report!("a \\\n                b");',
    ),
]


def self_test():
    failures = []
    lines = []

    def run(files_before, files_after, expect_pass, what):
        mounts = {"src/net/mod.rs": ("crate", "service", "net")}
        before = State("before", files_before.get, mounts)
        after = State("after", files_after.get, mounts)
        base = State("base", files_before.get, mounts)
        changed = sorted(
            {
                p
                for p in set(files_before) | set(files_after)
                if files_before.get(p) != files_after.get(p)
            }
        )
        commit = Commit(before, after, base, [(p, "M") for p in changed], lines.append)
        try:
            commit.run()
        except CheckError as error:
            commit.fail(str(error))
        passed = not commit.problems
        verdict = "passes" if passed else "fails: " + commit.problems[0]
        print(f"  {'ok ' if passed == expect_pass else 'BAD'} {what}: {verdict}")
        if passed != expect_pass:
            failures.append(what)
            for line in lines:
                print("     |", line)
        lines.clear()

    good = dict(SELF_BASE)
    good.update(SELF_GOOD)
    # the network module moves one level down in the good case's second step
    run(
        SELF_BASE,
        good,
        True,
        "a move with a de-indented escaped continuation, a dropped comma, "
        "a narrowed pub(super) and a re-export",
    )
    for what, path, old, new in SELF_DEFECTS:
        bad = dict(good)
        if old not in bad[path]:
            failures.append(what + " (the case does not apply)")
            continue
        bad[path] = bad[path].replace(old, new, 1)
        if what == "a moved #[path] mount":
            bad["src/service/helpers.rs"] += '\n#[path = "net/mod.rs"]\npub mod net;\n'
        run(SELF_BASE, bad, False, what)
    # a path rewritten inside stringify! names the same item, and changes its text
    moved = dict(good)
    moved["src/service.rs"] = moved["src/service.rs"].replace(
        "fn label() -> &'static str {\n    stringify!(self::MESSAGE)\n}\n\n", ""
    )
    moved["src/service/helpers.rs"] += (
        "\nfn label() -> &'static str {\n    stringify!(super::MESSAGE)\n}\n"
    )
    run(SELF_BASE, moved, False, "a path rewritten inside stringify!")
    # a path one level down names the same item
    deeper_before = dict(SELF_BASE)
    deeper_before["src/net/dispatch.rs"] = (
        "use super::reach;\n\npub fn relay() -> u32 {\n    reach() + super::super::LIMIT\n}\n"
    )
    deeper_after = dict(deeper_before)
    deeper_after["src/net/dispatch.rs"] = "mod relays;\n"
    deeper_after["src/net/dispatch/relays.rs"] = (
        "use super::super::reach;\n\npub fn relay() -> u32 {\n"
        "    reach() + super::super::super::LIMIT\n}\n"
    )
    run(deeper_before, deeper_after, False, "a public function moved without its re-export")
    deeper_after["src/net/dispatch.rs"] = "mod relays;\n\npub use relays::relay;\n"
    run(deeper_before, deeper_after, True, "a path written one level down")
    deeper_after["src/net/dispatch/relays.rs"] = (
        "use super::super::reach;\n\npub fn relay() -> u32 {\n"
        "    reach() + super::super::LIMIT\n}\n"
    )
    run(deeper_before, deeper_after, False, "a relative path left as it was one level down")
    if failures:
        print(f"self-test FAILED: {len(failures)} of {len(SELF_DEFECTS) + 5} cases")
        return 1
    print(f"self-test passed: {len(SELF_DEFECTS) + 5} cases")
    return 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("base", nargs="?")
    parser.add_argument("head", nargs="?")
    parser.add_argument(
        "--mount",
        action="append",
        default=[],
        help="<file>=<module path>: a file loaded through #[path]",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check this checker against moves it must pass and moves it must fail",
    )
    options = parser.parse_args(argv)
    if options.self_test:
        return self_test()
    if not options.base or not options.head:
        parser.error("give a base and a head, or --self-test")
    mounts = {}
    for m in options.mount:
        f, _, p = m.partition("=")
        mounts[f] = tuple(p.split("::"))
    repo = git(".", "rev-parse", "--show-toplevel").strip()
    return run_range(repo, options.base, options.head, mounts, print)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
