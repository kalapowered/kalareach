# kalareach/example-declarative

A complete package with no Wasm component. It recognises the example agent by its executable name,
presents a short document with a progress node, and registers one observation action that a control
invokes.

It exists so the catalogue pipeline, the host's package validator and the host's sync path all have
something real to run against, and so a package author has a working example to copy.

## What it asks for

Only the three capabilities a newly enrolled repository already permits: metadata matching,
declarative presentation, and broker semantic events the actor is already authorised to see. It
installs nothing, touches no files and sends nothing upstream.

## Files

| File | What it is |
| --- | --- |
| `plugin.json` | Identity, match rule, payloads, capabilities and the one registered action |
| `presentation.json` | Three nodes and one control |
| `fixtures/visibility.json` | Contexts and the controls each one should show and enable |
| `README.md` | This file, declared as a package asset so its digest is pinned with the rest |

The pipeline evaluates `fixtures/visibility.json` against the control predicates in
`presentation.json` on every validation run, so a change to a predicate that alters what a person
sees fails the build.
