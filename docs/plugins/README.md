# KalaReach plugin reference

A plugin is an installable package. An adapter is that package actively bound to a running
application. This describes what a package contains, what it may ask for, what it can and cannot
express, and how a host checks it before trusting any of it.

Three pieces make it up:

- `crates/kr-plugin-sdk` holds the manifest types, the WIT package, the effect table, the
  catalogue index and the package validator.
- `packages/plugin-sdk` is the generated TypeScript package: the same types, the package contract
  as data, the published WIT file and a schema-checking loader.
- `fixtures/plugins/` holds the packages both languages are tested against, including one of each
  defect the validator is meant to catch.

Rust is canonical. The JSON Schema comes from the Rust types, the TypeScript types come from the
schema, and the WIT file is copied from the crate. Each step has a check mode, so a change on one
side that is not carried to the other fails the build.

## What a package is

A directory:

| File | Required | What it is |
| --- | --- | --- |
| `plugin.json` | yes | The manifest: identity, match rules, payloads, capabilities and actions |
| `presentation.json` | yes | The document nodes and controls the package contributes |
| `connector.json` | no | The declarative native-proxy table |
| `component.wasm` | no | The Wasm component |
| anything else | no | Assets, native bridge files, skill packages and fixtures |

Every file except `plugin.json` is declared in `plugin.json` by path, SHA-256 digest and exact
length. A file on disk that the manifest does not declare is a finding. A declared file that is
absent, the wrong length or the wrong digest is a finding. The manifest is the one file that does
not declare itself: its digest lives in the catalogue index entry that points at it, which is what
lets a host pin one hash and get the whole package.

Most packages ship no Wasm. Match rules, a document and declarative controls are a complete
package, and that is the point: a vendor can add detection, semantic events and commands without a
core or companion-app release.

Check a package with the offline validator:

```bash
cargo run -p kr-plugin-sdk --bin kr-plugin-sandbox -- path/to/package
cargo run -p kr-plugin-sdk --bin kr-plugin-sandbox -- path/to/package --json
```

It reads the directory and executes nothing in it: no script, no installation step and no Wasm. It
exits 0 when the package is valid and 1 when it is not, and prints every finding rather than
stopping at the first.

## The manifest

`plugin.json` carries:

- **Identity.** `publisher_id` and `plugin_name`, both immutable for the package's life, plus an
  exact `version`. The wire identifier is the two joined with a slash.
- **Ranges.** `sdk_range` and `wit_range` say which SDK and component interface the package was
  written against. A range that admits every version is rejected, because it claims the package
  works on releases nobody tested it on.
- **Source.** The repository and revision the release was built from. A reviewed catalogue entry
  pins the publisher, the source revision and the package digest. Hosts install that release; they
  never run a vendor repository's current branch.
- **Match rules.** What the package recognises, by executable and distribution.
- **Platforms.** Operating systems and architectures.
- **Payloads.** Every byte, by role, path, digest and length.
- **Capabilities.** What the package asks to be permitted, each with the reason a person reads in
  the installation grant.
- **Actions.** Everything a control may invoke, each with its effect class and parameter schema.
- **Attachments and native bridge.** Optional, and each needs its matching capability.

### Paths

A package path is relative, uses `/` on every platform, and must mean one unambiguous file on
Linux, macOS and Windows. Rejected: `..` and `.` segments, absolute and drive-prefixed paths,
backslashes, empty segments, Windows device names (`nul`, `com1`, and the rest, with or without an
extension), trailing dots and spaces, control characters, and the zero-width and bidirectional
characters that make one name render as another. A path is at most 512 bytes and 8 segments; a
segment is at most 128 bytes.

Two paths that differ only by case, or only by a trailing dot or space, are treated as a
collision. macOS and Windows would resolve both to one file, and the package contract does not
decide which one wins.

### Match rules

A rule names an executable file stem, optionally some whole path segments its directory must end
with, and optionally the distribution the application came from: an npm package, a PyPI project, a
Homebrew formula, a crate, a Go module, a Debian package, a macOS bundle identifier, a Windows
package identifier or a container image.

There is no regular expression and no glob. The host evaluates these rules against every candidate
executable on the machine, so the grammar is fixed-cost by construction.

A rule states its own confidence. An `exact` rule identifies the application by something that
cannot be coincidence, such as a bundle identifier. An `inferred` rule is a reasonable guess from a
name on disk, and it is presented as a guess. Neither overrides a selection the user made.

## Capabilities

A package asks for capabilities from a closed vocabulary:

| Capability | Inside the default ceiling | Needs an installation grant |
| --- | --- | --- |
| `metadata.match` | yes | no |
| `presentation.declarative` | yes | no |
| `broker.semantic_events` | yes | no |
| `terminal.stream` | no | no |
| `terminal.transcript_tail` | no | no |
| `process.observe` | no | no |
| `upstream.action` | no | no |
| `approval.decode` | no | no |
| `terminal.input` | no | yes |
| `filesystem.read` | no | yes |
| `network.outbound` | no | yes |
| `approval.respond` | no | yes |
| `native_bridge.install` | no | yes |

Enrolling a repository sets a ceiling before anything is fetched. The default ceiling is the first
three rows: metadata matching, declarative presentation and broker semantic events the actor is
already authorised to see. That is what stops thousands of passive catalogue downloads from
becoming thousands of permission prompts. Everything else needs an explicit package or repository
grant, and a new executable bridge or an increase in privilege needs an explicit installation
grant.

Capability evidence is a separate thing with a confusingly similar name. A capability request is
what a package asks for. A capability evidence record is what a host currently knows about whether
something works here: the capability and version, the subject environment, application, terminal or
desktop generation, the exact binary, schema, package or profile identity it was gathered against,
the current state, what would invalidate it, and the reason a person reads when it is unavailable.

States are distinguished because "unavailable" alone sends people to the wrong fix: qualified and
available, missing installation, permission required, incompatible, temporarily unavailable, and
not tested.

Evidence is never authority. A signed compatibility record says how a version behaves; it does not
say this host has permission, and the validator rejects a signed or declared record that claims a
capability is qualified here. Only a host probe or a live binding can establish that, and the grant
check still happens separately on every action.

## Effect classes

An action declares its effect class in the manifest. The broker validates the prepared effect
against that class, so an action cannot acquire rights by calling itself something harmless.

| Effect class | Mutation | Rights the broker intersects | Capability it needs |
| --- | --- | --- | --- |
| `observe` | no | `session.view` | `broker.semantic_events` |
| `upstream.prompt` | yes | `agent.prompt` | `upstream.action` |
| `upstream.cancel` | yes | `agent.cancel` | `upstream.action` |
| `upstream.attachment` | yes | `agent.prompt`, `files.upload` | `upstream.action` |
| `approval.decode` | no | none | `approval.decode` |
| `approval.respond` | yes | `agent.approval.respond` | `approval.respond` |
| `terminal.input` | yes | `terminal.input` | `terminal.input` |

`approval.decode` needs no action right because decoding proposes a resource rather than answering
one. The trust to decode is recorded against the publisher and its methods, separately from the
action vocabulary, and answering still needs `agent.approval.respond`.

A control may name only an action the manifest registers, so the class the broker enforces is
always the one the publisher declared and a reviewer read.

### Parameters

An action's parameters are a bounded list rather than an arbitrary JSON Schema: text with a
maximum length, an integer with an inclusive range, a boolean, a choice from a fixed list, a
completed attachment handle, or a reference to a node in the package's own document. At most 16
parameters, at most 24 choices.

The bound is what makes the parameter hash in the action token mean something. A callback is bound
to the actor, the grant, the application and thread revision, the declared action and the hash of
exactly the parameters a person saw.

## The document

A package contributes a document, not an interface. The node union is closed:

`message`, `markdown`, `tool`, `diff`, `progress`, `form`, `attachment`, `approval_ref`,
`terminal_ref`, `action_button`, `action_group`, `command_palette`, `attachment_entry`.

Every node has a stable identifier and a revision, and the document names the base revision a delta
applies to. Clients render these with their own standard components. There is no variant that
carries HTML, CSS, JavaScript, React or a WebView, so a package cannot inject any. Adding a node
kind is a core version.

A node kind a client does not know renders as an unsupported-content block. The block keeps the
node's identifier and revision and carries no body, so a newer package cannot reach a hidden action
through a node an older client cannot read.

An `approval_ref` must name a ledger resource. A package cannot create an approval by drawing one:
a pending opaque request is not an actionable approval until its interpretation is verified under
the granted decoder.

Voice receives a separate bounded projection: which nodes it announces as status, which controls it
offers as choices, and which nodes it refers to without reading out.

### Controls

A control carries a stable identifier and revision, a label, a standard icon, an accessible
description, the registered action it invokes, its parameters, a semantic priority
(`primary`, `secondary`, `overflow`, `destructive`) and the reason it shows when disabled.

Icons come from a fixed set every client ships rather than from artwork in the package. A standard
icon renders at the platform's own size and weight, survives a theme change and means the same
thing in every package.

### Visibility

A control states when it is visible and when it is enabled as a predicate:

```json
{
  "op": "all",
  "terms": [
    { "op": "grant", "right": "agent.prompt" },
    { "op": "not", "term": { "op": "binding", "state": "disabled" } },
    { "op": "flag", "flag": "draft_not_empty" }
  ]
}
```

The grammar is `always`, `never`, `not`, `all`, `any`, `capability`, `grant`, `binding`,
`node_present` and `flag`. There is no variable, no arithmetic, no string matching and no
expression form. Nesting is bounded at 4 levels and 8 terms per combinator.

Two reasons for the bound. The host rechecks visibility when a control is invoked, so evaluation
has to be cheap and total. And a reviewer reads a predicate to decide whether a package is honest
about when it appears, which is only possible if the predicate is readable.

Hiding a control the actor could not use is a courtesy, not a check. The host checks the right
again at dispatch, so a predicate that lies only produces a control that then fails.

## The connector table

A native terminal application uses the gateway only when its connector supplies a qualified
declarative table for framing, request identifiers, response correlation, routing and method
classification. Core code interprets that table directly. No Wasm runs on the forwarding path, so a
component fault disables rich meaning without stalling or discarding valid native traffic.

`connector.json` names:

- **Transport:** `stdio`, `private_socket`, `loopback_http`, `web_socket`, `server_sent_events` or
  `byte_stream`.
- **Framing:** line-delimited JSON, a content-length header, a length prefix, or server-sent
  events, each with a maximum message size.
- **Field paths:** where a message carries its request identifier and its method name, as member
  names and array indices, at most 8 segments deep. No wildcard, no filter, no recursive descent.
- **Response correlation:** a matching identifier at a known path, or a single ordered channel.
- **Routes:** the method name in the table and its exact wire spelling.
- **Method classification:** `observation`, `mutation`, `credential` or `unsupported` per method,
  each with the evidence the publisher qualified it against.
- **Protocol pin:** the upstream protocol name, the versions the table was qualified against and
  the exact version the publisher tested.

Two rules are not configurable.

A method the table does not list is a mutation. There is no manifest field that changes this, and
the classifier returns `mutation` for anything unlisted, because a method a publisher forgot is
exactly the kind that changes something.

The transport is a kind, not a target. There is no field for a command line, an executable, a path
or a URL. The broker owns the handle and binds it to the executable, launch, upstream identity and
environment the host selected, so a package cannot point it somewhere else.

A vendor protocol that cannot meet this contract uses a native bridge beside the unchanged terminal
application instead. A connector without a tested volatile forwarding mode says so in its manifest:
on receipt-storage failure its unchanged terminal integration is the supported path, and a reader
should not have to guess.

## The component interface

The WIT package is `kalareach:plugin@0.1.0`, published at `packages/plugin-sdk/wit/`. A component
implements the `adapter` interface and targets the `plugin` world.

| Export | What it does | Deadline |
| --- | --- | --- |
| `bind` | Prepares the instance for one binding | compilation budget |
| `observe` | Receives one scoped source event | 10 ms |
| `snapshot` | Emits the complete current document | 100 ms |
| `prepare-action` | Turns an invoked control into a proposed effect | 10 ms |
| `decode-request` | Interprets a native request into a proposed resource | 50 ms |
| `encode-response` | Encodes a validated decision | 50 ms |
| `checkpoint` | Returns resumable component state | 100 ms |
| `restore` | Restores state from a checkpoint | 100 ms |

The host supplies four interfaces and nothing else:

- `source-events` reads the immutable bytes behind a handle the host passed to this call. A
  component cannot enumerate handles or construct one, so it cannot claim bytes it never received.
- `upstream` reports the binding state and the rights the actor holds. There is no send function.
- `attachments` lists completed attachment handles. Transfer finishes first; the component never
  sees the bytes and never starts an upload.
- `document` emits nodes from the closed union, bounded at 1 MiB per call.

`decode-request` and `encode-response` return values and send nothing. After encoding, the broker
rechecks the pending request, the actor grant and the binding revision, then atomically claims and
dispatches. A native answer that arrives during encoding wins, and the rich response returns the
resolved state instead.

There is no ambient filesystem, network, process or environment access anywhere in the import
surface. A component describes an effect and returns it; the broker decides whether it happens.
That is what keeps an observation callback from submitting input because it can read output.

## Limits

Per instance:

| Limit | Value |
| --- | --- |
| Linear memory | 64 MiB |
| `observe` and `prepare-action` deadline | 10 ms |
| `decode-request` and `encode-response` deadline | 50 ms |
| `snapshot` deadline | 100 ms |
| Output per call | 1 MiB |
| Broker observation queue | 4 MiB |
| Faults before the binding is disabled | 3 within 60 s |

Compilation is not part of any call deadline. Modules compile lazily at binding preparation under
their own budget at background priority, and a call budget starts only once the instance is ready,
so a cold compile never looks like a slow observation. Instructions are bounded with fuel and
elapsed execution with deadlines; fuel bounds work, it is not a CPU-time measurement.

Queue overflow produces an explicit gap and a fresh snapshot. It never drops an authoritative
request, because a dropped request is a decision nobody made.

Per repository, set at enrolment before the first fetch:

| Budget | Default |
| --- | --- |
| Metadata | 64 MiB |
| Index entries | 100 000 |
| Cached payloads | 1 GiB |
| Full offline mirror | off |

A larger full mirror needs the explicit setting. Exceeding a budget leaves the last generation
usable and reports which resource ran out, and a sync never evicts a live-bound or pinned payload
to finish.

Per package: at most 512 files and 64 MiB, at most 256 document nodes and 128 controls, and at most
512 classified methods in a connector table.

## The catalogue index

The index is the complete signed metadata snapshot a host synchronises: compact descriptions,
declarative match rules, capability declarations and immutable payload hashes and sizes. Offline
search covers all of it.

That shapes what an entry carries. Everything a host needs to search, match and decide is in the
index. Everything it would only need after deciding, including documentation, assets and the
component itself, stays behind a content hash until an explicit install, an enable, or an
already-authorised matching activation asks for it.

An entry adds two things to the manifest it came from: the manifest's own digest, and a revocation
record when the release has one. A revoked release stops new bindings. An active binding gets a
warning and follows the administrator's explicit disable policy; it does not change under a live
request.

The index renders as canonical JSON: entries sorted by publisher, plugin name and version, object
keys sorted, no insignificant whitespace, one trailing newline. The same inputs produce the same
bytes, which is what lets a signature over an index mean "these packages" rather than "this run of
the builder". The rendering is compact because a host holds the whole index so that search works
offline, and indentation would spend roughly half the metadata budget on whitespace nobody reads.

## Findings

The validator reports stable codes. A publisher's build, the catalogue pipeline and a host all
report the same code for the same defect.

| Code | What it means |
| --- | --- |
| `directory_unreadable` | The package directory could not be read |
| `manifest_missing` | A required manifest is absent |
| `manifest_unreadable` | A manifest does not parse against the closed schema |
| `manifest_version_unsupported` | The manifest format version is not the one this build reads |
| `unsafe_path` | A declared path is not safe on every supported platform |
| `not_a_regular_file` | A directory entry is a link or a device |
| `case_colliding_path` | Two paths name one file on a case-insensitive filesystem |
| `duplicate_path` | The manifest declares one path twice |
| `undeclared_file` | A file is present that the manifest does not declare |
| `missing_payload` | A declared payload is absent |
| `size_mismatch` | Bytes on disk do not match the declared length |
| `digest_mismatch` | Bytes on disk do not match the declared digest |
| `package_too_large` | The package is over the package size limit |
| `too_many_files` | The package holds more files than the limit |
| `unbounded_version_range` | A version range admits every version |
| `version_range_excludes_host` | A range excludes the SDK that would run the package |
| `no_match_rules` | Nothing would ever activate the package |
| `no_platforms` | Nothing would ever run the package |
| `duplicate_action_id` | Two actions share an identifier |
| `action_not_registered` | A control invokes an unregistered action |
| `effect_without_capability` | An action declares an effect whose capability is not requested |
| `duplicate_capability` | A capability is requested twice |
| `bridge_without_capability` | A native bridge without `native_bridge.install` |
| `attachment_without_capability` | Attachments without `upstream.action` |
| `predicate_invalid` | A visibility predicate breaks the grammar's bounds |
| `parameter_schema_invalid` | A parameter schema breaks its bounds |
| `document_too_large` | Too many nodes or controls in one document |
| `voice_projection_unknown` | The voice projection names something absent from the document |
| `connector_table_invalid` | A connector table breaks its bounds |
| `connector_method_unrouted` | A classified method has no route |
| `connector_payload_missing` | A declared connector table is absent |
| `connector_undeclared` | A connector table is present but undeclared |
| `connector_plugin_mismatch` | The connector names a different package |
| `unknown_effect_class` | An effect class outside the closed vocabulary |
| `unknown_capability` | A capability outside the closed vocabulary |

## What a signature does not do

A signed package establishes provenance. It says which publisher released these exact bytes. It
says nothing about whether the package is safe, whether this host has permission, or whether the
publisher's classification of an upstream method is correct.

Authenticated wire provenance proves which connection supplied bytes; it does not prove that a
decoder interpreted them correctly. An installed connector is a semantic trust boundary, and
sandboxing a malicious decoder does not make it truthful. That is why the trust to classify or
encode native mutations is explicit, why the publisher and methods are recorded, and why the ledger
retains the decoder and package hash, the original source, the native request identifier, the
offered decisions, the deadline and the resolution state for inspection.

## Fixtures

`fixtures/plugins/valid/` holds packages that must validate cleanly. `fixtures/plugins/invalid/`
holds one directory per defect: a `package/` directory and an `expected.json` naming the exact
finding codes it must produce. Both Rust and TypeScript read them, so a change that stops detecting
a defect fails the build.

Present defects: unsafe extraction path, case-colliding names, duplicate declared path, undeclared
size expansion, digest mismatch, undeclared file, unknown effect class, unregistered action, effect
without capability, unbounded SDK range, undeclared connector table, and an over-deep predicate.

## Generation and checking

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p kr-plugin-sdk

# Regenerate the schema, the contract table, the WIT file and the example fixture
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen
cargo run -p kr-plugin-sdk --bin kr-plugin-sdk-gen -- --check

# TypeScript
pnpm -C packages/plugin-sdk generate
pnpm -C packages/plugin-sdk generate:check
pnpm -C packages/plugin-sdk test
```

`packages/plugin-sdk/schema/package-contract.json` is the package contract as data: the effect
classes with the rights each needs, the capabilities with their ceiling, the node kinds, the WIT
exports and imports, the limits, the budgets and the finding codes. A consumer that is not written
in Rust reads that file instead of re-deriving any of it.
