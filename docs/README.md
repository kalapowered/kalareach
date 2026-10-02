# KalaReach documentation

These documents describe the code in this repository: the host, the clients, the protocol between
them and the rules each part keeps. Each one says what the code does, and where it stops.

## The documents

The protocol and the connection:

| Document | What it covers |
| --- | --- |
| [protocol/README.md](protocol/README.md) | The protocol reference: KR-CBOR-1, version negotiation, framing, envelopes, receipt states, relay leases, error codes, the method and authority table, the root integration, and the account, service-credential and push objects |
| [protocol/methods.md](protocol/methods.md) | Every method in the registry, generated from it, with its effect, its ingress, its summary and the section that describes it where one does |
| [protocol/glossary.md](protocol/glossary.md) | The terms the protocol relies on |
| [transport/README.md](transport/README.md) | How a client reaches a host: endpoint configuration and self-hosting, the connection handshake, streams, reconnection, actor envelopes, action windows and the remote dispatch lease |
| [pairing/README.md](pairing/README.md) | The short-code and direct QR pairing flows, their budgets, grants and owner confirmation |
| [crypto/README.md](crypto/README.md) | Purpose-separated keys, domain separation, encrypted objects and backup generations, envelopes, recovery and secret storage |

The host and what runs on it:

| Document | What it covers |
| --- | --- |
| [host/README.md](host/README.md) | The control daemon and the workers: directories, configuration, supervision, the terminal, input and size, action windows, journals, closure, recovery, grants and revocation, and the services the daemon hosts |
| [host/platforms.md](host/platforms.md) | Desktops, logout, reboot and sleep on each platform |
| [terminal/README.md](terminal/README.md) | The terminal engine: the `kr-vt/1` profile, the sequence class table, the byte policy, the canonical grid, the query broker, snapshots and probes |
| [shell-integration/README.md](shell-integration/README.md) | The root-editor contract a managed shell package implements |
| [shell-integration/host.md](shell-integration/host.md) | The worker's side of that contract |
| [shell-integration/packages.md](shell-integration/packages.md) | What each managed shell package changes, and how it is built, identified and licensed |
| [shell-integration/qualification.md](shell-integration/qualification.md) | How the packages are qualified against the startup customisations people run |
| [shell-integration/upstream.md](shell-integration/upstream.md) | Each package's upstream source, its security triage and its update target |
| [transfer/README.md](transfer/README.md) | Uploads, verified downloads, attachments and drafts, filesystem authority and previews |
| [project/README.md](project/README.md) | Project repositories, authorised locations, workspaces, the restricted Git execution profile and change sets |
| [automation/README.md](automation/README.md) | Workflows: definitions, the grant a workflow acts under, causal budgets, admission limits and durability |
| [describe/README.md](describe/README.md) | Local session names and descriptions |
| [delivery/README.md](delivery/README.md) | Notification delivery: what is sent, rate limits, external destinations and privacy mode |
| [contact/README.md](contact/README.md) | Agent contact: the skill, its four tools, the question ledger and installing it |
| [voice/README.md](voice/README.md) | Voice on the host: what a call may read and send, the voice grant, and what is never authority |

Plugins:

| Document | What it covers |
| --- | --- |
| [plugins/README.md](plugins/README.md) | The package contract: the manifest, capabilities, effect classes, the document, the connector table, the component interface, limits and findings |
| [plugins/catalogue.md](plugins/catalogue.md) | Repositories and the catalogue: enrolment, synchronisation, payloads, activation, budgets, revocation and native bridges |
| [plugins/runtime.md](plugins/runtime.md) | Where a plugin component runs, what bounds it, its faults and its compiled-code cache, and the signed catalogue generation that ships with the host |
| [plugins/sdk.md](plugins/sdk.md) | Answering an application's approval from a declarative package |
| [bridges/claude-code/README.md](bridges/claude-code/README.md) | The Claude Code bridge |
| [bridges/gemini-cli/README.md](bridges/gemini-cli/README.md) | The Gemini CLI bridge |
| [bridges/qoder-cli/README.md](bridges/qoder-cli/README.md) | The Qoder CLI bridge |

The clients:

| Document | What it covers |
| --- | --- |
| [cli/README.md](cli/README.md) | The `kr` command line: commands, exit codes and the `--json` shapes |
| [client/README.md](client/README.md) | The shared native client library: failures, diagnostics, drafts, settings sync, pairing, managed services and recovery |
| [companion/README.md](companion/README.md) | The desktop companion application and its boundary |
| [client/mobile.md](client/mobile.md) | The companion application on a phone |
| [client/voice.md](client/voice.md) | The voice client's architecture |
| [voice/client.md](voice/client.md) | Voice on the client: capture, playback, the capture gate and the device-owner confirmation |
| [voice/media-stack-survey.md](voice/media-stack-survey.md) | The native media stack chosen for the voice client, and why |

Conformance and performance:

| Document | What it covers |
| --- | --- |
| [conformance/README.md](conformance/README.md) | The conformance report: running it, how a test names the identifiers it proves, outcomes and verdicts, the result it writes and the application matrix |
| [performance/README.md](performance/README.md) | The reference host and the two configurations the performance targets are measured in, how each figure is taken and recorded, and where a release's figures come from |

Releases:

| Document | What it covers |
| --- | --- |
| [releases/packages.md](releases/packages.md) | How the generated protocol and plugin SDK packages are released and pinned, and the managed shell packages' update target |
| [releases/windows-signing.md](releases/windows-signing.md) | How Windows executables and PowerShell packages are signed, and the identity behind the signatures |
| [releases/platforms.md](releases/platforms.md) | The platforms and oldest releases a release runs on, where each executable is built, how each one's floor is read back, and the Linux distributions tested |
| [releases/evidence-gates.md](releases/evidence-gates.md) | The seven gates a release is made against, the evidence that closes each and the commands that produce it, and the pairing review exception |
| [releases/keys.md](releases/keys.md) | The signing keys of a release, the plugin catalogue, the relay service and each organisation: what each signs, where it is held and pinned, who rotates it and how it is recovered |

The [repository README](../README.md) says how to build and test this repository, how it is
released and how a host recovers.

## Three repositories

KalaReach is built in three repositories. They are separate release and trust boundaries, not three
implementations of one protocol.

| Repository | What it holds | What it releases |
| --- | --- | --- |
| `kalareach`, this one | The host (the control daemon, the workers and `kr`), the shared protocol, transport and client library, the Tauri companion application for desktops and phones, the plugin runtime and SDK, the managed shell packages, the contact skill and the conformance fixtures | The generated `@kalareach/protocol` and `@kalareach/plugin-sdk` packages, as immutable archives on GitHub releases ([releases/packages.md](releases/packages.md)). A `host/v*` tag runs the workflow that builds and signs the Windows host executables and PowerShell packages and publishes them as a release ([releases/windows-signing.md](releases/windows-signing.md)) |
| `kalareach-web` | The website at [reach.kala.to](https://reach.kala.to) and its public documentation, the account system, the managed service APIs and the Cloudflare Worker that serves them, the Stripe billing integration, and the infrastructure configuration, the relay and discovery deployments among it | Deployments of the website and the service backend |
| `kalareach-plugins` | The plugin catalogue: package sources, declarative manifests, fixtures, publisher records, revocations, and the pipeline that validates packages and builds and signs catalogue generations | Signed catalogue generations, built by its pipeline. The generation this repository ships with the host is copied, by digest, from the catalogue's signed development generation, and `bundled-plugins.lock` names the generation, its commit and its trust root |

The other two pin what they take from this one. The website service pins a `@kalareach/protocol`
release archive by URL and digest, and the catalogue pipeline pins `kr-plugin-sdk`, the validator a
host runs before it trusts a package, by Git revision in its lockfile.

No repository uses a Git submodule, holds a second copy of another repository's server, or depends
in production on a path in another repository's checkout. Every dependency between them is by
released archive digest or by Git revision, as is each dependency on the project's forks of WezTerm
and iroh. The website's relay crate takes `kr-protocol`, `kr-cbor` and `kr-crypto` by revision, and
this repository takes its bundled plugin packages from a signed catalogue generation by digest, which
`bundled-plugins.lock` records. The catalogue's `scripts/with-local-core.sh` points one command's
fetch of the pinned revision at a local checkout; it changes neither the revision nor the lockfile.

## What KalaReach includes

KalaReach is a host that owns durable terminal sessions on a person's own computers, the clients
that reach them, and a set of optional services around them. This list says what the product
includes and where each part is described. Each document states what the code does and where it
stops, so a limit that a part has is written in that part's own document.

- **Durable sessions.** A worker process for each session owns the pseudo-terminal and the terminal
  state, and the control daemon can restart without ending a session: [host](host/README.md),
  [terminal](terminal/README.md) and [cli](cli/README.md).
- **Agent interfaces.** Plugin packages for Codex, Claude Code, OpenCode, Gemini CLI, Kimi and
  Qoder CLI recognise those agents in a session, and the broker in each worker holds each binding,
  the evidence for what it can do, and the approvals. Typed requests to submit or queue a prompt,
  steer or cancel a turn and answer an approval act only where a binding has evidence for them, so
  what an agent offers depends on its package and its build. Claude Code's approvals are answered
  over its bridge channel, and the Gemini CLI and Qoder CLI packages report an agent's hooks to the
  worker. An approval is only ever created from the agent's own protocol: [the
  broker](host/README.md#the-broker), [the bridges](bridges/claude-code/README.md) and
  [plugins](plugins/README.md).
- **Attaching from elsewhere.** `kr attach` in an ordinary terminal, and the companion application
  on Linux, macOS, Windows, iOS and Android: [cli](cli/README.md), [companion](companion/README.md)
  and [mobile](client/mobile.md).
- **Diff review.** Projects, workspaces and immutable change sets, with the diffs between versions
  and a review state bound to an exact version: [project](project/README.md) and
  [host](host/README.md#attention-review-and-what-changed-since-a-visit).
- **Voice.** A coordinator on the host decides what a call may read and send, under a voice grant
  that a device holds apart from its ordinary grant, with an unlocked-screen confirmation for the
  actions that need one: [voice](voice/README.md) and [client voice](client/voice.md). The daemon
  this repository builds attaches no voice provider, so no call starts on it.
- **Encrypted push.** The host composes each notification, and a preview travels sealed to the
  receiving device's own preview key, so a service that carries it cannot read it:
  [delivery](delivery/README.md). Neither phone build opens a preview, so a phone shows the generic
  alert: [mobile](client/mobile.md).
- **Attention.** One inbox for every session and workflow of an environment, with escalation rules,
  quiet hours and review state, and a view of what changed since an actor's last visit:
  [host](host/README.md#attention-review-and-what-changed-since-a-visit).
- **Sharing and control.** Grants scoped to environments and sessions, a narrower grant that a
  holder can delegate, revocation that completes through a per-worker barrier, and an input lease
  that a controller takes explicitly: [grants](host/README.md#grants-sharing-and-revocation),
  [pairing](pairing/README.md) and [who may type](host/README.md#who-may-type).
- **Automation.** Versioned workflows that react to verified events, under causal budgets and a
  declared grant: [automation](automation/README.md).
- **Sync, recovery and backup.** Encrypted settings sync and the recovery kit in the shared client
  library, and the producer that encrypts and signs a history backup with the host's store of its
  generations. The host does not upload a backup to a service: [client](client/README.md), [the
  backup service](host/README.md#the-backup-service) and [crypto](crypto/README.md).
- **The plugin catalogue.** A signed catalogue of adapter packages, searched offline, whose entries
  carry each release's compatible SDK range and the executable builds it was qualified against:
  [catalogue](plugins/catalogue.md).
- **Teams.** Signed membership leases and an organisation's policy-signing chain, which a host
  verifies without reaching the service ([account authority
  objects](protocol/README.md#account-authority-objects)). The roles, single sign-on and SCIM that
  issue them run in the website's account system.
- **External notification destinations.** Webhook, Slack, Discord, Telegram and email destinations,
  each with its own recipient and content policy, and a stored credential for the four that need
  one: [delivery](delivery/README.md#external-destinations).
- **Environments and diagnostics.** WSL, container, SSH and paired environments the owner enrols
  with `kr bridge`, and `kr doctor`, which reports diagnostics and writes a support bundle that
  carries content only when the person passes `--include-content` and approves its preview:
  [host](host/README.md#wsl-and-containers) and [cli](cli/README.md).

## What is open source, and what is a service

This repository holds the host and every client, and it is open source under the BSD 3-Clause
License; the managed shell packages under `shells/` carry their shells' own licences. It works
without a KalaReach account: without one, a host creates sessions, pairs devices by direct QR or by
short code, runs plugins and workflows, and asks and answers questions.

Managed services are resources a client reaches over HTTPS at a service origin, through
authenticated service APIs. The clients for them are in `crates/kr-client/src/services` (account
sign-in, relay leases, the authority feed, the encrypted mailbox, settings sync and the voice
broker) and, for push delivery, in `crates/kr-controller/src/push`. Every method of the `Services`
group is proven by one signed service credential, and a request for something an account owns also
carries an account token. The service decides what to supply from those.

The boundary is documented on this side so another implementation can serve it:

- [The service credential](protocol/README.md#the-service-credential): what a service request's
  signature covers and how a service checks it;
- [The two representations](protocol/README.md#the-two-representations): JSON as the managed HTTP
  representation;
- [the `Services` methods](protocol/methods.md#services) and their authority entries, and the
  vectors under `fixtures/service/` and `fixtures/push/` that both languages are tested against;
- [Relay leases and receipts](protocol/README.md#relay-leases-and-receipts) and [Push
  objects](protocol/README.md#push-objects);
- [the client library's managed services](client/README.md), and the relay and discovery fields a
  host points at a deployment of its own ([transport/README.md](transport/README.md)).

### The commercial model

The commercial model is the managed services, and nothing that runs on a person's own computer is
sold. The hosted service sells relay bandwidth beyond a free allowance, encrypted storage, and
metered voice and reasoning. It authenticates each request and enforces payment, reservations and
limits before it supplies the resource. Basic managed push stays free within its abuse limits. The
clients carry no payment check of their own: each managed service sits behind a replaceable client
in `kr-client`, a client with none configured still has every local capability, and what a client
shows about entitlement explains availability and protects nothing. A fork can run a service of its
own with its own credentials, and it cannot obtain KalaReach's provider keys.

## Where work runs

A session, the agents inside it, its repositories and workspaces, its transfers and its automation
all run on a host: in the environment the host runs in, or in one its owner enrolled with
`environment.enrol`, which records a WSL, container, SSH or paired environment. KalaReach has no
hosted environment to run work in. The managed services relay, store and deliver encrypted data and
broker calls to a provider; none of them runs a session.

## What KalaReach does not do

There is no public browser terminal. The website serves pages, the account screens and the service
API, and none of its pages opens or shows a session. A session is shown by `kr attach` in an
ordinary terminal, or in the companion application, whose bundled interface reaches a host through
the native client library and only through the commands its native side names
([companion/README.md](companion/README.md)).

KalaReach does not adopt a terminal it did not start. Every session is a new pseudo-terminal its
worker created, with a new root shell, made by a create request from `kr new`, the companion
application or a paired device. A shell or terminal window already running elsewhere is
never taken over.

## How the repositories are kept

None of the three repositories holds an instruction file for a coding assistant. `AGENTS.md`,
`CLAUDE.md`, `GEMINI.md` and their lower-case and suffixed forms, and the configuration files and
directories of the common assistants, are ignored at any depth by the first section of each
repository's `.gitignore`, and no commit in any of the three has tracked one. Product files that
look similar, such as the installable `skills/kalareach-contact/SKILL.md`, are tracked.

Text in this repository describes the product and the change, and a commit message is one line with
no body and no trailer. `scripts/check-clean-checkout.sh` refuses a tracked file that names a task
or a decision identifier, a numbered review or another record kept outside the repository, a commit
message longer than one line and a broken relative link. It also creates each assistant instruction
name in its clone and refuses a `.gitignore` for which `git check-ignore` does not name one ignored,
and the `release-checks` workflow runs it on every change. The website's `pnpm records:check` refuses
coding-assistant instruction files, local work records and key material by path, and three
credential shapes by content, in the commits it is about to send, the packages it publishes and the
deployment bundle, and makes the same proof of its `.gitignore` in a repository of its own. The
catalogue's `scripts/check-local-names.sh` makes that proof for the catalogue repository.

There is no second specification hierarchy. The protocol reference, its generated method index and
glossary, and the generated schemas and vectors live beside the code they describe, in
`docs/protocol/`, `packages/protocol/` and `fixtures/`, and each part's reference lives under
`docs/` beside its crate. No repository holds a plan, a requirements register or a decision log.

Setup, build and test work from a clean checkout. `scripts/check-clean-checkout.sh` clones one
commit into an empty directory, gives the run a home directory, Cargo home, pnpm store and temporary
directory of its own, and runs the lists in the README's "Build and test" section, so nothing a
machine has collected can stand in for what the repository provides. The website's README lists its
commands from `pnpm install --frozen-lockfile`, and the catalogue's lists its own from its pinned
toolchain. Deploying the website needs the operator's credentials, which `pnpm setup:check` names
and which are never in a repository.

Each part that has a wire format, a stored format or a package contract keeps the fixtures that test
it with its code, and generates them: `kr-protocol-gen`, `kr-crypto-vectors`, `kr-pairing-vectors`,
`kr-plugin-sdk-gen`, `kr-term-fixtures`, `kr-shell-fixtures` and the TypeScript generators each
write theirs, and each has a `--check` mode that the README's list runs. A change to one of those
contracts is committed with its regenerated outputs and with every consumer in the repository, so
the check fails when one is left behind. The other two repositories take released packages, vectors
and revisions, pinned by lockfile.

Internal interfaces change in one commit with every caller in the repository, and the old form is
deleted. The code keeps no deprecated alias and no versioned copy of an interface that all its
callers have left. Compatibility is kept at the boundaries where something outside the commit still
runs or exists. A worker outlives an upgrade of the control daemon
([host/updates.md](host/updates.md)). A worker's journal that an earlier build wrote is brought
forward when it is opened, or refused: it migrates through a ladder with a stated window and an
explicit importer for what is older ([Migrations](host/README.md#migrations)). A host and a client
of different versions negotiate a protocol version ([Version
negotiation](protocol/README.md#version-negotiation)). A plugin package is built for an SDK and
component interface range ([plugins/README.md](plugins/README.md)).
