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
| [plugins/runtime.md](plugins/runtime.md) | Where a plugin component runs, what bounds it, its faults and its compiled-code cache, and the package that ships with the host |
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

The [repository README](../README.md) says how to build and test this repository, how it is
released and how a host recovers.

## Three repositories

KalaReach is built in three repositories. They are separate release and trust boundaries, not three
implementations of one protocol.

| Repository | What it holds | What it releases |
| --- | --- | --- |
| `kalareach`, this one | The host (the control daemon, the workers and `kr`), the shared protocol, transport and client library, the Tauri companion application for desktops and phones, the plugin runtime and SDK, the managed shell packages, the contact skill and the conformance fixtures | The generated `@kalareach/protocol` and `@kalareach/plugin-sdk` packages, as immutable archives on GitHub releases ([releases/packages.md](releases/packages.md)). A `host/v*` tag runs the workflow that builds and signs the Windows host executables and PowerShell packages and publishes them as a release ([releases/windows-signing.md](releases/windows-signing.md)) |
| `kalareach-web` | The website at [reach.kala.to](https://reach.kala.to) and its public documentation, the account system, the managed service APIs and the Cloudflare Worker that serves them, the Stripe billing integration, and the infrastructure configuration, the relay and discovery deployments among it | Deployments of the website and the service backend |
| `kalareach-plugins` | The plugin catalogue: package sources, declarative manifests, fixtures, publisher records, revocations, and the pipeline that validates packages and builds and signs catalogue generations | Signed catalogue generations, built by its pipeline. The package this repository ships with the host is copied, by digest, from the catalogue's signed development generation, and `bundled-plugins.lock` names the generation, its commit and its trust root |

The other two pin what they take from this one. The website service pins a `@kalareach/protocol`
release archive by URL and digest, and the catalogue pipeline pins `kr-plugin-sdk`, the validator a
host runs before it trusts a package, by Git revision in its lockfile.

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
application, a paired device or a workflow. A shell or terminal window already running elsewhere is
never taken over.
