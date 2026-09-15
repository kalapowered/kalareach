# Transport reference

How a KalaReach client reaches a host, what the connection guarantees, and which resources a remote
request depends on. The code is `crates/kr-transport` and `crates/kr-client`; the wire types it
carries are in `crates/kr-protocol`.

A connection is built in layers, and each layer refuses what the one below it did not establish:

```text
endpoint        one explicit selection of network services, nothing inherited
  connection    ALPN `kalareach`; iroh authenticates both transport keys
    handshake   hello, then the kr-connect/1 proof of both authorisation keys
      control   requests, responses, receipts, events, connection events
        data    terminal output, terminal input, semantic updates, attachment chunks
```

## Pinned versions

The relay and discovery services must run releases that match the client. These are the exact
versions this build links, and the versions the relay and DNS deployments install:

| Crate | Version |
| --- | --- |
| `iroh` | 1.2.0 |
| `iroh-base` | 1.2.0 |
| `iroh-relay` | 1.2.0 |
| `iroh-mdns-address-lookup` | 0.5.0 |
| `iroh-mainline-address-lookup` | 0.5.0 |
| `boot-time` | 0.1.3 |

`iroh-dns-server` 1.2.0 is the matching discovery server release. Client, relay and discovery
compatibility is explicit in the signed release matrix: deploy a backward-compatible network tier
before a client that needs its new behaviour, and retain the compatible tier for the documented
installed-client window.

## Endpoint configuration

An endpoint is built from `presets::Minimal`, which sets the cryptographic provider and nothing
else. Every service is then added by name. `presets::N0`, `RelayMode::Default` and
`RelayMode::Staging` are never used, so no public default can arrive by inheritance.

`EndpointConfig` names each selection separately, and a field left unset means the service is not
used:

| Field | What it selects |
| --- | --- |
| `relay_urls` | The relay map. Empty disables relaying; it does not fall back to a public map. |
| `discovery.pkarr_publisher_url` | Where this endpoint publishes its signed record. |
| `discovery.pkarr_resolver_url` | Where this endpoint resolves other endpoints over HTTPS. |
| `discovery.dns_origin` | The DNS origin this endpoint resolves from. |
| `discovery.local_discovery` | Local network discovery. Disabled unless selected. |
| `discovery.mainline_dht` | The public Mainline DHT. Disabled unless selected. |
| `discovery.publisher` | The republish rules below. |
| `direct_addresses` | Address hints for the peer this configuration describes. |
| `relay_ca_roots` | Extra trust anchors for a relay whose certificate comes from a private authority. |
| `bind_addr` | The local socket. |

Publication rules, which are the defaults of `PublisherPolicy`:

* a changed home relay is published immediately, because the publisher watches the endpoint's
  address;
* an unchanged record is republished every five minutes;
* records carry a 30-second time to live;
* relay addresses only. Signed Pkarr records are public, so direct addresses travel through the
  protected pairing exchange and authenticated peer updates instead. `PublishedAddresses::RelayAndDirect`
  is for a deployment whose addresses are already public.

`direct_addresses` and `relay_urls` describe where the *peer* is, not where this endpoint is
reachable, because that is what a pairing invitation carries. `EndpointConfig::peer_addr` turns them
into the address that is dialled; nothing in the configuration advertises them as this endpoint's
own. Cached hints are not permanent routes either: after a failure or a network change, resolve the
pinned endpoint identity again rather than reusing an address that worked before.

The publication filter applies to the publisher, not to the endpoint. An endpoint-wide filter would
also strip the direct addresses that local network discovery exists to advertise, so the public
record stays relay-only while a selected mDNS service publishes what a local network needs.

### Self-hosting

A self-hosted deployment replaces each service independently. The four fields above are the whole
contract: point `relay_urls` at your relays, `pkarr_publisher_url` and `pkarr_resolver_url` at your
`iroh-dns-server`'s `/pkarr` path, and `dns_origin` at the domain you delegated to it. If those
services present certificates from a private authority, add that authority's DER certificates to
`relay_ca_roots`; the public trust anchors stay in force alongside it.

The same selection travels in a pairing invitation and a host bundle as
`kr_protocol::pairing::NetworkConfig`, so a device pairs with and dials the same configuration.
`EndpointConfig::from_network_config` validates every field before it becomes part of an endpoint.
Local discovery and the Mainline DHT are deliberately absent from that object: they are each
device's own choice, not something one device selects on another's behalf.

## The connection handshake

The first bidirectional stream carries four frames, in this order:

1. `ClientOffer` — offered protocol versions, build identity, device identity and key revision,
   capabilities, the client's receive limits, and a fresh 256-bit client nonce.
2. `HelloReply` — either `Selected(HostSelection)` carrying a fresh host nonce, the connection
   identity, the selected version, the selected capabilities, the negotiated limits, the host's
   endpoint and device identity and its boot and clock epochs; or `Refused(ProtocolError)`. A major
   mismatch is refused here with `UNSUPPORTED_SCHEMA`, before any session data.
3. `ConnectProof` — the client's signature over
   `CBOR(["kr-connect/1", offer, selection, client_endpoint_id, host_endpoint_id])`.
4. `ConnectReply` — either `Accepted` with the host's proof over the same transcript and this
   connection's first action window, or `Refused`.

The host verifies the client's proof before sending its own, so a peer that cannot prove its
authorisation key never obtains the host's signature over a transcript it chose.

What authenticates what: iroh authenticates the two *transport* keys, so the connection exists only
between two endpoint identities. These proofs authenticate the two *authorisation* keys, which are
different keys for a different purpose. A holder of one transport key cannot substitute the
authorised application identity.

The paired record is selected by the endpoint identity iroh authenticated, never by the device
identity the peer claims. Verification then rejects, in order: a selected version the client did not
offer, a capability the client did not offer, a negotiated limit above what the client offered to
receive, a selection that does not echo the client's nonce, a mismatched device identity, a stale
key revision, a mismatched endpoint identity, a live endpoint that is not the paired one, and
finally either signature. The host's nonce is drawn per connection and consumed once, so a replayed
transcript names a challenge that is no longer outstanding.

The paired record is read again after the proof arrives, not only before the wait. A device revoked,
or a key rotated, while the handshake was waiting is refused rather than admitted under the record
that was current when the wait began. The offer itself is read under a 16 KiB bound rather than the
control stream's, because it arrives before anything about the peer has been established.

Negotiated limits are the smaller of the two declarations, and the transcript covers them, so a
downgrade after `hello` breaks both signatures. From the moment the connection is authorised those
limits are what the control stream enforces, in both directions.

### Unpaired connections

An endpoint with no paired record is not refused. It negotiates framing and version and then reaches
the bounded pre-authorisation pairing surface: `pair.redeem`, `pair.finish` and
candidate-authenticated `pair.status`, and nothing else. The surface is narrow on purpose:

* frames are bounded at 8 KiB rather than the control stream's 1 MiB;
* a connection may make at most 16 requests, at most 4 in any 10-second window;
* the candidate is identified by its authenticated endpoint identity, so `pair.status` answers about
  the attempt that endpoint is party to and a caller cannot name another;
* no mutation is served as early data.

What the transport hands the ceremony is `kr-pairing`'s own `LivePeer`: the endpoint identity iroh
authenticated, and whether this step arrived as early data. Those are the two facts a pairing state
machine cannot see for itself, and they are what it checks the authenticated bundle and the 0-RTT
rule against. Everything else — the budgets, the phase rules, the PAKE, the transcripts and the
owner confirmation — belongs to `kr-pairing`.

Three host-wide bounds sit above the per-connection ones, because a per-connection budget resets
when a peer reconnects and a host-wide one does not: at most 64 connections may be mid-handshake or
unpaired at once, unauthorised connections are admitted at most 32 in a burst and one every 250 ms
after that, and an unauthorised connection has 60 seconds to finish. The deadline covers the
unauthorised phase only; an authorised session lasts as long as its peer keeps it. Every request is
charged against the connection's budget, refused or not, and a connection that spends the whole
budget is answered once and then ended.

Pairing's own budgets, phase rules and proofs belong to the pairing crate, which implements the
surface's trait. The transport is the door, not the ceremony behind it.

### 0-RTT

Version 1 accepts no application mutation in QUIC 0-RTT — not just no pairing mutation. Three rules
enforce it, and the order matters because the first one is what makes the others truthful.

* **The host asks whether a stream carried early data.** QUIC marks a stream as early data only when
  it is accepted while the handshake is still running, so the listener accepts the first
  bidirectional stream from the 0-RTT connection and only then waits for the handshake to complete.
  Nothing is *read* before that wait, so no frame is ever acted on before the peer's endpoint
  identity is authenticated. The answer is not certain, though: if the connection's driver finishes
  the handshake before the listener's task accepts the buffered stream, early data arrives marked as
  ordinary. Closing that window needs an upstream change — the relay-and-transport dependency sets
  the server's TLS early-data size to its maximum and exposes no way to refuse it — so a host that
  requires the guarantee absolutely pins a build that sets it to zero.
* **An authorised connection never carries early data.** A handshake stream that arrived as early
  data is refused with `PERMISSION_DENIED` before the proof exchange, and so is a data stream. This
  costs nothing: a KalaReach endpoint keeps no TLS session tickets, so this product's own client
  cannot offer 0-RTT to anyone.
* **The pairing surface refuses its own mutations in early data.** `pair.status` is a read and is
  served; `pair.redeem` and `pair.finish` are writes and are refused. That is the one exception
  section 23 allows, and it is closed to everything that changes state.

Authorisation could not complete in 0-RTT in any case: the proof covers the host's fresh challenge,
which the client learns only after the handshake.

## Streams

Five kinds, each with its own stream, its own frame bound and its own place in the scheduler:

| Kind | Frame bound | Class | Priority |
| --- | --- | --- | --- |
| `control` | 1 MiB | interactive | 20 |
| `terminal_input` | 64 KiB | interactive | 20 |
| `terminal_output` | 1 MiB | live | 0 |
| `semantic_updates` | 1 MiB | live | 0 |
| `attachment_chunks` | 1 MiB + 4 KiB | bulk | -20 |

Every bound covers the complete frame, its four-byte length prefix included. A frame is that prefix
followed by one KR-CBOR-1 object, and the declared length is checked against the stream kind's bound
before any buffer is allocated. The attachment bound cannot be selected on a control stream, because
the bound is a property of the kind rather than of a frame.

Each stream after the control stream begins with a bounded 1 KiB header naming its kind, the
connection it belongs to, the event stream it corresponds to where one applies, and its authorised
resource. The header is validated against the established control connection: a header naming
another connection is refused, and so is one whose resource does not fit its kind — a terminal
stream without a session and attachment, a semantic stream without a session, an attachment stream
without a transfer.

Bulk streams are bounded three times. The connection's own QUIC send window is 8 MiB, which is
section 9's bounded send queue per peer enforced by the transport rather than only by the
application's accounting. Within that, at most 4 bulk streams may be open, and the application hands
the connection at most 7 MiB of bulk data at once, lowered further when the peer negotiated a
smaller send queue. Control and input are written at a higher stream priority, so the connection
sends them first whenever it has capacity.

What that does not do is reserve capacity inside QUIC: bytes the connection has accepted but not yet
had acknowledged still occupy the window, and the transport has no way to observe when they drain.
A sustained transfer can therefore fill the window, and a control write then waits for the peer to
acknowledge rather than for a scheduler decision. Bounding that properly needs per-stream send
accounting the transport crate does not expose.

The negotiated limits are in force as well as the stream kind's ceilings. A peer that declared it
could receive less than the kind allows is held to what it declared, in both directions, and a frame
that exceeds either bound is refused before its payload is allocated.

### Revocation

Closing or failing the control stream revokes every data stream it authorised and stops remote lease
renewal. Revocation reaches an operation that is already waiting: a read or write on a revoked
stream returns at once rather than waiting for a peer that will never send, and the stream is reset
rather than finished, so the peer sees that it was taken away instead of a clean end it might read
as completion. The connection's action windows are retired at the same moment, so none of them can
first-admit a request through a connection that no longer exists.

The cleanup runs on every way a connection can end, including a failed keepalive write, a panic in
the host's handler and a cancelled task, because it is a guard the connection owns rather than a
step at the end of a function. It fences window issuance first, then stops the keepalive, closes the
connection, revokes the streams and retires the windows, so a renewal that was in flight retires
itself rather than outliving the connection. Nothing kills a healthy worker to force any of this
through.

## Keepalive and reconnect

* Keepalive: 10 seconds while active, at the QUIC layer and as a `ControlEvent::Keepalive` on the
  control stream, so a local socket carrying the same frames has the same liveness signal.
* Inactivity: 30 seconds without traffic declares the transport unavailable. A mobile suspension
  that trips it is a normal disconnect.
* Reconnect: jittered exponential backoff from 250 ms to 30 seconds, drawn with full jitter so a
  fleet that lost the same relay does not return in step. The ladder resets after a connection that
  lasted at least the inactivity threshold; a connection that died immediately does not reset it.

A reconnect creates a new connection identity and a new input lane. Raw input is never replayed: an
input sequence belongs to one connection, acknowledgement positions are retained only for that
connection, and `InputLane` has no constructor that carries a position across. What the old lane
left unacknowledged is reported as an interruption, not resent.

The client restores state through cursors and receipts. `Restoration` enforces the order, and
refuses a step taken out of it: subscribe from the cursor *first*, then install the snapshot the
subscription returned, then apply the queued updates.

Receiving an event is not applying it. The session records what arrived; a consumer records what it
folded into its state, and only that moves the position a reconnect subscribes from. An event that
was delivered and never applied arrives again rather than being skipped. A gap in the sequence, or a
`RESYNC_REQUIRED` from the host, leaves the stream owing a snapshot: nothing it delivers establishes
a position until one is installed.

Receipts are carried across, and so are the identifiers of actions that were sent without any
receipt arriving, which is the one case a receipt tracker cannot name. A client reports both as
unresolved and asks the host what became of them; it never redispatches an action whose receipt is
incomplete.

## Actor envelopes

Ordinary live requests are authenticated by the connection plus the host-constructed verified actor
envelope, not by a per-request device signature. The envelope is built once from facts the
connection established, and a caller supplies none of them:

| Field | Where it comes from |
| --- | --- |
| `actor_id` | The principal the host assigns. |
| `ingress` | `paired_device` for a network connection, `local_ipc` for an authenticated OS caller. |
| `device_id` | The paired record the authenticated endpoint identity selected. |
| `grant_id`, `grant_revision` | The grant the request was checked against, when one applies. |
| `controller_generation` | The generation that admitted the connection. |
| `connection_id` | The connection the request arrived on. |

A request names the grant it claims; it cannot name its own device, its ingress or the generation
that admitted it. A local caller carries no device identity: local IPC uses its authenticated OS
caller and a host-stamped freshness context rather than pretending to be a paired device.

Admission resolves the method against the registry first — an unlisted method, an unsupported
version or a forbidden ingress is denied whatever rights the caller holds — and then applies the
0-RTT rule.

## Action windows

A window is a freshness resource, not a permission. The host issues one per authorised connection,
bound to that connection and to the host's boot identity, and renews it on the live connection
without being asked: a renewal arrives as `ControlEvent::ActionWindowRenewed` at half the window's
validity.

The window a client receives carries a *duration*, not an absolute deadline. The client schedules
its renewal from that duration; the authoritative deadline lives on the host's suspend-aware
continuous clock. The host derives an accepted deadline as the earliest of window expiry, receipt
time plus the requested time to live (capped at five minutes) and any applicable authority or
subject deadline.

A window from another connection, or from before a restart, cannot first-admit anything. Replacing a
window changes the payload digest, so it is never an automatic retry.

### The continuous clock

Every deadline in the transport is measured on a suspend-aware continuous clock. The standard
library offers no clock that is one everywhere: `Instant` is whatever its platform's monotonic
source is, and on Linux that excludes suspended time, so a five-second lease would outlive a
suspension of any length; `SystemTime` keeps running across a suspension but can be stepped in
either direction, so it can be stopped by anything that can step it.

The default implementation therefore reads the operating system's own continuous clock —
`CLOCK_BOOTTIME` on Linux, Android and OpenBSD, and `mach_continuous_time` on Apple platforms —
which is monotonic *and* includes suspended time. No arithmetic of ours stands between the kernel's
answer and a deadline. On platforms the crate does not name it falls back to `Instant`, and whether
that includes suspended time is the platform's answer rather than this crate's; a host there
supplies a qualified platform time adapter through the `ContinuousClock` trait, and until it does,
expiry rests on a clock this build has not qualified.

## The remote dispatch lease

Remote dispatch additionally requires a live worker-held authority lease from the current controller
generation and revision:

* validity is at most five seconds on the continuous clock, and every dispatch checks the deadline
  at the moment it runs rather than trusting a timer that fired earlier;
* renewal happens only after the worker has acknowledged the relevant authority revision;
* losing the generation binding stops renewal, and a replacement generation cannot renew a lease it
  did not issue;
* advancing the authority revision invalidates every outstanding lease at once, because a lease
  carries the revision it was issued at.

The lease is a bounded stop on stale remote work. It is not the revocation barrier: a revocation
reports `pending` per worker until each affected worker has acknowledged the revision or has been
confirmed ended. Cutting a network path or waiting for a lease timer is not completion, because a
paused worker could already be inside a dispatch transition.

## Wiring a host

### What the host owes

Two contracts the transport cannot keep for the host:

* **Admission and revocation.** The handshake re-reads the paired record as late as the exchange
  allows, but a revocation that lands between that check and the first protected read is the host's
  to fence. The host makes its final record validation and its own registration of the connection
  atomic with its authority store, and keeps that registration revocable for the life of the
  session. Section 9's dispatch barrier covers a worker's dispatch; it does not cover a read or a
  subscription on a connection that was authorised a moment before a device was revoked.
* **Work that must complete.** `HostHandler::serve` is dropped when the control stream ends, which
  is a cancellation: destructors run, but nothing after an outstanding `await` finishes. A durable
  commit or a dispatch marker belongs to an owner that outlives the connection.

A host joins the network with one call:

```rust
let listener = kr_transport::listener::register(config, identity, &transport_key, handler).await?;
```

`HostHandler` is the host's half: where a paired record comes from, what principal a device acts
under, whether pairing is open, what to do with an authorised connection, and what to do when a
control stream ends. Everything between an incoming QUIC connection and an authorised control
stream — the handshake, the pairing surface, the keepalive, the window renewal and the revocation
that follows a lost control stream — happens inside the call. A host that owns a qualified platform
time adapter uses `register_with_clock` and supplies it.
