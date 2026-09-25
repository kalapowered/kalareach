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

`iroh-dns-server` 1.2.0 is the matching discovery server release. The relay and discovery hosts run
`iroh-relay` 1.2.0 and `iroh-dns-server` 1.2.0 on Hetzner. Client, relay and discovery compatibility
is explicit in the signed release matrix: deploy a backward-compatible network tier before a client
that needs its new behaviour, and retain the compatible tier for the documented installed-client
window.

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
| `relay_only` | Removes the IP transports, so every packet goes through the selected relay. |
| `relay_ca_roots` | Extra trust anchors for a relay whose certificate comes from a private authority. |
| `bind_addr` | The local socket. |
| `proxy_url` | The HTTP proxy the endpoint reaches its relays and Pkarr servers through: the relay connection, the relay latency probe and captive-portal check, and the Pkarr publisher and resolver. A `ProxyUrl` is an `http` or `https` origin and never names a credential. |

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

The host fills an invitation's `direct_addresses` from the addresses its endpoint reports for itself
(`Endpoint::addr`), never from the sockets it bound. A socket bound to the unspecified address
answers on the machine's own addresses, so a host with no `bind_addr` hints its interface addresses
on the bound port; a host bound to one address hints that address; an address a relay observed or a
gateway mapped is added once the endpoint learns it. `0.0.0.0` and `[::]` never appear, because
they name no machine a peer could reach. The endpoint finds its interface addresses when it binds,
before the host can issue anything, so an invitation carries whatever the endpoint reports then.
When it reports none, the list is empty: for example on a relay-only host, which has no IP
transport, or on a host that listens on one address family while every usable address it has is of
the other. A device then reaches the host only through the selected relay and discovery, and only
when they are configured and reachable.

The publication filter applies to the publisher, not to the endpoint. An endpoint-wide filter would
also strip the direct addresses that local network discovery exists to advertise, so the public
record stays relay-only while a selected mDNS service publishes what a local network needs.

### Proxies, blocked upgrades and intercepted TLS

`proxy_url` is the way the endpoint reaches its relays and its Pkarr servers. With it set, the
relay client opens a `CONNECT` tunnel to each relay through the proxy, iroh's net report sends its
relay latency probe and captive-portal check through it, and the Pkarr publisher and resolver send
their requests through it. None of these goes around the proxy: when it cannot be reached, neither
can the relays or the Pkarr servers. The rest of the endpoint's traffic does not use it. Direct
paths and iroh's QUIC address discovery are UDP, the DNS lookup asks the system's name servers, and
the port mapper talks to the local gateway, each as it would without a proxy. A network that
requires a proxy usually blocks the first two, which leaves the relay's HTTPS path; a relay-only
endpoint has that path alone.

The DNS lookup is this crate's resolver, which `bind` gives iroh in place of its own. It asks the
system's name servers first, and when they fail or there are none it falls back to the same public
resolvers iroh falls back to (Cloudflare, Google and Quad9), over plain DNS, which asks again over
TCP when an answer is truncated or does not come, and over DNS over TLS. iroh's own fallback also
asks over DNS over HTTPS, and that client follows `HTTPS_PROXY` and `ALL_PROXY` whether or not a
proxy is selected; this one has no HTTP client, so no proxy variable moves a lookup. On Windows the
system's configuration includes the hosts file, which the resolver finds under `SystemRoot`. DNS
over TLS verifies against the relay's anchors: the public ones, and any `relay_ca_roots` add.

The proxy is each machine's own choice. A pairing invitation and a host bundle carry the relays and
discovery services a device dials with, never the proxy the inviting machine goes through. Nothing
reads it from the environment: `bind` never calls iroh's `proxy_from_env`, and the Pkarr publisher
and resolver are this crate's own, built on iroh's public `AddressLookup` trait, because iroh's own
build their HTTP client with no way to name a proxy and follow `HTTP_PROXY`, `HTTPS_PROXY` and
`ALL_PROXY` instead. They publish and read the same signed records, verified by iroh's record code,
and a record longer than a signed record can be is refused before it is read whole. With no proxy
selected, iroh still builds the client for its relay latency probe and captive-portal check with
the environment's proxy settings, so those two requests follow `HTTP_PROXY`, `HTTPS_PROXY` and
`ALL_PROXY` when they are set.

A proxy that needs credentials is not supported. `ProxyUrl` refuses an address that names a user or
a password, even an empty one, rather than using the proxy with the credential dropped.

A network that blocks WebSocket upgrades lets the relay's HTTPS through and answers the relay
connection's upgrade with something other than `101 Switching Protocols`, such as `403`. The relay
itself never answered, so `endpoint::connect` reports that as `TransportError::Connect`, never as
`RelayRefused`, with a message that names the relay and the status:

```
the network refused the WebSocket upgrade to the relay https://relay.example.com/ with HTTP status 403
```

It is decided as a relay's refusal is, below: it explains an attempt only through a relay on the
connection's route, an endpoint with no IP transport stops at once when no relay on its route can
be used, and one that can take a direct path lets its attempt run. A refused upgrade counts only
while the relay status still shows it, because the network can let the next attempt through.

A network that inspects TLS presents a certificate of its own for the relay. The endpoint refuses it
(`invalid peer certificate: UnknownIssuer`) unless the network's authority is among
`relay_ca_roots`, which an owner adds explicitly through `network.relay_trust_anchors` in the host
configuration document; the public anchors stay in force beside it.

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

## When a relay turns an endpoint away

`endpoint::connect` dials a peer, and `NetworkTransport::connect` uses it. A connection that no
path could open fails as `TransportError::Connect`, except in one case: a relay on the connection's
route had turned this endpoint away. Then it fails as `TransportError::RelayRefused`, which names
the relay, the kind of refusal, what the relay said and what may still work. A managed relay turns an
endpoint away when its relay allowance is spent, and section 17 requires that to be reported as
what it is rather than as a host that did not answer.

A KalaReach relay starts the reason it gives for a refusal with a kind token, then a colon and one
space, then words for a person:

```
reason = token ": " text
token  = "allowance_spent" / "stopping"
```

| Token | What the relay means | Code |
| --- | --- | --- |
| `allowance_spent` | The allowance this endpoint's traffic is paid from is spent or in its bounded grace, so the relay opens no new session for it | `QUOTA_EXCEEDED` |
| `stopping` | The relay is stopping and admits nothing new; another relay, or this one once it is back, can | `SERVICE_CAPACITY` |
| anything else | A reason with no token this build knows: an older relay, another operator's relay, or a kind added later | `RESOURCE_UNAVAILABLE`, as for any other connection that failed |

The token is the contract and the words are not. A reason that does not start with a known token
and its separator is kept whole and shown as it is, with no kind of its own.

A refusal counts only when the relay that gave it is on the route: a relay the dialled address
names, or one the endpoint already holds for the peer, both of which iroh tries. iroh keeps a
relay's reason only for the endpoint's own home relay, and only as the latest thing that relay
said, so the status is followed for the whole attempt: every value it delivers is taken in as it is
delivered, and it is read again whenever a decision rests on it. A refusal stands while iroh dials
the relay again, and ends when the relay admits the endpoint, when the latest attempt to reach it
failed for another cause, or when it is no longer a home relay, since nothing it says afterwards is
reported. A refusal by a home relay that is not on the route
says nothing about the connection. A route relay that is not the endpoint's home relay leaves no
reason to read, and a failure through it is reported as `TransportError::Connect`.

A refusal is reported only for an attempt that was made and then timed out before any connection
was established. A request that could not be made at all, a peer that answered and refused, and an
endpoint that was closing are each their own reason and are reported as `TransportError::Connect`,
whatever a relay said at the time. The timeout alone does not prove the refusal caused it: a peer
that began the handshake and then fell silent times out the same way. What the failure reports is
that a relay on the route had turned this endpoint away when the attempt ran out.

An endpoint with no IP transport, one built with `relay_only`, has nothing but relays to try, so
once every relay on its route has refused it the attempt ends at once rather than at its 30-second
deadline. An endpoint that can take a direct path lets the attempt run, because an address hint or
local discovery can still open one; if none does, it fails as the refusal. Connections already
established on a direct path are not affected by a relay's refusal at all.

What may still work is named by kind, because which of them a person can use depends on
configuration the failure does not carry:

| Alternative | Offered when |
| --- | --- |
| The peer's current direct addresses, from pairing or an authenticated update | the endpoint has a direct transport |
| Local network discovery the person selects | the endpoint has a direct transport |
| Another configured relay | always |
| A restored relay allowance | the relay said `allowance_spent` |

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

A `Refused` reply, and an error answer on the unpaired pairing surface, reach the caller as
`TransportError::Refused` with the peer's own protocol error, while `TransportError::Handshake` is
this side's own conclusion, such as a reply that never came, a stream that ended or an answer to
another request, and says nothing about what the peer decided.

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
enforce it, and the order matters because the first one is what makes the others truthful. The first
rule is also the one place the build does not reach the guarantee absolutely, and the residual case
is named rather than glossed.

* **The host asks whether a stream carried early data.** QUIC marks a stream as early data only when
  it is accepted while the handshake is still running, so the listener accepts the first
  bidirectional stream from the 0-RTT connection and only then waits for the handshake to complete.
  Nothing is *read* before that wait, so no frame is ever acted on before the peer's endpoint
  identity is authenticated. The answer is not certain, though: if the connection's driver finishes
  the handshake before the listener's task accepts the buffered stream, early data arrives marked as
  ordinary. Closing that window needs an upstream change: iroh 1.2.0 fixes the server's TLS
  early-data size at its maximum and exposes no way to refuse it. That fixed value stays as it is
  and this build does not fork iroh to change it. The residual case is covered by the layer above:
  the only surface reachable in early data is pairing, and pairing consumes an invitation once, so a
  replayed early-data frame redeems nothing a second time. What remains is narrow and stated
  plainly: in that delayed-classification case a first, non-replayed `pair.redeem` or `pair.finish`
  can be served as though it had arrived after the handshake. Section 23 and KR-ACC-026 are
  otherwise enforced absolutely, and this is the one exception the build carries.
* **An authorised connection never carries early data.** A handshake stream that arrived as early
  data is refused with `PERMISSION_DENIED` before the proof exchange, and so is a data stream. This
  costs nothing: a KalaReach endpoint keeps no TLS session tickets, so this product's own client
  cannot offer 0-RTT to anyone.
* **The pairing surface refuses its own mutations in early data.** `pair.status` is a read and is
  served; `pair.redeem` and `pair.finish` are writes and are refused. Pairing is the one surface
  section 23 lets a 0-RTT connection reach at all, and within it everything that changes state is
  closed — for every frame the first rule classified correctly.

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

The connection's own QUIC send window is 8 MiB, which is section 9's bounded send queue per peer
enforced by the transport rather than only by the application's accounting. Inside that window the
application keeps two ceilings of its own:

* **The whole connection.** Every data-stream write is charged against a per-connection budget of
  8 MiB, lowered to whatever the peer declared it would queue. No combination of terminal, semantic
  and attachment streams can hand the connection more than that at once.
* **Bulk within it.** At most 4 attachment streams may be open, and they may hand the connection at
  most 7 MiB at once, so a transfer can never occupy the last mebibyte of that budget.

Control frames are outside this accounting entirely: a connection writes them through one control
writer that holds its lock across the write, so at most one is outstanding at a time, and a control
write is never refused by the budget. The mebibyte the bulk ceiling leaves is what it is for. What
it is not is a reservation: other data streams may use it, so "control has room" means the budget
will not refuse a control write, not that the connection is holding space for one.

A charge covers the complete frame, its length prefix and its stream header included, and it is held
for as long as the write is in progress, which is what bounds a connection whose writes are all
blocked. A message's encoded payload is shrunk to its exact length before it is charged, so the
charge covers what the blocked write actually holds rather than whatever capacity the encoder grew
to. A write the budget refuses is refused whole: nothing is charged, nothing is sent, and the caller
retries. A message is encoded under the smaller of its stream kind's frame bound and the largest
frame its class could ever be admitted with, so a frame this connection could never queue is refused
as too large before it costs a write.

What is not charged is the encoder's own working memory. An oversized message no longer costs the
buffer its encoding would fill: the canonical encoder counts the encoding's length through a
counting writer and refuses the message before writing a byte of it. What a refusal still costs is
the validated value tree and the encoder's conversion of it, which are the same allocations writing
the bytes would have made. A message inside the bound is written into a buffer of exactly its own
length, which is what the charge then covers. The rest of that working memory is allocated and
released inside one synchronous encode with nothing awaited in it, so it cannot accumulate across
blocked writes.

An empty frame is refused before the write, because a zero length is what the peer's decoder reads
as a malformed frame. A caller's mistake stays a local error rather than becoming stream damage.

Control and input are written at a higher stream priority, so the connection sends them first
whenever it has capacity. That priority is conditional, and so is the protection it gives: it
reserves no capacity inside QUIC. Bytes the connection has accepted but not yet had acknowledged
still occupy the window, and the transport has no way to observe when they drain. A sustained
transfer can therefore fill the window, and a control write then waits for the peer to acknowledge
rather than for a scheduler decision. Section 23's guarantee against flow-control exhaustion holds
at the application's admission layer, not inside the window; closing the gap needs per-stream send
accounting the transport crate does not expose.

The negotiated limits are in force as well as the stream kind's ceilings. A peer that declared it
could receive less than the kind allows is held to what it declared, in both directions: an arriving
frame whose declared length exceeds either bound is refused before its payload is allocated, and an
outgoing one is refused before anything is written.

There is a floor under that negotiation, and `hello` is where it is applied. Both sides check the
negotiated result and refuse the connection with `INVALID_ARGUMENT` naming the field, rather than
establishing one that silently cannot carry something the protocol defines:

| Negotiated field | Floor | Why that number |
| --- | --- | --- |
| `max_control_frame_len` | 16 KiB | The largest frame this layer defines on a control stream: the `hello` read bound, and after it the keepalives, action-window renewals and refusals the connection sends on its own account |
| `max_input_frame_len` | 1 KiB | One actor envelope with room left for the keystrokes it carries |
| `max_attachment_frame_len` | 1 MiB + 4 KiB | The complete chunk allowance sections 14 and 23 define |
| `max_outstanding_mutations` | 1 | Below it no mutation could ever be in flight |
| `max_send_queue_bytes` | 2 MiB + 4 KiB | One complete attachment frame beside the control reserve |

Section 9 calls these configurable resource limits, and they are: a peer that wants smaller frames
than the protocol defaults gets them, and is held to what it declared. Each floor is a conservative
minimum for what the connection itself must carry, not a mathematically minimal bound. A declaration above a floor is always accepted and then
clamped to this build's own codec maxima, which is how a later version raises a bound without
breaking this one. Below the send-queue floor a connection could still carry smaller frames; what it
could never carry is the full chunk size a transfer needs, which is why the floor is there.

The same check is applied to a host's or client's own configured budget when it starts, so limits
that could never carry a transfer are refused at registration rather than at the first attachment.

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
subscription returned, then apply the queued updates. The steps are the consumer's to take: the
session tracks positions and delivers events, and the consumer calls `Session::applied`,
`Session::installed_snapshot` and `Session::discard_stream` as it folds them into its state. A
`RESYNC_REQUIRED` answer is returned as `ClientError::ResyncRequired`; discarding the stream it
names is the consumer's call, because only the consumer knows which stream it asked about.

Receiving an event is not applying it. The session records what arrived; a consumer records what it
folded into its state, and only that moves the position a reconnect subscribes from. An event that
was delivered and never applied arrives again rather than being skipped. A gap in the sequence, or a
`RESYNC_REQUIRED` from the host, leaves the stream owing a snapshot: nothing it delivers establishes
a position until one is installed.

Receipts are carried across, and so are the actions that were sent without any receipt arriving,
which is the one case a receipt tracker cannot name. Each of those carries the intent it was
submitted for — the method and the exact subject — so a person can be told which operation is
uncertain rather than which identifier is. A client reports both as unresolved and asks the host
what became of them; it never redispatches an action whose receipt is incomplete. It stops
submitting once 1,024 actions are unresolved, because an unresolved action is never forgotten and a
client that cannot reach its host would otherwise accumulate uncertainty without bound.

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

The barrier itself belongs to the host, because only the host can ask a worker what its fence did.
`docs/host/README.md` describes what the acknowledgement carries, how it is retained so a lost
answer does not lose it, and why membership comes from the registry's durable rows rather than from
whichever workers a daemon has reached. Nothing in either half ends a process to make a revocation
complete.

What the lease enforces today is the deadline: the daemon takes it at the moment it forwards and
bounds the deadline it gives the worker by whatever the lease has left, and the worker checks that
deadline in its serial path. The lease's own identity, generation and revision do not travel to the
worker, because a remote device's mutation does not yet reach one. That is the remaining half, and
it belongs with the path that carries such a mutation.

## Performance targets

Section 27 sets two targets for the transport. Both are measured over a real connection on
loopback, which is the floor rather than a claim about any network: what they show is that the
application's own scheduling and handshake are not where the delay comes from.

| Requirement | What is measured | Target |
| --- | --- | --- |
| KR-PERF-005 | What application scheduling adds above the measured path round trip while a transfer runs | under 25 ms p95 |
| KR-PERF-006 | The transport's share of a reconnect: connecting, the handshake, opening one stream and carrying a screen-sized frame | under two seconds |

KR-PERF-006 measures the transport's share and nothing beyond it. A frame the size of a 120x40
screen arriving is not a screen rendered from it: installing a snapshot belongs to the terminal and
the client that own its format, and their share of the two seconds is measured where they are.

`crates/kr-transport/tests/perf.rs` is the harness. Run it optimised and serially, because the two
measurements would otherwise time each other:

```bash
cargo test --release -p kr-transport --test perf -- --nocapture --test-threads=1
```

### The conditions a figure is taken under

Section 27 measures against a reference host: at least four processors and 8 GiB of memory, with
the operating system and architecture recorded beside the figure, and the host idle apart from the
measurement. The harness prints every one of those beside every figure. Two rules decide which of
them can suppress an assertion.

A condition counts against the host only when the host can be shown not to meet it. Fewer than
four processors is a shortfall. A memory figure below 8 GiB is a shortfall. A platform that does
not report its memory leaves that condition *unverified*, which the run prints and which is not a
shortfall, because a gap in the harness is not a property of the host. So a run that asserts its
target is a run with no measured shortfall rather than a certified reference-host measurement, and
it says so in those words.

And no condition rests on something the application under test could have caused, or a regression
in that application could switch off the check that would catch it. Section 27's idle host is the
hard one, because no interface reports whether the machine underneath a shared virtual one is
quiet. What the harness reads is the share of the processor time the hypervisor took away from the
whole guest, which is a host fact the measured application cannot produce. It is read once for the
idle phase and once for the loaded phase, because one average over both describes neither, and the
worse of the two decides: above one part in a hundred it is a shortfall. The share is a ratio of
the same counters, so it depends on neither the kernel's tick rate nor how many processors the
reading covers. Linux accounts for stolen time; where a platform does not, the condition is
unverified.

That one part in a hundred is this reference's own exclusion rule, not a figure section 27 states:
section 27 gives the reference host's processors and memory and says the host is idle, and
quantifies nothing about how idle. A zero reading is worth less than it looks, too. It means the
hypervisor reported no loss, which is not the same as an idle host: an environment that keeps no
such accounting reads zero, and throttling and a neighbour inside the same guest cost time without
being stolen.

Beside it the harness records how late a thread of its own was woken while the measurement ran, and
the load average where the platform reports one. Both are evidence for reading a run afterwards and
neither suppresses anything: lateness cannot tell a busy neighbour from a slow processor, and a
one-minute average carries the build that just finished.

KR-PERF-005 is asserted where the host meets every condition it can be shown against, and recorded
with the shortfall named where it does not. The reason is in the shape of the figure: it is a
difference between two percentiles taken on the same host, so noise enters it twice and does not
cancel. On a host the hypervisor kept taking the processor from, the figure alone cannot separate
what the application added from what the host took. It does not follow that contention caused the
whole difference, and nothing here claims it did: what a shortfall withdraws is the assertion, not
the figure. Where a run cannot
assert the target it prints its figure, names what was missing and asserts nothing about the
number; the evidence for the target is then the reference-host run in the release acceptance
record.

KR-PERF-006 is asserted on every run, unoptimised builds included. It has held on every host this
has run on by three orders of magnitude, which is why it is asserted unconditionally: that is a
choice about where the line sits rather than a claim that no host could ever miss it.

What both runs assert whatever the host: that the transfer was moving while KR-PERF-005 took its
loaded measurement, and that the frame arrived whole. Without those a harness could pass by
measuring an idle connection twice.

### The property behind the figure

`crates/kr-transport/tests/priority.rs` holds what KR-PERF-005 is about, with nothing timed in it,
so it is asserted on every run: optimised or not, shared runner or reference host. Three things.
The one deadline in that file turns a peer that has stopped answering into a named failure instead
of a job that runs until CI kills it, and it decides nothing about the property.

**Admission.** At the connection's own default limits, a transfer holding every byte its ceiling
allows still leaves the control reserve: one more transfer frame is refused, and a keystroke the
size of the whole reserve is admitted. Exact arithmetic rather than a timing.

**The priority the connection is using.** The connection's own control stream, the one the
handshake opens and the receipts section 23 names travel on, is read back on both sides of it. So
is one stream of every kind the registry opens, again on both sides, because the opening side and
the accepting side install it separately, and the handshake installs its own. A stream whose
priority never reached the connection answers the connection's default of zero and fails there, so
this observes the scheduler's decision arriving rather than the scheduler making it.

**Progress.** Over a real connection, with a transfer that never ends running through it, every
keystroke is answered and each echo carries what was sent; the transfer is still writing when the
keystrokes are done; and a further chunk of it reaches the far end after the keystrokes began,
which is waited for rather than assumed. That is progress on both sides rather than an ordering
between them: on loopback the receiver keeps up, so the standing backlog a keystroke could overtake
is small. The transfer is drained rather than left unread, because a receiver that stops reading
fills the connection's flow-control window, which no stream priority reaches past, and that is the
case named at the end of the streams section rather than this one.

## Local frame writer backpressure

The typed-frame writer over a local connection (`crates/kr-ipc/src/framed.rs`) waits for the peer to
make room between attempts. An attempt never blocks: it writes what the transport takes now and
reports what it could not, and the waiting happens separately, so the decision to send and the
sending are one step that never waits.

The wait differs by transport. On the Unix family the writer parks on the socket's own writability
and wakes when the peer reads. A Windows named pipe has no writability of its own the writer can hold
while the reader holds the other half, so the wait is a bounded poll: it sleeps a millisecond and
attempts again. Measured on Windows Server 2025, a writer waiting on a full pipe for thirty seconds
woke about seventy-four times a second and spent roughly 730 ms of processor time over that span,
about 2.4% of one core.

Because that poll makes progress only when the peer reads, every caller bounds its own wait rather
than relying on the pipe to end it: the worker's delivery ends on a withdrawal or a send deadline,
the controller's attention delivery on its release ticket's own expiry. `FrameWriter::write_frame`,
which waits with no bound of its own, is used only where the peer reads what it is sent — a control
reply, a handshake, a request whose answer the peer awaits — and a path whose peer may stop reading
uses the checked writes under a deadline instead.

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

### How the control daemon keeps them

`crates/kr-controller/src/net` is that host. It is one call at the end of the daemon's startup,
after the reservations are recovered and the worker directory is rebuilt, because a device must not
reach a daemon that does not yet know what it is running. An environment that selects no network
makes no call and serves its local endpoint alone.

| What the transport asks for | Where the daemon keeps it |
| --- | --- |
| `PairedDirectory` | `net::devices`, a durable table of device records keyed by endpoint identity. Revocation is a state of the record, not its absence, so a host can say a device *was* paired |
| `principal_for` | the device principal derived from the identity the host assigned at pairing, so `(actor_id, action_id)` names one device's action |
| `pairing_surface` | `net::pairing`, over `kr-pairing`'s own state machines. Every host on the network offers it: a host with no owner yet serves exactly the first-owner ceremony, and every confirmation is checked against the owner devices the host has paired |
| `serve` | `net::dispatch`, one authorised connection at a time |
| `control_stream_lost` | the connection's registration is withdrawn, which is what stops its lease being renewed |

**Admission atomic with registration.** The daemon reads the device record and writes the
connection into its authority store in one critical section, taking the registry lock and then the
connection table — the order a revocation takes. The store is the same one its local callers are
registered in, so a revocation fences both ingresses through one table, and every read, every
subscription batch and every dispatch checks it. Revoking a device writes the record's revocation
and advances the authority revision inside that one critical section too, so no connection can be
admitted between the record being withdrawn and the revision that fences the live ones.

**Work that must complete.** A mutation's effect runs on its own task, and the release of what a
connection owned at its worker runs on another, after the handler has been dropped.

**One worker link per remote connection.** A worker's attachments, subscriptions and input lane
belong to the connection that created them, so a device's attachment cannot share a connection
with the daemon's own housekeeping. The daemon opens a link per remote connection and declares it
a proxy before it presents a generation token: a proxy forwards its caller's admitted reads and
mutations and announces nothing, and it never displaces the connection that holds the authority. A
token for a higher generation fences the authority connection and every proxy of it together.
