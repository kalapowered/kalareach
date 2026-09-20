# Notification delivery

A KalaReach host decides that something wants a person, writes that down, and then tells a
destination about it. This is how the second half works: what is sent, what is never sent, what
happens when nobody answers, and what a person is told afterwards.

## The event comes first

The host records the underlying event before it produces a notification from it. Not beside it, and
not afterwards: the delivery journal holds a row for each event it has taken, and a notification
row names one of those rows through a foreign key. A notification for an event nothing has taken
cannot be written at all.

Taking an event and producing from it are two separate transactions, on purpose. A host that stops
between them comes back with the event and no notification, which is the safe direction: the person
can still see the pending work on the host. The event row carries the notice it was taken with, so
the next pass finishes what the last one started rather than skipping an event whose cursor has
already moved.

## What travels, and what does not

A notification carries four things: an opaque identifier, a sealed preview, an expiry, and a
collapse identifier.

The **alert** a locked screen shows is one of six fixed sentences. There is no field anywhere for
text a producer supplies, so a command line, an approval argument or a project name cannot reach a
provider's logs by mistake.

The **preview** is sealed to the destination device's `notification_preview` key and to no other
key. That key is registered through the device's own authenticated channel with a purpose and a
revision, and it is a different kind of key from the one that opens mailbox records, archive key
wraps and recovery bundles. A device that turns previews off stops receiving the recipient key on
future notifications; the generic alert still arrives.

The **collapse identifier** groups notifications about one thing so the newest replaces the older on
the device. It is a keyed digest of what the host groups by, under a secret only the delivery
journal holds, so two equal values tell a provider that they group and nothing about what they
group.

## Two sizes, measured rather than estimated

The preview text and the metadata sealed with it are bounded at 1,800 bytes before encryption and
padding. The complete provider payload is bounded below 3,500 bytes, and that figure is measured on
the document the gateway will send to the provider: the registration token, the platform block, the
generic alert and the preview re-encoded as a JSON string. The host does not hold the registration
token, so it reserves the largest one the protocol admits, which makes its own check stricter than
the gateway's.

Nothing multiplies one bound by a ratio to guess the other. When the built payload does not fit, the
detail moves into an encrypted object that stays on the host, and the preview carries a reference to
it. A destination with no key to seal such an object to has the notification refused, with the
reason recorded, rather than sent with its text cut out.

## Sending, and not sending twice

A notification identifier is 128 random bits, minted once. Every attempt presents the same request
bytes, so the gateway recognises a repeat and answers with the decision it already recorded.

- **Queued** means a provider accepted it for delivery. It does not mean displayed, read or
  executed, and nothing here treats it as though it did. Review state comes from host events and
  from what a client acknowledges.
- A **transient failure that never reached the gateway** is presented again, with an exponential
  backoff that is jittered and capped and that stops at the notification's own expiry.
- An **outcome nobody knows** is recorded as unknown and is not retried automatically. A
  reconciliation pass reads the decision the gateway recorded, which is a read rather than a second
  send.
- A **refused credential** is renewed rather than presented again, because presenting it again has
  the same answer.
- A **rejected token** takes the destination out of service until a native registration proves
  receipt again.

## Rate limits, and what a person is told

Twenty in a burst and sixty an hour, per destination. The burst allowance refills over a minute and
the hourly allowance over an hour, continuously, so a clock boundary is not a second burst. Excess
notifications collapse into one attention update every five minutes.

Every request the host made is retained, including the ones that collapsed, and the suppression is
reported locally. A destination over its limit is a destination whose pending work is still visible
on the host.

## External destinations

Webhooks and the documented Slack, email, Discord and Telegram integrations run on the host. Two
things have to be true before any content leaves: the destination is configured, and an explicit
rule or grant admits the content. They are separate facts, and writing down an address is not
authority over session content.

**Recipients of an external message can read it.** Encrypted KalaReach routing does not change that,
and every message says so in its own text. The content is intersected with the recipient's own
authority: the host filter decides which interval of history the grant reaches, and the producer
checks that each line's session is one the grant names. A line that fails either is left out, and
the message says how many were left out and why.

Retry follows from the destination rather than from optimism. A destination that deduplicates by a
delivery identifier the host chooses is presented again after an unknown outcome. One that does not
is not: the record says the message may have arrived and may arrive twice if it is sent again, and a
person is told that rather than a guess.

## Privacy mode

Enabling privacy mode fences the delivery outbox at once: nothing more is offered to a sender, and
the fence is in the read every sender makes rather than in a flag each of them remembers to check.
Work that was admitted and never dispatched is taken back, and its bytes go with it. The queued
request bodies and the encrypted objects a preview's excess moved into are removed; the records of
what happened stay, because a host that forgot its own attempts could not tell a person what the
device did not see.

Cleanup is not complete while an attempt is on the wire or an outcome is unknown. A result produced
under an earlier generation is refused rather than published.

What has already left is not erased and is not claimed to be. Notifications a provider queued and
messages another service accepted are listed as retained artifacts, each saying that this host holds
no way to recall it. Deleting one is a separate action, authorised on its own.

## Where the state lives

One delivery journal per environment, beside the daemon's other state, keyed by underlying event,
destination and attempt. A state transition, the attempt behind it and the outbox row that follows
from it are written in one transaction. Every notification an event produced, what they spent from
the destination's allowance, and the event's own completion are written in another.

Budgets, cursors, queued work and the collapse window survive a restart and a reboot. A store that
has lost a table or its privacy row is refused rather than reopened as an empty one, because an
empty outbox says the opposite of what is true.

A delivery credential is never written here. The journal holds the identifier of the authorisation,
which names it and proves nothing.
