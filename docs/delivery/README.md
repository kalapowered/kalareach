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

A registration is one action with one answer. The host keeps the answer with the action, so a
device whose answer was lost asks again with the same action and is told what it was told the first
time, even after a later rotation; a new action carrying an old revision is refused. The delivery
journal takes a registration before the device directory does, and a host that stopped between the
two finishes the directory's half from the journal when it next starts.

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
- An **outcome nobody knows** is recorded as unknown and is not retried automatically. What can
  still resolve it is a question that carries the notification identifier and nothing else, on a
  route that answers from what the gateway recorded; asking cannot deliver the notification, and
  the request bytes go with the settlement rather than being kept for a second presentation. A
  question nobody answers resolves nothing: the record stays uncertain and stays listed.
- A **refused credential** is renewed rather than presented again, because presenting it again has
  the same answer.
- A **rejected token** takes the destination out of service until a native registration proves
  receipt again.

## Who sends, and when

The daemon sends on its own. Its start path runs recovery first: an attempt an earlier daemon left
on the wire becomes an outcome nobody knows, queued work whose authority has ended is taken back,
and every event taken and never produced from is finished. Nothing is delivered until recovery has
succeeded; one that fails is tried again before every pass. Then a pass runs every second and
claims and sends whatever is due.

Every few minutes, on a loop of its own, the daemon renews delivery credentials inside their renewal
window, so a credential is current before a notification needs it, and asks about outcomes nobody
knows. Those questions are rationed: a bounded batch at a time, within a time limit, and a question
that finds nothing waits longer before it is asked again, so an old backlog cannot keep a newer
notification from being asked about. Each record waits from the moment its question fell due, first
question or repeat, so a stream of new ones cannot keep an older one waiting either. An old
notification is asked about less often, never dropped: the gateway keeps an answer for a time that
runs from its own decision, which the host cannot see.

The gateway allows each host 1,200 status questions an hour, and each installation the same, and it
counts them whichever loop asks: the pass asking about a notification the gateway is still retrying,
or the sweep over unknown outcomes. Each loop has a fixed share of its own. The pass may ask a burst
of 70 and then one about every five seconds; the sweep a burst of 30 and then one every twelve
seconds. Together that is at most 1,100 in any hour wherever the hour starts, and every question
about an installation is also one of the host's own, so the shares cover both limits. Neither loop
can spend the other's share, so a steady run of one kind of question never stops the other kind
being asked.

A question a share cannot cover yet is not put. A pass leaves that notification due and spends no
attempt on it; a sweep stops, and the records it did not reach keep their turn. A pass takes its
sends and its questions from the outbox separately, up to 32 of each, so questions left waiting
never hold a send back and a steady run of sends never keeps an older question from being asked.

Every exchange goes to an origin the delivery already knows. A notification, a status question and
a renewal go to the gateway the delivery credential names, which is the gateway that issued it; a
webhook message goes to the address its owner configured. Each origin is reached through the same
managed transport every other service call uses: HTTPS, no redirects, finite deadlines, a bounded
answer, and nothing sent again that may have arrived. A failure before a byte of the request was
written is the one failure that counts as "nothing was sent".

A renewal is two signed requests. The daemon asks the gateway for a nonce, then answers it with a
proof signed by the host key the installation named when it authorised the host, and receives a
fresh credential. The daemon holds credentials in memory and renews them; it never writes one down.

## Rate limits, and what a person is told

Twenty in a burst and sixty an hour, per destination. The burst allowance refills over a minute and
the hourly allowance over an hour, continuously, so a clock boundary is not a second burst. Excess
notifications collapse into one attention update every five minutes.

Every request the host made is retained, including the ones that collapsed, and the suppression is
reported locally. A destination over its limit is a destination whose pending work is still visible
on the host.

## External destinations

External delivery runs on the host. Two things have to be true before any content leaves: the
destination is configured, and an explicit rule or grant admits the content. They are separate
facts, and writing down an address is not authority over session content.

**Recipients of an external message can read it.** Encrypted KalaReach routing does not change that,
and every message says so in its own text. The content is intersected with the recipient's own
authority, which is the grant the destination's rule names, read from the host's grants and
intersected with the host's current policy at the moment of asking: a grant that is revoked,
expired, not yet redeemed, issued for another environment, refused by the policy (an organisation
grant whose recipient no current member lease answers for, a personal grant on a host that is
exclusively organisation-managed, remote use past the offline-validity bound), or one whose rights
no longer include viewing a session admits nothing. The host filter
decides which interval of history the grant reaches, and the producer checks that each line's
session is one the grant covers. A line that fails either is left out, and the message says how
many were left out and why.

### Five kinds

| Kind | What the host sends | Who can read it |
| --- | --- | --- |
| Webhook | The composed message as JSON, POSTed to the address the owner configured | Whoever runs the service at that address, and anyone that service passes it to |
| Slack | The message as text, POSTed to the incoming webhook's address with Slack's formatting and link unfurling off | Everyone who can read the channel the webhook posts to, and Slack |
| Discord | The message as text, POSTed to the webhook's address with `wait=true`, no mention allowed and link embeds suppressed | Everyone who can read the channel the webhook posts to, and Discord |
| Telegram | `sendMessage` to the chat the destination names, as plain text with link previews off | Everyone in that chat, and Telegram |
| Email | A plain-text message submitted over TLS under the owner's mail account, to the address the destination names | Everyone who can read that mailbox, and every mail server that carries the message |

Whatever the kind, the message ends with the sentence that says anyone who can read its destination
can read it, and configuring a Slack, Discord, Telegram or email destination's credential answers
with the same fact in that kind's own words. Session text reaches a chat service as text and never
as markup: Slack's `&`, `<` and `>` are escaped, Discord is told to ping nobody, and Telegram parses
no entities, so a line of terminal output cannot mention a channel, notify everyone or turn into a
link the service fetches. Discord takes 2,000 characters and Telegram 4,096, and a Slack message is
held well inside Slack's own limit; a longer message keeps its opening, says it was shortened, and
still ends with that sentence.

A webhook's status code never counts as "already delivered": a 2xx is delivered, a request for later
is nothing taken, and any other refusal, a 409 included, is a refusal. A webhook that deduplicates by
a delivery identifier receives one, under the header it names. The chat services read the same way:
a 2xx is delivered (for Telegram, a 2xx that says `"ok": true`), a 429 is nothing taken, any other
4xx is a refusal, and a 5xx is an outcome nobody knows. The request's address can hold the
credential, so a failure is recorded by what kind of failure it was and never with the transport's
own message, which names the address.

### Credentials

A webhook's address is where it sends and nothing more. The other four send with a credential: a
Slack or Discord webhook address is itself a bearer secret (whoever holds it can post to the channel
it was made for), Telegram sends through a bot token, and email through a mail submission account. A
destination's endpoint is never a credential. For those four it names the channel a webhook posts
to, the Telegram chat (its number or a public chat's `@username`), or the email recipient.

The owner hands a credential to the host with `delivery.destination.secret.set`, on the host's own
local socket. A paired device cannot, whatever its grant, host management included: a credential
decides who reads session content, so handing one over is the owner's act at the machine. The host
checks that the credential has the shape its service issues (a Slack address on Slack's webhook
host, a Discord address on Discord's, a Telegram token, a mail account with a server, a port and a
plain sender address) and keeps it in its secret store under the destination's identifier: the
platform's own credential store, or the owner-only directory where there is none. The answer names
the destination, the kind, whether the credential is in force, and who can read what the
destination delivers. Nothing ever answers with the credential. It is never written to the delivery
journal, a log or an error, and a refusal of a malformed request says what shape was expected
without repeating anything the request carried.

A destination of one of those kinds is configured only once its credential is kept, and without a
delivery identifier: none of the four services recognises a repeat by one. The journal records a
random stamp in place of the credential, and the stamp is part of what binds a notification to its
destination. Storing a new credential under a configured destination changes that binding, so a
notification admitted while the old credential was in force is taken back at its claim rather than
sent with the new one, which may reach somewhere else. A pass reads the credential as it sends and
sends nothing when the credential it finds is not the one the destination was configured with.

The credential goes with its destination. Removing a destination deletes the credential first; then,
in one journal transaction, everything queued for the destination is taken back (revoked when
nothing was dispatched, recorded as an outcome nobody can settle when an earlier attempt was), an
attempt on the wire keeps its answer but can never be followed by another, and the record goes, or
stays out of service as the name of what was already sent. Configuring a webhook or a paired device
under an identifier deletes any credential kept there, so a destination configured under it later
cannot pick up a credential nobody gave it.

### Email

Email goes over TLS and nothing else: implicit TLS for an account set to it (port 465), STARTTLS for
one set to that (port 587). Over STARTTLS the host says `EHLO` and `STARTTLS` in the clear and
nothing more. A server that does not offer STARTTLS is not sent to, and neither is one that sends
anything between agreeing to TLS and starting it. The server's certificate is verified by the
operating system's own verifier, the one the managed HTTPS transport uses, and nothing turns that
off. The host signs in with AUTH PLAIN, or AUTH LOGIN where the server offers only that.

The addresses and the subject are checked before they are written, and none may carry a line break,
so nothing a destination or an event supplies can add a header or a mail command. The body is
quoted-printable, every line ends in CR LF, and a line that begins with a dot is sent with a second
one in front of it.

What a server's answer means depends on when it came. Before the line that ends the message is
written, nothing was sent: a 4xx is a request for later, and a 5xx, a server with no STARTTLS or a
certificate that does not verify is an answer about the destination, so the attempt is abandoned
rather than marked uncertain. Once that line is written, a 2xx is delivered, a 5xx is a refusal, and
anything else, silence included, is an outcome nobody knows. A reply's own words are never written
down, only its code and its enhanced status code, because a server's words can repeat what it was
sent.

### Retries and uncertainty

Retry follows from the destination rather than from optimism. A destination that deduplicates by a
delivery identifier the host chooses is presented again after an unknown outcome. One that does not
is not: the record says the message may have arrived and may arrive twice if it is sent again, and a
person is told that rather than a guess. That is every Slack, Discord, Telegram and email
destination, and a webhook configured without an identifier.

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
messages another service accepted are listed as retained artifacts, each carrying the notification
and destination it is a copy of so that a separately authorised deletion action can name exactly the
artifact a person chose. Every entry is marked non-deletable (`deletable: false`): the flag says
whether this host holds a way to ask for a removal, and for a copy that is on a device or in another
service it does not.

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
