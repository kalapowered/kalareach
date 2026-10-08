# Voice on the host

The voice coordinator runs on the host. It selects what a call may know and interprets what a call
asks for, and it decides each action against the grants the host already keeps. Voice processing has
an explicit data-access boundary, separate from the encryption of terminal transport, and this
document is that boundary written down.

A host whose configuration document names a managed broker (`voice.broker_origin`) attaches it when
the daemon starts. The daemon reaches the broker over a transport of its own, through the proxy the
same document selects, and presents the account token of the account an operator signed in on the
host (`kr account sign-in`). A host whose
document names no broker attaches no provider, so no call starts on it: `voice.start` answers that
the host has no voice service configured. `voice.grant` acts as this document describes, and
`voice.prepare` returns the scope a call would have, with no managed terms. With no call there is no
voice session, so `voice.context` and `voice.delegate` are refused as naming no such session. The
sections on what a call may read and send, where it goes, the managed operator, what is never
authority, the session-bound grant, the rate and the account token describe what the coordinator
does once a provider is attached, which its code and its tests establish. The section on what this
daemon performs and supplies says which of that this daemon carries out itself.

## What the parts are

| Part | Where it runs | What it owns |
| --- | --- | --- |
| The native client | The paired device | The microphone, the speaker and the WebRTC media path |
| The coordinator | The host | Context selection, delegation, the voice grant, verification of the unlocked-screen confirmation |
| The managed service | KalaReach | Creating the provider call, the money, the metering channel and the six commands it carries |
| The provider | OpenAI | The model, the audio and the delegations it announces |

Audio travels between the device and the provider. It does not pass through the host, and it does
not pass through the managed service.

## What the coordinator may read

The coordinator may read one thing: content the host has already passed through its shared host-side
history filter at the voice-context surface, under a viewer scope built from the **requesting
device's** grant.

- The filter is the one section 10 requires, and voice context is one of its named callers. It is
  applied once, on the host side, before anything reaches the coordinator.
- The scope comes from the device's grant and from nothing else. There is no call shape that asks
  for the host owner's wider history: the seam takes a grant, and the owner's own authority is not
  a grant.
- The coordinator applies the grant's history lower bound again to every item it is handed. A host
  that filtered incorrectly does not get that mistake past the coordinator, and what the second
  check drops is reported as withheld rather than hidden.
- Every item carries the moment its content was **produced**, which is what the bound is checked
  against. A fact the host cannot place in time is named as missing rather than carried under the
  moment it was read, so a retained summary of a session that closed long ago cannot pass a bound
  written after it ended.

## What the coordinator may send back

The coordinator may send back the bounded selection the specification states, and nothing else. It
is an upper limit, and this daemon supplies less of it, as the section on what this daemon performs
and supplies says:

- the session description, the current working directory, the active application, the summaries of
  decisions waiting on a person, and the last twenty semantic messages;
- capped at eight thousand text tokens, enforced by dropping whole items rather than cutting one in
  half. The host cannot run the provider's encoder, so what it counts is a bound no byte-level
  tokenizer can exceed (the selection's own byte count), and a selection is therefore often
  smaller than the cap rather than larger;
- file contents, environment variables, raw terminal scrollback and attachment bytes are **excluded
  until the person selects them**, and the four are a closed list rather than a rule to remember.

Configured secret patterns are replaced on the way out. That is a **secondary** measure. Every
selection carries the sentence that says so, and the count of what was replaced: filtering does not
prove the remaining content holds no secrets.

All of it is project text. Instructions the application writes are a separate type on the wire, so
a reader can tell which is which without knowing where the value came from.

## Where it goes

The coordinator returns the selection and its results **to the paired client**. The client is what
sends them to the managed service, as bounded context requests. The host does not reach the managed
service with content at all; the only calls it makes are reading the terms the service publishes,
creating a call and ending one.

## What the managed operator can see

Managed voice gives KalaReach technical access to the conversation. The service's own channel to
the provider receives transcripts and copies of the audio so it can meter the call. Those events are
discarded before telemetry and are not stored, which reduces what is kept rather than making the
operator unable to read a call.

The service states this in its own words, and the host carries them to where the choice is made
rather than to a policy page. The preparation a person reads before a call carries them, the call
carries them when it starts, and every context selection for that call carries them too. The host
keeps no wording of its own for this.

Using a provider credential of your own would change who can read it, and nothing else about how
the host decides what a call may do. This daemon attaches only the managed broker.

## What an append acknowledgement does not mean

The provider acknowledges context it received. That acknowledgement proves **admission** and
nothing more. It is not evidence that a host action ran, and it is not evidence that audio was
played. Host action receipts are the authority for what was done, and a proposal the host accepted
without performing is reported as admitted rather than as done.

## What is never authority

A transcript is content. A provider delegation identifier is correlation data. A statement from the
model that you confirmed something is content too. None of them is authority, and none of them can
become authority by arriving over a channel the host trusts for something else.

- Every effect is decided against a grant in the host's one authority store.
- The actor is the paired device under its ordinary grant, **intersected** with a separately created
  voice grant and the session binding. Asking a voice grant for more than the device holds narrows
  it; it never adds.
- The five actions that need a confirmation on an unlocked screen need a signature from the paired
  device's identity key, bound to the exact action hash and the current request, single use and
  short lived. No amount of provider text produces one, and a confirmation for one action does not
  authorise another. Submitting one of those actions the first time answers with the challenge to
  sign rather than with a refusal, and the delegation is not spent by asking: the same delegation
  comes back carrying the signature and becomes one action.
- A delegation identifier is spent when it is submitted, for that device, through every call it holds
  and across a restart, for as long as the host keeps a de-duplication record. One delegation is one
  action.
- Submitting a prompt needs a spoken confirmation that names the destination session. The host
  checks the session against the one it is about to submit to, and checks the words themselves for
  a clear agreement, so silence and "do not send that" both stop it. The words reach the host from
  the paired device that transcribed them, so they are content: the grant is what permits the
  effect and this is what section 15 ¶13 asks for on top of it.
- An approval decision needs the verified request's details and an explicit answer. Details the host
  does not hold are refused rather than believed.
- Cancelling a coding task uses the agent's typed request and its current turn identifier.
  Interrupting speech stops playback; there is no path from one to the other, because interruption
  is not in the coordinator's vocabulary at all.

## The voice grant

A voice grant is an ordinary grant in the host's one authority store. There is no second store.

Two kinds exist per device. The **standing** grant says which voice actions the person chose to
permit and survives calls. The **session-bound** grant is delegated from it when a call starts,
narrows to the sessions that call may reach and to the call's own deadline, and is revoked the
moment the call stops, immediately and independently of the service's billing finalisation. A host
that names no broker starts no call, so none exists on it. Revoking the standing grant revokes its
descendants, so withdrawing it ends any call running under it.

The default grant permits session navigation, status queries, briefing and prompt composition, and
nothing else. Broadening it is a choice a person makes, and the change states which actions it
permits, one sentence per action. The statement lists every action the grant's rights permit rather
than only the ones that were named: several voice actions share one right, so asking for status
alone permits navigating, briefing and composing a prompt as well, and the person is shown that
rather than finding it later.

A device changes its own voice grant over its own connection. The person at this machine changes any
device's on the host's own socket. A device that tries to change another device's is refused: that
needs host-management authority, and this host does not resolve that right for a device.

## How a device reaches it

The six voice methods are served to a paired device over its own authenticated connection, which
is the ingress section 23 gives them. `voice.grant` is also served on the host's own socket, to the
person sitting at the machine. A device holds its ordinary grant and, separately, a voice grant; the
connection's own check resolves the voice right against that second grant, and the coordinator takes
the intersection of the two again at the moment of every decision.

One device starts one call at a time, and one change to a device's voice grant runs at a time, so
two requests can never each decide about the authority the other is writing.

## What this daemon performs and supplies

The daemon performs one kind of voice action itself, the reading of a session, which covers
navigating, status queries, briefing and composing a prompt. For every other action that has a
method it admits the proposal and reports it as admitted and not done, because the daemon does not
dispatch to a session's worker, and a receipt stands for what was done. Delivering something
externally has no method, so a proposal for it is refused. A decision on an approval is refused: the
daemon holds no approval's details to check a spoken decision against.

The context the daemon supplies is read from the daemon. The session number, pinned name (if any)
and shell are read, as is the time at which the session was created. The working directory and time
are the most recent recorded on the session's description host; if the description host has not seen
a directory yet, the directory the session started in and the time at which the session was created
are used instead. The active application and time are the most recent program the description host
saw in the foreground, and it counts as the active application only while its command runs; before
the host has seen one, and once the command has ended, no active application is provided, and the
selection carries the reason for withholding it instead. If a model has written any text about the
session this is also read; this text is marked as written by a local model which may be incorrect,
and as written at the start of the session, so a grant whose history begins after the start of the
session is not shown it. The model's text will not be read if a name is pinned. Summaries of pending
decisions, and messages, are not read as the daemon does not store semantic history for workers; the
selection carries that reason as withheld. Content of any of the four classes selected by the person
(file contents, environment variables, scrollback contents, and attachment bytes) will not be
provided: the companion selects none of these classes, and this daemon has no place to read them
from, so a request that selects one gets nothing for it and no withheld entry.

What a model wrote and what the description host saw leave the daemon only while the privacy mode is
in the same state as it was when they were read. Privacy mode removes both when it is turned on, and
the daemon reads neither while it is on. If the privacy mode is turned on whilst the context is
being read the context will be read again, and the answer carries neither. The context will be read
at most three times; if the privacy mode keeps changing the request will be refused as transient and
the device will request it again. The answer is checked once, when the read ends, so the privacy
mode may still be turned on between that check and the write to the device. The receipt for a voice
read of a session carries the pinned name and the facts the daemon holds itself, but no model text
or description host information.

## A voice session is not a terminal session

It has its own identity and its own end. Stopping a voice session names the terminal sessions it
reached and closes none of them; nothing in the coordinator can close one without an unlocked-screen
confirmation of its own. Voice can stop while the agent keeps working.

## The rate a call runs under

Before a call, `voice.prepare` reads the managed service's published terms and hands them to the
device unchanged: the model, the disclosure, the rate with its version, the longest call the service
authorises and whether an operator has it open. Reading them creates nothing on either side.

A start for a managed call names the version of the rate the person was shown, and the host passes
it on as the service's `expectedRateVersion`. The service compares it with the rate it would charge
now. When the two differ it refuses before anything is held, and the host answers `rate_changed`
with the rate as it is now; no voice session and no grant are written for that start.

## The account token

Brokering a managed call spends an account's balance, so the host presents the account token of an
account an operator signed in on it. `kr account sign-in` asks the control daemon, which listens on
the loopback address the desktop client is registered with, `127.0.0.1:8765`, while a browser signs
in; the daemon exchanges the answer with the service and keeps the account in the host's secret
store, `kr account show` says where that stands and `kr account sign-out` ends it. Only the daemon holds it, because its refresh
token rotates on every use and a second holder would end the sign-in. The setup is in
[Account sign-in](../host/README.md#account-sign-in).

The value is never printed: not by either command, not in a refusal, not in a log. It lives in a
type with no display, and the one place it is read is the authorisation header of the request it
authorises. The access token lasts ten minutes. The daemon refreshes it when a call needs one and
the one it holds is about to end, never before, so a host that starts no call spends no refresh
token. The browser signs in at the managed account service, and its code is redeemable there alone,
so a token is presented only to a voice broker that is that service; a host whose configuration
names another broker presents none. A token issued without the `voice` scope is refused before any
request carries it. A call closes under the account it started under, so a sign-in is refused while
a call is open; a call whose phone is lost stops counting when its deadline passes or the service
says it holds no such call, and the host ends its record then. When the service ends the sign-in, the host shows it as ended, and a call that needs
a token is refused with a message that says to sign in again.

A host with no account signed in and a host with no provider attached are both complete hosts.
They start no managed call, and nothing else on them depends on one: sessions, agents and their questions work as
they do without voice. The coordinator takes its provider through a seam, so a provider of a
person's own can stand where the managed one does, and this daemon attaches only the managed one.
