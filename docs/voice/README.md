# Voice on the host

The voice coordinator runs on the host. It selects what a call may know, interprets what a call
asks for, and submits every action through the checks the host already applies to a typed request.
Voice processing has an explicit data-access boundary, separate from the encryption of terminal
transport, and this document is that boundary written down.

## What the parts are

| Part | Where it runs | What it owns |
| --- | --- | --- |
| The native client | The paired device | The microphone, the speaker and the WebRTC media path |
| The coordinator | The host | Context selection, delegation, the voice grant, verification of the unlocked-screen confirmation |
| The managed service | KalaReach | Creating the provider call, the money, the metering channel and the six commands it will carry |
| The provider | OpenAI | The model, the audio and the delegations it announces |

Audio travels between the device and the provider. It does not pass through the host, and it does
not pass through the managed service.

## What the coordinator may read

One thing: content the host has already passed through its shared host-side history filter at the
voice-context surface, under a viewer scope built from the **requesting device's** grant.

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

The bounded selection the specification states, and nothing else:

- the session description, the current working directory, the active application, the summaries of
  decisions waiting on a person, and the last twenty semantic messages;
- capped at eight thousand text tokens, enforced by dropping whole items rather than cutting one in
  half. The host cannot run the provider's encoder, so what it counts is a bound no byte-level
  tokenizer can exceed — the selection's own byte count — and a selection is therefore often
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

Using a provider credential of your own changes who can read it, and nothing else about how the
host decides what a call may do.

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

Two exist per device. The **standing** grant says which voice actions the person chose to permit and
survives calls. The **session-bound** grant is delegated from it when a call starts, narrows to the
sessions that call may reach and to the call's own deadline, and is revoked the moment the call
stops — immediately, and independently of the service's billing finalisation. Revoking the standing
grant revokes its descendants, so withdrawing it ends any call running under it.

The default grant permits session navigation, status queries, briefing and prompt composition, and
nothing else. Broadening it is a choice a person makes, and the change states which actions it
permits, one sentence per action. The statement lists every action the grant's rights permit rather
than only the ones that were named: several voice actions share one right, so asking for status
alone permits navigating, briefing and composing a prompt as well, and the person is shown that
rather than finding it later.

A device changes its own voice grant over its own connection. The person at this machine changes any
device's on the host's own socket. A device changing another device's needs host-management
authority, which this host does not yet resolve for a device, so it is refused rather than guessed
at.

## How a device reaches it

The five voice methods are served to a paired device over its own authenticated connection, which
is the ingress section 23 gives them. `voice.grant` is also served on the host's own socket, to the
person sitting at the machine. A device holds its ordinary grant and, separately, a voice grant; the
connection's own check resolves the voice right against that second grant, and the coordinator takes
the intersection of the two again at the moment of every decision.

One device starts one call at a time, and one change to a device's voice grant runs at a time, so
two requests can never each decide about the authority the other is writing.

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

Brokering a managed call spends an account's balance, so the host presents an account token. It is
read from `account-token.json` under this host's runtime root, written by
`kr account token import <path>`, and it is never printed: not by the command that imports it, not
in a refusal, not in a log. The value lives in a type with no display, and the one place it is read
is the authorisation header of the request it authorises. The token lasts as long as the service
said when it issued it, ten minutes for the managed service, and the host does not refresh it; a
token issued without the `voice` scope is refused before any request carries it.

A host with no token, and a host with no broker configured, are both complete hosts. A provider
credential of your own and the agent already running in the session both still work.
