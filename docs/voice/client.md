# Voice on the client

The companion application holds the parts of a voice call that belong on the device: capture,
playback and the WebRTC connection in native code on each phone, the capture gate that decides
when the microphone may carry speech, and the voice screen. The device-owner confirmation ceremony
is the phones' own. The desktop application opens no call.

## What a person is told before a call exists

`voice.prepare` is a read that creates nothing: no provider session, no reservation, no grant, and
no context leaves the host for it. It answers with the sessions a call would reach, what the voice
grant would permit action by action, the content classes the default context leaves out, the host's
cap on selected context and the origin of the service the call would be brokered through. Beside
those it carries the managed service's own terms, which the host reads from the service's metadata
route for the answer: the model, the disclosure, the rate with its version, the longest call the
service authorises, and whether an operator has the service open (KR-REQ-15.19, KR-REQ-15.09). The
terms travel in the service's words, and a host that could not read them says so instead.

A start names the version of the rate the person was shown. The host passes it to the service
unchanged, and a version that is no longer current comes back as `rate_changed` with the rate as
it is now. Nothing was started, held or charged, and the host wrote no grant for it, so the device
shows the new rate and starts again only when the person accepts it.

It exists because the other two answers come too late. `voice.context` names a voice session, and
there is none before a call; `voice.start` answers with the model and the disclosure, but by then
the metered provider session has been created. A person who declines after reading has to be able
to decline something that cost nothing.

## Native audio, not a WebView path

Section 15 ¶2 explicitly forbids capturing or playing audio through a WebView `getUserMedia` path.
The native client implements media directly:

- **iOS**: `apps/companion/native/ios/KalaReachNative/VoiceCall.swift` holds a native WebRTC
  connection from the pinned `stasel/WebRTC` framework. Its audio session is WebRTC's
  `RTCAudioSession`, configured for play and record in the voice chat mode, with Bluetooth headsets
  allowed and the speaker by default. WebRTC's audio unit is held off (`useManualAudio`) from the
  moment the session object exists, before any connection, so negotiating starts no recording.
- **Android**: `apps/companion/native/android/android/src/main/java/.../voice/VoiceCall.kt` holds a
  native WebRTC connection from `io.github.webrtc-sdk:android:150.7871.01`, over WebRTC's Java audio
  device, which records through `AudioRecord` and plays through `AudioTrack`. Recording and playout
  are switched off the moment the connection exists, and every recorded frame passes the capture
  gate before the encoder sees it: a frame the gate refuses is replaced with silence.

On iOS and Android the connection reads the provider's data channel and never writes to it. The
voice screen asks the application to start a call, and the application does the rest, as the next
sections say. The page holds no connection.

## How the application reaches the call

The call is native code, and the rest of the application reaches it through one interface. The application asks for a call to be opened, for its offer, for the provider's answer to be applied, for the call to be permitted, muted or stopped, and for what the device holds. Native code answers each request once. It reports the call's news on a channel it was given when the call was opened: the state of the connection, what the provider sent on its read-only channel, the first remote audio, what the microphone is doing, and the end of the call.

Each item of news carries the call's name and a number, counted from one as native code sends it. News that is lost is told to the reader as lost news, in the place where it was lost: after the news that came before it and ahead of the news that came after it. It is never told as silence. News is lost when a number is skipped, when a queue is full, and when the text that arrives is not news. A full queue drops a provider event first. Any other news that finds the queue full takes the place of the oldest provider event waiting, or of the oldest news when there is no provider event, and the end of the call is never what is dropped. Nothing is queued after the end. A request that native code cannot carry out is refused with a code from a closed set: the microphone is not allowed, a call is already running, there is no such call, the call has ended, or the media engine could not do it.

On iOS the call lives in a target the platform plugin cannot see, so the plugin finds the application's adapter by the name of its class. On Android the application registers its bridge once, when its first activity starts, and the plugin finds it there. No class is looked up by name, so a minified build cannot break the link, and an activity that the system recreates still reaches a call that is running. The shapes of every request and every item of news, and the rule that queues news, are fixtures that the Rust, Swift and Kotlin tests all read; the Swift and Kotlin tests also read the requests that must be refused. The state of a call reports the person's own mute apart from what the gate shows of the microphone, so a microphone that is not running does not hide a mute. On Android the permission question is asked when a call is opened. If nobody answers in two minutes, the call goes on with what is allowed, and is refused if that leaves out the microphone. On iOS the application does not ask the person for notifications, since a call there needs none; it reports what the person has already allowed. A debug build can drive the interface on a simulator or an emulator with `scripts/e2e-voice-call-bridge.sh`.

## Who owns a call

Only one task owns a call, from the moment it is asked for until it is over. The screen asks and reads, and does not own the call. When a screen is loaded again, it finds the call where the application keeps it: `voice_call_state` names the call that is being set up or running, what the microphone and the speaker are doing, whether the voice service's control is connected, whether the host the call belongs to can be reached, the requests the voice announced, how the last call ended and what it left owed. Before the host has named a call, the state still says that the device is busy with one, because the call has no name to give yet. While the device is making the call, the screen offers no second start, which the device would turn away, and offers an end that names no call. The screen that asked for the start offers the same end beside the start control while the start waits for the host, and says that the end has begun once it is pressed. Once the end of a call has begun, there is nothing more to ask of the device, so the screen says only that the call is being ended. It says nothing of the microphone, because before a call runs the device cannot tell the screen what the microphone is doing. A start that ends with no call is recorded too, in the words its asker was given, so a screen that is loaded again meanwhile finds how the start ended, and not how the call before it ended.

A start first checks that the account can give a voice token, before anything is created. Native code then opens the call and asks for the microphone. The host is asked to start the call with the offer, and the provider's answer is applied. The call is then permitted, and the control is opened at the voice service the account is signed in at, whatever service the host named. A stop that arrives during any of these steps gives the call up, and a stop reaches the task that owns the call whether or not it names the call.

When the host's answer to a start is lost, the task asks the host again under the same action. A repeat is a question, not a second request, and only a result settles it: a refusal, a receipt or silence leaves the outcome unknown. A stop that comes while the host is answering the start, or during these questions, stops the media at once and is answered, but the wait goes on, because the host may have made a call that only its answer can name. When a repeat finds the call, the call is ended and its grant revoked. If none does, the start is recorded as having an unknown result, with the action it was sent under.

## How a call ends

Calls are ended the same way whatever the reason: the person hung up, the person pressed stop in the notification, the connection failed, native code stopped answering, the voice service closed or refused the call, the call's closing time was reached, the person signed out, the device forgot the host, the person chose another host in its place, or the task that owns the call failed. When a call ends, the media stops and the host is asked to revoke the call's grant, both at once and each with a bound of its own. The reason they run at once is that a stop that never comes back should not hold up the revocation, and a host that never answers should not hold up the media. The control asks the voice service to close the call as the end begins, and the service's own route does it when the host did not. The screen does not wait for the service.

The record keeps apart what the host did and what happened on the device. The host can have done four things: 1. The host revoked the call's grant and let the device know. 2. The host said it holds no call of this device by that name. 3. The host refused the stop for another reason, which does not say whether the grant is gone. 4. The host was not informed of the need to stop the call, or the host did not respond in time. In the last two cases, the revocation is owed to the host. In all cases, the words that say what happened are in the past tense. Whether the grant may still be open is said by whether a revocation is owed; what is owed lapses when the grant lapses. Whatever is owed names the host it is owed to. It stays on the screen until the moment the grant ends by itself. It stays with room for a clock that is not the device's own. A start that was never answered stays too: the device records the start under the action it was sent under, the next call does not remove it, and it is kept until the end of the action window it was sent under, on the host's own clock, plus the length of call it asked for and the clock allowance, since any call the host made for it could not run past that moment. Nothing that has not run out is removed to make room for a new entry. After the call has ended, the screen keeps reading until the voice service has said whether it closed the call; if the service did not confirm it, that is owed too. The notice stays until the call's own limit has passed. That is when the notice ends, not a time by which the voice service closes the call. The device also says whether any call is still waiting on the voice service, even after a new call has replaced the old call's record. A new start never takes this notice away. A call is bound to the host that made it, so a stop goes over a connection to that host. When the host revokes the device, the host ends what the device holds, since from the phone's perspective there is no difference between a revoked device and a host it cannot reach.

The device keeps what is owed, and the voice service's answer that it had no such call, in a file in the application's data directory, so a person who closes the application and opens it again is still told. When the application is opened again, the entries are read; an entry that has lapsed is not read. When the device reaches a host that it owes a revocation, it asks that host again, once for each call. If the host revokes the grant, the entry is settled. If the host replies with its own error code for an unknown session, which says it holds no call of this device by that name, the entry is settled too: a stop from this device can end nothing more there. This reply does not say that the grant is gone, and it says nothing of the fence the host owes its workers, which the host keeps to itself. The host gives it for a call that has ended, for a host that started again, whose record of the grant stands inert until the call's closing time, and for a call made under a pairing that was replaced. Any other reply, including a refusal or a failure to reply within the timeout interval, leaves the revocation owed until the grant lapses. A refusal does not say that the grant is gone, since the host also refuses before it looks at the call. If the system refuses to read the file, for example before the phone's first unlock, it is read again before it is next used rather than written over. If the file does not exist or has another layout, the device treats it as nothing kept; neither stops a call.

While the call is running, there is an entry in the file. When a phone's process ends in the middle of a call, the host ends nothing: the grant stays until the call's own closing time. That entry is written by the device before it sends the start, and represents a start the host never answered. When the host names the call, the entry is replaced with the revocation of the call's grant. While the call is running, the entry is in the file and not on the screen, and if the host is reached, the ongoing call will not be queried, because the call that runs is not one to stop. When the call ends, the entry is replaced with what the end owes, in one write, so that if the device fails in between, the record will not be lost. If the host answers the start with no call, a refusal or a decline, the entry is closed before native code is asked to stop.

To make sure a call is never left running with no owner, which would leave the microphone open, native code ends a call whose owner gives no sign of life: on both platforms, after 180 seconds while the call has not been permitted and 45 seconds once it has. The owner gives a sign every 10 seconds, and also while a step of the setup runs. Native code also ends a call whose connection has failed for good.

This version acts on nothing a person says. For each request the voice announces, the voice is told that nothing was done, and the screen shows the request as not done. The same words stand beside the list of what the grant permits, and before a start.

## The control socket

For each ongoing call, the device that holds the call's media will maintain an open WebSocket connection to the managed service. The relevant source code for the logic on the device side can be found in the shared client crate, in `crates/kr-client/src/services/voice_control.rs`. The device will open a `wss://` WebSocket at the control path that the call's creation answered. Plain `ws://` is permitted only for a development service on a loopback address, and no other address can be reached that way. The WebSocket will be opened with an upgrade header carrying a bearer token for the `voice` scope, taken from the account's token source on each connection attempt, so a reconnection presents whichever token the device holds at that moment. The service sends `ready` once the socket is open, and it has to name this call. Frames that come before it are ignored.

Heartbeats will be sent every 20 seconds whilst the WebSocket is open, and if nothing has been heard from the service for 45 seconds, the socket will be considered lost. If this happens, the device will open the connection again at once when the socket had served for 20 seconds or more, and after a wait that grows from half a second to 5 seconds when it had not or when an attempt failed, until 120 seconds have elapsed from the time the socket was lost - this is because the managed service will close a call after this period if the device has gone. If the socket is lost after a request was sent and before it was answered, that same request with the same identifier will be written again. If the service receives a request that repeats one it sent on to the provider (the same identifier, command, delegation and text length), it answers as it answered the first, without forwarding the request to the provider a second time, so the model hears the request once. A request the service accepted and has not yet admitted is written again in the same way, so the device hears the admission. A request is given up on once 120 seconds have passed since it was made (40 seconds for the closure), and is told whether it ever reached a socket. Some answers cannot be changed by trying again and will lead to the control closing immediately (a refused token, or a call the service does not have for this account), while a busy or slow service is tried again.

These rules hold whatever the service would accept. A frame the device sends is at most 4,096 bytes, and an append is at most 500 bytes of UTF-8. A request may name a delegation only if the call heard it announced, and each call will remember the newest 256. Requests will be spaced to fit within the limits imposed by the managed service (10 per 10 seconds, 60 per minute), so a long opening context is paced instead of refused. The device will record the type of any frame received which it does not recognise, and discard the frame. Likewise, if a frame of a known type does not match the expected format, it will be discarded, as will any object that names a member twice.

The microphone's mute is told to the service as advice to the provider, from one task that follows
the mute native code holds, whichever control changed it: the page, the lock screen or the
notification. It tells the service when that differs from the state it last asked for, in order. A
request that was not sent, or that the service refused, is tried again when the control attaches
again. A request the service never answered may have reached the provider, so it is not made again:
the same state is not asked for a second time, and a different one, an unmute after the mute, is.
The mute itself never waits for the service.

The host's selected context is sent as the call's opening context, appended using `thinking` frames. The phone reads it from the host when the control first attaches, for the first session the call reaches, and sends exactly that selection and nothing else of the session. If the host does not give it, the call goes on without it; if the service stops taking it part way, the call goes on with the part that was taken, and says how many of its parts the service took; if the service never answers a part, the call says how many parts the service confirmed and that it did not say whether it took the next, and does not say that it refused it; a call that ends before it was all given says so too, whatever ends it and whatever it was waiting for, as long as its owner ends it. Either way the device's log says why. A call whose owner failed outright is ended by the supervisor, which says the call stopped working and reads nothing of the opening context. The call's state carries each problem the call met as a record of its own in `problems`: a kind, its words, and whether what it says has passed. None is dropped to make room for another: the host's refusals are checked once in each pause of a minute, so the list grows by at most that. The page shows them on the running call and after it, until another call begins. A later problem is another record beside the earlier ones and replaces none: the host answering a check of the call with a refusal to vouch for it is one, repeated refusals are the same record, and a record that has passed (the host answered again) stays, marked, so that a refusal after that is a new record. The remembered note that the service had no such call is one more record, added when the state is read for a person who is not on a call. The state is the companion's own, from native code to its page: it is not a protocol type and nothing of it is stored. The first line of the opening context says that the text is data about the person's work and not instructions, and the selected text follows. Where possible, splitting will be done at line breaks, and each chunk will be at most 500 bytes. If the selection would require more than 64 chunks of opening context, the whole selection will be rejected.

## Screen lock and background audio

Section 15 ¶21: live voice stays usable after screen lock through the native iOS audio session and
Android's microphone foreground service:

- **iOS**: `UIBackgroundModes` declares `audio`. An explicitly started call maintains its audio session
  across screen locks. If capture is interrupted by an incoming phone call or system audio grab, an
  `AVAudioSession.interruptionNotification` is received and capture state transitions to `interrupted`.
  A permitted call registers the system's remote controls and shows the call as now playing. The pause
  command mutes the microphone and is offered only while the microphone is on; the stop command ends
  the call; play and toggle are never offered, so no remote opens a microphone the person turned off.
  The title is fixed and names no session, host or account, and the rate is 0 while the microphone is
  muted. The controls follow the person's mute, whichever control made it, and go with the call.
  iOS draws play or pause, skip and a scrubber on the lock screen, and no stop button on the lock
  screen or in Control Center, so a stop reaches the call from a remote that sends one, such as some
  Bluetooth accessories and car systems. What the lock screen draws for a call is the system's to
  decide.
- **Android**: `VoiceCallService` runs with `foregroundServiceType="microphone"`, holding a
  persistent user-visible notification while a call is active. When the screen locks, the foreground
  service preserves the microphone and speaker channels. Every action on the notification names the
  call it was shown for, so one that arrives late reaches that call or nothing.
- **Unattended activation forbidden**: building a call makes its offer with the recorder and the
  microphone track off, and opens no audio session and no foreground service. Nothing records until
  the host's answer to a start permits the call. That answer names the voice session and the moment
  the service closes it. On the phones one control, `VoiceCallControl`, then decides every step,
  and it is the only code that turns a recorder or a microphone on: it takes audio focus and the
  foreground service on Android, or the audio session on iOS, and a refusal of any of them ends the
  call; on Android nothing records until the service holds the foreground; and on both phones the
  microphone carries speech only once audio is arriving from it. Android takes that from its
  recorder's own start and stop, and iOS from the local source's count of audio taken in, read four
  times a second, which grows only while the microphone delivers; there the record vouches for time
  only up to the last reading that saw it grow, however capture ends and whatever the screen said
  while the stop was not yet noticed. The deadline is kept on the device's monotonic clock, read
  again after the platform's own steps so their time counts against it. The call ends at the
  deadline on its own thread rather than the main one. On the phones, anything that reaches the
  call's control after the deadline ends it at once: a change, a report from the recorder or the
  service, or a second permit, including for a call still waiting for its foreground service; on iOS
  a question asked of the call does too. On Android every frame after the deadline is refused as
  well; iOS checks no frames, so there the microphone keeps its state until the call's own queue
  runs the end or something reaches the call, and audio reported after the deadline is not counted
  as heard. A stopped call never reopens, and a second permit for the same call is refused.
- **One call at a time**: the audio belongs to one call. On iOS a second call is refused before its
  control can change the shared audio, and a change named for a call that does not hold the audio
  does nothing. A call let go of before it opened the audio leaves it free; one that has opened it is
  kept until it ends, and a call whose offer or answer fails ends. On Android the process claims one
  call at a time and refuses a second.

## Capture states and unheard speech

If capture is muted, interrupted, suspended, or unavailable, the interface displays the state
plainly, with the statement that **unheard speech never authorises an action** (KR-REQ-15.36):

- `capturing`: Microphone is on and carrying the person's voice.
- `muted_by_person`: The person pressed mute.
- `interrupted`: Another call or high-priority audio took the microphone.
- `route_changing`: Switching between speaker, receiver, or Bluetooth.
- `suspended_by_system`: The OS suspended capture.
- `unavailable`: No microphone hardware or permission is available, the recorder has not
  started or has failed, or (on Android) the system has not reported the call's own recording, so
  the call cannot tell its own recording from another application's.
- `idle`: No call has been permitted, the call has ended, or its deadline has passed.

On the phones, what a call displays and whether its microphone carries speech come from the same
gate, so the two cannot disagree. The gate keeps the recent intervals in which capture was on, and
answers for the past only: an instant later than the moment it is asked at, or older than the oldest
interval it kept, is treated as unheard. That record is what a claim that something was said would
be checked against (KR-ACC-014). A spoken delegation is checked against the gate's record of the
call, not against the news the call tells of it ([Spoken delegations](#spoken-delegations)).

Whenever capture is in any state other than `capturing`, the UI displays:
> "Nothing spoken while the microphone was not carrying your voice can authorise an action."

## Spoken delegations

This version hands no spoken delegation to the host. A delegation is announced twice, by the
provider on its data channel and by the voice service on the call's control socket; each one the
service announces is answered to the model by a fixed sentence that nothing was done, the screen
shows a row that says so, and the transcript and delegation events on the data channel are not read
at all. A constant in the call's owner holds this, and the code that would act otherwise is switched
on only by a setter compiled in test and debug builds. A release build compiles neither the setter
nor any caller of it.

Switched on, the call's owner decides each delegation itself, from the provider's data channel
alone. The voice service's announcement only has to agree with it, at the same identifier and the
same offset, and to be read within the wait after the delegation. The owner reads
`session.input_transcript.delta` (a fragment of what the caller said, with the interval of the
call's timeline it covers) and `session.delegation.created` (the delegation's identifier and
offset). Neither carries authority. The owner collects the fragments
for a wait after the delegation, asks native code for a capture proof that also puts a marker into
the call's news, reads the news up to that marker, and only then decides:

- **Taint.** What shows the device cannot know it read everything said since the call began ends
  the call's authority for good, and the person is told once: news that was lost; a required event
  that cannot be read as its schema states it; a fragment whose text is empty, over 512 bytes or
  holds a control character; a time that is not a whole number from 0 to a call's longest length
  (a fraction, a negative and a huge value pass the provider's schema); fragments that run
  backwards or overlap; a delegation whose offset is below an earlier one's; a fragment that
  arrives after the set it belongs to was read; a fragment that arrives before capture first
  opened; native code's own record of capture showing more than one opening or any break (a
  mute, an interruption, a route change, a suspension, a recorder gap or a silenced recording),
  which taints the call when the proof is read, without waiting for the news up to its marker, so
  that a request still waiting to be written is never written; an answer that turns discontinuous
  transmission on; and the provider's own acknowledgement of a mute after capture opened. A call
  that starts muted and whose provider acknowledges the mute after the microphone first opens is
  tainted by it for the rest of the call. So does a flow of more fragments than the gate keeps
  (4,096 within five minutes); a call that is tainted keeps none of what it hears.
- **The first fragment.** The device cannot hear what was said before capture first opened, and a
  person can say "do not" before it. A set that holds the first fragment the call delivered, or
  the first one that arrived after the opening, never authorises: the first thing a person says in
  a call never acts. The two are checked apart, each by when the fragment arrived against the
  first opening.
- **The set.** The fragments that start at or before the delegation's offset, no more than 30
  seconds before it, that no earlier set used, in the order they arrived; at most 16 fragments and
  2,048 bytes, otherwise the set is refused and never cut. A fragment outside the set that
  overlaps its span taints the call, and one that ends within 2 seconds before the set's first
  fragment refuses the set, since it may be the first half of the same instruction. The gate keeps
  what was said in the last five minutes; a delegation whose reach goes back to a fragment it
  forgot, which could be one of those, is refused as too old. A set that is refused is spent all
  the same: what it held answers no later delegation. So is a set that is dropped before it
  freezes, because the path to the host was lost, native code gave no proof or the news was not
  read up to the marker in time, and so is what arrives later at or before its offset.

The 30 seconds, the 2 seconds, the wait after a delegation, the 40 ms and 100 ms capture-gap
thresholds and the 500 ms age of a proof are parameters of the device's reading, not safety bounds,
and no rule here decides exactly what separates two instructions. These limits stand and no case
asserts them:

- A first fragment older than the 30 seconds, followed after a pause by a command, leaves a set
  that holds no first fragment: "do not ever", said as the call opens, does not stop "show me the
  status of session three" said a minute later.
- A fragment can arrive after the wait, so a later "no" can follow a read that was performed.
  Nothing on the device decides how long the provider takes to send a fragment.
- Loss below the capture gate's thresholds, silence supplied at the normal rate, an invented
  transcript, the model's own voice echoed and a bystander are outside what the device can see.
- On Android, another application that starts recording from the call's audio source after the
  device is on and before the system lists the call's own recording reads as the call's.

A request is composed once, as a whole, and kept: the host answers an exact repeat from its record
and refuses a request recomposed under a later action window as another request under the same
identifier. Before the request is written, a fresh capture proof is taken, and it is used only
while its age plus the time to the write is within the bound, and while the call can still hand a
request over. Both are checked once the connection holds the right to write and before every write
to the socket: a write that waits past the bound writes nothing, and a request the connection has
taken only part of when the bound runs out is cut off and the connection ends with it, so that the
host reads a request that stops short and acts on none of it. A request that was written and not
answered stays unknown, and is asked about again by repeat on another connection; when the host is
lost, a request not yet written is discarded and one that was is not known to have been carried
out. A call that ends with such a request open says so, and never says nothing was done. Neither
does the record that a call that may act leaves for the next launch, nor the end of a call whose
owner failed: neither can know what was written.

### A request that needs a confirmation on the unlocked screen

A close said aloud is the one request in the five classes that need an unlocked-screen confirmation
which the host's grammar reads. The host answers its first submission with a challenge, and the
same delegation then goes back under the same action with the person's signature on it.

The first request is settled when the host answers it, and kept whole. Before anybody is asked, the
owner compares the challenge with that request and with the call:

- the challenge is for the action the request carried, and for the delegation it named;
- the class of action it names is the one the host read the words to ask for;
- the host that issued it is the host the call belongs to, it is for this device, and it is for this
  voice session;
- the class is one the call's grant says still needs a confirmation on the unlocked screen;
- the session the host says the words named is one the call reaches;
- the digest it asks to be signed over is the digest of the plan the phone computes itself, from the
  delegation it sent and the action and session the host named.

A challenge that fails any of these is put to nobody, and the person is told it was not what was
said. A challenge that the phone's own clock says has run out is put to nobody either. The host's
clock decides whether a confirmation has run out; the phone's only stops it asking for, or signing,
what its own clock says is over, and the person is told so ("this phone's clock says the
confirmation ran out").

The person is asked through the platform's ceremony, which names the session by the number the host
gives it, and the host. The phone holds no name for a session outside the host's answer, so when
that answer does not come within the lookup's bound, or is a refusal, nobody is asked: the row
reads "session not named" and the model is told so. The dialog is put up only while the
confirmation is still open and the phone's clock does not say it has run out, and it stays for what
is left of it. While they are asked the call goes on, and anything
that taints it, or a loss of the path to the host, drops the confirmation at once, as does the end
of the call. What was handed over before a loss is not carried on after it: a challenge that
reaches the phone after the path to the host was lost is put to nobody, whether or not the host is
back by then.

After the ceremony the owner looks at taint and the phone's clock again, takes a capture proof with
a marker and reads the news up to the marker, so that anything said while the person was asked has
been read before anything is signed; then it looks at taint, the path to the host and the clock once
more. The task that reads the proof taken after the ceremony raises the call's taint flag when the
proof shows a break, before it tells the owner, and so does the task that reads the proof taken
just before the signed write. Every request waiting for the connection's turn looks at that flag,
which no reconnection clears, so none leaves before the owner has handled the message that tells
it.

The challenge is then signed with the device's own identity key, and the request goes out again
through the same hand-over as the first: composed once, after the first was settled, with the same
fragments, under the same action; a fresh capture proof just before the write, whose age is held to
through the write itself. The signed request is composed once and kept whole. When its answer is
lost it is asked about again with the request as it was composed, on another connection, and the
host answers from its record with the result; it is never sent again as new. A receipt in a result's
place is no decision: the row says it is not known, and nothing more is sent. A host that answers
the signed request with a challenge again has not taken the confirmation, and the person is not
asked a second time.

A person who does not confirm, and a phone with no ceremony to run, sign nothing and leave the call
as it was: the same request can be said again and is asked for again. A confirmation dropped for a
break, a late fragment, a lost host or a news queue not read in time is dropped with the cause the
row shows, and the call is tainted where the cause is one that taints.

### What voice may do

A person who already allowed voice has no other way to say that a spoken close is welcome, so the
idle voice screen offers "What voice may do" while a spoken request can reach the host at all. It
reads what the host says the standing grant permits and the sessions it covers, whichever session
the screen was opened for, shows the close in the protocol's own sentence (off unless the grant
already permits it), and changes only that: allowing sends the grant's other actions and its
sessions as they stand, with the close ticked or cleared, as a replacement grant. What is shown is
bound to the host it was read from. The change names that host's environment, and is not sent when
the grant has changed, or the application is connected to another host, by the time the person
presses; the command refuses it as well. The host's answer says what the
phone's own access could not carry and which sessions' workers have still to confirm the fence the
replacement owed, because a replacement ends the calls that ran under the grant it replaces. With
the constant off the entry is not offered.

## What a call's media has carried

Native code reads the connection's statistics and reports what the call's media has carried as an
optional `media` object in what it holds: the audio packets received, the audio packets sent, and the
samples the speaker side has taken to play. A figure the statistics did not hold is left out of the
object and is never sent as zero, so a count of none and a count that could not be read stay apart.
The object is read when the application asks what native code holds, and not at each sign of life,
because the read waits for the statistics. It is absent once the call has ended.

Native code tells the application once per call, with a `playout` news item, that audio was played out
of the device for the first time. A remote track being added is not that news: a track arrives before
any sound does. The observation is an estimate, and the application labels it so.

- On Android it is the first buffer handed to the speaker side with a sample above a floor of 128 (about
  48 decibels below full scale) while playback is on, unmuted and uninterrupted.
- On iOS the system hands the application no playout buffer, so it is the first reading of the
  connection's statistics in which the inbound audio energy and the playout sample count both grew,
  with playback on and the reading not spanning a change of that state. A missing or stale reading
  counts as none.

The application keeps `first_audio_ms` for the call: the milliseconds from the entry of the call's
start in the application to the application's receipt of the `playout` news, not to the observation
itself and not from the person's press. It is absent until the news comes and for a call that never
plays any sound, it is serialised only when set, and the screen does not draw it. It is a figure for
device runs and has no target here.

## Context requests and admission

`VoiceContextFrame::new` (`crates/kr-client/src/services/voice.rs`) refuses an append over
`VOICE_CONTEXT_BYTES` (500) rather than truncating it. The control client
above builds every context request, and the task that owns the call opens the control socket.
Reading what the host selected for a call is a read from the host, and the
screen shows it as the host's selection.

A delegation the host admits without performing it is shown as **admission**, never as execution
(KR-REQ-15.17), with the host's note that admission is not evidence anything ran. Host action
receipts remain the sole authority for what ran on a host.

## Local survival when the broker fails

Muting the microphone, silencing the model's voice ("Stop the voice") and hanging up a call are
local operations of the call's own native media pipeline, and they depend on neither the broker nor
the network. A hang-up stops the media and has the host revoke the call's grant at once, and neither
waits for the voice service.

The call's own report about its control channel is the only source of whether the voice service is
answering. It is `connecting` while the control opens its first socket, `connected` while it holds
one, and `unreachable` from the first attempt that fails, or from the loss of a socket it served,
until a socket is held again. The control tells each outage once, not each attempt, and a call
whose control stays unreachable for 120 seconds ends. It is `none` when the call holds no control.
When a call reports the service unreachable, the screen says so, and muting the microphone,
silencing the voice and ending the session stay available, as do the requests that go to the host.

## Speech interruption vs task cancellation

Section 15 ¶13: speech interruption stops playback, not a coding task.
The call controls keep them strictly separated:
- **Stop the voice**: silences the speaker locally. It contacts no host and cancels no task.
- **Cancel the current turn**: sends a typed cancellation to the host, after a deliberate
  confirmation step ("Cancel this turn"). The request names the session, the application instance
  running its agent, the binding revision and the turn ID.

The screen reads the instance, the revision and the turn from the session's worker while a call
runs: first the session's live instance, then that instance's binding and capabilities
(`agent.capabilities`). It reads again on the agent's cadence, when the host is reached again, and
after each cancellation. The control is offered on the rule the composer offers its interrupt by:
the agent is on a turn, the binding is one the host verified, the agent's cancel capability is
usable now, and this device holds the right. Whenever the control is off, the screen says why: the
agent is on no turn, the session has no live instance, the read failed, or, for a turn the agent is
on, which of the last three does not hold. Before the first read has answered it says that it has
not yet read the turn. A call that reaches more than one session names no turn, and the screen says
so rather than pick one.

The confirmation keeps the turn and revision it was opened on. The question is discarded, and has
to be asked again, when a read shows another turn, revision or instance, or no turn, when a read
fails, and when the offer is taken back: the binding is no longer verified, the cancel capability
is no longer usable, or the connection no longer says this device holds the right, as when contact
with the host is lost. When the host moved on before the screen read it, the request still names
what the person was shown. The host refuses it, and the screen shows the host's words. The screen
never reads the turn at the moment a person confirms.

The screen tells the host's answer as it came. A cancellation the host took reads as asked. A
refusal shows what the host said. An answer that carries no receipt and no result reads as not
known: the screen does not say whether the turn was cancelled. The answer is told only while the
call it was asked on is still on screen, and the same holds for the reply to a read of what the host
selected.

## Device runs

`scripts/e2e-voice-call-device.sh <ios|android> [native-failure|outage]` runs a whole call on a
simulator or an emulator, with the real application, the real platform plugin and a real host. The
voice service is a stand-in on the machine's loopback interface, and the script is run inside the
machine's device lease. The result is exit 0 when every check passed, 2 when one failed,
3 when the device is not available, and 4 when every check that measured passed and some check could
not measure what it asks about; the run names those checks. A check that could not measure is neither
a pass nor a failure of what it asks about.

In the default mode, `native-failure`, the stand-in's answer leads nowhere. The connection fails after
about half a minute, native code ends the call, and the checks read the end: the media stopped on the
device, the host revoked the grant, and the voice service was told the call is over.

In the `outage` mode the call has a peer. A debug build starts a peer inside the application when
`kr-probe/peer.json` names a loopback port and a token, and a release build has no peer and reads no
file. The stand-in asks the peer for the answer to each offer, so the call connects and carries audio.
The peer is a second WebRTC factory whose audio device makes a tone for its microphone and counts what
it is played, and it opens neither the audio session nor a microphone of the machine. It is a full ICE
agent that answers with the provider's marks, not an ICE-lite one, and it is not the provider, so the
run shows that the call connects to such an answer and carries audio, and not that the provider's own
answer does.

The checks judge audio by counters crossing a floor, never by elapsed time: about a second of audio
packets in each direction, and a fifth of a second of samples played. A direction that nothing
counted, or that stayed under its floor with no microphone to send from, is reported as not measured.
The packets the call sent are counted whatever its microphone delivered, silence included, so they say
nothing of speech; the call's capture word says whether speech could have been heard. The script
grants the application the simulator's microphone permission and nothing on the machine, and it does
not isolate the Simulator's input route. When the application has read its figure of the first audio,
the script takes the voice service away. The checks then expect the control to read
`unreachable`, the microphone's mute and the speaker's silence to work with the media still
connected, a stop to return without waiting for the service, the media to stop on the device, the host
to revoke the grant, and the service's closure to be reported as not confirmed. On iOS the machine also
reads the system's lock-screen state through the peer while the call is held and after it ends.

The checks that need a person on a real phone are in [phone-checks.md](phone-checks.md).

The emulator starts with `-audio none` in this mode unless `KR_EMULATOR_AUDIO_ARGS` says otherwise;
the default mode starts it with `-no-audio`, and a call there reads its capture as `unavailable`. The
input driver should be `none` wherever it works, so that no microphone of the machine is opened. The
script turns the emulator's mobile data off, so that only Wi-Fi carries the run;
`KR_EMULATOR_MOBILE_DATA=on` leaves it as the emulator starts it.

## Unlocked-screen ceremony

Actions requiring unlocked-screen confirmation (session closure, grant changes, arbitrary shell input,
diff application, and external delivery) require a client-signed confirmation over the action hash.
The platform asks the person, and the shared client library signs:
- **iOS**: `LocalAuthentication` (`evaluatePolicy(.deviceOwnerAuthentication)`) asks the person.
- **Android**: `BiometricPrompt` asks the person. From Android 11 it accepts a strong
  biometric or the device credential; before it, a strong biometric only, on a device with a secure
  lock screen, because the older way to allow the credential also admits weak biometrics.
- The client library (`kr-client`) signs the host's challenge with the paired device's identity key
  once the person has confirmed, on every platform, so there is one signing code and one set of
  vectors.
- A phone that cannot verify the owner's presence refuses the confirmation rather than falsely
  answering "verified".
- The signature binds the exact action hash and request ID with the paired device's identity key,
  never a session key. Provider text or model claims cannot produce a valid confirmation.

The desktop application holds no such ceremony. A challenge the host sends it is shown with the
host's words and the fact that the screen cannot sign it, and the host does not act on it.
