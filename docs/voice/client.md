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

The record keeps apart what the host did and what happened on the device. The host revoked the grant, or it refused the stop, which does not say whether the grant is gone, or it was not told or did not answer in time. In the last two cases the revocation is owed. The words that say what happened are in the past tense. Whether the grant may still be open is said by what is owed, which lapses with the grant. Whatever is owed names the host it is owed to. It stays on the screen until the moment the grant ends by itself, with room for a clock that is not the device's own, along with a start that was never answered, which the device keeps under the action it was sent under, and the next call does not clear it. An unknown start is kept until the end of the action window it was sent under, on the host's own clock, plus the length of call it asked for and the clock allowance, because a call the host made for it cannot run past that moment. Nothing that has not run out is dropped to make room for a newer entry. Once the call has ended, the screen goes on reading until the voice service has said whether it closed the call. A new start replaces the record of the call before it, so a person who starts again before the service has said does not see what it says of the earlier call. A call is bound to the host that made it, so a stop goes over a connection to that host. When a host revokes the device, the host ends what the device holds, because a phone cannot tell a revoked device from a host it cannot reach.

What is owed, and the voice service's answer that it had no such call, are kept in a file in the application's data directory, so a person who closes the application and opens it again is still told. An entry that has lapsed is not read. When the device reaches a host that it owes a revocation, it asks that host again. If the host revokes the grant, the entry is settled. Any other answer, a refusal included, or none, leaves it owed until the grant ends by itself, because a refusal does not say that the grant is gone: the host also refuses before it looks at the call. A file that cannot be read counts as nothing kept, and it never stops a call.

To make sure a call is never left running with no owner, which would leave the microphone open, native code ends a call whose owner gives no sign of life: on both platforms, after 180 seconds while the call has not been permitted and 45 seconds once it has. The owner gives a sign every 10 seconds, and also while a step of the setup runs. Native code also ends a call whose connection has failed for good.

This version acts on nothing a person says. For each request the voice announces, the voice is told that nothing was done, and the screen shows the request as not done. The same words stand beside the list of what the grant permits, and before a start.

## The control socket

For each ongoing call, the device that holds the call's media will maintain an open WebSocket connection to the managed service. The relevant source code for the logic on the device side can be found in the shared client crate, in `crates/kr-client/src/services/voice_control.rs`. The device will open a `wss://` WebSocket at the control path that the call's creation answered. Plain `ws://` is permitted only for a development service on a loopback address, and no other address can be reached that way. The WebSocket will be opened with an upgrade header carrying a bearer token for the `voice` scope, taken from the account's token source on each connection attempt, so a reconnection presents whichever token the device holds at that moment. The service sends `ready` once the socket is open, and it has to name this call. Frames that come before it are ignored.

Heartbeats will be sent every 20 seconds whilst the WebSocket is open, and if nothing has been heard from the service for 45 seconds, the socket will be considered lost. If this happens, the device will open the connection again at once when the socket had served for 20 seconds or more, and after a wait that grows from half a second to 5 seconds when it had not or when an attempt failed, until 120 seconds have elapsed from the time the socket was lost - this is because the managed service will close a call after this period if the device has gone. If the socket is lost after a request was sent and before it was answered, that same request with the same identifier will be written again. If the service receives a request that repeats one it sent on to the provider (the same identifier, command, delegation and text length), it answers as it answered the first, without forwarding the request to the provider a second time, so the model hears the request once. A request the service accepted and has not yet admitted is written again in the same way, so the device hears the admission. A request is given up on once 120 seconds have passed since it was made (40 seconds for the closure), and is told whether it ever reached a socket. Some answers cannot be changed by trying again and will lead to the control closing immediately (a refused token, or a call the service does not have for this account), while a busy or slow service is tried again.

These rules hold whatever the service would accept. A frame the device sends is at most 4,096 bytes, and an append is at most 500 bytes of UTF-8. A request may name a delegation only if the call heard it announced, and each call will remember the newest 256. Requests will be spaced to fit within the limits imposed by the managed service (10 per 10 seconds, 60 per minute), so a long opening context is paced instead of refused. The device will record the type of any frame received which it does not recognise, and discard the frame. Likewise, if a frame of a known type does not match the expected format, it will be discarded, as will any object that names a member twice.

The host's selected context is sent as the call's opening context, appended using `thinking` frames. The first line of the opening context says that the text is data about the person's work and not instructions, and the selected text follows. Where possible, splitting will be done at line breaks, and each chunk will be at most 500 bytes. If the selection would require more than 64 chunks of opening context, the whole selection will be rejected.

## Screen lock and background audio

Section 15 ¶21: live voice stays usable after screen lock through the native iOS audio session and
Android's microphone foreground service:

- **iOS**: `UIBackgroundModes` declares `audio`. An explicitly started call maintains its audio session
  across screen locks. If capture is interrupted by an incoming phone call or system audio grab, an
  `AVAudioSession.interruptionNotification` is received and capture state transitions to `interrupted`.
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
- `unavailable`: No microphone hardware or permission is available, or the recorder has not
  started or has failed.
- `idle`: No call has been permitted, the call has ended, or its deadline has passed.

On the phones, what a call displays and whether its microphone carries speech come from the same
gate, so the two cannot disagree. The gate keeps the recent intervals in which capture was on, and
answers for the past only: an instant later than the moment it is asked at, or older than the oldest
interval it kept, is treated as unheard. That record is what a claim that something was said would
be checked against (KR-ACC-014). The screen does not check a delegation against it: delegations
reach the screen from the host, not from the provider's channel.

Whenever capture is in any state other than `capturing`, the UI displays:
> "Nothing spoken while the microphone was not carrying your voice can authorise an action."

## Context requests and admission

`VoiceContextFrame::new` (`crates/kr-client/src/services/voice.rs`) refuses an append over
`VOICE_CONTEXT_BYTES` (500) rather than truncating it. The control client
above builds every context request, and the companion application's own process does not yet
open a control socket. Reading what the host selected for a call is a read from the host, and the
screen shows it as the host's selection.

A delegation the host admits without performing it is shown as **admission**, never as execution
(KR-REQ-15.17), with the host's note that admission is not evidence anything ran. Host action
receipts remain the sole authority for what ran on a host.

## Local survival when the broker fails

Muting the microphone, silencing the model's voice ("Stop the voice") and hanging up a call are
local operations of the call's own native media pipeline, and they depend on neither the broker nor
the network. The companion application's own process holds no call: its mute commands refuse with
"this device is not holding a voice call", and its stop command asks the host and reports that
nothing was closed locally.

The call's own report about its control channel (`none`, `connected` or `unreachable`) is the only
source of whether the voice service is answering, and this application reports `none`. When a call
reports the service unreachable, the screen says so, and muting the microphone, silencing the voice
and ending the session stay available, as do the requests that go to the host.

## Speech interruption vs task cancellation

Section 15 ¶13: speech interruption stops playback, not a coding task.
The call controls keep them strictly separated:
- **Stop the voice**: silences the speaker locally. It contacts no host and cancels no task.
- **Cancel the current turn**: sends a typed cancellation naming the current session and turn ID to
  the host, after a deliberate confirmation step ("Cancel this turn"). It needs the turn the agent
  is on from the host; while no host answer names one, the control stays off and the screen says
  why.

## Unlocked-screen ceremony

Actions requiring unlocked-screen confirmation (session closure, grant changes, arbitrary shell input,
diff application, and external delivery) require a client-signed confirmation over the action hash:
- **iOS**: `LocalAuthentication` (`evaluatePolicy(.deviceOwnerAuthentication)`), followed by CryptoKit Ed25519 signing.
- **Android**: `BiometricPrompt`, followed by Ed25519 signing. From Android 11 it accepts a strong
  biometric or the device credential; before it, a strong biometric only, on a device with a secure
  lock screen, because the older way to allow the credential also admits weak biometrics.
- A phone that cannot verify the owner's presence refuses the confirmation rather than falsely
  answering "verified".
- The signature binds the exact action hash and request ID with the paired device's identity key,
  never a session key. Provider text or model claims cannot produce a valid confirmation.

The desktop application holds no such ceremony. The voice screen has no way to reach these
ceremonies. A challenge the host sends it is shown with the host's words and the fact that the
screen cannot sign it, and the host does not act on it.
