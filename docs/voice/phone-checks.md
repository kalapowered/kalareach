# Checking a voice call on a phone

This page contains the instructions for things you have to do on the phone. Four things need a person: what the lock screen shows, whether audio keeps going after the screen locks, how the call behaves with no network, and the provider choice screen before a call. No script reaches them. The device script, `scripts/e2e-voice-call-device.sh`, covers the rest on a simulator or an emulator. A call on your own phone goes to the managed voice service, which charges for each second, so run these steps when you mean to.

## Before you start

Pair the phone to the host and allow voice for one session.

## Read the provider choice screen

Open the voice screen for the session, and before you press the start button take a screenshot of the provider choice screen. It should show the voice model, the service that carries the call, the managed content access in the service's own words, the classes the call would carry and the classes it would leave out, the host's cap on selected context, and the rate above the start control. Keep the screenshot. It is the evidence for KR-REQ-15.09 and KR-REQ-15.19.

## Lock the screen during a call

Press the start button, say something, wait for the voice model to respond, and then lock your phone. Continue the conversation, and check that it is ongoing. When you unlock your phone, the call should still be going on the call screen.

On an iPhone, the lock screen shows the call as the current now playing, with a pause button. Pause mutes your microphone, and the call screen then shows the microphone as muted. Nothing on the lock screen turns the microphone back on: if iOS draws a play button while the microphone is muted, it does nothing. iOS draws no stop button, so you end the call from the call screen. A headset or car system that sends a stop command ends it.

On an Android phone, the call notification provides the ability to mute and unmute your end of the microphone.

## Mute and hang up with no network

Start a call, then put the phone in airplane mode. The call screen will tell you that the voice service is no longer reachable, and possibly that the host is no longer reachable. Mute the microphone and silence the voice. Both take effect at once, and neither waits for a service. Then end the session, and the phone will stop the media immediately. If the host cannot be reached, the screen says the revocation is still owed to the host, and the notice stays until the call's own limit has passed. Turn airplane mode off again and check that the host revokes the grant.

## End a call with the network on

End the session while the network is on. The screen reports separately what the phone did, what the host did and what the voice service did. The service's part reads closed, or not confirmed when the service did not say.

## Read the first-audio figure

A release build on your phone shows no figure for the first audio. To read one, run `scripts/e2e-voice-call-device.sh ios outage` or `scripts/e2e-voice-call-device.sh android outage` on a Mac. It writes `kr-voice-first-audio.md` beside the other evidence. The figure is an estimate from a stand-in voice service. It is not what the managed service delivers to you.

## Play the spoken-request legs on a simulator or an emulator

A shipped build never hands a spoken request to your computer: the voice model hears that nothing was done, and the host is sent nothing. In a debug build you can switch the check on for a single call, so you can watch it decide without saying a word. To do this from your Mac, run `scripts/e2e-voice-call-device.sh ios delegating` or `scripts/e2e-voice-call-device.sh android delegating` while inside the device lease. This plays nine calls in sequence. Each call does a fresh installation and starts a new host that holds one real session. Name one leg after `delegating` to play only that call: `production`, `positive`, `first_utterance`, `mute`, `gap`, `dtx`, `malformed`, `late_fragment` or `broker_disagrees`.

In the `production` leg the check is switched off, so you see the same behaviour as the shipped application. In the other eight legs the check is on. The first thing said in a call never acts. In the `first_utterance` leg a status is said first and the phone refuses it, and most of the other legs begin with one throwaway sentence that the phone refuses for the same reason. In the `positive` leg a status is said next, and the host performs it. In the remaining legs one thing goes wrong: a mute and an unmute in the middle of a command, a gap in the recorder, an answer that turns on discontinuous transmission, a message on the data channel that is not an event, a fragment that arrives after its request was read, or a voice service that does not announce the delegation the provider did. In each of these cases the phone refuses the command and names the cause, and the host is sent nothing more. Each leg is read beside a request the host performed when nothing was wrong, in the same call or, for `dtx`, in the `positive` leg. A leg whose recorder broke by itself before the leg's own subject began is played again on a new call, up to three times, and the earlier attempts stay beside the result.

The legs show what the application does with the check on. They do not show what a phone's system does to a recording. Since the simulator has no recorder, its call records a tone from a synthetic device that opens no microphone of your Mac, and the emulator records silence. The Android rule for a recording the system silences, a phone call, Siri and a Bluetooth headset all need a real phone. A shipped build still answers that nothing was done, and this run does not change that.
