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
