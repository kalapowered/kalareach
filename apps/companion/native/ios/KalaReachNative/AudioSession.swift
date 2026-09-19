//
//  The audio session, configured where the platform expects it to be.
//
//  An audio session belongs to the process, not to a page: it survives the interface being
//  suspended, and it is what decides whether recording continues when the screen locks. Setting it
//  from native code is what makes that true; setting it from a page would mean it is configured
//  only while the page is running, which is the opposite of what is wanted.
//
//  What uses the session is the voice surface, which is built elsewhere. This is the session
//  itself, and it is deliberately the smallest thing that can be correct.
//

import AVFoundation

/// Configures and releases this application's audio session.
struct AudioSession {
    /// Makes the session ready for recording and playback over whatever route is attached.
    ///
    /// `.mixWithOthers` is deliberate: an application that stops a person's music the moment it
    /// starts is an application that takes something it was not given.
    static func activate() throws {
        let session = AVAudioSession.sharedInstance()
        try session.setCategory(
            .playAndRecord,
            mode: .spokenAudio,
            options: [.allowBluetooth, .defaultToSpeaker, .mixWithOthers]
        )
        try session.setActive(true, options: [])
    }

    /// Gives the session back, and tells whatever was interrupted that it may resume.
    static func deactivate() throws {
        try AVAudioSession.sharedInstance().setActive(
            false,
            options: [.notifyOthersOnDeactivation]
        )
    }
}
