//
//  The call on the lock screen, and in the system's other remote controls.
//
//  A call the person started keeps running with the screen locked (section 15 paragraph 21), and a
//  person who cannot unlock the phone can still silence their microphone from the lock screen or
//  end the call from a headset or a car. The system's header has no mute command:
//  `pauseCommand` is the one that carries it here. Nothing a remote sends ever opens the
//  microphone: `playCommand` and `togglePlayPauseCommand` are never offered, so a stray tap, a
//  headset button or a voice assistant cannot turn on a microphone the person turned off.
//
//  iOS draws play or pause, skip and a scrubber on the lock screen and no stop button, and none in
//  Control Center, so `stopCommand` is what a remote that sends stop reaches, such as some Bluetooth
//  accessories and car systems. What the lock screen draws for a call is the system's to decide.
//
//  The call owns one of these. It is begun when the host's answer permits the call, follows the
//  person's mute, and ends with the call. Everything runs on the call's own queue, and a command the
//  system sends on another thread is moved there before it is looked at.
//

import Foundation
import MediaPlayer

/// A command the system delivers from a remote control.
public enum RemoteCommand: Equatable, Sendable {
    case pause
    case play
    case togglePlayPause
    case stop
}

/// What the lock screen shows of the call. It names no session, host or account.
public struct NowPlaying: Equatable, Sendable {
    public let title: String
    /// 1 while the microphone is on, 0 while the person has muted it.
    public let playbackRate: Double

    public init(title: String, playbackRate: Double) {
        self.title = title
        self.playbackRate = playbackRate
    }
}

/// The system's remote controls and its now playing information, as the call uses them.
public protocol RemoteControlSurface: AnyObject {
    /// Makes the pause and stop commands live and sends each command the system delivers to
    /// `handler`, which may be called on any thread. Pause is offered only once `present` says so.
    /// Nothing else is offered.
    func install(_ handler: @escaping (RemoteCommand) -> Void)
    /// Sets whether the pause command is offered and what is playing (`info`, or nothing) as one
    /// change: no reading of the surface finds one of them changed and the other not.
    func present(pauseOffered: Bool, info: NowPlaying?)
    /// Takes every handler away and offers no command.
    func remove()
}

/// The system's own centres.
public final class SystemRemoteControls: RemoteControlSurface {
    /// The centres are one thing for the whole process. Each surface takes a serial when it is made,
    /// in the order the calls are made, and the newest surface that has registered holds them. A
    /// registration by an older surface than that is late and is refused, and an older one that
    /// comes to take its call away late turns off and clears nothing of the newer one's. Held
    /// across each change and each reading, so that none is made on a surface that has just lost
    /// the centres and none is read half made.
    private static let centres = NSLock()
    private static var issued: UInt64 = 0
    private static var newest: UInt64 = 0
    private static var holder: UInt64?

    private let serial: UInt64
    private let lock = NSLock()
    private var tokens: [(command: MPRemoteCommand, token: Any)] = []

    public init() {
        Self.centres.lock()
        defer { Self.centres.unlock() }
        Self.issued &+= 1
        serial = Self.issued
    }

    public func install(_ handler: @escaping (RemoteCommand) -> Void) {
        Self.centres.lock()
        defer { Self.centres.unlock() }
        guard serial >= Self.newest else { return }
        Self.newest = serial
        Self.holder = serial
        let center = MPRemoteCommandCenter.shared()
        // Offered by none of them, whatever else the application or the system does with them.
        center.playCommand.isEnabled = false
        center.togglePlayPauseCommand.isEnabled = false
        center.pauseCommand.isEnabled = false
        center.stopCommand.isEnabled = true
        let pause = center.pauseCommand.addTarget { _ in
            handler(.pause)
            return .success
        }
        let stop = center.stopCommand.addTarget { _ in
            handler(.stop)
            return .success
        }
        lock.lock()
        tokens += [(center.pauseCommand, pause), (center.stopCommand, stop)]
        lock.unlock()
    }

    public func present(pauseOffered: Bool, info: NowPlaying?) {
        Self.centres.lock()
        defer { Self.centres.unlock() }
        guard Self.holder == serial else { return }
        MPRemoteCommandCenter.shared().pauseCommand.isEnabled = pauseOffered
        let center = MPNowPlayingInfoCenter.default()
        guard let info else {
            center.nowPlayingInfo = nil
            center.playbackState = .stopped
            return
        }
        center.nowPlayingInfo = [
            MPMediaItemPropertyTitle: info.title,
            MPNowPlayingInfoPropertyPlaybackRate: info.playbackRate,
            MPNowPlayingInfoPropertyDefaultPlaybackRate: 1.0,
        ]
        center.playbackState = info.playbackRate == 0 ? .paused : .playing
    }

    public func remove() {
        Self.centres.lock()
        defer { Self.centres.unlock() }
        lock.lock()
        let held = tokens
        tokens = []
        lock.unlock()
        for (command, token) in held { command.removeTarget(token) }
        guard Self.holder == serial else { return }
        Self.holder = nil
        let center = MPRemoteCommandCenter.shared()
        center.pauseCommand.isEnabled = false
        center.stopCommand.isEnabled = false
        center.playCommand.isEnabled = false
        center.togglePlayPauseCommand.isEnabled = false
    }

    /// What the system's centres hold now, for a run on a simulator that reads them.
    public static func reading() -> LockScreenReading {
        centres.lock()
        defer { centres.unlock() }
        let remote = MPRemoteCommandCenter.shared()
        let playing = MPNowPlayingInfoCenter.default().nowPlayingInfo
        return LockScreenReading(
            pauseOffered: remote.pauseCommand.isEnabled,
            stopOffered: remote.stopCommand.isEnabled,
            playOffered: remote.playCommand.isEnabled,
            toggleOffered: remote.togglePlayPauseCommand.isEnabled,
            title: playing?[MPMediaItemPropertyTitle] as? String,
            rate: (playing?[MPNowPlayingInfoPropertyPlaybackRate] as? NSNumber)?.doubleValue
        )
    }
}

/// The lock screen as the system holds it, read back.
public struct LockScreenReading: Equatable, Sendable {
    public let pauseOffered: Bool
    public let stopOffered: Bool
    public let playOffered: Bool
    public let toggleOffered: Bool
    public let title: String?
    public let rate: Double?
}

/// A call's hold on the remote controls, from its permit to its end.
public final class LockScreenControls: @unchecked Sendable {
    /// What the lock screen is told the call is called. Fixed: no session, host or account.
    public static let title = "Kala Reach voice call"

    private let surface: RemoteControlSurface
    private let queue: DispatchQueue
    private let muteMicrophone: () -> Void
    private let endCall: () -> Void
    // Touched on `queue` only.
    private var shown = false
    private var generation: UInt64 = 0
    private var mutedByPerson = false

    /// - Parameters:
    ///   - queue: the call's own queue; every change and every command runs on it.
    ///   - mute: mutes the person's microphone. It is the only thing a remote can do to it.
    ///   - stop: ends the call.
    public init(
        surface: RemoteControlSurface,
        queue: DispatchQueue,
        mute: @escaping () -> Void,
        stop: @escaping () -> Void
    ) {
        self.surface = surface
        self.queue = queue
        muteMicrophone = mute
        endCall = stop
    }

    /// The call was permitted: registers the commands and shows the call. `stillActive` is asked
    /// on the queue, when the registration would happen, so a call that ended meanwhile registers
    /// nothing.
    public func begin(mutedByPerson muted: Bool, stillActive: @escaping () -> Bool) {
        queue.async { [self] in
            guard !shown, stillActive() else { return }
            shown = true
            generation &+= 1
            mutedByPerson = muted
            let mine = generation
            surface.install { [weak self] command in
                guard let self else { return }
                self.queue.async { self.received(command, generation: mine) }
            }
            present()
        }
    }

    /// The person's mute changed, from whatever control: pause is offered while the microphone is
    /// on and not while it is muted, and the rate follows.
    public func follow(mutedByPerson muted: Bool) {
        queue.async { [self] in
            guard shown, muted != mutedByPerson else { return }
            mutedByPerson = muted
            present()
        }
    }

    /// The call ended: takes the commands away and shows nothing.
    public func end() {
        queue.async { [self] in
            guard shown else { return }
            shown = false
            generation &+= 1
            // What is shown goes first: taking the commands away ends this surface's hold of the
            // system's centres, after which it may change nothing there.
            surface.present(pauseOffered: false, info: nil)
            surface.remove()
        }
    }

    private func present() {
        surface.present(
            pauseOffered: !mutedByPerson,
            info: NowPlaying(title: Self.title, playbackRate: mutedByPerson ? 0 : 1)
        )
    }

    private func received(_ command: RemoteCommand, generation sent: UInt64) {
        // A command registered for a call that has ended, or for an earlier hold, is not this one's.
        guard shown, sent == generation else { return }
        switch command {
        case .pause:
            if !mutedByPerson { muteMicrophone() }
        case .stop:
            endCall()
        case .play, .togglePlayPause:
            // Never offered, and never an unmute if one arrives.
            break
        }
    }
}
