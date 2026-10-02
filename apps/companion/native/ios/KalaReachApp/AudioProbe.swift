//
//  The audio check a debug build can be started to run on a device.
//
//  It opens the application's audio session the way a call does, through the product's own
//  `AudioSession`, claims the process's audio first, runs an engine of its own on it, and reports
//  what the system did. The engine plays silence and listens, and drops everything it hears: the
//  input tap records only that it ran, and nothing of what the microphone carried is kept or looked
//  at. What the check answers is whether the session opens, what the microphone's state is, whether
//  input and output keep running second after second, what a locked phone does to them, and what a
//  change of route does. Compiled into debug builds only.
//

#if DEBUG
import AVFoundation
import Foundation
import UIKit

/// The call object the audio session tells about interruptions and route changes, and records them.
private final class ProbeCall: AudioSessionEvents {
    private let lock = NSLock()
    private var began = 0
    private var ended = 0
    private var routeEvents = 0
    private var resets = 0
    private var recorderStops = 0

    func audioSessionInterruption(began: Bool, mayResume: Bool) {
        lock.lock(); defer { lock.unlock() }
        if began { self.began += 1 } else { ended += 1 }
    }

    func audioSessionRoute(changing: Bool, hasInput: Bool) {
        lock.lock(); defer { lock.unlock() }
        if changing { routeEvents += 1 }
    }

    func audioSessionReset() {
        lock.lock(); defer { lock.unlock() }
        resets += 1
    }

    func audioSessionRecorderStopped() {
        lock.lock(); defer { lock.unlock() }
        recorderStops += 1
    }

    var facts: [String: String] {
        lock.lock(); defer { lock.unlock() }
        return [
            "interruptions.began": String(began),
            "interruptions.ended": String(ended),
            "route.product.events": String(routeEvents),
            "reset": String(resets),
        ]
    }
}

/// When the check's input and output ran, written on the audio threads and read on the main one.
private final class RunClock {
    private let lock = NSLock()
    private var input = CallbackClock()
    private var output = CallbackClock()

    func inputRan() { lock.lock(); input.ran(at: ProcessInfo.processInfo.systemUptime); lock.unlock() }
    func outputRan() { lock.lock(); output.ran(at: ProcessInfo.processInfo.systemUptime); lock.unlock() }

    /// What each stream did since the last reading.
    func reading() -> (lastInput: TimeInterval?, lastOutput: TimeInterval?, longestInput: TimeInterval?, longestOutput: TimeInterval?, inputCount: Int, outputCount: Int) {
        lock.lock(); defer { lock.unlock() }
        return (input.last, output.last, input.longestIntervalSinceLastReading(), output.longestIntervalSinceLastReading(), input.count, output.count)
    }

    var counts: (input: Int, output: Int) {
        lock.lock(); defer { lock.unlock() }
        return (input.count, output.count)
    }
}

enum AudioProbe {
    private static let call = ProbeCall()
    private static let clock = RunClock()
    private static let engine = AVAudioEngine()
    private static var timer: DispatchSourceTimer?
    private static var log = AudioTickLog(start: 0)
    private static var facts: [String: String] = [:]
    private static var routeNotifications = 0
    private static var moves = 0
    private static var trail: [String] = []
    private static var stopped = false

    /// Starts the check, which runs until the test stops it or the process ends.
    static func start(show: @escaping ([String: String]) -> Void) {
        facts = [:]
        guard AudioSession.shared.claim(call) else {
            facts["error"] = "claim refused"
            show(facts)
            return
        }
        // The permission first. A person's answer is the system's, and the product's session reads it.
        AVAudioApplication.requestRecordPermission { granted in
            DispatchQueue.main.async {
                facts["permission"] = granted ? "granted" : "denied"
                guard granted else {
                    // A refusal is the product's own: the session says so, and the microphone's state
                    // says it is unavailable.
                    do {
                        try AudioSession.shared.activate(for: call)
                        facts["activated"] = "1"
                    } catch {
                        facts["activated"] = "0"
                        facts["error"] = "\(error)"
                    }
                    facts["capture"] = "\(AudioSession.shared.capture)"
                    AudioSession.shared.release(call)
                    show(facts)
                    return
                }
                begin(show: show)
            }
        }
    }

    private static func begin(show: @escaping ([String: String]) -> Void) {
        do {
            try AudioSession.shared.activate(for: call)
            facts["activated"] = "1"
        } catch {
            facts["activated"] = "0"
            facts["error"] = "\(error)"
            facts["capture"] = "\(AudioSession.shared.capture)"
            AudioSession.shared.release(call)
            show(facts)
            return
        }

        // Silence out, and a tap in that only notes that it ran.
        let source = AVAudioSourceNode { _, _, _, buffers -> OSStatus in
            for buffer in UnsafeMutableAudioBufferListPointer(buffers) {
                if let data = buffer.mData { memset(data, 0, Int(buffer.mDataByteSize)) }
            }
            clock.outputRan()
            return noErr
        }
        engine.attach(source)
        engine.connect(source, to: engine.mainMixerNode, format: nil)
        let input = engine.inputNode
        input.installTap(onBus: 0, bufferSize: 1024, format: input.outputFormat(forBus: 0)) { _, _ in
            clock.inputRan()
        }
        do {
            try engine.start()
            facts["engine"] = "running"
        } catch {
            facts["engine"] = "failed"
            facts["error"] = "\(error)"
        }

        NotificationCenter.default.addObserver(forName: AVAudioSession.routeChangeNotification, object: nil, queue: .main) { _ in
            routeNotifications += 1
        }
        observeRequests(show: show)

        let started = ProcessInfo.processInfo.systemUptime
        log = AudioTickLog(start: started)
        let source1 = DispatchSource.makeTimerSource(queue: .main)
        source1.schedule(deadline: .now() + 1, repeating: 1)
        source1.setEventHandler {
            guard !stopped else { return }
            let seen = clock.reading()
            log.tick(
                now: ProcessInfo.processInfo.systemUptime,
                lastInput: seen.lastInput,
                lastOutput: seen.lastOutput,
                longestInputInterval: seen.longestInput,
                longestOutputInterval: seen.longestOutput,
                protectedDataAvailable: UIApplication.shared.isProtectedDataAvailable
            )
            report(show: show)
        }
        source1.resume()
        timer = source1
        report(show: show)
    }

    /// The two requests a test can make while the check runs, as notifications it posts: a move of
    /// the route, and the end of the check.
    private static func observeRequests(show: @escaping ([String: String]) -> Void) {
        let centre = CFNotificationCenterGetDarwinNotifyCenter()
        CFNotificationCenterAddObserver(centre, nil, { _, _, _, _, _ in
            DispatchQueue.main.async { AudioProbe.moveRoute() }
        }, "to.kala.reach.probe.route" as CFString, nil, .deliverImmediately)
        CFNotificationCenterAddObserver(centre, nil, { _, _, _, _, _ in
            DispatchQueue.main.async { AudioProbe.stop() }
        }, "to.kala.reach.probe.audio-stop" as CFString, nil, .deliverImmediately)
        stopHandler = { report(show: show) }
    }

    private static var stopHandler: (() -> Void)?

    /// Moves the output the way a person's phone does without any accessory: the session without its
    /// speaker default sends it to the receiver, an override sends it to the speaker, taking the
    /// override away sends it back, and then the session's own options are set again. The system
    /// reports each move as a change of route, and the ports it named are kept in order.
    private static func moveRoute() {
        let session = AVAudioSession.sharedInstance()
        let own: AVAudioSession.CategoryOptions = [.allowBluetooth, .allowBluetoothA2DP, .defaultToSpeaker]
        let steps: [() throws -> Void] = [
            { try session.setCategory(.playAndRecord, mode: .voiceChat, options: [.allowBluetooth, .allowBluetoothA2DP]) },
            { try session.overrideOutputAudioPort(.speaker) },
            { try session.overrideOutputAudioPort(.none) },
            { try session.setCategory(.playAndRecord, mode: .voiceChat, options: own) },
        ]
        for step in steps {
            do {
                try step()
                moves += 1
            } catch {
                facts["route.error"] = "\(error)"
            }
            trail.append(session.currentRoute.outputs.map { $0.portType.rawValue }.joined(separator: "+"))
        }
    }

    /// Ends the check the way a call ends: the session is given back, and then the audio.
    private static func stop() {
        guard !stopped else { return }
        stopped = true
        timer?.cancel()
        engine.stop()
        engine.inputNode.removeTap(onBus: 0)
        do {
            try AudioSession.shared.deactivate(for: call)
            facts["deactivated"] = "1"
        } catch {
            facts["deactivated"] = "0"
            facts["error"] = "\(error)"
        }
        AudioSession.shared.release(call)
        facts["stopped"] = "1"
        stopHandler?()
    }

    private static func report(show: ([String: String]) -> Void) {
        var all = facts
        all.merge(log.facts) { _, new in new }
        all.merge(call.facts) { _, new in new }
        all["capture"] = "\(AudioSession.shared.capture)"
        all["callbacks.input"] = String(clock.counts.input)
        all["callbacks.output"] = String(clock.counts.output)
        all["route.notifications"] = String(routeNotifications)
        all["route.moves"] = String(moves)
        all["route.trail"] = trail.joined(separator: ",")
        all["route.input"] = AVAudioSession.sharedInstance().currentRoute.inputs.map { $0.portType.rawValue }.joined(separator: ",")
        all["route.output"] = AVAudioSession.sharedInstance().currentRoute.outputs.map { $0.portType.rawValue }.joined(separator: ",")
        all["protected"] = UIApplication.shared.isProtectedDataAvailable ? "1" : "0"
        show(all)
    }
}
#endif
