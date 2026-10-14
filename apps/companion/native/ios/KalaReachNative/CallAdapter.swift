//
//  What the platform plugin asks of the voice call, and what the call tells back.
//
//  The call is `VoiceCall`, in the application's own target, which the plugin's package cannot see,
//  so the plugin finds this adapter by the name of its class (`CallLink` in the plugin's package
//  holds the same names, and `link.json` is what both are tested against) and sends it one
//  request: a command's name, its arguments as JSON, a block for its answer and, for the command
//  that opens a call, a block for the call's news. The adapter does the work off the thread the
//  request arrived on, since opening a call asks the person for permission and making an offer
//  waits on the media engine, and answers once.
//
//  It reports facts and carries out requests. It decides nothing about the call: which commands
//  come, and when, is Rust's.
//

import AVFoundation
import Foundation
import UserNotifications
import WebRTC

/// What the adapter needs of a call, which `VoiceCall` is.
public protocol CallEngine: AnyObject {
    func offer() async throws -> String
    func accept(answerSdp: String) async throws
    var answerUsesDtx: Bool? { get }
    func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool
    func setMutedByPerson(_ muted: Bool)
    func setPlaybackMuted(_ muted: Bool)
    var isPlaybackMuted: Bool { get }
    func stop()
}

/// A call, and the bridge it reports through, which it holds only weakly.
private final class BridgedCall: CallEngine {
    private let call: VoiceCall
    private let bridge: ObserverBridge

    init(call: VoiceCall, bridge: ObserverBridge) {
        self.call = call
        self.bridge = bridge
    }

    func offer() async throws -> String { try await call.offer() }
    func accept(answerSdp: String) async throws { try await call.accept(answerSdp: answerSdp) }
    var answerUsesDtx: Bool? { call.answerUsesDtx }
    func permit(voiceSessionId: String, closesAtEpochMs: UInt64) -> Bool {
        call.permit(voiceSessionId: voiceSessionId, closesAtEpochMs: closesAtEpochMs)
    }
    func setMutedByPerson(_ muted: Bool) { call.setMutedByPerson(muted) }
    func setPlaybackMuted(_ muted: Bool) { call.setPlaybackMuted(muted) }
    var isPlaybackMuted: Bool { call.isPlaybackMuted }
    func stop() { call.stop() }
}

/// What the adapter needs of the device: the person's permissions, and what the microphone is doing.
public protocol CallDevice {
    /// Asks the person for the microphone when they have not been asked, and answers whether the
    /// application may use it.
    func requestMicrophone(_ answered: @escaping (Bool) -> Void)
    /// Answers whether the application may post notifications. A call on iOS needs none, so the
    /// person is not asked: this reports what they have already allowed.
    func notificationsAllowed(_ answered: @escaping (Bool) -> Void)
    /// What the microphone is doing now.
    func capture() -> VoiceCaptureState
}

/// What one call tells the adapter. Each call is given a reporter of its own, so a late report of a
/// call that has ended is never taken for news of the call that replaced it.
public protocol CallReporting: AnyObject {
    func connection(_ state: String)
    func providerEvent(_ data: Data)
    func firstAudio()
    func capture(_ state: VoiceCaptureState)
    func ended()
}

/// Makes the call, with the reporter it tells.
public protocol CallEngineMaker {
    func make(reporting: CallReporting) throws -> CallEngine
}

/// Carries what a `VoiceCall` reports to a call's reporter.
private final class ObserverBridge: VoiceCallObserver {
    private let reporting: CallReporting

    init(_ reporting: CallReporting) { self.reporting = reporting }

    func voiceCall(_: VoiceCall, connectionChanged state: RTCPeerConnectionState) {
        reporting.connection(CallWire.connectionWord(state))
    }

    func voiceCall(_: VoiceCall, receivedProviderEvent data: Data) { reporting.providerEvent(data) }

    func voiceCallReceivedFirstAudio(_: VoiceCall) { reporting.firstAudio() }

    func voiceCall(_: VoiceCall, captureChanged state: VoiceCaptureState) { reporting.capture(state) }

    func voiceCallEnded(_: VoiceCall) { reporting.ended() }
}

/// The product's call and the product's device.
struct ProductCalls: CallEngineMaker, CallDevice {
    func make(reporting: CallReporting) throws -> CallEngine {
        // The call keeps its observer weakly, so the bridge is kept alive by the engine's holder.
        let bridge = ObserverBridge(reporting)
        let call = try VoiceCall(observer: bridge)
        return BridgedCall(call: call, bridge: bridge)
    }

    func requestMicrophone(_ answered: @escaping (Bool) -> Void) {
        switch AVAudioApplication.shared.recordPermission {
        case .granted: answered(true)
        case .denied: answered(false)
        default: AVAudioApplication.requestRecordPermission(completionHandler: answered)
        }
    }

    func notificationsAllowed(_ answered: @escaping (Bool) -> Void) {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral: answered(true)
            default: answered(false)
            }
        }
    }

    func capture() -> VoiceCaptureState { AudioSession.shared.capture }
}

/// What a command could not do, with the code the plugin rejects it by.
struct CallRefusal: Error {
    let code: String
    let message: String

    static let microphoneRefused = "microphone_refused"
    static let alreadyRunning = "already_running"
    static let noSuchCall = "no_such_call"
    static let ended = "ended"
    static let engine = "engine"
}

/// One item of a call's news.
enum CallItem {
    case connection(String)
    case providerEvent(Data)
    case firstAudio
    case capture(VoiceCaptureState)
    case ended
}

/// A call's news on its way to Rust: numbered from 1, in order, and bounded.
///
/// A call reports from several threads, and sending on the channel Rust gave must not hold one of
/// them, so news is queued here and sent one item at a time by a queue of its own. A provider event
/// that finds the queue full is dropped and its number is spent, so Rust sees the gap as lost news
/// and does not take the quiet for there being nothing to say. Every other kind of news is kept.
final class CallNewsQueue {
    /// How many items may wait for the sender.
    static let capacity = 256

    private let call: String
    private let send: (String) -> Void
    private let capacity: Int
    private let lock = NSLock()
    private let sender = DispatchQueue(label: "to.kala.reach.call-news")
    private var pending: [String] = []
    private var seq: UInt64 = 0
    private var draining = false

    init(call: String, capacity: Int = CallNewsQueue.capacity, send: @escaping (String) -> Void) {
        self.call = call
        self.capacity = capacity
        self.send = send
    }

    func offer(_ item: CallItem) {
        lock.lock()
        seq += 1
        if case .providerEvent = item, pending.count >= capacity {
            lock.unlock()
            return
        }
        pending.append(CallWire.frame(call: call, seq: seq, item: item))
        let start = !draining
        draining = true
        lock.unlock()
        if start { sender.async { [self] in drain() } }
    }

    private func drain() {
        while true {
            lock.lock()
            guard !pending.isEmpty else {
                draining = false
                lock.unlock()
                return
            }
            let next = pending.removeFirst()
            lock.unlock()
            send(next)
        }
    }
}

/// The commands the plugin takes and the news it sends, as the JSON the Rust half speaks. The
/// shapes are the fixtures under `native/platform/fixtures/call`, which the Rust and Kotlin halves
/// are tested against as well.
enum CallWire {
    struct Call: Decodable { let call: String }
    struct Answer: Decodable { let call: String; let sdp: String }
    struct Permit: Decodable {
        let call: String
        let voiceSessionId: String
        let closesAtEpochMs: UInt64
    }
    struct Mute: Decodable {
        let call: String
        let what: String
        let muted: Bool
    }

    static func decode<T: Decodable>(_ type: T.Type, _ arguments: String) throws -> T {
        do { return try JSONDecoder().decode(type, from: Data(arguments.utf8)) } catch {
            throw CallRefusal(code: CallRefusal.engine, message: "the command's arguments are not what it takes")
        }
    }

    static func text(_ object: [String: Any]) -> String {
        let data = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data("{}".utf8)
        return String(decoding: data, as: UTF8.self)
    }

    static func captureWord(_ state: VoiceCaptureState) -> String {
        switch state {
        case .capturing: return "capturing"
        case .mutedByPerson: return "muted_by_person"
        case .interrupted: return "interrupted"
        case .routeChanging: return "route_changing"
        case .suspendedBySystem: return "suspended_by_system"
        case .unavailable: return "unavailable"
        case .idle: return "idle"
        }
    }

    static func connectionWord(_ state: RTCPeerConnectionState) -> String {
        switch state {
        case .new: return "new"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .disconnected: return "disconnected"
        case .failed: return "failed"
        case .closed: return "closed"
        @unknown default: return "failed"
        }
    }

    static func frame(call: String, seq: UInt64, item: CallItem) -> String {
        var frame: [String: Any] = ["call": call, "seq": seq]
        switch item {
        case .connection(let state):
            frame["kind"] = "connection"
            frame["state"] = state
        case .providerEvent(let data):
            frame["kind"] = "provider_event"
            frame["bytes"] = data.base64EncodedString()
        case .firstAudio:
            frame["kind"] = "first_audio"
        case .capture(let state):
            frame["kind"] = "capture"
            frame["state"] = captureWord(state)
        case .ended:
            frame["kind"] = "ended"
        }
        return text(frame)
    }
}

/// The adapter the plugin finds by name.
@objc(KRCallAdapter)
public final class CallAdapter: NSObject {
    /// The names the plugin reaches this by, which `link.json` holds as well.
    enum Link {
        static let command = "command"
        static let arguments = "arguments"
        static let news = "news"
        static let reply = "reply"
    }

    private typealias Reply = @convention(block) (NSString?, NSString?, NSString?) -> Void
    private typealias News = @convention(block) (NSString) -> Void

    private static let product = CallAdapter(maker: ProductCalls(), device: ProductCalls())

    /// The one adapter, which the plugin asks for by `krShared`.
    @objc(krShared)
    public static func krShared() -> CallAdapter { product }

    private let maker: CallEngineMaker
    private let device: CallDevice
    /// Everything below is touched on this queue only, apart from the news, which has its own.
    private let queue = DispatchQueue(label: "to.kala.reach.call-adapter")
    private var held: (id: String, engine: CallEngine, news: CallNewsQueue)?
    /// The call the observer's reports are for, so a late report of an ended call is not news.
    private var ended: Set<String> = []

    init(maker: CallEngineMaker, device: CallDevice) {
        self.maker = maker
        self.device = device
    }

    /// Takes one request: see the file's description. The answer comes on a block, once.
    @objc(krCall:)
    public func krCall(_ request: NSDictionary) {
        guard
            let command = request[Link.command] as? String,
            let arguments = request[Link.arguments] as? String,
            let replying = request[Link.reply] as AnyObject?
        else { return }
        let reply = unsafeBitCast(replying, to: Reply.self)
        let news = (request[Link.news] as AnyObject?).map { unsafeBitCast($0, to: News.self) }
        Task {
            do {
                reply(try await self.run(command, arguments, news: news) as NSString, nil, nil)
            } catch let refusal as CallRefusal {
                reply(nil, refusal.code as NSString, refusal.message as NSString)
            } catch {
                reply(nil, CallRefusal.engine as NSString, error.localizedDescription as NSString)
            }
        }
    }

    private func run(_ command: String, _ arguments: String, news: News?) async throws -> String {
        switch command {
        case "callOpen":
            return try await open(CallWire.decode(CallWire.Call.self, arguments).call, news: news)
        case "callOffer":
            let engine = try engine(CallWire.decode(CallWire.Call.self, arguments).call)
            return CallWire.text(["sdp": try await engine.offer()])
        case "callAccept":
            let answer = try CallWire.decode(CallWire.Answer.self, arguments)
            let engine = try engine(answer.call)
            try await engine.accept(answerSdp: answer.sdp)
            return CallWire.text(["usesDtx": engine.answerUsesDtx ?? false])
        case "callPermit":
            let permit = try CallWire.decode(CallWire.Permit.self, arguments)
            let engine = try engine(permit.call)
            let permitted = engine.permit(
                voiceSessionId: permit.voiceSessionId, closesAtEpochMs: permit.closesAtEpochMs)
            return CallWire.text(["permitted": permitted])
        case "callMute":
            let mute = try CallWire.decode(CallWire.Mute.self, arguments)
            let engine = try engine(mute.call)
            switch mute.what {
            case "microphone": engine.setMutedByPerson(mute.muted)
            case "playback": engine.setPlaybackMuted(mute.muted)
            default: throw CallRefusal(code: CallRefusal.engine, message: "a mute is of the microphone or of playback")
            }
            return "{}"
        case "callStop":
            let call = try CallWire.decode(CallWire.Call.self, arguments).call
            try engine(call).stop()
            // The end is told once, and the call is let go of now, so that the next command to
            // open one does not meet it; the call's own report of its end finds it gone.
            queue.sync {
                guard let held = held, held.id == call else { return }
                finish(call)
                held.news.offer(.ended)
            }
            return "{}"
        case "callState":
            return state()
        default:
            throw CallRefusal(code: CallRefusal.engine, message: "this build takes no such command")
        }
    }

    /// The call by that name, or why there is none.
    private func engine(_ call: String) throws -> CallEngine {
        try queue.sync {
            if let held = held, held.id == call { return held.engine }
            throw CallRefusal(
                code: ended.contains(call) ? CallRefusal.ended : CallRefusal.noSuchCall,
                message: "no call by that name is held")
        }
    }

    private func state() -> String {
        queue.sync {
            let playing = held.map { !$0.engine.isPlaybackMuted } ?? false
            return CallWire.text([
                "call": held.map { $0.id as Any } ?? NSNull(),
                "capture": CallWire.captureWord(held == nil ? .idle : device.capture()),
                "playing": playing,
            ])
        }
    }

    private func open(_ call: String, news: News?) async throws -> String {
        guard let news = news else {
            throw CallRefusal(code: CallRefusal.engine, message: "a call is opened with a channel for its news")
        }
        if queue.sync(execute: { held != nil }) {
            throw CallRefusal(code: CallRefusal.alreadyRunning, message: "this device already holds a call")
        }
        let microphone = await withCheckedContinuation { (answer: CheckedContinuation<Bool, Never>) in
            device.requestMicrophone { answer.resume(returning: $0) }
        }
        guard microphone else {
            throw CallRefusal(code: CallRefusal.microphoneRefused, message: "the microphone is not allowed")
        }
        let notifications = await withCheckedContinuation { (answer: CheckedContinuation<Bool, Never>) in
            device.notificationsAllowed { answer.resume(returning: $0) }
        }
        let queued = CallNewsQueue(call: call) { news($0 as NSString) }
        let made: CallEngine
        do {
            made = try queue.sync {
                guard held == nil else { throw VoiceAudioError.callAlreadyRunning }
                let engine = try maker.make(reporting: Reporter(call: call, adapter: self))
                held = (call, engine, queued)
                return engine
            }
        } catch VoiceAudioError.callAlreadyRunning {
            throw CallRefusal(code: CallRefusal.alreadyRunning, message: "this device already holds a call")
        } catch {
            throw CallRefusal(code: CallRefusal.engine, message: "\(error)")
        }
        _ = made
        return CallWire.text(["notifications": notifications ? "granted" : "denied"])
    }

    // MARK: What a call reports

    /// What one call tells the adapter, tied to that call.
    private final class Reporter: CallReporting {
        let call: String
        private weak var adapter: CallAdapter?

        init(call: String, adapter: CallAdapter) {
            self.call = call
            self.adapter = adapter
        }

        func connection(_ state: String) { adapter?.report(call, .connection(state)) }
        func providerEvent(_ data: Data) { adapter?.report(call, .providerEvent(data)) }
        func firstAudio() { adapter?.report(call, .firstAudio) }
        func capture(_ state: VoiceCaptureState) { adapter?.report(call, .capture(state)) }
        func ended() { adapter?.report(call, .ended) }
    }

    private func report(_ call: String, _ item: CallItem) {
        queue.async { [self] in
            guard let held = held, held.id == call else { return }
            if case .ended = item { finish(held.id) }
            held.news.offer(item)
        }
    }

    /// The call is over: it is no longer held, and a command that names it says so.
    private func finish(_ call: String) {
        ended.insert(call)
        held = nil
    }
}
