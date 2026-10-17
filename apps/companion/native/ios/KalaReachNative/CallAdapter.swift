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
    var isMutedByPerson: Bool { get }
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
    var isMutedByPerson: Bool { call.isMutedByPerson }
    func stop() { call.stop() }
}

/// What the adapter needs of the device: the person's permissions.
public protocol CallDevice {
    /// Asks the person for the microphone when they have not been asked, and answers whether the
    /// application may use it.
    func requestMicrophone(_ answered: @escaping (Bool) -> Void)
    /// Answers whether the application may post notifications. A call on iOS needs none, so the
    /// person is not asked: this reports what they have already allowed.
    func notificationsAllowed(_ answered: @escaping (Bool) -> Void)
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
    /// Some news was dropped here. Never queued as news: it marks a place in the queue.
    case lost

    var isProviderEvent: Bool {
        if case .providerEvent = self { return true }
        return false
    }
}

/// A call's news waiting for the sender: bounded, in order, with a loss kept in its place.
///
/// At most `limit` items of news wait. A provider event that finds the buffer full is dropped. Any
/// other news that finds it full takes the place of the oldest provider event waiting, or, when
/// there is none, of the oldest news: what was displaced is lost, and the buffer holds the mark of
/// the loss where it happened, one mark for losses that sit together. The end of the call closes
/// the buffer, so nothing is queued after it. It holds no thread: `CallNewsQueue` sends from it.
struct CallNewsBuffer {
    enum Entry {
        case news(CallItem)
        case lost
    }

    private var entries: [Entry] = []
    private var events = 0
    private var closed = false
    private let limit: Int

    init(limit: Int) { self.limit = limit }

    /// Queues one item of news.
    mutating func push(_ item: CallItem) {
        if closed { return }
        if events >= limit {
            if item.isProviderEvent {
                markLost()
                return
            }
            let victim =
                entries.firstIndex { entry in
                    if case .news(let queued) = entry { return queued.isProviderEvent }
                    return false
                }
                ?? entries.firstIndex { entry in
                    if case .news = entry { return true }
                    return false
                }
            if let victim = victim {
                entries[victim] = .lost
                events -= 1
                mergeMarks()
            }
        }
        if case .ended = item { closed = true }
        entries.append(.news(item))
        events += 1
    }

    /// Records that news was lost after everything queued so far.
    mutating func markLost() {
        if closed { return }
        if case .lost? = entries.last { return }
        entries.append(.lost)
    }

    private mutating func mergeMarks() {
        var merged: [Entry] = []
        for entry in entries {
            if case .lost = entry, case .lost? = merged.last { continue }
            merged.append(entry)
        }
        entries = merged
    }

    /// The next place, oldest first.
    mutating func pop() -> Entry? {
        if entries.isEmpty { return nil }
        let entry = entries.removeFirst()
        if case .news = entry { events -= 1 }
        return entry
    }
}

/// A call's news on its way to Rust: numbered from 1 as it is sent, in order, and bounded.
///
/// A call reports from several threads, and sending on the channel Rust gave must not hold one of
/// them, so news is queued in a `CallNewsBuffer` and sent one item at a time by a queue of its own.
/// News the buffer dropped is sent as a `lost` item in its place.
final class CallNewsQueue {
    /// How many items may wait for the sender.
    static let capacity = 256

    private let call: String
    private let send: (String) -> Void
    private let lock = NSLock()
    private let sender = DispatchQueue(label: "to.kala.reach.call-news")
    private var buffer: CallNewsBuffer
    private var seq: UInt64 = 0
    private var draining = false

    init(call: String, limit: Int = CallNewsQueue.capacity, send: @escaping (String) -> Void) {
        self.call = call
        self.buffer = CallNewsBuffer(limit: limit)
        self.send = send
    }

    func offer(_ item: CallItem) {
        lock.lock()
        buffer.push(item)
        let start = !draining
        draining = true
        lock.unlock()
        if start { sender.async { [self] in drain() } }
    }

    private func drain() {
        while true {
            lock.lock()
            guard let taken = buffer.pop() else {
                draining = false
                lock.unlock()
                return
            }
            seq += 1
            let item: CallItem
            if case .news(let news) = taken { item = news } else { item = .lost }
            let next = CallWire.frame(call: call, seq: seq, item: item)
            lock.unlock()
            send(next)
        }
    }
}

/// The time a call's owner may leave without a sign before the call ends itself.
///
/// The call is ended by the Rust side that owns it. If that side is gone (the process was killed
/// under a running call, a task was lost) nothing else would end it before the host's deadline,
/// with the microphone open. So the owner gives a sign of life every few seconds, and a call that
/// has had none for `afterPermit` seconds ends. A call that was opened and not yet permitted has
/// the longer `beforePermit`, which covers the host's start and the provider's answer, but not for
/// ever: it holds the device's one call. The clock is a monotonic one, and `expired` is true once.
/// This is the same rule as the Android half's, with the same bounds.
struct CallWatch {
    /// How long an opened call waits for its permit and for signs before then.
    static let beforePermit: TimeInterval = 180
    /// How long a permitted call goes without a sign.
    static let afterPermit: TimeInterval = 45

    private let clock: () -> TimeInterval
    private let before: TimeInterval
    private let after: TimeInterval
    private var lastSign: TimeInterval
    private var permitted = false
    private var spent = false

    init(
        clock: @escaping () -> TimeInterval,
        beforePermit: TimeInterval = CallWatch.beforePermit,
        afterPermit: TimeInterval = CallWatch.afterPermit
    ) {
        self.clock = clock
        self.before = beforePermit
        self.after = afterPermit
        self.lastSign = clock()
    }

    /// The owner is there.
    mutating func sign() { lastSign = clock() }

    /// The call is permitted, and the shorter bound applies from now.
    mutating func permit() {
        permitted = true
        lastSign = clock()
    }

    /// Whether the owner has given no sign for too long. True once, for the call to end on.
    mutating func expired() -> Bool {
        if spent { return false }
        if clock() - lastSign < (permitted ? after : before) { return false }
        spent = true
        return true
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
        case .lost:
            frame["kind"] = "lost"
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
    /// Where the adapter's calls into the engine's control run. The control is one lock, and a stop
    /// holds it while it waits for the connection to close, so a call that touches it (a stop, a
    /// permit, a mute, a read of a mute) can wait behind a stop. It waits here, on a thread of
    /// this queue, and never on a thread of Swift's cooperative pool.
    private let engineQueue = DispatchQueue(label: "to.kala.reach.call-engine", attributes: .concurrent)
    private var held: (id: String, engine: CallEngine, news: CallNewsQueue, capture: VoiceCaptureState)?
    /// The call the observer's reports are for, so a late report of an ended call is not news.
    private var ended: Set<String> = []
    /// How long the held call's owner has been silent, kept for the call held.
    private var watch: CallWatch?
    /// The time the watch is measured on.
    private let clock: () -> TimeInterval
    /// Looks for an owner that has stopped giving signs, on the adapter's queue.
    private var watching: DispatchSourceTimer?

    /// How often a call's owner is looked for.
    static let watchEvery: TimeInterval = 5

    init(
        maker: CallEngineMaker,
        device: CallDevice,
        clock: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
        watches: Bool = true
    ) {
        self.maker = maker
        self.device = device
        self.clock = clock
        if watches { startWatching() }
    }

    private func startWatching() {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + CallAdapter.watchEvery, repeating: CallAdapter.watchEvery)
        timer.setEventHandler { [weak self] in self?.endIfGone() }
        timer.resume()
        watching = timer
    }

    /// Looks for an owner that has given no sign for too long, and ends the call if so.
    func endIfOwnerIsGone() { queue.sync { endIfGone() } }

    /// Ends the held call when its owner has given no sign for too long: as it ends when the person
    /// stops it, and the owner, if there is one, is told by the end. Runs on the adapter's queue.
    private func endIfGone() {
        guard let held = held, var watch = watch, watch.expired() else { return }
        self.watch = watch
        let engine = held.engine
        engineQueue.async { engine.stop() }
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
            let permitted = await onTheEngineQueue {
                engine.permit(
                    voiceSessionId: permit.voiceSessionId, closesAtEpochMs: permit.closesAtEpochMs)
            }
            if permitted { queue.sync { watch?.permit() } }
            return CallWire.text(["permitted": permitted])
        case "callMute":
            let mute = try CallWire.decode(CallWire.Mute.self, arguments)
            let engine = try engine(mute.call)
            switch mute.what {
            case "microphone": await onTheEngineQueue { engine.setMutedByPerson(mute.muted) }
            case "playback": await onTheEngineQueue { engine.setPlaybackMuted(mute.muted) }
            default: throw CallRefusal(code: CallRefusal.engine, message: "a mute is of the microphone or of playback")
            }
            return "{}"
        case "callStop":
            let call = try CallWire.decode(CallWire.Call.self, arguments).call
            let engine = try engine(call)
            await onTheEngineQueue { engine.stop() }
            // The end is told once, and the call is let go of now, so that the next command to
            // open one does not meet it; the call's own report of its end finds it gone.
            queue.sync {
                guard let held = held, held.id == call else { return }
                finish(call)
                held.news.offer(.ended)
            }
            return "{}"
        case "callState":
            return await state()
        case "callAlive":
            // The owner is there. The call is named, so a sign for a call that has ended says so.
            _ = try engine(CallWire.decode(CallWire.Call.self, arguments).call)
            queue.sync { watch?.sign() }
            return await state()
        default:
            throw CallRefusal(code: CallRefusal.engine, message: "this build takes no such command")
        }
    }

    /// Runs `work`, which may wait, off Swift's cooperative pool, and answers when it is done.
    private func onTheEngineQueue<T>(_ work: @escaping () -> T) async -> T {
        await withCheckedContinuation { continuation in
            engineQueue.async { continuation.resume(returning: work()) }
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

    private func state() async -> String {
        let seen = queue.sync { held.map { (id: $0.id, engine: $0.engine, capture: $0.capture) } }
        // The engine's mutes are read on the engine queue: a read can wait behind a stop there.
        let mutes = await onTheEngineQueue { (person: seen?.engine.isMutedByPerson ?? false,
                                              playback: seen?.engine.isPlaybackMuted ?? true) }
        return CallWire.text([
            "call": seen.map { $0.id as Any } ?? NSNull(),
            "capture": CallWire.captureWord(seen?.capture ?? .idle),
            "microphoneMuted": mutes.person,
            "playing": seen != nil && !mutes.playback,
        ])
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
                held = (call, engine, queued, .idle)
                watch = CallWatch(clock: clock)
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
            if case .capture(let state) = item { self.held?.capture = state }
            held.news.offer(item)
            // A connection that has failed for good carries no call: it ends here, and the owner
            // is told by the end.
            if case .connection("failed") = item {
                let engine = held.engine
                engineQueue.async { engine.stop() }
            }
        }
    }

    /// The call is over: it is no longer held, and a command that names it says so.
    private func finish(_ call: String) {
        ended.insert(call)
        held = nil
        watch = nil
    }
}
