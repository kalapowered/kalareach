//
//  The other end of a device run's call: a peer in this process that answers the call's offer and
//  sends and receives audio, so that the call's media is measured by what each end receives.
//
//  A script puts `kr-probe/peer.json` in the application's data directory, naming a loopback port
//  and a token. The peer serves four routes on that port, and only to a request that carries the
//  token. `POST /answer` takes the call's offer and answers with the peer's own answer, marked as
//  the provider's is (an ICE-lite agent), and the stand-in voice service on the machine the
//  application runs beside relays it as the provider's; with `?dtx=1` the answer also turns Opus
//  discontinuous transmission on. `GET /figures` says what the peer received and sent, and what
//  the system's lock screen holds for the call. `POST /events` writes its body, as text, to the
//  call's `oai-events` channel as the provider would, and `POST /drop?ms=N` takes N milliseconds
//  of audio out of the call's recorder (the device run's drop hook).
//
//  The peer's audio is its own: a second factory with an audio device that makes a tone for its
//  microphone and takes what it is played, and opens neither the audio session nor the
//  microphone. It shares nothing with the call's factory and its audio unit.
//
//  When the peer file also says `"recorder": "synthetic"`, the call's own factory is given a device
//  of the same kind, because a simulator has no recorder: the call then records a tone at the pace
//  of real audio, opens no microphone of the machine, and is the one the drop hook acts on. Without
//  it, and in a release build, the call has the system's audio device.
//
//  Compiled into debug builds only. A release build has no peer and reads no file.
//

#if DEBUG
import Foundation
import Network
import WebRTC

/// An audio device that makes a tone for its microphone and drains what it is played, on a thread
/// of its own, at the pace of real audio. It touches no audio session and no hardware.
final class SyntheticAudioDevice: NSObject, RTCAudioDevice {
    private static let rate = 48_000
    private static let frames = 480

    /// Whether the device run's drop hook acts on this device's recorder: the call's, not the peer's.
    private let honoursDrops: Bool

    init(honoursDrops: Bool = false) {
        self.honoursDrops = honoursDrops
        super.init()
    }

    var deviceInputSampleRate: Double { Double(Self.rate) }
    var inputIOBufferDuration: TimeInterval { 0.01 }
    var inputNumberOfChannels: Int { 1 }
    var inputLatency: TimeInterval { 0 }
    var deviceOutputSampleRate: Double { Double(Self.rate) }
    var outputIOBufferDuration: TimeInterval { 0.01 }
    var outputNumberOfChannels: Int { 1 }
    var outputLatency: TimeInterval { 0 }

    private let lock = NSLock()
    private var delegate: RTCAudioDeviceDelegate?
    private var worker: Thread?
    private var initialized = false
    private var playoutInitialized = false
    private var recordingInitialized = false
    private var playing = false
    private var recording = false
    private var recordedFrames = 0
    private var playedFrames = 0

    var isInitialized: Bool { locked { initialized } }
    var isPlayoutInitialized: Bool { locked { playoutInitialized } }
    var isPlaying: Bool { locked { playing } }
    var isRecordingInitialized: Bool { locked { recordingInitialized } }
    var isRecording: Bool { locked { recording } }

    /// What the device did, for the peer's figures.
    var facts: [String: Any] {
        locked { ["recorderStarted": recordedFrames > 0, "recordedFrames": recordedFrames, "playedFrames": playedFrames] }
    }

    func initialize(with delegate: RTCAudioDeviceDelegate) -> Bool {
        locked {
            self.delegate = delegate
            initialized = true
        }
        return true
    }

    func terminateDevice() -> Bool {
        let stopping = locked { () -> Thread? in
            initialized = false
            playing = false
            recording = false
            delegate = nil
            let thread = worker
            worker = nil
            return thread
        }
        stopping?.cancel()
        return true
    }

    func initializePlayout() -> Bool {
        locked { playoutInitialized = true }
        return true
    }

    func startPlayout() -> Bool {
        locked { playing = true }
        runWorker()
        return true
    }

    func stopPlayout() -> Bool {
        locked { playing = false }
        return true
    }

    func initializeRecording() -> Bool {
        locked { recordingInitialized = true }
        return true
    }

    func startRecording() -> Bool {
        locked { recording = true }
        runWorker()
        return true
    }

    func stopRecording() -> Bool {
        locked { recording = false }
        return true
    }

    private func runWorker() {
        let started: Thread? = locked {
            guard worker == nil else { return nil }
            let thread = Thread { [weak self] in self?.loop() }
            thread.name = "to.kala.reach.peer-audio"
            worker = thread
            return thread
        }
        started?.start()
    }

    /// Delivers a tone and drains the playout every ten milliseconds, on this one thread, for as
    /// long as the device runs.
    private func loop() {
        var phase = 0.0
        var silentUntil = Date.distantPast
        var tone = [Int16](repeating: 0, count: Self.frames)
        var drain = [Int16](repeating: 0, count: Self.frames)
        let step = 2 * Double.pi * 440 / Double(Self.rate)
        let period = Double(Self.frames) / Double(Self.rate)
        var due = ProcessInfo.processInfo.systemUptime
        while !Thread.current.isCancelled {
            let (delegate, recording, playing) = locked { (self.delegate, self.recording, self.playing) }
            guard let delegate else { break }
            if recording, honoursDrops, let dropped = DeviceRunDrop.take() {
                // The recorder delivers nothing for this long: audio the call never gets. What is
                // played out goes on.
                silentUntil = Date().addingTimeInterval(dropped)
            }
            if recording, Date() >= silentUntil {
                for index in 0..<Self.frames {
                    tone[index] = Int16(sin(phase) * 9_000)
                    phase += step
                }
                tone.withUnsafeMutableBytes { raw in
                    var list = AudioBufferList(
                        mNumberBuffers: 1,
                        mBuffers: AudioBuffer(
                            mNumberChannels: 1,
                            mDataByteSize: UInt32(Self.frames * 2),
                            mData: raw.baseAddress
                        )
                    )
                    var flags = AudioUnitRenderActionFlags()
                    var stamp = AudioTimeStamp()
                    stamp.mHostTime = mach_absolute_time()
                    stamp.mFlags = .hostTimeValid
                    _ = delegate.deliverRecordedData(&flags, &stamp, 0, UInt32(Self.frames), &list, nil, nil)
                }
                locked { recordedFrames += Self.frames }
            }
            if playing {
                drain.withUnsafeMutableBytes { raw in
                    var list = AudioBufferList(
                        mNumberBuffers: 1,
                        mBuffers: AudioBuffer(
                            mNumberChannels: 1,
                            mDataByteSize: UInt32(Self.frames * 2),
                            mData: raw.baseAddress
                        )
                    )
                    var flags = AudioUnitRenderActionFlags()
                    var stamp = AudioTimeStamp()
                    stamp.mHostTime = mach_absolute_time()
                    stamp.mFlags = .hostTimeValid
                    _ = delegate.getPlayoutData(&flags, &stamp, 0, UInt32(Self.frames), &list)
                }
                locked { playedFrames += Self.frames }
            }
            // Keeps time: each frame is due one period after the last was due, so a thread that woke
            // late catches up, and the audio taken in keeps pace with the clock as a real recorder's
            // does (a sleep of one period after each frame delivers a fifth too little on a busy
            // machine, which the call's own progress watch reads as a gap). Audio a drop took away is
            // not made up for, and a thread that fell far behind starts again from now.
            let now = ProcessInfo.processInfo.systemUptime
            due += period
            if !recording || Date() < silentUntil || now - due > 0.5 { due = now + period }
            if due > now { Thread.sleep(forTimeInterval: due - now) }
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// The device run's drop hook: a length of time the call's recorder is to deliver nothing for.
/// Armed by the peer's `/drop` route, taken by the call's recording device, counted when taken.
enum DeviceRunDrop {
    private static let lock = NSLock()
    private static var pending: TimeInterval?
    private static var done = 0

    static func arm(milliseconds: Int) {
        lock.lock()
        pending = Double(milliseconds) / 1_000
        lock.unlock()
    }

    /// The length to deliver nothing for, once; nil when no drop is armed.
    static func take() -> TimeInterval? {
        lock.lock()
        defer { lock.unlock() }
        guard let length = pending else { return nil }
        pending = nil
        done += 1
        return length
    }

    static var drops: Int {
        lock.lock()
        defer { lock.unlock() }
        return done
    }
}

/// The peer: a peer connection with an audio device of its own, and the routes.
final class AudioPeer: NSObject, RTCPeerConnectionDelegate, @unchecked Sendable {
    /// Kept alive for the life of the process.
    private static var running: AudioPeer?
    /// Whether the peer file asked for the call's recorder to be the synthetic device.
    private static var syntheticRecorder = false

    private let device = SyntheticAudioDevice()
    private let factory: RTCPeerConnectionFactory
    private let token: String
    private let lock = NSLock()
    private var connection: RTCPeerConnection?
    private var waiting: CheckedContinuation<Void, Never>?
    private var addressFound = false
    private var server: PeerServer?
    /// The channel the call made for the provider's events, once the connection carries it.
    private var events: RTCDataChannel?
    private var eventsSent = 0

    /// The audio device the call's own factory is given when the run asked for a synthetic recorder:
    /// a tone and no hardware, with the drop hook acting on it. Nil otherwise.
    static func deviceForTheCall() -> SyntheticAudioDevice? {
        running != nil && syntheticRecorder ? SyntheticAudioDevice(honoursDrops: true) : nil
    }

    /// Starts the peer when the run asked for one: `kr-probe/peer.json` holds a port and a token.
    static func startIfRequested() {
        guard
            let bundle = Bundle.main.bundleIdentifier,
            let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
        else { return }
        let file = support.appendingPathComponent(bundle).appendingPathComponent("kr-probe/peer.json")
        guard
            let data = try? Data(contentsOf: file),
            let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
            let port = object["port"] as? Int, let token = object["token"] as? String,
            let number = UInt16(exactly: port)
        else { return }
        let peer = AudioPeer(token: token)
        guard let server = try? PeerServer(port: number, token: token, handler: { await peer.handle($0) }) else {
            return
        }
        peer.server = server
        syntheticRecorder = (object["recorder"] as? String) == "synthetic"
        running = peer
    }

    init(token: String) {
        self.token = token
        factory = RTCPeerConnectionFactory(
            encoderFactory: RTCDefaultVideoEncoderFactory(),
            decoderFactory: RTCDefaultVideoDecoderFactory(),
            audioDevice: device
        )
        super.init()
    }

    private func handle(_ request: PeerRequest) async -> PeerResponse {
        let parts = request.path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)
        let path = String(parts.first ?? "")
        var query: [String: String] = [:]
        if parts.count == 2 {
            for pair in parts[1].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                if kv.count == 2 { query[String(kv[0])] = String(kv[1]) }
            }
        }
        switch (request.method, path) {
        case ("POST", "/answer"):
            let offer = String(decoding: request.body, as: UTF8.self)
            do {
                return PeerResponse(status: 200, body: Data(try await answer(offer, dtx: query["dtx"] == "1").utf8))
            } catch {
                return PeerResponse(status: 500, body: Data("\(error)".utf8))
            }
        case ("GET", "/figures"):
            let text = (try? JSONSerialization.data(withJSONObject: await figures(), options: [.sortedKeys])) ?? Data("{}".utf8)
            return PeerResponse(status: 200, body: text)
        case ("POST", "/events"):
            return send(request.body)
                ? PeerResponse(status: 200, body: Data("sent".utf8))
                : PeerResponse(status: 409, body: Data("the events channel is not open".utf8))
        case ("POST", "/drop"):
            guard let text = query["ms"], let milliseconds = Int(text), (1...2_000).contains(milliseconds) else {
                return PeerResponse(status: 400, body: Data("ms is a whole number of milliseconds up to 2000".utf8))
            }
            DeviceRunDrop.arm(milliseconds: milliseconds)
            return PeerResponse(status: 200, body: Data("armed".utf8))
        default:
            return PeerResponse(status: 404, body: Data())
        }
    }

    /// Applies `offer` and answers it, with the candidates this peer has found by its first,
    /// marked as the provider's answer is.
    func answer(_ offer: String, dtx: Bool = false) async throws -> String {
        let configuration = RTCConfiguration()
        configuration.sdpSemantics = .unifiedPlan
        configuration.continualGatheringPolicy = .gatherContinually
        let constraints = RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil)
        guard let made = factory.peerConnection(with: configuration, constraints: constraints, delegate: self) else {
            throw PeerError.noConnection
        }
        keep(made)
        try await made.setRemoteDescription(RTCSessionDescription(type: .offer, sdp: offer))
        let source = factory.audioSource(with: RTCMediaConstraints(mandatoryConstraints: nil, optionalConstraints: nil))
        made.add(factory.audioTrack(with: source, trackId: "kr-peer-tone"), streamIds: ["kr-peer"])
        let answer = try await made.answer(for: RTCMediaConstraints(
            mandatoryConstraints: [kRTCMediaConstraintsOfferToReceiveAudio: kRTCMediaConstraintsValueTrue],
            optionalConstraints: nil
        ))
        try await made.setLocalDescription(answer)
        await withCheckedContinuation { (done: CheckedContinuation<Void, Never>) in
            if wait(for: done) {
                // A peer that finds no address answers with what it has after this long.
                DispatchQueue.global().asyncAfter(deadline: .now() + 30) { [weak self] in self?.foundAnAddress() }
            }
        }
        let sdp = Self.asIceLite(made.localDescription?.sdp ?? answer.sdp)
        return dtx ? Self.withDtx(sdp) : sdp
    }

    /// The answer with Opus discontinuous transmission turned on (`usedtx=1`), as an answer that
    /// asks for it reads. The peer's own connection runs as it was answered; only what the call is
    /// told changes.
    static func withDtx(_ sdp: String) -> String {
        var lines = sdp.components(separatedBy: "\r\n")
        guard
            let map = lines.firstIndex(where: { $0.hasPrefix("a=rtpmap:") && $0.contains(" opus/") }),
            let payload = lines[map].dropFirst("a=rtpmap:".count).split(separator: " ").first
        else { return sdp }
        if let index = lines.firstIndex(where: { $0.hasPrefix("a=fmtp:\(payload) ") }) {
            if !lines[index].contains("usedtx=") { lines[index] += ";usedtx=1" }
        } else {
            lines.insert("a=fmtp:\(payload) usedtx=1", at: map + 1)
        }
        return lines.joined(separator: "\r\n")
    }

    /// Writes `body` to the call's events channel as one text message, and says whether it was written.
    private func send(_ body: Data) -> Bool {
        lock.lock()
        let channel = events
        lock.unlock()
        guard let channel, channel.readyState == .open else { return false }
        let written = channel.sendData(RTCDataBuffer(data: body, isBinary: false))
        if written {
            lock.lock()
            eventsSent += 1
            lock.unlock()
        }
        return written
    }

    /// The answer as the provider's reads: an ICE-lite agent answers the checks it is sent. The peer
    /// is a full agent, which WebRTC offers no way to make lite, so the run shows that the call
    /// connects and carries audio to such an answer, and not that the provider's own does.
    private static func asIceLite(_ sdp: String) -> String {
        guard !sdp.contains("a=ice-lite"), let media = sdp.range(of: "m=") else { return sdp }
        return sdp.replacingCharacters(in: media.lowerBound..<media.lowerBound, with: "a=ice-lite\r\n")
    }

    /// Makes `made` the connection the figures read, and forgets any address found for an earlier one.
    private func keep(_ made: RTCPeerConnection) {
        lock.lock()
        connection = made
        addressFound = false
        lock.unlock()
    }

    /// Holds `done` until an address is found, and says whether it is held; false when one was found
    /// already and `done` is resumed at once.
    private func wait(for done: CheckedContinuation<Void, Never>) -> Bool {
        lock.lock()
        if addressFound {
            lock.unlock()
            done.resume()
            return false
        }
        waiting = done
        lock.unlock()
        return true
    }

    private func current() -> RTCPeerConnection? {
        lock.lock()
        defer { lock.unlock() }
        return connection
    }

    private func foundAnAddress() {
        lock.lock()
        addressFound = true
        let done = waiting
        waiting = nil
        lock.unlock()
        done?.resume()
    }

    /// What the peer received and sent, what its audio device did, and what the lock screen holds.
    func figures() async -> [String: Any] {
        var out: [String: Any] = device.facts
        if let open = current() {
            let report = await withCheckedContinuation { (continuation: CheckedContinuation<RTCStatisticsReport, Never>) in
                open.statistics { continuation.resume(returning: $0) }
            }
            for stats in report.statistics.values where (stats.values["kind"] as? String) == "audio" {
                if stats.type == "inbound-rtp", let packets = stats.values["packetsReceived"] as? NSNumber {
                    out["packetsReceived"] = packets.int64Value
                }
                if stats.type == "outbound-rtp", let packets = stats.values["packetsSent"] as? NSNumber {
                    out["packetsSent"] = packets.int64Value
                }
            }
        }
        lock.lock()
        out["eventsOpen"] = events?.readyState == .open
        out["eventsSent"] = eventsSent
        lock.unlock()
        out["dropsDone"] = DeviceRunDrop.drops
        let reading = SystemRemoteControls.reading()
        out["lockScreen"] = [
            "pauseOffered": reading.pauseOffered,
            "stopOffered": reading.stopOffered,
            "playOffered": reading.playOffered,
            "toggleOffered": reading.toggleOffered,
            "title": reading.title as Any? ?? NSNull(),
            "rate": reading.rate as Any? ?? NSNull(),
        ]
        return out
    }

    // MARK: RTCPeerConnectionDelegate

    func peerConnection(_: RTCPeerConnection, didGenerate _: RTCIceCandidate) { foundAnAddress() }
    func peerConnectionShouldNegotiate(_: RTCPeerConnection) {}
    func peerConnection(_: RTCPeerConnection, didChange _: RTCSignalingState) {}
    func peerConnection(_: RTCPeerConnection, didAdd _: RTCMediaStream) {}
    func peerConnection(_: RTCPeerConnection, didRemove _: RTCMediaStream) {}
    func peerConnection(_: RTCPeerConnection, didChange _: RTCIceConnectionState) {}
    func peerConnection(_: RTCPeerConnection, didChange _: RTCIceGatheringState) {}
    func peerConnection(_: RTCPeerConnection, didRemove _: [RTCIceCandidate]) {}
    func peerConnection(_: RTCPeerConnection, didOpen channel: RTCDataChannel) {
        lock.lock()
        events = channel
        lock.unlock()
    }
}

private enum PeerError: Error { case noConnection }

/// One request the peer's server read.
struct PeerRequest {
    let method: String
    let path: String
    let body: Data
}

/// What the peer's server answers.
struct PeerResponse {
    let status: Int
    let body: Data
}

/// A small HTTP server on a loopback port that answers only requests carrying its token.
final class PeerServer {
    private let listener: NWListener
    private let token: String
    private let handler: (PeerRequest) async -> PeerResponse

    init(port: UInt16, token: String, handler: @escaping (PeerRequest) async -> PeerResponse) throws {
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        guard let port = NWEndpoint.Port(rawValue: port) else { throw PeerServerError.badPort }
        listener = try NWListener(using: parameters, on: port)
        self.token = token
        self.handler = handler
        listener.newConnectionHandler = { [weak self] connection in self?.serve(connection) }
        listener.start(queue: DispatchQueue(label: "to.kala.reach.peer-server"))
    }

    private enum PeerServerError: Error { case badPort }

    private func serve(_ connection: NWConnection) {
        connection.start(queue: DispatchQueue(label: "to.kala.reach.peer-connection"))
        read(connection, collected: Data())
    }

    private func read(_ connection: NWConnection, collected: Data) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { [weak self] data, _, finished, error in
            guard let self else { return }
            var collected = collected
            if let data { collected.append(data) }
            if let request = self.parse(collected) {
                Task {
                    let response = request.authorised ? await self.handler(request.value) : PeerResponse(status: 401, body: Data())
                    self.send(response, on: connection)
                }
            } else if finished || error != nil || collected.count > 262_144 {
                connection.cancel()
            } else {
                self.read(connection, collected: collected)
            }
        }
    }

    /// The request, once the head and the whole body have arrived.
    private func parse(_ data: Data) -> (value: PeerRequest, authorised: Bool)? {
        guard let end = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = String(decoding: data[..<end.lowerBound], as: UTF8.self)
        let lines = head.components(separatedBy: "\r\n")
        let first = (lines.first ?? "").split(separator: " ")
        guard first.count >= 2 else { return nil }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            if let colon = line.firstIndex(of: ":") {
                headers[line[..<colon].lowercased()] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            }
        }
        let length = max(0, min(Int(headers["content-length"] ?? "0") ?? 0, 262_144))
        let body = data[end.upperBound...]
        guard body.count >= length else { return nil }
        let request = PeerRequest(method: String(first[0]), path: String(first[1]), body: Data(body.prefix(length)))
        return (request, headers["x-peer-token"] == token)
    }

    private func send(_ response: PeerResponse, on connection: NWConnection) {
        let head = "HTTP/1.1 \(response.status) X\r\ncontent-type: text/plain\r\ncontent-length: \(response.body.count)\r\nconnection: close\r\n\r\n"
        connection.send(content: Data(head.utf8) + response.body, completion: .contentProcessed { _ in connection.cancel() })
    }
}
#endif
