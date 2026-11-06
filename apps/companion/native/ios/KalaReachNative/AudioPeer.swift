//
//  The other end of a device run's call: a peer in this process that answers the call's offer and
//  sends and receives audio, so that the call's media is measured by what each end receives.
//
//  A script puts `kr-probe/peer.json` in the application's data directory, naming a loopback port
//  and a token. The peer serves two routes on that port, and only to a request that carries the
//  token. `POST /answer` takes the call's offer and answers with the peer's own answer, marked as
//  the provider's is (an ICE-lite agent), and the stand-in voice service on the machine the
//  application runs beside relays it as the provider's. `GET /figures` says what the peer received
//  and sent, and what the system's lock screen holds for the call.
//
//  The peer's audio is its own: a second factory with an audio device that makes a tone for its
//  microphone and takes what it is played, and opens neither the audio session nor the
//  microphone. It shares nothing with the call's factory and its audio unit.
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
        var tone = [Int16](repeating: 0, count: Self.frames)
        var drain = [Int16](repeating: 0, count: Self.frames)
        let step = 2 * Double.pi * 440 / Double(Self.rate)
        while !Thread.current.isCancelled {
            let (delegate, recording, playing) = locked { (self.delegate, self.recording, self.playing) }
            guard let delegate else { break }
            if recording {
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
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

/// The peer: a peer connection with an audio device of its own, and the two routes.
final class AudioPeer: NSObject, RTCPeerConnectionDelegate, @unchecked Sendable {
    /// Kept alive for the life of the process.
    private static var running: AudioPeer?

    private let device = SyntheticAudioDevice()
    private let factory: RTCPeerConnectionFactory
    private let token: String
    private let lock = NSLock()
    private var connection: RTCPeerConnection?
    private var waiting: CheckedContinuation<Void, Never>?
    private var addressFound = false
    private var server: PeerServer?

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
        switch (request.method, request.path) {
        case ("POST", "/answer"):
            let offer = String(decoding: request.body, as: UTF8.self)
            do {
                return PeerResponse(status: 200, body: Data(try await answer(offer).utf8))
            } catch {
                return PeerResponse(status: 500, body: Data("\(error)".utf8))
            }
        case ("GET", "/figures"):
            let text = (try? JSONSerialization.data(withJSONObject: await figures(), options: [.sortedKeys])) ?? Data("{}".utf8)
            return PeerResponse(status: 200, body: text)
        default:
            return PeerResponse(status: 404, body: Data())
        }
    }

    /// Applies `offer` and answers it, with the candidates this peer has found by its first,
    /// marked as the provider's answer is.
    func answer(_ offer: String) async throws -> String {
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
        return Self.asIceLite(made.localDescription?.sdp ?? answer.sdp)
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
    func peerConnection(_: RTCPeerConnection, didOpen _: RTCDataChannel) {}
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
