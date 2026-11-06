//
//  What a call's media has carried, and when audio was first played out of the device.
//
//  Both come from the connection's statistics and nothing else: the audio unit is WebRTC's own and
//  hands this code no buffer. So the first audio played out is an estimate. The statistics are read
//  a few times a second while the audio device is on, and the estimate is the first reading in which
//  the audio the connection received had energy and the speaker side had taken more samples than in
//  the reading before, with playback on, unmuted and uninterrupted when the reading was asked for
//  and when it was answered. A reading that is missing, that comes from before playback was on, or
//  that spans a change of it, counts as none and starts the comparison again.
//

import Foundation

/// What a call's media has carried. A figure the statistics did not hold is nil, never zero.
public struct MediaCounters: Equatable, Sendable {
    public var packetsReceived: Int64?
    public var packetsSent: Int64?
    public var playedSamples: Int64?

    public init(packetsReceived: Int64? = nil, packetsSent: Int64? = nil, playedSamples: Int64? = nil) {
        self.packetsReceived = packetsReceived
        self.packetsSent = packetsSent
        self.playedSamples = playedSamples
    }

    /// The wire's object, with a figure left out when it is nil.
    var wire: [String: Any] {
        var object: [String: Any] = [:]
        if let packetsReceived { object["packetsReceived"] = packetsReceived }
        if let packetsSent { object["packetsSent"] = packetsSent }
        if let playedSamples { object["playedSamples"] = playedSamples }
        return object
    }
}

/// One reading of the audio the connection received and the speaker side took.
public struct MediaReading: Equatable, Sendable {
    /// The inbound audio's total energy, which grows with decoded audio that is not silent.
    public var audioEnergy: Double?
    /// The samples the speaker side has taken to play.
    public var playedSamples: Double?

    public init(audioEnergy: Double?, playedSamples: Double?) {
        self.audioEnergy = audioEnergy
        self.playedSamples = playedSamples
    }
}

/// Watches readings for the first audio played out, and says so once.
public struct PlayoutWatch: Sendable {
    private var before: MediaReading?
    private var told = false

    public init() {}

    /// The speaker side was switched on or off since the last reading was asked for: what was read
    /// before is no baseline for what is read next, whatever the state is now.
    public mutating func playbackChanged() { before = nil }

    /// Takes one reading. `playbackOnAtRequest` and `playbackOnAtAnswer` are whether playback was
    /// on, unmuted and uninterrupted when the statistics were asked for and when they came back.
    /// Returns true once: at the first reading, after one valid one, in which both figures grew.
    public mutating func reading(
        _ reading: MediaReading?,
        playbackOnAtRequest: Bool,
        playbackOnAtAnswer: Bool
    ) -> Bool {
        guard !told else { return false }
        guard
            playbackOnAtRequest, playbackOnAtAnswer,
            let reading, let energy = reading.audioEnergy, let samples = reading.playedSamples
        else {
            before = nil
            return false
        }
        let previous = before
        before = reading
        guard let previous, let earlier = previous.audioEnergy, let taken = previous.playedSamples else {
            return false
        }
        guard energy > earlier, samples > taken else { return false }
        told = true
        return true
    }
}
