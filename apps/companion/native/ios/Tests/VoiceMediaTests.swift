//
//  When audio is first played out of the device, read from the connection's statistics, and what
//  the media counters leave out.
//

import XCTest

final class VoiceMediaTests: XCTestCase {
    private func read(_ energy: Double?, _ samples: Double?) -> MediaReading {
        MediaReading(audioEnergy: energy, playedSamples: samples)
    }

    /// KR-PERF-010: the first audio played out is the first reading, after one valid one, in which
    /// both the energy of what was received and the samples the speaker took grew; it is told once.
    func testTheFirstGrowthOfBothFiguresIsTheFirstAudioAndIsToldOnce() {
        var watch = PlayoutWatch()
        XCTAssertFalse(watch.reading(read(0, 0), playbackOnAtRequest: true, playbackOnAtAnswer: true), "the first valid reading is the baseline")
        XCTAssertTrue(watch.reading(read(0.4, 480), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(watch.reading(read(0.9, 960), playbackOnAtRequest: true, playbackOnAtAnswer: true), "once")
    }

    /// KR-PERF-010: samples taken for silence are not audio: the speaker side runs at its own pace
    /// whatever was received, so only energy that grew with them counts.
    func testSilenceTheSpeakerPlaysIsNotAudio() {
        var watch = PlayoutWatch()
        for step in 0..<5 {
            XCTAssertFalse(
                watch.reading(read(0, Double(step) * 480), playbackOnAtRequest: true, playbackOnAtAnswer: true),
                "step \(step)"
            )
        }
        XCTAssertTrue(watch.reading(read(0.2, 3_000), playbackOnAtRequest: true, playbackOnAtAnswer: true))
    }

    /// KR-PERF-010: energy that grew with the speaker side muted, silenced or interrupted is not
    /// audio played out, and a reading that spans a change of that state is not one reading.
    func testNothingIsPlayedOutWhilePlaybackIsOffOrChangesDuringTheReading() {
        var watch = PlayoutWatch()
        XCTAssertFalse(watch.reading(read(0, 0), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(
            watch.reading(read(0.5, 480), playbackOnAtRequest: false, playbackOnAtAnswer: false),
            "playback was off"
        )
        XCTAssertFalse(
            watch.reading(read(0.9, 960), playbackOnAtRequest: true, playbackOnAtAnswer: false),
            "playback went off while the statistics were read"
        )
        XCTAssertFalse(
            watch.reading(read(1.4, 1_440), playbackOnAtRequest: false, playbackOnAtAnswer: true),
            "playback came on while the statistics were read"
        )
        // The comparison starts again from the next valid reading, not from before the break.
        XCTAssertFalse(watch.reading(read(1.4, 1_440), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertTrue(watch.reading(read(1.9, 1_920), playbackOnAtRequest: true, playbackOnAtAnswer: true))
    }

    /// KR-PERF-010: a reading that is missing, or has only one of the figures, counts as none and
    /// breaks the comparison; a stale one, equal to the last, shows no growth.
    func testAMissingOrStaleReadingIsNone() {
        var watch = PlayoutWatch()
        XCTAssertFalse(watch.reading(read(0, 0), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(watch.reading(nil, playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(
            watch.reading(read(0.5, 480), playbackOnAtRequest: true, playbackOnAtAnswer: true),
            "after a missing reading this one is a baseline"
        )
        XCTAssertFalse(watch.reading(read(0.5, nil), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(watch.reading(read(nil, 960), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(watch.reading(read(0.8, 960), playbackOnAtRequest: true, playbackOnAtAnswer: true))
        XCTAssertFalse(
            watch.reading(read(0.8, 960), playbackOnAtRequest: true, playbackOnAtAnswer: true),
            "a reading equal to the last shows no growth"
        )
        XCTAssertTrue(watch.reading(read(0.9, 1_440), playbackOnAtRequest: true, playbackOnAtAnswer: true))
    }

    /// The counters say only what was measured: a figure the statistics did not hold is left out of
    /// what is sent, so Rust never reads a missing figure as zero.
    func testTheCountersLeaveOutWhatWasNotMeasured() {
        XCTAssertTrue(MediaCounters().wire.isEmpty)
        let partial = MediaCounters(packetsReceived: 40).wire
        XCTAssertEqual(partial.count, 1)
        XCTAssertEqual(partial["packetsReceived"] as? Int64, 40)
        let all = MediaCounters(packetsReceived: 1, packetsSent: 2, playedSamples: 3).wire
        XCTAssertEqual(Set(all.keys), ["packetsReceived", "packetsSent", "playedSamples"])
    }
}
