//
//  What the call reads of the provider's SDP answer.
//

import Foundation

/// A reader of the provider's SDP answer.
public enum VoiceAnswer {
    /// Whether the answer turns Opus discontinuous transmission on: an `a=fmtp` line of an Opus
    /// payload type with `usedtx=1`.
    ///
    /// With it on the sender stops the stream during silence, so a gap in the stream is no longer
    /// evidence that the microphone was closed.
    public static func usesDtx(_ sdp: String) -> Bool {
        let lines = sdp.split(whereSeparator: { $0 == "\r" || $0 == "\n" }).map(String.init)
        var opus = Set<String>()
        for line in lines where line.hasPrefix("a=rtpmap:") {
            // a=rtpmap:111 opus/48000/2
            let parts = line.dropFirst("a=rtpmap:".count).split(separator: " ", maxSplits: 1)
            if parts.count == 2, parts[1].lowercased().hasPrefix("opus/") {
                opus.insert(String(parts[0]))
            }
        }
        for line in lines where line.hasPrefix("a=fmtp:") {
            // a=fmtp:111 minptime=10;useinbandfec=1
            let parts = line.dropFirst("a=fmtp:".count).split(separator: " ", maxSplits: 1)
            guard parts.count == 2, opus.contains(String(parts[0])) else { continue }
            for parameter in parts[1].split(separator: ";") {
                let pair = parameter.split(separator: "=", maxSplits: 1)
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                if pair.count == 2, pair[0].lowercased() == "usedtx", pair[1] == "1" {
                    return true
                }
            }
        }
        return false
    }
}
