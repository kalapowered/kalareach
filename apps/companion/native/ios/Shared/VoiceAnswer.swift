//
//  What the call reads of the provider's SDP answer.
//

import Foundation

/// A reader of the provider's SDP answer.
public enum VoiceAnswer {
    /// Whether the answer turns Opus discontinuous transmission on: an `a=fmtp` line of an Opus
    /// payload type with `usedtx=1`, in an audio section the answer accepted.
    ///
    /// With it on the sender stops the stream during silence, so a gap in the stream is no longer
    /// evidence that the microphone was closed. A section that carries no audio, or one the answer
    /// rejected (port 0), says nothing about the call's audio and is not read.
    public static func usesDtx(_ sdp: String) -> Bool {
        sections(sdp).filter { acceptedAudio($0[0]) }.contains { usesDtx(in: $0) }
    }

    /// The answer's media sections, each from its `m=` line to the line before the next.
    private static func sections(_ sdp: String) -> [[String]] {
        // By scalar, not by character: Swift reads a carriage return and a line feed together as
        // one character, which equals neither.
        var found: [[String]] = []
        for line in sdp.components(separatedBy: .newlines) where !line.isEmpty {
            if line.hasPrefix("m=") {
                found.append([line])
            } else if !found.isEmpty {
                found[found.count - 1].append(line)
            }
        }
        return found
    }

    /// `m=audio <port> ...` with a port other than 0.
    private static func acceptedAudio(_ mediaLine: String) -> Bool {
        let parts = mediaLine.split(separator: " ")
        return parts.count > 1 && parts[0] == "m=audio" && parts[1] != "0"
    }

    private static func usesDtx(in section: [String]) -> Bool {
        var opus = Set<String>()
        for line in section where line.hasPrefix("a=rtpmap:") {
            // a=rtpmap:111 opus/48000/2
            let parts = line.dropFirst("a=rtpmap:".count).split(separator: " ", maxSplits: 1)
            if parts.count == 2, parts[1].trimmingCharacters(in: .whitespaces).lowercased().hasPrefix("opus/") {
                opus.insert(String(parts[0]))
            }
        }
        for line in section where line.hasPrefix("a=fmtp:") {
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
