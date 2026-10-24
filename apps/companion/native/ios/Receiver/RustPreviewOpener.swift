//
//  Opening a sealed preview, with the Rust library's own function.
//
//  The envelope is sealed with the shared client's construction, and the library that opens it is
//  linked into the notification extension as a static library of its own (`companion-preview`):
//  the extension is a separate process with its own binary, and carries this function and what it
//  depends on, not the application. No second implementation of the construction is written here,
//  because two implementations of one sealing construction is how they come to disagree.
//
//  The application does not compile this file: it never opens a preview.
//

import Foundation

// The library's two functions, by their C names. They are exported by `companion-preview` and kept
// by it.
@_silgen_name("kr_preview_open")
private func krPreviewOpen(
    _ input: UnsafePointer<CChar>,
    _ seed: UnsafePointer<UInt8>,
    _ seedLength: Int
) -> UnsafeMutablePointer<CChar>?

@_silgen_name("kr_preview_free")
private func krPreviewFree(_ pointer: UnsafeMutablePointer<CChar>?)

/// The opener this build carries.
struct RustPreviewOpener: PreviewOpening {
    func open(
        preview: String,
        alert: String,
        seed: Data,
        senderKey: Data,
        nowMilliseconds: UInt64
    ) -> PreviewOpened {
        guard
            let input = PreviewOpenerJson.input(
                preview: preview, senderKey: senderKey, alert: alert, nowMilliseconds: nowMilliseconds)
        else { return .refused("input") }
        // The seed is held only for the call, and cleared after it.
        var held = [UInt8](seed)
        defer { for index in held.indices { held[index] = 0 } }
        let answered: UnsafeMutablePointer<CChar>? = input.withCString { text in
            held.withUnsafeBufferPointer { bytes in
                guard let base = bytes.baseAddress else { return nil }
                return krPreviewOpen(text, base, bytes.count)
            }
        }
        guard let answered else { return .refused("answer") }
        defer { krPreviewFree(answered) }
        return PreviewOpenerJson.answer(String(cString: answered))
    }
}
