//
//  Opening a sealed preview.
//
//  The envelope is sealed with the shared client's own construction: a 24-byte nonce and a public
//  key sealing primitive whose implementation lives in the native client library. That library is
//  linked into the application, not into this extension, and an extension is a separate process
//  with its own binary.
//
//  Until this extension links that primitive, there is nothing here that can open an envelope, and
//  the honest answer is to say so: the decision then shows the generic alert, which is exactly what
//  the specification asks for when a preview cannot be opened. Nothing is faked and no second
//  implementation of the construction is written here, because two implementations of one sealing
//  construction is how they come to disagree.
//

import Foundation

/// The opener this build carries.
struct SharedClientPreviewOpener: PreviewOpening {
    func open(envelope: PreviewEnvelope, key: Data) throws -> String {
        _ = envelope
        _ = key
        throw PreviewOpenFailure.unavailable
    }
}
