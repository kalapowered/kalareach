import CoreGraphics
import CoreVideo
import Foundation
import ImageIO
import Vision

/// Reads a QR code from a picture or from a camera frame, with the system's own detector.
///
/// The text of a direct invitation's code holds the invitation's whole secret, so this is the one
/// place it is read, and what it answers goes no further than native code. A reader judges nothing
/// about the text: whether it is a KalaReach invitation is the application's own decision, made in
/// Rust where the host's tests reach it.
public enum QrReader {
  /// The text of the first QR code in `image`, or nil when it shows none.
  public static func text(in image: CGImage) -> String? {
    read(VNImageRequestHandler(cgImage: image, options: [:]))
  }

  /// The text of the first QR code in a camera frame, or nil when it shows none. `orientation` is
  /// how the frame is turned relative to the way it is held.
  public static func text(in frame: CVPixelBuffer, orientation: CGImagePropertyOrientation = .up) -> String? {
    read(VNImageRequestHandler(cvPixelBuffer: frame, orientation: orientation, options: [:]))
  }

  /// The text of the first QR code in the picture `data` holds, or nil when it holds none or is no
  /// picture. The picture is read in memory and never written, and is brought down to
  /// `longestSide` pixels on its longest side when it is larger: a photograph is much larger than
  /// a code needs, and a version-20 code, the largest a host draws, is read well at 2,048.
  public static func text(in data: Data, longestSide: Int = 2048) -> String? {
    guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
    let options: [CFString: Any] = [
      kCGImageSourceCreateThumbnailFromImageAlways: true,
      kCGImageSourceCreateThumbnailWithTransform: true,
      kCGImageSourceThumbnailMaxPixelSize: longestSide,
    ]
    guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary) else {
      return nil
    }
    return text(in: image)
  }

  private static func read(_ handler: VNImageRequestHandler) -> String? {
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    #if targetEnvironment(simulator)
      // The simulator has no accelerator for the detector's model-based revisions to run on: they cannot
      // create their context there, and the first revision (the constant for it is deprecated, the
      // revision is not) reads a QR code without one.
      request.revision = 1
    #endif
    do {
      try handler.perform([request])
    } catch {
      return nil
    }
    return request.results?.lazy.compactMap { $0.payloadStringValue }.first { !$0.isEmpty }
  }
}
