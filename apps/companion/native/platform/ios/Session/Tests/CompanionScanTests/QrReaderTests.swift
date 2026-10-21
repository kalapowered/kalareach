import CoreGraphics
import Foundation
import ImageIO
import XCTest

@testable import CompanionScan

/// The pictures of the pairing fixtures' two QR codes, drawn as the host draws a code (low error
/// correction, a quiet zone of four modules), read back to the text the fixtures hold. The
/// pictures are the ones the host's own test holds equal to its drawing, so this is the phone's
/// decoder against what a host shows.
final class QrReaderTests: XCTestCase {
  /// The repository's pairing fixtures.
  private static let fixtures: URL = {
    var url = URL(fileURLWithPath: #filePath)
    // Tests/CompanionScanTests/QrReaderTests.swift, then up to the repository's root.
    for _ in 0..<9 { url.deleteLastPathComponent() }
    return url.appendingPathComponent("fixtures/pairing")
  }()

  private func texts() throws -> [String: String] {
    let data = try Data(contentsOf: Self.fixtures.appendingPathComponent("codes.json"))
    let object = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    let qr = object["qr"] as! [String: Any]
    return qr.compactMapValues { ($0 as? [String: Any])?["text"] as? String }
  }

  func testTheHostsDirectInvitationReadsBackAsTheFixtureHoldsIt() throws {
    let picture = try Data(contentsOf: Self.fixtures.appendingPathComponent("qr-direct.png"))
    XCTAssertEqual(QrReader.text(in: picture), try texts()["direct"])
  }

  func testTheHostsCodeInvitationReadsBackAsTheFixtureHoldsIt() throws {
    let picture = try Data(contentsOf: Self.fixtures.appendingPathComponent("qr-code.png"))
    XCTAssertEqual(QrReader.text(in: picture), try texts()["code"])
  }

  /// A photograph is brought down before it is read, and the largest code still reads.
  func testTheLargestCodeStillReadsWhenThePictureIsBroughtDown() throws {
    let picture = try Data(contentsOf: Self.fixtures.appendingPathComponent("qr-direct.png"))
    XCTAssertEqual(QrReader.text(in: picture, longestSide: 1024), try texts()["direct"])
  }

  func testAPictureWithNoCodeAndBytesThatAreNoPictureGiveNothing() throws {
    XCTAssertNil(QrReader.text(in: Data("not a picture".utf8)))
    let context = CGContext(
      data: nil, width: 64, height: 64, bitsPerComponent: 8, bytesPerRow: 0,
      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue)!
    context.setFillColor(gray: 0.5, alpha: 1)
    context.fill(CGRect(x: 0, y: 0, width: 64, height: 64))
    XCTAssertNil(QrReader.text(in: context.makeImage()!))
  }
}
