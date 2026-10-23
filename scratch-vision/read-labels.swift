import AppKit
import Vision

let labels = ["Attention", "Sessions", "Hosts", "Account"]
guard CommandLine.arguments.count == 2,
    let image = NSImage(contentsOfFile: CommandLine.arguments[1]),
    let picture = image.cgImage(forProposedRect: nil, context: nil, hints: nil)
else {
    FileHandle.standardError.write(Data("read-labels: no image to read\n".utf8))
    exit(2)
}
let request = VNRecognizeTextRequest()
request.recognitionLevel = .accurate
request.usesLanguageCorrection = false
do {
    try VNImageRequestHandler(cgImage: picture, options: [:]).perform([request])
} catch {
    FileHandle.standardError.write(Data("read-labels: the text could not be recognised: \(error)\n".utf8))
    exit(2)
}
let read = (request.results ?? []).compactMap { $0.topCandidates(1).first?.string }
print("text read from the screen: \(read.joined(separator: " | "))")
// Each label is a line of its own on the tab bar: a line that equals it, so that the word in a
// sentence of the page does not count.
let missing = labels.filter { label in
    !read.contains { $0.trimmingCharacters(in: .whitespaces).caseInsensitiveCompare(label) == .orderedSame }
}
if !missing.isEmpty {
    print("labels not found: \(missing.joined(separator: ", "))")
    exit(1)
}
