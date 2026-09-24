// swift-tools-version:5.5

import PackageDescription

// The iOS sign-in session's rules, apart from the plugin so that they build and test on a Mac with
// `swift test`: which callback a session takes, that it is ephemeral, and which attempt a
// completion belongs to.
let package = Package(
  name: "companion-session",
  platforms: [
    .iOS(.v14),
    .macOS(.v10_13),
  ],
  products: [
    .library(name: "CompanionSession", targets: ["CompanionSession"])
  ],
  targets: [
    .target(name: "CompanionSession"),
    .testTarget(name: "CompanionSessionTests", dependencies: ["CompanionSession"]),
  ]
)
