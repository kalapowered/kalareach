// swift-tools-version:5.5

import PackageDescription

// The iOS sign-in session's rules, apart from the plugin so that they build and test on a Mac with
// `swift test`: which callback a session takes, that it is ephemeral, and which attempt a
// completion belongs to, and how the plugin reaches the application's voice call.
let package = Package(
  name: "companion-session",
  platforms: [
    .iOS("17.0"),
    .macOS("14.0"),
  ],
  products: [
    .library(name: "CompanionSession", targets: ["CompanionSession"]),
    .library(name: "CompanionCallLink", targets: ["CompanionCallLink"]),
  ],
  targets: [
    .target(name: "CompanionSession"),
    .testTarget(name: "CompanionSessionTests", dependencies: ["CompanionSession"]),
    .target(name: "CompanionCallLink"),
    .testTarget(name: "CompanionCallLinkTests", dependencies: ["CompanionCallLink"]),
  ]
)
