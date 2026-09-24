// swift-tools-version:5.3

import PackageDescription

// The iOS half of the companion's platform plugin: the browser-backed authentication session.
// Tauri builds and links this package when the application is built for iOS; its decisions are
// taken in the plugin's Rust crate from the facts this half reports, and the session's own rules
// are the `Session` package beside it, which tests on a Mac.
let package = Package(
  name: "companion-platform",
  platforms: [
    .iOS(.v14)
  ],
  products: [
    .library(
      name: "companion-platform",
      type: .static,
      targets: ["companion-platform"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api"),
    .package(name: "companion-session", path: "Session"),
  ],
  targets: [
    .target(
      name: "companion-platform",
      dependencies: [
        .byName(name: "Tauri"),
        .product(name: "CompanionSession", package: "companion-session"),
      ],
      path: "Sources")
  ]
)
