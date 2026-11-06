// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Huma",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Huma", targets: ["Huma"])],
    // Sparkle checks huma.social/appcast.xml for new versions and installs them (pinned; bump deliberately).
    dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.0")],
    targets: [
        .target(name: "HumaCore"),
        .executableTarget(name: "Huma", dependencies: ["HumaCore", .product(name: "Sparkle", package: "Sparkle")],
                          // Sparkle.framework ships inside the app, in Contents/Frameworks.
                          linkerSettings: [.unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])]),
        // Runs the proof engine's JavaScript on macOS's own JavaScriptCore instead of a bundled Node.js (extra/Resources/NoirEngine).
        .executableTarget(name: "HumaScriptHost", swiftSettings: [.swiftLanguageMode(.v5)]),
        .testTarget(name: "HumaCoreTests", dependencies: ["HumaCore"])
    ]
)
