// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ShuttleNext",
    defaultLocalization: "en",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ShuttleNext", targets: ["ShuttleNext"]),
        .executable(name: "ShuttleNextHelper", targets: ["ShuttleNextHelper"]),
    ],
    // Use standalone Swift Testing for Command Line Tools installations.
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", revision: "5ee435b15ad40ec1f644b5eb9d247f263ccd2170") // swift-6.2.4-RELEASE
    ],
    targets: [
        .target(name: "ShuttleCore", resources: [.process("Resources")], linkerSettings: [.linkedFramework("Security")]),
        .executableTarget(name: "ShuttleNext", dependencies: ["ShuttleCore"], linkerSettings: [.linkedFramework("Carbon")]),
        .executableTarget(name: "ShuttleNextHelper", dependencies: ["ShuttleCore"]),
        .testTarget(name: "ShuttleCoreTests", dependencies: [
            "ShuttleCore", .product(name: "Testing", package: "swift-testing")
        ]),
        .testTarget(name: "ShuttleNextTests", dependencies: [
            "ShuttleNext", "ShuttleCore", .product(name: "Testing", package: "swift-testing")
        ])
    ]
)
