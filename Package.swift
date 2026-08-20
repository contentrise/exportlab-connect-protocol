// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ExportlabConnectProtocol",
    platforms: [.macOS(.v15), .iOS(.v17)],
    products: [
        .library(name: "ExportlabConnectProtocol", targets: ["ExportlabConnectProtocol"]),
    ],
    targets: [
        .target(
            name: "ExportlabConnectProtocol",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "ExportlabConnectProtocolTests",
            dependencies: ["ExportlabConnectProtocol"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
