// swift-tools-version:3.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PeacemakrCoreCrypto",
    products: [
        .library(
            name: "PeacemakrCoreCrypto",
            targets: ["PeacemakrCoreCrypto"]),
    ],
    targets: [
        .target(
            name: "PeacemakrCoreCrypto",
            dependencies: []),
        .testTarget(
            name: "PeacemakrCoreCryptoTests",
            dependencies: ["PeacemakrCoreCrypto"]),
    ]
)
