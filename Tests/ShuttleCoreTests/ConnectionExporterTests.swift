import Foundation
import Darwin
import Testing
import ShuttleCore

struct ConnectionExporterTests {
    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-export-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    @Test func portableMetadataRoundTripsWithoutEmbeddingReferencedFiles() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = directory.appendingPathComponent("private-key")
        let config = directory.appendingPathComponent("ssh-config")
        let keyContent = Data("private-key-content-must-stay-outside-export".utf8)
        let configContent = Data("Host secret-alias\n  ProxyCommand echo private-config-content\n".utf8)
        try keyContent.write(to: key)
        try configContent.write(to: config)
        let profile = ServerProfile(name: "Production", host: "production.example.test", user: "deploy", port: 2202,
                                    group: "Work", identity: .privateKey, passwordMode: .keychain,
                                    identityFile: key.path, isFavorite: true, sshConfigPath: config.path, notes: "Keep these notes")
        let destination = directory.appendingPathComponent("connections.json")
        try ConnectionExporter.exportProfiles([profile], to: destination)
        let data = try Data(contentsOf: destination)
        let decoded = try JSONDecoder().decode(LibraryDocument.self, from: data)
        #expect(decoded.profiles == [profile])
        #expect(data.range(of: keyContent) == nil)
        #expect(data.range(of: Data("private-config-content".utf8)) == nil)
        #expect(try Data(contentsOf: key) == keyContent)
        #expect(try Data(contentsOf: config) == configContent)
        let imported = try ConnectionImporter.importProfiles(from: destination)
        try #require(imported.candidates.count == 1)
        let candidate = imported.candidates[0]
        #expect(candidate.profile.id != profile.id)
        var expected = profile
        expected.id = candidate.profile.id
        expected.passwordMode = .askWhenNeeded
        #expect(candidate.profile == expected)
        #expect(candidate.password == nil)
    }

    @Test func replacingExistingExportUsesPrivatePermissionsAndCompleteNewData() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("connections.json")
        try Data("old export with public permissions".utf8).write(to: destination)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: destination.path)
        let profiles = [ServerProfile(name: "New", host: "new.example.test")]
        try ConnectionExporter.exportProfiles(profiles, to: destination)
        let decoded = try JSONDecoder().decode(LibraryDocument.self, from: Data(contentsOf: destination))
        #expect(decoded.profiles == profiles)
        let permissions = try #require(FileManager.default.attributesOfItem(atPath: destination.path)[.posixPermissions] as? NSNumber)
        #expect(permissions.intValue & 0o777 == 0o600)
    }

    @Test func invalidAndOversizedExportsPreserveExistingDestination() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let destination = directory.appendingPathComponent("connections.json")
        let original = Data("keep existing backup".utf8)
        try original.write(to: destination)
        let profile = ServerProfile(name: "Valid", host: "valid.example.test")
        var duplicate = profile
        duplicate.host = "another.example.test"
        let tooMany = (0...10_000).map { ServerProfile(name: "Server \($0)", host: "host-\($0).example.test") }
        let tooLarge = ServerProfile(name: "Large", host: "large.example.test", notes: String(repeating: "x", count: 8 * 1024 * 1024))
        for profiles in [[profile, duplicate], [ServerProfile(name: "Invalid", host: "-bad")], tooMany, [tooLarge]] {
            #expect(throws: ShuttleError.self) { try ConnectionExporter.exportProfiles(profiles, to: destination) }
            #expect(try Data(contentsOf: destination) == original)
        }
    }

    @Test func nonregularDestinationsAreRejectedWithoutTouchingTheirTargets() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("existing.json")
        let original = Data("preserve symlink target".utf8)
        try original.write(to: target)
        let link = directory.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        let fifo = directory.appendingPathComponent("pipe.json")
        try #require(mkfifo(fifo.path, mode_t(0o600)) == 0)
        let profiles = [ServerProfile(name: "Safe", host: "safe.example.test")]
        for destination in [link, directory, fifo] {
            #expect(throws: ShuttleError.self) { try ConnectionExporter.exportProfiles(profiles, to: destination) }
        }
        #expect(try Data(contentsOf: target) == original)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)
    }
}
