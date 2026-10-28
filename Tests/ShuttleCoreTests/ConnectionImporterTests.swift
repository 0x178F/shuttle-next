import Foundation
import Testing
import ShuttleCore

struct ConnectionImporterTests {
    private func temporaryDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-auto-import-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private func shuttleFile(_ hosts: [[String: Any]], in directory: URL) throws -> URL {
        let url = directory.appendingPathComponent("Shuttle Settings")
        let data = try JSONSerialization.data(withJSONObject: ["hosts": hosts, "terminal": "obsolete-nightly", "default_theme": "obsolete"])
        try data.write(to: url)
        return url
    }

    @Test func nestedLegacyPasswordAndPostHostOptions() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let secret = "a synthetic 'quoted' $ password; never execute"
        let quoted = "'" + secret.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let marker = directory.appendingPathComponent("must-not-run")
        let url = try shuttleFile([["Work": [["Europe": [
            ["name": "My Production Server", "cmd": "sshpass -p \(quoted) ssh root@192.0.2.8 -i '/tmp/a private key' -p2222"],
            ["name": "Unsafe", "cmd": "ssh example.test; touch '\(marker.path)'"]
        ]]]]], in: directory)
        let original = try Data(contentsOf: url)
        let result = try ConnectionImporter.importProfiles(from: url)
        let candidate = try #require(result.candidates.first)
        #expect(result.candidates.count == 1)
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains(secret))
        #expect(candidate.password == secret)
        #expect(candidate.profile.identity == .privateKey)
        #expect(candidate.profile.passwordMode == .keychain)
        #expect(candidate.profile.group == "Work / Europe")
        #expect(candidate.profile.name == "My Production Server")
        #expect(candidate.profile.host == "192.0.2.8")
        #expect(candidate.profile.user == "root")
        #expect(candidate.profile.port == 2222)
        #expect(candidate.profile.identityFile == "/tmp/a private key")
        let repository = ProfileRepository(directory: directory.appendingPathComponent("Library"))
        try repository.save(LibraryDocument(profiles: result.candidates.map(\.profile)))
        let saved = try String(contentsOf: repository.fileURL, encoding: .utf8)
        #expect(!saved.contains(secret))
        #expect(!saved.contains("sshpass"))
        #expect(try Data(contentsOf: url) == original)
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test func importedIdentityAndServerPasswordAreIndependent() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = try shuttleFile([
            ["name": "A quoted name", "cmd": "'/usr/bin/ssh' -l alice -p 2201 -i\"/tmp/Key With Spaces\" example.test"],
            ["name": "Agent", "cmd": "ssh example.test"],
            ["name": "Password", "cmd": "sshpass -p 'synthetic-password' ssh example.test"]
        ], in: directory)
        let result = try ConnectionImporter.importProfiles(from: url)
        try #require(result.candidates.count == 3)
        #expect(result.candidates[0].profile.identityFile == "/tmp/Key With Spaces")
        #expect(result.candidates[0].profile.identity == .privateKey)
        #expect(result.candidates[0].profile.passwordMode == .askWhenNeeded)
        #expect(result.candidates[0].password == nil)
        #expect(result.candidates[0].profile.user == "alice")
        #expect(result.candidates[0].profile.port == 2201)
        #expect(result.candidates[1].profile.identity == .automatic)
        #expect(result.candidates[1].profile.passwordMode == .askWhenNeeded)
        #expect(result.candidates[1].password == nil)
        #expect(result.candidates[2].profile.identity == .none)
        #expect(result.candidates[2].profile.passwordMode == .keychain)
        #expect(result.candidates[2].profile.identityFile.isEmpty)
        #expect(result.candidates[2].password == "synthetic-password")
    }

    @Test func unsupportedSyntaxNeverLeaksPasswordOrDropsOptions() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let secret = "synthetic-secret-9284"
        let commands = [
            "sshpass -p '\(secret)' ssh example.test; echo unsafe",
            "sshpass -p '\(secret)' ssh -o ProxyCommand=unsafe example.test",
            "sshpass -p '\(secret)' ssh example.test uptime",
            "sshpass -p '\(secret)' ssh $(unsafe)",
            "sshpass -p '\(secret)' ssh example.test | unsafe",
            "sshpass -p '\(secret)' ssh -J jump.test example.test",
            "sshpass -p '\(secret)' ssh -i /tmp/a -i /tmp/b example.test",
            "sshpass -p '\(secret)' ssh -i relative-key example.test",
            "sshpass -p '\(secret)' ssh -p 0 example.test",
            "sshpass -p '\(secret)' ssh example.test > /tmp/output",
            "sshpass -p '\(secret)' ssh \"`unsafe`\"",
            "echo '\(secret)'"
        ]
        let url = try shuttleFile(commands.map { ["name": "Unsafe", "cmd": $0] }, in: directory)
        let result = try ConnectionImporter.importProfiles(from: url)
        #expect(result.candidates.isEmpty)
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains(secret))
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains("ProxyCommand=unsafe"))
    }

    @Test func printablePrivateKeyPathsImportWhileControlCharactersRemainRejected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let asciiKey = "/tmp/id_ed25519"
        let unicodeKey = "/tmp/key-\u{00E9}"
        let source = try shuttleFile([
            ["name": "Plain key", "cmd": "ssh -i '\(asciiKey)' alice@192.0.2.10"],
            ["name": "Key and password", "cmd": "sshpass -p 'synthetic!password' ssh bob@192.0.2.20 -i '\(unicodeKey)'"],
            ["name": "Newline path", "cmd": "ssh -i '/tmp/key\nother' bad.example.test"],
            ["name": "NUL path", "cmd": "ssh -i '/tmp/key\0other' bad.example.test"]
        ], in: directory)
        let original = try Data(contentsOf: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        try #require(result.candidates.count == 2)
        let plain = try #require(result.candidates.first { $0.profile.name == "Plain key" })
        let combined = try #require(result.candidates.first { $0.profile.name == "Key and password" })
        #expect(plain.profile.identityFile == asciiKey)
        #expect(plain.profile.identity == .privateKey)
        #expect(plain.password == nil)
        #expect(combined.profile.identityFile == unicodeKey)
        #expect(combined.profile.identity == .privateKey)
        #expect(combined.profile.passwordMode == .keychain)
        #expect(combined.password == "synthetic!password")
        #expect(try Data(contentsOf: source) == original)
    }

    @Test func currentInventoryPreservesMetadataWithoutReusingKeychainIdentity() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let profile = ServerProfile(name: "Existing", host: "example.test", user: "deploy", port: 2202,
                                    group: "Work", identity: .privateKey, passwordMode: .keychain,
                                    identityFile: "/tmp/existing-key", isFavorite: true,
                                    sshConfigPath: "/tmp/trusted-config", notes: "Keep these notes")
        let original = try JSONEncoder().encode(LibraryDocument(profiles: [profile], settings: AppSettings(terminal: .iTerm, openMode: .tab)))
        let source = directory.appendingPathComponent("inventory.backup")
        try original.write(to: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        try #require(result.candidates.count == 1)
        let imported = result.candidates[0]
        #expect(imported.profile.id != profile.id)
        var expected = profile
        expected.id = imported.profile.id
        expected.passwordMode = .askWhenNeeded
        #expect(imported.profile == expected)
        #expect(imported.password == nil)
        #expect(try Data(contentsOf: source) == original)
    }

    @Test func oldOwnInventoryAndLongWhitespaceBOMAreConverted() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let oldID = UUID()
        let legacy: [String: Any] = [
            "version": 1,
            "settings": ["terminal": "terminal", "openMode": "window", "globalShortcutEnabled": false],
            "profiles": [["id": oldID.uuidString, "name": "Old app", "host": "old.example.test", "user": "root",
                          "port": 2222, "group": "Old group", "authentication": "password", "identityFile": "/tmp/old-key",
                          "isFavorite": true, "notes": "Old notes"]]
        ]
        var data = Data([0xEF, 0xBB, 0xBF])
        data.append(Data(String(repeating: " ", count: 5000).utf8))
        data.append(try JSONSerialization.data(withJSONObject: legacy))
        let source = directory.appendingPathComponent("old-backup")
        try data.write(to: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        let candidate = try #require(result.candidates.first)
        #expect(candidate.profile.id != oldID)
        #expect(candidate.profile.identity == .privateKey)
        #expect(candidate.profile.identityFile == "/tmp/old-key")
        #expect(candidate.profile.passwordMode == .askWhenNeeded)
        #expect(candidate.profile.group == "Old group")
        #expect(candidate.profile.notes == "Old notes")
        #expect(candidate.password == nil)
        #expect(try Data(contentsOf: source) == data)
    }

    @Test func classicArraySkipsInvalidEntriesWithoutDroppingValidNeighbors() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let object: [Any] = [42, ["name": "A", "cmd": "ssh a.example.test"],
                             ["Group": [false, ["name": "B", "cmd": "ssh b.example.test"]]]]
        let source = directory.appendingPathComponent("array.json")
        try JSONSerialization.data(withJSONObject: object).write(to: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        #expect(result.candidates.map(\.profile.name) == ["A", "B"])
        #expect(result.candidates.map(\.profile.group) == ["", "Group"])
    }

    @Test func originalShuttleMenusPreserveNestedTitlesAndIgnoreEmptyMenus() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let object: [String: Any] = [
            "terminal": "Terminal.app", "iTerm_version": "nightly", "default_theme": "Homebrew",
            "hosts": [
                ["KNS": [
                    ["name": "Direct", "cmd": "ssh deploy@direct.example.test", "theme": "basic"],
                    ["Databases": [["name": "Nested", "cmd": "ssh -p2222 -i '~/.ssh/a key' db.example.test",
                                    "inTerminal": "tab", "title": "old title"]]]
                ]],
                ["My": []],
                ["cmd": [["name": "Reserved cmd", "cmd": "ssh cmd.example.test"]]],
                ["name": [["name": "Reserved name", "cmd": "ssh name.example.test"]]],
                ["hosts": [["name": "Reserved hosts", "cmd": "ssh hosts.example.test"]]]
            ]
        ]
        let source = directory.appendingPathComponent("shuttle.json")
        let original = try JSONSerialization.data(withJSONObject: object)
        try original.write(to: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        #expect(result.candidates.map(\.profile.name) == ["Direct", "Nested", "Reserved cmd", "Reserved name", "Reserved hosts"])
        #expect(result.candidates.map(\.profile.group) == ["KNS", "KNS / Databases", "cmd", "name", "hosts"])
        let nested = try #require(result.candidates.first(where: { $0.profile.name == "Nested" }))
        #expect(nested.profile.identityFile == (("~/.ssh/a key" as NSString).expandingTildeInPath))
        #expect(nested.profile.identity == .privateKey)
        #expect(nested.profile.port == 2222)
        #expect(try Data(contentsOf: source) == original)
    }

    @Test func originalShuttleDeepGroupsDoNotHideValidNeighborsOrLeakCommands() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let marker = directory.appendingPathComponent("must-not-run")
        var nested: [String: Any] = ["name": "Too deep", "cmd": "ssh deep.example.test"]
        for index in 0..<34 { nested = ["Group \(index)": [nested]] }
        let object: [String: Any] = ["hosts": [nested, ["Valid": [
            ["name": "Unsafe secret title", "cmd": "sshpass -p 'synthetic-secret' ssh bad.example.test; touch '\(marker.path)'"],
            ["name": "Healthy", "cmd": "ssh healthy.example.test"]
        ]]]]
        let source = directory.appendingPathComponent("shuttle.json")
        try JSONSerialization.data(withJSONObject: object).write(to: source)
        let result = try ConnectionImporter.importProfiles(from: source)
        #expect(result.candidates.map(\.profile.host) == ["healthy.example.test"])
        #expect(result.candidates.map(\.profile.group) == ["Valid"])
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains("synthetic-secret"))
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains("Unsafe secret title"))
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test func sshConfigIsDetectedAndNeverExecutesMatch() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let marker = directory.appendingPathComponent("must-not-run")
        let source = directory.appendingPathComponent("config")
        let text = "Host imported-alias\n HostName 192.0.2.8\nMatch exec \"touch '\(marker.path)'\"\n User conditional\n"
        try text.write(to: source, atomically: true, encoding: .utf8)
        let result = try ConnectionImporter.importProfiles(from: source)
        let candidate = try #require(result.candidates.first)
        #expect(candidate.profile.host == "imported-alias")
        #expect(candidate.profile.sshConfigPath == source.standardizedFileURL.path)
        #expect(candidate.profile.user.isEmpty)
        #expect(!FileManager.default.fileExists(atPath: marker.path))
        #expect(try String(contentsOf: source, encoding: .utf8) == text)
    }

    @Test("Reject invalid imports without leaking source data or changing the file", arguments: ["future", "duplicates", "invalid-profile", "malformed"])
    func invalidInventoriesRemainUnchanged(kind: String) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let secret = "synthetic-must-not-appear-in-error"
        let profile = ServerProfile(name: "Safe", host: "safe.example.test", notes: secret)
        var object = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(LibraryDocument(profiles: [profile]))) as? [String: Any])
        object["hosts"] = [["name": "Must not import", "cmd": "ssh legacy.example.test"]]
        var profiles = try #require(object["profiles"] as? [[String: Any]])
        switch kind {
        case "future": object["version"] = 999
        case "duplicates": object["profiles"] = profiles + profiles
        case "invalid-profile":
            profiles[0]["host"] = "-oProxyCommand=\(secret)"
            object["profiles"] = profiles
        default: break
        }
        let data: Data
        if kind == "malformed" { data = Data("{\"profiles\": [broken \(secret)".utf8) }
        else { data = try JSONSerialization.data(withJSONObject: object) }
        let source = directory.appendingPathComponent("bad.json")
        try data.write(to: source)
        do {
            _ = try ConnectionImporter.importProfiles(from: source)
            Issue.record("Invalid inventory unexpectedly imported")
        } catch { #expect(!error.localizedDescription.contains(secret)) }
        #expect(try Data(contentsOf: source) == data)
    }

    @Test func oversizedAndNonRegularInputsAreRejected() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let source = directory.appendingPathComponent("oversized.json")
        try Data().write(to: source)
        let handle = try FileHandle(forWritingTo: source)
        try handle.truncate(atOffset: 8 * 1024 * 1024 + 1)
        try handle.close()
        #expect(throws: ShuttleError.self) { try ConnectionImporter.importProfiles(from: source) }
        #expect(throws: ShuttleError.self) { try ConnectionImporter.importProfiles(from: directory) }
        let attributes = try FileManager.default.attributesOfItem(atPath: source.path)
        #expect((attributes[.size] as? NSNumber)?.intValue == 8 * 1024 * 1024 + 1)
    }
}
