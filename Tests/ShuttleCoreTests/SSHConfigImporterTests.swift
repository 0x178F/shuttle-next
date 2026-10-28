import Testing
import Foundation
import Darwin
import ShuttleCore

struct SSHConfigImporterTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNextImportTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func sshIncludesQuotedGlobAliasesCyclesAndInheritedFields() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let includes = directory.appendingPathComponent("Config Parts", isDirectory: true)
        try FileManager.default.createDirectory(at: includes, withIntermediateDirectories: true)
        let root = directory.appendingPathComponent("custom config")
        let first = includes.appendingPathComponent("01.conf")
        let second = includes.appendingPathComponent("02.conf")
        let rootText = "Include \"\(includes.path)/*.conf\"\nHost Direct direct *.wild !negated\n User ignored\n Port 2200\n IdentityFile /not/copied\n"
        try rootText.write(to: root, atomically: true, encoding: .utf8)
        try "Host Included\nInclude \"\(root.path)\"\n".write(to: first, atomically: true, encoding: .utf8)
        try "Host=Second # comment\n".write(to: second, atomically: true, encoding: .utf8)
        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Included", "Second", "Direct"])
        for candidate in result.candidates {
            #expect(candidate.profile.sshConfigPath == root.standardizedFileURL.path)
            #expect(candidate.profile.user == "")
            #expect(candidate.profile.port == nil)
            #expect(candidate.profile.identityFile == "")
            #expect(candidate.profile.identity == .automatic)
            #expect(candidate.profile.passwordMode == .askWhenNeeded)
        }
        #expect(try String(contentsOf: root, encoding: .utf8) == rootText)
    }

    @Test func sshQuotesCommentsAndLiteralBackslashesPreserveTokenBoundaries() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let first = directory.appendingPathComponent("part \"quoted\" #one.conf")
        let second = directory.appendingPathComponent("part#two.conf")
        try "Host 'First'\n".write(to: first, atomically: true, encoding: .utf8)
        try "Host Second\n".write(to: second, atomically: true, encoding: .utf8)
        let root = directory.appendingPathComponent("config")
        let text = """
        Include '\(first.path)'
        Include \(second.path)
        Host "Double" 'Single' Bare#Suffix rejected\\name # trailing comment
        Host Neighbor
        """
        try text.write(to: root, atomically: true, encoding: .utf8)

        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["First", "Second", "Double", "Single", "Neighbor"])
        #expect(try String(contentsOf: root, encoding: .utf8) == text)
    }

    @Test func sshRelativeIncludesUseOpenSSHUserRootEvenWhenNested() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("root")
        let child = directory.appendingPathComponent("child.conf")
        let grandchild = directory.appendingPathComponent("grandchild.conf")
        // Resolve relative fixture paths without touching the user's ~/.ssh directory.
        let upward = Array(repeating: "..", count: FileManager.default.homeDirectoryForCurrentUser.pathComponents.count).joined(separator: "/")
        func relative(_ url: URL) -> String { upward + "/" + url.path.dropFirst() }
        try "Include \"\(relative(child))\"\n".write(to: root, atomically: true, encoding: .utf8)
        try "Host Child\nInclude \"\(relative(grandchild))\"\n".write(to: child, atomically: true, encoding: .utf8)
        try "Host Grandchild\n".write(to: grandchild, atomically: true, encoding: .utf8)
        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Child", "Grandchild"])
    }

    @Test func sshMatchDoesNotExecuteOrImportConditionalInclude() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let marker = directory.appendingPathComponent("must-not-exist")
        let conditional = directory.appendingPathComponent("conditional")
        try "Host ShouldNotImport\n".write(to: conditional, atomically: true, encoding: .utf8)
        let root = directory.appendingPathComponent("config")
        let text = "Host *\n User default\nMatch exec \"touch \(marker.path)\"\n Include \"\(conditional.path)\"\n User ignored\nHost Safe\n"
        try text.write(to: root, atomically: true, encoding: .utf8)
        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Safe"])
        #expect(!FileManager.default.fileExists(atPath: marker.path))
    }

    @Test func sshRuntimeIncludesDoNotExpandOrRevealInput() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("config")
        try "Include ${SHUTTLENEXT_SYNTHETIC_SECRET}/config\nHost Safe\n".write(to: root, atomically: true, encoding: .utf8)
        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Safe"])
        #expect(!result.warnings.map { AppLocalizer(language: .en).text($0) }.joined().contains("SHUTTLENEXT_SYNTHETIC_SECRET"))
    }

    @Test func sshIncludeDepthIsBounded() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let files = (0..<64).map { directory.appendingPathComponent("level-\($0).conf") }
        for index in files.indices {
            var text = "Host Level\(index)\n"
            if index + 1 < files.count { text += "Include \"\(files[index + 1].path)\"\n" }
            if index == 0 { text += "Host RootNeighbor\n" }
            try text.write(to: files[index], atomically: true, encoding: .utf8)
        }
        let result = try SSHConfigImporter.importProfiles(from: files[0])
        #expect(result.candidates.first?.profile.host == "Level0")
        #expect(!result.candidates.contains { $0.profile.host == "Level63" })
        #expect(result.candidates.last?.profile.host == "RootNeighbor")
    }

    @Test func sshIncludePatternWorkIsCumulativeAndKeepsTopLevelNeighbors() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let root = directory.appendingPathComponent("config")
        let lateInclude = directory.appendingPathComponent("late.conf")
        try "Host BeyondWorkLimit\n".write(to: lateInclude, atomically: false, encoding: .utf8)
        let missing = "\"\(directory.path)/missing-*\""
        let patterns = Array(repeating: missing, count: 5_000).joined(separator: " ")
        let text = "Host Before\nInclude \(patterns)\nInclude \"\(lateInclude.path)\"\nHost After\n"
        try text.write(to: root, atomically: false, encoding: .utf8)

        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Before", "After"])
        #expect(try String(contentsOf: root, encoding: .utf8) == text)
    }

    @Test func sshOversizedRepeatedGlobsStopBeforeLaterIncludesAndKeepNeighbors() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let parts = directory.appendingPathComponent("parts", isDirectory: true)
        try FileManager.default.createDirectory(at: parts, withIntermediateDirectories: true)
        for index in 0..<1_000 {
            try Data("Host Included\(index)\n".utf8).write(to: parts.appendingPathComponent("\(index).conf"))
        }
        let root = directory.appendingPathComponent("config")
        let lateInclude = directory.appendingPathComponent("late.conf")
        try "Host BeyondExpansionLimit\n".write(to: lateInclude, atomically: false, encoding: .utf8)
        let pattern = "\"\(parts.path)/*.conf\""
        let patterns = Array(repeating: pattern, count: 5_000).joined(separator: " ")
        try "Host Before\nInclude \(patterns)\nInclude \"\(lateInclude.path)\"\nHost After\n"
            .write(to: root, atomically: false, encoding: .utf8)

        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Before", "After"])
    }

    @Test func sshInvalidIncludesKeepTopLevelNeighborsAndLeaveInputsUntouched() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let fifo = directory.appendingPathComponent("pipe")
        try #require(mkfifo(fifo.path, mode_t(0o600)) == 0)
        let oversized = directory.appendingPathComponent("oversized")
        try Data().write(to: oversized)
        let handle = try FileHandle(forWritingTo: oversized)
        try handle.truncate(atOffset: 8 * 1024 * 1024 + 1)
        try handle.close()
        let invalidText = directory.appendingPathComponent("invalid-utf8")
        let original = Data([0xFF])
        try original.write(to: invalidText)
        let root = directory.appendingPathComponent("config")
        try "Host Before\nInclude \"\(fifo.path)\" \"\(directory.path)\" \"\(oversized.path)\" \"\(invalidText.path)\"\nHost After\n"
            .write(to: root, atomically: false, encoding: .utf8)

        let result = try SSHConfigImporter.importProfiles(from: root)
        #expect(result.candidates.map(\.profile.host) == ["Before", "After"])
        #expect(try Data(contentsOf: invalidText) == original)
        var info = stat()
        #expect(lstat(fifo.path, &info) == 0)
        #expect((info.st_mode & S_IFMT) == S_IFIFO)
        let attributes = try FileManager.default.attributesOfItem(atPath: oversized.path)
        #expect((attributes[.size] as? NSNumber)?.intValue == 8 * 1024 * 1024 + 1)
    }
}
