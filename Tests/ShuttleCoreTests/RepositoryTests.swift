import Testing
import Foundation
import Darwin
import Dispatch
import ShuttleCore

struct RepositoryTests {
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNextRepositoryTests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func missingLibraryAndPrivateRoundTrip() throws {
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let directory = root.appendingPathComponent("Private Library", isDirectory: true)
        let repository = ProfileRepository(directory: directory)
        #expect(try repository.load() == LibraryDocument())
        let profile = ServerProfile(name: "  Production  ", host: "example.test", user: "alice", port: 2222,
                                    group: "Work", identity: .privateKey, passwordMode: .keychain,
                                    identityFile: "/tmp/private_key", isFavorite: true,
                                    sshConfigPath: "/tmp/trusted-config", notes: "Keep this note")
        let document = LibraryDocument(profiles: [profile], settings: AppSettings(terminal: .iTerm, openMode: .tab))
        try repository.save(document)
        let loaded = try repository.load()
        var expected = profile
        expected.name = "Production"
        #expect(loaded == LibraryDocument(profiles: [expected], settings: document.settings))
        let directoryAttributes = try FileManager.default.attributesOfItem(atPath: directory.path)
        let fileAttributes = try FileManager.default.attributesOfItem(atPath: repository.fileURL.path)
        #expect((directoryAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700)
        #expect((fileAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
    }

    @Test func versionTwoWithoutLanguageLoadsWithoutRewriting() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let profile = ServerProfile(name: "Existing", host: "example.test", notes: "Keep this note")
        let encoded = try JSONEncoder().encode(LibraryDocument(profiles: [profile]))
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        var settings = try #require(object["settings"] as? [String: Any])
        settings.removeValue(forKey: "language")
        object["settings"] = settings
        let original = try JSONSerialization.data(withJSONObject: object)
        try original.write(to: repository.fileURL)

        let loaded = try repository.load()
        #expect(loaded.settings.language == .system)
        #expect(loaded.profiles == [profile])
        #expect(try Data(contentsOf: repository.fileURL) == original)
    }

    @Test func explicitLanguagesSurviveRepositoryRoundTrip() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let profile = ServerProfile(name: "Existing", host: "example.test")
        for language in AppLanguage.allCases {
            let document = LibraryDocument(profiles: [profile], settings: AppSettings(language: language))
            try repository.save(document)
            #expect(try repository.load() == document)
        }
    }

    @Test func unknownLanguageFallsBackWithoutLosingServersOrRewriting() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let profile = ServerProfile(name: "Existing", host: "example.test", notes: "Keep this note")
        let encoded = try JSONEncoder().encode(LibraryDocument(profiles: [profile]))
        var object = try #require(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        var settings = try #require(object["settings"] as? [String: Any])
        settings["language"] = "future-language"
        object["settings"] = settings
        let original = try JSONSerialization.data(withJSONObject: object)
        try original.write(to: repository.fileURL)

        let loaded = try repository.load()
        #expect(loaded.settings.language == .system)
        #expect(loaded.profiles == [profile])
        #expect(try Data(contentsOf: repository.fileURL) == original)
        try repository.save(loaded)
        #expect(try repository.load() == loaded)
    }

    @Test func malformedFileSurvivesLoadAndSave() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let damaged = Data("{\"profiles\": [broken".utf8)
        try damaged.write(to: repository.fileURL)
        #expect(throws: ShuttleError.self) { try repository.load() }
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument()) }
        #expect(try Data(contentsOf: repository.fileURL) == damaged)
    }

    @Test func fifoLibraryIsRejectedPromptlyWithoutReplacement() throws {
        for saving in [false, true] {
            let directory = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: directory) }
            let repository = ProfileRepository(directory: directory)
            try #require(mkfifo(repository.fileURL.path, mode_t(0o600)) == 0)
            let operationFinished = DispatchSemaphore(value: 0)
            let watchdogFinished = DispatchSemaphore(value: 0)
            let rescueUsed = DispatchSemaphore(value: 0)
            let path = repository.fileURL.path
            // A pre-fix blocking open is released after the deadline, so this
            // regression fails rather than hanging the entire test process.
            DispatchQueue.global().async {
                if operationFinished.wait(timeout: .now() + 2) == .timedOut {
                    let descriptor = open(path, O_RDWR | O_NONBLOCK | O_CLOEXEC)
                    rescueUsed.signal()
                    operationFinished.wait()
                    if descriptor >= 0 { close(descriptor) }
                }
                watchdogFinished.signal()
            }
            #expect(throws: ShuttleError.self) {
                if saving { try repository.save(LibraryDocument()) }
                else { _ = try repository.load() }
            }
            operationFinished.signal()
            watchdogFinished.wait()
            #expect(rescueUsed.wait(timeout: .now()) == .timedOut)
            var info = stat()
            #expect(lstat(path, &info) == 0)
            #expect((info.st_mode & S_IFMT) == S_IFIFO)
        }
    }

    @Test func credentialAccessExcludesOtherOwnersWithoutBlockingLibraryOperations() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        func probeLock(_ name: String, available: Bool) throws {
            let descriptor = open(directory.appendingPathComponent(name).path,
                                  O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
            defer { close(descriptor) }
            let status = flock(descriptor, LOCK_EX | LOCK_NB)
            let failure = errno
            if available {
                try #require(status == 0)
            } else {
                try #require(status == -1)
                #expect(failure == EWOULDBLOCK)
            }
        }
        let profile = ServerProfile(name: "Stored", host: "stored.example.test")
        let loaded = try repository.withCredentialAccess {
            // Fail before nested I/O if the locks are missing or accidentally merged.
            try probeLock(".credentials.lock", available: false)
            try probeLock(".library.lock", available: true)
            try repository.save(LibraryDocument(profiles: [profile]))
            return try repository.load()
        }
        #expect(loaded.profiles == [profile])
        for name in [".credentials.lock", ".library.lock"] {
            let attributes = try FileManager.default.attributesOfItem(atPath: directory.appendingPathComponent(name).path)
            #expect(attributes[.type] as? FileAttributeType == .typeRegular)
            #expect((attributes[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        }
        enum Expected: Error { case failure }
        #expect(throws: Expected.self) {
            try repository.withCredentialAccess { throw Expected.failure }
        }
        try probeLock(".credentials.lock", available: true)
        try probeLock(".library.lock", available: true)
    }

    @Test func bothLocksRejectSymbolicLinksAndNonRegularFiles() throws {
        for name in [".credentials.lock", ".library.lock"] {
            for symbolic in [false, true] {
                let directory = try temporaryDirectory()
                defer { try? FileManager.default.removeItem(at: directory) }
                let repository = ProfileRepository(directory: directory)
                let lock = directory.appendingPathComponent(name)
                let target = directory.appendingPathComponent("untouched")
                let original = Data("untouched".utf8)
                if symbolic {
                    try original.write(to: target)
                    try FileManager.default.createSymbolicLink(at: lock, withDestinationURL: target)
                } else {
                    try #require(mkfifo(lock.path, mode_t(0o600)) == 0)
                }
                #expect(throws: ShuttleError.self) {
                    if name == ".credentials.lock" { try repository.withCredentialAccess {} }
                    else { _ = try repository.load() }
                }
                var info = stat()
                #expect(lstat(lock.path, &info) == 0)
                #expect((info.st_mode & S_IFMT) == (symbolic ? S_IFLNK : S_IFIFO))
                if symbolic { #expect(try Data(contentsOf: target) == original) }
            }
        }
    }

    @Test func unsupportedSchemaSurvivesSave() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let newer = try JSONEncoder().encode(LibraryDocument(version: 999))
        try newer.write(to: repository.fileURL)
        #expect(throws: ShuttleError.self) { try repository.load() }
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument()) }
        #expect(try Data(contentsOf: repository.fileURL) == newer)
    }

    @Test func duplicateAndInvalidProfilesCannotReplaceLibrary() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let profile = ServerProfile(name: "Valid", host: "example.test")
        try repository.save(LibraryDocument(profiles: [profile]))
        let original = try Data(contentsOf: repository.fileURL)
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument(profiles: [profile, profile])) }
        #expect(throws: ShuttleError.self) {
            try repository.save(LibraryDocument(profiles: [ServerProfile(name: "Invalid", host: "-oProxyCommand=bad")]))
        }
        #expect(try Data(contentsOf: repository.fileURL) == original)
    }

    @Test func duplicateIdentifiersOnDiskArePreserved() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let profile = ServerProfile(name: "Same ID", host: "example.test")
        let duplicate = try JSONEncoder().encode(LibraryDocument(profiles: [profile, profile]))
        try duplicate.write(to: repository.fileURL)
        #expect(throws: ShuttleError.self) { try repository.load() }
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument()) }
        #expect(try Data(contentsOf: repository.fileURL) == duplicate)
    }

    @Test func symbolicLinkLibraryNeverReplacesTarget() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("untouched.json")
        let original = try JSONEncoder().encode(LibraryDocument(profiles: [
            ServerProfile(name: "Untouched", host: "untouched.example.test", notes: "Preserve this file")
        ]))
        try original.write(to: target)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: target.path)
        let repository = ProfileRepository(directory: directory.appendingPathComponent("Library"))
        try FileManager.default.createDirectory(at: repository.directory, withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(at: repository.fileURL, withDestinationURL: target)
        #expect(throws: ShuttleError.self) { try repository.load() }
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument()) }
        #expect(try Data(contentsOf: target) == original)
        let permissions = try FileManager.default.attributesOfItem(atPath: target.path)[.posixPermissions] as? NSNumber
        #expect(permissions?.intValue == 0o644)
    }

    @Test func versionOneMigrationPreservesCredentialsAndOnlyWritesOnSave() throws {
        let cases: [(String, String, SSHIdentity, ServerPasswordMode)] = [
            ("automatic", "", .automatic, .askWhenNeeded),
            ("automatic", "/tmp/configured-key", .privateKey, .askWhenNeeded),
            ("privateKey", "/tmp/chosen-key", .privateKey, .askWhenNeeded),
            ("password", "", .none, .keychain),
            ("password", "/tmp/combined-key", .privateKey, .keychain),
            ("askEveryTime", "/tmp/unused-key", .none, .askWhenNeeded)
        ]
        for (method, key, identity, passwordMode) in cases {
            let directory = try temporaryDirectory()
            defer { try? FileManager.default.removeItem(at: directory) }
            let repository = ProfileRepository(directory: directory)
            let id = UUID()
            let original = try legacyDocument(id: id, method: method, key: key)
            try original.write(to: repository.fileURL)
            let loaded = try repository.load()
            let expected = ServerProfile(id: id, name: "Existing", host: "example.test", user: "alice", port: 2222,
                                         group: "Work", identity: identity, passwordMode: passwordMode,
                                         identityFile: identity == .privateKey ? key : "", isFavorite: true,
                                         sshConfigPath: "/tmp/legacy-config", notes: "Keep this note")
            #expect(loaded.version == LibraryDocument.currentVersion)
            #expect(loaded.profiles == [expected])
            #expect(loaded.settings == AppSettings(terminal: .iTerm, openMode: .tab))
            #expect(try Data(contentsOf: repository.fileURL) == original)
            try repository.save(loaded)
            #expect(try repository.load() == loaded)
            let object = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: repository.fileURL)) as? [String: Any])
            #expect(object["version"] as? Int == LibraryDocument.currentVersion)
        }
    }

    @Test func invalidLegacyPrivateKeyPreservesOriginalLibrary() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let repository = ProfileRepository(directory: directory)
        let original = try legacyDocument(id: UUID(), method: "privateKey", key: "")
        try original.write(to: repository.fileURL)
        #expect(throws: ShuttleError.self) { try repository.load() }
        #expect(throws: ShuttleError.self) { try repository.save(LibraryDocument()) }
        #expect(try Data(contentsOf: repository.fileURL) == original)
    }

    private func legacyDocument(id: UUID, method: String, key: String) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "version": 1,
            "settings": ["terminal": "iTerm", "openMode": "tab", "globalShortcutEnabled": false],
            "profiles": [[
                "id": id.uuidString, "name": "Existing", "host": "example.test", "user": "alice",
                "port": 2222, "group": "Work", "authentication": method, "identityFile": key,
                "isFavorite": true, "sshConfigPath": "/tmp/legacy-config", "notes": "Keep this note"
            ]]
        ], options: [.sortedKeys])
    }
}
