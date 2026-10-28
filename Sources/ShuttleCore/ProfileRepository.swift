import Foundation
import Darwin

public final class ProfileRepository: Sendable {
    public let directory: URL
    public var fileURL: URL { directory.appendingPathComponent("library.json") }

    public init(directory: URL? = nil) {
        if let directory {
            self.directory = directory.standardizedFileURL
        } else if let override = ProcessInfo.processInfo.environment["SHUTTLENEXT_DATA_DIR"], !override.isEmpty {
            self.directory = URL(fileURLWithPath: override, isDirectory: true).standardizedFileURL
        } else {
            self.directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
                .appendingPathComponent("ShuttleNext", isDirectory: true)
        }
    }

    public func load() throws -> LibraryDocument {
        try withLock(".library.lock") { try readExisting() ?? LibraryDocument() }
    }

    public func save(_ document: LibraryDocument) throws {
        let normalized = try validate(document)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do { data = try encoder.encode(normalized) }
        catch { throw ShuttleError.storage("The library could not be encoded.") }
        try withLock(".library.lock") {
            // Even an explicit save must not overwrite a damaged or newer library.
            _ = try readExisting()
            let temporary = directory.appendingPathComponent(".library-\(UUID().uuidString).tmp")
            let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard descriptor >= 0 else { throw ShuttleError.storage("Cannot create a private library file.") }
            var closed = false
            defer {
                if !closed { close(descriptor) }
                unlink(temporary.path)
            }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw ShuttleError.storage("The library could not be written.") }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0 else { throw ShuttleError.storage("The library could not be synchronized.") }
            let closeResult = close(descriptor)
            closed = true
            guard closeResult == 0, rename(temporary.path, fileURL.path) == 0 else {
                throw ShuttleError.storage("The library could not be atomically replaced.")
            }
            let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            if directoryFD >= 0 { _ = fsync(directoryFD); close(directoryFD) }
        }
    }

    // Acquire this before load/save when coordinating credentials with library changes.
    public func withCredentialAccess<T>(_ operation: () throws -> T) throws -> T {
        try withLock(".credentials.lock", operation)
    }

    private func withLock<T>(_ filename: String, _ operation: () throws -> T) throws -> T {
        do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]) }
        catch { throw ShuttleError.storage("Cannot create the private library directory.") }
        var info = stat()
        guard lstat(directory.path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              chmod(directory.path, mode_t(0o700)) == 0 else {
            throw ShuttleError.storage("The library directory must be a private directory, not a symbolic link.")
        }
        let lockURL = directory.appendingPathComponent(filename)
        let descriptor = open(lockURL.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw ShuttleError.storage("Cannot lock the library.") }
        defer { close(descriptor) }
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              fchmod(descriptor, mode_t(0o600)) == 0, flock(descriptor, LOCK_EX) == 0 else {
            throw ShuttleError.storage("Cannot lock the library.")
        }
        defer { flock(descriptor, LOCK_UN) }
        return try operation()
    }

    private func readExisting() throws -> LibraryDocument? {
        let descriptor = open(fileURL.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw ShuttleError.storage("Cannot read the library. The existing file was left unchanged.")
        }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              fchmod(descriptor, mode_t(0o600)) == 0 else {
            throw ShuttleError.storage("The library must be a private regular file.")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        let data: Data
        do { data = try handle.readToEnd() ?? Data() }
        catch { throw ShuttleError.storage("Cannot read the library. The existing file was left unchanged.") }
        let document: LibraryDocument
        do { document = try JSONDecoder().decode(LibraryDocument.self, from: data) }
        catch let error as ShuttleError { throw error }
        catch { throw ShuttleError.storage("The library is malformed. Preserve or repair the existing library.json before saving; it has not been overwritten.") }
        return try validate(document)
    }

    private func validate(_ document: LibraryDocument) throws -> LibraryDocument {
        guard document.version == LibraryDocument.currentVersion else {
            throw ShuttleError.storage("This library uses an unsupported format version. It has not been overwritten.")
        }
        var result = document
        var identifiers = Set<UUID>()
        result.profiles = try document.profiles.map { profile in
            guard identifiers.insert(profile.id).inserted else {
                throw ShuttleError.storage("The library contains duplicate server identifiers. It has not been overwritten.")
            }
            return try profile.validated()
        }
        return result
    }
}
