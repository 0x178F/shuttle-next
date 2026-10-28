import Foundation
import Darwin

public enum ConnectionExporter {
    public static func exportProfiles(_ profiles: [ServerProfile], to url: URL) throws {
        guard url.isFileURL, !url.path.contains("\0") else {
            throw ShuttleError.storage("Choose a local file for the export.")
        }
        guard profiles.count <= 10_000 else {
            throw ShuttleError.storage("The export exceeds the 10,000-connection import limit.")
        }
        var identifiers = Set<UUID>()
        let normalized = try profiles.map { profile in
            guard identifiers.insert(profile.id).inserted else {
                throw ShuttleError.storage("The library contains duplicate server identifiers. Nothing was exported.")
            }
            return try profile.validated()
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data: Data
        do { data = try encoder.encode(LibraryDocument(profiles: normalized)) }
        catch { throw ShuttleError.storage("The connections could not be encoded.") }
        guard data.count <= 8 * 1024 * 1024 else {
            throw ShuttleError.storage("The export exceeds the 8 MB import limit.")
        }
        try PrivateAtomicFile.write(data, to: url)
    }
}

/// Only already-serialized output belongs here; secret backup payloads must be encrypted first.
enum PrivateAtomicFile {
    static func write(_ data: Data, to url: URL) throws {
        guard url.isFileURL, !url.path.contains("\0") else {
            throw ShuttleError.storage("Choose a local file for the export.")
        }
        var info = stat()
        let status = lstat(url.path, &info)
        guard status == 0 ? (info.st_mode & S_IFMT) == S_IFREG : errno == ENOENT else {
            throw ShuttleError.storage("Choose a regular file, not a directory or symbolic link.")
        }
        let directory = url.deletingLastPathComponent()
        let temporary = directory.appendingPathComponent(".ShuttleNext-export-\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw ShuttleError.storage("Cannot create a private export file in this folder.") }
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
                guard count > 0 else { throw ShuttleError.storage("The export could not be written.") }
                offset += count
            }
        }
        guard fsync(descriptor) == 0 else { throw ShuttleError.storage("The export could not be synchronized.") }
        let closeResult = close(descriptor)
        closed = true
        guard closeResult == 0, rename(temporary.path, url.path) == 0 else {
            throw ShuttleError.storage("The export could not be atomically saved.")
        }
        let directoryFD = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if directoryFD >= 0 { _ = fsync(directoryFD); close(directoryFD) }
    }
}
