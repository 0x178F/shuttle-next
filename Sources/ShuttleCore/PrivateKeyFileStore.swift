import Foundation
import Darwin

/// Envelope validation is not cryptographic validation; encrypted keys remain encrypted.
public final class PrivateKeyFileStore: Sendable {
    public let directory: URL
    private let validDirectory: Bool
    private static let maximumInputBytes = 1_048_576

    public init(directory: URL) {
        self.directory = directory.standardizedFileURL
        self.validDirectory = directory.isFileURL && !directory.path.utf8.contains(0)
            && directory.standardizedFileURL.path != "/"
    }

    public func create(from text: String) throws -> URL {
        let data = try Self.normalizedKey(text)
        let directoryFD = try openDirectory(create: true)
        defer { close(directoryFD) }
        let name = UUID().uuidString + ".key"
        let descriptor = openat(directoryFD, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard descriptor >= 0 else { throw ShuttleError.storage("Cannot create a private key file.") }
        var closed = false
        do {
            guard fchmod(descriptor, mode_t(0o600)) == 0 else {
                throw ShuttleError.storage("Cannot make the key file private.")
            }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw ShuttleError.storage("The private key file could not be written.") }
                    offset += count
                }
            }
            guard fsync(descriptor) == 0 else {
                throw ShuttleError.storage("The private key file could not be synchronized.")
            }
            let closeResult = close(descriptor)
            closed = true
            guard closeResult == 0 else { throw ShuttleError.storage("The private key file could not be closed.") }
            _ = fsync(directoryFD)
            return directory.appendingPathComponent(name)
        } catch {
            if !closed { close(descriptor) }
            if unlinkat(directoryFD, name, 0) != 0 && errno != ENOENT {
                throw ShuttleError.storage("Saving the private key failed, and its incomplete file could not be removed. Review \(directory.appendingPathComponent(name).path).")
            }
            throw error
        }
    }

    /// Call only for an uncommitted file returned by create(from:).
    public func removeCreatedFile(at url: URL) throws {
        let name = url.lastPathComponent
        let identifier = String(name.dropLast(4))
        guard validDirectory, url.isFileURL, !url.hasDirectoryPath,
              !url.path.utf8.contains(0), name.hasSuffix(".key"),
              UUID(uuidString: identifier)?.uuidString == identifier,
              url.path == url.standardizedFileURL.path,
              url.path == directory.appendingPathComponent(name).path else {
            throw ShuttleError.storage("Only a newly created file in the private key directory can be removed.")
        }
        let directoryFD = try openDirectory(create: false)
        defer { close(directoryFD) }
        var info = stat()
        if fstatat(directoryFD, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return }
            throw ShuttleError.storage("The private key file could not be inspected for rollback.")
        }
        guard (info.st_mode & S_IFMT) == S_IFREG else {
            throw ShuttleError.storage("Only a regular private key file can be removed.")
        }
        guard unlinkat(directoryFD, name, 0) == 0 else {
            throw ShuttleError.storage("The newly created private key file could not be removed.")
        }
        _ = fsync(directoryFD)
    }

    private func openDirectory(create: Bool) throws -> Int32 {
        guard validDirectory else { throw ShuttleError.storage("The private key directory is invalid.") }
        let parent = directory.deletingLastPathComponent()
        if create {
            do {
                try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700])
            } catch {
                throw ShuttleError.storage("Cannot create the private key directory.")
            }
        }
        // Allow ancestor aliases such as /var; reject symlinks at the store itself.
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard parentFD >= 0 else { throw ShuttleError.storage("Cannot open the private key directory's parent.") }
        defer { close(parentFD) }
        let name = directory.lastPathComponent
        if create, mkdirat(parentFD, name, mode_t(0o700)) != 0, errno != EEXIST {
            throw ShuttleError.storage("Cannot create the private key directory.")
        }
        let descriptor = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else {
            throw ShuttleError.storage("The private key directory must be a directory, not a symbolic link.")
        }
        guard fchmod(descriptor, mode_t(0o700)) == 0 else {
            close(descriptor)
            throw ShuttleError.storage("Cannot make the private key directory private.")
        }
        return descriptor
    }

    static func normalizedKey(_ text: String) throws -> Data {
        guard text.utf8.prefix(Self.maximumInputBytes + 1).count <= Self.maximumInputBytes else {
            throw ShuttleError.invalidProfile("The private key must be no larger than 1 MiB.")
        }
        guard !text.utf8.contains(0) else {
            throw ShuttleError.invalidProfile("The private key must not contain NUL characters.")
        }
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        // Canonical output always adds a final newline; bound the bytes actually saved.
        guard normalized.utf8.count < Self.maximumInputBytes else {
            throw ShuttleError.invalidProfile("The private key must be no larger than 1 MiB.")
        }
        let lines = normalized.components(separatedBy: "\n")
        let labels = ["OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY",
                      "PRIVATE KEY", "ENCRYPTED PRIVATE KEY"]
        guard lines.count >= 3,
              let label = labels.first(where: { lines.first == "-----BEGIN \($0)-----" }),
              lines.last == "-----END \(label)-----" else {
            throw invalidEnvelope()
        }
        var body = lines.dropFirst().dropLast()
        if ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"].contains(label),
           body.first == "Proc-Type: 4,ENCRYPTED" {
            body = body.dropFirst()
            guard let metadata = body.first, metadata.hasPrefix("DEK-Info: "),
                  metadata.count > "DEK-Info: ".count else { throw invalidEnvelope() }
            body = body.dropFirst()
            guard body.first == "" else { throw invalidEnvelope() }
            body = body.dropFirst()
        }
        guard let payload = Data(base64Encoded: body.joined()), !payload.isEmpty else {
            throw invalidEnvelope()
        }
        return Data((normalized + "\n").utf8)
    }

    private static func invalidEnvelope() -> ShuttleError {
        .invalidProfile("Enter a complete OpenSSH or PEM private key with matching BEGIN and END lines and a nonempty base64 body. Envelope validation does not verify the cryptographic key.")
    }
}
