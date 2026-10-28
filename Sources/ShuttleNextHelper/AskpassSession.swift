import Darwin
import Foundation
import ShuttleCore

/// Contains routing metadata only. A password is never persisted here.
struct AskpassSession {
    static let environmentKey = "SHUTTLENEXT_ASKPASS_SESSION"
    private static let prefix = "/private/tmp/ShuttleNext-askpass-"
    private static let metadataName = "connection.json"
    private static let submissionName = "password-submitted"

    struct Metadata: Codable {
        let profileID: UUID
        let libraryPath: String
        let host: String
        let user: String
        let port: Int?
        let identity: SSHIdentity
        let identityFile: String
        let passwordMode: ServerPasswordMode
        let sshConfigPath: String?
        let ownerPID: Int32
    }

    let directory: String
    let metadata: Metadata

    static func create(profile: ServerProfile, library: URL) throws -> AskpassSession {
        let profile = try profile.validated()
        var template = Array((prefix + "XXXXXXXXXXXX").utf8CString)
        guard let pointer = mkdtemp(&template) else { throw sessionError() }
        let path = String(cString: pointer)
        do {
            let metadata = Metadata(profileID: profile.id, libraryPath: library.path,
                                    host: profile.host, user: profile.user, port: profile.port,
                                    identity: profile.identity, identityFile: profile.identityFile,
                                    passwordMode: profile.passwordMode, sshConfigPath: profile.sshConfigPath,
                                    ownerPID: getpid())
            let data = try JSONEncoder().encode(metadata)
            let descriptor = open(path + "/" + metadataName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard descriptor >= 0 else { throw sessionError() }
            guard fchmod(descriptor, 0o600) == 0 else {
                close(descriptor)
                throw sessionError()
            }
            let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
            try handle.write(contentsOf: data)
            try handle.close()
            return AskpassSession(directory: path, metadata: metadata)
        } catch {
            try? FileManager.default.removeItem(atPath: path)
            throw sessionError()
        }
    }

    static func load(directory: String, profileID: UUID, library: URL) throws -> AskpassSession {
        guard directory.hasPrefix(prefix),
              !directory.dropFirst(prefix.count).isEmpty,
              !directory.dropFirst(prefix.count).contains("/") else { throw sessionError() }
        let descriptor = try openDirectory(directory)
        defer { close(descriptor) }
        let file = openat(descriptor, metadataName, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { throw sessionError() }
        let handle = FileHandle(fileDescriptor: file, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(file, &info) == 0,
              info.st_uid == getuid(), (info.st_mode & 0o777) == 0o600,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_nlink == 1, info.st_size > 0, info.st_size <= 16_384,
              let data = try handle.read(upToCount: 16_385), data.count <= 16_384,
              let metadata = try? JSONDecoder().decode(Metadata.self, from: data),
              metadata.profileID == profileID, metadata.libraryPath == library.path,
              metadata.ownerPID > 1, kill(metadata.ownerPID, 0) == 0 else { throw sessionError() }
        try validateCaller(ownerPID: metadata.ownerPID)
        return AskpassSession(directory: directory, metadata: metadata)
    }

    func validate(profile: ServerProfile) throws {
        let profile = try profile.validated()
        guard metadata.profileID == profile.id,
              metadata.host == profile.host, metadata.user == profile.user, metadata.port == profile.port,
              metadata.identity == profile.identity, metadata.identityFile == profile.identityFile,
              metadata.passwordMode == profile.passwordMode, metadata.sshConfigPath == profile.sshConfigPath else {
            throw ShuttleError.connection("The connection settings changed. Start a new SSH connection.")
        }
    }

    // Claim before Keychain access so retries cannot send a second saved password.
    func claimSavedPassword() throws {
        let descriptor = try Self.openDirectory(directory)
        defer { close(descriptor) }
        let marker = openat(descriptor, Self.submissionName,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard marker >= 0 else {
            throw ShuttleError.connection("The saved password was already attempted, or the connection session is unavailable. Reconnect to try again.")
        }
        guard fchmod(marker, 0o600) == 0 else {
            close(marker)
            throw Self.sessionError()
        }
        close(marker)
    }

    var isCancelled: Bool {
        guard metadata.ownerPID > 1, kill(metadata.ownerPID, 0) == 0 else { return true }
        guard let descriptor = try? Self.openDirectory(directory) else { return true }
        defer { close(descriptor) }
        var info = stat()
        return fstatat(descriptor, "cancelled", &info, AT_SYMLINK_NOFOLLOW) == 0
    }

    // Persist cancellation before signalling so another challenge cannot reopen a dialog.
    func cancelConnection() {
        if let descriptor = try? Self.openDirectory(directory) {
            let marker = openat(descriptor, "cancelled", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            if marker >= 0 {
                fchmod(marker, 0o600)
                close(marker)
            }
            close(descriptor)
        }
        if metadata.ownerPID > 1, metadata.ownerPID != getpid() {
            // Let the owner reap SSH and remove the session; signalling it can race cleanup.
            let sshPID = getppid()
            var query = [CTL_KERN, KERN_PROC, KERN_PROC_PID, sshPID]
            var info = kinfo_proc()
            var size = MemoryLayout<kinfo_proc>.size
            let result = query.withUnsafeMutableBufferPointer {
                sysctl($0.baseAddress, UInt32($0.count), &info, &size, nil, 0)
            }
            if result == 0, size == MemoryLayout<kinfo_proc>.size,
               info.kp_eproc.e_ppid == metadata.ownerPID {
                kill(sshPID, SIGTERM)
            }
        }
    }

    func remove() {
        try? FileManager.default.removeItem(atPath: directory)
    }

    private static func validateCaller(ownerPID: pid_t) throws {
        let parent = getppid()
        var query = [CTL_KERN, KERN_PROC, KERN_PROC_PID, parent]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        let result = query.withUnsafeMutableBufferPointer {
            sysctl($0.baseAddress, UInt32($0.count), &info, &size, nil, 0)
        }
        guard result == 0, size == MemoryLayout<kinfo_proc>.size,
              info.kp_eproc.e_ppid == ownerPID,
              processPath(parent) == "/usr/bin/ssh",
              let ownPath = processPath(getpid()), processPath(ownerPID) == ownPath else {
            throw sessionError()
        }
    }

    private static func processPath(_ pid: pid_t) -> String? {
        var path = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        guard proc_pidpath(pid, &path, UInt32(path.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: path)).resolvingSymlinksInPath().path
    }

    private static func openDirectory(_ path: String) throws -> Int32 {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw sessionError() }
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              info.st_uid == getuid(), (info.st_mode & 0o777) == 0o700,
              (info.st_mode & S_IFMT) == S_IFDIR else {
            close(descriptor)
            throw sessionError()
        }
        return descriptor
    }

    private static func sessionError() -> ShuttleError {
        .connection("The private SSH authentication session is unavailable. Start a new connection from ShuttleNext.")
    }
}
