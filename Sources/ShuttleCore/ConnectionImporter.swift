import Foundation
import Darwin

public enum ConnectionImporter {
    public static func importProfiles(from url: URL) throws -> ImportResult {
        switch try ConnectionImportFile.read(from: url) {
        case .sshConfig(let data):
            return try SSHConfigImporter.importProfiles(from: url, contents: data)
        case .json(let data):
            do { return try JSONDecoder().decode(Document.self, from: data).result }
            catch let error as ShuttleError { throw error }
            catch {
                throw ShuttleError.importFailure("The file is not a supported ShuttleNext inventory or classic Shuttle JSON document. Nothing was imported.")
            }
        }
    }

    private struct Document: Decodable {
        let result: ImportResult
        private enum Keys: String, CodingKey { case profiles }

        init(from decoder: Decoder) throws {
            if let fields = try? decoder.container(keyedBy: Keys.self), fields.contains(.profiles) {
                let document = try LibraryDocument(from: decoder)
                guard document.profiles.count <= 10_000 else {
                    throw ShuttleError.importFailure("The inventory exceeds the 10,000-connection import limit.")
                }
                var candidates: [ImportCandidate] = []
                candidates.reserveCapacity(document.profiles.count)
                var identifiers = Set<UUID>()
                var omittedPasswords = false
                var externalFiles = false
                for original in document.profiles {
                    guard identifiers.insert(original.id).inserted else {
                        throw ShuttleError.importFailure("The inventory contains duplicate server identifiers. Nothing was imported.")
                    }
                    var profile = try original.validated()
                    // Imported UUIDs must not authorize access to existing Keychain secrets.
                    profile.id = UUID()
                    if profile.passwordMode == .keychain {
                        profile.passwordMode = .askWhenNeeded
                        omittedPasswords = true
                    }
                    externalFiles = externalFiles || !profile.identityFile.isEmpty || profile.sshConfigPath != nil
                    candidates.append(ImportCandidate(profile: profile))
                }
                var warnings: [LocalizedStringResource] = ["ShuttleNext inventory detected. Only connections are merged; terminal settings and shortcuts are not changed."]
                if omittedPasswords {
                    warnings.append("Keychain passwords are not included in this file. Imported connections will ask when a password is needed; save a password again after importing if desired.")
                }
                if externalFiles {
                    warnings.append("Private keys and SSH configurations are file references, not included files. Check these paths and trust their contents before connecting.")
                }
                result = ImportResult(candidates: candidates, warnings: warnings)
            } else {
                result = try ShuttleImporter.Document(from: decoder).result
            }
        }
    }
}

enum ConnectionImportFile {
    case json(Data)
    case sshConfig(Data)

    static func read(from url: URL) throws -> ConnectionImportFile {
        let data = try readData(from: url, maximumBytes: 8 * 1024 * 1024)
        let jsonName = url.pathExtension.caseInsensitiveCompare("json") == .orderedSame
        let start = data.starts(with: [0xEF, 0xBB, 0xBF]) ? data.index(data.startIndex, offsetBy: 3) : data.startIndex
        guard let first = data[start...].firstIndex(where: { $0 != 0x20 && $0 != 0x09 && $0 != 0x0D && $0 != 0x0A }) else {
            return jsonName ? .json(Data()) : .sshConfig(data)
        }
        let marker = data[first]
        let jsonContent = marker == 0x7B || marker == 0x5B || data.starts(with: [0xFF, 0xFE]) || data.starts(with: [0xFE, 0xFF])
        return jsonName || jsonContent ? .json(first == data.startIndex ? data : Data(data[first...])) : .sshConfig(data)
    }

    // Shared by format detection and SSH Includes: check and read the same descriptor,
    // including one extra byte so growth after fstat cannot bypass the bound.
    static func readData(from url: URL, maximumBytes: Int) throws -> Data {
        guard url.isFileURL, !url.path.contains("\0") else { throw unreadable() }
        let descriptor = url.path.withCString { open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC) }
        guard descriptor >= 0 else { throw unreadable() }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        defer { try? handle.close() }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0, info.st_size <= maximumBytes else { throw unreadable() }
        var data = Data()
        do {
            while let chunk = try handle.read(upToCount: min(4096, maximumBytes - data.count + 1)), !chunk.isEmpty {
                guard chunk.count <= maximumBytes - data.count else { throw unreadable() }
                data.append(chunk)
            }
            return data
        } catch let error as ShuttleError { throw error }
        catch { throw unreadable() }
    }

    private static func unreadable() -> ShuttleError {
        .importFailure("Choose a readable local connection file no larger than 8 MB. Nothing was imported.")
    }
}
