import Foundation
import Darwin

public enum SSHConfigImporter {
    public static func importProfiles(from url: URL) throws -> ImportResult {
        try importProfiles(from: url, contents: nil)
    }

    static func importProfiles(from url: URL, contents: Data?) throws -> ImportResult {
        let root = url.standardizedFileURL
        var reader = Reader(root: root)
        try reader.read(root, depth: 0, isRoot: true, contents: contents)
        return reader.result
    }

    private struct Reader {
        let root: URL
        var result = ImportResult(warnings: ["Only import SSH configurations you trust. When connecting, OpenSSH may execute commands from directives such as ProxyCommand or Match exec; importing does not execute them."])
        var activeFiles = Set<String>()
        var aliases = Set<String>()
        var fileCount = 0
        var byteCount = 0
        var patternCount = 0
        var expandedPathCount = 0
        var inMatch = false
        var warnedLimit = false

        // Relative user Includes use ~/.ssh, not the including file's directory.
        var includeBase: URL {
            root.path == "/etc/ssh/ssh_config"
                ? URL(fileURLWithPath: "/etc/ssh", isDirectory: true)
                : FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".ssh", isDirectory: true)
        }

        mutating func read(_ url: URL, depth: Int, isRoot: Bool = false, contents: Data? = nil) throws {
            guard depth <= 16, fileCount < 256, byteCount < 8 * 1024 * 1024 else { limitWarning(); return }
            let canonical = url.resolvingSymlinksInPath().standardizedFileURL.path
            guard activeFiles.insert(canonical).inserted else {
                result.warnings.append("A cyclic SSH Include was skipped.")
                return
            }
            defer { activeFiles.remove(canonical) }
            fileCount += 1
            let text: String
            do {
                let remainingBytes = 8 * 1024 * 1024 - byteCount
                let data = try contents ?? ConnectionImportFile.readData(from: URL(fileURLWithPath: canonical), maximumBytes: remainingBytes)
                guard data.count <= remainingBytes else { throw ReadFailure.invalid }
                byteCount += data.count
                guard let decoded = String(data: data, encoding: .utf8) else { throw ReadFailure.invalid }
                text = decoded
            } catch {
                if isRoot { throw ShuttleError.importFailure("The SSH configuration is unreadable, too large, or not UTF-8 text.") }
                result.warnings.append("An unreadable, non-regular, or oversized SSH Include was skipped.")
                return
            }
            for line in text.components(separatedBy: .newlines) {
                let words: [String]
                do { words = try Self.words(line) }
                catch { result.warnings.append("A malformed SSH configuration line was skipped."); continue }
                guard let keyword = words.first?.lowercased() else { continue }
                let arguments = words.dropFirst()
                switch keyword {
                case "match":
                    inMatch = true
                case "host":
                    inMatch = false
                    for alias in arguments where Self.isExplicitAlias(alias) {
                        guard aliases.count < 10_000 else { limitWarning(); break }
                        guard aliases.insert(alias.lowercased()).inserted else { continue }
                        do {
                            let profile = try ServerProfile(name: alias, host: alias, sshConfigPath: root.path).validated()
                            result.candidates.append(ImportCandidate(profile: profile))
                        } catch { result.warnings.append("An unsupported SSH host alias was skipped.") }
                    }
                case "include":
                    // Match conditions are deliberately never evaluated during import.
                    guard !inMatch else { continue }
                    for argument in arguments {
                        guard patternCount < 256, expandedPathCount < 256 else { limitWarning(); break }
                        patternCount += 1
                        guard !argument.contains("%"), !argument.contains("${"), !argument.contains("\0") else {
                            result.warnings.append("An SSH Include using runtime token or environment expansion was skipped.")
                            continue
                        }
                        let expanded = (argument as NSString).expandingTildeInPath
                        let patternURL = expanded.hasPrefix("/") ? URL(fileURLWithPath: expanded) : includeBase.appendingPathComponent(expanded)
                        let pattern = patternURL.standardizedFileURL.path
                        for included in expand(pattern) {
                            try read(included, depth: depth + 1)
                        }
                    }
                default:
                    break
                }
            }
        }

        mutating func expand(_ pattern: String) -> [URL] {
            var matches = glob_t()
            // Darwin's GLOB_LIMIT takes the pathname limit from gl_matchc on input.
            // It stops expansion inside glob, before a large result is materialized.
            matches.gl_matchc = Int32(256 - expandedPathCount)
            defer { globfree(&matches) }
            let status = pattern.withCString { Darwin.glob($0, GLOB_LIMIT, nil, &matches) }
            if status == GLOB_NOMATCH { return [] }
            if status == GLOB_NOSPACE {
                expandedPathCount = 256
                limitWarning()
                return []
            }
            guard status == 0 else {
                result.warnings.append("An SSH Include pattern could not be expanded.")
                return []
            }
            let count = Int(matches.gl_pathc)
            expandedPathCount += count
            guard let paths = matches.gl_pathv else { return [] }
            return (0..<count).compactMap { index in
                guard let path = paths[index] else { return nil }
                return URL(fileURLWithPath: String(cString: path))
            }.sorted { $0.path < $1.path }
        }

        mutating func limitWarning() {
            if !warnedLimit { result.warnings.append("The SSH Include limit was reached; remaining entries were skipped."); warnedLimit = true }
        }

        static func isExplicitAlias(_ alias: String) -> Bool {
            !alias.isEmpty && !alias.contains(where: { "*?![],".contains($0) }) && !alias.hasPrefix("-")
        }

        enum ReadFailure: Error { case invalid }

        static func words(_ line: String) throws -> [String] {
            var result: [String] = []
            var token = ""
            var started = false
            var quote: Character?
            var separatedKeyword = false
            var characters = line.makeIterator()
            var current = characters.next()
            while let character = current {
                current = characters.next()
                if character == "\\" {
                    if let next = current,
                       next == "'" || next == "\"" || next == "\\" || (quote == nil && next == " ") {
                        token.append(next)
                        current = characters.next()
                    } else {
                        token.append(character)
                    }
                    started = true
                    continue
                }
                if let delimiter = quote {
                    if character == delimiter { quote = nil }
                    else { token.append(character) }
                    continue
                }
                if character == "\"" || character == "'" { quote = character; started = true; continue }
                if character == "#" && !started { break }
                if character == " " || character == "\t" || (!separatedKeyword && character == "=" && (result.isEmpty || (result.count == 1 && !started))) {
                    if started { result.append(token); token = ""; started = false }
                    if character == "=" { separatedKeyword = true }
                } else { token.append(character); started = true }
            }
            guard quote == nil else { throw ReadFailure.invalid }
            if started { result.append(token) }
            return result
        }
    }
}
