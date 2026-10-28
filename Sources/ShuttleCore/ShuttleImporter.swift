import Foundation

enum ShuttleImporter {
    private static let controlCharacters = CharacterSet.controlCharacters

    struct Document: Decodable {
        let result: ImportResult
        private enum RootKeys: String, CodingKey { case hosts }
        private enum EntryKeys: String, CodingKey { case name, cmd }
        private struct GroupKey: CodingKey {
            let stringValue: String
            var intValue: Int? { nil }
            init?(stringValue: String) { self.stringValue = stringValue }
            init?(intValue: Int) { return nil }
        }

        init(from decoder: Decoder) throws {
            var entries: UnkeyedDecodingContainer
            if let array = try? decoder.unkeyedContainer() { entries = array }
            else {
                let root = try decoder.container(keyedBy: RootKeys.self)
                entries = try root.nestedUnkeyedContainer(forKey: .hosts)
            }
            var result = ImportResult()
            var count = 0
            func visit(_ entries: inout UnkeyedDecodingContainer, groups: [String], depth: Int) throws {
                guard depth <= 32 else {
                    result.warnings.append("A group exceeded the nesting limit and was skipped.")
                    return
                }
                while !entries.isAtEnd {
                    count += 1
                    guard count <= 10_000 else {
                        if count == 10_001 { result.warnings.append("The import entry limit was reached.") }
                        return
                    }
                    let entry = try entries.superDecoder()
                    guard let object = try? entry.container(keyedBy: EntryKeys.self) else {
                        result.warnings.append("An invalid Shuttle entry was skipped.")
                        continue
                    }
                    let name = ((try? object.decode(String.self, forKey: .name)) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
                    guard let command = try? object.decode(String.self, forKey: .cmd) else {
                        // Original Shuttle menus use their titles as JSON object keys.
                        let menus = try entry.container(keyedBy: GroupKey.self)
                        var foundGroup = false
                        for key in menus.allKeys.sorted(by: { $0.stringValue < $1.stringValue }) {
                            guard var children = try? menus.nestedUnkeyedContainer(forKey: key) else { continue }
                            foundGroup = true
                            let title = key.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
                            try visit(&children, groups: title.isEmpty ? groups : groups + [title], depth: depth + 1)
                            if count > 10_000 { return }
                        }
                        if !foundGroup { result.warnings.append("An entry without a server name or SSH command was skipped.") }
                        continue
                    }
                    guard !name.isEmpty else {
                        result.warnings.append("An entry without a server name or SSH command was skipped.")
                        continue
                    }
                    do {
                        let candidate = try ShuttleImporter.parse(command: command, name: name, group: groups.joined(separator: " / "))
                        result.candidates.append(candidate)
                        if candidate.profile.sshConfigPath != nil {
                            result.warnings.append("An imported connection references an SSH configuration. Only connect if you trust that configuration: OpenSSH may execute its configured commands.")
                        }
                    } catch {
                        // Names and source commands may themselves contain secrets.
                        result.warnings.append("An entry was skipped because its command is not a supported, plain SSH connection. Shell syntax, remote commands, and unsupported options are not imported.")
                    }
                }
            }
            try visit(&entries, groups: [], depth: 0)
            self.result = result
        }
    }

    private enum ParseFailure: Error { case invalid }

    private static func parse(command: String, name: String, group: String) throws -> ImportCandidate {
        let words = try tokenize(command)
        guard !words.isEmpty else { throw ParseFailure.invalid }
        var index = 0
        var password: String?
        if words[index] == "sshpass" || words[index] == "/usr/bin/sshpass" || words[index] == "/usr/local/bin/sshpass" || words[index] == "/opt/homebrew/bin/sshpass" {
            index += 1
            guard index < words.count else { throw ParseFailure.invalid }
            if words[index] == "-p" {
                index += 1
                guard index < words.count else { throw ParseFailure.invalid }
                password = words[index]
                index += 1
            } else if words[index].hasPrefix("-p"), words[index].count > 2 {
                password = String(words[index].dropFirst(2))
                index += 1
            } else { throw ParseFailure.invalid }
        }
        guard index < words.count, words[index] == "ssh" || words[index] == "/usr/bin/ssh" else { throw ParseFailure.invalid }
        index += 1
        var destination: String?
        var user: String?
        var port: Int?
        var identity: String?
        var configuration: String?
        var optionsEnded = false
        while index < words.count {
            let word = words[index]
            index += 1
            if word == "--" && !optionsEnded { optionsEnded = true; continue }
            if word.hasPrefix("-") && !optionsEnded {
                guard word.count >= 2 else { throw ParseFailure.invalid }
                let option = word[word.index(after: word.startIndex)]
                guard [Character("i"), "p", "l", "F"].contains(option) else { throw ParseFailure.invalid }
                let attached = String(word.dropFirst(2))
                let value: String
                if attached.isEmpty {
                    guard index < words.count else { throw ParseFailure.invalid }
                    value = words[index]
                    index += 1
                } else { value = attached }
                guard !value.isEmpty else { throw ParseFailure.invalid }
                switch option {
                case "i":
                    guard identity == nil else { throw ParseFailure.invalid }
                    identity = try absolutePath(value)
                case "p":
                    guard port == nil, let number = Int(value), (1...65535).contains(number) else { throw ParseFailure.invalid }
                    port = number
                case "l":
                    guard user == nil else { throw ParseFailure.invalid }
                    user = value
                case "F":
                    guard configuration == nil else { throw ParseFailure.invalid }
                    configuration = try absolutePath(value)
                default: throw ParseFailure.invalid
                }
            } else {
                guard destination == nil, !word.isEmpty else { throw ParseFailure.invalid }
                destination = word
            }
        }
        guard var host = destination else { throw ParseFailure.invalid }
        if host.contains("@") {
            let parts = host.split(separator: "@", omittingEmptySubsequences: false)
            guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty, user == nil else { throw ParseFailure.invalid }
            user = String(parts[0]); host = String(parts[1])
        }
        let sshIdentity: SSHIdentity = identity != nil ? .privateKey : (password == nil ? .automatic : .none)
        let profile = try ServerProfile(name: name, host: host, user: user ?? "", port: port, group: group,
                                        identity: sshIdentity, passwordMode: password == nil ? .askWhenNeeded : .keychain,
                                        identityFile: identity ?? "", sshConfigPath: configuration).validated()
        return ImportCandidate(profile: profile, password: password)
    }

    private static func absolutePath(_ value: String) throws -> String {
        // Relative paths depend on the old terminal's working directory.
        let path = (value as NSString).expandingTildeInPath
        guard path.hasPrefix("/"), !path.unicodeScalars.contains(where: { controlCharacters.contains($0) }) else { throw ParseFailure.invalid }
        return path
    }

    // Tokenize migration input without executing shell syntax.
    private static func tokenize(_ command: String) throws -> [String] {
        enum Quote { case none, single, double }
        var quote = Quote.none
        var escaped = false
        var token = ""
        var started = false
        var words: [String] = []
        for character in command {
            if escaped {
                guard character != "\n", character != "\r" else { throw ParseFailure.invalid }
                if quote == .double && ![Character("$"), "`", "\"", "\\"].contains(character) { token.append("\\") }
                token.append(character); escaped = false; started = true
                continue
            }
            if quote == .single {
                if character == "'" { quote = .none } else { token.append(character) }
                continue
            }
            if character == "\\" { escaped = true; started = true; continue }
            if quote == .double {
                if character == "\"" { quote = .none }
                else if character == "$" || character == "`" || character == "\n" || character == "\r" { throw ParseFailure.invalid }
                else { token.append(character) }
                continue
            }
            if character == "'" { quote = .single; started = true }
            else if character == "\"" { quote = .double; started = true }
            else if character == " " || character == "\t" {
                if started { words.append(token); token = ""; started = false }
            } else if character.unicodeScalars.contains(where: { controlCharacters.contains($0) }) || "|&;<>()`$*?[]{}!#".contains(character) {
                throw ParseFailure.invalid
            } else { token.append(character); started = true }
        }
        guard !escaped, quote == .none else { throw ParseFailure.invalid }
        if started { words.append(token) }
        return words
    }
}
