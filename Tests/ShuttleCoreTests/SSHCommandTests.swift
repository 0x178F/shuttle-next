import Foundation
import Testing
import ShuttleCore

@Suite("SSH transport boundaries")
struct SSHCommandTests {
    @Test("OpenSSH preserves inherited settings but enforces host-key safeguards")
    func inheritedConfiguration() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var server = ServerProfile(name: "Server", host: "production-alias")
        server.sshConfigPath = try writeConfig(in: directory).path
        let effective = try effectiveConfiguration(server)
        #expect(effective["hostname"] == ["192.0.2.1"])
        #expect(effective["user"] == ["inherited-user"])
        #expect(effective["port"] == ["2201"])
        #expect(effective["stricthostkeychecking"] == ["ask"])
        #expect(effective["numberofpasswordprompts"] == ["1"])
        #expect(try !enabled("permitlocalcommand", in: effective))
        #expect(try !enabled("batchmode", in: effective))
        #expect(effective["identityfile"]?.contains("/tmp/inherited-key") == true)
        #expect(effective["preferredauthentications"] == ["publickey"])
        #expect(try enabled("pubkeyauthentication", in: effective))
        #expect(try !enabled("passwordauthentication", in: effective))
        #expect(try !enabled("kbdinteractiveauthentication", in: effective))
    }

    @Test("OpenSSH uses an explicit key first with an independent server password mode",
          arguments: [ServerPasswordMode.askWhenNeeded, .keychain])
    func explicitIdentityAndUser(passwordMode: ServerPasswordMode) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var server = ServerProfile(name: "Server", host: "production-alias", user: "deploy-user",
                                   port: 2222, identity: .privateKey, passwordMode: passwordMode,
                                   identityFile: directory.appendingPathComponent("a key'; echo not-a-command; #").path)
        server.sshConfigPath = try writeConfig(in: directory, publicKeyEnabled: false).path
        try Data().write(to: URL(fileURLWithPath: server.identityFile))
        let effective = try effectiveConfiguration(server)
        #expect(effective["user"] == [server.user])
        #expect(effective["port"] == ["2222"])
        #expect(try enabled("identitiesonly", in: effective))
        #expect(try enabled("pubkeyauthentication", in: effective))
        #expect(effective["preferredauthentications"] == ["publickey,password,keyboard-interactive"])
        #expect(try enabled("passwordauthentication", in: effective) == (passwordMode == .keychain))
        #expect(try enabled("kbdinteractiveauthentication", in: effective) == (passwordMode == .keychain))
        #expect(effective["identityfile"]?.contains(server.identityFile) == true)
    }

    @Test("No-key identity permits manual or saved passwords despite conflicting SSH configuration",
          arguments: [ServerPasswordMode.askWhenNeeded, .keychain])
    func passwordModes(passwordMode: ServerPasswordMode) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var server = ServerProfile(name: "Server", host: "production-alias", identity: .none,
                                   passwordMode: passwordMode)
        server.sshConfigPath = try writeConfig(in: directory).path
        let effective = try effectiveConfiguration(server)
        #expect(effective["preferredauthentications"] == ["password,keyboard-interactive"])
        #expect(try !enabled("pubkeyauthentication", in: effective))
        #expect(try enabled("passwordauthentication", in: effective))
        #expect(try enabled("kbdinteractiveauthentication", in: effective))
        #expect(effective["numberofpasswordprompts"] == ["1"])
    }

    @Test("Keychain server passwords preserve the configured agent and public-key policy",
          arguments: [true, false])
    func automaticIdentityAndSavedPassword(publicKeyEnabled: Bool) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var server = ServerProfile(name: "Server", host: "production-alias",
                                   identity: .automatic, passwordMode: .keychain)
        server.sshConfigPath = try writeConfig(in: directory, publicKeyEnabled: publicKeyEnabled).path
        let effective = try effectiveConfiguration(server)
        #expect(effective["preferredauthentications"] == ["publickey,password,keyboard-interactive"])
        #expect(try enabled("pubkeyauthentication", in: effective) == publicKeyEnabled)
        #expect(try enabled("passwordauthentication", in: effective))
        #expect(try enabled("kbdinteractiveauthentication", in: effective))
        #expect(try !enabled("identitiesonly", in: effective))
        #expect(effective["identityfile"]?.contains("/tmp/inherited-key") == true)
    }

    @Test("Inactive identity-file values never become SSH arguments", arguments: [SSHIdentity.automatic, .none])
    func inactiveIdentityFile(identity: SSHIdentity) throws {
        let server = ServerProfile(name: "Server", host: "server.example", identity: identity,
                                   identityFile: "/tmp/inactive-key")
        let arguments = try SSHCommand.arguments(for: server)
        #expect(!arguments.contains("-i"))
        #expect(!arguments.contains(server.identityFile))
    }

    @Test("Reject option, command, and invalid destination boundaries", arguments: [
        "-oProxyCommand=evil", "host;id", "host $(id)", "user@host", "host\ncommand", "host\0command", "host/command"
    ])
    func unsafeHost(host: String) {
        let server = ServerProfile(name: "Server", host: host)
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
    }

    @Test("Reject invalid port boundaries", arguments: [0, -1, 65_536])
    func invalidPort(port: Int) {
        let server = ServerProfile(name: "Server", host: "server.example", port: port)
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
    }

    @Test("OpenSSH accepts both valid port endpoints", arguments: [1, 65_535])
    func validPort(port: Int) throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        var server = ServerProfile(name: "Server", host: "production-alias", port: port)
        server.sshConfigPath = try writeConfig(in: directory).path
        #expect(try effectiveConfiguration(server)["port"] == [String(port)])
    }

    @Test("Reject invalid identity and configuration paths")
    func invalidPaths() {
        var server = ServerProfile(name: "Server", host: "server.example", identity: .privateKey)
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
        server.identityFile = "/tmp/key\n-oProxyCommand=evil"
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
        server.identity = .automatic
        server.identityFile = ""
        server.sshConfigPath = "relative/config"
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
        server.sshConfigPath = "/tmp/config\0other"
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
    }

    @Test("Reject unsafe username boundaries", arguments: ["-root", "user@host", "two users", "user\0name", "user;$(id)", "root|id", "root`id`"])
    func invalidUser(user: String) {
        let server = ServerProfile(name: "Server", host: "server.example", user: user)
        #expect(throws: (any Error).self) { try SSHCommand.arguments(for: server) }
    }

    @Test("POSIX shell round-trips every quoted word without executing content")
    func shellRoundTrip() throws {
        let directory = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let sentinel = directory.appendingPathComponent("must-not-exist")
        let values = [
            "", "a'b", "a\"b", "line one\nline two", "$(/usr/bin/touch \(sentinel.path))",
            "'; /usr/bin/touch \(sentinel.path); #", "`/usr/bin/touch \(sentinel.path)`",
            "$HOME & * ? [abc] ; \\ café", "/Applications/Shuttle Next.app/Contents/Helpers/ShuttleNextHelper"
        ]
        let command = "/usr/bin/printf '%s\\0' " + values.map(SSHCommand.shellQuote).joined(separator: " ")
        let result = try execute("/bin/sh", arguments: ["-c", command])
        #expect(result.status == 0)
        let returned = String(decoding: result.output, as: UTF8.self)
            .split(separator: "\0", omittingEmptySubsequences: false).dropLast().map(String.init)
        #expect(returned == values)
        #expect(!FileManager.default.fileExists(atPath: sentinel.path))
    }

    @Test("Recognize only an uncombined password challenge", arguments: [
        "Password:", "password: ", "alice@server.example's password: ", "root@192.0.2.1's password:",
        "(alice@server.example) Password:", "(alice@server.example) password:\t"
    ])
    func recognizedPassword(prompt: String) {
        #expect(SSHCommand.isPasswordPrompt(prompt))
    }

    @Test("Combined challenges and OTPs never consume a saved password", arguments: [
        "(password + OTP) Password:", "(alice@host) (password + OTP) Password:",
        "(alice@host) (OTP) Password:", "((alice@host)) Password:", "(alice @host) Password:",
        "(alice\n@host) Password:", "Password and verification code:", "One-time password:",
        "Verification code:", "Enter passphrase for key '/tmp/key':", "Password:\nOTP:",
        "Are you sure you want to continue connecting (yes/no/[fingerprint])?"
    ])
    func manualChallenge(prompt: String) {
        #expect(!SSHCommand.isPasswordPrompt(prompt))
    }

    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("ShuttleNext-transport-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
        return url
    }

    private func writeConfig(in directory: URL, publicKeyEnabled: Bool = true) throws -> URL {
        let url = directory.appendingPathComponent("isolated-config")
        try """
        Host production-alias
            HostName 192.0.2.1
            User inherited-user
            Port 2201
            IdentityFile /tmp/inherited-key
            StrictHostKeyChecking no
            NumberOfPasswordPrompts 9
            PermitLocalCommand yes
            BatchMode yes
            PreferredAuthentications publickey
            PubkeyAuthentication \(publicKeyEnabled ? "yes" : "no")
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            IdentitiesOnly no
        """.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    private func effectiveConfiguration(_ profile: ServerProfile) throws -> [String: [String]] {
        // The explicit synthetic -F prevents reading the user's SSH configuration.
        let result = try execute("/usr/bin/ssh", arguments: ["-G"] + SSHCommand.arguments(for: profile))
        try #require(result.status == 0)
        let text = try #require(String(data: result.output, encoding: .utf8))
        var values: [String: [String]] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: " ", maxSplits: 1)
            if parts.count == 2 { values[String(parts[0]), default: []].append(String(parts[1])) }
        }
        return values
    }

    private func enabled(_ option: String, in configuration: [String: [String]]) throws -> Bool {
        let value = try #require(configuration[option]?.first)
        return try #require(["yes": true, "true": true, "no": false, "false": false][value] as Bool?)
    }

    private func execute(_ executable: String, arguments: [String]) throws -> (status: Int32, output: Data) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        let output = Pipe()
        process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, data)
    }
}
