import Foundation

public enum SSHCommand {
    public static func arguments(for profile: ServerProfile) throws -> [String] {
        let profile = try profile.validated()
        // OpenSSH takes the first value, so safeguards must precede imported configuration.
        var arguments = [
            "-o", "StrictHostKeyChecking=ask",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "PermitLocalCommand=no",
            "-o", "BatchMode=no"
        ]
        if let path = profile.sshConfigPath { arguments += ["-F", path] }
        if let port = profile.port { arguments += ["-p", String(port)] }
        if !profile.user.isEmpty { arguments += ["-l", profile.user] }
        switch profile.identity {
        case .automatic:
            break
        case .privateKey:
            arguments += [
                "-i", profile.identityFile,
                "-o", "IdentitiesOnly=yes",
                "-o", "PubkeyAuthentication=yes"
            ]
        case .none:
            arguments += ["-o", "PubkeyAuthentication=no"]
        }
        if profile.identity == .none {
            arguments += ["-o", "PreferredAuthentications=password,keyboard-interactive"]
        } else if profile.identity == .privateKey || profile.passwordMode == .keychain {
            arguments += ["-o", "PreferredAuthentications=publickey,password,keyboard-interactive"]
        }
        if profile.identity == .none || profile.passwordMode == .keychain {
            arguments += [
                "-o", "PasswordAuthentication=yes",
                "-o", "KbdInteractiveAuthentication=yes"
            ]
        }
        arguments += ["--", profile.host]
        return arguments
    }

    public static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }

    // Never send a saved password to combined or unknown challenges.
    public static func isPasswordPrompt(_ prompt: String) -> Bool {
        let pattern = #"\A(?:[^\s\p{Cc}()]+'s |\([^\s\p{Cc}()]+\) )?[Pp]assword:[ \t]*\z"#
        return prompt.range(of: pattern, options: .regularExpression) != nil
    }
}
