import Foundation
import Security
import LocalAuthentication

public final class CredentialStore: Sendable {
    public static let defaultService = "com.fatihakdogan.ShuttleNext.credentials"
    private let service: String
    private let trustedApplications: [URL]

    public init(service: String = CredentialStore.defaultService, trustedApplications: [URL] = []) {
        self.service = service
        self.trustedApplications = trustedApplications
    }

    public func password(for id: UUID) throws -> String? {
        var query = baseQuery(id)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        try check(status)
        guard let data = result as? Data, let password = String(data: data, encoding: .utf8) else {
            throw ShuttleError.credentials("The saved credential could not be decoded.")
        }
        return password
    }

    public func containsPassword(for id: UUID) throws -> Bool {
        var query = baseQuery(id)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        let context = LAContext()
        context.interactionNotAllowed = true
        query[kSecUseAuthenticationContext as String] = context
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecItemNotFound { return false }
        try check(status)
        return true
    }

    public func setPassword(_ password: String, for id: UUID) throws {
        let access = try makeAccess()
        let attributes: [String: Any] = [
            kSecValueData as String: Data(password.utf8),
            kSecAttrAccess as String: access
        ]
        let status = SecItemUpdate(baseQuery(id) as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var addition = baseQuery(id)
            attributes.forEach { addition[$0.key] = $0.value }
            addition[kSecAttrLabel as String] = "ShuttleNext SSH password"
            try check(SecItemAdd(addition as CFDictionary, nil))
        } else {
            try check(status)
        }
    }

    public func deletePassword(for id: UUID) throws {
        let status = SecItemDelete(baseQuery(id) as CFDictionary)
        if status != errSecItemNotFound { try check(status) }
    }

    private func baseQuery(_ id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString,
         kSecAttrSynchronizable as String: false]
    }

    private func makeAccess() throws -> SecAccess {
        // File-based ACLs support local app/helper builds without granting universal access.
        var applications: [SecTrustedApplication] = []
        var currentApplication: SecTrustedApplication?
        try check(SecTrustedApplicationCreateFromPath(nil, &currentApplication))
        guard let currentApplication else { throw ShuttleError.credentials("Cannot authorize this application for Keychain access.") }
        applications.append(currentApplication)
        for url in Set(trustedApplications.map { $0.standardizedFileURL }) {
            var application: SecTrustedApplication?
            let status = url.path.withCString { SecTrustedApplicationCreateFromPath($0, &application) }
            try check(status)
            guard let application else { throw ShuttleError.credentials("Cannot authorize the SSH password helper.") }
            applications.append(application)
        }
        var access: SecAccess?
        try check(SecAccessCreate("ShuttleNext SSH password" as CFString, applications as CFArray, &access))
        guard let access else { throw ShuttleError.credentials("Cannot create private Keychain access controls.") }
        return access
    }

    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess else {
            let message: LocalizedStringResource
            switch status {
            case errSecInteractionNotAllowed, errSecAuthFailed:
                message = "Keychain access is locked or not authorized. Unlock the login Keychain and authorize ShuttleNext and its bundled helper."
            case errSecUserCanceled:
                message = "Keychain access was cancelled."
            default:
                message = "The Keychain operation failed (status \(status))."
            }
            throw ShuttleError.credentials(message)
        }
    }
}
