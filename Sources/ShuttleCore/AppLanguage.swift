import Foundation

public enum AppLanguage: String, Codable, CaseIterable, Identifiable, Sendable {
    case system, en, tr, de, fr, es, it
    case ptBR = "pt-BR"
    case ja
    case zhHans = "zh-Hans"
    case ko

    public var id: String { rawValue }

    public var nativeName: String {
        switch self {
        case .system: return "System"
        case .en: return "English"
        case .tr: return "Türkçe"
        case .de: return "Deutsch"
        case .fr: return "Français"
        case .es: return "Español"
        case .it: return "Italiano"
        case .ptBR: return "Português (Brasil)"
        case .ja: return "日本語"
        case .zhHans: return "简体中文"
        case .ko: return "한국어"
        }
    }

    public func resolved(preferredLanguages: [String]) -> AppLanguage {
        guard self == .system else { return self }
        for identifier in preferredLanguages {
            let language = Locale(identifier: identifier).language
            switch language.languageCode?.identifier {
            case "pt": return .ptBR
            case "zh":
                if language.script?.identifier == "Hans" { return .zhHans }
            case let code?:
                if let supported = Self(rawValue: code), supported != .system { return supported }
            case nil: break
            }
        }
        return .en
    }
}

public struct AppLocalizer: Sendable {
    public let language: AppLanguage
    public let locale: Locale
    private let bundle: Bundle
    private static let resources: Bundle = {
        if let url = Bundle.main.resourceURL?.appendingPathComponent("ShuttleNext_ShuttleCore.bundle"),
           let packaged = Bundle(url: url) { return packaged }
        return .module
    }()

    public init(language: AppLanguage = .system, preferredLanguages: [String] = Locale.preferredLanguages) {
        self.language = language
        let resolved = language.resolved(preferredLanguages: preferredLanguages)
        locale = Locale(identifier: resolved.rawValue)
        let localization = Bundle.preferredLocalizations(from: Self.resources.localizations, forPreferences: [resolved.rawValue]).first ?? "en"
        bundle = Self.resources.url(forResource: localization, withExtension: "lproj")
            .flatMap(Bundle.init(url:)) ?? Self.resources
    }

    public func text(_ resource: LocalizedStringResource) -> String {
        // Preserve captured interpolation arguments when selecting the bundle.
        String(localized: resource.defaultValue, table: resource.table, bundle: bundle, locale: locale)
    }

    public func error(_ error: Error) -> String {
        if let error = error as? ShuttleError {
            return text(error.message)
        }
        return error.localizedDescription
    }
}
