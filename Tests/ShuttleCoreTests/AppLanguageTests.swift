import Testing
import ShuttleCore

struct AppLanguageTests {
    @Test func regionalSystemPreferencesResolveToSupportedLanguages() {
        let cases: [(String, AppLanguage)] = [
            ("en-GB", .en), ("tr-TR", .tr), ("de-AT", .de), ("fr-CA", .fr),
            ("es-MX", .es), ("it-CH", .it), ("de_DE", .de),
            ("pt-BR", .ptBR), ("pt-PT", .ptBR), ("pt", .ptBR),
            ("ja-JP", .ja), ("ko-KR", .ko),
            ("zh-Hans", .zhHans), ("zh-CN", .zhHans), ("zh-SG", .zhHans),
            ("zh", .zhHans), ("zh-Hans-TW", .zhHans), ("zh_Hans_CN", .zhHans)
        ]
        for (identifier, language) in cases {
            #expect(AppLanguage.system.resolved(preferredLanguages: [identifier]) == language)
        }
    }

    @Test func systemSkipsUnsupportedPreferencesAndFallsBackToEnglish() {
        #expect(AppLanguage.system.resolved(preferredLanguages: ["ar-SA", "fr-CA", "de-DE"]) == .fr)
        #expect(AppLanguage.system.resolved(preferredLanguages: ["ar-SA", "system", "he-IL"]) == .en)
        #expect(AppLanguage.system.resolved(preferredLanguages: []) == .en)
    }

    @Test func traditionalOrTransliteratedChineseDoesNotSelectSimplifiedChinese() {
        for identifier in ["zh-Hant", "zh-TW", "zh-HK", "zh-MO", "zh-Hant-CN", "zh-Latn"] {
            #expect(AppLanguage.system.resolved(preferredLanguages: [identifier, "de-DE"]) == .de)
            #expect(AppLanguage.system.resolved(preferredLanguages: [identifier]) == .en)
        }
    }

    @Test func explicitSelectionIgnoresSystemPreferences() {
        for language in AppLanguage.allCases where language != .system {
            #expect(language.resolved(preferredLanguages: ["ja-JP", "en-US"]) == language)
        }
    }
}
