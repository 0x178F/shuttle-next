import SwiftUI
import ShuttleCore

struct PasswordField: View {
    let title: String
    @Binding var text: String
    let localizer: AppLocalizer
    var prompt: String? = nil
    @State private var isVisible = false
    @FocusState private var focusedField: Field?

    private enum Field: Hashable { case secure, visible }

    var body: some View {
        HStack(spacing: 6) {
            Group {
                if isVisible {
                    TextField(title, text: $text, prompt: Text(prompt ?? title))
                        .focused($focusedField, equals: .visible)
                        .autocorrectionDisabled()
                } else {
                    SecureField(title, text: $text, prompt: Text(prompt ?? title))
                        .focused($focusedField, equals: .secure)
                }
            }
            .accessibilityLabel(title)
            .textFieldStyle(.roundedBorder)
            Button {
                isVisible.toggle()
                focusedField = isVisible ? .visible : .secure
            } label: {
                Image(systemName: isVisible ? "eye.slash" : "eye")
                    .frame(width: 24, height: 24)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.borderless)
            .help(visibilityLabel)
            .accessibilityLabel(visibilityLabel)
        }
        .onDisappear { isVisible = false }
    }

    private var visibilityLabel: String {
        localizer.text(isVisible ? "Hide password" : "Show password")
    }
}
