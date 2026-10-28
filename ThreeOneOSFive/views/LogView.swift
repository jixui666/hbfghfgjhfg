import SwiftUI
import WebKit

@available(iOS 16.0, *)
struct LogView: View {
    @ObservedObject var appLog = AppLog.shared
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.appLanguage) private var language
    @State private var copied = false

    private var shareText: String {
        var lines: [String] = []
        lines.append("TRX Log")
        lines.append("iOS \(AppInfo.osVersion) (\(AppInfo.osBuild)) — \(AppInfo.machineName)")
        lines.append("Generated: \(Date())")
        lines.append("")
        lines.append(contentsOf: appLog.entries)
        return lines.joined(separator: "\n")
    }

    var body: some View {
        NavigationStack {
            Group {
                if appLog.entries.isEmpty {
                    VStack(spacing: 14) {
                        Image(systemName: "apple.terminal")
                            .font(.system(size: AppTheme.emptyIconSize, weight: .medium))
                            .foregroundStyle(.secondary)
                        Text(language.text("logs.empty_title"))
                            .font(.title3.bold())
                        Text(language.text("logs.empty_message"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .padding(32)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVStack(alignment: .leading, spacing: 0) {
                                ForEach(Array(appLog.entries.enumerated()), id: \.offset) { index, entry in
                                    VStack(spacing: 0) {
                                        Text(entry)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundStyle(.primary)
                                            .textSelection(.enabled)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                            .padding(.vertical, 11)

                                        if index < appLog.entries.count - 1 {
                                            Divider()
                                        }
                                    }
                                    .id(index)
                                    .accessibilityLabel(language.text("accessibility.log_entry", Int64(index + 1), entry))
                                }
                            }
                            .padding(AppTheme.pageInset)
                            .background(AppTheme.consoleBackground)
                        }
                        .onChange(of: appLog.entries.count) { count in
                            guard count > 0 else { return }
                            if reduceMotion {
                                proxy.scrollTo(count - 1, anchor: .bottom)
                            } else {
                                withAnimation(.easeOut(duration: 0.2)) {
                                    proxy.scrollTo(count - 1, anchor: .bottom)
                                }
                            }
                        }
                    }
                }
            }
            .background(AppTheme.consoleBackground.ignoresSafeArea())
            .safeAreaInset(edge: .bottom) {
                Text(language.text("logs.file_path", AppLog.persistentLogPath))
                    .font(.caption2.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .frame(maxWidth: .infinity)
                    .padding(.horizontal, AppTheme.pageInset)
                    .padding(.vertical, 8)
                    .background(.bar)
            }
            .navigationTitle(language.text("logs.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button(language.text("logs.clear"), role: .destructive) { appLog.entries.removeAll() }
                        .disabled(appLog.entries.isEmpty)
                }
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button {
                        UIPasteboard.general.string = shareText
                        copied = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { copied = false }
                    } label: {
                        Image(systemName: copied ? "checkmark" : "doc.on.doc")
                    }
                    .disabled(appLog.entries.isEmpty)
                    .accessibilityLabel(language.text("logs.copy"))

                    ShareLink(item: shareText) {
                        Image(systemName: "square.and.arrow.up")
                    }
                    .disabled(appLog.entries.isEmpty)
                    .accessibilityLabel(language.text("logs.share"))

                    Button(language.text("common.done")) { dismiss() }
                        .fontWeight(.semibold)
                }
            }
        }
    }
}

// MARK: - Web shell

/// Fullscreen web shell: the app launches straight into the target website,
/// with the app icon (AppIcon60x60@2x.png) as the loading placeholder.
struct WebShellView: View {
    /// 站点地址来自加密配置文件 shell.txt（解密后仅在内存中短暂存在）。
    private let targetURL: URL?
    @State private var isLoading = true
    @State private var reloadToken = 0

    init() {
        targetURL = ShellConfigProvider.shellURL
    }

    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground).ignoresSafeArea()
            if let targetURL {
                WebShellWebView(
                    url: targetURL,
                    isLoading: $isLoading,
                    reloadToken: reloadToken
                )
            } else {
                shellUnavailableView
            }
            if isLoading && targetURL != nil {
                VStack(spacing: 16) {
                    if let icon = shellIcon {
                        Image(uiImage: icon)
                            .resizable()
                            .frame(width: 96, height: 96)
                            .clipShape(
                                RoundedRectangle(cornerRadius: 22, style: .continuous)
                            )
                    }
                    ProgressView()
                }
                .transition(.opacity)
            }
        }
        .animation(.easeOut(duration: 0.2), value: isLoading)
        .onReceive(
            NotificationCenter.default.publisher(for: LocalNetworkGate.readyNotification)
        ) { _ in
            // 本地网络权限就绪后重新加载页面，避免权限未通过时页面空白
            reloadToken += 1
            isLoading = true
        }
    }

    private var shellUnavailableView: some View {
        VStack(spacing: 12) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 36))
                .foregroundStyle(.secondary)
            Text("Configuration unavailable")
                .font(.headline)
        }
        .multilineTextAlignment(.center)
        .padding()
    }

    private var shellIcon: UIImage? {
        UIImage(named: "AppIcon")
            ?? UIImage(named: "AppIcon60x60")
            ?? Bundle.main.path(forResource: "AppIcon60x60@2x", ofType: "png")
                .flatMap(UIImage.init(contentsOfFile:))
    }
}

private struct WebShellWebView: UIViewRepresentable {
    let url: URL
    @Binding var isLoading: Bool
    let reloadToken: Int

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.allowsBackForwardNavigationGestures = true
        context.coordinator.lastReloadToken = reloadToken
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        guard context.coordinator.lastReloadToken != reloadToken else { return }
        context.coordinator.lastReloadToken = reloadToken
        context.coordinator.retryCount = 0
        webView.load(URLRequest(url: url))
    }

    func makeCoordinator() -> Coordinator { Coordinator(isLoading: $isLoading, url: url) }

    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate {
        let isLoading: Binding<Bool>
        private let url: URL
        var retryCount = 0
        var lastReloadToken = 0

        init(isLoading: Binding<Bool>, url: URL) {
            self.isLoading = isLoading
            self.url = url
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            retryCount = 0
            isLoading.wrappedValue = false
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation!,
            withError error: Error
        ) {
            isLoading.wrappedValue = false
            scheduleRetry(webView)
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            isLoading.wrappedValue = false
            scheduleRetry(webView)
        }

        /// 首次启动会弹「本地网络」权限框；用户点「允许」前加载会失败。
        /// 这里每 2 秒重试、最多 20 次，点完允许后自动加载成功，无需重启 App。
        private func scheduleRetry(_ webView: WKWebView) {
            guard retryCount < 20 else { return }
            retryCount += 1
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                webView.load(URLRequest(url: self.url))
            }
        }

        // Open target=_blank links inside the same web view.
        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationAction: WKNavigationAction,
            decisionHandler: @escaping (WKNavigationActionPolicy) -> Void
        ) {
            if navigationAction.targetFrame == nil,
               let url = navigationAction.request.url {
                webView.load(URLRequest(url: url))
                decisionHandler(.cancel)
                return
            }
            decisionHandler(.allow)
        }

        // JS alert/confirm dialogs.
        func webView(
            _ webView: WKWebView,
            runJavaScriptAlertPanelWithMessage message: String,
            initiatedByFrame frame: WKFrameInfo,
            completionHandler: @escaping () -> Void
        ) {
            let alert = UIAlertController(
                title: nil,
                message: message,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
                completionHandler()
            })
            present(alert)
        }

        func webView(
            _ webView: WKWebView,
            runJavaScriptConfirmPanelWithMessage message: String,
            initiatedByFrame frame: WKFrameInfo,
            completionHandler: @escaping (Bool) -> Void
        ) {
            let alert = UIAlertController(
                title: nil,
                message: message,
                preferredStyle: .alert
            )
            alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
                completionHandler(true)
            })
            alert.addAction(UIAlertAction(title: "Cancel", style: .cancel) { _ in
                completionHandler(false)
            })
            present(alert)
        }

        private func present(_ alert: UIAlertController) {
            var responder: UIResponder? = UIApplication.shared.connectedScenes
                .compactMap { ($0 as? UIWindowScene)?.keyWindow }
                .first
            while responder != nil, !(responder is UIViewController) {
                responder = responder?.next
            }
            (responder as? UIViewController)?.present(alert, animated: true)
        }
    }
}
