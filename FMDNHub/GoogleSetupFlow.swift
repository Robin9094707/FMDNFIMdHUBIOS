import SwiftUI
import WebKit

// MARK: - Google EmbeddedSetup

struct GoogleLoginSheet: View {
    let onToken: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            GoogleEmbeddedSetupWebView(onToken: onToken)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle("Google sign in")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Cancel") {
                            dismiss()
                        }
                    }
                }
        }
    }
}

struct GoogleEmbeddedSetupWebView: UIViewRepresentable {
    let onToken: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onToken: onToken)
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true

        let webView = WKWebView(
            frame: .zero,
            configuration: configuration
        )
        webView.navigationDelegate = context.coordinator
        context.coordinator.webView = webView

        let request = URLRequest(
            url: URL(
                string: "https://accounts.google.com/EmbeddedSetup"
            )!
        )

        webView.load(request)
        context.coordinator.startCookiePolling()

        return webView
    }

    func updateUIView(
        _ uiView: WKWebView,
        context: Context
    ) {}

    static func dismantleUIView(
        _ uiView: WKWebView,
        coordinator: Coordinator
    ) {
        coordinator.stop()
        uiView.stopLoading()
        uiView.navigationDelegate = nil
    }

    final class Coordinator: NSObject, WKNavigationDelegate {
        let onToken: (String) -> Void
        weak var webView: WKWebView?
        private var timer: Timer?
        private var completed = false

        init(onToken: @escaping (String) -> Void) {
            self.onToken = onToken
        }

        func startCookiePolling() {
            timer?.invalidate()
            timer = Timer.scheduledTimer(
                withTimeInterval: 0.7,
                repeats: true
            ) { [weak self] _ in
                self?.checkCookies()
            }
            checkCookies()
        }

        func stop() {
            timer?.invalidate()
            timer = nil
        }

        private func checkCookies() {
            guard !completed,
                  let webView else {
                return
            }

            webView.configuration
                .websiteDataStore
                .httpCookieStore
                .getAllCookies { [weak self] cookies in
                    guard let self,
                          !self.completed,
                          let cookie = cookies.first(
                            where: {
                                $0.name == "oauth_token"
                                && !$0.value.isEmpty
                            }
                          )
                    else {
                        return
                    }

                    self.completed = true
                    self.stop()

                    DispatchQueue.main.async {
                        self.onToken(cookie.value)
                    }
                }
        }

        func webView(
            _ webView: WKWebView,
            didFinish navigation: WKNavigation!
        ) {
            checkCookies()
        }
    }
}

// MARK: - Google security-domain unlock

struct SecurityUnlockSheet: View {
    let onVaultKeys: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            SecurityUnlockWebView(
                url: SecurityDomainUnlock.requestURL(),
                onVaultKeys: onVaultKeys,
                onClose: { dismiss() }
            )
            .ignoresSafeArea(edges: .bottom)
            .navigationTitle("Unlock encryption")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }
}

struct SecurityUnlockWebView: UIViewRepresentable {
    let url: URL
    let onVaultKeys: (String) -> Void
    let onClose: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            onVaultKeys: onVaultKeys,
            onClose: onClose
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()

        let controller = WKUserContentController()

        let bridge = """
        window.mm = {
          setVaultSharedKeys: function(str, vaultKeys) {
            try {
              window.webkit.messageHandlers.findHubVault.postMessage({
                method: "setVaultSharedKeys",
                str: String(str || ""),
                vaultKeys: vaultKeys
              });
            } catch (e) {}
          },
          closeView: function() {
            try {
              window.webkit.messageHandlers.findHubVault.postMessage({
                method: "closeView"
              });
            } catch (e) {}
          }
        };
        """

        controller.addUserScript(
            WKUserScript(
                source: bridge,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: false
            )
        )
        controller.add(
            context.coordinator,
            name: "findHubVault"
        )

        configuration.userContentController = controller

        let webView = WKWebView(
            frame: .zero,
            configuration: configuration
        )
        webView.navigationDelegate = context.coordinator
        webView.load(URLRequest(url: url))

        return webView
    }

    func updateUIView(
        _ uiView: WKWebView,
        context: Context
    ) {}

    static func dismantleUIView(
        _ uiView: WKWebView,
        coordinator: Coordinator
    ) {
        uiView.configuration
            .userContentController
            .removeScriptMessageHandler(
                forName: "findHubVault"
            )
        uiView.stopLoading()
        uiView.navigationDelegate = nil
    }

    final class Coordinator:
        NSObject,
        WKScriptMessageHandler,
        WKNavigationDelegate
    {
        let onVaultKeys: (String) -> Void
        let onClose: () -> Void
        private var completed = false

        init(
            onVaultKeys: @escaping (String) -> Void,
            onClose: @escaping () -> Void
        ) {
            self.onVaultKeys = onVaultKeys
            self.onClose = onClose
        }

        func userContentController(
            _ userContentController: WKUserContentController,
            didReceive message: WKScriptMessage
        ) {
            guard message.name == "findHubVault",
                  let object = message.body
                    as? [String: Any],
                  let method = object["method"]
                    as? String else {
                return
            }

            if method == "closeView" {
                DispatchQueue.main.async {
                    self.onClose()
                }
                return
            }

            guard method == "setVaultSharedKeys",
                  !completed,
                  let raw = object["vaultKeys"]
            else {
                return
            }

            do {
                let string: String

                if let existing = raw as? String {
                    string = existing
                } else {
                    let data =
                        try JSONSerialization.data(
                            withJSONObject: raw,
                            options: []
                        )
                    string = String(
                        decoding: data,
                        as: UTF8.self
                    )
                }

                completed = true

                DispatchQueue.main.async {
                    self.onVaultKeys(string)
                }
            } catch {
                // The session layer will surface protocol errors after
                // a valid setVaultSharedKeys callback is received.
            }
        }
    }
}

// MARK: - Security-domain request and vault parser

enum SecurityDomainUnlock {
    static func requestURL() -> URL {
        var extras = ProtoWriter()
        extras.int32(1, 1)
        extras.message(2) { domain in
            domain.string(1, "finder_hw")
            domain.int32(2, 0)
        }
        extras.string(
            6,
            UUID().uuidString.lowercased()
        )

        var components = URLComponents(
            string:
                "https://accounts.google.com/encryption/unlock/android"
        )!

        components.queryItems = [
            URLQueryItem(
                name: "kdi",
                value:
                    extras.data.base64EncodedString()
            )
        ]

        return components.url!
    }

    static func parseFinderHWKey(
        _ vaultKeys: String
    ) throws -> (key: Data, epoch: Int) {
        guard let data = vaultKeys.data(
            using: .utf8
        ),
        let root =
            try JSONSerialization.jsonObject(
                with: data
            ) as? [String: Any],
        let values =
            root["finder_hw"]
                as? [[String: Any]],
        !values.isEmpty
        else {
            throw FindHubError.crypto(
                "Google did not return a finder_hw vault key."
            )
        }

        let sorted = values.sorted {
            (($0["epoch"] as? NSNumber)?.intValue ?? 0)
            >
            (($1["epoch"] as? NSNumber)?.intValue ?? 0)
        }

        for entry in sorted {
            guard let keyObject =
                    entry["key"]
                        as? [String: Any]
            else {
                continue
            }

            let indexed: [(Int, UInt8)] =
                keyObject.compactMap {
                    rawIndex,
                    rawValue in

                    guard
                        let index =
                            Int(rawIndex),
                        let number =
                            rawValue
                                as? NSNumber
                    else {
                        return nil
                    }

                    return (
                        index,
                        UInt8(
                            truncating:
                                number
                        )
                    )
                }
                .sorted { $0.0 < $1.0 }

            guard !indexed.isEmpty else {
                continue
            }

            let bytes = indexed.map(\.1)
            let epoch =
                (entry["epoch"]
                    as? NSNumber)?
                    .intValue
                ?? 0

            return (Data(bytes), epoch)
        }

        throw FindHubError.crypto(
            "The finder_hw vault key had an unsupported format."
        )
    }
}
