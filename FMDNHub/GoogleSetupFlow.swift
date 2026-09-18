import SwiftUI
import WebKit

// MARK: - Google EmbeddedSetup

struct GoogleLoginSheet: View {
    let androidID: String
    let onDebug: (String) -> Void
    let onToken: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            GoogleEmbeddedSetupWebView(
                androidID: androidID,
                onDebug: onDebug,
                onToken: onToken
            )
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
    let androidID: String
    let onDebug: (String) -> Void
    let onToken: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            androidID: androidID,
            onDebug: onDebug,
            onToken: onToken
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        configuration.defaultWebpagePreferences.allowsContentJavaScript = true
        configuration.applicationNameForUserAgent = "MinuteMaid"

        let androidHex =
            UInt64(androidID)
                .map { String($0, radix: 16) }
            ?? androidID

        let setupBridge = """
        (() => {
          const noop = function() {};
          const mm = {
            addAccount: noop,
            attemptLogin: noop,
            backupSyncOptIn: noop,
            cancelFido2SignRequest: noop,
            clearOldLoginAttempts: noop,
            closeView: noop,
            fetchIIDToken: noop,
            fetchVerifiedPhoneNumber: function() { return null; },
            getAccounts: function() { return "[]"; },
            getAllowedDomains: function() { return "[]"; },
            getAndroidId: function() { return "(androidHex)"; },
            getAuthModuleVersionCode: function() { return 244433022; },
            getBuildVersionSdk: function() { return 35; },
            getDeviceContactsCount: function() { return -1; },
            getDeviceDataVersionInfo: function() { return 1; },
            getDroidGuardResult: noop,
            getFactoryResetChallenges: function() { return "[]"; },
            getPhoneNumber: function() { return null; },
            getPlayServicesVersionCode: function() { return 244433022; },
            getSimSerial: function() { return null; },
            getSimState: function() { return 0; },
            goBack: noop,
            hasPhoneNumber: function() { return false; },
            hasTelephony: function() { return false; },
            hideKeyboard: noop,
            isUserOwner: function() { return true; },
            launchEmergencyDialer: noop,
            log: noop,
            notifyOnTermsOfServiceAccepted: noop,
            sendFido2SkUiEvent: noop,
            setAccountIdentifier: noop,
            setAllActionsEnabled: noop,
            setBackButtonEnabled: noop,
            setNewAccountCreated: noop,
            setPrimaryActionEnabled: noop,
            setPrimaryActionLabel: noop,
            setSecondaryActionEnabled: noop,
            setSecondaryActionLabel: noop,
            showKeyboard: noop,
            showView: noop,
            skipLogin: noop,
            startAfw: noop,
            startFido2SignRequest: noop
          };

          if (!window.mm) {
            Object.defineProperty(window, "mm", {
              configurable: true,
              enumerable: true,
              writable: true,
              value: mm
            });
          } else {
            Object.keys(mm).forEach((key) => {
              if (typeof window.mm[key] === "undefined") {
                window.mm[key] = mm[key];
              }
            });
          }
        })();
        """

        let controller = WKUserContentController()
        controller.addUserScript(
            WKUserScript(
                source: setupBridge,
                injectionTime: .atDocumentStart,
                forMainFrameOnly: false
            )
        )
        configuration.userContentController = controller

        let webView = WKWebView(
            frame: .zero,
            configuration: configuration
        )
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        context.coordinator.webView = webView

        let request = URLRequest(
            url: Self.embeddedSetupURL()
        )

        context.coordinator.beginFreshSetup(
            request: request
        )

        return webView
    }

    private static func embeddedSetupURL() -> URL {
        let language =
            Locale.current.language.languageCode?.identifier
            ?? "en"

        let region =
            Locale.current.region?.identifier
                .lowercased()
            ?? "us"

        let locale =
            Locale.current.identifier
                .replacingOccurrences(
                    of: "_",
                    with: "-"
                )

        var components = URLComponents(
            string:
                "https://accounts.google.com/EmbeddedSetup"
        )!

        components.queryItems = [
            URLQueryItem(
                name: "source",
                value: "android"
            ),
            URLQueryItem(
                name: "xoauth_display_name",
                value: "Android Device"
            ),
            URLQueryItem(
                name: "lang",
                value: language
            ),
            URLQueryItem(
                name: "cc",
                value: region
            ),
            URLQueryItem(
                name: "langCountry",
                value:
                    Locale.current.identifier
                        .lowercased()
            ),
            URLQueryItem(
                name: "hl",
                value: locale
            ),
            URLQueryItem(
                name: "tmpl",
                value: "new_account"
            )
        ]

        return components.url!
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
        uiView.uiDelegate = nil
    }

    final class Coordinator:
        NSObject,
        WKNavigationDelegate,
        WKUIDelegate
    {
        let androidID: String
        let onDebug: (String) -> Void
        let onToken: (String) -> Void
        weak var webView: WKWebView?
        private var timer: Timer?
        private var completed = false

        init(
            androidID: String,
            onDebug: @escaping (String) -> Void,
            onToken: @escaping (String) -> Void
        ) {
            self.androidID = androidID
            self.onDebug = onDebug
            self.onToken = onToken
        }

        private func log(_ message: String) {
            DispatchQueue.main.async {
                self.onDebug(message)
            }
        }

        private func safeDescription(_ url: URL?) -> String {
            guard let url else {
                return "(no URL)"
            }

            return "(url.host ?? "?")(url.path)"
        }

        func beginFreshSetup(
            request: URLRequest
        ) {
            guard let webView else {
                return
            }

            let cookieStore =
                webView.configuration
                    .websiteDataStore
                    .httpCookieStore

            cookieStore.getAllCookies {
                [weak self] cookies in

                guard let self else {
                    return
                }

                // Aurora Store clears the WebView cookie jar before
                // EmbeddedSetup. Do the same here so Google always starts
                // a fresh setup flow, while the resulting session remains
                // available for the subsequent finder_hw unlock.
                let group = DispatchGroup()

                for cookie in cookies {
                    group.enter()
                    cookieStore.delete(cookie) {
                        group.leave()
                    }
                }

                group.notify(
                    queue: .main
                ) {
                    self.log(
                        "Google EmbeddedSetup starting with fresh cookies"
                    )
                    webView.load(request)
                    self.startCookiePolling()
                }
            }
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
            didStartProvisionalNavigation navigation: WKNavigation!
        ) {
            log(
                "Google login navigation started: (safeDescription(webView.url))"
            )
        }

        func webView(
            _ webView: WKWebView,
            didFinish navigation: WKNavigation!
        ) {
            log(
                "Google login navigation finished: (safeDescription(webView.url))"
            )
            checkCookies()
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationResponse: WKNavigationResponse,
            decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
        ) {
            if let http =
                navigationResponse.response
                    as? HTTPURLResponse
            {
                log(
                    "Google login HTTP (http.statusCode): (safeDescription(http.url))"
                )
            }

            decisionHandler(.allow)
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation!,
            withError error: Error
        ) {
            log(
                "Google login navigation failed: (error.localizedDescription)"
            )
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            log(
                "Google login provisional navigation failed: (error.localizedDescription)"
            )
        }

        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for navigationAction: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            if navigationAction.targetFrame == nil {
                webView.load(
                    navigationAction.request
                )
            }

            return nil
        }
    }
}

// MARK: - Google security-domain unlock

struct SecurityUnlockSheet: View {
    let onVaultKeys: (String) -> Void
    let onDebug: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            SecurityUnlockWebView(
                unlockURL: SecurityDomainUnlock.requestURL(),
                onVaultKeys: onVaultKeys,
                onClose: { dismiss() },
                onDebug: onDebug
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
    let unlockURL: URL
    let onVaultKeys: (String) -> Void
    let onClose: () -> Void
    let onDebug: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(
            unlockURL: unlockURL,
            onVaultKeys: onVaultKeys,
            onClose: onClose,
            onDebug: onDebug
        )
    }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .default()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        configuration.applicationNameForUserAgent = "MinuteMaid"

        let controller = WKUserContentController()

        // Google may assign window.mm after our document-start script runs.
        // Keep a property wrapper installed so our capture hooks survive that
        // assignment while still calling Google's own implementation.
        let bridge = """
        (() => {
          const post = (payload) => {
            try {
              window.webkit.messageHandlers.findHubVault.postMessage(payload);
            } catch (_) {}
          };

          const wrapMethod = (obj, name, marker, capture) => {
            if (!obj || obj[marker]) return;
            let target = (typeof obj[name] === 'function') ? obj[name] : null;
            const call = function() {
              try { capture.apply(null, arguments); } catch (_) {}
              if (target) return target.apply(this, arguments);
            };
            Object.defineProperty(obj, name, {
              configurable: true,
              enumerable: true,
              get: () => call,
              set: (fn) => {
                target = (typeof fn === 'function') ? fn : null;
              }
            });
            obj[marker] = true;
          };

          const wrapVault = (value) => {
            const obj = (value && typeof value === 'object') ? value : {};
            wrapMethod(
              obj,
              'setVaultSharedKeys',
              '__findhub_keys_wrapped',
              function(str, vaultKeys) {
                post({
                  method: 'setVaultSharedKeys',
                  str: String(str || ''),
                  vaultKeys: vaultKeys
                });
              }
            );
            wrapMethod(
              obj,
              'closeView',
              '__findhub_close_wrapped',
              function() {
                post({ method: 'closeView' });
              }
            );
            return obj;
          };

          let mm = wrapVault(window.mm);
          Object.defineProperty(window, 'mm', {
            configurable: true,
            enumerable: true,
            get: () => mm,
            set: (value) => { mm = wrapVault(value); }
          });
        })();
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
        webView.uiDelegate = context.coordinator

        context.coordinator.webView = webView
        context.coordinator.log("Unlock preflight: accounts.google.com")

        // Mirror the working browser flow: establish/confirm the regular
        // Google account session first, then navigate to the security domain.
        webView.load(
            URLRequest(
                url: URL(
                    string: "https://accounts.google.com/"
                )!
            )
        )

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
        uiView.uiDelegate = nil
    }

    final class Coordinator:
        NSObject,
        WKScriptMessageHandler,
        WKNavigationDelegate,
        WKUIDelegate
    {
        let unlockURL: URL
        let onVaultKeys: (String) -> Void
        let onClose: () -> Void
        let onDebug: (String) -> Void
        weak var webView: WKWebView?

        private var completed = false
        private var openedUnlock = false

        init(
            unlockURL: URL,
            onVaultKeys: @escaping (String) -> Void,
            onClose: @escaping () -> Void,
            onDebug: @escaping (String) -> Void
        ) {
            self.unlockURL = unlockURL
            self.onVaultKeys = onVaultKeys
            self.onClose = onClose
            self.onDebug = onDebug
        }

        func log(_ message: String) {
            DispatchQueue.main.async {
                self.onDebug(message)
            }
        }

        private func safeDescription(_ url: URL?) -> String {
            guard let url else { return "(no URL)" }
            return "\(url.host ?? "?")\(url.path)"
        }

        private func openUnlockIfAuthenticated(_ url: URL?) {
            guard !openedUnlock,
                  let url else {
                return
            }

            let host =
                url.host?.lowercased()
                ?? ""

            if host == "myaccount.google.com" {
                openUnlock(
                    reason:
                        "myaccount session confirmed"
                )
                return
            }

            guard host == "accounts.google.com",
                  let webView else {
                return
            }

            // WKWebView can keep an authenticated Google session on
            // accounts.google.com instead of redirecting to myaccount.
            // We do not inspect field values. We only detect whether a
            // login/password input is currently present.
            let script = """
            (() => {
              return Boolean(
                document.querySelector(
                  'input[type="email"], input[type="password"], input[name="identifier"]'
                )
              );
            })();
            """

            webView.evaluateJavaScript(
                script
            ) { [weak self] result, error in
                guard let self,
                      !self.openedUnlock
                else {
                    return
                }

                if let error {
                    self.log(
                        "Google session probe failed: \(error.localizedDescription)"
                    )
                    return
                }

                let hasLoginInput =
                    (result as? Bool)
                    ?? true

                if !hasLoginInput {
                    self.openUnlock(
                        reason:
                            "authenticated accounts session confirmed"
                    )
                } else {
                    self.log(
                        "Google account page is waiting for sign-in"
                    )
                }
            }
        }

        private func openUnlock(
            reason: String
        ) {
            guard !openedUnlock else {
                return
            }

            openedUnlock = true

            log(
                "Google \(reason); opening finder_hw unlock (kdi length: \(SecurityDomainUnlock.kdiLength()))"
            )

            webView?.load(
                URLRequest(
                    url: unlockURL
                )
            )
        }

        func webView(
            _ webView: WKWebView,
            didStartProvisionalNavigation navigation: WKNavigation!
        ) {
            log(
                "Navigation started: \(safeDescription(webView.url))"
            )
        }

        func webView(
            _ webView: WKWebView,
            didFinish navigation: WKNavigation!
        ) {
            log(
                "Navigation finished: \(safeDescription(webView.url))"
            )
            openUnlockIfAuthenticated(webView.url)
        }

        func webView(
            _ webView: WKWebView,
            decidePolicyFor navigationResponse: WKNavigationResponse,
            decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void
        ) {
            if let http = navigationResponse.response as? HTTPURLResponse {
                log(
                    "HTTP \(http.statusCode): \(safeDescription(http.url))"
                )
            }
            decisionHandler(.allow)
        }

        func webView(
            _ webView: WKWebView,
            didFail navigation: WKNavigation!,
            withError error: Error
        ) {
            log(
                "Navigation failed: \(error.localizedDescription)"
            )
        }

        func webView(
            _ webView: WKWebView,
            didFailProvisionalNavigation navigation: WKNavigation!,
            withError error: Error
        ) {
            log(
                "Provisional navigation failed: \(error.localizedDescription)"
            )
        }

        func webView(
            _ webView: WKWebView,
            createWebViewWith configuration: WKWebViewConfiguration,
            for navigationAction: WKNavigationAction,
            windowFeatures: WKWindowFeatures
        ) -> WKWebView? {
            if navigationAction.targetFrame == nil {
                webView.load(navigationAction.request)
            }
            return nil
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

            log("Vault bridge callback: \(method)")

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
                log("Vault keys received from Google")

                DispatchQueue.main.async {
                    self.onVaultKeys(string)
                }
            } catch {
                log(
                    "Vault callback parse failed: \(error.localizedDescription)"
                )
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

        let kdi =
            extras.data
                .base64EncodedString()
                .replacingOccurrences(
                    of: "+",
                    with: "-"
                )
                .replacingOccurrences(
                    of: "/",
                    with: "_"
                )
                .replacingOccurrences(
                    of: "=",
                    with: ""
                )

        return URL(
            string:
                "https://accounts.google.com/encryption/unlock/android?kdi=\(kdi)"
        )!
    }

    static func kdiLength() -> Int {
        let url = requestURL()
        return URLComponents(
            url: url,
            resolvingAgainstBaseURL: false
        )?
        .queryItems?
        .first(where: { $0.name == "kdi" })?
        .value?
        .count ?? 0
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
                        number.uint8Value
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
