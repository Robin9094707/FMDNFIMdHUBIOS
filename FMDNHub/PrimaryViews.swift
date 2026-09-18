import SwiftUI
import UniformTypeIdentifiers
import UIKit

struct RootView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        Group {
            if session.secrets == nil {
                SetupView()
            } else {
                MainTabView()
            }
        }
        .alert(
            "Find Hub",
            isPresented: Binding(
                get: { session.errorMessage != nil },
                set: { if !$0 { session.errorMessage = nil } }
            )
        ) {
            Button("OK", role: .cancel) {
                session.errorMessage = nil
            }
        } message: {
            Text(session.errorMessage ?? "")
        }
    }
}

struct SetupView: View {
    @EnvironmentObject private var session: AppSession

    @State private var showImporter = false
    @State private var showGoogleLogin = false
    @State private var showSecurityUnlock = false
    @State private var showDebugLog = false

    var body: some View {
        NavigationStack {
            ZStack {
                LinearGradient(
                    colors: [
                        .blue.opacity(0.38),
                        .purple.opacity(0.24),
                        .clear
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
                .ignoresSafeArea()

                ScrollView {
                    VStack(spacing: 24) {
                        Spacer(minLength: 54)

                        Image(
                            systemName:
                                "location.circle.fill"
                        )
                        .font(
                            .system(
                                size: 82,
                                weight: .semibold
                            )
                        )
                        .symbolRenderingMode(
                            .hierarchical
                        )

                        VStack(spacing: 8) {
                            Text("Find Hub")
                                .font(
                                    .largeTitle
                                        .bold()
                                )

                            Text(
                                "Sign in once and the app creates its own Find Hub secrets on this iPhone."
                            )
                            .font(.headline)
                            .foregroundStyle(
                                .secondary
                            )
                            .multilineTextAlignment(
                                .center
                            )
                        }

                        GlassCard {
                            VStack(
                                alignment: .leading,
                                spacing: 14
                            ) {
                                Label(
                                    "Google sign in",
                                    systemImage:
                                        "person.crop.circle.badge.checkmark"
                                )
                                .font(.headline)

                                Text(
                                    "1. Sign in on Google's EmbeddedSetup page with your normal Google account."
                                )
                                .foregroundStyle(
                                    .secondary
                                )

                                Text(
                                    "2. Google then asks you to unlock the Find Hub encryption domain. This can include the PIN of an Android device already linked to the account."
                                )
                                .foregroundStyle(
                                    .secondary
                                )

                                Text(
                                    "3. Find Hub creates and stores the AAS token, finder_hw shared key and owner key locally."
                                )
                                .foregroundStyle(
                                    .secondary
                                )
                            }
                        }

                        Button {
                            Task {
                                if await session
                                    .prepareGeneratedSetup()
                                {
                                    showGoogleLogin =
                                        true
                                }
                            }
                        } label: {
                            HStack {
                                if session.isBusy {
                                    ProgressView()
                                }

                                Label(
                                    session.isBusy
                                        ? "Preparing…"
                                        : "Sign in with Google",
                                    systemImage:
                                        "person.crop.circle.fill"
                                )
                            }
                            .frame(
                                maxWidth: .infinity
                            )
                            .padding(
                                .vertical,
                                8
                            )
                        }
                        .buttonStyle(
                            .borderedProminent
                        )
                        .controlSize(.large)
                        .disabled(
                            session.isBusy
                        )

                        GlassCard {
                            VStack(
                                alignment: .leading,
                                spacing: 10
                            ) {
                                Label(
                                    "Privacy",
                                    systemImage:
                                        "lock.shield.fill"
                                )
                                .font(.headline)

                                Text(
                                    "Your password and Android-device PIN are entered only into Google's pages. Find Hub does not receive those values. It stores only Google's resulting tokens and encryption keys in the iOS Keychain."
                                )
                                .foregroundStyle(
                                    .secondary
                                )
                                .font(.subheadline)
                            }
                        }

                        Menu {
                            Button {
                                showImporter = true
                            } label: {
                                Label(
                                    "Import existing secrets.json",
                                    systemImage:
                                        "square.and.arrow.down"
                                )
                            }

                            Button {
                                showDebugLog = true
                            } label: {
                                Label(
                                    "Setup debug log",
                                    systemImage:
                                        "ladybug"
                                )
                            }

                            Divider()

                            Button(
                                role: .destructive
                            ) {
                                session.resetPushIdentity()
                            } label: {
                                Label(
                                    "Reset setup identity",
                                    systemImage:
                                        "arrow.counterclockwise.circle"
                                )
                            }
                        } label: {
                            Label(
                                "Advanced / existing setup",
                                systemImage:
                                    "ellipsis.circle"
                            )
                        }

                        Text(session.status)
                            .font(.footnote)
                            .foregroundStyle(
                                .secondary
                            )
                            .multilineTextAlignment(
                                .center
                            )
                    }
                    .padding(22)
                }
            }
            .fileImporter(
                isPresented:
                    $showImporter,
                allowedContentTypes: [.json]
            ) { result in
                guard
                    case .success(let url) =
                        result
                else {
                    return
                }

                let scoped =
                    url.startAccessingSecurityScopedResource()

                defer {
                    if scoped {
                        url.stopAccessingSecurityScopedResource()
                    }
                }

                if let data =
                    try? Data(
                        contentsOf: url
                    )
                {
                    session.importSecrets(
                        data: data
                    )
                }
            }
            .fullScreenCover(
                isPresented:
                    $showGoogleLogin
            ) {
                GoogleLoginSheet(
                    androidID:
                        session.googleSetupAndroidID
                        ?? "",
                    onDebug: {
                        message in
                        session.debug(message)
                    },
                    onToken: {
                        oauthToken in

                        Task {
                        let succeeded =
                            await session
                                .completeEmbeddedSetup(
                                    oauthToken:
                                        oauthToken
                                )

                        guard succeeded else {
                            return
                        }

                        showGoogleLogin = false

                        try? await Task.sleep(
                            for:
                                .milliseconds(
                                    300
                                )
                        )

                        showSecurityUnlock =
                            true
                        }
                    }
                )
            }
            .fullScreenCover(
                isPresented:
                    $showSecurityUnlock
            ) {
                SecurityUnlockSheet(
                    onVaultKeys: {
                        vaultKeys in

                        Task {
                            if await session
                                .completeSecurityUnlock(
                                    vaultKeys:
                                        vaultKeys
                                )
                            {
                                showSecurityUnlock =
                                    false
                            }
                        }
                    },
                    onDebug: {
                        message in
                        session.debug(message)
                    }
                )
            }
            .sheet(
                isPresented:
                    $showDebugLog
            ) {
                SetupDebugLogView()
                    .environmentObject(
                        session
                    )
            }
        }
    }
}

struct SetupDebugLogView: View {
    @EnvironmentObject private var session: AppSession
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if session.debugEvents.isEmpty {
                    ContentUnavailableView(
                        "No debug entries",
                        systemImage:
                            "ladybug",
                        description:
                            Text(
                                "Run the Google setup once and the safe diagnostic events will appear here."
                            )
                    )
                } else {
                    List {
                        ForEach(
                            Array(
                                session.debugEvents
                                    .enumerated()
                            ),
                            id: \.offset
                        ) { _, entry in
                            Text(entry)
                                .font(
                                    .system(
                                        .caption,
                                        design:
                                            .monospaced
                                    )
                                )
                                .textSelection(
                                    .enabled
                                )
                        }
                    }
                }
            }
            .navigationTitle(
                "Setup Debug"
            )
            .navigationBarTitleDisplayMode(
                .inline
            )
            .toolbar {
                ToolbarItem(
                    placement:
                        .topBarLeading
                ) {
                    Button("Done") {
                        dismiss()
                    }
                }

                ToolbarItemGroup(
                    placement:
                        .topBarTrailing
                ) {
                    Button {
                        UIPasteboard.general.string =
                            session.debugEvents
                                .joined(
                                    separator:
                                        "\n"
                                )
                    } label: {
                        Image(
                            systemName:
                                "doc.on.doc"
                        )
                    }
                    .disabled(
                        session.debugEvents
                            .isEmpty
                    )

                    Button(
                        role: .destructive
                    ) {
                        session.clearDebugLog()
                    } label: {
                        Image(
                            systemName:
                                "trash"
                        )
                    }
                }
            }
            .safeAreaInset(
                edge: .bottom
            ) {
                Text(
                    "Passwords, PINs, OAuth tokens and encryption keys are intentionally not written to this log."
                )
                .font(.caption2)
                .foregroundStyle(
                    .secondary
                )
                .padding(10)
                .frame(
                    maxWidth:
                        .infinity
                )
                .background(
                    .ultraThinMaterial
                )
            }
        }
    }
}

struct MainTabView: View {
    var body: some View {
        TabView {
            TrackerListView()
                .tabItem {
                    Label("Trackers", systemImage: "location.fill")
                }

            SettingsView()
                .tabItem {
                    Label("Settings", systemImage: "gearshape.fill")
                }
        }
    }
}

struct TrackerListView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        NavigationStack {
            List(session.visibleDevices) { device in
                NavigationLink(value: device.id) {
                    TrackerRow(device: device)
                }
            }
            .listStyle(.insetGrouped)
            .overlay {
                if session.visibleDevices.isEmpty && !session.isBusy {
                    ContentUnavailableView(
                        "No trackers",
                        systemImage: "location.slash",
                        description: Text(
                            "Pull to refresh after importing a valid account."
                        )
                    )
                }
            }
            .refreshable {
                await session.refreshDevices()
            }
            .navigationTitle("Find Hub")
            .navigationDestination(for: String.self) { id in
                TrackerDetailView(deviceID: id)
            }
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if session.isBusy {
                        ProgressView()
                    } else {
                        Button {
                            Task {
                                await session.refreshDevices()
                            }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                        }
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                Text(session.status)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 7)
                    .hubGlass(cornerRadius: 14)
                    .padding(.bottom, 4)
            }
        }
    }
}

struct TrackerRow: View {
    let device: TrackerDevice

    var body: some View {
        HStack(spacing: 14) {
            Group {
                if let url = device.imageURL {
                    AsyncImage(url: url) { image in
                        image
                            .resizable()
                            .scaledToFit()
                    } placeholder: {
                        Image(systemName: device.kind.symbol)
                    }
                } else {
                    Image(systemName: device.kind.symbol)
                }
            }
            .font(.title2)
            .frame(width: 48, height: 48)
            .background(.thinMaterial, in: Circle())

            VStack(alignment: .leading, spacing: 4) {
                Text(device.name)
                    .font(.headline)

                if let location = device.lastLocation {
                    Text(
                        location.semanticName
                        ?? location.timestamp.formatted(
                            date: .abbreviated,
                            time: .shortened
                        )
                    )
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                } else {
                    let details = [
                        device.manufacturer,
                        device.model
                    ]
                    .filter { !$0.isEmpty }
                    .joined(separator: " · ")

                    Text(details.isEmpty ? "Ready to locate" : details)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 3)
    }
}

struct GlassCard<Content: View>: View {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .hubGlass(cornerRadius: 24)
    }
}

extension View {
    @ViewBuilder
    func hubGlass(cornerRadius: CGFloat = 22) -> some View {
#if compiler(>=6.2)
        if #available(iOS 26.0, *) {
            self.glassEffect()
        } else {
            self
                .background(
                    .ultraThinMaterial,
                    in: RoundedRectangle(
                        cornerRadius: cornerRadius,
                        style: .continuous
                    )
                )
                .overlay(
                    RoundedRectangle(
                        cornerRadius: cornerRadius,
                        style: .continuous
                    )
                    .stroke(.white.opacity(0.14), lineWidth: 0.7)
                )
        }
#else
        self
            .background(
                .ultraThinMaterial,
                in: RoundedRectangle(
                    cornerRadius: cornerRadius,
                    style: .continuous
                )
            )
            .overlay(
                RoundedRectangle(
                    cornerRadius: cornerRadius,
                    style: .continuous
                )
                .stroke(.white.opacity(0.14), lineWidth: 0.7)
            )
#endif
    }
}
