import SwiftUI
import UniformTypeIdentifiers

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
                        Spacer(minLength: 64)

                        Image(systemName: "location.circle.fill")
                            .font(.system(size: 82, weight: .semibold))
                            .symbolRenderingMode(.hierarchical)

                        VStack(spacing: 8) {
                            Text("Find Hub")
                                .font(.largeTitle.bold())

                            Text("Your Google trackers in a native iPhone experience.")
                                .font(.headline)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }

                        GlassCard {
                            VStack(alignment: .leading, spacing: 12) {
                                Label(
                                    "Private by design",
                                    systemImage: "lock.shield.fill"
                                )
                                .font(.headline)

                                Text(
                                    "Import the secrets.json created by GoogleFindMyTools. "
                                    + "Your Google password is never requested or stored by this app."
                                )
                                .foregroundStyle(.secondary)
                            }
                        }

                        Button {
                            showImporter = true
                        } label: {
                            Label(
                                "Import secrets.json",
                                systemImage: "square.and.arrow.down"
                            )
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 8)
                        }
                        .buttonStyle(.borderedProminent)
                        .controlSize(.large)

                        Text(
                            "The file needs username, aas_token, the original Android ID "
                            + "and shared_key or owner_key."
                        )
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                    }
                    .padding(22)
                }
            }
            .fileImporter(
                isPresented: $showImporter,
                allowedContentTypes: [.json]
            ) { result in
                guard case .success(let url) = result else { return }

                let scoped = url.startAccessingSecurityScopedResource()
                defer {
                    if scoped {
                        url.stopAccessingSecurityScopedResource()
                    }
                }

                if let data = try? Data(contentsOf: url) {
                    session.importSecrets(data: data)
                }
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
